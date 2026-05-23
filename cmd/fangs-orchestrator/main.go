// SPDX-License-Identifier: Apache-2.0
//
// fangs-orchestrator is the FANGS control-plane binary. It exposes an
// HTTPS API for runners to register, poll for jobs, and stream events
// back. Events are persisted via the configured storage backend.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/api"
	"github.com/irchaosclub/FANGS/internal/orchestrator/config"
	"github.com/irchaosclub/FANGS/internal/orchestrator/metrics"
	"github.com/irchaosclub/FANGS/internal/orchestrator/notifier"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/postgres"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/sqlite"
	"github.com/irchaosclub/FANGS/internal/orchestrator/ui"
	"github.com/irchaosclub/FANGS/internal/orchestrator/watcher"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// version is overridden via -ldflags at build time; "dev" is the default.
var version = "dev"

func main() {
	var (
		addr           = flag.String("addr", "127.0.0.1:8443", "HTTP listen address")
		orchestratorID = flag.String("id", "fangs-orchestrator", "identifier reported to runners on register")
		backendKind    = flag.String("storage", "sqlite", "storage backend: sqlite | postgres | none")
		sqlitePath     = flag.String("sqlite-path", "var/lib/fangs/fangs.db", "sqlite database file path")
		postgresDSN    = flag.String("postgres-dsn", "", "postgres DSN (also reads $FANGS_PG_DSN if unset)")
		watchInterval  = flag.Duration("watch-interval", 5*time.Minute, "watcher poll interval for the npm registry")
		watchEnabled   = flag.Bool("watch", true, "enable the npm registry watcher")
		uiEnabled      = flag.Bool("ui", true, "serve the read-only web dashboard on /ui/")
		notifiersFile  = flag.String("notifiers-file", "", "optional path to a JSON file declaring webhook targets — entries are upserted into the DB at startup")
		retentionDays  = flag.Int("retention-days", 90, "delete raw events older than this many days (0 = never prune). Deviation-evidence events are pinned and never pruned.")
		retentionEvery = flag.Duration("retention-interval", 24*time.Hour, "how often the pruner runs (a one-shot also fires shortly after startup)")
		tlsCert        = flag.String("tls-cert", "", "PEM-encoded server certificate; when set with -tls-key, switches to HTTPS")
		tlsKey         = flag.String("tls-key", "", "PEM-encoded server private key")
		tlsClientCA    = flag.String("tls-client-ca", "", "PEM-encoded CA bundle for verifying runner client certs (enables mTLS)")
		metricsEnabled = flag.Bool("metrics", true, "expose Prometheus metrics at /metrics on the same listen address")
		configPath     = flag.String("config", "config/orchestrator.yaml", "optional YAML config file (watched_paths, future sections); missing file is OK — hardcoded defaults apply")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Error("config load", "err", err, "path", *configPath)
		os.Exit(1)
	}
	defaultPaths := cfg.WatchedPathsAsProto()
	if defaultPaths == nil {
		defaultPaths = watcher.DefaultWatchedPaths()
		logger.Info("config absent or no watched_paths — using hardcoded defaults",
			"path", *configPath, "paths", len(defaultPaths))
	} else {
		logger.Info("config loaded", "path", *configPath, "watched_paths", len(defaultPaths))
	}

	store, err := openStorage(ctx, *backendKind, *sqlitePath, *postgresDSN, logger)
	if err != nil {
		logger.Error("storage init", "err", err, "backend", *backendKind)
		os.Exit(1)
	}
	if store != nil {
		defer store.Close()
	}

	// Apply config-managed allowlist entries (IPs / SNIs / path
	// exclusions) into the DB. Idempotent — re-applies on every
	// startup with deterministic IDs, no duplicate rows.
	if store != nil {
		if err := cfg.ApplyAllowlist(ctx, store, logger); err != nil {
			logger.Warn("config: apply allowlist", "err", err)
		}
	}

	var notif *notifier.Notifier
	if store != nil {
		notif = notifier.New(notifier.Options{Store: store, Logger: logger})
		if *notifiersFile != "" {
			n, err := notifier.LoadFromFile(ctx, store, *notifiersFile)
			if err != nil {
				logger.Error("notifiers-file load", "err", err, "path", *notifiersFile)
				os.Exit(1)
			}
			logger.Info("notifiers-file loaded", "path", *notifiersFile, "entries", n)
		}
	}

	srv := api.New(api.Options{
		Addr:                *addr,
		OrchestratorID:      *orchestratorID,
		Version:             version,
		Logger:              logger,
		Storage:             store,
		Notifier:            notif,
		TLSCertFile:         *tlsCert,
		TLSKeyFile:          *tlsKey,
		TLSClientCAFile:     *tlsClientCA,
		DefaultWatchedPaths: defaultPaths,
	})

	var mreg *metrics.Registry
	if *metricsEnabled {
		mreg = metrics.New(metrics.Options{
			Version:   version,
			Logger:    logger,
			RunnersFn: func() int { return len(srv.RegisteredRunners()) },
		})
		srv.SetMetrics(mreg)
		if notif != nil {
			notif.SetMetrics(mreg)
		}
	}

	// Watcher — autonomous trigger that polls the npm registry for new
	// releases of watched packages and submits scan jobs. Requires
	// storage (to list watched packages) and at least one registered
	// runner (to receive the scan). Skipped when -watch=false.
	if *watchEnabled && store != nil {
		submit := func(ctx context.Context, pkg, version string) (string, error) {
			runner := srv.FirstRegisteredRunner()
			if runner == "" {
				return "", errors.New("no runners registered")
			}
			job := proto.Job{
				Kind:        "sandbox_scan",
				PackageName: pkg,
				Version:     version,
				// WatchedPaths intentionally empty — SubmitScan fills in
				// the orchestrator's configured defaults so config edits
				// take effect without restarting the watcher path.
				Duration: 60 * time.Second,
			}
			sb := watcher.BuildSandboxScan(pkg, version)
			job.Sandbox = &sb
			return srv.SubmitScan(ctx, runner, job)
		}
		w := watcher.New(watcher.Options{
			Store:    store,
			Registry: watcher.NewNPMRegistry(),
			Submit:   submit,
			Logger:   logger,
			Interval: *watchInterval,
		})
		go func() {
			if err := w.Run(ctx); err != nil {
				logger.Warn("watcher exited", "err", err)
			}
		}()
	}

	// Retention pruner — daily job that deletes events older than the
	// configured cutoff EXCEPT those pinned as deviation evidence. Fires
	// once 30s after startup so operators get an immediate "5 events
	// pruned" line confirming the wiring works, then on the regular
	// interval (default 24h). Skipped when retention-days = 0.
	if store != nil && *retentionDays > 0 {
		go pruneLoop(ctx, store, logger, *retentionDays, *retentionEvery)
	}

	// Wire the HTTP mux: /v1/* from api.Server, /ui/* + /static/* + / from
	// the UI handler when -ui=true and a storage backend is configured.
	mux := http.NewServeMux()
	srv.Mount(mux)
	if mreg != nil {
		mreg.Mount(mux)
		logger.Info("metrics enabled", "url", "http://"+*addr+"/metrics")
	}
	if *uiEnabled && store != nil {
		uih, err := ui.New(ui.Options{
			Store:                 store,
			RunnersFn:             srv.RegisteredRunnersDetail,
			Logger:                logger,
			Version:               version,
			EffectiveWatchedPaths: defaultPaths,
			ConfigPath:            *configPath,
		})
		if err != nil {
			logger.Error("ui init", "err", err)
			os.Exit(1)
		}
		uih.Mount(mux)
		logger.Info("ui enabled", "url", "http://"+*addr+"/ui/")
	} else if *uiEnabled && store == nil {
		logger.Warn("ui disabled — no storage backend (use -storage sqlite or -storage postgres)")
	}

	if err := srv.ServeWith(ctx, mux); err != nil {
		logger.Error("orchestrator exited with error", "err", err)
		os.Exit(1)
	}
	logger.Info("orchestrator shut down cleanly")
}

func openStorage(ctx context.Context, kind, sqlitePath, pgDSN string, logger *slog.Logger) (storage.Backend, error) {
	switch kind {
	case "none":
		logger.Warn("storage disabled — events will be logged but not persisted")
		return nil, nil
	case "sqlite":
		if err := os.MkdirAll(filepath.Dir(sqlitePath), 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite dir: %w", err)
		}
		b, err := sqlite.Open(sqlitePath)
		if err != nil {
			return nil, err
		}
		if err := b.Migrate(ctx); err != nil {
			_ = b.Close()
			return nil, fmt.Errorf("sqlite migrate: %w", err)
		}
		logger.Info("storage ready", "backend", "sqlite", "path", sqlitePath)
		return b, nil
	case "postgres":
		dsn := pgDSN
		if dsn == "" {
			dsn = os.Getenv("FANGS_PG_DSN")
		}
		if dsn == "" {
			return nil, fmt.Errorf("postgres backend requires -postgres-dsn or $FANGS_PG_DSN")
		}
		b, err := postgres.Open(dsn)
		if err != nil {
			return nil, err
		}
		if err := b.Migrate(ctx); err != nil {
			_ = b.Close()
			return nil, fmt.Errorf("postgres migrate: %w", err)
		}
		logger.Info("storage ready", "backend", "postgres")
		return b, nil
	default:
		return nil, fmt.Errorf("unknown -storage backend %q (sqlite|postgres|none)", kind)
	}
}

// pruneLoop runs the event-retention pruner. Fires an immediate one-shot
// 30s after startup so operators see it work in the logs, then on a
// ticker at `every` cadence until ctx cancels. Logs deletion count per
// pass; errors are warned-and-continue so a transient DB hiccup doesn't
// kill the loop.
func pruneLoop(ctx context.Context, store storage.Backend, logger *slog.Logger, retainDays int, every time.Duration) {
	prune := func() {
		cutoff := time.Now().Add(-time.Duration(retainDays) * 24 * time.Hour).UnixNano()
		pctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		n, err := store.PruneEvents(pctx, cutoff)
		if err != nil {
			logger.Warn("retention prune failed", "err", err, "retain_days", retainDays)
			return
		}
		logger.Info("retention prune complete",
			"deleted_rows", n,
			"retain_days", retainDays,
			"cutoff_ts", time.Unix(0, cutoff).Format(time.RFC3339),
		)
	}
	// Initial one-shot — 30s grace so the orchestrator finishes booting
	// before the first prune.
	select {
	case <-time.After(30 * time.Second):
		prune()
	case <-ctx.Done():
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			prune()
		}
	}
}
