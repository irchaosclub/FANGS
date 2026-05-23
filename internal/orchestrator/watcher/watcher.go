// SPDX-License-Identifier: Apache-2.0
package watcher

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

// SubmitFunc enqueues a scan job for a watched package's new release.
// The Watcher calls this when a new dist-tags.latest is observed. The
// orchestrator's API server implements this by reusing the same
// SubmitScan path as the /v1/scans HTTP handler.
type SubmitFunc func(ctx context.Context, packageName, version string) (runID string, err error)

// Options configures a Watcher.
type Options struct {
	Store    storage.Backend
	Registry Registry
	Submit   SubmitFunc
	Logger   *slog.Logger
	// Interval between full polls. D37: 5 minutes default.
	Interval time.Duration
}

// Watcher polls the npm registry for new releases of watched packages
// and submits scan jobs when changes are detected.
type Watcher struct {
	store    storage.Backend
	registry Registry
	submit   SubmitFunc
	logger   *slog.Logger
	interval time.Duration
}

// New constructs a Watcher. Caller passes a SubmitFunc that wires into
// the orchestrator's scan dispatch.
func New(opts Options) *Watcher {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Minute
	}
	return &Watcher{
		store:    opts.Store,
		registry: opts.Registry,
		submit:   opts.Submit,
		logger:   opts.Logger,
		interval: opts.Interval,
	}
}

// Run loops the poll cycle until ctx is canceled. Each tick polls every
// watched package; new releases trigger a release row + a scan job.
func (w *Watcher) Run(ctx context.Context) error {
	w.logger.Info("watcher started", "interval", w.interval.String())
	// Tick once immediately, then on the configured interval.
	w.PollOnce(ctx)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			w.logger.Info("watcher stopped", "reason", ctx.Err())
			return nil
		case <-t.C:
			w.PollOnce(ctx)
		}
	}
}

// PollOnce runs a single cycle over every watched package. Exposed for
// tests and on-demand triggering via the CLI.
func (w *Watcher) PollOnce(ctx context.Context) {
	pkgs, err := w.store.ListWatchedPackages(ctx)
	if err != nil {
		w.logger.Warn("watcher: list packages", "err", err)
		return
	}
	if len(pkgs) == 0 {
		w.logger.Debug("watcher: nothing to watch")
		return
	}
	for _, p := range pkgs {
		if ctx.Err() != nil {
			return
		}
		w.pollPackage(ctx, p)
	}
}

func (w *Watcher) pollPackage(ctx context.Context, p storage.WatchedPackage) {
	logger := w.logger.With("package", p.Name)
	v, err := w.registry.LatestVersion(ctx, p.Name)
	if err != nil {
		if errors.Is(err, ErrPackageNotFound) {
			logger.Warn("registry says package not found")
		} else {
			logger.Warn("registry poll failed", "err", err)
		}
		return
	}
	if err := w.store.UpdatePackageCheck(ctx, p.Name, v.Version); err != nil {
		logger.Warn("update last_checked_at", "err", err)
		// continue — we still want to record the release & submit
	}
	if v.Version == p.LastSeenVersion {
		// No change since last poll.
		return
	}
	// New release detected.
	if err := w.store.RecordRelease(ctx, storage.ReleaseRow{
		PackageName:   p.Name,
		Version:       v.Version,
		TarballSHA256: v.TarballSHA,
		NPMIntegrity:  v.Integrity,
		PublishedAt:   v.PublishedAt,
		DiscoveredAt:  time.Now().UTC(),
	}); err != nil {
		logger.Warn("record release", "err", err)
		// don't return — still submit the scan
	}
	logger.Info("new release detected",
		"version", v.Version,
		"previous_version", p.LastSeenVersion,
		"published_at", v.PublishedAt,
	)
	runID, err := w.submit(ctx, p.Name, v.Version)
	if err != nil {
		logger.Warn("submit scan", "err", err)
		return
	}
	logger.Info("scan queued", "version", v.Version, "run_id", runID)
}

// DefaultWatchedPaths is the canonical watched-path set used by every
// auto-submitted scan (watcher + `fangs package add` + `fangs scan
// submit`). Single source of truth so the autonomous and manual paths
// can't drift apart.
//
// Mix of broad observation prefixes (/etc/, /tmp/, /usr/, /root/) and
// targeted cred-tagged hits (shadow, ssh, aws creds, environ). The
// cred tag drives the red row + CRED badge in the UI; the broad
// prefixes catch generic poking that lights up a deviation when the
// path normalization rules don't squash it.
//
// Returns a fresh slice on each call — callers may mutate it without
// poisoning subsequent invocations.
func DefaultWatchedPaths() []proto.WatchedPath {
	return []proto.WatchedPath{
		{Prefix: "/etc/"},
		{Prefix: "/etc/shadow", CredTagged: true},
		{Prefix: "/etc/passwd", CredTagged: true},
		{Prefix: "/root/"},
		{Prefix: "/root/.ssh/", CredTagged: true},
		{Prefix: "/root/.aws/", CredTagged: true},
		{Prefix: "/root/.npmrc", CredTagged: true},
		{Prefix: "/root/.docker/", CredTagged: true},
		{Prefix: "/root/.kube/", CredTagged: true},
		{Prefix: "/root/.gnupg/", CredTagged: true},
		{Prefix: "/proc/self/environ", CredTagged: true},
		{Prefix: "/tmp/"},
		{Prefix: "/usr/"},
		{Prefix: "/dev/"},
	}
}

// BuildSandboxScan constructs a SandboxSpec for a fresh npm install of
// a specific package version. Exposed so the orchestrator's HTTP path
// (when invoked from the watcher) can produce the same shape.
func BuildSandboxScan(packageName, version string) proto.SandboxSpec {
	return proto.SandboxSpec{
		Image: "node:20-slim",
		Command: []string{
			"sh", "-c",
			"cd /tmp && mkdir -p test && cd test && " +
				"npm init -y >/dev/null 2>&1 && " +
				"npm install " + packageName + "@" + version + " 2>&1 | tail -3; " +
				"sleep 2",
		},
		NetworkMode: "bridge",
		PullPolicy:  "missing",
		User:        "0:0",
		GracePeriod: 2 * time.Second,
	}
}
