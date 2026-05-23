// SPDX-License-Identifier: Apache-2.0
//
// Package cli holds the operator console's command dispatch and
// subcommand implementations. Exported entry: Run(ctx, args, stdout,
// stderr). Tests construct in-memory backends and call Run directly,
// asserting on stdout.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/postgres"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/sqlite"
)

// Run dispatches the given argv to the matching subcommand. Caller
// supplies stdout/stderr so tests can capture output.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	globals := flag.NewFlagSet("fangs", flag.ContinueOnError)
	globals.SetOutput(stderr)
	backendKind := globals.String("storage", "sqlite", "storage backend: sqlite | postgres")
	sqlitePath := globals.String("sqlite-path", "var/lib/fangs/fangs.db", "sqlite database file path")
	postgresDSN := globals.String("postgres-dsn", "", "postgres DSN (also reads $FANGS_PG_DSN)")
	asJSON := globals.Bool("json", false, "emit JSON instead of a table")

	// Split argv at the first positional (the subcommand). flag.Parse
	// would stop at any non-flag, but we want global flags to be
	// allowed BEFORE the subcommand only.
	globals.Usage = func() { usage(stderr) }
	if err := globals.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	rest := globals.Args()
	if len(rest) == 0 {
		usage(stderr)
		return errors.New("no subcommand provided")
	}

	store, err := openStore(ctx, *backendKind, *sqlitePath, *postgresDSN)
	if err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	defer store.Close()

	app := &app{store: store, out: stdout, err: stderr, asJSON: *asJSON}
	switch rest[0] {
	case "run":
		return app.runCmd(ctx, rest[1:])
	case "deviation":
		return app.deviationCmd(ctx, rest[1:])
	case "baseline":
		return app.baselineCmd(ctx, rest[1:])
	case "package":
		return app.packageCmd(ctx, rest[1:])
	case "release":
		return app.releaseCmd(ctx, rest[1:])
	case "notifier":
		return app.notifierCmd(ctx, rest[1:])
	case "allow":
		return app.allowCmd(ctx, rest[1:])
	case "scan":
		return app.scanCmd(ctx, rest[1:])
	case "pending":
		return app.pendingCmd(ctx, rest[1:])
	case "help", "-h", "--help":
		usage(stdout)
		return nil
	default:
		usage(stderr)
		return fmt.Errorf("unknown subcommand %q", rest[0])
	}
}

type app struct {
	store  storage.Backend
	out    io.Writer
	err    io.Writer
	asJSON bool
}

func openStore(ctx context.Context, kind, sqlitePath, pgDSN string) (storage.Backend, error) {
	switch kind {
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
			return nil, err
		}
		return b, nil
	case "postgres":
		dsn := pgDSN
		if dsn == "" {
			dsn = os.Getenv("FANGS_PG_DSN")
		}
		if dsn == "" {
			return nil, errors.New("postgres backend requires -postgres-dsn or $FANGS_PG_DSN")
		}
		b, err := postgres.Open(dsn)
		if err != nil {
			return nil, err
		}
		if err := b.Migrate(ctx); err != nil {
			_ = b.Close()
			return nil, err
		}
		return b, nil
	default:
		return nil, fmt.Errorf("unknown -storage %q", kind)
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `fangs - operator console for the FANGS NPM supply-chain monitor

Usage:
  fangs [global flags] <subcommand> [args]

Subcommands:
  run list [-package P] [-limit N]
  run show <run_id>
  deviation list [-package P] [-severity S] [-run-id R] [-limit N]
  deviation show <deviation_id>
  baseline list [-package P]
  baseline promote <run_id>
  package list                       all packages with run summaries
  package watched                    just the watched packages
  package add <name>                 add a package to the watcher
  package remove <name>              remove from the watcher
  release list -package P [-limit N] releases captured by the watcher
  notifier list                      configured webhook targets
  notifier add -name N -url U -template slack|discord|generic [-secret-env E] [-min-severity S] [-headers JSON]
  notifier remove <name>             delete a target
  notifier test <name>               fire a synthetic test notification
  notifier history -run R            delivery attempts for a run
  allow list [-package P]            allowlist entries (global + per-package)
  allow add -kind cidr|path|sni -value V [-package P] [-note N]
                                     scope = package when -package set, else global
  allow remove <id_prefix>           delete an entry by id (or unique prefix)
  scan submit -package P -version V [-orchestrator URL] [-runner ID]
                                     queue a one-off sandbox scan
  pending [-package P] [-min-severity S] [-limit N]
                                     runs awaiting baseline-promote (the triage queue)

Global flags:
  -storage      sqlite|postgres   (default: sqlite)
  -sqlite-path  PATH               (default: var/lib/fangs/fangs.db)
  -postgres-dsn DSN                (also reads $FANGS_PG_DSN)
  -json                            emit JSON instead of table

Examples:
  fangs package list
  fangs run list -package chalk -limit 10
  fangs deviation list -severity warn -limit 20
  fangs baseline promote 18b1f8...
`)
}
