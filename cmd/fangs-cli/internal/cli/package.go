// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/watcher"
)

func (a *app) packageCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("package: missing subcommand (list|add|remove|watched)")
	}
	switch args[0] {
	case "list":
		return a.packageList(ctx)
	case "add":
		return a.packageAdd(ctx, args[1:])
	case "remove", "rm":
		return a.packageRemove(ctx, args[1:])
	case "watched":
		return a.packageWatched(ctx)
	default:
		return fmt.Errorf("package: unknown subcommand %q", args[0])
	}
}

func (a *app) packageAdd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("package add", flag.ContinueOnError)
	orchestrator := fs.String("orchestrator", "http://127.0.0.1:8443", "orchestrator base URL for the kickoff scan")
	runner := fs.String("runner", "", "target runner id for the kickoff scan (default: server picks)")
	skipScan := fs.Bool("skip-initial-scan", false, "don't auto-submit a scan of the current latest version")
	skipValidate := fs.Bool("skip-registry-validate", false, "don't verify the package exists on the npm registry")
	duration := fs.Duration("duration", 60*time.Second, "max sandbox duration for the kickoff scan")
	if err := fs.Parse(args); err != nil {
		return err
	}
	posArgs := fs.Args()
	if len(posArgs) == 0 {
		return errors.New("package add: missing package name")
	}
	name := posArgs[0]

	// Refuse to silently re-add. ListWatchedPackages is small enough
	// (operator-curated list) that a linear scan beats threading a new
	// storage method.
	watched, err := a.store.ListWatchedPackages(ctx)
	if err != nil {
		return fmt.Errorf("list watched: %w", err)
	}
	for _, w := range watched {
		if w.Name == name {
			return fmt.Errorf("package %q is already watched (added %s)",
				name, w.AddedAt.UTC().Format(time.RFC3339))
		}
	}

	// Validate against the registry — and grab the latest version in
	// the same call so we can kick off an immediate scan.
	var latest watcher.PackageVersion
	if !*skipValidate {
		reg := watcher.NewNPMRegistry()
		latest, err = reg.Resolve(ctx, name, "")
		if err != nil {
			if errors.Is(err, watcher.ErrPackageNotFound) {
				return fmt.Errorf("package add: %q not found on registry.npmjs.org", name)
			}
			return fmt.Errorf("package add: registry lookup failed: %w", err)
		}
	}

	if err := a.store.AddWatchedPackage(ctx, name); err != nil {
		return err
	}
	// Stamp last_seen_version so the next watcher poll doesn't re-flag
	// the current latest as "newly observed" (which would queue a
	// duplicate of the kickoff scan we're about to submit).
	if latest.Version != "" {
		_ = a.store.UpdatePackageCheck(ctx, name, latest.Version)
	}

	// Kick off a scan of the current latest. Without this, the operator
	// has to wait up to -watch-interval (default 5m) for the autonomous
	// watcher loop to discover the package — frustrating after manual
	// `package add`.
	var runID string
	if !*skipScan && latest.Version != "" {
		runID, err = a.submitScan(ctx, *orchestrator, *runner, name, latest.Version, *duration)
		if err != nil {
			// Don't roll back the package add — the row is useful even
			// if the kickoff scan failed (operator can fix the
			// orchestrator URL and retry via scan submit).
			fmt.Fprintf(a.err, "warning: added watch but kickoff scan failed: %v\n", err)
		}
	}

	if a.asJSON {
		out := map[string]any{
			"package":        name,
			"added":          true,
			"latest_version": latest.Version,
		}
		if runID != "" {
			out["kickoff_run_id"] = runID
		}
		return renderJSON(a.out, out)
	}
	fmt.Fprintf(a.out, "added %q to watched packages", name)
	if latest.Version != "" {
		fmt.Fprintf(a.out, " (latest: %s)", latest.Version)
	}
	fmt.Fprintln(a.out)
	if runID != "" {
		fmt.Fprintf(a.out, "kickoff scan queued: run_id=%s\n", shortID(runID))
		fmt.Fprintf(a.out, "watch: %s/ui/runs/%s\n", *orchestrator, runID)
	} else if *skipScan {
		fmt.Fprintln(a.out, "kickoff scan skipped (-skip-initial-scan).")
	} else if latest.Version == "" {
		fmt.Fprintln(a.out, "kickoff scan skipped (registry validation off, no version known).")
	}
	return nil
}

func (a *app) packageRemove(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("package remove: missing package name")
	}
	name := args[0]
	if err := a.store.RemoveWatchedPackage(ctx, name); err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, map[string]any{"package": name, "removed": true})
	}
	fmt.Fprintf(a.out, "removed %q from watched packages\n", name)
	return nil
}

func (a *app) packageWatched(ctx context.Context) error {
	pkgs, err := a.store.ListWatchedPackages(ctx)
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, pkgs)
	}
	rows := make([][]string, 0, len(pkgs))
	for _, p := range pkgs {
		lastCheck := "(never)"
		if p.LastCheckedAt != nil {
			lastCheck = p.LastCheckedAt.UTC().Format("2006-01-02 15:04:05")
		}
		ver := p.LastSeenVersion
		if ver == "" {
			ver = "-"
		}
		rows = append(rows, []string{
			p.Name,
			p.AddedAt.UTC().Format("2006-01-02 15:04:05"),
			lastCheck,
			ver,
		})
	}
	renderTable(a.out, []string{"PACKAGE", "ADDED", "LAST_CHECKED", "LAST_SEEN"}, rows)
	return nil
}

func (a *app) packageList(ctx context.Context) error {
	pkgs, err := a.store.ListPackages(ctx)
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, pkgs)
	}
	rows := make([][]string, 0, len(pkgs))
	for _, p := range pkgs {
		rows = append(rows, []string{
			p.Name,
			fmt.Sprintf("%d", p.RunsTotal),
			fmt.Sprintf("%d", p.RunsBaseline),
			p.LatestVersion,
			fmt.Sprintf("%d", p.DeviationsLatest),
			shortID(p.LatestRunID),
		})
	}
	renderTable(a.out, []string{"PACKAGE", "RUNS", "BASELINES", "LATEST_VERSION", "LATEST_DEVS", "LATEST_RUN"}, rows)
	return nil
}
