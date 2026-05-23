// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (a *app) runCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("run: missing subcommand (list|show)")
	}
	switch args[0] {
	case "list":
		return a.runList(ctx, args[1:])
	case "show":
		return a.runShow(ctx, args[1:])
	default:
		return fmt.Errorf("run: unknown subcommand %q", args[0])
	}
}

func (a *app) runList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run list", flag.ContinueOnError)
	fs.SetOutput(a.err)
	pkg := fs.String("package", "", "filter by package_name")
	limit := fs.Int("limit", 50, "max rows")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var runs []storage.Run
	var err error
	if *pkg != "" {
		runs, err = a.store.ListRunsByPackage(ctx, *pkg, *limit)
	} else {
		runs, err = a.store.ListRuns(ctx, *limit)
	}
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, runs)
	}
	rows := make([][]string, 0, len(runs))
	for _, r := range runs {
		baseline := "·"
		if r.IsBaseline {
			baseline = "★"
		}
		started := "-"
		if r.StartedAt != nil {
			started = r.StartedAt.Format("2006-01-02 15:04:05")
		}
		rows = append(rows, []string{
			shortID(r.ID),
			truncate(r.PackageName, 24),
			r.Version,
			string(r.State),
			baseline,
			started,
		})
	}
	renderTable(a.out, []string{"RUN_ID", "PACKAGE", "VERSION", "STATE", "BASE", "STARTED"}, rows)
	return nil
}

func (a *app) runShow(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("run show: missing run_id argument")
	}
	run, err := a.store.ResolveRunPrefix(ctx, args[0])
	if err != nil {
		return err
	}
	id := run.ID
	devs, err := a.store.ListDeviations(ctx, id)
	if err != nil {
		return err
	}
	evtCount, err := a.store.EventCount(ctx, id)
	if err != nil {
		return err
	}

	if a.asJSON {
		return renderJSON(a.out, map[string]any{
			"run":         run,
			"deviations":  devs,
			"event_count": evtCount,
		})
	}

	fmt.Fprintf(a.out, "Run %s\n", run.ID)
	fmt.Fprintf(a.out, "  package:    %s\n", run.PackageName)
	fmt.Fprintf(a.out, "  version:    %s\n", run.Version)
	fmt.Fprintf(a.out, "  state:      %s\n", run.State)
	fmt.Fprintf(a.out, "  attempt:    %d\n", run.Attempt)
	fmt.Fprintf(a.out, "  baseline:   %v\n", run.IsBaseline)
	if run.StartedAt != nil {
		fmt.Fprintf(a.out, "  started_at: %s\n", run.StartedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if run.FinishedAt != nil {
		fmt.Fprintf(a.out, "  finished_at: %s\n", run.FinishedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if run.FailureReason != "" {
		fmt.Fprintf(a.out, "  failure:    %s\n", run.FailureReason)
	}
	fmt.Fprintf(a.out, "  events:     %s\n", strconv.FormatInt(evtCount, 10))
	fmt.Fprintf(a.out, "  deviations: %d\n", len(devs))

	if len(devs) > 0 {
		fmt.Fprintln(a.out)
		rows := make([][]string, 0, len(devs))
		for _, d := range devs {
			rows = append(rows, []string{
				shortID(d.ID),
				d.Severity,
				d.Category,
				truncate(d.Value, 60),
			})
		}
		renderTable(a.out, []string{"DEV_ID", "SEV", "CATEGORY", "VALUE"}, rows)
	}
	return nil
}
