// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"

	"github.com/irchaosclub/FANGS/internal/orchestrator/differ"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (a *app) baselineCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("baseline: missing subcommand (list|promote)")
	}
	switch args[0] {
	case "list":
		return a.baselineList(ctx, args[1:])
	case "promote":
		return a.baselinePromote(ctx, args[1:])
	default:
		return fmt.Errorf("baseline: unknown subcommand %q", args[0])
	}
}

func (a *app) baselineList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("baseline list", flag.ContinueOnError)
	fs.SetOutput(a.err)
	pkg := fs.String("package", "", "package_name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pkg == "" {
		return errors.New("baseline list: -package is required")
	}
	baseline, err := a.store.LoadBaseline(ctx, *pkg)
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, baseline)
	}
	rows := make([][]string, 0, len(baseline))
	for _, b := range baseline {
		rows = append(rows, []string{
			b.Category,
			truncate(b.Value, 60),
			fmt.Sprintf("%d", b.OccurrenceCount),
			shortID(b.FirstSeenRunID),
			shortID(b.LastSeenRunID),
		})
	}
	renderTable(a.out, []string{"CATEGORY", "VALUE", "COUNT", "FIRST_SEEN", "LAST_SEEN"}, rows)
	return nil
}

// baselinePromote manually adds a run's fingerprints to the package
// baseline. Use this to accept a run that had deviations after human
// review — the next run will see those values as "known" instead of
// flagging them again.
func (a *app) baselinePromote(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("baseline promote: missing run_id argument")
	}
	run, err := a.store.ResolveRunPrefix(ctx, args[0])
	if err != nil {
		return err
	}
	runID := run.ID
	if run.PackageName == "" {
		return errors.New("baseline promote: run has empty package_name")
	}
	events, err := a.store.ListEventsByRun(ctx, runID, 0)
	if err != nil {
		return err
	}
	// Apply the same allowlist filter the orchestrator's Differ uses, so
	// CLI-driven promotes don't accidentally bake suppressed entries
	// into the baseline.
	allEntries, _ := a.store.ListAllowEntries(ctx)
	filter := differ.NewFilter(storage.EntriesForPackage(allEntries, run.PackageName), nil)
	fps := differ.ExtractFingerprintsWith(events, filter)
	rows := make([]storage.BaselineRow, 0, len(fps))
	for _, fp := range fps {
		rows = append(rows, storage.BaselineRow{
			PackageName:     run.PackageName,
			Category:        string(fp.Category),
			Value:           fp.Value,
			FirstSeenRunID:  runID,
			LastSeenRunID:   runID,
			OccurrenceCount: fp.Count,
		})
	}
	if err := a.store.MergeBaseline(ctx, runID, rows); err != nil {
		return err
	}
	if err := a.store.MarkRunBaseline(ctx, runID, true); err != nil {
		return err
	}
	// Also clear the deviations for this run, since it's been approved.
	if err := a.store.DeleteDeviationsForRun(ctx, runID); err != nil {
		fmt.Fprintf(a.err, "warning: could not clear deviations: %v\n", err)
	}
	if a.asJSON {
		return renderJSON(a.out, map[string]any{
			"run_id":              runID,
			"package":             run.PackageName,
			"fingerprints_merged": len(rows),
			"promoted":            true,
		})
	}
	fmt.Fprintf(a.out, "Promoted run %s (package=%s) to baseline.\n", shortID(runID), run.PackageName)
	fmt.Fprintf(a.out, "Merged %d fingerprints into baseline_fingerprints.\n", len(rows))
	return nil
}
