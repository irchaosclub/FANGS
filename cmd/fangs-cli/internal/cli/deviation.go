// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (a *app) deviationCmd(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("deviation: missing subcommand (list|show)")
	}
	switch args[0] {
	case "list":
		return a.deviationList(ctx, args[1:])
	case "show":
		return a.deviationShow(ctx, args[1:])
	default:
		return fmt.Errorf("deviation: unknown subcommand %q", args[0])
	}
}

func (a *app) deviationList(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("deviation list", flag.ContinueOnError)
	fs.SetOutput(a.err)
	pkg := fs.String("package", "", "filter by package_name")
	sev := fs.String("severity", "", "filter by severity (info|warn|crit)")
	runID := fs.String("run-id", "", "filter by run_id")
	limit := fs.Int("limit", 50, "max rows")
	if err := fs.Parse(args); err != nil {
		return err
	}

	devs, err := a.store.ListDeviationsFiltered(ctx, storage.DeviationFilter{
		PackageName: *pkg,
		Severity:    *sev,
		RunID:       *runID,
		Limit:       *limit,
	})
	if err != nil {
		return err
	}
	if a.asJSON {
		return renderJSON(a.out, devs)
	}
	rows := make([][]string, 0, len(devs))
	for _, d := range devs {
		when := "-"
		if !d.DetectedAt.IsZero() {
			when = d.DetectedAt.UTC().Format("2006-01-02 15:04:05")
		}
		rows = append(rows, []string{
			shortID(d.ID),
			when,
			d.Severity,
			d.Category,
			truncate(d.Value, 60),
			shortID(d.RunID),
		})
	}
	renderTable(a.out, []string{"DEV_ID", "DETECTED", "SEV", "CATEGORY", "VALUE", "RUN_ID"}, rows)
	return nil
}

func (a *app) deviationShow(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("deviation show: missing deviation_id argument")
	}
	d, err := a.store.ResolveDeviationPrefix(ctx, args[0])
	if err != nil {
		return err
	}
	evt, evtErr := a.store.GetEvent(ctx, d.EvidenceEventID)

	if a.asJSON {
		out := map[string]any{"deviation": d}
		if evtErr == nil {
			out["evidence_event"] = map[string]any{
				"id":    evt.ID,
				"ts_ns": evt.TsNS,
				"type":  evt.Type,
				"data":  json.RawMessage(evt.Data),
			}
		}
		return renderJSON(a.out, out)
	}

	fmt.Fprintf(a.out, "Deviation %s\n", d.ID)
	fmt.Fprintf(a.out, "  run_id:    %s\n", d.RunID)
	fmt.Fprintf(a.out, "  category:  %s\n", d.Category)
	fmt.Fprintf(a.out, "  value:     %s\n", d.Value)
	fmt.Fprintf(a.out, "  severity:  %s\n", d.Severity)
	if !d.DetectedAt.IsZero() {
		fmt.Fprintf(a.out, "  detected:  %s\n", d.DetectedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	fmt.Fprintf(a.out, "  suppressed: %v\n", d.Suppressed)
	fmt.Fprintln(a.out)

	if evtErr != nil {
		fmt.Fprintf(a.out, "evidence event (id=%d): %v\n", d.EvidenceEventID, evtErr)
		return nil
	}
	fmt.Fprintf(a.out, "Evidence event #%d (type=%s, ts_ns=%d):\n", evt.ID, evt.Type, evt.TsNS)
	var pretty map[string]any
	if err := json.Unmarshal(evt.Data, &pretty); err == nil {
		b, _ := json.MarshalIndent(pretty, "  ", "  ")
		fmt.Fprintf(a.out, "  %s\n", b)
	} else {
		fmt.Fprintf(a.out, "  %s\n", evt.Data)
	}
	return nil
}
