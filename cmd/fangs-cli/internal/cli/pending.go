// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"flag"
	"fmt"
	"sort"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// pendingRow is one entry in the triage queue — a run with at least
// one non-promoted deviation. Mirrors the /ui/pending structure so
// operators get the same view in both surfaces.
type pendingRow struct {
	Run           storage.Run
	DevCount      int
	MaxSeverity   string
	FirstDetected time.Time
	LastDetected  time.Time
}

func (a *app) pendingCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pending", flag.ContinueOnError)
	pkg := fs.String("package", "", "filter to one package")
	minSev := fs.String("min-severity", "", "low | medium | high | critical (omit = all)")
	limit := fs.Int("limit", 0, "cap on rows returned (0 = no cap)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Walk the most recent N deviations and group by run. 5000 covers any
	// realistic triage backlog; the table is indexed by detected_at.
	devs, err := a.store.ListDeviationsFiltered(ctx, storage.DeviationFilter{
		PackageName: *pkg,
		Limit:       5000,
	})
	if err != nil {
		return fmt.Errorf("list deviations: %w", err)
	}

	byRun := map[string]*pendingRow{}
	for _, d := range devs {
		row, ok := byRun[d.RunID]
		if !ok {
			run, err := a.store.GetRun(ctx, d.RunID)
			if err != nil {
				continue
			}
			// Already-promoted runs (auto or CLI) skip the queue.
			if run.IsBaseline {
				continue
			}
			row = &pendingRow{
				Run:           run,
				FirstDetected: d.DetectedAt,
				LastDetected:  d.DetectedAt,
			}
			byRun[d.RunID] = row
		}
		row.DevCount++
		if pendingSeverityRank(d.Severity) > pendingSeverityRank(row.MaxSeverity) {
			row.MaxSeverity = d.Severity
		}
		if d.DetectedAt.Before(row.FirstDetected) {
			row.FirstDetected = d.DetectedAt
		}
		if d.DetectedAt.After(row.LastDetected) {
			row.LastDetected = d.DetectedAt
		}
	}

	// Min-severity filter (post-grouping so we use the run's max severity).
	minRank := pendingSeverityRank(*minSev)
	rows := make([]*pendingRow, 0, len(byRun))
	for _, r := range byRun {
		if pendingSeverityRank(r.MaxSeverity) < minRank {
			continue
		}
		rows = append(rows, r)
	}
	// Sort: severity desc, then most-recently-detected.
	sort.Slice(rows, func(i, j int) bool {
		ri := pendingSeverityRank(rows[i].MaxSeverity)
		rj := pendingSeverityRank(rows[j].MaxSeverity)
		if ri != rj {
			return ri > rj
		}
		return rows[i].LastDetected.After(rows[j].LastDetected)
	})
	if *limit > 0 && len(rows) > *limit {
		rows = rows[:*limit]
	}

	if a.asJSON {
		return renderJSON(a.out, rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(a.out, "no runs awaiting review.")
		return nil
	}
	headers := []string{"SEVERITY", "RUN", "PACKAGE", "VERSION", "FINDINGS", "DETECTED", "PROMOTE"}
	tbl := make([][]string, 0, len(rows))
	for _, r := range rows {
		tbl = append(tbl, []string{
			r.MaxSeverity,
			shortID(r.Run.ID),
			r.Run.PackageName,
			r.Run.Version,
			fmt.Sprintf("%d", r.DevCount),
			relTime(r.LastDetected),
			"fangs baseline promote " + shortID(r.Run.ID),
		})
	}
	renderTable(a.out, headers, tbl)
	fmt.Fprintf(a.out, "\n%d run%s awaiting review.\n", len(rows), pluralS(len(rows)))
	return nil
}

func pendingSeverityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// relTime — same coarse "5m ago" formatting the UI uses. Local copy so
// the cli package doesn't depend on the ui package.
func relTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	d := time.Since(t)
	switch {
	case d < 0:
		return "future"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
