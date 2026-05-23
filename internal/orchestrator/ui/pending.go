// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"net/http"
	"sort"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// pendingRow aggregates one run's outstanding deviations into a single
// triage row.
type pendingRow struct {
	Run           storage.Run
	DevCount      int
	MaxSeverity   string
	FirstDetected time.Time
	LastDetected  time.Time
}

// handlePending lists runs whose deviations haven't been accepted into
// baseline yet — the human-decision queue. A run appears here iff:
//
//   - it has at least one row in the deviations table
//   - is_baseline = false on the run row (auto-promoted or
//     CLI-promoted runs are filtered out)
//
// Built by walking recent deviations (capped to keep the query cheap)
// and grouping by run_id; each unique run is enriched with a Run row
// for package + version.
func (h *Handler) handlePending(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Pull a generous slice of recent deviations. Cap big enough to
	// cover any realistic triage backlog; the DB-side query is indexed
	// on detected_at.
	devs, err := h.store.ListDeviationsFiltered(ctx, storage.DeviationFilter{Limit: 1000})
	if err != nil {
		h.logger.Warn("ui pending: ListDeviationsFiltered", "err", err)
	}

	rowsByRun := map[string]*pendingRow{}
	for _, d := range devs {
		row, ok := rowsByRun[d.RunID]
		if !ok {
			run, err := h.store.GetRun(ctx, d.RunID)
			if err != nil {
				continue // run row gone (pruned, deleted) — skip
			}
			// Auto-promoted or CLI-promoted runs shouldn't appear in the
			// triage queue. Deviation rows are cleared on promote but
			// guard defensively in case the operator manually flipped
			// is_baseline without going through the CLI.
			if run.IsBaseline {
				continue
			}
			row = &pendingRow{
				Run:           run,
				FirstDetected: d.DetectedAt,
				LastDetected:  d.DetectedAt,
			}
			rowsByRun[d.RunID] = row
		}
		row.DevCount++
		if severityRank(d.Severity) > severityRank(row.MaxSeverity) {
			row.MaxSeverity = d.Severity
		}
		if d.DetectedAt.Before(row.FirstDetected) {
			row.FirstDetected = d.DetectedAt
		}
		if d.DetectedAt.After(row.LastDetected) {
			row.LastDetected = d.DetectedAt
		}
	}

	list := make([]*pendingRow, 0, len(rowsByRun))
	for _, r := range rowsByRun {
		list = append(list, r)
	}
	// Sort: highest severity first, then most-recently-detected.
	sort.Slice(list, func(i, j int) bool {
		ri := severityRank(list[i].MaxSeverity)
		rj := severityRank(list[j].MaxSeverity)
		if ri != rj {
			return ri > rj
		}
		return list[i].LastDetected.After(list[j].LastDetected)
	})

	h.render(w, "pending", map[string]any{
		"Rows":  list,
		"Total": len(list),
	})
}

// severityRank — higher = more severe. Local to the UI package because
// the differ + notifier each have their own (intentionally — no
// cross-package dependency on a constant).
func severityRank(s string) int {
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
