// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"net/http"
	"sort"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/api"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// runnerView wraps api.RunnerSnapshot with view-derived flags so the
// template doesn't need helpers to compute liveness.
type runnerView struct {
	api.RunnerSnapshot
	IsStale bool
}

// overviewStats are the headline counters at the top of /ui/.
type overviewStats struct {
	WatchedCount       int
	PackagesTotal      int
	RunsTotal          int
	RunsBaseline       int
	DeviationsTotal    int
	DeviationsPackages int
	EventsDropped      int64 // lifetime sensor ringbuf-reserve failures
}

func (h *Handler) handleOverview(w http.ResponseWriter, r *http.Request) {
	// Only match exact /ui/ here — sub-paths route to their own handlers.
	if r.URL.Path != "/ui/" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()

	stats := overviewStats{}

	if watched, err := h.store.ListWatchedPackages(ctx); err == nil {
		stats.WatchedCount = len(watched)
	} else {
		h.logger.Warn("ui overview: ListWatchedPackages", "err", err)
	}

	pkgs, err := h.store.ListPackages(ctx)
	if err != nil {
		h.logger.Warn("ui overview: ListPackages", "err", err)
	}
	stats.PackagesTotal = len(pkgs)
	for _, p := range pkgs {
		stats.RunsTotal += p.RunsTotal
		stats.RunsBaseline += p.RunsBaseline
	}

	if dropped, err := h.store.EventsDroppedTotal(ctx); err == nil {
		stats.EventsDropped = dropped
	} else {
		h.logger.Warn("ui overview: EventsDroppedTotal", "err", err)
	}

	devs, err := h.store.ListDeviationsFiltered(ctx, storage.DeviationFilter{Limit: 0})
	if err != nil {
		h.logger.Warn("ui overview: ListDeviationsFiltered", "err", err)
	}
	pkgSet := map[string]struct{}{}
	for _, d := range devs {
		stats.DeviationsTotal++
		// We don't store package on the deviation row directly; we'd need
		// the run's package. Skip the pkgSet count for now (best-effort).
		_ = d
	}
	stats.DeviationsPackages = len(pkgSet)

	runners := h.runnersFn()
	sort.Slice(runners, func(i, j int) bool { return runners[i].ID < runners[j].ID })

	// Mark anything quieter than 60s as stale — the runner heartbeats
	// every 30s and the orchestrator prunes at 90s, so 60s is the
	// halfway-warning band.
	const staleAfter = 60 * time.Second
	views := make([]runnerView, 0, len(runners))
	now := time.Now()
	for _, r := range runners {
		views = append(views, runnerView{
			RunnerSnapshot: r,
			IsStale:        !r.LastSeen.IsZero() && now.Sub(r.LastSeen) > staleAfter,
		})
	}

	recentRuns, err := h.store.ListRuns(ctx, 10)
	if err != nil {
		h.logger.Warn("ui overview: ListRuns", "err", err)
	}

	// Latest 10 deviations across all packages.
	recentDeviations, err := h.store.ListDeviationsFiltered(ctx, storage.DeviationFilter{Limit: 10})
	if err != nil {
		h.logger.Warn("ui overview: ListDeviationsFiltered recent", "err", err)
	}

	h.render(w, "overview", map[string]any{
		"Stats":            stats,
		"Runners":          views,
		"RecentRuns":       recentRuns,
		"RecentDeviations": recentDeviations,
	})
}
