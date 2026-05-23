// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (h *Handler) handleRuns(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pkg := r.URL.Query().Get("package")
	limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)

	var runs []storage.Run
	var err error
	if pkg != "" {
		runs, err = h.store.ListRunsByPackage(ctx, pkg, limit)
	} else {
		runs, err = h.store.ListRuns(ctx, limit)
	}
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		h.logger.Warn("ui runs: ListRuns", "err", err)
	}

	h.render(w, "runs", map[string]any{
		"Runs":      runs,
		"Filter":    pkg,
		"Limit":     limit,
		"ResultLen": len(runs),
	})
}

// runEventSummary holds an aggregated event count per type for the run
// detail header.
type runEventSummary struct {
	Type  string
	Count int
}

// formattedEvent is one event row in the run-detail table — pre-shaped so
// the template doesn't need to do JSON decoding.
type formattedEvent struct {
	ID      int64
	Type    string
	Comm    string
	Summary string
	Tags    int
}

func (h *Handler) handleRunDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()

	run, err := h.store.GetRun(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		// Try prefix-match (git-style short IDs).
		run, err = h.store.ResolveRunPrefix(ctx, id)
		if errors.Is(err, storage.ErrAmbiguous) {
			http.Error(w, "ambiguous run id prefix", http.StatusBadRequest)
			return
		}
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
	}
	if err != nil {
		h.logger.Warn("ui run detail: GetRun", "err", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	events, err := h.store.ListEventsByRun(ctx, run.ID, 500)
	if err != nil {
		h.logger.Warn("ui run detail: ListEventsByRun", "err", err)
	}

	// Compute the per-type tally over ALL events first so the chip row
	// at the top stays stable as the operator filters down.
	summaryMap := map[string]int{}
	for _, ev := range events {
		summaryMap[ev.Type]++
	}
	summary := make([]runEventSummary, 0, len(summaryMap))
	for t, n := range summaryMap {
		summary = append(summary, runEventSummary{Type: t, Count: n})
	}
	// Stable display order so clicking a chip doesn't reshuffle the row
	// (Go map iteration is random; without this the chips dance every
	// page load). Same priority used by sortedCounts in ui.go — high-
	// signal types first.
	sort.SliceStable(summary, func(i, j int) bool {
		return chipOrderRank(summary[i].Type) < chipOrderRank(summary[j].Type)
	})

	// ?type=<event_type> filter (empty = show all). The chip row links
	// build these URLs.
	typeFilter := r.URL.Query().Get("type")
	formatted := make([]formattedEvent, 0, len(events))
	for _, ev := range events {
		if typeFilter != "" && ev.Type != typeFilter {
			continue
		}
		formatted = append(formatted, formattedEvent{
			ID:      ev.ID,
			Type:    ev.Type,
			Comm:    extractField(ev.Data, "CommStr"),
			Summary: summarizeEvent(ev.Type, ev.Data),
			Tags:    extractTags(ev.Data),
		})
	}

	deviations, err := h.store.ListDeviations(ctx, run.ID)
	if err != nil {
		h.logger.Warn("ui run detail: ListDeviations", "err", err)
	}

	h.render(w, "run_detail", map[string]any{
		"Run":         run,
		"Events":      formatted,
		"EventCount":  len(formatted),
		"TotalEvents": len(events),
		"Summary":     summary,
		"TypeFilter":  typeFilter,
		"Deviations":  deviations,
	})
}

func parseLimit(raw string, def, max int) int {
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// extractField pulls a top-level string field from a JSON-encoded event
// payload. Returns "" on any parse failure or missing key.
func extractField(data []byte, field string) string {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}

// extractTags reads Header.Tags from a JSON-encoded event.
func extractTags(data []byte) int {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return 0
	}
	h, ok := m["Header"].(map[string]any)
	if !ok {
		return 0
	}
	switch v := h["Tags"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// summarizeEvent produces a one-line human description for an event row,
// e.g. file path, net dest, SNI, exec binary. Type-specific — used in the
// run-detail event list.
func summarizeEvent(eventType string, data []byte) string {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return ""
	}
	switch eventType {
	case "file_access":
		return asString(m["PathName"])
	case "exec":
		bin := asString(m["BinaryPathStr"])
		return bin
	case "net_connect":
		ip := asString(m["DestIP"])
		port := asNumberStr(m["DestPort"])
		if port != "" {
			return ip + ":" + port
		}
		return ip
	case "dns_query":
		return asString(m["QName"])
	case "tls_sni":
		return asString(m["SNI"])
	}
	return ""
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asNumberStr(v any) string {
	switch n := v.(type) {
	case float64:
		return strconv.Itoa(int(n))
	case int:
		return strconv.Itoa(n)
	}
	return ""
}
