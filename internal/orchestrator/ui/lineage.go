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

// procNode is one node in the rendered process tree.
type procNode struct {
	PID      uint32
	PPID     uint32
	Comm     string
	Binary   string // populated when we see an exec for this pid
	Events   []eventMarker
	Children []*procNode
	Depth    int

	// IsTarget — this node's pid emitted the target event.
	IsTarget bool
	// HasTargetIn — this node OR any descendant is the target. Used by
	// the template to auto-open the chain back to root.
	HasTargetIn bool

	// EventCounts — per-type counter for the summary chips on the row
	// header. Populated alongside Events during build.
	EventCounts map[string]int
}

// eventMarker is one event entry shown inside an expanded process row.
type eventMarker struct {
	ID       int64
	Type     string
	Summary  string
	Tags     int
	IsTarget bool
}

// lineageView is the data the lineage template renders.
type lineageView struct {
	RunID     string
	Run       storage.Run
	Roots     []*procNode
	NodeCount int
	TargetID  int64
	// Flat is the depth-first walk of the forest. Template iterates this
	// to render the indented row list — each row keeps its Depth for
	// CSS padding-left.
	Flat []*procNode

	// TypeFilter narrows the event chips shown on each process row to
	// one event type. Empty = show all. Each node's Events slice is
	// pre-filtered when this is set; EventCounts always reflects the
	// FULL (unfiltered) tally so the chip-row totals stay stable.
	TypeFilter string

	// AllTypes is the union of event types observed across the whole
	// run — used to render the chip row at the top.
	AllTypes []countEntry

	// TotalEvents is the unfiltered event count for the run; FilteredEvents
	// counts only events matching TypeFilter.
	TotalEvents    int
	FilteredEvents int
}

func (h *Handler) handleLineage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()

	run, err := h.store.GetRun(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
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
		h.logger.Warn("ui lineage: GetRun", "err", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	var targetID int64
	if t := r.URL.Query().Get("event"); t != "" {
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			targetID = n
		}
	}

	events, err := h.store.ListEventsByRun(ctx, run.ID, 5000)
	if err != nil {
		h.logger.Warn("ui lineage: ListEventsByRun", "err", err)
	}

	typeFilter := r.URL.Query().Get("type")

	roots, flat := buildLineage(events, targetID, typeFilter)

	// Aggregate the chip-row totals from the per-node counts. EventCounts
	// is populated for every event regardless of the filter; n.Events
	// only includes events matching the filter (or all when typeFilter
	// is empty).
	totals := map[string]int{}
	totalEvents := 0
	filteredEvents := 0
	for _, n := range flat {
		for t, c := range n.EventCounts {
			totals[t] += c
			totalEvents += c
		}
		filteredEvents += len(n.Events)
	}

	view := lineageView{
		RunID:          run.ID,
		Run:            run,
		Roots:          roots,
		NodeCount:      len(flat),
		TargetID:       targetID,
		Flat:           flat,
		TypeFilter:     typeFilter,
		AllTypes:       sortedCounts(totals),
		TotalEvents:    totalEvents,
		FilteredEvents: filteredEvents,
	}

	h.render(w, "lineage", map[string]any{
		"View": view,
	})
}

// buildLineage walks the events list and produces a process forest plus
// a flat depth-first node list. Each unique PID becomes one node; the
// edge to its parent comes from Header.PPID (or, when an exec event is
// available, the ancestors chain confirms the link).
//
// typeFilter: when non-empty, only events of that type get a Summary
// extracted and attached to the node's Events slice. Counts (used by
// the chip-row totals) always reflect ALL events regardless of the
// filter — operators need to see the full tally to know what's there
// to filter to.
//
// Performance: each event's JSON payload is decoded EXACTLY ONCE per
// call (into a map[string]any reused across the various extractors).
// Previously every extractor did its own Unmarshal, producing
// ~10000 unmarshals per 5000-event run; now it's one per event.
func buildLineage(events []storage.EventRow, targetID int64, typeFilter string) (roots []*procNode, flat []*procNode) {
	byPID := map[uint32]*procNode{}

	upsert := func(pid, ppid uint32, comm string) *procNode {
		n, ok := byPID[pid]
		if !ok {
			n = &procNode{PID: pid, PPID: ppid, Comm: comm, EventCounts: map[string]int{}}
			byPID[pid] = n
			return n
		}
		// Already exists — keep first non-empty comm + first non-zero ppid.
		if n.Comm == "" && comm != "" {
			n.Comm = comm
		}
		if n.PPID == 0 && ppid != 0 {
			n.PPID = ppid
		}
		return n
	}

	for _, ev := range events {
		var body map[string]any
		if err := json.Unmarshal(ev.Data, &body); err != nil {
			continue
		}
		hdr := headerFromBody(body)
		if hdr.PID == 0 {
			continue
		}
		n := upsert(hdr.PID, hdr.PPID, hdr.Comm)

		// Counts are unfiltered — the chip row at the top shows the
		// full tally so the operator knows what filters are available.
		n.EventCounts[ev.Type]++

		// Only the events matching the filter (or all, when no filter)
		// get a Summary extracted + attached. summarizeFromBody re-uses
		// the already-decoded body so there's no second JSON pass.
		isTarget := ev.ID == targetID && targetID != 0
		if typeFilter == "" || ev.Type == typeFilter || isTarget {
			marker := eventMarker{
				ID:       ev.ID,
				Type:     ev.Type,
				Summary:  summarizeFromBody(ev.Type, body),
				Tags:     hdr.Tags,
				IsTarget: isTarget,
			}
			n.Events = append(n.Events, marker)
			if isTarget {
				n.IsTarget = true
			}
		}

		// Exec events ship up to 5 ancestors — record those nodes too so
		// the tree shows the chain even when the ancestors themselves
		// didn't fire events. The binary path of THIS exec belongs to
		// the current process.
		if ev.Type == "exec" {
			if bin := bodyString(body, "BinaryPathStr"); bin != "" {
				n.Binary = bin
			}
			for _, anc := range ancestorsFromBody(body) {
				if anc.PID == 0 {
					continue
				}
				upsert(anc.PID, anc.PPID, anc.Comm)
			}
		}
	}

	// Build parent links.
	for _, n := range byPID {
		if parent, ok := byPID[n.PPID]; ok && parent != n {
			parent.Children = append(parent.Children, n)
		}
	}

	// Roots: nodes whose PPID isn't in the map (or is 0).
	for _, n := range byPID {
		if _, ok := byPID[n.PPID]; !ok || n.PPID == 0 {
			roots = append(roots, n)
		}
	}

	// Stable child ordering — by PID for determinism (events are timestamped
	// but the same logical process tree should render identically across
	// reloads). Roots ordered the same way.
	sort.Slice(roots, func(i, j int) bool { return roots[i].PID < roots[j].PID })
	for _, n := range byPID {
		sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].PID < n.Children[j].PID })
		// Float the target event to the front of each node's chip strip
		// so the visible-chip cap can't hide what the operator came to see.
		if targetID != 0 && len(n.Events) > 1 {
			sort.SliceStable(n.Events, func(i, j int) bool {
				if n.Events[i].IsTarget != n.Events[j].IsTarget {
					return n.Events[i].IsTarget
				}
				return false
			})
		}
	}

	// Propagate HasTargetIn to ancestors of target nodes — used to draw
	// the lineage path with emphasis.
	if targetID != 0 {
		var mark func(n *procNode) bool
		visiting := map[uint32]bool{}
		var dive func(n *procNode) bool
		dive = func(n *procNode) bool {
			if visiting[n.PID] {
				return false
			}
			visiting[n.PID] = true
			defer delete(visiting, n.PID)
			found := n.IsTarget
			for _, c := range n.Children {
				if dive(c) {
					found = true
				}
			}
			if found {
				n.HasTargetIn = true
			}
			return found
		}
		mark = dive
		for _, r := range roots {
			mark(r)
		}
	}

	// Depth-first flatten.
	visited := map[uint32]bool{}
	var visit func(n *procNode, d int)
	visit = func(n *procNode, d int) {
		if visited[n.PID] {
			return
		}
		visited[n.PID] = true
		n.Depth = d
		flat = append(flat, n)
		for _, c := range n.Children {
			visit(c, d+1)
		}
	}
	for _, r := range roots {
		visit(r, 0)
	}
	return roots, flat
}

// --- header / ancestor extraction ---

type lineageHeader struct {
	PID  uint32
	PPID uint32
	Tags int
	Comm string
}

func extractHeader(data []byte) lineageHeader {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return lineageHeader{}
	}
	return headerFromBody(m)
}

// headerFromBody is the cheap path used inside buildLineage where the
// event JSON has already been decoded once. Reads the same fields
// extractHeader does, but skips the Unmarshal.
func headerFromBody(m map[string]any) lineageHeader {
	h, ok := m["Header"].(map[string]any)
	if !ok {
		return lineageHeader{}
	}
	out := lineageHeader{
		PID:  asUint32(h["PID"]),
		PPID: asUint32(h["PPID"]),
		Tags: asInt(h["Tags"]),
	}
	if commStr, ok := m["CommStr"].(string); ok && commStr != "" {
		out.Comm = commStr
	} else {
		out.Comm = readCommBytes(h["Comm"])
	}
	return out
}

// bodyString reads a top-level string field from an already-decoded
// event body. Cheap replacement for extractField when the caller has
// the decoded map in hand.
func bodyString(m map[string]any, field string) string {
	if v, ok := m[field].(string); ok {
		return v
	}
	return ""
}

// summarizeFromBody is the body-cached cousin of summarizeEvent. Saves
// a json.Unmarshal per event when the caller already decoded the
// payload (e.g. buildLineage).
func summarizeFromBody(eventType string, m map[string]any) string {
	switch eventType {
	case "file_access":
		return bodyString(m, "PathName")
	case "exec":
		return bodyString(m, "BinaryPathStr")
	case "net_connect":
		ip := bodyString(m, "DestIP")
		port := ""
		switch p := m["DestPort"].(type) {
		case float64:
			port = strconv.Itoa(int(p))
		case int:
			port = strconv.Itoa(p)
		}
		if port != "" {
			return ip + ":" + port
		}
		return ip
	case "dns_query":
		return bodyString(m, "QName")
	case "tls_sni":
		return bodyString(m, "SNI")
	}
	return ""
}

type lineageAncestor struct {
	PID  uint32
	PPID uint32
	Comm string
}

func extractAncestors(data []byte) []lineageAncestor {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil
	}
	return ancestorsFromBody(m)
}

// ancestorsFromBody is the no-extra-unmarshal sibling of extractAncestors.
func ancestorsFromBody(m map[string]any) []lineageAncestor {
	raw, ok := m["Ancestors"].([]any)
	if !ok {
		// Some decoders capture the parsed AncestorComms slice separately.
		if commsRaw, ok := m["AncestorComms"].([]any); ok {
			out := make([]lineageAncestor, 0, len(commsRaw))
			for _, c := range commsRaw {
				if s, ok := c.(string); ok {
					out = append(out, lineageAncestor{Comm: s})
				}
			}
			return out
		}
		return nil
	}
	out := make([]lineageAncestor, 0, len(raw))
	for _, a := range raw {
		am, ok := a.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, lineageAncestor{
			PID:  asUint32(am["PID"]),
			PPID: asUint32(am["PPID"]),
			Comm: readCommBytes(am["Comm"]),
		})
	}
	return out
}

func asUint32(v any) uint32 {
	switch n := v.(type) {
	case float64:
		return uint32(n)
	case int:
		return uint32(n)
	}
	return 0
}

func asInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return 0
}

// readCommBytes turns a JSON-encoded byte array (e.g. [110, 111, 100, 101,
// 0, 0, 0, 0, ...] for "node") into the trimmed string.
func readCommBytes(v any) string {
	arr, ok := v.([]any)
	if !ok {
		return ""
	}
	buf := make([]byte, 0, len(arr))
	for _, b := range arr {
		bn := asInt(b)
		if bn == 0 {
			break
		}
		buf = append(buf, byte(bn))
	}
	return string(buf)
}
