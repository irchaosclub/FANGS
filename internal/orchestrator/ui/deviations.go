// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

func (h *Handler) handleDeviations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pkg := r.URL.Query().Get("package")
	sev := r.URL.Query().Get("severity")
	runID := r.URL.Query().Get("run")
	limit := parseLimit(r.URL.Query().Get("limit"), 100, 1000)

	filter := storage.DeviationFilter{
		PackageName: pkg,
		Severity:    sev,
		RunID:       runID,
		Limit:       limit,
	}
	devs, err := h.store.ListDeviationsFiltered(ctx, filter)
	if err != nil {
		h.logger.Warn("ui deviations: ListDeviationsFiltered", "err", err)
	}

	h.render(w, "deviations", map[string]any{
		"Deviations": devs,
		"Filter":     filter,
		"ResultLen":  len(devs),
	})
}

func (h *Handler) handleDeviationDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()

	dev, err := h.store.GetDeviation(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		dev, err = h.store.ResolveDeviationPrefix(ctx, id)
		if errors.Is(err, storage.ErrAmbiguous) {
			http.Error(w, "ambiguous deviation id prefix", http.StatusBadRequest)
			return
		}
		if errors.Is(err, storage.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
	}
	if err != nil {
		h.logger.Warn("ui deviation detail: GetDeviation", "err", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}

	var evidence storage.EventRow
	var evidenceJSON string
	if dev.EvidenceEventID > 0 {
		evidence, err = h.store.GetEvent(ctx, dev.EvidenceEventID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			h.logger.Warn("ui deviation detail: GetEvent", "err", err)
		}
		if evidence.ID > 0 {
			evidenceJSON = prettyJSON(evidence.Data)
		}
	}

	// Also fetch the run for context.
	run, _ := h.store.GetRun(ctx, dev.RunID)

	h.render(w, "deviation_detail", map[string]any{
		"Deviation":    dev,
		"Run":          run,
		"Evidence":     evidence,
		"EvidenceJSON": evidenceJSON,
	})
}

func (h *Handler) handleEventDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	if idStr == "" {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	id, err := parseInt64(idStr)
	if err != nil {
		http.Error(w, "invalid event id", http.StatusBadRequest)
		return
	}
	ev, err := h.store.GetEvent(ctx, id)
	if errors.Is(err, storage.ErrNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		h.logger.Warn("ui event detail: GetEvent", "err", err)
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	h.render(w, "event_detail", map[string]any{
		"Event":     ev,
		"EventJSON": prettyJSON(ev.Data),
	})
}

// prettyJSON normalizes an event payload for the UI's evidence /
// event-detail panes. The wire shape is a 1:1 copy of the kernel's C
// structs — fixed-size byte arrays (Path[256], Comm[16], Argv[8*64],
// Ancestors[5].Comm[16], DestAddr[16], RunID[16]) serialize as long
// integer-array literals that drown out the actual signal. We have
// parallel parsed-string fields (PathName, CommStr, BinaryPathStr,
// ArgvStrs, AncestorComms, DestIP, SNI) already in the payload — keep
// those, drop the raw arrays + the RunID/header padding noise, then
// pretty-print.
//
// Storage stays untouched: this is purely a display filter.
func prettyJSON(raw []byte) string {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		// Not a map (e.g. an array payload) — just pretty-print as-is.
		return rawPrettyJSON(raw)
	}
	stripEventNoise(v)
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return rawPrettyJSON(raw)
	}
	return string(out)
}

// rawPrettyJSON pretty-prints without applying the noise filter.
// Fallback path for payloads that don't parse as a JSON object.
func rawPrettyJSON(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// stripEventNoise rewrites a decoded event map in place to drop the
// fixed-size byte-array fields whose contents are already represented
// by the parsed-string siblings. Also hex-encodes the RunID for
// readability and drops Header.Type (the JSON key already disambiguates).
func stripEventNoise(m map[string]any) {
	// Top-level raw fields that have a parsed parallel. Each entry is
	// the wire-side byte-array field; the parallel parsed string lives
	// under a DIFFERENT key so deleting these is safe.
	//
	// TLSSniEvent intentionally NOT listed: the outer parsed string
	// field also happens to be named "SNI" and shadows the byte array
	// in the JSON output, so the byte array never appears here.
	for _, key := range []string{
		"Path",       // → PathName       (file_access)
		"BinaryPath", // → BinaryPathStr  (exec)
		"Argv",       // → ArgvStrs       (exec)
		"ArgvLens",   // implementation detail; ArgvStrs already split
		"DestAddr",   // → DestIP         (net_connect, dns_query)
		"Query",      // → QName          (dns_query) — raw bytes only useful for parser debug
		"RawPayload", // 512-byte TLS ClientHello capture; drop for now
	} {
		delete(m, key)
	}
	// Header cleanup.
	if hdr, ok := m["Header"].(map[string]any); ok {
		// Comm has CommStr as its parsed parallel.
		delete(hdr, "Comm")
		// Hex-encode RunID for a readable identifier.
		if arr, ok := hdr["RunID"].([]any); ok {
			hdr["RunID"] = bytesToHex(arr)
		}
		// Type is encoded as a uint8 — operators see the event Type at
		// the storage layer (column) so the numeric in-payload field is
		// redundant noise.
		delete(hdr, "Type")
	}
	// Exec ancestors: each entry has Comm[16] byte array; remove since
	// AncestorComms is the parsed parallel.
	if anc, ok := m["Ancestors"].([]any); ok {
		for _, e := range anc {
			if entry, ok := e.(map[string]any); ok {
				delete(entry, "Comm")
			}
		}
	}
}

// bytesToHex turns a JSON-encoded byte array (slice of float64s) into a
// hex string. Tolerant of mixed numeric types; ignores non-numeric
// entries.
func bytesToHex(arr []any) string {
	buf := make([]byte, 0, len(arr))
	for _, v := range arr {
		switch n := v.(type) {
		case float64:
			buf = append(buf, byte(int(n)))
		case int:
			buf = append(buf, byte(n))
		}
	}
	// Trim trailing zeros so a 16-byte RunID with 8 bytes of payload
	// shows as "18b2089cca..." not "18b2089cca...00000000".
	end := len(buf)
	for end > 0 && buf[end-1] == 0 {
		end--
	}
	return fmt.Sprintf("%x", buf[:end])
}

func parseInt64(s string) (int64, error) {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int64(c-'0')
	}
	return n, nil
}
