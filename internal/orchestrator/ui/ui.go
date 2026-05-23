// SPDX-License-Identifier: Apache-2.0
//
// Package ui hosts FANGS's read-only operator dashboard. Server-rendered
// Go templates, no JS framework, no build step. Mounted onto the
// orchestrator's HTTP mux under /ui/ (page routes) and /static/ (assets).
//
// The UI is intentionally read-only: every state-changing action
// (promote, reject, package add/remove) stays in the `fangs` CLI to
// keep the authoritative path explicit and scriptable. The UI is for
// browsing + ops awareness.
//
// Wiring (typical):
//
//	mux := http.NewServeMux()
//	apiSrv.Mount(mux)
//	ui.New(ui.Options{
//	    Store:        store,
//	    Dispatcher:   disp,
//	    RunnersFn:    apiSrv.RegisteredRunnersDetail,
//	}).Mount(mux)
//	apiSrv.ServeWith(ctx, mux)
package ui

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/api"
	"github.com/irchaosclub/FANGS/internal/orchestrator/core"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/shared/proto"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

// Options configures the UI handler. Storage + RunnersFn are required;
// Dispatcher is optional (queue-depth metrics omitted when nil).
type Options struct {
	Store      storage.Backend
	Dispatcher *core.Dispatcher
	RunnersFn  func() []api.RunnerSnapshot
	Logger     *slog.Logger
	// Version is rendered in the footer for build-info.
	Version string

	// EffectiveWatchedPaths is the watched-path list the orchestrator
	// is actually stamping onto incoming jobs — config merged with the
	// hardcoded fallback. Shown on /ui/config.
	EffectiveWatchedPaths []proto.WatchedPath
	// ConfigPath is the path the YAML was loaded from (or attempted —
	// reported even when missing so the operator sees where to put a
	// file).
	ConfigPath string
}

// Handler implements http.Handler for the /ui/ and /static/ routes.
//
// Templates are parsed per-page: each page's content template gets paired
// with layout.html into its own *template.Template. This is the standard
// way to handle a shared layout in html/template — defining {{define
// "content"}} in every file would have them stomp each other at parse
// time (last one wins).
type Handler struct {
	store          storage.Backend
	disp           *core.Dispatcher
	runnersFn      func() []api.RunnerSnapshot
	logger         *slog.Logger
	version        string
	effectivePaths []proto.WatchedPath
	configPath     string
	pages          map[string]*template.Template
	staticHTTP     http.Handler
}

// New constructs a Handler with templates parsed from the embedded FS.
// Returns an error if templates fail to parse — the caller should treat
// that as fatal at startup.
func New(opts Options) (*Handler, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("ui: Store is required")
	}
	if opts.RunnersFn == nil {
		opts.RunnersFn = func() []api.RunnerSnapshot { return nil }
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	pages, err := parsePages()
	if err != nil {
		return nil, fmt.Errorf("ui: parse templates: %w", err)
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, fmt.Errorf("ui: sub static: %w", err)
	}

	return &Handler{
		store:          opts.Store,
		disp:           opts.Dispatcher,
		runnersFn:      opts.RunnersFn,
		logger:         logger,
		version:        opts.Version,
		effectivePaths: opts.EffectiveWatchedPaths,
		configPath:     opts.ConfigPath,
		pages:          pages,
		staticHTTP:     http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))),
	}, nil
}

// parsePages walks the embedded templates dir and builds one
// *template.Template per page (= per non-layout file). Each pairs the
// layout with exactly one content template.
func parsePages() (map[string]*template.Template, error) {
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		return nil, err
	}
	pages := make(map[string]*template.Template)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == "layout.html" {
			continue
		}
		page := name
		if i := len(page) - len(".html"); i > 0 && page[i:] == ".html" {
			page = page[:i]
		}
		t, err := template.New(page).Funcs(funcMap()).ParseFS(templatesFS, "templates/layout.html", "templates/"+name)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", name, err)
		}
		pages[page] = t
	}
	return pages, nil
}

// Mount registers the UI routes on mux. Pattern is /ui/* for pages and
// /static/* for assets; / 302s to /ui/.
func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /", h.handleRoot)
	mux.HandleFunc("GET /ui/", h.handleOverview)
	mux.HandleFunc("GET /ui/packages", h.handlePackages)
	mux.HandleFunc("GET /ui/packages/{name}", h.handlePackageDetail)
	mux.HandleFunc("GET /ui/runs", h.handleRuns)
	mux.HandleFunc("GET /ui/runs/{id}", h.handleRunDetail)
	mux.HandleFunc("GET /ui/runs/{id}/lineage", h.handleLineage)
	mux.HandleFunc("GET /ui/deviations", h.handleDeviations)
	mux.HandleFunc("GET /ui/deviations/{id}", h.handleDeviationDetail)
	mux.HandleFunc("GET /ui/events/{id}", h.handleEventDetail)
	mux.HandleFunc("GET /ui/pending", h.handlePending)
	mux.HandleFunc("GET /ui/allowlist", h.handleAllowlist)
	mux.HandleFunc("GET /ui/notifiers", h.handleNotifiers)
	mux.HandleFunc("GET /ui/config", h.handleConfig)
	mux.Handle("GET /static/", h.staticHTTP)
}

// handleRoot redirects bare / to the overview. Anything else under / that
// the API didn't claim gets a 404.
func (h *Handler) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		http.Redirect(w, r, "/ui/", http.StatusFound)
		return
	}
	http.NotFound(w, r)
}

// render executes the named page template (which includes layout + that
// page's content) and writes it to the response. On template error,
// writes 500 + logs.
func (h *Handler) render(w http.ResponseWriter, page string, data map[string]any) {
	tpl, ok := h.pages[page]
	if !ok {
		h.logger.Error("ui template not found", "page", page)
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]any{}
	}
	data["Page"] = page
	data["Version"] = h.version
	data["Now"] = time.Now()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tpl.ExecuteTemplate(w, "layout.html", data); err != nil {
		h.logger.Error("ui template render", "page", page, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// funcMap defines the template helpers shared by every page.
func funcMap() template.FuncMap {
	return template.FuncMap{
		"shortID":      shortID,
		"relTime":      relTime,
		"formatTS":     formatTS,
		"truncate":     truncate,
		"severity":     severityClass,
		"derefTime":    derefTime,
		"join":         joinStrings,
		"add":          func(a, b int) int { return a + b },
		"mul":          func(a, b int) int { return a * b },
		"chipColor":    chipColorClass,
		"sortedCounts": sortedCounts,
		"nsToDuration": nsToDuration,
		"hasPrefix": func(s, prefix string) bool {
			return len(s) >= len(prefix) && s[:len(prefix)] == prefix
		},
	}
}

// chipOrderRank returns a small integer "sort priority" for an event
// type. Lower = earlier in chip rows. Shared by run-detail + lineage
// so the same chip-row ordering applies everywhere.
//
// Priority: exec (process lifecycle, highest signal) → net_connect →
// dns_query → tls_sni → file_access (highest volume, lowest signal
// per row). Unknown types sink to the end alphabetically.
func chipOrderRank(t string) int {
	switch t {
	case "exec":
		return 1
	case "net_connect":
		return 2
	case "dns_query":
		return 3
	case "tls_sni":
		return 4
	case "file_access":
		return 5
	}
	return 99
}

// chipColorClass returns the CSS class for an event-type chip.
func chipColorClass(eventType string) string {
	switch eventType {
	case "file_access":
		return "chip-file"
	case "exec":
		return "chip-exec"
	case "net_connect":
		return "chip-net"
	case "dns_query":
		return "chip-dns"
	case "tls_sni":
		return "chip-tls"
	}
	return "chip-info"
}

// countEntry is one row in sortedCounts output. Templates can't range
// over Go maps with a stable order, so we hand them a sorted slice.
type countEntry struct {
	Type  string
	Count int
}

// nsToDuration formats a nanosecond count as a human-friendly duration
// string (e.g. "4.3s", "12.7m"). Used by the run detail card.
func nsToDuration(ns int64) string {
	d := time.Duration(ns)
	if d == 0 {
		return "—"
	}
	if d < time.Millisecond {
		return d.String()
	}
	// Round to two significant places for readability.
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	if d < time.Minute {
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

func sortedCounts(m map[string]int) []countEntry {
	out := make([]countEntry, 0, len(m))
	for k, v := range m {
		out = append(out, countEntry{Type: k, Count: v})
	}
	// Shared rank with the run-detail chip row + lineage chip row so
	// chips never reshuffle when you click one.
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := chipOrderRank(out[i].Type), chipOrderRank(out[j].Type)
		if ri != rj {
			return ri < rj
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func formatTS(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Format("2006-01-02 15:04:05")
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// relTime formats t as a coarse "5m ago" / "2h ago" / "3d ago" string.
// Returns "—" for zero time.
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

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// severityClass maps a Differ severity string to a CSS class for the
// colored severity badge.
func severityClass(s string) string {
	switch s {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	default:
		return "sev-info"
	}
}

func joinStrings(sep string, in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}
