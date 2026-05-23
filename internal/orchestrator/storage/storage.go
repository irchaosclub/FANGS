// SPDX-License-Identifier: Apache-2.0
//
// Package storage is the orchestrator's persistence layer. It exposes
// a Backend interface plus shared row types; concrete implementations
// live in sqlite/ and postgres/ subpackages. Both speak the same
// contract so the orchestrator binary works identically against either.
//
// D14 — dual-backend by design. The interface lives here so any future
// engine (e.g., CockroachDB, DynamoDB) only has to satisfy this one
// type to drop in.
package storage

import (
	"context"
	"errors"
	"time"
)

// Errors surfaced by every backend.
var (
	ErrNotFound  = errors.New("storage: not found")
	ErrConflict  = errors.New("storage: conflicting row")
	ErrAmbiguous = errors.New("storage: prefix matches multiple rows")
)

// Backend is the orchestrator's persistence API. All methods are safe
// for concurrent use across goroutines.
type Backend interface {
	// Migrate brings the database up to the latest schema. Idempotent.
	Migrate(ctx context.Context) error

	// CreateRun records a newly-scheduled run. Returns ErrConflict if
	// the run id already exists.
	CreateRun(ctx context.Context, r Run) error

	// UpdateRunState moves a run through its lifecycle and stamps the
	// appropriate timestamp. Allowed transitions:
	//   pending -> building -> sandboxed -> analyzed -> done
	//   any   -> failed (with FailureReason)
	UpdateRunState(ctx context.Context, runID string, state RunState, failureReason string) error

	// GetRun fetches a single run by id. Returns ErrNotFound if absent.
	GetRun(ctx context.Context, runID string) (Run, error)

	// ListRuns returns recent runs, newest first, up to limit.
	ListRuns(ctx context.Context, limit int) ([]Run, error)

	// AppendEvents persists a batch of events for an existing run.
	// Events are inserted in the order given; the assigned event IDs
	// are monotonically increasing.
	AppendEvents(ctx context.Context, runID string, events []EventRow) error

	// ListEventsByRun streams all events for a run, ordered by ts_ns
	// ascending. Caller bounds the result with limit.
	ListEventsByRun(ctx context.Context, runID string, limit int) ([]EventRow, error)

	// EventCount returns the number of events recorded for a run.
	EventCount(ctx context.Context, runID string) (int64, error)

	// LoadBaseline returns the current baseline_fingerprints rows for a
	// package. Empty slice + nil err means this is the first run we've
	// ever seen for the package.
	LoadBaseline(ctx context.Context, packageName string) ([]BaselineRow, error)

	// MergeBaseline upserts baseline rows for a package. For each row,
	// if (package_name, category, value) exists, last_seen_run_id is
	// updated and occurrence_count incremented; otherwise inserted.
	// Used both for first-baseline-establishment and auto-promotion of
	// zero-deviation runs.
	MergeBaseline(ctx context.Context, runID string, rows []BaselineRow) error

	// MarkRunBaseline flips runs.is_baseline=true for runID. Called when
	// a run is auto-promoted (D38: zero deviations) or manually approved.
	MarkRunBaseline(ctx context.Context, runID string, isBaseline bool) error

	// WriteDeviations inserts deviations rows for a run. Each row's id
	// is assigned by the storage layer.
	WriteDeviations(ctx context.Context, rows []DeviationRow) error

	// DeleteDeviationsForRun removes all deviations for the given
	// run_id. Used by the Differ when it re-analyzes a run so we don't
	// duplicate rows on debounced re-runs.
	DeleteDeviationsForRun(ctx context.Context, runID string) error

	// ListDeviations returns deviations for a run in detection order.
	ListDeviations(ctx context.Context, runID string) ([]DeviationRow, error)

	// ListDeviationsFiltered returns deviations across all runs matching
	// the filter. Empty filter fields are ignored. Ordered newest-first.
	ListDeviationsFiltered(ctx context.Context, f DeviationFilter) ([]DeviationRow, error)

	// GetDeviation returns a single deviation by id. Returns ErrNotFound
	// when absent.
	GetDeviation(ctx context.Context, id string) (DeviationRow, error)

	// GetEvent returns a single event row by its integer id. Used by the
	// CLI to show the evidence event behind a deviation.
	GetEvent(ctx context.Context, id int64) (EventRow, error)

	// ListPackages returns one row per distinct package_name in runs,
	// with summary counts.
	ListPackages(ctx context.Context) ([]PackageSummary, error)

	// ListRunsByPackage returns runs for a specific package, newest first.
	ListRunsByPackage(ctx context.Context, packageName string, limit int) ([]Run, error)

	// ResolveRunPrefix returns the unique run whose id starts with the
	// given prefix. Returns ErrNotFound when no match, ErrAmbiguous when
	// multiple matches. Used by the CLI for git-style short ids.
	ResolveRunPrefix(ctx context.Context, prefix string) (Run, error)

	// ResolveDeviationPrefix is the deviation equivalent of
	// ResolveRunPrefix — fangs deviation show <short>.
	ResolveDeviationPrefix(ctx context.Context, prefix string) (DeviationRow, error)

	// AddWatchedPackage inserts (or no-ops on conflict) a package name
	// in the packages table. The package is then included in every
	// Watcher poll cycle until RemoveWatchedPackage is called.
	AddWatchedPackage(ctx context.Context, name string) error

	// RemoveWatchedPackage deletes the row. Does NOT touch existing runs.
	RemoveWatchedPackage(ctx context.Context, name string) error

	// ListWatchedPackages returns one row per watched package with the
	// last_checked / last_seen_version state used by the Watcher.
	ListWatchedPackages(ctx context.Context) ([]WatchedPackage, error)

	// UpdatePackageCheck stamps last_checked_at = now() and, when
	// version != "", updates last_seen_version. Called by the Watcher
	// after each successful registry poll.
	UpdatePackageCheck(ctx context.Context, name, version string) error

	// RecordRelease inserts a release row. Idempotent on
	// (package_name, version) — duplicates are no-ops so a Watcher
	// re-run after restart doesn't error.
	RecordRelease(ctx context.Context, r ReleaseRow) error

	// ListReleasesByPackage returns releases for a package, newest first.
	ListReleasesByPackage(ctx context.Context, name string, limit int) ([]ReleaseRow, error)

	// RecordScanResult finalizes a run: transitions state to done/failed,
	// stamps finished_at, and stores the ScanResult metadata (events
	// emitted/dropped, duration).
	RecordScanResult(ctx context.Context, runID string, r ScanResult) error

	// EventsDroppedTotal returns the sum of events_dropped across every
	// run — a quick health indicator for ringbuf overflow. Used by the
	// UI overview + the /metrics gauge.
	EventsDroppedTotal(ctx context.Context) (int64, error)

	// PruneEvents deletes events with ts_ns older than olderThanNS, EXCEPT
	// those referenced as evidence by an existing deviation. Returns the
	// number of rows removed. Idempotent; safe to run on an empty DB.
	//
	// Per D34: raw events retain for ~90 days; baselines + findings stay
	// indefinitely. The deviation-referenced exclusion is what makes the
	// "click evidence on a deviation" link survive past the retention
	// window for findings the operator actually cared about.
	PruneEvents(ctx context.Context, olderThanNS int64) (int64, error)

	// --- allowlists ---

	// AddAllowEntry inserts a global or package-scoped allowlist row.
	AddAllowEntry(ctx context.Context, e AllowEntry) error

	// ListAllowEntries returns every allowlist entry, ordered by scope
	// then package_name then kind. The caller filters per-run via
	// EntriesForPackage helper.
	ListAllowEntries(ctx context.Context) ([]AllowEntry, error)

	// DeleteAllowEntry removes a row by id. Idempotent.
	DeleteAllowEntry(ctx context.Context, id string) error

	// ResolveAllowPrefix supports git-style short ids in the CLI.
	ResolveAllowPrefix(ctx context.Context, prefix string) (AllowEntry, error)

	// --- notifier targets ---

	// UpsertNotifier inserts or updates a webhook target. Idempotent on
	// (name).
	UpsertNotifier(ctx context.Context, n NotifierRow) error

	// ListNotifiers returns every configured notifier (enabled + disabled),
	// ordered by name.
	ListNotifiers(ctx context.Context) ([]NotifierRow, error)

	// GetNotifier returns a single notifier by name. ErrNotFound when absent.
	GetNotifier(ctx context.Context, name string) (NotifierRow, error)

	// DeleteNotifier removes a notifier by name. Idempotent.
	DeleteNotifier(ctx context.Context, name string) error

	// --- notification delivery log ---

	// RecordNotification inserts one delivery-attempt row.
	RecordNotification(ctx context.Context, n NotificationRow) error

	// ListNotificationsByRun returns all delivery attempts for a run,
	// ordered by attempt asc.
	ListNotificationsByRun(ctx context.Context, runID string) ([]NotificationRow, error)

	// Close releases any pooled resources. Safe to call once.
	Close() error
}

// RunState enumerates the lifecycle stages for a Run. Matches the
// ARCHITECTURE.md §7 schema state machine.
type RunState string

const (
	RunStatePending   RunState = "pending"
	RunStateBuilding  RunState = "building"
	RunStateSandboxed RunState = "sandboxed"
	RunStateAnalyzed  RunState = "analyzed"
	RunStateDone      RunState = "done"
	RunStateFailed    RunState = "failed"
)

// IsValid reports whether s is one of the defined RunState values.
func (s RunState) IsValid() bool {
	switch s {
	case RunStatePending, RunStateBuilding, RunStateSandboxed,
		RunStateAnalyzed, RunStateDone, RunStateFailed:
		return true
	}
	return false
}

// Run is one row of the `runs` table.
type Run struct {
	ID             string
	PackageName    string
	Version        string
	TarballSHA256  string
	LockfileSHA256 string
	NodeVersion    string
	NPMVersion     string
	State          RunState
	Attempt        int
	IsBaseline     bool
	StartedAt      *time.Time
	FinishedAt     *time.Time
	FailureReason  string
	// Result metadata populated by RecordScanResult after the runner
	// posts its final ScanResult. Zero values before completion.
	EventsEmitted int64
	EventsDropped int64
	DurationNS    int64
}

// ScanResult is the structured payload the runner posts to finalize a
// run. Mirrors proto.ScanResult in shape; lives here to keep the
// storage layer independent of the wire package.
type ScanResult struct {
	Status        string // "ok" | "failed" | "timeout"
	Reason        string
	EventsEmitted int64
	EventsDropped int64
	DurationNS    int64
}

// EventRow is one row of the `events` table — the persisted form of a
// proto.EventEnvelope. Data is the marshalled JSON payload.
type EventRow struct {
	ID    int64 // assigned on insert; zero on input
	RunID string
	TsNS  int64
	Type  string
	Data  []byte // JSON-encoded payload
}

// BaselineRow is one row of the baseline_fingerprints table — the
// rolling-window memory of "what this package legitimately does."
type BaselineRow struct {
	PackageName     string
	Category        string
	Value           string
	FirstSeenRunID  string
	LastSeenRunID   string
	OccurrenceCount int
}

// DeviationFilter narrows ListDeviationsFiltered results. All fields
// optional — zero values match everything.
type DeviationFilter struct {
	PackageName string
	Severity    string
	RunID       string
	Limit       int
}

// WatchedPackage is one row of the packages table — the Watcher's
// per-package state.
type WatchedPackage struct {
	Name            string
	AddedAt         time.Time
	LastCheckedAt   *time.Time
	LastSeenVersion string
}

// ReleaseRow is one row of the releases table.
type ReleaseRow struct {
	PackageName   string
	Version       string
	TarballSHA256 string
	NPMIntegrity  string
	PublishedAt   time.Time
	DiscoveredAt  time.Time
}

// PackageSummary is one row of the ListPackages aggregate result.
type PackageSummary struct {
	Name             string
	RunsTotal        int
	RunsBaseline     int
	DeviationsLatest int
	LatestRunID      string
	LatestVersion    string
}

// DeviationRow is one row of the deviations table — a (category, value)
// pair observed in a run that was NOT in the baseline_fingerprints.
type DeviationRow struct {
	ID              string
	RunID           string
	Category        string
	Value           string
	EvidenceEventID int64
	Severity        string
	DetectedAt      time.Time
	NotifiedAt      *time.Time
	Suppressed      bool
}

// AllowScope is the visibility of an allowlist entry. Global entries
// apply to every run; package entries only to runs of the named
// package.
type AllowScope string

const (
	AllowScopeGlobal  AllowScope = "global"
	AllowScopePackage AllowScope = "package"
)

// AllowKind selects which Differ category the entry suppresses.
type AllowKind string

const (
	AllowKindCIDR AllowKind = "cidr" // net_new_destination — value is a CIDR (e.g. "10.0.0.0/8")
	AllowKindPath AllowKind = "path" // fs_new_path_* — value is a path prefix (e.g. "/srv/data/")
	AllowKindSNI  AllowKind = "sni"  // net_new_https_host — value is an SNI (e.g. "telemetry.example")
)

// AllowEntry is one operator-managed allowlist row.
type AllowEntry struct {
	ID          string
	Scope       AllowScope
	PackageName string // empty when Scope == AllowScopeGlobal
	Kind        AllowKind
	Value       string
	Note        string
	CreatedAt   time.Time
}

// EntriesForPackage returns the subset of entries applicable to runs of
// packageName — i.e. every global entry plus every package entry whose
// PackageName matches. Used by the Differ to build the per-run filter.
func EntriesForPackage(all []AllowEntry, packageName string) []AllowEntry {
	out := make([]AllowEntry, 0, len(all))
	for _, e := range all {
		if e.Scope == AllowScopeGlobal {
			out = append(out, e)
		} else if e.Scope == AllowScopePackage && e.PackageName == packageName {
			out = append(out, e)
		}
	}
	return out
}

// NotifierRow is one configured webhook target.
type NotifierRow struct {
	Name        string
	URL         string
	Template    string // 'slack' | 'discord' | 'generic'
	SecretEnv   string // env var holding HMAC secret; "" = no signing
	Headers     string // JSON-encoded extra headers; "" = none
	MinSeverity string // 'low'|'medium'|'high'|'critical'; "" = any
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NotificationRow is one webhook delivery attempt — append-only audit log.
type NotificationRow struct {
	ID              string
	RunID           string
	NotifierName    string
	Attempt         int
	Status          string // 'queued'|'sent'|'failed'|'permanent'
	LastAttemptedAt *time.Time
	NextAttemptAt   *time.Time
	ResponseCode    int
	ResponseBody    string
	ErrorMsg        string
	DeviationCount  int
	CreatedAt       time.Time
}
