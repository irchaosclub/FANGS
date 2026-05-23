// SPDX-License-Identifier: Apache-2.0
//
// Package differ implements FANGS' delta detector: compare a run's
// observed behavior against the package's rolling baseline and emit
// deviations for any new (category, value) pair not previously seen.
//
// FANGS doesn't try to know what's malicious — it knows what's
// DIFFERENT. The Differ is that comparison engine.
//
// Flow:
//
//  1. Run completes → orchestrator marks it RunStateDone.
//  2. Differ.AnalyzeRun(ctx, runID) loads the run's events, extracts
//     fingerprints, normalizes them.
//  3. Differ loads the package's baseline_fingerprints rows.
//  4. For each run fingerprint NOT in baseline → write a deviations row.
//  5. If zero deviations: (D38) mark the run is_baseline=true and merge
//     its fingerprints into baseline_fingerprints. Otherwise hold for
//     human review.
//
// Categories per D18 (initial 7):
//   - net_new_destination     "ip:port"
//   - net_new_dns             "qname"
//   - net_new_https_host      "sni"
//   - fs_new_path_read        "normalized path"
//   - fs_new_path_write       "normalized path"
//   - proc_new_exec           "binary path"
//   - syscall_rare_category   (deferred — not implemented yet)
package differ

// Category is the deviation taxonomy.
type Category string

const (
	CatNetDestination Category = "net_new_destination"
	CatNetDNS         Category = "net_new_dns"
	CatNetHTTPSHost   Category = "net_new_https_host"
	CatFSPathRead     Category = "fs_new_path_read"
	CatFSPathWrite    Category = "fs_new_path_write"
	CatProcExec       Category = "proc_new_exec"
)

// AllCategories lists every category this Differ emits.
var AllCategories = []Category{
	CatNetDestination,
	CatNetDNS,
	CatNetHTTPSHost,
	CatFSPathRead,
	CatFSPathWrite,
	CatProcExec,
}

// Fingerprint is one categorized data point extracted from a run's
// events. Multiple events collapsing to the same (Category, Value)
// dedupe to a single Fingerprint with Count summed.
type Fingerprint struct {
	Category   Category
	Value      string
	Count      int
	FirstEvtID int64 // the lowest events.id that contributed — used as evidence pointer for deviations
}

// Key returns the (category, value) tuple as a stable string for map
// lookups.
func (f Fingerprint) Key() string { return string(f.Category) + "|" + f.Value }

// Deviation is one (category, value) seen in a run that is NOT in the
// package's baseline_fingerprints. Persisted to the deviations table.
type Deviation struct {
	Category        Category
	Value           string
	EvidenceEventID int64
	Severity        Severity
}

// Severity is a coarse triage level. Currently every deviation is
// "warn" — finer-grained scoring lands when we add suppression rules
// and per-category weights.
type Severity string

const (
	SevInfo Severity = "info"
	SevWarn Severity = "warn"
	SevCrit Severity = "crit"
)

// defaultSeverity assigns each category an initial severity.
// Tuned so credential-territory and unexpected destinations land
// at warn/crit even on first encounter.
func defaultSeverity(c Category) Severity {
	switch c {
	case CatNetDestination, CatNetHTTPSHost, CatNetDNS:
		return SevWarn
	case CatProcExec:
		return SevWarn
	case CatFSPathRead, CatFSPathWrite:
		return SevInfo
	default:
		return SevInfo
	}
}
