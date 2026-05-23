// SPDX-License-Identifier: Apache-2.0
package differ

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// Differ runs the delta analysis on completed runs.
type Differ struct {
	store   storage.Backend
	logger  *slog.Logger
	metrics metricsSink
}

// metricsSink is the contract Differ needs from the metrics package —
// kept local to avoid pulling prometheus into differ.
type metricsSink interface {
	ObserveDeviationsWritten(rows []storage.DeviationRow)
}

// New constructs a Differ bound to the given storage backend.
func New(store storage.Backend, logger *slog.Logger) *Differ {
	if logger == nil {
		logger = slog.Default()
	}
	return &Differ{store: store, logger: logger}
}

// SetMetrics wires the metrics sink. nil disables instrumentation.
func (d *Differ) SetMetrics(m metricsSink) { d.metrics = m }

// AnalyzeRun is the entry point: load the run, extract fingerprints,
// diff against baseline, write deviations (or seed baseline on first
// run). Returns the deviation count so the caller can decide whether
// to flag for review.
func (d *Differ) AnalyzeRun(ctx context.Context, runID string) (int, error) {
	run, err := d.store.GetRun(ctx, runID)
	if err != nil {
		return 0, fmt.Errorf("GetRun: %w", err)
	}
	if run.PackageName == "" {
		// Skip diffing — no package identity to baseline against.
		d.logger.Info("skip differ — run has empty package_name", "run_id", runID)
		return 0, nil
	}

	events, err := d.store.ListEventsByRun(ctx, runID, 0)
	if err != nil {
		return 0, fmt.Errorf("ListEventsByRun: %w", err)
	}

	// Operator allowlist for this package = every global rule + every
	// rule scoped to this package. Failure here is non-fatal — Differ
	// falls back to the hardcoded CDN allowlist only.
	allEntries, err := d.store.ListAllowEntries(ctx)
	if err != nil {
		d.logger.Warn("ListAllowEntries (using default CDN list only)", "err", err)
		allEntries = nil
	}
	filter := NewFilter(storage.EntriesForPackage(allEntries, run.PackageName), d.logger)

	runFPs := ExtractFingerprintsWith(events, filter)
	d.logger.Info("fingerprints extracted",
		"run_id", runID,
		"package", run.PackageName,
		"events_in", len(events),
		"fingerprints_out", len(runFPs),
	)

	baseline, err := d.store.LoadBaseline(ctx, run.PackageName)
	if err != nil {
		return 0, fmt.Errorf("LoadBaseline: %w", err)
	}

	if len(baseline) == 0 {
		// First-ever run for this package — establish baseline.
		// (D38: future hardening will require N>=K clean runs before
		// auto-promotion; for v1 we promote the first one.)
		if err := d.seedBaseline(ctx, runID, run.PackageName, runFPs); err != nil {
			return 0, fmt.Errorf("seedBaseline: %w", err)
		}
		d.logger.Info("first run — baseline seeded",
			"run_id", runID,
			"package", run.PackageName,
			"fingerprints", len(runFPs),
		)
		return 0, nil
	}

	// Build baseline lookup set.
	known := make(map[string]struct{}, len(baseline))
	for _, b := range baseline {
		known[string(b.Category)+"|"+b.Value] = struct{}{}
	}

	// Walk runFPs; anything not in `known` is a deviation.
	var deviations []storage.DeviationRow
	var newBaselineRows []storage.BaselineRow
	for _, fp := range runFPs {
		if _, seen := known[fp.Key()]; seen {
			// Existing baseline entry — bump occurrence_count.
			newBaselineRows = append(newBaselineRows, storage.BaselineRow{
				PackageName:     run.PackageName,
				Category:        string(fp.Category),
				Value:           fp.Value,
				FirstSeenRunID:  runID,
				LastSeenRunID:   runID,
				OccurrenceCount: 1,
			})
			continue
		}
		// Novel — emit deviation.
		deviations = append(deviations, storage.DeviationRow{
			ID:              newID(),
			RunID:           runID,
			Category:        string(fp.Category),
			Value:           fp.Value,
			EvidenceEventID: fp.FirstEvtID,
			Severity:        string(defaultSeverity(fp.Category)),
			DetectedAt:      time.Now().UTC(),
		})
	}

	// Idempotent: clear any prior deviations for this run before writing
	// the fresh set. The orchestrator may invoke AnalyzeRun more than
	// once per run (each event-batch POST triggers a debounced re-run);
	// we want the final state to reflect the latest analysis, not stack.
	if err := d.store.DeleteDeviationsForRun(ctx, runID); err != nil {
		d.logger.Warn("DeleteDeviationsForRun (continuing)", "err", err, "run_id", runID)
	}
	if err := d.store.WriteDeviations(ctx, deviations); err != nil {
		return 0, fmt.Errorf("WriteDeviations: %w", err)
	}
	if d.metrics != nil {
		d.metrics.ObserveDeviationsWritten(deviations)
	}

	// Bump occurrence counts for known baseline rows that fired again.
	if err := d.store.MergeBaseline(ctx, runID, newBaselineRows); err != nil {
		d.logger.Warn("MergeBaseline (occurrence bump)", "err", err, "run_id", runID)
	}

	// D38 auto-promotion: zero-deviation runs join the baseline.
	if len(deviations) == 0 {
		if err := d.store.MarkRunBaseline(ctx, runID, true); err != nil && !errors.Is(err, storage.ErrNotFound) {
			d.logger.Warn("MarkRunBaseline", "err", err, "run_id", runID)
		}
		d.logger.Info("zero deviations — run auto-promoted to baseline", "run_id", runID, "package", run.PackageName)
	} else {
		d.logger.Info("deviations detected — run held for review",
			"run_id", runID,
			"package", run.PackageName,
			"deviations", len(deviations),
		)
	}

	return len(deviations), nil
}

// seedBaseline records every fingerprint in a first-run as baseline and
// marks the run is_baseline=true.
func (d *Differ) seedBaseline(ctx context.Context, runID, pkgName string, fps []Fingerprint) error {
	rows := make([]storage.BaselineRow, 0, len(fps))
	for _, fp := range fps {
		rows = append(rows, storage.BaselineRow{
			PackageName:     pkgName,
			Category:        string(fp.Category),
			Value:           fp.Value,
			FirstSeenRunID:  runID,
			LastSeenRunID:   runID,
			OccurrenceCount: fp.Count,
		})
	}
	if err := d.store.MergeBaseline(ctx, runID, rows); err != nil {
		return err
	}
	return d.store.MarkRunBaseline(ctx, runID, true)
}

func newID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
