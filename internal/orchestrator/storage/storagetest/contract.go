// SPDX-License-Identifier: Apache-2.0
//
// Package storagetest holds the shared contract suite every storage
// backend must satisfy. Each backend's *_test.go constructs a fresh
// Backend and calls RunContract.

package storagetest

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

// RunContract executes the full storage contract against the supplied
// backend. Each named subtest is fully isolated: the backend's state
// after one subtest is not assumed by another. Callers should pass a
// freshly-migrated, empty backend.
func RunContract(t *testing.T, b storage.Backend) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateRun then GetRun roundtrip", func(t *testing.T) {
		run := storage.Run{
			ID:          "run-001",
			PackageName: "left-pad",
			Version:     "1.3.0",
			State:       storage.RunStatePending,
			Attempt:     1,
		}
		if err := b.CreateRun(ctx, run); err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		got, err := b.GetRun(ctx, "run-001")
		if err != nil {
			t.Fatalf("GetRun: %v", err)
		}
		if got.ID != "run-001" || got.PackageName != "left-pad" || got.Version != "1.3.0" {
			t.Errorf("roundtrip mismatch: %+v", got)
		}
		if got.State != storage.RunStatePending {
			t.Errorf("state: got %q want pending", got.State)
		}
	})

	t.Run("GetRun missing returns ErrNotFound", func(t *testing.T) {
		_, err := b.GetRun(ctx, "does-not-exist")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("CreateRun duplicate returns ErrConflict", func(t *testing.T) {
		run := storage.Run{ID: "run-dup", State: storage.RunStatePending, Attempt: 1}
		if err := b.CreateRun(ctx, run); err != nil {
			t.Fatalf("first CreateRun: %v", err)
		}
		err := b.CreateRun(ctx, run)
		if !errors.Is(err, storage.ErrConflict) {
			t.Errorf("want ErrConflict, got %v", err)
		}
	})

	t.Run("UpdateRunState transitions", func(t *testing.T) {
		run := storage.Run{ID: "run-trans", State: storage.RunStatePending, Attempt: 1}
		if err := b.CreateRun(ctx, run); err != nil {
			t.Fatalf("CreateRun: %v", err)
		}
		if err := b.UpdateRunState(ctx, "run-trans", storage.RunStateBuilding, ""); err != nil {
			t.Fatalf("update -> building: %v", err)
		}
		got, _ := b.GetRun(ctx, "run-trans")
		if got.State != storage.RunStateBuilding {
			t.Errorf("state after building update: %q", got.State)
		}
		if got.StartedAt == nil {
			t.Errorf("StartedAt not stamped on building transition")
		}
		if err := b.UpdateRunState(ctx, "run-trans", storage.RunStateDone, ""); err != nil {
			t.Fatalf("update -> done: %v", err)
		}
		got, _ = b.GetRun(ctx, "run-trans")
		if got.FinishedAt == nil {
			t.Errorf("FinishedAt not stamped on done transition")
		}
	})

	t.Run("UpdateRunState failed records reason", func(t *testing.T) {
		run := storage.Run{ID: "run-fail", State: storage.RunStatePending, Attempt: 1}
		_ = b.CreateRun(ctx, run)
		if err := b.UpdateRunState(ctx, "run-fail", storage.RunStateFailed, "image pull timeout"); err != nil {
			t.Fatalf("update -> failed: %v", err)
		}
		got, _ := b.GetRun(ctx, "run-fail")
		if got.State != storage.RunStateFailed {
			t.Errorf("state: %q", got.State)
		}
		if got.FailureReason != "image pull timeout" {
			t.Errorf("failure_reason: %q", got.FailureReason)
		}
	})

	t.Run("UpdateRunState missing returns ErrNotFound", func(t *testing.T) {
		err := b.UpdateRunState(ctx, "no-such-run", storage.RunStateDone, "")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("AppendEvents persists and orders by ts", func(t *testing.T) {
		run := storage.Run{ID: "run-evt", State: storage.RunStatePending, Attempt: 1}
		_ = b.CreateRun(ctx, run)

		body1, _ := json.Marshal(map[string]any{"path": "/etc/passwd"})
		body2, _ := json.Marshal(map[string]any{"path": "/etc/shadow"})
		body3, _ := json.Marshal(map[string]any{"dest": "1.2.3.4:443"})

		events := []storage.EventRow{
			{RunID: "run-evt", TsNS: 200, Type: "file_access", Data: body2},
			{RunID: "run-evt", TsNS: 100, Type: "file_access", Data: body1},
			{RunID: "run-evt", TsNS: 300, Type: "net_connect", Data: body3},
		}
		if err := b.AppendEvents(ctx, "run-evt", events); err != nil {
			t.Fatalf("AppendEvents: %v", err)
		}

		count, err := b.EventCount(ctx, "run-evt")
		if err != nil {
			t.Fatalf("EventCount: %v", err)
		}
		if count != 3 {
			t.Errorf("EventCount = %d, want 3", count)
		}

		out, err := b.ListEventsByRun(ctx, "run-evt", 0)
		if err != nil {
			t.Fatalf("ListEventsByRun: %v", err)
		}
		if len(out) != 3 {
			t.Fatalf("returned %d events, want 3", len(out))
		}
		if out[0].TsNS != 100 || out[1].TsNS != 200 || out[2].TsNS != 300 {
			t.Errorf("not ordered by ts_ns: %v %v %v", out[0].TsNS, out[1].TsNS, out[2].TsNS)
		}
		if out[2].Type != "net_connect" {
			t.Errorf("type roundtrip: %q", out[2].Type)
		}
	})

	t.Run("AppendEvents empty is no-op", func(t *testing.T) {
		run := storage.Run{ID: "run-empty", State: storage.RunStatePending, Attempt: 1}
		_ = b.CreateRun(ctx, run)
		if err := b.AppendEvents(ctx, "run-empty", nil); err != nil {
			t.Errorf("AppendEvents(nil): %v", err)
		}
		n, _ := b.EventCount(ctx, "run-empty")
		if n != 0 {
			t.Errorf("expected 0 events, got %d", n)
		}
	})

	t.Run("ListRuns returns newest first", func(t *testing.T) {
		runIDs := []string{"list-a", "list-b", "list-c"}
		for _, id := range runIDs {
			_ = b.CreateRun(ctx, storage.Run{ID: id, State: storage.RunStatePending, Attempt: 1})
			if err := b.UpdateRunState(ctx, id, storage.RunStateBuilding, ""); err != nil {
				t.Fatalf("UpdateRunState: %v", err)
			}
			time.Sleep(2 * time.Millisecond) // ensure distinct started_at
		}
		runs, err := b.ListRuns(ctx, 50)
		if err != nil {
			t.Fatalf("ListRuns: %v", err)
		}
		// Find positions of our test ids in the returned list.
		positions := map[string]int{}
		for i, r := range runs {
			positions[r.ID] = i
		}
		// Newest first: list-c should appear earlier than list-a.
		if positions["list-c"] >= positions["list-a"] {
			t.Errorf("ordering wrong: list-c at %d, list-a at %d", positions["list-c"], positions["list-a"])
		}
	})

	t.Run("AppendEvents to missing run returns error", func(t *testing.T) {
		ev := []storage.EventRow{{RunID: "no-run", TsNS: 1, Type: "file_access", Data: []byte(`{}`)}}
		err := b.AppendEvents(ctx, "no-run", ev)
		if err == nil {
			t.Errorf("expected error appending to missing run, got nil")
		}
	})

	t.Run("RecordScanResult finalizes a run with metrics", func(t *testing.T) {
		_ = b.CreateRun(ctx, storage.Run{ID: "scan-res-1", PackageName: "p", Version: "1", State: storage.RunStatePending, Attempt: 1})
		err := b.RecordScanResult(ctx, "scan-res-1", storage.ScanResult{
			Status: "ok", EventsEmitted: 42, EventsDropped: 3, DurationNS: 5_500_000_000,
		})
		if err != nil {
			t.Fatalf("RecordScanResult: %v", err)
		}
		got, _ := b.GetRun(ctx, "scan-res-1")
		if got.State != storage.RunStateDone {
			t.Errorf("state: got %q want done", got.State)
		}
		if got.FinishedAt == nil {
			t.Errorf("finished_at not stamped")
		}
		if got.EventsEmitted != 42 || got.EventsDropped != 3 || got.DurationNS != 5_500_000_000 {
			t.Errorf("metrics: emitted=%d dropped=%d duration=%d (want 42/3/5.5e9)",
				got.EventsEmitted, got.EventsDropped, got.DurationNS)
		}
	})

	t.Run("RecordScanResult failed populates reason", func(t *testing.T) {
		_ = b.CreateRun(ctx, storage.Run{ID: "scan-res-2", PackageName: "p", Version: "1", State: storage.RunStatePending, Attempt: 1})
		err := b.RecordScanResult(ctx, "scan-res-2", storage.ScanResult{
			Status: "failed", Reason: "container exited 137",
		})
		if err != nil {
			t.Fatalf("RecordScanResult: %v", err)
		}
		got, _ := b.GetRun(ctx, "scan-res-2")
		if got.State != storage.RunStateFailed {
			t.Errorf("state: got %q want failed", got.State)
		}
		if got.FailureReason != "container exited 137" {
			t.Errorf("failure_reason: %q", got.FailureReason)
		}
	})

	t.Run("RecordScanResult missing run returns ErrNotFound", func(t *testing.T) {
		err := b.RecordScanResult(ctx, "ghost", storage.ScanResult{Status: "ok"})
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("EventsDroppedTotal sums across runs", func(t *testing.T) {
		_ = b.CreateRun(ctx, storage.Run{ID: "drop-a", PackageName: "p", Version: "1", State: storage.RunStatePending, Attempt: 1})
		_ = b.CreateRun(ctx, storage.Run{ID: "drop-b", PackageName: "p", Version: "1", State: storage.RunStatePending, Attempt: 1})
		_ = b.RecordScanResult(ctx, "drop-a", storage.ScanResult{Status: "ok", EventsDropped: 5})
		_ = b.RecordScanResult(ctx, "drop-b", storage.ScanResult{Status: "ok", EventsDropped: 7})

		got, err := b.EventsDroppedTotal(ctx)
		if err != nil {
			t.Fatalf("EventsDroppedTotal: %v", err)
		}
		if got < 12 {
			// >= because earlier subtests may have written drops too.
			t.Errorf("EventsDroppedTotal = %d, want at least 12", got)
		}
	})

	t.Run("PruneEvents excludes deviation-evidence", func(t *testing.T) {
		// Seed a run + 2 events: one old & unpinned, one old & pinned-as-evidence.
		_ = b.CreateRun(ctx, storage.Run{ID: "prune-run", PackageName: "p", Version: "1", State: storage.RunStatePending, Attempt: 1})
		oldTS := int64(1) // way before any reasonable cutoff
		_ = b.AppendEvents(ctx, "prune-run", []storage.EventRow{
			{RunID: "prune-run", TsNS: oldTS, Type: "file_access", Data: []byte(`{}`)},
			{RunID: "prune-run", TsNS: oldTS, Type: "net_connect", Data: []byte(`{}`)},
		})
		evs, _ := b.ListEventsByRun(ctx, "prune-run", 0)
		if len(evs) != 2 {
			t.Fatalf("seed: expected 2 events, got %d", len(evs))
		}
		// Pin event #1 as evidence of a deviation.
		err := b.WriteDeviations(ctx, []storage.DeviationRow{{
			ID: "dev-prune", RunID: "prune-run", Category: "net_new_destination", Value: "1.1.1.1:80",
			EvidenceEventID: evs[1].ID, Severity: "high", DetectedAt: time.Now().UTC(),
		}})
		if err != nil {
			t.Fatalf("WriteDeviations: %v", err)
		}

		// Cutoff WAY in the future — every event qualifies for prune.
		cutoff := time.Now().Add(24 * time.Hour).UnixNano()
		n, err := b.PruneEvents(ctx, cutoff)
		if err != nil {
			t.Fatalf("PruneEvents: %v", err)
		}
		if n < 1 {
			t.Errorf("PruneEvents deleted %d rows, expected at least 1", n)
		}
		// Pinned event must survive.
		after, _ := b.ListEventsByRun(ctx, "prune-run", 0)
		var stillThere bool
		for _, e := range after {
			if e.ID == evs[1].ID {
				stillThere = true
			}
		}
		if !stillThere {
			t.Errorf("pinned evidence event was pruned — should have survived")
		}
	})

	t.Run("Allowlist add/list/delete/resolve", func(t *testing.T) {
		g := storage.AllowEntry{
			ID: "allow-glob-1", Scope: storage.AllowScopeGlobal, Kind: storage.AllowKindCIDR,
			Value: "10.0.0.0/8", Note: "internal",
		}
		p := storage.AllowEntry{
			ID: "allow-pkg-1", Scope: storage.AllowScopePackage, PackageName: "axios",
			Kind: storage.AllowKindSNI, Value: "telemetry.example",
		}
		if err := b.AddAllowEntry(ctx, g); err != nil {
			t.Fatalf("AddAllowEntry global: %v", err)
		}
		if err := b.AddAllowEntry(ctx, p); err != nil {
			t.Fatalf("AddAllowEntry package: %v", err)
		}
		all, err := b.ListAllowEntries(ctx)
		if err != nil {
			t.Fatalf("ListAllowEntries: %v", err)
		}
		seen := map[string]bool{}
		for _, e := range all {
			seen[e.ID] = true
		}
		if !seen["allow-glob-1"] || !seen["allow-pkg-1"] {
			t.Errorf("ListAllowEntries missing entries: %v", seen)
		}

		// EntriesForPackage helper: axios should get the global + the
		// package entry; some-other-pkg should get only the global.
		for_axios := storage.EntriesForPackage(all, "axios")
		hasGlob, hasPkg := false, false
		for _, e := range for_axios {
			if e.ID == "allow-glob-1" {
				hasGlob = true
			}
			if e.ID == "allow-pkg-1" {
				hasPkg = true
			}
		}
		if !hasGlob || !hasPkg {
			t.Errorf("EntriesForPackage(axios) missing entries — glob=%v pkg=%v", hasGlob, hasPkg)
		}
		for_other := storage.EntriesForPackage(all, "lodash")
		for _, e := range for_other {
			if e.ID == "allow-pkg-1" {
				t.Errorf("EntriesForPackage(lodash) leaked axios's entry")
			}
		}

		// Prefix resolution.
		got, err := b.ResolveAllowPrefix(ctx, "allow-glob")
		if err != nil {
			t.Fatalf("ResolveAllowPrefix: %v", err)
		}
		if got.ID != "allow-glob-1" {
			t.Errorf("ResolveAllowPrefix wrong row: %s", got.ID)
		}
		if _, err := b.ResolveAllowPrefix(ctx, "missing-"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("ResolveAllowPrefix missing: want ErrNotFound, got %v", err)
		}

		// Delete + idempotent re-delete.
		if err := b.DeleteAllowEntry(ctx, "allow-glob-1"); err != nil {
			t.Errorf("DeleteAllowEntry: %v", err)
		}
		if err := b.DeleteAllowEntry(ctx, "allow-glob-1"); err != nil {
			t.Errorf("DeleteAllowEntry idempotent: %v", err)
		}
		if _, err := b.ResolveAllowPrefix(ctx, "allow-glob"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expected ErrNotFound after delete, got %v", err)
		}
	})

	t.Run("Notifier upsert/list/get/delete", func(t *testing.T) {
		n := storage.NotifierRow{
			Name: "notif-1", URL: "https://hooks.example/x", Template: "generic",
			MinSeverity: "high", Enabled: true,
		}
		if err := b.UpsertNotifier(ctx, n); err != nil {
			t.Fatalf("UpsertNotifier: %v", err)
		}
		// Upsert with same name should update, not error.
		n.URL = "https://hooks.example/updated"
		if err := b.UpsertNotifier(ctx, n); err != nil {
			t.Fatalf("UpsertNotifier update: %v", err)
		}
		got, err := b.GetNotifier(ctx, "notif-1")
		if err != nil {
			t.Fatalf("GetNotifier: %v", err)
		}
		if got.URL != "https://hooks.example/updated" {
			t.Errorf("upsert didn't update URL: %s", got.URL)
		}

		list, err := b.ListNotifiers(ctx)
		if err != nil {
			t.Fatalf("ListNotifiers: %v", err)
		}
		found := false
		for _, row := range list {
			if row.Name == "notif-1" {
				found = true
			}
		}
		if !found {
			t.Errorf("ListNotifiers missing notif-1")
		}

		// GetNotifier missing.
		_, err = b.GetNotifier(ctx, "no-such-notifier")
		if !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("GetNotifier missing: want ErrNotFound, got %v", err)
		}

		// Delete + idempotent.
		if err := b.DeleteNotifier(ctx, "notif-1"); err != nil {
			t.Errorf("DeleteNotifier: %v", err)
		}
		if err := b.DeleteNotifier(ctx, "notif-1"); err != nil {
			t.Errorf("DeleteNotifier idempotent: %v", err)
		}
	})

	t.Run("RecordNotification audit log", func(t *testing.T) {
		_ = b.CreateRun(ctx, storage.Run{ID: "notif-run", PackageName: "p", Version: "1", State: storage.RunStatePending, Attempt: 1})
		_ = b.UpsertNotifier(ctx, storage.NotifierRow{Name: "notif-audit", URL: "https://x", Template: "generic", Enabled: true})

		// Insert two attempts.
		now := time.Now().UTC()
		err := b.RecordNotification(ctx, storage.NotificationRow{
			ID: "nrow-1", RunID: "notif-run", NotifierName: "notif-audit",
			Attempt: 1, Status: "failed", LastAttemptedAt: &now,
			ResponseCode: 503, ErrorMsg: "upstream down", DeviationCount: 3,
		})
		if err != nil {
			t.Fatalf("RecordNotification 1: %v", err)
		}
		err = b.RecordNotification(ctx, storage.NotificationRow{
			ID: "nrow-2", RunID: "notif-run", NotifierName: "notif-audit",
			Attempt: 2, Status: "sent", LastAttemptedAt: &now,
			ResponseCode: 200, DeviationCount: 3,
		})
		if err != nil {
			t.Fatalf("RecordNotification 2: %v", err)
		}

		rows, err := b.ListNotificationsByRun(ctx, "notif-run")
		if err != nil {
			t.Fatalf("ListNotificationsByRun: %v", err)
		}
		if len(rows) != 2 {
			t.Fatalf("expected 2 attempts, got %d", len(rows))
		}
		// Ordered by attempt ascending.
		if rows[0].Attempt != 1 || rows[1].Attempt != 2 {
			t.Errorf("not ordered by attempt: %d, %d", rows[0].Attempt, rows[1].Attempt)
		}
		if rows[0].Status != "failed" || rows[1].Status != "sent" {
			t.Errorf("status roundtrip: %q, %q", rows[0].Status, rows[1].Status)
		}
		if rows[1].ResponseCode != 200 {
			t.Errorf("response_code roundtrip: %d", rows[1].ResponseCode)
		}
	})
}
