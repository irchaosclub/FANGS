// SPDX-License-Identifier: Apache-2.0
package differ_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/irchaosclub/FANGS/internal/orchestrator/differ"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/sqlite"
)

func setupDB(t *testing.T) storage.Backend {
	t.Helper()
	tmp := t.TempDir()
	b, err := sqlite.Open(filepath.Join(tmp, "differ.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return b
}

func payload(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDifferFirstRunSeedsBaseline(t *testing.T) {
	store := setupDB(t)
	ctx := context.Background()

	// Insert a run + a few events.
	if err := store.CreateRun(ctx, storage.Run{
		ID: "run-001", PackageName: "art-template", State: storage.RunStateDone, Attempt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	events := []storage.EventRow{
		{RunID: "run-001", TsNS: 1, Type: "tls_sni", Data: payload(t, map[string]any{"SNI": "registry.npmjs.org"})},
		{RunID: "run-001", TsNS: 2, Type: "dns_query", Data: payload(t, map[string]any{"QName": "registry.npmjs.org"})},
	}
	if err := store.AppendEvents(ctx, "run-001", events); err != nil {
		t.Fatal(err)
	}

	d := differ.New(store, nil)
	n, err := d.AnalyzeRun(ctx, "run-001")
	if err != nil {
		t.Fatalf("AnalyzeRun: %v", err)
	}
	if n != 0 {
		t.Errorf("first-run deviations: got %d, want 0 (should seed baseline)", n)
	}

	bl, err := store.LoadBaseline(ctx, "art-template")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if len(bl) != 2 {
		t.Errorf("baseline rows: got %d, want 2", len(bl))
	}

	// Run should be marked is_baseline=true
	run, _ := store.GetRun(ctx, "run-001")
	if !run.IsBaseline {
		t.Errorf("first run not auto-marked baseline")
	}
}

func TestDifferSecondRunFlagsDeviations(t *testing.T) {
	store := setupDB(t)
	ctx := context.Background()

	// First run = clean baseline
	_ = store.CreateRun(ctx, storage.Run{ID: "run-clean", PackageName: "art-template", State: storage.RunStateDone, Attempt: 1})
	_ = store.AppendEvents(ctx, "run-clean", []storage.EventRow{
		{RunID: "run-clean", TsNS: 1, Type: "tls_sni", Data: payload(t, map[string]any{"SNI": "registry.npmjs.org"})},
		{RunID: "run-clean", TsNS: 2, Type: "exec", Data: payload(t, map[string]any{"BinaryPathStr": "/usr/local/bin/node"})},
	})
	d := differ.New(store, nil)
	if _, err := d.AnalyzeRun(ctx, "run-clean"); err != nil {
		t.Fatal(err)
	}

	// Second run = same baseline + malicious activity
	_ = store.CreateRun(ctx, storage.Run{ID: "run-mal", PackageName: "art-template", State: storage.RunStateDone, Attempt: 1})
	_ = store.AppendEvents(ctx, "run-mal", []storage.EventRow{
		{RunID: "run-mal", TsNS: 1, Type: "tls_sni", Data: payload(t, map[string]any{"SNI": "registry.npmjs.org"})},                     // known
		{RunID: "run-mal", TsNS: 2, Type: "exec", Data: payload(t, map[string]any{"BinaryPathStr": "/usr/local/bin/node"})},             // known
		{RunID: "run-mal", TsNS: 3, Type: "tls_sni", Data: payload(t, map[string]any{"SNI": "exfil-c2.attacker.example"})},              // NEW
		{RunID: "run-mal", TsNS: 4, Type: "net_connect", Data: payload(t, map[string]any{"DestIP": "1.1.1.1", "DestPort": 31337})},      // NEW
		{RunID: "run-mal", TsNS: 5, Type: "file_access", Data: payload(t, map[string]any{"PathName": "/root/.ssh/id_rsa", "Flags": 0})}, // NEW
	})

	n, err := d.AnalyzeRun(ctx, "run-mal")
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("deviations: got %d, want 3", n)
	}

	devs, err := store.ListDeviations(ctx, "run-mal")
	if err != nil {
		t.Fatal(err)
	}
	gotValues := map[string]string{}
	for _, d := range devs {
		gotValues[d.Category] = d.Value
	}
	if gotValues["net_new_https_host"] != "exfil-c2.attacker.example" {
		t.Errorf("missing exfil host deviation: %+v", gotValues)
	}
	if gotValues["net_new_destination"] != "1.1.1.1:31337" {
		t.Errorf("missing raw-IP deviation: %+v", gotValues)
	}
	if gotValues["fs_new_path_read"] != "/root/.ssh/id_rsa" {
		t.Errorf("missing SSH-key-read deviation: %+v", gotValues)
	}

	// Second run should NOT be auto-promoted to baseline (has deviations).
	run, _ := store.GetRun(ctx, "run-mal")
	if run.IsBaseline {
		t.Errorf("run with deviations should not be marked baseline")
	}
}

func TestDifferSkipsRunsWithoutPackage(t *testing.T) {
	store := setupDB(t)
	ctx := context.Background()
	_ = store.CreateRun(ctx, storage.Run{ID: "run-nopkg", State: storage.RunStateDone, Attempt: 1})
	d := differ.New(store, nil)
	n, err := d.AnalyzeRun(ctx, "run-nopkg")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("expected 0 deviations for empty-package run, got %d", n)
	}
}
