// SPDX-License-Identifier: Apache-2.0
package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cliPkg "github.com/irchaosclub/FANGS/cmd/fangs-cli/internal/cli"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/sqlite"
)

// withDB returns (sqlitePath, cleanup) — caller seeds the DB then
// invokes Run with -sqlite-path pointed at it.
func withDB(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cli.db")
	b, err := sqlite.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = b.Close()
	return p
}

func runCLI(t *testing.T, dbPath string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	full := append([]string{"-storage", "sqlite", "-sqlite-path", dbPath}, args...)
	err := cliPkg.Run(context.Background(), full, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

func seedRuns(t *testing.T, dbPath string) {
	t.Helper()
	b, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now()
	for _, r := range []storage.Run{
		{ID: "run-aaa", PackageName: "chalk", Version: "5.6.1", State: storage.RunStateDone, Attempt: 1, IsBaseline: true, StartedAt: &now},
		{ID: "run-bbb", PackageName: "chalk", Version: "5.6.2", State: storage.RunStateDone, Attempt: 1, IsBaseline: false, StartedAt: &now},
		{ID: "run-ccc", PackageName: "lodash", Version: "4.18.1", State: storage.RunStateDone, Attempt: 1, IsBaseline: true, StartedAt: &now},
	} {
		if err := b.CreateRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	// Seed an event so the FK from deviations.evidence_event_id resolves.
	if err := b.AppendEvents(ctx, "run-bbb", []storage.EventRow{
		{RunID: "run-bbb", TsNS: 1, Type: "tls_sni", Data: []byte(`{"SNI":"exfil.attacker.example"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	evts, _ := b.ListEventsByRun(ctx, "run-bbb", 1)
	evtID := evts[0].ID
	// Seed a deviation against run-bbb
	if err := b.WriteDeviations(ctx, []storage.DeviationRow{
		{ID: "dev-001", RunID: "run-bbb", Category: "net_new_https_host", Value: "exfil.attacker.example", EvidenceEventID: evtID, Severity: "warn", DetectedAt: now},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPackageList(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)

	out, _, err := runCLI(t, dbPath, "package", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "chalk") {
		t.Errorf("expected 'chalk' in output: %q", out)
	}
	if !strings.Contains(out, "lodash") {
		t.Errorf("expected 'lodash' in output: %q", out)
	}
}

func TestRunListFilteredByPackage(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)

	out, _, err := runCLI(t, dbPath, "run", "list", "-package", "chalk")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "5.6.1") || !strings.Contains(out, "5.6.2") {
		t.Errorf("expected chalk versions in run list: %q", out)
	}
	if strings.Contains(out, "lodash") {
		t.Errorf("run list -package chalk should not show lodash: %q", out)
	}
}

func TestDeviationList(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)

	out, _, err := runCLI(t, dbPath, "deviation", "list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "exfil.attacker.example") {
		t.Errorf("expected deviation value in output: %q", out)
	}
}

func TestDeviationListJSON(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)

	out, _, err := runCLI(t, dbPath, "-json", "deviation", "list")
	if err != nil {
		t.Fatal(err)
	}
	var devs []map[string]any
	if err := json.Unmarshal([]byte(out), &devs); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	if len(devs) != 1 || devs[0]["Value"] != "exfil.attacker.example" {
		t.Errorf("unexpected JSON: %+v", devs)
	}
}

func TestRunShow(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)

	out, _, err := runCLI(t, dbPath, "run", "show", "run-bbb")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"run-bbb", "chalk", "5.6.2", "exfil.attacker.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in run show output: %q", want, out)
		}
	}
}

func TestBaselinePromoteAddsToBaseline(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)
	// Seed events against run-bbb so ExtractFingerprints has something to work with.
	b, _ := sqlite.Open(dbPath)
	defer b.Close()
	_ = b.Migrate(context.Background())
	_ = b.AppendEvents(context.Background(), "run-bbb", []storage.EventRow{
		{RunID: "run-bbb", TsNS: 1, Type: "tls_sni", Data: []byte(`{"SNI":"exfil.attacker.example"}`)},
	})

	out, _, err := runCLI(t, dbPath, "baseline", "promote", "run-bbb")
	if err != nil {
		t.Fatalf("promote: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Promoted run") {
		t.Errorf("expected confirmation: %q", out)
	}

	// Check baseline now contains the SNI from run-bbb.
	bl, err := b.LoadBaseline(context.Background(), "chalk")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range bl {
		if row.Value == "exfil.attacker.example" {
			found = true
		}
	}
	if !found {
		t.Errorf("baseline did not gain promoted fingerprint: %+v", bl)
	}
	// Deviations for run-bbb should now be cleared.
	devs, _ := b.ListDeviations(context.Background(), "run-bbb")
	if len(devs) != 0 {
		t.Errorf("expected deviations cleared after promote, got %d", len(devs))
	}
}

func TestRunShowAcceptsPrefix(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)

	// "run-bb" is the unique prefix matching "run-bbb"
	out, _, err := runCLI(t, dbPath, "run", "show", "run-bb")
	if err != nil {
		t.Fatalf("prefix lookup: %v", err)
	}
	if !strings.Contains(out, "run-bbb") {
		t.Errorf("expected run-bbb id in output: %q", out)
	}
}

func TestRunShowAmbiguousPrefix(t *testing.T) {
	dbPath := withDB(t)
	seedRuns(t, dbPath)

	// "run-" matches all 3 seeded runs
	_, _, err := runCLI(t, dbPath, "run", "show", "run-")
	if err == nil {
		t.Errorf("expected ambiguity error")
	}
	if !strings.Contains(err.Error(), "multiple rows") {
		t.Errorf("expected 'multiple rows' in error: %v", err)
	}
}

func TestUsageOnNoArgs(t *testing.T) {
	dbPath := withDB(t)
	_, stderr, err := runCLI(t, dbPath)
	if err == nil {
		t.Errorf("expected error on no subcommand")
	}
	if !strings.Contains(stderr, "fangs - operator console") {
		t.Errorf("expected usage in stderr: %q", stderr)
	}
}
