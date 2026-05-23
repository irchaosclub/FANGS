// SPDX-License-Identifier: Apache-2.0
package watcher_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/sqlite"
	"github.com/irchaosclub/FANGS/internal/orchestrator/watcher"
)

// fakeRegistry returns canned PackageVersion values per call.
type fakeRegistry struct {
	mu    sync.Mutex
	calls []string
	resp  map[string]watcher.PackageVersion
}

func (f *fakeRegistry) Resolve(_ context.Context, name, version string) (watcher.PackageVersion, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	v, ok := f.resp[name]
	if !ok {
		return watcher.PackageVersion{}, watcher.ErrPackageNotFound
	}
	if version != "" && version != v.Version {
		return watcher.PackageVersion{}, watcher.ErrVersionNotFound
	}
	return v, nil
}

func (f *fakeRegistry) LatestVersion(ctx context.Context, name string) (watcher.PackageVersion, error) {
	return f.Resolve(ctx, name, "")
}

func setupStore(t *testing.T) storage.Backend {
	t.Helper()
	p := filepath.Join(t.TempDir(), "w.db")
	b, err := sqlite.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPollOnceFirstReleaseSubmitsScan(t *testing.T) {
	ctx := context.Background()
	store := setupStore(t)
	if err := store.AddWatchedPackage(ctx, "chalk"); err != nil {
		t.Fatal(err)
	}
	reg := &fakeRegistry{resp: map[string]watcher.PackageVersion{
		"chalk": {Name: "chalk", Version: "5.6.2", TarballSHA: "abc", Integrity: "sha512-xyz", PublishedAt: time.Now()},
	}}
	var submitted []string
	submit := func(_ context.Context, pkg, version string) (string, error) {
		submitted = append(submitted, pkg+"@"+version)
		return "run-1", nil
	}
	w := watcher.New(watcher.Options{
		Store:    store,
		Registry: reg,
		Submit:   submit,
	})
	w.PollOnce(ctx)

	if len(submitted) != 1 || submitted[0] != "chalk@5.6.2" {
		t.Errorf("expected one submission for chalk@5.6.2, got %v", submitted)
	}
	pkgs, _ := store.ListWatchedPackages(ctx)
	if pkgs[0].LastSeenVersion != "5.6.2" {
		t.Errorf("last_seen_version not updated: %q", pkgs[0].LastSeenVersion)
	}
	if pkgs[0].LastCheckedAt == nil {
		t.Error("last_checked_at not stamped")
	}
	rels, _ := store.ListReleasesByPackage(ctx, "chalk", 10)
	if len(rels) != 1 || rels[0].Version != "5.6.2" {
		t.Errorf("expected release row for 5.6.2, got %+v", rels)
	}
}

func TestPollOnceNoChangeSkips(t *testing.T) {
	ctx := context.Background()
	store := setupStore(t)
	_ = store.AddWatchedPackage(ctx, "chalk")
	_ = store.UpdatePackageCheck(ctx, "chalk", "5.6.2")

	reg := &fakeRegistry{resp: map[string]watcher.PackageVersion{
		"chalk": {Name: "chalk", Version: "5.6.2"},
	}}
	calls := 0
	submit := func(_ context.Context, _, _ string) (string, error) {
		calls++
		return "run-1", nil
	}
	w := watcher.New(watcher.Options{Store: store, Registry: reg, Submit: submit})
	w.PollOnce(ctx)
	if calls != 0 {
		t.Errorf("expected no submission when version unchanged, got %d", calls)
	}
}

func TestPollOnceNewVersionTriggersSecondScan(t *testing.T) {
	ctx := context.Background()
	store := setupStore(t)
	_ = store.AddWatchedPackage(ctx, "chalk")
	_ = store.UpdatePackageCheck(ctx, "chalk", "5.6.1") // baseline already at 5.6.1

	reg := &fakeRegistry{resp: map[string]watcher.PackageVersion{
		"chalk": {Name: "chalk", Version: "5.6.2"},
	}}
	var calls []string
	submit := func(_ context.Context, pkg, v string) (string, error) {
		calls = append(calls, pkg+"@"+v)
		return "run-1", nil
	}
	w := watcher.New(watcher.Options{Store: store, Registry: reg, Submit: submit})
	w.PollOnce(ctx)
	if len(calls) != 1 || calls[0] != "chalk@5.6.2" {
		t.Errorf("expected one submission for chalk@5.6.2, got %v", calls)
	}
}

func TestPollOnceRegistryErrorLeavesStateUnchanged(t *testing.T) {
	ctx := context.Background()
	store := setupStore(t)
	_ = store.AddWatchedPackage(ctx, "ghost-package")
	reg := &fakeRegistry{resp: map[string]watcher.PackageVersion{}} // intentionally empty -> ErrPackageNotFound
	calls := 0
	submit := func(_ context.Context, _, _ string) (string, error) {
		calls++
		return "", nil
	}
	w := watcher.New(watcher.Options{Store: store, Registry: reg, Submit: submit})
	w.PollOnce(ctx)
	if calls != 0 {
		t.Errorf("no submission expected when registry says not-found")
	}
	pkgs, _ := store.ListWatchedPackages(ctx)
	if pkgs[0].LastSeenVersion != "" || pkgs[0].LastCheckedAt != nil {
		t.Errorf("state should be unchanged on registry error, got %+v", pkgs[0])
	}
}

func TestBuildSandboxScan(t *testing.T) {
	spec := watcher.BuildSandboxScan("axios", "1.2.3")
	if spec.Image != "node:20-slim" {
		t.Errorf("image: got %q", spec.Image)
	}
	if spec.User != "0:0" {
		t.Errorf("user: got %q", spec.User)
	}
	joined := ""
	for _, c := range spec.Command {
		joined += c + " "
	}
	if !contains(joined, "axios@1.2.3") {
		t.Errorf("command does not mention axios@1.2.3: %s", joined)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
