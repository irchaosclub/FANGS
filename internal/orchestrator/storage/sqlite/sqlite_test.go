// SPDX-License-Identifier: Apache-2.0
package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/sqlite"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/storagetest"
)

func TestContractSQLite(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "fangs-test.db")

	b, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	storagetest.RunContract(t, b)
}

func TestMigrateIdempotent(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "idempotent.db")
	b, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	for i := 0; i < 3; i++ {
		if err := b.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate attempt %d: %v", i+1, err)
		}
	}
}
