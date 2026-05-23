// SPDX-License-Identifier: Apache-2.0
package postgres_test

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/postgres"
	"github.com/irchaosclub/FANGS/internal/orchestrator/storage/storagetest"
)

// TestContractPostgres runs the storage contract against a real Postgres
// instance. Gated on FANGS_PG_TEST_DSN — if not set, the test is skipped.
// CI provides the DSN via a postgres service container.
func TestContractPostgres(t *testing.T) {
	dsn := os.Getenv("FANGS_PG_TEST_DSN")
	if dsn == "" {
		t.Skip("FANGS_PG_TEST_DSN not set; skipping postgres contract test")
	}

	ctx := context.Background()

	// Drop any leftover tables from a previous run so we start clean.
	clean, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open cleanup conn: %v", err)
	}
	for _, drop := range []string{
		`DROP TABLE IF EXISTS notifications CASCADE`,
		`DROP TABLE IF EXISTS deviations CASCADE`,
		`DROP TABLE IF EXISTS baseline_fingerprints CASCADE`,
		`DROP TABLE IF EXISTS events CASCADE`,
		`DROP TABLE IF EXISTS runs CASCADE`,
		`DROP TABLE IF EXISTS releases CASCADE`,
		`DROP TABLE IF EXISTS packages CASCADE`,
		`DROP TABLE IF EXISTS schema_migrations CASCADE`,
	} {
		if _, err := clean.ExecContext(ctx, drop); err != nil {
			t.Logf("cleanup %q: %v (continuing)", drop, err)
		}
	}
	_ = clean.Close()

	b, err := postgres.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	if err := b.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	storagetest.RunContract(t, b)
}
