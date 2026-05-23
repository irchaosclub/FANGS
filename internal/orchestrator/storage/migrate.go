// SPDX-License-Identifier: Apache-2.0
package storage

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed all:migrations
var migrationsFS embed.FS

// MigrationsForDialect returns the embedded migrations subtree for the
// given dialect ("sqlite" or "postgres").
func MigrationsForDialect(dialect string) (fs.FS, error) {
	sub, err := fs.Sub(migrationsFS, "migrations/"+dialect)
	if err != nil {
		return nil, fmt.Errorf("locate embedded migrations for %q: %w", dialect, err)
	}
	return sub, nil
}

// ApplyMigrations runs every *.up.sql in fsys in lexicographic order,
// recording applied versions in schema_migrations. Idempotent.
//
// versionPlaceholder is the dialect's parameter placeholder for the
// version INSERT: "?" for sqlite, "$1" for postgres. Passed in rather
// than detected because the database/sql layer hides the dialect.
func ApplyMigrations(ctx context.Context, db *sql.DB, fsys fs.FS, versionPlaceholder string) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	applied := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("list applied: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	var ups []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".up.sql") {
			continue
		}
		ups = append(ups, e.Name())
	}
	sort.Strings(ups)

	insertSQL := fmt.Sprintf(`INSERT INTO schema_migrations(version) VALUES (%s)`, versionPlaceholder)

	for _, name := range ups {
		version := strings.TrimSuffix(name, ".up.sql")
		if applied[version] {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(body)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("exec %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, insertSQL, version); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}
