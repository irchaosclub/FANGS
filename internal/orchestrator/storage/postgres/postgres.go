// SPDX-License-Identifier: Apache-2.0
//
// Package postgres is the production storage backend for the FANGS
// orchestrator. Uses jackc/pgx/v5's database/sql wrapper so we share
// the migration helper with the sqlite backend; for hot paths
// (AppendEvents) we still use the pool's batch API via Exec.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

const dialect = "postgres"

// Backend is the Postgres-backed implementation of storage.Backend.
type Backend struct {
	db *sql.DB
}

// Open connects to Postgres with the given DSN (pgx-compatible — either
// keyword form "host=... dbname=..." or URL form "postgres://...").
// The returned Backend has no schema applied yet — call Migrate.
func Open(dsn string) (*Backend, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(time.Hour)
	return &Backend{db: db}, nil
}

// Migrate brings the schema up to the latest version.
func (b *Backend) Migrate(ctx context.Context) error {
	fsys, err := storage.MigrationsForDialect(dialect)
	if err != nil {
		return err
	}
	return storage.ApplyMigrations(ctx, b.db, fsys, "$1")
}

// Close releases the underlying connection pool.
func (b *Backend) Close() error { return b.db.Close() }

// --- Runs ---

func (b *Backend) CreateRun(ctx context.Context, r storage.Run) error {
	if !r.State.IsValid() {
		return fmt.Errorf("invalid run state %q", r.State)
	}
	if r.StartedAt == nil {
		now := time.Now().UTC()
		r.StartedAt = &now
	}
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO runs(
			id, package_name, version, tarball_sha256, lockfile_sha256,
			node_version, npm_version, state, attempt, is_baseline,
			started_at, finished_at, failure_reason
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		r.ID, r.PackageName, r.Version, r.TarballSHA256, r.LockfileSHA256,
		r.NodeVersion, r.NPMVersion, string(r.State), r.Attempt, r.IsBaseline,
		nullableTime(r.StartedAt), nullableTime(r.FinishedAt), r.FailureReason,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return storage.ErrConflict
		}
		return fmt.Errorf("insert run: %w", err)
	}
	return nil
}

func (b *Backend) UpdateRunState(ctx context.Context, runID string, state storage.RunState, failureReason string) error {
	if !state.IsValid() {
		return fmt.Errorf("invalid run state %q", state)
	}
	res, err := b.db.ExecContext(ctx, `
		UPDATE runs SET
			state = $1,
			started_at = COALESCE(started_at, CASE WHEN $1 = 'building' THEN now() ELSE NULL END),
			finished_at = CASE WHEN $1 IN ('done','failed') THEN now() ELSE finished_at END,
			failure_reason = CASE WHEN $1 = 'failed' THEN $2 ELSE failure_reason END
		WHERE id = $3`,
		string(state), failureReason, runID,
	)
	if err != nil {
		return fmt.Errorf("update run state: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (b *Backend) GetRun(ctx context.Context, runID string) (storage.Run, error) {
	row := b.db.QueryRowContext(ctx, `
		SELECT id, package_name, version, tarball_sha256, lockfile_sha256,
		       node_version, npm_version, state, attempt, is_baseline,
		       started_at, finished_at, failure_reason,
		       events_emitted, events_dropped, duration_ns
		  FROM runs WHERE id = $1`, runID)
	return scanRun(row)
}

func (b *Backend) ListRuns(ctx context.Context, limit int) ([]storage.Run, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, package_name, version, tarball_sha256, lockfile_sha256,
		       node_version, npm_version, state, attempt, is_baseline,
		       started_at, finished_at, failure_reason,
		       events_emitted, events_dropped, duration_ns
		  FROM runs ORDER BY started_at DESC NULLS LAST LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Events ---

func (b *Backend) AppendEvents(ctx context.Context, runID string, events []storage.EventRow) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events(run_id, ts_ns, type, data) VALUES ($1,$2,$3,$4)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		if _, err := stmt.ExecContext(ctx, runID, e.TsNS, e.Type, string(e.Data)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert event: %w", err)
		}
	}
	return tx.Commit()
}

func (b *Backend) ListEventsByRun(ctx context.Context, runID string, limit int) ([]storage.EventRow, error) {
	if limit <= 0 {
		limit = 10000
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, run_id, ts_ns, type, data::text
		  FROM events WHERE run_id = $1 ORDER BY ts_ns ASC, id ASC LIMIT $2`, runID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.EventRow
	for rows.Next() {
		var e storage.EventRow
		var data string
		if err := rows.Scan(&e.ID, &e.RunID, &e.TsNS, &e.Type, &data); err != nil {
			return nil, err
		}
		e.Data = []byte(data)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (b *Backend) EventCount(ctx context.Context, runID string) (int64, error) {
	var n int64
	err := b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE run_id = $1`, runID).Scan(&n)
	return n, err
}

// --- helpers ---

type rowLike interface {
	Scan(dest ...any) error
}

func scanRun(r rowLike) (storage.Run, error) {
	var (
		run      storage.Run
		state    string
		started  sql.NullTime
		finished sql.NullTime
	)
	err := r.Scan(
		&run.ID, &run.PackageName, &run.Version, &run.TarballSHA256, &run.LockfileSHA256,
		&run.NodeVersion, &run.NPMVersion, &state, &run.Attempt, &run.IsBaseline,
		&started, &finished, &run.FailureReason,
		&run.EventsEmitted, &run.EventsDropped, &run.DurationNS,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.Run{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Run{}, err
	}
	run.State = storage.RunState(state)
	if started.Valid {
		t := started.Time
		run.StartedAt = &t
	}
	if finished.Valid {
		t := finished.Time
		run.FinishedAt = &t
	}
	return run, nil
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC()
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) {
		return pgerr.Code == "23505"
	}
	return strings.Contains(err.Error(), "duplicate key")
}

// --- Baseline ---

func (b *Backend) LoadBaseline(ctx context.Context, packageName string) ([]storage.BaselineRow, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT package_name, category, value, first_seen_run_id, last_seen_run_id, occurrence_count
		  FROM baseline_fingerprints WHERE package_name = $1`, packageName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.BaselineRow
	for rows.Next() {
		var r storage.BaselineRow
		if err := rows.Scan(&r.PackageName, &r.Category, &r.Value, &r.FirstSeenRunID, &r.LastSeenRunID, &r.OccurrenceCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (b *Backend) MergeBaseline(ctx context.Context, runID string, rows []storage.BaselineRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO baseline_fingerprints(
			package_name, category, value,
			first_seen_run_id, last_seen_run_id, occurrence_count
		) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (package_name, category, value) DO UPDATE SET
			last_seen_run_id = EXCLUDED.last_seen_run_id,
			occurrence_count = baseline_fingerprints.occurrence_count + EXCLUDED.occurrence_count`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if r.OccurrenceCount == 0 {
			r.OccurrenceCount = 1
		}
		if r.FirstSeenRunID == "" {
			r.FirstSeenRunID = runID
		}
		if r.LastSeenRunID == "" {
			r.LastSeenRunID = runID
		}
		if _, err := stmt.ExecContext(ctx, r.PackageName, r.Category, r.Value, r.FirstSeenRunID, r.LastSeenRunID, r.OccurrenceCount); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("merge baseline %s/%s: %w", r.Category, r.Value, err)
		}
	}
	return tx.Commit()
}

func (b *Backend) MarkRunBaseline(ctx context.Context, runID string, isBaseline bool) error {
	res, err := b.db.ExecContext(ctx, `UPDATE runs SET is_baseline = $1 WHERE id = $2`, isBaseline, runID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// --- Deviations ---

func (b *Backend) WriteDeviations(ctx context.Context, rows []storage.DeviationRow) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO deviations(id, run_id, category, value, evidence_event_id, severity, detected_at, suppressed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx, r.ID, r.RunID, r.Category, r.Value, r.EvidenceEventID, r.Severity, r.DetectedAt.UTC(), r.Suppressed); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert deviation: %w", err)
		}
	}
	return tx.Commit()
}

func (b *Backend) DeleteDeviationsForRun(ctx context.Context, runID string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM deviations WHERE run_id = $1`, runID)
	return err
}

func (b *Backend) ListDeviationsFiltered(ctx context.Context, f storage.DeviationFilter) ([]storage.DeviationRow, error) {
	q := `SELECT d.id, d.run_id, d.category, d.value, d.evidence_event_id, d.severity, d.detected_at, d.notified_at, d.suppressed
	      FROM deviations d JOIN runs r ON d.run_id = r.id WHERE TRUE`
	args := []any{}
	n := 0
	add := func(cond string, v any) {
		n++
		q += " AND " + fmt.Sprintf(cond, n)
		args = append(args, v)
	}
	if f.PackageName != "" {
		add("r.package_name = $%d", f.PackageName)
	}
	if f.Severity != "" {
		add("d.severity = $%d", f.Severity)
	}
	if f.RunID != "" {
		add("d.run_id = $%d", f.RunID)
	}
	q += " ORDER BY d.detected_at DESC, d.id DESC"
	if f.Limit > 0 {
		n++
		q += fmt.Sprintf(" LIMIT $%d", n)
		args = append(args, f.Limit)
	}
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanDeviationRows(rows)
}

func (b *Backend) GetDeviation(ctx context.Context, id string) (storage.DeviationRow, error) {
	row := b.db.QueryRowContext(ctx, `
		SELECT id, run_id, category, value, evidence_event_id, severity, detected_at, notified_at, suppressed
		  FROM deviations WHERE id = $1`, id)
	return scanDeviationRow(row)
}

func (b *Backend) GetEvent(ctx context.Context, id int64) (storage.EventRow, error) {
	row := b.db.QueryRowContext(ctx, `SELECT id, run_id, ts_ns, type, data::text FROM events WHERE id = $1`, id)
	var (
		e    storage.EventRow
		data string
	)
	if err := row.Scan(&e.ID, &e.RunID, &e.TsNS, &e.Type, &data); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return storage.EventRow{}, storage.ErrNotFound
		}
		return storage.EventRow{}, err
	}
	e.Data = []byte(data)
	return e, nil
}

func (b *Backend) ListPackages(ctx context.Context) ([]storage.PackageSummary, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT package_name,
		       COUNT(*) AS runs_total,
		       SUM(CASE WHEN is_baseline THEN 1 ELSE 0 END) AS runs_baseline
		  FROM runs WHERE package_name <> ''
		  GROUP BY package_name
		  ORDER BY package_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.PackageSummary
	for rows.Next() {
		var p storage.PackageSummary
		if err := rows.Scan(&p.Name, &p.RunsTotal, &p.RunsBaseline); err != nil {
			return nil, err
		}
		latest := b.db.QueryRowContext(ctx, `
			SELECT id, version FROM runs
			  WHERE package_name = $1 ORDER BY started_at DESC NULLS LAST, id DESC LIMIT 1`, p.Name)
		var latestID, latestVer sql.NullString
		if err := latest.Scan(&latestID, &latestVer); err == nil && latestID.Valid {
			p.LatestRunID = latestID.String
			p.LatestVersion = latestVer.String
			var n int
			_ = b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deviations WHERE run_id = $1`, p.LatestRunID).Scan(&n)
			p.DeviationsLatest = n
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (b *Backend) ListRunsByPackage(ctx context.Context, pkg string, limit int) ([]storage.Run, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, package_name, version, tarball_sha256, lockfile_sha256,
		       node_version, npm_version, state, attempt, is_baseline,
		       started_at, finished_at, failure_reason,
		       events_emitted, events_dropped, duration_ns
		  FROM runs WHERE package_name = $1
		  ORDER BY started_at DESC NULLS LAST, id DESC LIMIT $2`, pkg, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Watched packages + releases ---

func (b *Backend) AddWatchedPackage(ctx context.Context, name string) error {
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO packages(name, added_at) VALUES ($1, now())
		ON CONFLICT(name) DO NOTHING`, name)
	return err
}

func (b *Backend) RemoveWatchedPackage(ctx context.Context, name string) error {
	res, err := b.db.ExecContext(ctx, `DELETE FROM packages WHERE name = $1`, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (b *Backend) ListWatchedPackages(ctx context.Context) ([]storage.WatchedPackage, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT name, added_at, last_checked_at, last_seen_version
		  FROM packages ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.WatchedPackage
	for rows.Next() {
		var (
			p         storage.WatchedPackage
			lastCheck sql.NullTime
			lastSeen  sql.NullString
		)
		if err := rows.Scan(&p.Name, &p.AddedAt, &lastCheck, &lastSeen); err != nil {
			return nil, err
		}
		if lastCheck.Valid {
			t := lastCheck.Time
			p.LastCheckedAt = &t
		}
		if lastSeen.Valid {
			p.LastSeenVersion = lastSeen.String
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (b *Backend) UpdatePackageCheck(ctx context.Context, name, version string) error {
	if version != "" {
		_, err := b.db.ExecContext(ctx, `
			UPDATE packages SET last_checked_at = now(), last_seen_version = $1
			 WHERE name = $2`, version, name)
		return err
	}
	_, err := b.db.ExecContext(ctx, `
		UPDATE packages SET last_checked_at = now() WHERE name = $1`, name)
	return err
}

func (b *Backend) RecordRelease(ctx context.Context, r storage.ReleaseRow) error {
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO releases(package_name, version, tarball_sha256, npm_integrity, published_at, discovered_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT(package_name, version) DO NOTHING`,
		r.PackageName, r.Version, r.TarballSHA256, r.NPMIntegrity,
		r.PublishedAt.UTC(), r.DiscoveredAt.UTC())
	return err
}

func (b *Backend) ListReleasesByPackage(ctx context.Context, name string, limit int) ([]storage.ReleaseRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT package_name, version, tarball_sha256, npm_integrity, published_at, discovered_at
		  FROM releases WHERE package_name = $1
		  ORDER BY discovered_at DESC LIMIT $2`, name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.ReleaseRow
	for rows.Next() {
		var r storage.ReleaseRow
		if err := rows.Scan(&r.PackageName, &r.Version, &r.TarballSHA256, &r.NPMIntegrity, &r.PublishedAt, &r.DiscoveredAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (b *Backend) ResolveRunPrefix(ctx context.Context, prefix string) (storage.Run, error) {
	if prefix == "" {
		return storage.Run{}, storage.ErrNotFound
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, package_name, version, tarball_sha256, lockfile_sha256,
		       node_version, npm_version, state, attempt, is_baseline,
		       started_at, finished_at, failure_reason,
		       events_emitted, events_dropped, duration_ns
		  FROM runs WHERE id LIKE $1 LIMIT 2`, prefix+"%")
	if err != nil {
		return storage.Run{}, err
	}
	defer rows.Close()
	var matches []storage.Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return storage.Run{}, err
		}
		matches = append(matches, r)
	}
	if len(matches) == 0 {
		return storage.Run{}, storage.ErrNotFound
	}
	if len(matches) > 1 {
		return storage.Run{}, storage.ErrAmbiguous
	}
	return matches[0], nil
}

func (b *Backend) ResolveDeviationPrefix(ctx context.Context, prefix string) (storage.DeviationRow, error) {
	if prefix == "" {
		return storage.DeviationRow{}, storage.ErrNotFound
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, run_id, category, value, evidence_event_id, severity, detected_at, notified_at, suppressed
		  FROM deviations WHERE id LIKE $1 LIMIT 2`, prefix+"%")
	if err != nil {
		return storage.DeviationRow{}, err
	}
	defer rows.Close()
	var matches []storage.DeviationRow
	for rows.Next() {
		d, err := scanDeviationRow(rows)
		if err != nil {
			return storage.DeviationRow{}, err
		}
		matches = append(matches, d)
	}
	if len(matches) == 0 {
		return storage.DeviationRow{}, storage.ErrNotFound
	}
	if len(matches) > 1 {
		return storage.DeviationRow{}, storage.ErrAmbiguous
	}
	return matches[0], nil
}

func scanDeviationRow(r rowLike) (storage.DeviationRow, error) {
	var (
		d        storage.DeviationRow
		notified sql.NullTime
		detected sql.NullTime
	)
	err := r.Scan(&d.ID, &d.RunID, &d.Category, &d.Value, &d.EvidenceEventID, &d.Severity, &detected, &notified, &d.Suppressed)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.DeviationRow{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.DeviationRow{}, err
	}
	if detected.Valid {
		d.DetectedAt = detected.Time
	}
	if notified.Valid {
		t := notified.Time
		d.NotifiedAt = &t
	}
	return d, nil
}

func scanDeviationRows(rows *sql.Rows) ([]storage.DeviationRow, error) {
	var out []storage.DeviationRow
	for rows.Next() {
		d, err := scanDeviationRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (b *Backend) ListDeviations(ctx context.Context, runID string) ([]storage.DeviationRow, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, run_id, category, value, evidence_event_id, severity, detected_at, notified_at, suppressed
		  FROM deviations WHERE run_id = $1 ORDER BY detected_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.DeviationRow
	for rows.Next() {
		var (
			r        storage.DeviationRow
			notified sql.NullTime
			detected sql.NullTime
		)
		if err := rows.Scan(&r.ID, &r.RunID, &r.Category, &r.Value, &r.EvidenceEventID, &r.Severity, &detected, &notified, &r.Suppressed); err != nil {
			return nil, err
		}
		if detected.Valid {
			r.DetectedAt = detected.Time
		}
		if notified.Valid {
			t := notified.Time
			r.NotifiedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- allowlists ---

func (b *Backend) AddAllowEntry(ctx context.Context, e storage.AllowEntry) error {
	created := e.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	pkg := nullableStringPg(e.PackageName)
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO allowlists(id, scope, package_name, kind, value, note, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, string(e.Scope), pkg, string(e.Kind), e.Value, e.Note, created)
	if err != nil {
		return fmt.Errorf("insert allowlist: %w", err)
	}
	return nil
}

func (b *Backend) ListAllowEntries(ctx context.Context) ([]storage.AllowEntry, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, scope, package_name, kind, value, note, created_at
		  FROM allowlists
		  ORDER BY scope, COALESCE(package_name, ''), kind, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.AllowEntry
	for rows.Next() {
		e, err := scanAllowEntryPg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (b *Backend) DeleteAllowEntry(ctx context.Context, id string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM allowlists WHERE id = $1`, id)
	return err
}

func (b *Backend) ResolveAllowPrefix(ctx context.Context, prefix string) (storage.AllowEntry, error) {
	if prefix == "" {
		return storage.AllowEntry{}, storage.ErrNotFound
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, scope, package_name, kind, value, note, created_at
		  FROM allowlists WHERE id LIKE $1 LIMIT 2`, prefix+"%")
	if err != nil {
		return storage.AllowEntry{}, err
	}
	defer rows.Close()
	var matches []storage.AllowEntry
	for rows.Next() {
		e, err := scanAllowEntryPg(rows)
		if err != nil {
			return storage.AllowEntry{}, err
		}
		matches = append(matches, e)
	}
	if len(matches) == 0 {
		return storage.AllowEntry{}, storage.ErrNotFound
	}
	if len(matches) > 1 {
		return storage.AllowEntry{}, storage.ErrAmbiguous
	}
	return matches[0], nil
}

func scanAllowEntryPg(s pgRowScanner) (storage.AllowEntry, error) {
	var (
		e     storage.AllowEntry
		pkg   sql.NullString
		scope string
		kind  string
	)
	if err := s.Scan(&e.ID, &scope, &pkg, &kind, &e.Value, &e.Note, &e.CreatedAt); err != nil {
		return storage.AllowEntry{}, err
	}
	e.Scope = storage.AllowScope(scope)
	e.Kind = storage.AllowKind(kind)
	e.PackageName = pkg.String
	return e, nil
}

// EventsDroppedTotal returns the lifetime sum of events_dropped.
func (b *Backend) EventsDroppedTotal(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	err := b.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(events_dropped), 0) FROM runs`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("events_dropped total: %w", err)
	}
	return n.Int64, nil
}

// PruneEvents removes events older than the cutoff that aren't pinned
// as deviation evidence (see storage.Backend docstring for rationale).
func (b *Backend) PruneEvents(ctx context.Context, olderThanNS int64) (int64, error) {
	res, err := b.db.ExecContext(ctx, `
		DELETE FROM events
		 WHERE ts_ns < $1
		   AND id NOT IN (SELECT evidence_event_id FROM deviations)`, olderThanNS)
	if err != nil {
		return 0, fmt.Errorf("prune events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (b *Backend) RecordScanResult(ctx context.Context, runID string, r storage.ScanResult) error {
	state := storage.RunStateDone
	switch r.Status {
	case "failed", "timeout":
		state = storage.RunStateFailed
	}
	now := time.Now().UTC()
	res, err := b.db.ExecContext(ctx, `
		UPDATE runs SET
			state          = $1,
			finished_at    = $2,
			failure_reason = CASE WHEN $3 <> '' THEN $4 ELSE failure_reason END,
			events_emitted = $5,
			events_dropped = $6,
			duration_ns    = $7
		WHERE id = $8`,
		string(state), now, r.Reason, r.Reason,
		r.EventsEmitted, r.EventsDropped, r.DurationNS, runID)
	if err != nil {
		return fmt.Errorf("record scan result: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return storage.ErrNotFound
	}
	return nil
}

// --- notifier targets ---

func (b *Backend) UpsertNotifier(ctx context.Context, n storage.NotifierRow) error {
	now := time.Now().UTC()
	created := n.CreatedAt
	if created.IsZero() {
		created = now
	}
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO notifiers(name, url, template, secret_env, headers, min_severity, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT(name) DO UPDATE SET
			url = EXCLUDED.url,
			template = EXCLUDED.template,
			secret_env = EXCLUDED.secret_env,
			headers = EXCLUDED.headers,
			min_severity = EXCLUDED.min_severity,
			enabled = EXCLUDED.enabled,
			updated_at = EXCLUDED.updated_at`,
		n.Name, n.URL, n.Template, nullableStringPg(n.SecretEnv), nullableStringPg(n.Headers),
		nullableStringPg(n.MinSeverity), n.Enabled, created, now)
	return err
}

func (b *Backend) ListNotifiers(ctx context.Context) ([]storage.NotifierRow, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT name, url, template, secret_env, headers, min_severity, enabled, created_at, updated_at
		  FROM notifiers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.NotifierRow
	for rows.Next() {
		n, err := scanNotifierPg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (b *Backend) GetNotifier(ctx context.Context, name string) (storage.NotifierRow, error) {
	row := b.db.QueryRowContext(ctx, `
		SELECT name, url, template, secret_env, headers, min_severity, enabled, created_at, updated_at
		  FROM notifiers WHERE name = $1`, name)
	n, err := scanNotifierPg(row)
	if err == sql.ErrNoRows {
		return storage.NotifierRow{}, storage.ErrNotFound
	}
	return n, err
}

func (b *Backend) DeleteNotifier(ctx context.Context, name string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM notifiers WHERE name = $1`, name)
	return err
}

func (b *Backend) RecordNotification(ctx context.Context, n storage.NotificationRow) error {
	created := n.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO notifications(id, run_id, notifier_name, attempt, status,
		  last_attempted_at, next_attempt_at, response_code, response_body, error_msg,
		  deviation_count, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		n.ID, n.RunID, n.NotifierName, n.Attempt, n.Status,
		nullableTime(n.LastAttemptedAt), nullableTime(n.NextAttemptAt),
		n.ResponseCode, nullableStringPg(n.ResponseBody), nullableStringPg(n.ErrorMsg),
		n.DeviationCount, created)
	return err
}

func (b *Backend) ListNotificationsByRun(ctx context.Context, runID string) ([]storage.NotificationRow, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, run_id, notifier_name, attempt, status,
		       last_attempted_at, next_attempt_at, response_code, response_body, error_msg,
		       deviation_count, created_at
		  FROM notifications WHERE run_id = $1 ORDER BY attempt`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.NotificationRow
	for rows.Next() {
		n, err := scanNotificationPg(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

type pgRowScanner interface {
	Scan(dest ...any) error
}

func scanNotifierPg(s pgRowScanner) (storage.NotifierRow, error) {
	var (
		n         storage.NotifierRow
		secretEnv sql.NullString
		headers   sql.NullString
		minSev    sql.NullString
	)
	if err := s.Scan(&n.Name, &n.URL, &n.Template, &secretEnv, &headers, &minSev,
		&n.Enabled, &n.CreatedAt, &n.UpdatedAt); err != nil {
		return storage.NotifierRow{}, err
	}
	n.SecretEnv = secretEnv.String
	n.Headers = headers.String
	n.MinSeverity = minSev.String
	return n, nil
}

func scanNotificationPg(s pgRowScanner) (storage.NotificationRow, error) {
	var (
		n        storage.NotificationRow
		lastAt   sql.NullTime
		nextAt   sql.NullTime
		respCode sql.NullInt64
		respBody sql.NullString
		errMsg   sql.NullString
	)
	if err := s.Scan(&n.ID, &n.RunID, &n.NotifierName, &n.Attempt, &n.Status,
		&lastAt, &nextAt, &respCode, &respBody, &errMsg, &n.DeviationCount, &n.CreatedAt); err != nil {
		return storage.NotificationRow{}, err
	}
	if lastAt.Valid {
		t := lastAt.Time
		n.LastAttemptedAt = &t
	}
	if nextAt.Valid {
		t := nextAt.Time
		n.NextAttemptAt = &t
	}
	if respCode.Valid {
		n.ResponseCode = int(respCode.Int64)
	}
	n.ResponseBody = respBody.String
	n.ErrorMsg = errMsg.String
	return n, nil
}

func nullableStringPg(s string) any {
	if s == "" {
		return nil
	}
	return s
}
