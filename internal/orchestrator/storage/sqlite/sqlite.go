// SPDX-License-Identifier: Apache-2.0
//
// Package sqlite is the file-backed default storage backend for the
// FANGS orchestrator. Uses modernc.org/sqlite (pure Go — no CGO) so
// the binary cross-compiles cleanly. WAL mode is enabled on open for
// concurrent reads + a single writer.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/irchaosclub/FANGS/internal/orchestrator/storage"
)

const dialect = "sqlite"

// Backend is a SQLite-backed implementation of storage.Backend.
type Backend struct {
	db *sql.DB
}

// Open creates or opens a SQLite database at path. The parent directory
// must exist. The returned Backend has WAL + foreign-keys enabled but
// no schema yet — call Migrate before use.
func Open(path string) (*Backend, error) {
	// modernc registers the driver as "sqlite".
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)", filepath.ToSlash(path))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite at %q: %w", path, err)
	}
	// modernc.org/sqlite allows >1 conn but writes still serialize via
	// SQLite's own locking. Pin to a modest pool size.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(0)
	return &Backend{db: db}, nil
}

// Migrate brings the schema up to the latest version.
func (b *Backend) Migrate(ctx context.Context) error {
	fsys, err := storage.MigrationsForDialect(dialect)
	if err != nil {
		return err
	}
	return storage.ApplyMigrations(ctx, b.db, fsys, "?")
}

// Close releases the underlying connection pool.
func (b *Backend) Close() error { return b.db.Close() }

// --- Runs ---

func (b *Backend) CreateRun(ctx context.Context, r storage.Run) error {
	if !r.State.IsValid() {
		return fmt.Errorf("invalid run state %q", r.State)
	}
	// Stamp StartedAt at creation if caller didn't set one — gives the
	// CLI a useful "when did this scan come in" timestamp even when the
	// run skips the explicit pending->building transition.
	if r.StartedAt == nil {
		now := time.Now().UTC()
		r.StartedAt = &now
	}
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO runs(
			id, package_name, version, tarball_sha256, lockfile_sha256,
			node_version, npm_version, state, attempt, is_baseline,
			started_at, finished_at, failure_reason
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.PackageName, r.Version, r.TarballSHA256, r.LockfileSHA256,
		r.NodeVersion, r.NPMVersion, string(r.State), r.Attempt, boolToInt(r.IsBaseline),
		nullableTime(r.StartedAt), nullableTime(r.FinishedAt), r.FailureReason,
	)
	if err != nil {
		// SQLite's UNIQUE-constraint error message contains "UNIQUE".
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := b.db.ExecContext(ctx, `
		UPDATE runs SET
			state = ?,
			started_at = COALESCE(started_at, CASE WHEN ? = 'building' THEN ? ELSE NULL END),
			finished_at = CASE WHEN ? IN ('done','failed') THEN ? ELSE finished_at END,
			failure_reason = CASE WHEN ? = 'failed' THEN ? ELSE failure_reason END
		WHERE id = ?`,
		string(state),
		string(state), now,
		string(state), now,
		string(state), failureReason,
		runID,
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
		  FROM runs WHERE id = ?`, runID)
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
		  FROM runs ORDER BY COALESCE(started_at, '') DESC LIMIT ?`, limit)
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
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO events(run_id, ts_ns, type, data) VALUES (?,?,?,?)`)
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
		SELECT id, run_id, ts_ns, type, data
		  FROM events WHERE run_id = ? ORDER BY ts_ns ASC, id ASC LIMIT ?`, runID, limit)
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
	err := b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE run_id = ?`, runID).Scan(&n)
	return n, err
}

// --- helpers ---

// rowLike abstracts *sql.Row and *sql.Rows for shared scanRun logic.
type rowLike interface {
	Scan(dest ...any) error
}

func scanRun(r rowLike) (storage.Run, error) {
	var (
		run        storage.Run
		isBaseline int
		started    sql.NullString
		finished   sql.NullString
		state      string
	)
	err := r.Scan(
		&run.ID, &run.PackageName, &run.Version, &run.TarballSHA256, &run.LockfileSHA256,
		&run.NodeVersion, &run.NPMVersion, &state, &run.Attempt, &isBaseline,
		&started, &finished, &run.FailureReason,
		&run.EventsEmitted, &run.EventsDropped, &run.DurationNS,
	)
	if err == sql.ErrNoRows {
		return storage.Run{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.Run{}, err
	}
	run.State = storage.RunState(state)
	run.IsBaseline = isBaseline != 0
	if started.Valid {
		t, _ := time.Parse(time.RFC3339Nano, started.String)
		run.StartedAt = &t
	}
	if finished.Valid {
		t, _ := time.Parse(time.RFC3339Nano, finished.String)
		run.FinishedAt = &t
	}
	return run, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || strings.Contains(msg, "constraint failed: UNIQUE")
}

// --- Baseline ---

func (b *Backend) LoadBaseline(ctx context.Context, packageName string) ([]storage.BaselineRow, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT package_name, category, value, first_seen_run_id, last_seen_run_id, occurrence_count
		  FROM baseline_fingerprints WHERE package_name = ?`, packageName)
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
		) VALUES (?,?,?,?,?,?)
		ON CONFLICT(package_name, category, value) DO UPDATE SET
			last_seen_run_id = excluded.last_seen_run_id,
			occurrence_count = baseline_fingerprints.occurrence_count + excluded.occurrence_count`)
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
	v := 0
	if isBaseline {
		v = 1
	}
	res, err := b.db.ExecContext(ctx, `UPDATE runs SET is_baseline = ? WHERE id = ?`, v, runID)
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
		VALUES (?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		susp := 0
		if r.Suppressed {
			susp = 1
		}
		if _, err := stmt.ExecContext(ctx, r.ID, r.RunID, r.Category, r.Value, r.EvidenceEventID, r.Severity, r.DetectedAt.UTC().Format(time.RFC3339Nano), susp); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("insert deviation: %w", err)
		}
	}
	return tx.Commit()
}

func (b *Backend) DeleteDeviationsForRun(ctx context.Context, runID string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM deviations WHERE run_id = ?`, runID)
	return err
}

func (b *Backend) ListDeviationsFiltered(ctx context.Context, f storage.DeviationFilter) ([]storage.DeviationRow, error) {
	q := `SELECT d.id, d.run_id, d.category, d.value, d.evidence_event_id, d.severity, d.detected_at, d.notified_at, d.suppressed
	      FROM deviations d JOIN runs r ON d.run_id = r.id WHERE 1=1`
	args := []any{}
	if f.PackageName != "" {
		q += ` AND r.package_name = ?`
		args = append(args, f.PackageName)
	}
	if f.Severity != "" {
		q += ` AND d.severity = ?`
		args = append(args, f.Severity)
	}
	if f.RunID != "" {
		q += ` AND d.run_id = ?`
		args = append(args, f.RunID)
	}
	q += ` ORDER BY d.detected_at DESC, d.id DESC`
	if f.Limit > 0 {
		q += ` LIMIT ?`
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
		  FROM deviations WHERE id = ?`, id)
	return scanDeviationRow(row)
}

func (b *Backend) GetEvent(ctx context.Context, id int64) (storage.EventRow, error) {
	row := b.db.QueryRowContext(ctx, `SELECT id, run_id, ts_ns, type, data FROM events WHERE id = ?`, id)
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
		       SUM(CASE WHEN is_baseline = 1 THEN 1 ELSE 0 END) AS runs_baseline
		  FROM runs WHERE package_name != ''
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
		// Decorate with the latest run's id, version, and deviation count.
		latest := b.db.QueryRowContext(ctx, `
			SELECT id, version FROM runs
			  WHERE package_name = ? ORDER BY started_at DESC, id DESC LIMIT 1`, p.Name)
		var latestID, latestVer sql.NullString
		if err := latest.Scan(&latestID, &latestVer); err == nil && latestID.Valid {
			p.LatestRunID = latestID.String
			p.LatestVersion = latestVer.String
			var n int
			_ = b.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM deviations WHERE run_id = ?`, p.LatestRunID).Scan(&n)
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
		  FROM runs WHERE package_name = ?
		  ORDER BY COALESCE(started_at, '') DESC, id DESC LIMIT ?`, pkg, limit)
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO packages(name, added_at) VALUES (?, ?)
		ON CONFLICT(name) DO NOTHING`, name, now)
	return err
}

func (b *Backend) RemoveWatchedPackage(ctx context.Context, name string) error {
	res, err := b.db.ExecContext(ctx, `DELETE FROM packages WHERE name = ?`, name)
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
			added     string
			lastCheck sql.NullString
			lastSeen  sql.NullString
		)
		if err := rows.Scan(&p.Name, &added, &lastCheck, &lastSeen); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, added); err == nil {
			p.AddedAt = t
		}
		if lastCheck.Valid {
			if t, err := time.Parse(time.RFC3339Nano, lastCheck.String); err == nil {
				p.LastCheckedAt = &t
			}
		}
		if lastSeen.Valid {
			p.LastSeenVersion = lastSeen.String
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (b *Backend) UpdatePackageCheck(ctx context.Context, name, version string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if version != "" {
		_, err := b.db.ExecContext(ctx, `
			UPDATE packages SET last_checked_at = ?, last_seen_version = ?
			 WHERE name = ?`, now, version, name)
		return err
	}
	_, err := b.db.ExecContext(ctx, `
		UPDATE packages SET last_checked_at = ? WHERE name = ?`, now, name)
	return err
}

func (b *Backend) RecordRelease(ctx context.Context, r storage.ReleaseRow) error {
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO releases(package_name, version, tarball_sha256, npm_integrity, published_at, discovered_at)
		VALUES (?,?,?,?,?,?)
		ON CONFLICT(package_name, version) DO NOTHING`,
		r.PackageName, r.Version, r.TarballSHA256, r.NPMIntegrity,
		r.PublishedAt.UTC().Format(time.RFC3339Nano),
		r.DiscoveredAt.UTC().Format(time.RFC3339Nano),
	)
	return err
}

func (b *Backend) ListReleasesByPackage(ctx context.Context, name string, limit int) ([]storage.ReleaseRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT package_name, version, tarball_sha256, npm_integrity, published_at, discovered_at
		  FROM releases WHERE package_name = ?
		  ORDER BY discovered_at DESC LIMIT ?`, name, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.ReleaseRow
	for rows.Next() {
		var (
			r          storage.ReleaseRow
			published  string
			discovered string
		)
		if err := rows.Scan(&r.PackageName, &r.Version, &r.TarballSHA256, &r.NPMIntegrity, &published, &discovered); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339Nano, published); err == nil {
			r.PublishedAt = t
		}
		if t, err := time.Parse(time.RFC3339Nano, discovered); err == nil {
			r.DiscoveredAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResolveRunPrefix supports git-style short ids in the CLI.
func (b *Backend) ResolveRunPrefix(ctx context.Context, prefix string) (storage.Run, error) {
	if prefix == "" {
		return storage.Run{}, storage.ErrNotFound
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, package_name, version, tarball_sha256, lockfile_sha256,
		       node_version, npm_version, state, attempt, is_baseline,
		       started_at, finished_at, failure_reason,
		       events_emitted, events_dropped, duration_ns
		  FROM runs WHERE id LIKE ? LIMIT 2`, prefix+"%")
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
		  FROM deviations WHERE id LIKE ? LIMIT 2`, prefix+"%")
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
		d          storage.DeviationRow
		detected   string
		notified   sql.NullString
		suppressed int
	)
	err := r.Scan(&d.ID, &d.RunID, &d.Category, &d.Value, &d.EvidenceEventID, &d.Severity, &detected, &notified, &suppressed)
	if errors.Is(err, sql.ErrNoRows) {
		return storage.DeviationRow{}, storage.ErrNotFound
	}
	if err != nil {
		return storage.DeviationRow{}, err
	}
	if t, perr := time.Parse(time.RFC3339Nano, detected); perr == nil {
		d.DetectedAt = t
	}
	if notified.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, notified.String); perr == nil {
			d.NotifiedAt = &t
		}
	}
	d.Suppressed = suppressed != 0
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
		  FROM deviations WHERE run_id = ? ORDER BY detected_at ASC, id ASC`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.DeviationRow
	for rows.Next() {
		var (
			r          storage.DeviationRow
			detected   string
			notified   sql.NullString
			suppressed int
		)
		if err := rows.Scan(&r.ID, &r.RunID, &r.Category, &r.Value, &r.EvidenceEventID, &r.Severity, &detected, &notified, &suppressed); err != nil {
			return nil, err
		}
		if t, perr := time.Parse(time.RFC3339Nano, detected); perr == nil {
			r.DetectedAt = t
		}
		if notified.Valid {
			if t, perr := time.Parse(time.RFC3339Nano, notified.String); perr == nil {
				r.NotifiedAt = &t
			}
		}
		r.Suppressed = suppressed != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- allowlists ---

func (b *Backend) AddAllowEntry(ctx context.Context, e storage.AllowEntry) error {
	created := e.CreatedAt.UTC().Format(time.RFC3339Nano)
	if e.CreatedAt.IsZero() {
		created = time.Now().UTC().Format(time.RFC3339Nano)
	}
	pkg := nullableString(e.PackageName)
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO allowlists(id, scope, package_name, kind, value, note, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
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
		e, err := scanAllowEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (b *Backend) DeleteAllowEntry(ctx context.Context, id string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM allowlists WHERE id = ?`, id)
	return err
}

func (b *Backend) ResolveAllowPrefix(ctx context.Context, prefix string) (storage.AllowEntry, error) {
	if prefix == "" {
		return storage.AllowEntry{}, storage.ErrNotFound
	}
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, scope, package_name, kind, value, note, created_at
		  FROM allowlists WHERE id LIKE ? LIMIT 2`, prefix+"%")
	if err != nil {
		return storage.AllowEntry{}, err
	}
	defer rows.Close()
	var matches []storage.AllowEntry
	for rows.Next() {
		e, err := scanAllowEntry(rows)
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

func scanAllowEntry(s rowScanner) (storage.AllowEntry, error) {
	var (
		e       storage.AllowEntry
		pkg     sql.NullString
		scope   string
		kind    string
		created string
	)
	if err := s.Scan(&e.ID, &scope, &pkg, &kind, &e.Value, &e.Note, &created); err != nil {
		return storage.AllowEntry{}, err
	}
	e.Scope = storage.AllowScope(scope)
	e.Kind = storage.AllowKind(kind)
	e.PackageName = pkg.String
	if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
		e.CreatedAt = t
	}
	return e, nil
}

// EventsDroppedTotal returns the lifetime sum of events_dropped from
// every run.
func (b *Backend) EventsDroppedTotal(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	err := b.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(events_dropped), 0) FROM runs`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("events_dropped total: %w", err)
	}
	return n.Int64, nil
}

// PruneEvents removes events older than the cutoff that aren't pinned
// as deviation evidence.
func (b *Backend) PruneEvents(ctx context.Context, olderThanNS int64) (int64, error) {
	// SQLite's NOT IN with NULL handling is fine here because
	// evidence_event_id is NOT NULL on the deviations table.
	res, err := b.db.ExecContext(ctx, `
		DELETE FROM events
		 WHERE ts_ns < ?
		   AND id NOT IN (SELECT evidence_event_id FROM deviations)`, olderThanNS)
	if err != nil {
		return 0, fmt.Errorf("prune events: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RecordScanResult finalizes a run.
func (b *Backend) RecordScanResult(ctx context.Context, runID string, r storage.ScanResult) error {
	state := storage.RunStateDone
	switch r.Status {
	case "failed", "timeout":
		state = storage.RunStateFailed
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := b.db.ExecContext(ctx, `
		UPDATE runs SET
			state          = ?,
			finished_at    = ?,
			failure_reason = CASE WHEN ? <> '' THEN ? ELSE failure_reason END,
			events_emitted = ?,
			events_dropped = ?,
			duration_ns    = ?
		WHERE id = ?`,
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
	now := time.Now().UTC().Format(time.RFC3339Nano)
	created := n.CreatedAt.UTC().Format(time.RFC3339Nano)
	if n.CreatedAt.IsZero() {
		created = now
	}
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO notifiers(name, url, template, secret_env, headers, min_severity, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			url = excluded.url,
			template = excluded.template,
			secret_env = excluded.secret_env,
			headers = excluded.headers,
			min_severity = excluded.min_severity,
			enabled = excluded.enabled,
			updated_at = excluded.updated_at`,
		n.Name, n.URL, n.Template, nullableString(n.SecretEnv), nullableString(n.Headers),
		nullableString(n.MinSeverity), boolInt(n.Enabled), created, now)
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
		n, err := scanNotifier(rows)
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
		  FROM notifiers WHERE name = ?`, name)
	n, err := scanNotifier(row)
	if err == sql.ErrNoRows {
		return storage.NotifierRow{}, storage.ErrNotFound
	}
	return n, err
}

func (b *Backend) DeleteNotifier(ctx context.Context, name string) error {
	_, err := b.db.ExecContext(ctx, `DELETE FROM notifiers WHERE name = ?`, name)
	return err
}

// --- notification delivery log ---

func (b *Backend) RecordNotification(ctx context.Context, n storage.NotificationRow) error {
	created := n.CreatedAt.UTC().Format(time.RFC3339Nano)
	if n.CreatedAt.IsZero() {
		created = time.Now().UTC().Format(time.RFC3339Nano)
	}
	_, err := b.db.ExecContext(ctx, `
		INSERT INTO notifications(id, run_id, notifier_name, attempt, status,
		  last_attempted_at, next_attempt_at, response_code, response_body, error_msg,
		  deviation_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		n.ID, n.RunID, n.NotifierName, n.Attempt, n.Status,
		nullableTime(n.LastAttemptedAt), nullableTime(n.NextAttemptAt),
		n.ResponseCode, nullableString(n.ResponseBody), nullableString(n.ErrorMsg),
		n.DeviationCount, created)
	return err
}

func (b *Backend) ListNotificationsByRun(ctx context.Context, runID string) ([]storage.NotificationRow, error) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT id, run_id, notifier_name, attempt, status,
		       last_attempted_at, next_attempt_at, response_code, response_body, error_msg,
		       deviation_count, created_at
		  FROM notifications WHERE run_id = ? ORDER BY attempt`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.NotificationRow
	for rows.Next() {
		n, err := scanNotification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// --- helpers ---

func scanNotifier(s rowScanner) (storage.NotifierRow, error) {
	var (
		n         storage.NotifierRow
		secretEnv sql.NullString
		headers   sql.NullString
		minSev    sql.NullString
		enabled   int
		created   string
		updated   string
	)
	if err := s.Scan(&n.Name, &n.URL, &n.Template, &secretEnv, &headers, &minSev, &enabled, &created, &updated); err != nil {
		return storage.NotifierRow{}, err
	}
	n.SecretEnv = secretEnv.String
	n.Headers = headers.String
	n.MinSeverity = minSev.String
	n.Enabled = enabled != 0
	if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
		n.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339Nano, updated); err == nil {
		n.UpdatedAt = t
	}
	return n, nil
}

func scanNotification(s rowScanner) (storage.NotificationRow, error) {
	var (
		n        storage.NotificationRow
		lastAt   sql.NullString
		nextAt   sql.NullString
		respCode sql.NullInt64
		respBody sql.NullString
		errMsg   sql.NullString
		created  string
	)
	if err := s.Scan(&n.ID, &n.RunID, &n.NotifierName, &n.Attempt, &n.Status,
		&lastAt, &nextAt, &respCode, &respBody, &errMsg, &n.DeviationCount, &created); err != nil {
		return storage.NotificationRow{}, err
	}
	if lastAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, lastAt.String); err == nil {
			n.LastAttemptedAt = &t
		}
	}
	if nextAt.Valid {
		if t, err := time.Parse(time.RFC3339Nano, nextAt.String); err == nil {
			n.NextAttemptAt = &t
		}
	}
	if respCode.Valid {
		n.ResponseCode = int(respCode.Int64)
	}
	n.ResponseBody = respBody.String
	n.ErrorMsg = errMsg.String
	if t, err := time.Parse(time.RFC3339Nano, created); err == nil {
		n.CreatedAt = t
	}
	return n, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
