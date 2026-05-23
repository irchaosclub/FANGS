-- Postgres schema for FANGS orchestrator. ARCHITECTURE.md §7.

CREATE TABLE packages (
  name              TEXT PRIMARY KEY,
  added_at          TIMESTAMPTZ NOT NULL,
  last_checked_at   TIMESTAMPTZ,
  last_seen_version TEXT
);

CREATE TABLE releases (
  package_name   TEXT NOT NULL REFERENCES packages(name) ON DELETE CASCADE,
  version        TEXT NOT NULL,
  tarball_sha256 TEXT NOT NULL,
  npm_integrity  TEXT NOT NULL,
  published_at   TIMESTAMPTZ NOT NULL,
  discovered_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (package_name, version)
);

CREATE TABLE runs (
  id              TEXT PRIMARY KEY,
  package_name    TEXT NOT NULL DEFAULT '',
  version         TEXT NOT NULL DEFAULT '',
  tarball_sha256  TEXT NOT NULL DEFAULT '',
  lockfile_sha256 TEXT NOT NULL DEFAULT '',
  node_version    TEXT NOT NULL DEFAULT '',
  npm_version     TEXT NOT NULL DEFAULT '',
  state           TEXT NOT NULL,
  attempt         INTEGER NOT NULL DEFAULT 1,
  is_baseline     BOOLEAN NOT NULL DEFAULT FALSE,
  started_at      TIMESTAMPTZ,
  finished_at     TIMESTAMPTZ,
  failure_reason  TEXT NOT NULL DEFAULT ''
);

CREATE INDEX runs_by_pkg_state ON runs (package_name, state);
CREATE INDEX runs_by_finished  ON runs (finished_at);

CREATE TABLE events (
  id     BIGSERIAL PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  ts_ns  BIGINT NOT NULL,
  type   TEXT NOT NULL,
  data   JSONB NOT NULL
);

CREATE INDEX events_by_run ON events (run_id, ts_ns);

CREATE TABLE baseline_fingerprints (
  package_name      TEXT NOT NULL,
  category          TEXT NOT NULL,
  value             TEXT NOT NULL,
  first_seen_run_id TEXT NOT NULL,
  last_seen_run_id  TEXT NOT NULL,
  occurrence_count  INTEGER NOT NULL,
  PRIMARY KEY (package_name, category, value)
);

CREATE TABLE deviations (
  id                TEXT PRIMARY KEY,
  run_id            TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  category          TEXT NOT NULL,
  value             TEXT NOT NULL,
  evidence_event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  severity          TEXT NOT NULL,
  detected_at       TIMESTAMPTZ NOT NULL,
  notified_at       TIMESTAMPTZ,
  suppressed        BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX deviations_by_run ON deviations (run_id);

CREATE TABLE notifications (
  id                TEXT PRIMARY KEY,
  deviation_id      TEXT NOT NULL REFERENCES deviations(id) ON DELETE CASCADE,
  webhook_url       TEXT NOT NULL,
  attempt           INTEGER NOT NULL,
  status            TEXT NOT NULL,
  last_attempted_at TIMESTAMPTZ,
  response_code     INTEGER,
  response_body     TEXT
);
