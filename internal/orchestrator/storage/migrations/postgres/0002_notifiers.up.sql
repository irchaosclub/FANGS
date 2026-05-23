-- 0002 — notifier infrastructure (postgres).
-- See sqlite/0002 for the design rationale.

DROP TABLE IF EXISTS notifications;

CREATE TABLE notifiers (
  name         TEXT PRIMARY KEY,
  url          TEXT NOT NULL,
  template     TEXT NOT NULL,
  secret_env   TEXT,
  headers      TEXT,
  min_severity TEXT,
  enabled      BOOLEAN NOT NULL DEFAULT TRUE,
  created_at   TIMESTAMPTZ NOT NULL,
  updated_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE notifications (
  id                TEXT PRIMARY KEY,
  run_id            TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  notifier_name     TEXT NOT NULL REFERENCES notifiers(name) ON DELETE CASCADE,
  attempt           INTEGER NOT NULL,
  status            TEXT NOT NULL,
  last_attempted_at TIMESTAMPTZ,
  next_attempt_at   TIMESTAMPTZ,
  response_code     INTEGER,
  response_body     TEXT,
  error_msg         TEXT,
  deviation_count   INTEGER NOT NULL DEFAULT 0,
  created_at        TIMESTAMPTZ NOT NULL
);

CREATE INDEX notifications_by_status ON notifications (status, next_attempt_at);
CREATE INDEX notifications_by_run    ON notifications (run_id);
