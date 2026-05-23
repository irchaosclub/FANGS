-- 0002 — notifier infrastructure.
--
-- Replaces the per-deviation notifications table from 0001 with a
-- per-run delivery log keyed to (run_id, notifier_name, attempt).
-- Operator chose per-run summary semantics: when a run finishes with
-- deviations, ONE webhook fires per configured target with the full
-- finding list. Retries log additional attempt rows.

DROP TABLE IF EXISTS notifications;

CREATE TABLE notifiers (
  name         TEXT PRIMARY KEY,
  url          TEXT NOT NULL,
  template     TEXT NOT NULL,      -- 'slack' | 'discord' | 'generic'
  secret_env   TEXT,               -- env-var name holding the HMAC secret; NULL = no signing
  headers      TEXT,               -- JSON object of extra request headers
  min_severity TEXT,               -- 'low'|'medium'|'high'|'critical'; '' = fire on any
  enabled      INTEGER NOT NULL DEFAULT 1,
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);

CREATE TABLE notifications (
  id                TEXT PRIMARY KEY,
  run_id            TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  notifier_name     TEXT NOT NULL REFERENCES notifiers(name) ON DELETE CASCADE,
  attempt           INTEGER NOT NULL,
  status            TEXT NOT NULL,  -- 'queued'|'sent'|'failed'|'permanent'
  last_attempted_at TEXT,
  next_attempt_at   TEXT,
  response_code     INTEGER,
  response_body     TEXT,
  error_msg         TEXT,
  deviation_count   INTEGER NOT NULL DEFAULT 0,
  created_at        TEXT NOT NULL
);

CREATE INDEX notifications_by_status ON notifications (status, next_attempt_at);
CREATE INDEX notifications_by_run    ON notifications (run_id);
