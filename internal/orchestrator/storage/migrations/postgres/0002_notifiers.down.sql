-- Reverse of 0002 (postgres).
DROP INDEX IF EXISTS notifications_by_run;
DROP INDEX IF EXISTS notifications_by_status;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notifiers;

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
