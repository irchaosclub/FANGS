-- Reverse of 0002.
DROP INDEX IF EXISTS notifications_by_run;
DROP INDEX IF EXISTS notifications_by_status;
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notifiers;

-- Restore the 0001 notifications shape so a clean down-migrate doesn't
-- leave the schema in a hybrid state.
CREATE TABLE notifications (
  id                TEXT PRIMARY KEY,
  deviation_id      TEXT NOT NULL REFERENCES deviations(id) ON DELETE CASCADE,
  webhook_url       TEXT NOT NULL,
  attempt           INTEGER NOT NULL,
  status            TEXT NOT NULL,
  last_attempted_at TEXT,
  response_code     INTEGER,
  response_body     TEXT
);
