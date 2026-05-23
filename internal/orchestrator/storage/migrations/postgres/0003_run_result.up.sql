-- 0003 — surface ScanResult metadata on the runs table (postgres).
-- See sqlite/0003 for rationale.
ALTER TABLE runs ADD COLUMN events_emitted BIGINT NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN events_dropped BIGINT NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN duration_ns    BIGINT NOT NULL DEFAULT 0;
