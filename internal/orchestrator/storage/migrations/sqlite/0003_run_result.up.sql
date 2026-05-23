-- 0003 — surface ScanResult metadata on the runs table.
--
-- The runner POSTs ScanResult at the end of every job (P2P.8); this
-- migration adds the three fields it carries so the UI and CLI can show
-- "how many events did we capture, did the ringbuf overflow, how long
-- did the scan take".
ALTER TABLE runs ADD COLUMN events_emitted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN events_dropped INTEGER NOT NULL DEFAULT 0;
ALTER TABLE runs ADD COLUMN duration_ns    INTEGER NOT NULL DEFAULT 0;
