-- Reverse of 0003. SQLite supports DROP COLUMN since 3.35 (2021).
ALTER TABLE runs DROP COLUMN events_emitted;
ALTER TABLE runs DROP COLUMN events_dropped;
ALTER TABLE runs DROP COLUMN duration_ns;
