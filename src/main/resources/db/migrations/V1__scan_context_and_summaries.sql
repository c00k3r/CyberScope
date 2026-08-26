-- Migration 1: port summaries, network context, and a target index.
--
-- Applied to every database, new or existing. A brand-new database starts at
-- the v0 baseline in schema.sql and is migrated forward exactly as an existing
-- one is, so this file is exercised by every test run rather than only on the
-- day it matters.
--
-- ALTER TABLE ... ADD COLUMN is one of the few schema changes SQLite performs
-- in place. The NOT NULL DEFAULT '' is what makes it legal: SQLite has to have
-- a value to put in the existing rows, and refuses the statement without one.

ALTER TABLE scan_sessions ADD COLUMN source_address TEXT    NOT NULL DEFAULT '';
ALTER TABLE scan_sessions ADD COLUMN interface_name TEXT    NOT NULL DEFAULT '';
ALTER TABLE scan_sessions ADD COLUMN interface_p2p  INTEGER NOT NULL DEFAULT 0;

-- The ports Nmap collapsed into an <extraports> block.
--
-- port_numbers holds Nmap's own compressed notation ("7,9,21-23,1025-1029"),
-- not one row per port. Ninety-nine closed ports are one fact with a count; a
-- row each would put roughly 25,000 rows of "closed" in this table for a single
-- /24 scan and answer no question that this column cannot.
--
-- An empty port_numbers with a positive port_count is meaningful, not missing
-- data: Nmap's DTD marks the ports attribute #IMPLIED, so it records "this many
-- ports were in this state, and we cannot say which".
CREATE TABLE IF NOT EXISTS port_summaries (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    state        TEXT    NOT NULL,
    port_count   INTEGER NOT NULL,
    reasons      TEXT    NOT NULL DEFAULT '',
    port_numbers TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_summaries_host ON port_summaries(host_id);

-- Finding the previous scan of a target is the central query of scan
-- comparison. Measured over 400 scans across 20 targets:
--
--   without: SCAN scan_sessions + USE TEMP B-TREE FOR ORDER BY   15.4 ms / 200
--   with:    SEARCH USING COVERING INDEX idx_sessions_target      7.7 ms / 200
--
-- Covering, because started_at is in the index: SQLite answers the query from
-- the index alone without touching the table.
CREATE INDEX IF NOT EXISTS idx_sessions_target
    ON scan_sessions(target, started_at DESC);