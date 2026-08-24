-- CyberScope scan history.
--
-- Timestamps are ISO-8601 in UTC. SQLite has no date type, and storing local
-- time would make history unsortable across a timezone change.

CREATE TABLE IF NOT EXISTS scan_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT    NOT NULL,
    target_kind   TEXT    NOT NULL,
    address_count INTEGER NOT NULL,
    scan_type     TEXT    NOT NULL,
    command       TEXT    NOT NULL,
    started_at    TEXT    NOT NULL,
    elapsed_ms    INTEGER NOT NULL,
    warnings      TEXT    NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS hosts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    ip_address TEXT    NOT NULL,
    hostname   TEXT    NOT NULL DEFAULT '',
    state      TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS ports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    number       INTEGER NOT NULL,
    protocol     TEXT    NOT NULL,
    state        TEXT    NOT NULL,
    reason       TEXT    NOT NULL DEFAULT '',
    service_name TEXT    NOT NULL DEFAULT '',
    product      TEXT    NOT NULL DEFAULT '',
    version      TEXT    NOT NULL DEFAULT '',
    extra_info   TEXT    NOT NULL DEFAULT '',
    cpes         TEXT    NOT NULL DEFAULT '',
    method       TEXT    NOT NULL,
    confidence   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hosts_session ON hosts(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_host    ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_sessions_time ON scan_sessions(started_at DESC);
