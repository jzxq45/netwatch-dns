-- Multi-statements; executed atomically per Open. IF NOT EXISTS for idempotent migration.
CREATE TABLE IF NOT EXISTS devices (
    ip        TEXT PRIMARY KEY,
    mac       TEXT,
    hostname  TEXT,
    last_seen INTEGER
);

CREATE TABLE IF NOT EXISTS dns_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip TEXT,
    domain    TEXT,
    qtype     TEXT,
    ts        INTEGER,
    noise     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_dns_ts        ON dns_log(ts);
CREATE INDEX IF NOT EXISTS idx_dns_client    ON dns_log(client_ip);
CREATE INDEX IF NOT EXISTS idx_dns_client_ts ON dns_log(client_ip, ts DESC);

CREATE TABLE IF NOT EXISTS sni_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip TEXT,
    sni       TEXT,
    ts        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sni_ts ON sni_log(ts);

CREATE TABLE IF NOT EXISTS custom_rules (
    domain     TEXT PRIMARY KEY,
    action     TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_rewrites (
    domain     TEXT PRIMARY KEY,
    ip         TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS flow_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip   TEXT,
    dst_ip   TEXT,
    dst_port INTEGER,
    bytes    INTEGER,
    ts       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_flow_ts ON flow_log(ts);
CREATE INDEX IF NOT EXISTS idx_flow_src ON flow_log(src_ip);
