"""SQLite data-access layer for RansomGuard IR.

A single shared connection (WAL mode) with a fixed schema and small helper
functions used by the service layer. No ORM — stdlib sqlite3 only.
"""

from __future__ import annotations

import sqlite3
import threading

from . import config, ids, timeutil

_lock = threading.Lock()
_conn: sqlite3.Connection | None = None
_conn_path: str | None = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL UNIQUE,
    ip_address TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT 'Unknown',
    agent_status TEXT NOT NULL DEFAULT 'online',
    risk_score INTEGER NOT NULL DEFAULT 0,
    severity TEXT NOT NULL DEFAULT 'none',
    network_status TEXT NOT NULL DEFAULT 'connected',
    last_seen TEXT NOT NULL DEFAULT 'Just now',
    department TEXT NOT NULL DEFAULT 'Unknown',
    incident_id TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    threat_type TEXT NOT NULL DEFAULT 'Ransomware Behavior',
    hostname TEXT NOT NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    department TEXT NOT NULL DEFAULT 'Unknown',
    os TEXT NOT NULL DEFAULT 'Unknown',
    severity TEXT NOT NULL DEFAULT 'low',
    risk_score INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'detected',
    detected_at TEXT NOT NULL,
    detection_engine TEXT NOT NULL DEFAULT 'Behavioral Detection',
    agent_status TEXT NOT NULL DEFAULT 'online',
    network_status TEXT NOT NULL DEFAULT 'connected',
    threat_details TEXT,
    last_event_at TEXT
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    ts TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    type TEXT NOT NULL DEFAULT 'action',
    automated INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (incident_id, seq)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    size TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    collected_at TEXT NOT NULL,
    integrity TEXT NOT NULL DEFAULT 'verified',
    description TEXT NOT NULL DEFAULT '',
    storage_path TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS activity_log (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    timestamp TEXT NOT NULL,
    event TEXT NOT NULL,
    actor TEXT NOT NULL,
    actor_type TEXT NOT NULL DEFAULT 'automation',
    target TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT 'success',
    details TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS notifications (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'low',
    timestamp TEXT NOT NULL,
    read INTEGER NOT NULL DEFAULT 0,
    incident_id TEXT
);

CREATE TABLE IF NOT EXISTS identity_state (
    username TEXT PRIMARY KEY,
    hostname TEXT NOT NULL DEFAULT '',
    user_status TEXT NOT NULL DEFAULT 'active',
    sessions_revoked INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_custody (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
"""

# Columns added after the initial release; applied to existing databases via
# _migrate() so older demo databases keep working without a rebuild.
EVIDENCE_ADDED_COLUMNS = [
    ("artifact_name", "TEXT NOT NULL DEFAULT ''"),
    ("mime_type", "TEXT NOT NULL DEFAULT ''"),
    ("collection_method", "TEXT NOT NULL DEFAULT 'automated'"),
    ("collected_by", "TEXT NOT NULL DEFAULT ''"),
    ("size_bytes", "INTEGER NOT NULL DEFAULT 0"),
]

# Demo identity seeded on startup when the endpoints table is empty.
SEED_HOSTNAME = "VICTIM-PC-01"
SEED_ENDPOINT = {
    "ip_address": "192.168.56.105",
    "username": "demo-user",
    "os": "Windows 11 Pro",
    "department": "Demo Lab",
}


def get_connection() -> sqlite3.Connection:
    """Return the shared connection, (re)opening it when the DB path changes.

    The path is resolved on every call so tests can swap RANSOMGUARD_DB_PATH.
    """
    global _conn, _conn_path
    with _lock:
        path = str(config.db_path())
        if _conn is None or _conn_path != path:
            if _conn is not None:
                _conn.close()
            db_file = config.db_path()
            db_file.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(db_file, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA)
            _migrate(conn)
            conn.commit()
            _conn = conn
            _conn_path = path
        return _conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply additive migrations to databases created by older versions."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(evidence)")}
    for name, declaration in EVIDENCE_ADDED_COLUMNS:
        if name not in columns:
            conn.execute(f"ALTER TABLE evidence ADD COLUMN {name} {declaration}")


def reset_connection() -> None:
    """Close the shared connection (used between test runs)."""
    global _conn, _conn_path
    with _lock:
        if _conn is not None:
            _conn.close()
        _conn = None
        _conn_path = None


def init_db() -> None:
    """Create the schema (if needed) and seed the demo endpoint registry."""
    get_connection()
    _seed_endpoints()


def _seed_endpoints() -> None:
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) AS n FROM endpoints").fetchone()["n"]
    if count:
        return
    execute(conn,
            "INSERT INTO endpoints (id, hostname, ip_address, username, os, agent_status,"
            " risk_score, severity, network_status, last_seen, department, incident_id)"
            " VALUES (?, ?, ?, ?, ?, 'online', 0, 'none', 'connected', 'Just now', ?, NULL)",
            (ids.next_endpoint_id(conn), SEED_HOSTNAME, SEED_ENDPOINT["ip_address"],
             SEED_ENDPOINT["username"], SEED_ENDPOINT["os"], SEED_ENDPOINT["department"]))


# ── Generic helpers ──────────────────────────────────────────────────────────

def fetch_all(conn: sqlite3.Connection, query: str, params: tuple = ()) -> list[sqlite3.Row]:
    return conn.execute(query, params).fetchall()


def fetch_one(conn: sqlite3.Connection, query: str, params: tuple = ()) -> sqlite3.Row | None:
    return conn.execute(query, params).fetchone()


def execute(conn: sqlite3.Connection, query: str, params: tuple = ()) -> None:
    conn.execute(query, params)
    conn.commit()


# ── Append helpers (assign sequential IDs + contract timestamps) ─────────────

def append_timeline(conn: sqlite3.Connection, incident_id: str, *, ts_dt,
                    title: str, description: str, type_: str,
                    automated: bool = True) -> str:
    event_id = ids.next_timeline_id(conn, incident_id)
    seq = int(event_id.rsplit("-", 1)[1])
    execute(conn,
            "INSERT INTO timeline_events (id, incident_id, seq, ts, title, description,"
            " type, automated) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (event_id, incident_id, seq, timeutil.time_of_day(ts_dt), title,
             description, type_, int(automated)))
    return event_id


def append_activity(conn: sqlite3.Connection, *, ts_dt, event: str, actor: str,
                    actor_type: str, target: str, result: str = "success",
                    details: str = "") -> str:
    entry_id = ids.next_activity_id(conn)
    execute(conn,
            "INSERT INTO activity_log (id, timestamp, event, actor, actor_type, target,"
            " result, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (entry_id, timeutil.iso_z(ts_dt), event, actor, actor_type, target,
             result, details))
    return entry_id


def insert_notification(conn: sqlite3.Connection, *, ts_dt, title: str,
                        description: str, severity: str,
                        incident_id: str | None = None) -> str:
    notification_id = ids.next_notification_id(conn)
    execute(conn,
            "INSERT INTO notifications (id, title, description, severity, timestamp,"
            " read, incident_id) VALUES (?, ?, ?, ?, ?, 0, ?)",
            (notification_id, title, description, severity,
             timeutil.short_time(ts_dt), incident_id))
    return notification_id


def append_custody(conn: sqlite3.Connection, evidence_id: str, *, ts_dt,
                   action: str, actor: str = "", detail: str = "") -> None:
    """Record one chain-of-custody entry for an evidence item."""
    execute(conn,
            "INSERT INTO evidence_custody (evidence_id, timestamp, action, actor, detail)"
            " VALUES (?, ?, ?, ?, ?)",
            (evidence_id, timeutil.iso_z(ts_dt), action, actor, detail))
