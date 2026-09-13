"""Sequential ID generation for all record types.

Formats (shared/CONTRACTS.md):
- incidents:      RAN-<year>-<NNN>   (first -> RAN-2026-001)
- evidence:       EVD-<NNN>
- activity log:   act-<NNN>
- notifications:  notif-<NNN>
- endpoints:      ep-<NNN>
- timeline:       tl-<NNN> (per incident)
"""

from datetime import datetime, timezone
from typing import Iterable

import sqlite3


def _max_suffix(values: Iterable[str]) -> int:
    best = 0
    for raw in values:
        suffix = raw.rsplit("-", 1)[-1]
        if suffix.isdigit():
            best = max(best, int(suffix))
    return best


def next_id(conn: sqlite3.Connection, table: str, prefix: str, where: str = "",
            params: tuple = ()) -> str:
    query = f"SELECT id AS v FROM {table}"  # noqa: S608 - table names are internal constants
    if where:
        query += f" WHERE {where}"
    rows = conn.execute(query, params).fetchall()
    number = _max_suffix([row["v"] for row in rows]) + 1
    return f"{prefix}{number:03d}"


def next_incident_id(conn: sqlite3.Connection, when: datetime | None = None) -> str:
    year = (when or datetime.now(timezone.utc)).year
    return next_id(conn, "incidents", f"RAN-{year}-",
                   where="id LIKE ?", params=(f"RAN-{year}-%",))


def next_evidence_id(conn: sqlite3.Connection) -> str:
    return next_id(conn, "evidence", "EVD-")


def next_activity_id(conn: sqlite3.Connection) -> str:
    return next_id(conn, "activity_log", "act-")


def next_notification_id(conn: sqlite3.Connection) -> str:
    return next_id(conn, "notifications", "notif-")


def next_endpoint_id(conn: sqlite3.Connection) -> str:
    return next_id(conn, "endpoints", "ep-")


def next_timeline_id(conn: sqlite3.Connection, incident_id: str) -> str:
    return next_id(conn, "timeline_events", "tl-",
                   where="incident_id = ?", params=(incident_id,))
