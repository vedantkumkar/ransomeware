"""IncidentStateService — analyst-driven incident state transitions."""

from datetime import datetime

from .. import db, timeutil


class IncidentStateService:

    def mark_false_positive(self, conn, incident, *, actor: str = "SOC Analyst",
                            ts: datetime | None = None) -> None:
        now = ts or timeutil.utc_now()
        db.execute(conn, "UPDATE incidents SET status = 'false_positive' WHERE id = ?",
                   (incident["id"],))
        db.append_timeline(conn, incident["id"], ts_dt=now,
            title="Incident marked as false positive",
            description=f"{incident['id']} closed as a false positive by {actor}.",
            type_="action", automated=False)
        db.append_activity(conn, ts_dt=now, event="Incident Marked False Positive",
                           actor=actor, actor_type="analyst", target=incident["id"],
                           details=f"{incident['id']} marked as false positive.")

    def close(self, conn, incident, *, actor: str = "SOC Analyst",
              ts: datetime | None = None) -> None:
        now = ts or timeutil.utc_now()
        db.execute(conn, "UPDATE incidents SET status = 'resolved' WHERE id = ?",
                   (incident["id"],))
        db.append_timeline(conn, incident["id"], ts_dt=now,
            title="Incident closed by analyst",
            description=f"{incident['id']} resolved and closed by {actor}.",
            type_="action", automated=False)
        db.append_activity(conn, ts_dt=now, event="Incident Closed",
                           actor=actor, actor_type="analyst", target=incident["id"],
                           details=f"{incident['id']} closed successfully.")
