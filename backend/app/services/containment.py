"""ContainmentService — simulated network containment.

Never executes OS commands; only updates stored incident/endpoint state and
writes timeline + activity records.
"""

from datetime import datetime, timedelta

from .. import db, timeutil


class ContainmentService:

    def isolate(self, conn, incident, *, automated: bool, actor: str,
                ts: datetime | None = None) -> None:
        """Isolate the incident host on the (simulated) network."""
        now = ts or timeutil.utc_now()
        hostname = incident["hostname"]
        db.execute(conn, "UPDATE incidents SET network_status = 'isolated' WHERE id = ?",
                   (incident["id"],))
        db.execute(conn, "UPDATE endpoints SET network_status = 'isolated' WHERE hostname = ?",
                   (hostname,))
        if automated:
            db.append_timeline(conn, incident["id"], ts_dt=now,
                title="Host isolation command initiated",
                description=f"Containment module issued a network isolation command for {hostname}.",
                type_="action")
            db.append_timeline(conn, incident["id"], ts_dt=now + timedelta(seconds=0.4),
                title=f"{hostname} successfully isolated",
                description="Host removed from the network; management channel retained.",
                type_="success")
        else:
            db.append_timeline(conn, incident["id"], ts_dt=now,
                title="Host isolated by analyst",
                description=f"{hostname} isolated from the network by {actor}.",
                type_="action", automated=False)
        db.append_activity(conn, ts_dt=now, event="Host Isolated", actor=actor,
                           actor_type="automation" if automated else "analyst",
                           target=hostname,
                           details=f"Network isolation simulated for {hostname} ({incident['id']}).")

    def release(self, conn, incident, *, actor: str,
                ts: datetime | None = None) -> None:
        """Restore the incident host to the network (reversible containment)."""
        now = ts or timeutil.utc_now()
        hostname = incident["hostname"]
        db.execute(conn, "UPDATE incidents SET network_status = 'connected' WHERE id = ?",
                   (incident["id"],))
        db.execute(conn, "UPDATE endpoints SET network_status = 'connected' WHERE hostname = ?",
                   (hostname,))
        db.append_timeline(conn, incident["id"], ts_dt=now,
            title="Host released by analyst",
            description=f"{hostname} restored to the network by {actor}.",
            type_="action", automated=False)
        db.append_activity(conn, ts_dt=now, event="Host Released", actor=actor,
                           actor_type="analyst", target=hostname,
                           details=f"Host release simulated successfully for {hostname}.")
