"""NotificationService — creates SOC notifications (Alert records)."""

from datetime import datetime

from .. import db


class NotificationService:

    def emit_detection_alerts(self, conn, incident, event, assessment, *,
                              ts: datetime | None = None) -> None:
        """The 3 standard detection notifications: critical / high / low."""
        now = ts
        hostname = incident["hostname"]
        items = [
            (f"Critical ransomware detected on {hostname}",
             f"{event.process_name} flagged on {hostname} with risk score "
             f"{assessment.score}/100. Automated containment executed.",
             "critical"),
            (f"Host isolated: {hostname}",
             f"{hostname} was automatically isolated from the network in response to "
             f"{incident['id']}.",
             "high"),
            ("Evidence collection completed",
             f"4 forensic artifacts secured for incident {incident['id']}.",
             "low"),
        ]
        for title, description, severity in items:
            self.notify(conn, ts_dt=now, title=title, description=description,
                        severity=severity, incident_id=incident["id"])

        db.append_timeline(conn, incident["id"], ts_dt=now,
            title="SOC notification generated",
            description="3 notifications dispatched to SOC channels (critical, high, low).",
            type_="notification")
        db.append_activity(conn, ts_dt=now, event="SOC Notification Sent",
                           actor="Automation Engine", actor_type="automation",
                           target=incident["id"],
                           details="3 SOC notifications dispatched (critical, high, low).")

    def notify(self, conn, *, ts_dt, title: str, description: str, severity: str,
               incident_id: str | None = None) -> str:
        return db.insert_notification(conn, ts_dt=ts_dt, title=title,
                                      description=description, severity=severity,
                                      incident_id=incident_id)
