"""IncidentOrchestrator — the automated response flow for detection events.

On an accepted (non-duplicate) detection event it:
  1. Scores the event with the deterministic risk engine.
  2. Applies per-hostname duplicate protection (cooldown window).
  3. Creates the incident and runs, in order:
     ContainmentService -> IdentityResponseService ->
     EvidenceCollectionService -> NotificationService
  4. Generates the exact 10-step timeline from shared/CONTRACTS.md section 4
     and sets the final incident/endpoint state (contained + isolated).
"""

import json
import sqlite3
from datetime import datetime, timedelta

from .. import config, db, ids, timeutil
from ..schemas import DetectionEventIn, DetectionIngestionResult
from . import risk_engine
from .containment import ContainmentService
from .evidence_service import EvidenceCollectionService
from .identity import IdentityResponseService
from .notifications import NotificationService

# Cumulative second offsets for the 10 timeline steps, measured from the
# detection event timestamp (total automated response: 3.4s).
STEP_OFFSETS = (0.0, 0.4, 0.8, 1.2, 1.6, 2.0, 2.4, 2.8, 3.2, 3.4)

ACTIVE_EXCLUDED_STATUSES = ("resolved", "false_positive")


class IncidentOrchestrator:

    def __init__(self) -> None:
        self.containment = ContainmentService()
        self.identity = IdentityResponseService()
        self.evidence = EvidenceCollectionService()
        self.notifications = NotificationService()

    # ── Entry point ──────────────────────────────────────────────────────

    def process_detection(self, event: DetectionEventIn) -> DetectionIngestionResult:
        conn = db.get_connection()
        event_dt = timeutil.parse_iso(event.timestamp)
        assessment = risk_engine.assess(event.detection_reasons)

        active = db.fetch_one(
            conn,
            "SELECT * FROM incidents WHERE hostname = ?"
            f" AND status NOT IN ({', '.join('?' * len(ACTIVE_EXCLUDED_STATUSES))})"
            " ORDER BY detected_at DESC LIMIT 1",
            (event.hostname, *ACTIVE_EXCLUDED_STATUSES),
        )
        if active is not None and self._within_cooldown(active, event_dt):
            self._refresh_existing(conn, active, event, event_dt)
            return DetectionIngestionResult(accepted=True,
                                            incident_id=active["id"],
                                            deduplicated=True)

        incident_id = self._create_incident(conn, event, assessment, event_dt)
        incident = db.fetch_one(conn, "SELECT * FROM incidents WHERE id = ?",
                                (incident_id,))
        self._run_automated_response(conn, incident, event, assessment, event_dt)
        return DetectionIngestionResult(accepted=True,
                                        incident_id=incident_id,
                                        deduplicated=False)

    # ── Duplicate protection ─────────────────────────────────────────────

    @staticmethod
    def _within_cooldown(active: sqlite3.Row, event_dt: datetime) -> bool:
        reference = active["last_event_at"] or active["detected_at"]
        delta = abs((event_dt - timeutil.parse_iso(reference)).total_seconds())
        return delta <= config.detection_cooldown_seconds()

    def _refresh_existing(self, conn, active: sqlite3.Row, event: DetectionEventIn,
                          event_dt: datetime) -> None:
        """Fold a duplicate detection into the active incident — no new noise."""
        details = json.loads(active["threat_details"]) if active["threat_details"] else {}
        details["filesModified"] = max(int(details.get("filesModified", 0)),
                                       event.files_modified)
        details["filesLocked"] = max(int(details.get("filesLocked", 0)),
                                     event.locked_files)
        db.execute(conn, "UPDATE incidents SET last_event_at = ?, threat_details = ? WHERE id = ?",
                   (timeutil.iso_z(event_dt), json.dumps(details), active["id"]))
        db.execute(conn,
                   "UPDATE endpoints SET last_seen = 'Just now', agent_status = 'online',"
                   " ip_address = ?, username = ? WHERE hostname = ?",
                   (event.ip_address, event.username, event.hostname))

    # ── Incident creation ────────────────────────────────────────────────

    def _create_incident(self, conn, event: DetectionEventIn, assessment,
                         event_dt: datetime) -> str:
        incident_id = ids.next_incident_id(conn, event_dt)
        endpoint = db.fetch_one(conn, "SELECT * FROM endpoints WHERE hostname = ?",
                                (event.hostname,))
        if endpoint is None:
            db.execute(conn,
                       "INSERT INTO endpoints (id, hostname, ip_address, username, os,"
                       " agent_status, risk_score, severity, network_status, last_seen,"
                       " department, incident_id)"
                       " VALUES (?, ?, ?, ?, 'Unknown', 'online', 0, 'none', 'connected',"
                       " 'Just now', 'Unknown', NULL)",
                       (ids.next_endpoint_id(conn), event.hostname, event.ip_address,
                        event.username))
            department, os_name = "Unknown", "Unknown"
        else:
            department, os_name = endpoint["department"], endpoint["os"]

        threat_details = {
            "process": event.process_name,
            "pid": event.process_id,
            "processPath": event.process_path,
            "targetDirectory": event.target_directory,
            "filesModified": event.files_modified,
            "filesLocked": event.locked_files,
            "ransomNote": event.ransom_note_name if event.ransom_note_detected else "",
            "detectionReasons": assessment.reasons_display,
            "riskBreakdown": assessment.breakdown,
        }
        detected_at = timeutil.iso_z(event_dt)
        db.execute(conn,
                   "INSERT INTO incidents (id, threat_type, hostname, ip_address,"
                   " username, department, os, severity, risk_score, status,"
                   " detected_at, detection_engine, agent_status, network_status,"
                   " threat_details, last_event_at)"
                   " VALUES (?, 'Ransomware Behavior', ?, ?, ?, ?, ?, ?, ?, 'detected',"
                   " ?, 'Behavioral Detection', 'online', 'connected', ?, ?)",
                   (incident_id, event.hostname, event.ip_address, event.username,
                    department, os_name, assessment.severity, assessment.score,
                    detected_at, json.dumps(threat_details), detected_at))

        db.append_activity(conn, ts_dt=event_dt, event="Ransomware Behavior Detected",
                           actor="Detection Agent", actor_type="agent",
                           target=event.hostname,
                           details=f"Behavioral engine flagged {event.process_name} on "
                                   f"{event.hostname} (risk {assessment.score}/100).")
        return incident_id

    # ── Automated response (10-step timeline) ────────────────────────────

    def _run_automated_response(self, conn, incident: sqlite3.Row,
                                event: DetectionEventIn, assessment,
                                event_dt: datetime) -> None:
        incident_id = incident["id"]
        hostname = incident["hostname"]

        def step(index: int) -> datetime:
            return event_dt + timedelta(seconds=STEP_OFFSETS[index])

        # Steps 1-3: detection, risk analysis, incident creation.
        db.append_timeline(conn, incident_id, ts_dt=step(0),
            title="Suspicious activity detected",
            description=f"Behavioral engine flagged ransomware-like activity by "
                        f"{event.process_name} on {hostname}.",
            type_="detection")
        db.append_timeline(conn, incident_id, ts_dt=step(1),
            title=f"Risk score calculated: {assessment.score}/100",
            description=f"Risk engine weighted {len(assessment.breakdown)} behavioral "
                        f"indicators; severity assessed as {assessment.severity}.",
            type_="analysis")
        db.append_timeline(conn, incident_id, ts_dt=step(2),
            title=f"{assessment.severity.capitalize()} ransomware incident created",
            description=f"Incident {incident_id} opened for {hostname}.",
            type_="action")
        db.append_activity(conn, ts_dt=step(2), event="Incident Created",
                           actor="Automation Engine", actor_type="automation",
                           target=incident_id,
                           details=f"{assessment.severity.capitalize()} incident opened "
                                   f"for {hostname}.")

        # Steps 4-10: containment, identity response, evidence, notifications.
        self.containment.isolate(conn, incident, automated=True,
                                 actor="Automation Engine", ts=step(3))
        self.identity.suspend(conn, incident, automated=True,
                              actor="Automation Engine", ts=step(5))
        self.evidence.collect_automated(conn, incident, event, assessment, ts=step(7))
        self.notifications.emit_detection_alerts(conn, incident, event, assessment,
                                                 ts=step(9))

        # Final states.
        db.execute(conn, "UPDATE incidents SET status = 'contained' WHERE id = ?",
                   (incident_id,))
        db.execute(conn,
                   "UPDATE endpoints SET risk_score = ?, severity = ?,"
                   " network_status = 'isolated', incident_id = ?,"
                   " agent_status = 'online', last_seen = 'Just now' WHERE hostname = ?",
                   (assessment.score, assessment.severity, incident_id, hostname))


orchestrator = IncidentOrchestrator()
