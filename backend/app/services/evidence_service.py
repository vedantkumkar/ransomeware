"""EvidenceCollectionService — writes demo forensic artifacts to disk.

Artifacts are stored under <evidence_storage>/<incident_id>/ with real
SHA-256 hashes of the stored bytes. Content is metadata describing the
detection event only — nothing is read from or executed on the host.
"""

import hashlib
import json
from datetime import datetime, timedelta

from .. import config, db, ids, timeutil
from ..schemas import DetectionEventIn

AUTOMATED_ARTIFACT_TYPES = ("detection_log", "file_manifest", "ransom_note", "process_snapshot")


class EvidenceCollectionService:

    def collect_automated(self, conn, incident, event: DetectionEventIn,
                          assessment, *, ts: datetime | None = None) -> list[str]:
        """Collect the standard 4-artifact evidence package."""
        now = ts or timeutil.utc_now()
        hostname = incident["hostname"]
        collected_at = timeutil.iso_z(now)
        folder = self._incident_folder(incident["id"])

        artifacts = [
            ("detection_log", "detection_event.json",
             json.dumps(event.model_dump(), indent=2).encode("utf-8"),
             f"Behavioral detection event for {event.process_name} on {hostname}"),
            ("file_manifest", "file_manifest.json",
             json.dumps(self._file_manifest(incident, event), indent=2).encode("utf-8"),
             f"Manifest of {event.files_modified} modified files under {event.target_directory}"),
            ("ransom_note", f"ransom_note_{event.ransom_note_name or 'README_RESTORE_FILES.txt'}",
             self._ransom_note_text(incident).encode("utf-8"),
             f"Ransom note {event.ransom_note_name or 'README_RESTORE_FILES.txt'} captured from {event.target_directory}"),
            ("process_snapshot", "process_snapshot.json",
             json.dumps(self._process_snapshot(incident, event, collected_at), indent=2).encode("utf-8"),
             f"Process snapshot for {event.process_name} (PID {event.process_id})"),
        ]

        evidence_ids = []
        for type_, filename, content, description in artifacts:
            path = folder / filename
            path.write_bytes(content)
            evidence_ids.append(self._insert_evidence(
                conn, incident, type_, hostname, path, collected_at, description))

        db.append_timeline(conn, incident["id"], ts_dt=now,
            title="Forensic collection started",
            description=f"EvidenceCollectionService began acquiring artifacts from {hostname}.",
            type_="evidence")
        db.append_timeline(conn, incident["id"], ts_dt=now + timedelta(seconds=0.4),
            title="Evidence package secured — 4 artifacts",
            description="4 artifacts hashed (SHA-256) and stored with verified integrity.",
            type_="success")
        db.append_activity(conn, ts_dt=now, event="Evidence Collected",
                           actor="Automation Engine", actor_type="automation",
                           target=incident["id"],
                           details="4 forensic artifacts secured "
                                   "(detection_log, file_manifest, ransom_note, process_snapshot).")
        return evidence_ids

    def collect_analyst(self, conn, incident, *, actor: str = "SOC Analyst",
                        ts: datetime | None = None) -> int:
        """Analyst-triggered collection: one event_logs artifact per call."""
        now = ts or timeutil.utc_now()
        collected_at = timeutil.iso_z(now)
        details = json.loads(incident["threat_details"]) if incident["threat_details"] else {}
        previous = db.fetch_one(
            conn, "SELECT COUNT(*) AS n FROM evidence WHERE incident_id = ? AND type = 'event_logs'",
            (incident["id"],))
        seq = (previous["n"] if previous else 0) + 1

        payload = {
            "incidentId": incident["id"],
            "hostname": incident["hostname"],
            "collectedBy": actor,
            "collectedAt": collected_at,
            "events": [
                {"channel": "Security", "id": 4688,
                 "message": f"Process creation: {details.get('process', 'unknown')} "
                            f"(PID {details.get('pid', 0)})"},
                {"channel": "Security", "id": 4663,
                 "message": f"File write attempts to {details.get('targetDirectory', 'unknown directory')}"},
                {"channel": "System", "id": 7045, "message": "No new services installed"},
            ],
        }
        path = self._incident_folder(incident["id"]) / f"event_logs_{seq}.json"
        path.write_bytes(json.dumps(payload, indent=2).encode("utf-8"))
        self._insert_evidence(conn, incident, "event_logs", incident["hostname"], path,
                              collected_at,
                              f"Windows event log extract #{seq} collected by {actor}")

        db.append_timeline(conn, incident["id"], ts_dt=now,
            title="Additional forensic collection by analyst",
            description=f"Event log extract #{seq} acquired for {incident['id']} by {actor}.",
            type_="evidence", automated=False)
        db.append_activity(conn, ts_dt=now, event="Evidence Collected", actor=actor,
                           actor_type="analyst", target=incident["id"],
                           details=f"Evidence collection simulated for {incident['id']} (event_logs #{seq}).")
        return 1

    # ── Internals ────────────────────────────────────────────────────────

    @staticmethod
    def _incident_folder(incident_id: str):
        folder = config.evidence_storage_dir() / incident_id
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    @staticmethod
    def _file_manifest(incident, event: DetectionEventIn) -> dict:
        entries = []
        locked = max(0, event.locked_files)
        plain = max(0, event.files_modified - event.locked_files)
        entries.extend({"name": f"document_{i + 1:03d}.docx.locked", "status": "encrypted"}
                       for i in range(locked))
        entries.extend({"name": f"temp_{i + 1:03d}.tmp", "status": "modified"}
                       for i in range(plain))
        return {
            "incidentId": incident["id"],
            "hostname": incident["hostname"],
            "targetDirectory": event.target_directory,
            "filesModified": event.files_modified,
            "filesLocked": event.locked_files,
            "entries": entries,
        }

    @staticmethod
    def _ransom_note_text(incident) -> str:
        return (
            "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\n\n"
            "All documents, photos and databases in this directory were encrypted.\n"
            "To restore them, follow the payment instructions and contact us with your ID.\n\n"
            f"Contact: restore-help@onionmail.example\nID: {incident['id']}\n\n"
            "--- Demo artifact generated by RansomGuard IR for training purposes. "
            "Not real malware. ---\n"
        )

    @staticmethod
    def _process_snapshot(incident, event: DetectionEventIn, collected_at: str) -> dict:
        return {
            "hostname": incident["hostname"],
            "processName": event.process_name,
            "pid": event.process_id,
            "processPath": event.process_path,
            "commandLine": f'"{event.process_path}"',
            "parentProcess": "explorer.exe",
            "capturedAt": collected_at,
        }

    @staticmethod
    def _insert_evidence(conn, incident, type_: str, source: str, path,
                         collected_at: str, description: str) -> str:
        content = path.read_bytes()
        evidence_id = ids.next_evidence_id(conn)
        db.execute(conn,
                   "INSERT INTO evidence (id, incident_id, type, source, size, sha256,"
                   " collected_at, integrity, description, storage_path)"
                   " VALUES (?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?)",
                   (evidence_id, incident["id"], type_, source,
                    timeutil.human_size(len(content)),
                    hashlib.sha256(content).hexdigest(),
                    collected_at, description, str(path)))
        return evidence_id
