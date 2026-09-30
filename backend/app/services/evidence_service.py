"""EvidenceCollectionService — captures and stores real forensic artifacts.

Artifacts are stored under <evidence_storage>/<incident_id>/ and hashed with
SHA-256 over the actual stored bytes. Capture rules:

- Automated collection records what the detection pipeline actually observed:
  the detection event itself, a best-effort scan of the incident's target
  directory (when reachable from the backend host), the ransom note content
  when the source file is readable, and the process fields reported by the
  detection agent. Anything that could not be observed is recorded explicitly
  as "notCaptured" with a reason — nothing is invented.
- Manual collection produces real artifacts from real sources (live event-log
  extract, live process listing, fresh directory scan, analyst-supplied text).
  If a source cannot be read, collection FAILS and no evidence record is
  created.
- Integrity is verified by recalculating SHA-256 from the stored artifact and
  comparing it with the recorded hash. "Verified" means the stored artifact
  matches its recorded hash — it does not independently prove event truth.
"""

import csv
import hashlib
import io
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .. import config, db, ids, timeutil
from ..schemas import DetectionEventIn

AUTOMATED_ARTIFACT_TYPES = ("detection_log", "file_manifest", "ransom_note", "process_snapshot")
MANUAL_EVIDENCE_TYPES = ("windows_event_logs", "process_snapshot", "file_manifest", "text_artifact")

# Manual collection types map onto the EvidenceType contract union
# (windows_event_logs is stored under the existing 'event_logs' type).
MANUAL_TYPE_CONTRACT = {
    "windows_event_logs": "event_logs",
    "process_snapshot": "process_snapshot",
    "file_manifest": "file_manifest",
    "text_artifact": "text_artifact",
}

_MIME_BY_SUFFIX = {
    ".json": "application/json",
    ".txt": "text/plain",
    ".log": "text/plain",
    ".csv": "text/csv",
}

_POWERSHELL_TIMEOUT = 25
_TASKLIST_TIMEOUT = 30


def sha256_of_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class CollectionError(Exception):
    """Manual collection could not produce a real artifact. No record is created."""


class EvidenceCollectionService:

    # ── Automated collection (detection pipeline) ─────────────────────────

    def collect_automated(self, conn, incident, event: DetectionEventIn,
                          assessment, *, ts: datetime | None = None) -> list[str]:
        """Collect the standard 4-artifact evidence package from real data."""
        now = ts or timeutil.utc_now()
        hostname = incident["hostname"]
        collected_at = timeutil.iso_z(now)
        folder = self._incident_folder(incident["id"])
        actor = "VM Detection Agent"

        directory_scan = self._scan_directory(event.target_directory)

        # 1. Detection event log — the real ingested event.
        detection_content = json.dumps(event.model_dump(), indent=2).encode("utf-8")
        detection_path = folder / "detection_event.json"
        detection_path.write_bytes(detection_content)

        # 2. File manifest — real directory scan + the agent's real counters.
        manifest = {
            "incidentId": incident["id"],
            "hostname": hostname,
            "targetDirectory": event.target_directory,
            "filesModified": event.files_modified,
            "filesLocked": event.locked_files,
            "countersReportedBy": "VM detection agent (observed during detection)",
            "directoryScan": directory_scan,
        }
        manifest_content = json.dumps(manifest, indent=2).encode("utf-8")
        manifest_path = folder / "file_manifest.json"
        manifest_path.write_bytes(manifest_content)

        # 3. Ransom note — the ACTUAL note file content when readable.
        note_name = event.ransom_note_name or "README_RESTORE_FILES.txt"
        note_bytes, note_meta = self._capture_note(event.target_directory, note_name)
        if note_bytes is not None:
            note_path = folder / f"ransom_note_{note_name}"
            note_path.write_bytes(note_bytes)
            note_description = (f"Ransom note {note_name} captured from "
                                f"{event.target_directory}")
        else:
            note_path = folder / f"ransom_note_{note_name}.meta.json"
            note_path.write_bytes(json.dumps(note_meta, indent=2).encode("utf-8"))
            note_description = (f"Ransom note {note_name} metadata — content not "
                                f"captured ({note_meta['notCaptured']['reason']})")

        # 4. Process snapshot — only what the detection event actually reported.
        snapshot = {
            "hostname": hostname,
            "source": "detection event reported by VM detection agent",
            "processName": event.process_name,
            "pid": event.process_id if event.process_id else None,
            "processPath": event.process_path or None,
            "targetDirectory": event.target_directory,
            "detectedAt": event.timestamp,
            "capturedAt": collected_at,
            "notCaptured": {
                "commandLine": "not observable by the detection agent",
                "parentProcess": "not observable by the detection agent",
            },
        }
        snapshot_content = json.dumps(snapshot, indent=2).encode("utf-8")
        snapshot_path = folder / "process_snapshot.json"
        snapshot_path.write_bytes(snapshot_content)

        artifacts = [
            ("detection_log", detection_path,
             f"Behavioral detection event for {event.process_name} on {hostname}"),
            ("file_manifest", manifest_path,
             f"File manifest for {event.target_directory} "
             f"({event.files_modified} modified / {event.locked_files} locked reported by agent)"),
            ("ransom_note", note_path, note_description),
            ("process_snapshot", snapshot_path,
             f"Process snapshot for {event.process_name}"
             + (f" (PID {event.process_id})" if event.process_id else "")),
        ]

        evidence_ids = []
        for type_, path, description in artifacts:
            evidence_ids.append(self._insert_evidence(
                conn, incident, type_, hostname, path, collected_at, description,
                collection_method="automated", collected_by=actor, ts=now))

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

    # ── Manual collection (analyst-initiated, real sources) ───────────────

    def collect_manual(self, conn, incident, evidence_type: str, *, actor: str,
                       text_content: str = "", ts: datetime | None = None) -> str:
        """Analyst-triggered collection. Raises CollectionError (no record created)
        when the real source cannot be read."""
        if evidence_type not in MANUAL_EVIDENCE_TYPES:
            raise CollectionError(f"Unsupported manual evidence type: {evidence_type}")

        now = ts or timeutil.utc_now()
        collected_at = timeutil.iso_z(now)
        folder = self._incident_folder(incident["id"])
        hostname = incident["hostname"]

        if evidence_type == "windows_event_logs":
            path, description, mime = self._collect_windows_event_logs(folder, incident)
        elif evidence_type == "process_snapshot":
            path, description, mime = self._collect_live_process_snapshot(folder, incident)
        elif evidence_type == "file_manifest":
            path, description, mime = self._collect_fresh_manifest(folder, incident)
        else:  # text_artifact
            if not text_content or not text_content.strip():
                raise CollectionError("Text artifact is empty — provide the log/text content to store.")
            seq = self._type_sequence(conn, incident["id"], "event_logs") + 1
            path = folder / f"analyst_text_{seq}.txt"
            path.write_bytes(text_content.encode("utf-8"))
            mime = "text/plain"
            description = f"Analyst-supplied text/log artifact #{seq}"

        evidence_id = self._insert_evidence(
            conn, incident, MANUAL_TYPE_CONTRACT[evidence_type], hostname, path,
            collected_at, description,
            collection_method="manual", collected_by=actor, ts=now)

        db.append_timeline(conn, incident["id"], ts_dt=now,
            title="Additional forensic collection by analyst",
            description=f"{description} — stored and hashed (SHA-256).",
            type_="evidence", automated=False)
        db.append_activity(conn, ts_dt=now, event="Evidence Collected", actor=actor,
                           actor_type="analyst", target=incident["id"],
                           details=f"Manual collection ({evidence_type}) for {incident['id']}.")
        db.insert_notification(conn, ts_dt=now,
            title=f"Manual evidence collection completed for {incident['id']}",
            description=description,
            severity="low", incident_id=incident["id"])
        return evidence_id

    def _collect_windows_event_logs(self, folder: Path, incident):
        """Real event-log extract from the backend host via Get-WinEvent."""
        if not config_on_windows():
            raise CollectionError("Windows event log collection requires a Windows host.")
        script = (
            "Get-WinEvent -FilterHashtable @{LogName='Application';StartTime="
            "(Get-Date).AddHours(-24)} -MaxEvents 40 -ErrorAction SilentlyContinue | "
            "Select-Object TimeCreated,ProviderName,Id,LevelDisplayName,Message | "
            "ConvertTo-Json -Depth 3"
        )
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True, text=True, errors="replace",
                timeout=_POWERSHELL_TIMEOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as exc:
            raise CollectionError(f"Windows event log collection failed: {exc}") from exc
        if completed.returncode != 0 or not completed.stdout.strip():
            raise CollectionError(
                "Windows event log collection failed: no events returned "
                f"(exit {completed.returncode}).")

        events = self._normalize_event_log_json(completed.stdout)
        payload = {
            "incidentId": incident["id"],
            "capturedFrom": backend_host_label(),
            "note": ("Live extract from the backend host's Application event log "
                     "(last 24h, up to 40 events). The isolated endpoint's own event "
                     "log is not reachable from the backend."),
            "collectedAt": timeutil.iso_z(timeutil.utc_now()),
            "events": events,
        }
        number = self._manifest_sequence(incident, folder, "event_logs")
        path = folder / f"event_logs_{number}.json"
        path.write_bytes(json.dumps(payload, indent=2).encode("utf-8"))
        description = (f"Windows Application event log extract #{number} "
                       f"(live, {len(events)} events, captured from {backend_host_label()})")
        return path, description, "application/json"

    def _collect_live_process_snapshot(self, folder: Path, incident):
        """Real process listing from the backend host via tasklist."""
        if not config_on_windows():
            raise CollectionError("Live process snapshot requires a Windows host.")
        try:
            completed = subprocess.run(
                ["tasklist", "/fo", "csv", "/nh"],
                capture_output=True, text=True, errors="replace",
                timeout=_TASKLIST_TIMEOUT,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except (OSError, subprocess.SubprocessError) as exc:
            raise CollectionError(f"Process snapshot collection failed: {exc}") from exc
        if completed.returncode != 0 or not completed.stdout.strip():
            raise CollectionError("Process snapshot collection failed: tasklist returned no data.")

        processes = []
        for row in csv.reader(io.StringIO(completed.stdout)):
            if len(row) >= 5:
                processes.append({
                    "imageName": row[0],
                    "pid": _safe_int(row[1]),
                    "sessionName": row[2] if len(row) > 2 else "",
                    "memUsage": row[4] if len(row) > 4 else "",
                })
        payload = {
            "incidentId": incident["id"],
            "capturedFrom": backend_host_label(),
            "note": ("Live process listing of the backend host at collection time. "
                     "Processes inside the isolated endpoint VM are not observable "
                     "from the backend."),
            "collectedAt": timeutil.iso_z(timeutil.utc_now()),
            "processCount": len(processes),
            "processes": processes,
        }
        number = self._manifest_sequence(incident, folder, "process_snapshot")
        path = folder / f"process_snapshot_live_{number}.json"
        path.write_bytes(json.dumps(payload, indent=2).encode("utf-8"))
        description = (f"Live process snapshot #{number} of {backend_host_label()} "
                       f"({len(processes)} processes)")
        return path, description, "application/json"

    def _collect_fresh_manifest(self, folder: Path, incident):
        """Fresh real scan of the incident's target directory."""
        details = json.loads(incident["threat_details"]) if incident["threat_details"] else {}
        target = details.get("targetDirectory", "")
        scan = self._scan_directory(target)
        if not scan["reachable"]:
            raise CollectionError(
                f"File manifest collection failed: {scan['note'] or 'target directory not reachable'}.")
        payload = {
            "incidentId": incident["id"],
            "hostname": incident["hostname"],
            "targetDirectory": target,
            "scannedAt": timeutil.iso_z(timeutil.utc_now()),
            "directoryScan": scan,
        }
        number = self._manifest_sequence(incident, folder, "file_manifest")
        path = folder / f"file_manifest_fresh_{number}.json"
        path.write_bytes(json.dumps(payload, indent=2).encode("utf-8"))
        description = (f"Fresh directory manifest #{number} of {target} "
                       f"({len(scan['entries'])} files observed)")
        return path, description, "application/json"

    # ── Integrity verification ────────────────────────────────────────────

    def verify_integrity(self, conn, evidence_id: str, *, actor: str = "SOC Analyst",
                         ts: datetime | None = None):
        """Recalculate SHA-256 from the stored artifact and compare with the
        recorded hash. Persists the result and a custody entry. Returns
        (row, status, message) or (None, ...) when the evidence id is unknown."""
        row = db.fetch_one(conn, "SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        if row is None:
            return None, "artifact_missing", f"Evidence {evidence_id} not found"

        now = ts or timeutil.utc_now()
        path = Path(row["storage_path"]) if row["storage_path"] else None
        if path is None or not path.is_file():
            status = "artifact_missing"
            message = ("Stored artifact file is missing — integrity cannot be verified "
                       "against the recorded hash.")
            detail = "Verification failed: artifact file missing."
        else:
            actual = sha256_of_bytes(path.read_bytes())
            if actual == row["sha256"]:
                status = "verified"
                message = ("Integrity verified — the stored artifact matches its "
                           "recorded SHA-256 hash.")
                detail = f"Recalculated SHA-256 matches recorded hash ({actual[:16]}…)."
            else:
                status = "verification_failed"
                message = ("Verification FAILED — the stored artifact no longer matches "
                           "its recorded SHA-256 hash.")
                detail = "Recalculated SHA-256 does NOT match the recorded hash."

        db.execute(conn, "UPDATE evidence SET integrity = ? WHERE id = ?", (status, evidence_id))
        db.append_custody(conn, evidence_id, ts_dt=now,
                          action="Integrity checked", actor=actor, detail=detail)
        updated = db.fetch_one(conn, "SELECT * FROM evidence WHERE id = ?", (evidence_id,))
        return updated, status, message

    # ── Artifact access ───────────────────────────────────────────────────

    def read_artifact(self, row) -> dict:
        """Return the stored artifact as text for inspection (never executed)."""
        path = Path(row["storage_path"]) if row["storage_path"] else None
        artifact_name = row["artifact_name"] or (path.name if path else "")
        if path is None or not path.is_file():
            raise FileNotFoundError(
                "Artifact unavailable for legacy record"
                if not row["storage_path"] else
                f"Artifact file missing: {row['storage_path']}")
        content_bytes = path.read_bytes()
        mime = row["mime_type"] or _MIME_BY_SUFFIX.get(path.suffix.lower(), "text/plain")
        binary_unsupported = b"\x00" in content_bytes[:4096]
        content = ("Binary artifact — content not rendered. Use the recorded metadata "
                   "and SHA-256 for verification.") if binary_unsupported else \
            content_bytes.decode("utf-8", errors="replace")
        return {
            "evidence_id": row["id"],
            "artifact_name": artifact_name,
            "mime_type": mime,
            "content": content,
            "binary_unsupported": binary_unsupported,
        }

    # ── Internals ─────────────────────────────────────────────────────────

    @staticmethod
    def _incident_folder(incident_id: str):
        folder = config.evidence_storage_dir() / incident_id
        folder.mkdir(parents=True, exist_ok=True)
        return folder

    @staticmethod
    def _scan_directory(target: str) -> dict:
        """Best-effort real, read-only scan of a directory reachable from the
        backend host. Records what is actually observed — never invents files."""
        result: dict = {"reachable": False, "path": target, "scannedAt": None,
                        "entries": [], "notCaptured": None}
        if not target:
            result["notCaptured"] = {"reason": "No target directory recorded in the detection event."}
            return result
        root = Path(target)
        if not root.is_dir():
            result["notCaptured"] = {
                "reason": ("Directory not reachable from the backend host at collection "
                           "time (the source endpoint is isolated or remote).")}
            return result
        try:
            now_iso = timeutil.iso_z(timeutil.utc_now())
            result["scannedAt"] = now_iso
            for entry in sorted(root.iterdir()):
                if not entry.is_file():
                    continue
                stat = entry.stat()
                lowered = entry.name.lower()
                if lowered.endswith(".locked"):
                    state = "locked_copy"
                elif lowered == "readme_restore_files.txt":
                    state = "ransom_note"
                else:
                    state = "present"
                result["entries"].append({
                    "name": entry.name,
                    "path": str(entry),
                    "sizeBytes": stat.st_size,
                    "modifiedAt": datetime.fromtimestamp(
                        stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "state": state,
                })
            result["reachable"] = True
            result["entries"].sort(key=lambda e: e["name"])
        except OSError as exc:
            result["notCaptured"] = {"reason": f"Directory scan failed: {exc}"}
        return result

    @staticmethod
    def _capture_note(target_directory: str, note_name: str) -> tuple[bytes | None, dict]:
        """Read the actual ransom-note file when reachable; otherwise return a
        metadata artifact that records exactly why the content was not captured."""
        if target_directory:
            candidate = Path(target_directory) / note_name
            if candidate.is_file():
                try:
                    return candidate.read_bytes(), {}
                except OSError as exc:
                    reason = f"Note file exists but could not be read: {exc}"
            else:
                reason = ("Note file not present in the target directory at collection "
                          "time or the directory is not reachable from the backend host.")
        else:
            reason = "No target directory recorded in the detection event."
        meta = {
            "noteName": note_name,
            "sourcePath": str(Path(target_directory) / note_name) if target_directory else "",
            "collectedAt": timeutil.iso_z(timeutil.utc_now()),
            "notCaptured": {"reason": reason},
        }
        return None, meta

    @staticmethod
    def _normalize_event_log_json(stdout: str) -> list[dict]:
        """Normalize ConvertTo-Json output (dict for a single event, list for many)."""
        try:
            parsed = json.loads(stdout)
        except ValueError:
            return []
        if isinstance(parsed, dict):
            parsed = [parsed]
        events = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            events.append({
                "timeCreated": _normalize_powershell_date(item.get("TimeCreated", "")),
                "provider": item.get("ProviderName", ""),
                "eventId": item.get("Id"),
                "level": item.get("LevelDisplayName", ""),
                "message": (item.get("Message") or "").strip(),
            })
        return events

    @staticmethod
    def _type_sequence(conn, incident_id: str, type_: str) -> int:
        row = db.fetch_one(
            conn, "SELECT COUNT(*) AS n FROM evidence WHERE incident_id = ? AND type = ?",
            (incident_id, type_))
        return (row["n"] if row else 0)

    def _manifest_sequence(self, incident, folder: Path, prefix: str) -> int:
        """Per-incident/per-prefix sequence number for manually collected files."""
        counter_file = folder / f".seq_{prefix}"
        try:
            number = int(counter_file.read_text()) + 1
        except (OSError, ValueError):
            number = 1
        counter_file.write_text(str(number))
        return number

    @staticmethod
    def _insert_evidence(conn, incident, type_: str, source: str, path: Path,
                         collected_at: str, description: str, *,
                         collection_method: str, collected_by: str,
                         ts: datetime) -> str:
        content = path.read_bytes()
        evidence_id = ids.next_evidence_id(conn)
        db.execute(conn,
                   "INSERT INTO evidence (id, incident_id, type, source, size, sha256,"
                   " collected_at, integrity, description, storage_path,"
                   " artifact_name, mime_type, collection_method, collected_by, size_bytes)"
                   " VALUES (?, ?, ?, ?, ?, ?, ?, 'verified', ?, ?, ?, ?, ?, ?, ?)",
                   (evidence_id, incident["id"], type_, source,
                    timeutil.human_size(len(content)),
                    sha256_of_bytes(content),
                    collected_at, description, str(path),
                    path.name, _MIME_BY_SUFFIX.get(path.suffix.lower(), "text/plain"),
                    collection_method, collected_by, len(content)))
        method_label = ("Collected automatically" if collection_method == "automated"
                        else f"Collected manually by {collected_by}")
        db.append_custody(conn, evidence_id, ts_dt=ts,
                          action=method_label,
                          actor=collected_by or "RansomGuard backend",
                          detail=f"Artifact {path.name} acquired from {source}.")
        db.append_custody(conn, evidence_id, ts_dt=ts,
                          action="SHA-256 calculated",
                          actor="RansomGuard Evidence Service",
                          detail=f"{sha256_of_bytes(content)}")
        db.append_custody(conn, evidence_id, ts_dt=ts,
                          action="Stored in evidence repository",
                          actor="RansomGuard backend",
                          detail=str(path))
        return evidence_id


def config_on_windows() -> bool:
    import os
    return os.name == "nt"


def backend_host_label() -> str:
    import socket
    return f"backend host '{socket.gethostname()}'"


def _safe_int(value: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _normalize_powershell_date(value) -> str:
    """Convert Windows PowerShell '/Date(ms)/' serialization to ISO 8601 UTC."""
    import re
    if not isinstance(value, str):
        return str(value or "")
    match = re.fullmatch(r"/Date\((\d+)\)/", value)
    if not match:
        return value
    dt = datetime.fromtimestamp(int(match.group(1)) / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
