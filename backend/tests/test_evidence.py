"""Evidence artifact, integrity-verification, chain-of-custody and
notification read-state tests (extension suite)."""

import hashlib
import json
from pathlib import Path

DETECTION_EVENT = {
    "event_type": "ransomware_behavior",
    "hostname": "VICTIM-PC-01",
    "ip_address": "192.168.56.105",
    "username": "demo-user",
    "process_name": "DemoRansomware.exe",
    "process_id": 4824,
    "process_path": "C:\\RansomwareDemo\\DemoRansomware.exe",
    "target_directory": "C:\\RansomwareDemo\\TestFiles",
    "files_modified": 37,
    "locked_files": 32,
    "ransom_note_detected": True,
    "ransom_note_name": "README_RESTORE_FILES.txt",
    "detection_reasons": [
        "rapid_file_modification",
        "locked_extension_activity",
        "ransom_note_detected",
        "suspicious_process",
    ],
    "timestamp": "2026-08-29T10:32:01.124Z",
}


def trigger_detection(client) -> str:
    response = client.post("/api/events/detection", json=DETECTION_EVENT)
    assert response.status_code == 200
    return response.json()["incident_id"]


def get_evidence_list(client) -> list[dict]:
    return client.get("/api/evidence").json()


def by_type(items: list[dict], type_: str) -> dict:
    return next(item for item in items if item["type"] == type_)


# ── Automated collection: real artifacts, hashes, custody ────────────────────

class TestAutomatedArtifacts:

    def test_artifacts_generated_and_stored(self, client, tmp_path):
        trigger_detection(client)
        items = get_evidence_list(client)
        assert len(items) == 4
        evidence_dir = tmp_path / "evidence_storage" / "RAN-2026-001"
        for item in items:
            assert item["hasArtifact"] is True
            assert item["artifactName"]
            assert item["sizeBytes"] > 0
            assert Path(item["artifactName"]).name == item["artifactName"]
            assert (evidence_dir / item["artifactName"]).is_file()

    def test_sha256_computed_from_artifact_bytes(self, client, tmp_path):
        trigger_detection(client)
        evidence_dir = tmp_path / "evidence_storage" / "RAN-2026-001"
        for item in get_evidence_list(client):
            content = (evidence_dir / item["artifactName"]).read_bytes()
            assert hashlib.sha256(content).hexdigest() == item["sha256"]

    def test_detection_log_contains_real_event_data(self, client):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        artifact = client.get(f"/api/evidence/{item['id']}/artifact").json()
        payload = json.loads(artifact["content"])
        assert payload["hostname"] == "VICTIM-PC-01"
        assert payload["process_name"] == "DemoRansomware.exe"
        assert payload["files_modified"] == 37

    def test_process_snapshot_has_no_fabricated_fields(self, client):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "process_snapshot")
        artifact = client.get(f"/api/evidence/{item['id']}/artifact").json()
        payload = json.loads(artifact["content"])
        assert payload["processName"] == "DemoRansomware.exe"
        assert payload["pid"] == 4824
        assert "commandLine" in payload["notCaptured"]
        assert "parentProcess" in payload["notCaptured"]
        assert "commandLine" not in payload

    def test_ransom_note_captures_real_content(self, client, tmp_path, monkeypatch):
        # Make the target directory real on the backend host with a real note.
        target = tmp_path / "TestFiles"
        target.mkdir()
        note_text = "SAFE simulation demo note — nothing was encrypted.\n"
        (target / "README_RESTORE_FILES.txt").write_text(note_text, encoding="utf-8")
        (target / "report.docx.locked").write_text("locked copy", encoding="utf-8")
        monkeypatch.setattr(
            "app.services.evidence_service.Path", Path, raising=False)

        import app.services.evidence_service as es

        original_scan = es.EvidenceCollectionService._scan_directory
        original_note = es.EvidenceCollectionService._capture_note
        monkeypatch.setattr(
            es.EvidenceCollectionService, "_scan_directory",
            staticmethod(lambda t: original_scan(str(target))))
        monkeypatch.setattr(
            es.EvidenceCollectionService, "_capture_note",
            staticmethod(lambda t, n: original_note(str(target), n)))

        trigger_detection(client)
        item = by_type(get_evidence_list(client), "ransom_note")
        artifact = client.get(f"/api/evidence/{item['id']}/artifact").json()
        assert artifact["content"].replace("\r\n", "\n") == note_text  # REAL note content
        manifest = by_type(get_evidence_list(client), "file_manifest")
        manifest_artifact = client.get(f"/api/evidence/{manifest['id']}/artifact").json()
        scan = json.loads(manifest_artifact["content"])["directoryScan"]
        assert scan["reachable"] is True
        names = {entry["name"] for entry in scan["entries"]}
        assert names == {"README_RESTORE_FILES.txt", "report.docx.locked"}

    def test_unreachable_target_marked_not_captured(self, client):
        trigger_detection(client)  # C:\RansomwareDemo\TestFiles may or may not exist
        item = by_type(get_evidence_list(client), "ransom_note")
        artifact = client.get(f"/api/evidence/{item['id']}/artifact").json()
        try:
            payload = json.loads(artifact["content"])
        except ValueError:
            payload = artifact["content"]  # real captured note text
        # Either the real content or an explicit notCaptured record — never a fake note.
        if isinstance(payload, dict) and "notCaptured" in payload:
            assert payload["notCaptured"]["reason"]
        else:
            assert "encrypt" in str(payload).lower() or "safe" in str(payload).lower()

    def test_custody_history_created_on_collection(self, client):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        detail = client.get(f"/api/evidence/{item['id']}").json()
        actions = [entry["action"] for entry in detail["custody"]]
        assert "Collected automatically" in actions
        assert "SHA-256 calculated" in actions
        assert "Stored in evidence repository" in actions
        for entry in detail["custody"]:
            assert entry["timestamp"]

    def test_evidence_detail_has_forensic_metadata(self, client):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        detail = client.get(f"/api/evidence/{item['id']}").json()
        assert detail["collectionMethod"] == "automated"
        assert detail["collectedBy"] == "VM Detection Agent"
        assert detail["mimeType"] == "application/json"


# ── Integrity verification ───────────────────────────────────────────────────

class TestIntegrityVerification:

    def test_verification_succeeds_on_intact_artifact(self, client):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        result = client.post(f"/api/evidence/{item['id']}/verify").json()
        assert result["integrity"] == "verified"
        assert "matches" in result["message"].lower()

    def test_tampered_artifact_does_not_return_verified(self, client, tmp_path):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        evidence_dir = tmp_path / "evidence_storage" / "RAN-2026-001"
        (evidence_dir / item["artifactName"]).write_bytes(b"tampered content")
        result = client.post(f"/api/evidence/{item['id']}/verify").json()
        assert result["integrity"] == "verification_failed"

    def test_missing_artifact_returns_artifact_missing(self, client, tmp_path):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        evidence_dir = tmp_path / "evidence_storage" / "RAN-2026-001"
        (evidence_dir / item["artifactName"]).unlink()
        result = client.post(f"/api/evidence/{item['id']}/verify").json()
        assert result["integrity"] == "artifact_missing"

    def test_verification_records_custody_entry(self, client):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        before = client.get(f"/api/evidence/{item['id']}").json()
        client.post(f"/api/evidence/{item['id']}/verify")
        after = client.get(f"/api/evidence/{item['id']}").json()
        actions = [entry["action"] for entry in after["custody"]]
        assert "Integrity checked" in actions
        assert len(after["custody"]) == len(before["custody"]) + 1
        assert after["integrity"] == "verified"

    def test_verify_unknown_evidence_404(self, client):
        assert client.post("/api/evidence/EVD-9999/verify").status_code == 404

    def test_artifact_missing_404_for_legacy_record(self, client):
        trigger_detection(client)
        item = by_type(get_evidence_list(client), "detection_log")
        conn = client.app.dependency_overrides  # not used; direct db update below
        from app import db as app_db
        app_db.execute(app_db.get_connection(),
                       "UPDATE evidence SET storage_path = '' WHERE id = ?",
                       (item["id"],))
        response = client.get(f"/api/evidence/{item['id']}/artifact")
        assert response.status_code == 404
        assert "legacy" in response.json()["detail"].lower()


# ── Manual collection ────────────────────────────────────────────────────────

class TestManualCollection:

    def test_manual_text_artifact_creates_real_record(self, client, tmp_path):
        trigger_detection(client)
        response = client.post("/api/incidents/RAN-2026-001/collect-evidence", json={
            "evidenceType": "text_artifact",
            "content": "analyst captured log line 1\nline 2",
        })
        assert response.status_code == 200
        items = get_evidence_list(client)
        assert len(items) == 5
        created = items[-1]
        assert created["type"] == "text_artifact"
        assert created["collectionMethod"] == "manual"
        assert created["collectedBy"] == "SOC Analyst"
        artifact = client.get(f"/api/evidence/{created['id']}/artifact").json()
        assert artifact["content"] == "analyst captured log line 1\nline 2"
        assert hashlib.sha256(artifact["content"].encode()).hexdigest() == created["sha256"]

    def test_manual_empty_text_fails_without_record(self, client):
        trigger_detection(client)
        before = len(get_evidence_list(client))
        response = client.post("/api/incidents/RAN-2026-001/collect-evidence", json={
            "evidenceType": "text_artifact", "content": "   ",
        })
        assert response.status_code == 400
        assert len(get_evidence_list(client)) == before  # no record created

    def test_manual_collection_records_custody_and_timeline(self, client):
        trigger_detection(client)
        client.post("/api/incidents/RAN-2026-001/collect-evidence", json={
            "evidenceType": "text_artifact", "content": "custody test",
        })
        detail = client.get("/api/evidence/" + get_evidence_list(client)[-1]["id"]).json()
        actions = [entry["action"] for entry in detail["custody"]]
        assert "Collected manually by SOC Analyst" in actions
        timeline = client.get("/api/incidents/RAN-2026-001/timeline").json()
        manual = [event for event in timeline if not event["automated"]]
        assert any("forensic collection by analyst" in event["title"].lower()
                   for event in manual)

    def test_manual_process_snapshot_is_real(self, client):
        import os
        if os.name != "nt":
            return
        trigger_detection(client)
        response = client.post("/api/incidents/RAN-2026-001/collect-evidence", json={
            "evidenceType": "process_snapshot",
        })
        assert response.status_code == 200
        created = [i for i in get_evidence_list(client)
                   if i["collectionMethod"] == "manual"][0]
        artifact = client.get(f"/api/evidence/{created['id']}/artifact").json()
        payload = json.loads(artifact["content"])
        assert payload["processCount"] > 0
        assert any(p["imageName"].lower() == "python.exe" for p in payload["processes"])

    def test_manual_windows_event_logs_are_real(self, client):
        import os
        if os.name != "nt":
            return
        trigger_detection(client)
        response = client.post("/api/incidents/RAN-2026-001/collect-evidence", json={
            "evidenceType": "windows_event_logs",
        })
        assert response.status_code == 200
        created = [i for i in get_evidence_list(client)
                   if i["type"] == "event_logs"][0]
        artifact = client.get(f"/api/evidence/{created['id']}/artifact").json()
        payload = json.loads(artifact["content"])
        # Real events only — if the host log has entries, they carry real fields.
        assert "events" in payload and "capturedFrom" in payload

    def test_manual_fresh_manifest_requires_reachable_dir(self, client):
        trigger_detection(client)
        response = client.post("/api/incidents/RAN-2026-001/collect-evidence", json={
            "evidenceType": "file_manifest",
        })
        # Real directory C:\RansomwareDemo\TestFiles exists on this host → success
        # with real entries; otherwise a clean 400 failure. Never a fake record.
        if response.status_code == 200:
            created = [i for i in get_evidence_list(client)
                       if i["collectionMethod"] == "manual"][0]
            artifact = client.get(f"/api/evidence/{created['id']}/artifact").json()
            scan = json.loads(artifact["content"])["directoryScan"]
            assert scan["reachable"] is True
        else:
            assert response.status_code == 400
            assert len([i for i in get_evidence_list(client)
                        if i["collectionMethod"] == "manual"]) == 0

    def test_manual_collection_notification_created(self, client):
        trigger_detection(client)
        before = client.get("/api/notifications").json()
        client.post("/api/incidents/RAN-2026-001/collect-evidence", json={
            "evidenceType": "text_artifact", "content": "notify test",
        })
        after = client.get("/api/notifications").json()
        assert len(after) == len(before) + 1
        assert "Manual evidence collection" in after[0]["title"]


# ── Notification read state ──────────────────────────────────────────────────

class TestNotificationReadState:

    def test_unread_count_derived_from_read_state(self, client):
        trigger_detection(client)  # creates 3 unread notifications
        notifications = client.get("/api/notifications").json()
        unread = sum(1 for n in notifications if not n["read"])
        assert unread == 3

    def test_mark_all_read_persists(self, client):
        trigger_detection(client)
        result = client.post("/api/notifications/mark-all-read").json()
        assert result["updated"] == 3
        assert result["unread"] == 0
        notifications = client.get("/api/notifications").json()
        assert all(n["read"] for n in notifications)
        assert sum(1 for n in notifications if not n["read"]) == 0

    def test_individual_read_decrements_count(self, client):
        trigger_detection(client)
        notifications = client.get("/api/notifications").json()
        first_id = notifications[0]["id"]
        result = client.post(f"/api/notifications/{first_id}/read").json()
        assert result["updated"] == 1
        assert result["unread"] == 2
        after = client.get("/api/notifications").json()
        target = next(n for n in after if n["id"] == first_id)
        assert target["read"] is True
        assert sum(1 for n in after if not n["read"]) == 2

    def test_read_unknown_notification_404(self, client):
        assert client.post("/api/notifications/notif-9999/read").status_code == 404

    def test_mark_all_read_is_idempotent(self, client):
        trigger_detection(client)
        client.post("/api/notifications/mark-all-read")
        result = client.post("/api/notifications/mark-all-read").json()
        assert result["updated"] == 0
        assert result["unread"] == 0
