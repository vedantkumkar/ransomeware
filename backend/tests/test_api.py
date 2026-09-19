"""API contract tests for the RansomGuard IR backend.

The detection event payload is the exact sample from shared/CONTRACTS.md
section 1. Expected demo results: risk 96, severity critical, status
contained, 10 timeline steps, 4 evidence artifacts, 3 notifications.
"""

import hashlib
import re
from datetime import datetime

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

TIMESTAMP_OF_DAY = re.compile(r"\d{2}:\d{2}:\d{2}\.\d{3}")
SHORT_TIME = re.compile(r"\d{1,2}:\d{2} [AP]M")
SHA256 = re.compile(r"[0-9a-f]{64}")


def ingest(client, event=None):
    return client.post("/api/events/detection", json=event or DETECTION_EVENT)


# ── Health & seeding ─────────────────────────────────────────────────────────

def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_seeded_demo_endpoint(client):
    endpoints = client.get("/api/endpoints").json()
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep["hostname"] == "VICTIM-PC-01"
    assert ep["ipAddress"] == "192.168.56.105"
    assert ep["user"] == "demo-user"
    assert ep["os"] == "Windows 11 Pro"
    assert ep["department"] == "Demo Lab"
    assert ep["agentStatus"] == "online"
    assert ep["riskScore"] == 0
    assert ep["severity"] == "none"
    assert ep["networkStatus"] == "connected"


def test_endpoint_by_id(client):
    endpoints = client.get("/api/endpoints").json()
    endpoint_id = endpoints[0]["id"]
    assert endpoint_id == "ep-001"
    fetched = client.get(f"/api/endpoints/{endpoint_id}")
    assert fetched.status_code == 200
    assert fetched.json()["hostname"] == "VICTIM-PC-01"


# ── Detection ingestion / orchestrator ───────────────────────────────────────

def test_detection_creates_incident(client):
    response = ingest(client)
    assert response.status_code == 200
    assert response.json() == {
        "accepted": True,
        "incident_id": "RAN-2026-001",
        "deduplicated": False,
    }

    incident = client.get("/api/incidents/RAN-2026-001").json()
    assert incident["id"] == "RAN-2026-001"
    assert incident["riskScore"] == 96
    assert incident["severity"] == "critical"
    assert incident["status"] == "contained"
    assert incident["networkStatus"] == "isolated"
    assert incident["agentStatus"] == "online"
    assert incident["threatType"] == "Ransomware Behavior"
    assert incident["detectionEngine"] == "Behavioral Detection"
    assert incident["hostname"] == "VICTIM-PC-01"
    assert incident["ipAddress"] == "192.168.56.105"
    assert incident["user"] == "demo-user"
    assert incident["department"] == "Demo Lab"
    assert incident["os"] == "Windows 11 Pro"
    assert incident["detectedAt"].startswith("2026-08-29T10:32:01.124")

    details = incident["threatDetails"]
    assert details["process"] == "DemoRansomware.exe"
    assert details["pid"] == 4824
    assert details["processPath"] == "C:\\RansomwareDemo\\DemoRansomware.exe"
    assert details["targetDirectory"] == "C:\\RansomwareDemo\\TestFiles"
    assert details["filesModified"] == 37
    assert details["filesLocked"] == 32
    assert details["ransomNote"] == "README_RESTORE_FILES.txt"
    assert details["detectionReasons"] == [
        "Rapid file modification detected",
        "Multiple .locked extensions created",
        "Ransom note creation detected",
        "Abnormal file activity threshold exceeded",
    ]
    breakdown = {item["label"]: item["value"] for item in details["riskBreakdown"]}
    assert breakdown == {
        "Rapid File Changes": 30,
        "Locked Extensions": 30,
        "Ransom Note": 25,
        "Suspicious Process": 11,
    }

    # Endpoint record updated by the orchestrator.
    endpoint = client.get("/api/endpoints").json()[0]
    assert endpoint["riskScore"] == 96
    assert endpoint["severity"] == "critical"
    assert endpoint["networkStatus"] == "isolated"
    assert endpoint["incidentId"] == "RAN-2026-001"


def test_timeline_contract(client):
    ingest(client)
    timeline = client.get("/api/incidents/RAN-2026-001/timeline").json()

    assert len(timeline) == 10
    assert [event["title"] for event in timeline] == [
        "Suspicious activity detected",
        "Risk score calculated: 96/100",
        "Critical ransomware incident created",
        "Host isolation command initiated",
        "VICTIM-PC-01 successfully isolated",
        "User demo-user suspended",
        "Active sessions revoked",
        "Forensic collection started",
        "Evidence package secured — 4 artifacts",
        "SOC notification generated",
    ]
    assert [event["type"] for event in timeline] == [
        "detection", "analysis", "action", "action", "success",
        "action", "action", "evidence", "success", "notification",
    ]
    assert all(event["automated"] is True for event in timeline)

    # Timestamps are "HH:MM:SS.mmm" and strictly increasing so the frontend
    # can compute the total response duration.
    parsed = []
    for event in timeline:
        assert TIMESTAMP_OF_DAY.fullmatch(event["timestamp"])
        parsed.append(datetime.strptime(event["timestamp"], "%H:%M:%S.%f"))
    assert all(later > earlier for earlier, later in zip(parsed, parsed[1:]))
    assert timeline[0]["timestamp"] == "10:32:01.124"


def test_evidence_records(client, tmp_path):
    ingest(client)

    evidence = client.get("/api/incidents/RAN-2026-001/evidence").json()
    assert [item["id"] for item in evidence] == ["EVD-001", "EVD-002", "EVD-003", "EVD-004"]
    assert {item["type"] for item in evidence} == {
        "detection_log", "file_manifest", "ransom_note", "process_snapshot",
    }
    for item in evidence:
        assert item["incidentId"] == "RAN-2026-001"
        assert item["source"] == "VICTIM-PC-01"
        assert item["integrity"] == "verified"
        assert item["collectedAt"].endswith("Z")
        assert item["size"]
        assert item["description"]
        assert SHA256.fullmatch(item["sha256"])

    assert len(client.get("/api/evidence").json()) == 4

    # Stored artifacts exist on disk and hashes match the stored SHA-256.
    evidence_dir = tmp_path / "evidence_storage" / "RAN-2026-001"
    stored_files = [path for path in evidence_dir.iterdir() if path.is_file()]
    assert len(stored_files) == 4
    stored_hashes = {hashlib.sha256(path.read_bytes()).hexdigest() for path in stored_files}
    assert {item["sha256"] for item in evidence} <= stored_hashes


def test_notifications(client):
    ingest(client)
    notifications = client.get("/api/notifications").json()
    assert len(notifications) == 3
    assert {item["severity"] for item in notifications} == {"critical", "high", "low"}
    for item in notifications:
        assert item["read"] is False
        assert item["incidentId"] == "RAN-2026-001"
        assert item["title"] and item["description"]
        assert SHORT_TIME.fullmatch(item["timestamp"])


def test_activity_log(client):
    ingest(client)
    entries = client.get("/api/activity").json()
    assert len(entries) >= 6

    detection = [e for e in entries if e["event"] == "Ransomware Behavior Detected"]
    assert detection and detection[0]["actor"] == "Detection Agent"
    assert detection[0]["actorType"] == "agent"
    assert detection[0]["target"] == "VICTIM-PC-01"

    assert any(e["actor"] == "Automation Engine" and e["actorType"] == "automation"
               and e["event"] == "Host Isolated" for e in entries)
    assert any(e["actor"] == "Automation Engine" and e["actorType"] == "automation"
               and e["event"] == "Evidence Collected" for e in entries)

    for entry in entries:
        assert entry["result"] == "success"
        assert entry["timestamp"].endswith("Z")
        assert entry["details"]


# ── Dashboard ────────────────────────────────────────────────────────────────

def test_dashboard_before_and_after_detection(client):
    before = client.get("/api/dashboard").json()
    assert before["stats"]["activeIncidents"] == 0
    assert before["stats"]["containedHosts"] == 0
    assert before["stats"]["criticalAlerts"] == 0
    assert before["stats"]["evidenceCollected"] == 0
    assert len(before["incidentsOverTime"]) == 7
    for point in before["incidentsOverTime"] + before["severityDistribution"]:
        assert set(point) == {"name", "value"}

    ingest(client)
    data = client.get("/api/dashboard").json()
    stats = data["stats"]
    assert stats["activeIncidents"] == 1
    assert stats["containedHosts"] == 1
    assert stats["criticalAlerts"] == 1  # 1 unread critical notification
    assert stats["evidenceCollected"] == 4
    assert isinstance(stats["avgDetectionTime"], str)
    assert isinstance(stats["avgContainmentTime"], str)
    assert stats["automationSuccessRate"].endswith("%")

    severity = {point["name"]: point["value"] for point in data["severityDistribution"]}
    assert severity == {"Critical": 1, "High": 0, "Medium": 0, "Low": 0}
    assert len(data["incidentsOverTime"]) == 7


# ── Duplicate protection ─────────────────────────────────────────────────────

def test_duplicate_event_within_cooldown_is_deduplicated(client):
    first = ingest(client).json()
    second = ingest(client).json()

    assert first["deduplicated"] is False
    assert second == {"accepted": True, "incident_id": "RAN-2026-001", "deduplicated": True}

    assert len(client.get("/api/incidents").json()) == 1
    assert len(client.get("/api/incidents/RAN-2026-001/timeline").json()) == 10
    assert len(client.get("/api/notifications").json()) == 3
    assert len(client.get("/api/evidence").json()) == 4


def test_event_after_cooldown_expiry_creates_new_incident(client):
    ingest(client)
    later = dict(DETECTION_EVENT)
    later["timestamp"] = "2026-08-29T10:37:02.124Z"  # 301s after the first event

    response = client.post("/api/events/detection", json=later).json()
    assert response == {"accepted": True, "incident_id": "RAN-2026-002",
                        "deduplicated": False}
    assert len(client.get("/api/incidents").json()) == 2


def test_detection_after_close_creates_new_incident(client):
    ingest(client)
    assert client.post("/api/incidents/RAN-2026-001/close").json()["success"] is True

    response = client.post("/api/events/detection", json=DETECTION_EVENT).json()
    assert response == {"accepted": True, "incident_id": "RAN-2026-002",
                        "deduplicated": False}


def test_invalid_detection_payload_rejected(client):
    bad_reasons = dict(DETECTION_EVENT, detection_reasons=["not_a_code"])
    assert client.post("/api/events/detection", json=bad_reasons).status_code == 422

    missing_host = dict(DETECTION_EVENT)
    del missing_host["hostname"]
    assert client.post("/api/events/detection", json=missing_host).status_code == 422

    assert client.get("/api/incidents").json() == []


# ── Analyst actions ──────────────────────────────────────────────────────────

def test_isolate_then_release(client):
    ingest(client)

    isolated = client.post("/api/incidents/RAN-2026-001/isolate")
    assert isolated.status_code == 200
    body = isolated.json()
    assert body["success"] is True
    assert "VICTIM-PC-01" in body["message"]
    assert client.get("/api/endpoints").json()[0]["networkStatus"] == "isolated"
    assert len(client.get("/api/incidents/RAN-2026-001/timeline").json()) == 11

    released = client.post("/api/incidents/RAN-2026-001/release").json()
    assert released["success"] is True
    incident = client.get("/api/incidents/RAN-2026-001").json()
    assert incident["networkStatus"] == "connected"
    assert client.get("/api/endpoints").json()[0]["networkStatus"] == "connected"

    activity = client.get("/api/activity").json()
    assert any(e["actor"] == "SOC Analyst" and e["actorType"] == "analyst"
               and e["event"] == "Host Released" for e in activity)
    timeline = client.get("/api/incidents/RAN-2026-001/timeline").json()
    assert len(timeline) == 12
    assert timeline[-1]["automated"] is False


def test_suspend_user(client):
    ingest(client)
    body = client.post("/api/incidents/RAN-2026-001/suspend-user").json()
    assert body["success"] is True
    assert "demo-user" in body["message"]

    activity = client.get("/api/activity").json()
    assert any(e["event"] == "User Account Suspended" and e["actor"] == "SOC Analyst"
               and e["actorType"] == "analyst" for e in activity)
    timeline = client.get("/api/incidents/RAN-2026-001/timeline").json()
    assert len(timeline) == 11


def test_collect_evidence(client):
    ingest(client)
    before = client.get("/api/evidence").json()

    body = client.post("/api/incidents/RAN-2026-001/collect-evidence").json()
    assert body["success"] is True

    after = client.get("/api/evidence").json()
    assert len(after) == len(before) + 1
    assert "event_logs" in {item["type"] for item in after} - {item["type"] for item in before}
    assert len(client.get("/api/incidents/RAN-2026-001/timeline").json()) == 11


def test_close_resolves_incident(client):
    ingest(client)
    body = client.post("/api/incidents/RAN-2026-001/close").json()
    assert body["success"] is True
    assert "RAN-2026-001" in body["message"]
    assert client.get("/api/incidents/RAN-2026-001").json()["status"] == "resolved"


def test_false_positive_marks_incident(client):
    ingest(client)
    body = client.post("/api/incidents/RAN-2026-001/false-positive").json()
    assert body["success"] is True
    assert client.get("/api/incidents/RAN-2026-001").json()["status"] == "false_positive"


def test_unknown_incident_returns_404(client):
    assert client.get("/api/incidents/RAN-9999-999").status_code == 404
    assert client.get("/api/incidents/RAN-9999-999/timeline").status_code == 404
    assert client.get("/api/incidents/RAN-9999-999/evidence").status_code == 404
    for action in ("isolate", "release", "suspend-user", "collect-evidence",
                   "false-positive", "close"):
        response = client.post(f"/api/incidents/RAN-9999-999/{action}")
        assert response.status_code == 404
    assert client.get("/api/endpoints/ep-999").status_code == 404


# ── Serialization contract (camelCase) ───────────────────────────────────────

def test_responses_are_camel_case(client):
    ingest(client)

    incident = client.get("/api/incidents").json()[0]
    for key in ("riskScore", "detectedAt", "detectionEngine", "networkStatus",
                "agentStatus", "threatType", "threatDetails"):
        assert key in incident
    assert "risk_score" not in incident

    endpoint = client.get("/api/endpoints").json()[0]
    for key in ("ipAddress", "riskScore", "agentStatus", "networkStatus",
                "lastSeen", "incidentId"):
        assert key in endpoint

    evidence = client.get("/api/evidence").json()[0]
    for key in ("incidentId", "collectedAt", "sha256", "integrity"):
        assert key in evidence

    entry = client.get("/api/activity").json()[0]
    for key in ("actorType", "timestamp", "result", "event"):
        assert key in entry

    notification = client.get("/api/notifications").json()[0]
    for key in ("incidentId", "timestamp", "read", "severity"):
        assert key in notification
