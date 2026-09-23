"""Event payload contract tests: EXACT field names from CONTRACTS.md section 1."""

import re

from detector.monitor import RANSOM_NOTE_NAME, DetectionEngine

CONTRACT_KEYS = [
    "event_type",
    "hostname",
    "ip_address",
    "username",
    "process_name",
    "process_id",
    "process_path",
    "target_directory",
    "files_modified",
    "locked_files",
    "ransom_note_detected",
    "ransom_note_name",
    "detection_reasons",
    "timestamp",
]

ALLOWED_REASON_CODES = {
    "rapid_file_modification",
    "locked_extension_activity",
    "ransom_note_detected",
    "suspicious_process",
}

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")


def fire_all_reasons(config):
    engine = DetectionEngine(config, process_finder=lambda name: 4824)
    before = {"doc%d.txt" % i: (10, i) for i in range(15)}
    engine.process_snapshot(dict(before))  # baseline
    snapshot = {"doc%d.txt" % i: (20, 100 + i) for i in range(15)}  # modified
    snapshot.update({"doc%d.txt.locked" % i: (10, 200 + i) for i in range(6)})
    snapshot[RANSOM_NOTE_NAME] = (50, 999)
    event = engine.process_snapshot(dict(snapshot))  # burst starts
    for _ in range(6):
        if event is not None:
            break
        event = engine.process_snapshot(dict(snapshot))  # quiet scans
    assert event is not None
    return event


def test_event_has_exactly_the_contract_fields(make_config):
    event = fire_all_reasons(make_config())
    assert list(event.keys()) == CONTRACT_KEYS


def test_event_type_and_reason_codes(make_config):
    event = fire_all_reasons(make_config())
    assert event["event_type"] == "ransomware_behavior"
    assert set(event["detection_reasons"]) <= ALLOWED_REASON_CODES
    assert event["detection_reasons"] == [
        "rapid_file_modification",
        "locked_extension_activity",
        "ransom_note_detected",
        "suspicious_process",
    ]


def test_event_identity_and_process_fields(make_config):
    config = make_config()
    event = fire_all_reasons(config)
    assert event["hostname"] == "VICTIM-PC-01"
    assert event["ip_address"] == "192.168.56.105"
    assert event["username"] == "demo-user"
    assert event["process_name"] == "DemoRansomware.exe"
    assert event["process_id"] == 4824
    assert event["process_path"] == r"C:\RansomwareDemo\DemoRansomware.exe"
    assert event["target_directory"] == config.monitor_dir


def test_event_counters_and_note_fields(make_config):
    event = fire_all_reasons(make_config())
    assert event["files_modified"] == 15
    assert event["locked_files"] == 6
    assert event["ransom_note_detected"] is True
    assert event["ransom_note_name"] == "README_RESTORE_FILES.txt"
    assert TIMESTAMP_RE.match(event["timestamp"])


def test_event_without_note_has_empty_note_name(make_config):
    engine = DetectionEngine(make_config(), process_finder=lambda name: 0)
    engine.process_snapshot({})
    snapshot = {"doc%d.txt" % i: (10, i) for i in range(15)}
    event = engine.process_snapshot(dict(snapshot))  # burst starts
    for _ in range(6):
        if event is not None:
            break
        event = engine.process_snapshot(dict(snapshot))  # quiet scans
    assert event is not None
    assert event["ransom_note_detected"] is False
    assert event["ransom_note_name"] == ""
    assert "ransom_note_detected" not in event["detection_reasons"]


def test_risk_assessment_matches_contract_weights():
    from detector.monitor import risk_assessment

    all_reasons = [
        "rapid_file_modification",
        "locked_extension_activity",
        "ransom_note_detected",
        "suspicious_process",
    ]
    assert risk_assessment(all_reasons) == (96, "critical")
    assert risk_assessment(["ransom_note_detected"]) == (25, "low")
    assert risk_assessment(
        ["rapid_file_modification", "locked_extension_activity"]
    ) == (60, "high")
