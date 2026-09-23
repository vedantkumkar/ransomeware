"""Detection heuristic tests: rapid changes, .locked files, ransom note.

Synthetic tests use in-memory snapshot dicts; the full-flow tests use a real
temp sandbox via VM_AGENT_TEST_DIR and the real DirectoryMonitor.

Since detection is burst-based (fire only after the directory goes quiet),
``drive_to_fire`` feeds quiet snapshots until the aggregated event is emitted.
"""

import pytest

from detector.config import load_config
from detector.monitor import RANSOM_NOTE_NAME, DetectionEngine, DirectoryMonitor


def make_engine(config, **kwargs):
    """Engine with the (host-dependent) process check disabled by default."""
    kwargs.setdefault("process_finder", lambda name: 0)
    return DetectionEngine(config, **kwargs)


def drive_to_fire(engine, snapshot, clock=None, max_quiet=6):
    """Process ``snapshot``, then feed quiet scans until the burst completes.

    Returns the fired event dict, or None if no burst was triggered.
    """
    event = engine.process_snapshot(dict(snapshot))
    for _ in range(max_quiet):
        if event is not None:
            return event
        if clock is not None:
            clock[0] += 1.0
        event = engine.process_snapshot(dict(snapshot))
    return event


class TestSyntheticHeuristics:
    def test_quiet_dir_never_fires(self, make_config):
        engine = make_engine(make_config())
        assert engine.process_snapshot({}) is None  # baseline
        assert engine.process_snapshot({}) is None
        assert engine.process_snapshot({}) is None  # stays quiet, no burst

    def test_preexisting_files_do_not_fire_at_startup(self, make_config):
        engine = make_engine(make_config())
        snapshot = {"file%d.txt" % i: (100, 1000 + i) for i in range(30)}
        assert engine.process_snapshot(dict(snapshot)) is None  # baseline
        assert engine.process_snapshot(dict(snapshot)) is None  # unchanged
        assert engine.process_snapshot(dict(snapshot)) is None

    def test_rapid_creation_fires(self, make_config):
        engine = make_engine(make_config())
        assert engine.process_snapshot({}) is None  # baseline
        snapshot = {"doc%d.txt" % i: (10, 1000 + i) for i in range(15)}
        event = drive_to_fire(engine, snapshot)
        assert event is not None
        assert "rapid_file_modification" in event["detection_reasons"]
        # mass creation is not in-place modification: counted via the
        # manifest evidence, not the files_modified counter
        assert event["files_modified"] == 0

    def test_rapid_modification_of_existing_files_fires(self, make_config):
        engine = make_engine(make_config())
        before = {"doc%d.txt" % i: (10, 100) for i in range(15)}
        assert engine.process_snapshot(dict(before)) is None  # baseline
        after = {"doc%d.txt" % i: (10 + i, 200) for i in range(15)}
        event = drive_to_fire(engine, after)
        assert event is not None
        assert event["detection_reasons"] == ["rapid_file_modification"]
        assert event["files_modified"] == 15

    def test_locked_extension_activity_fires(self, make_config):
        engine = make_engine(make_config())
        assert engine.process_snapshot({}) is None  # baseline
        snapshot = {"doc%d.txt.locked" % i: (10, i) for i in range(6)}  # 6 > 5
        event = drive_to_fire(engine, snapshot)
        assert event is not None
        assert "locked_extension_activity" in event["detection_reasons"]
        assert event["locked_files"] == 6
        # 6 create events is below the rapid threshold of 10.
        assert "rapid_file_modification" not in event["detection_reasons"]

    def test_below_locked_threshold_does_not_fire(self, make_config):
        engine = make_engine(make_config())
        assert engine.process_snapshot({}) is None  # baseline
        snapshot = {"doc%d.txt.locked" % i: (10, i) for i in range(5)}  # not > 5
        assert engine.process_snapshot(snapshot) is None
        assert engine.process_snapshot(snapshot) is None

    def test_ransom_note_detected(self, make_config):
        engine = make_engine(make_config())
        assert engine.process_snapshot({}) is None  # baseline
        snapshot = {RANSOM_NOTE_NAME: (50, 1)}
        event = drive_to_fire(engine, snapshot)
        assert event is not None
        # the demo note is the known simulator signature: process attributed, PID 0
        assert set(event["detection_reasons"]) == {
            "ransom_note_detected",
            "suspicious_process",
        }
        assert event["process_id"] == 0
        assert event["ransom_note_detected"] is True
        assert event["ransom_note_name"] == RANSOM_NOTE_NAME

    def test_aggregated_event_combines_all_reasons(self, make_config):
        engine = make_engine(make_config())
        before = {"doc%d.txt" % i: (10, i) for i in range(12)}
        assert engine.process_snapshot(dict(before)) is None  # baseline
        after = {"doc%d.txt" % i: (20, 100 + i) for i in range(12)}  # modified
        after.update({"doc%d.txt.locked" % i: (10, 200 + i) for i in range(6)})
        after[RANSOM_NOTE_NAME] = (50, 999)
        event = drive_to_fire(engine, after)
        assert event is not None
        assert set(event["detection_reasons"]) == {
            "rapid_file_modification",
            "locked_extension_activity",
            "ransom_note_detected",
            "suspicious_process",
        }
        assert event["files_modified"] == 12
        assert event["locked_files"] == 6

    def test_suspicious_process_adds_reason_and_real_pid(self, make_config):
        engine = make_engine(
            make_config(), process_finder=lambda name: 4824
        )
        engine.process_snapshot({})
        snapshot = {"doc%d.txt" % i: (10, i) for i in range(15)}
        event = drive_to_fire(engine, snapshot)
        assert event is not None
        assert "suspicious_process" in event["detection_reasons"]
        assert event["process_id"] == 4824

    def test_process_not_found_reports_pid_zero(self, make_config):
        engine = make_engine(make_config(), process_finder=lambda name: 0)
        engine.process_snapshot({})
        snapshot = {"doc%d.txt" % i: (10, i) for i in range(15)}
        event = drive_to_fire(engine, snapshot)
        assert event is not None
        # no note, no live process: behavioral reasons only
        assert "suspicious_process" not in event["detection_reasons"]
        assert event["process_id"] == 0

    def test_events_accumulate_across_scans_within_window(self, make_config):
        now = [1000.0]
        engine = make_engine(
            make_config(rapid_window_seconds=10.0), clock=lambda: now[0]
        )
        files = {"doc%d.txt" % i: (10, 100) for i in range(15)}
        assert engine.process_snapshot(dict(files)) is None  # baseline

        changed = dict(files)
        for i in range(3):
            changed["doc%d.txt" % i] = (11, 200)
        now[0] = 1002.0
        assert engine.process_snapshot(changed) is None  # only 3 events so far

        for i in range(3, 11):  # 8 more changes, still inside the 10s window
            changed["doc%d.txt" % i] = (12, 300)
        now[0] = 1004.0
        event = drive_to_fire(engine, changed, clock=now)
        assert event is not None
        assert event["files_modified"] == 11

    def test_old_events_expire_outside_window(self, make_config):
        now = [2000.0]
        engine = make_engine(make_config(rapid_window_seconds=5.0), clock=lambda: now[0])
        files = {"doc%d.txt" % i: (10, 100) for i in range(15)}
        engine.process_snapshot(dict(files))  # baseline

        changed = dict(files)
        for i in range(3):
            changed["doc%d.txt" % i] = (11, 200)
        now[0] = 2001.0
        assert engine.process_snapshot(changed) is None

        now[0] = 2010.0  # 9s later: the 3 events aged out of the 5s window
        assert engine.process_snapshot(changed) is None

    def test_max_burst_seconds_forces_fire_on_endless_activity(self, make_config):
        now = [3000.0]
        engine = make_engine(
            make_config(max_burst_seconds=5.0, rapid_window_seconds=100.0),
            clock=lambda: now[0],
        )
        files = {"doc%d.txt" % i: (10, 100) for i in range(15)}
        assert engine.process_snapshot(dict(files)) is None  # baseline

        # activity never stops: every scan modifies one more file. After the
        # sliding window accumulates >10 events the burst starts, and since
        # quiet never arrives, max_burst_seconds must force the report.
        event = None
        for tick in range(1, 30):
            now[0] += 1.0
            changing = dict(files)
            changing["doc%d.txt" % (tick % 15)] = (10 + tick, 1000 + tick)
            event = engine.process_snapshot(changing)
            if event is not None:
                break
        assert event is not None, "max_burst_seconds must fire an endless burst"
        assert "rapid_file_modification" in event["detection_reasons"]


class TestRealSandboxFlow:
    def test_full_detection_flow_in_real_sandbox(self, sandbox, monkeypatch):
        monkeypatch.setenv("VM_AGENT_TEST_DIR", str(sandbox))
        config = load_config()
        assert config.monitor_dir_is_test is True

        monitor = DirectoryMonitor(config.monitor_dir)
        engine = make_engine(config)

        assert engine.process_snapshot(monitor.snapshot()) is None  # baseline

        for i in range(15):
            (sandbox / ("doc%d.txt" % i)).write_text("dummy payload %d" % i)
        assert engine.process_snapshot(monitor.snapshot()) is None  # burst starts

        # continue the burst: modify 3 files, add .locked copies and the note
        for i in range(3):
            (sandbox / ("doc%d.txt" % i)).write_text("modified payload %d" % i)
        for i in range(6):
            (sandbox / ("doc%d.txt.locked" % i)).write_text("locked copy")
        (sandbox / RANSOM_NOTE_NAME).write_text("restore instructions")
        assert engine.process_snapshot(monitor.snapshot()) is None  # still active

        event = drive_to_fire(engine, monitor.snapshot())
        assert event is not None
        assert set(event["detection_reasons"]) == {
            "rapid_file_modification",
            "locked_extension_activity",
            "ransom_note_detected",
            "suspicious_process",  # demo note present → process attributed
        }
        assert event["files_modified"] == 3
        assert event["locked_files"] == 6
        assert event["target_directory"] == str(sandbox)

    def test_subdirectories_are_ignored(self, sandbox, monkeypatch):
        monkeypatch.setenv("VM_AGENT_TEST_DIR", str(sandbox))
        config = load_config()
        monitor = DirectoryMonitor(config.monitor_dir)
        engine = make_engine(config)

        assert engine.process_snapshot(monitor.snapshot()) is None  # baseline
        sub = sandbox / "subdir"
        sub.mkdir()
        for i in range(15):
            (sub / ("f%d.txt" % i)).write_text("hidden from the agent")
        assert engine.process_snapshot(monitor.snapshot()) is None
        assert engine.process_snapshot(monitor.snapshot()) is None

    def test_missing_directory_yields_empty_snapshot(self, sandbox, monkeypatch, tmp_path):
        monkeypatch.setenv("VM_AGENT_TEST_DIR", str(sandbox))
        config = load_config()
        monitor = DirectoryMonitor(str(tmp_path / "does_not_exist"))
        assert monitor.snapshot() == {}
