"""Cooldown and deduplication-of-alerts tests (burst-aware)."""

from detector.monitor import DetectionEngine


def files_snapshot(count, offset=0, size=10):
    return {
        "doc%d.txt" % (i + offset): (size, 1000 + i + offset) for i in range(count)
    }


def drive_to_fire(engine, snapshot, max_quiet=6):
    """Process a snapshot, then feed quiet scans until the burst completes."""
    event = engine.process_snapshot(dict(snapshot))
    for _ in range(max_quiet):
        if event is not None:
            return event
        event = engine.process_snapshot(dict(snapshot))
    return event


def test_two_triggered_scans_within_cooldown_report_once(make_config):
    engine = DetectionEngine(make_config(cooldown_seconds=60.0),
                             process_finder=lambda name: 0)
    assert engine.process_snapshot({}) is None  # baseline

    first = drive_to_fire(engine, files_snapshot(15))
    assert first is not None

    second = drive_to_fire(engine, files_snapshot(20))  # new activity again
    assert second is None  # suppressed by the 60s cooldown


def test_after_cooldown_persistent_state_does_not_refire(make_config):
    # cooldown 0 means the cooldown gate is always open; only NEW activity
    # may trigger a second report.
    engine = DetectionEngine(make_config(cooldown_seconds=0.0),
                             process_finder=lambda name: 0)
    assert engine.process_snapshot({}) is None  # baseline

    snapshot = files_snapshot(0)
    snapshot.update({"doc%d.txt.locked" % i: (10, i) for i in range(6)})
    first = drive_to_fire(engine, snapshot)
    assert first is not None

    # Unchanged state after the report: no re-fire even though reasons persist.
    assert drive_to_fire(engine, snapshot) is None


def test_after_cooldown_new_activity_can_report_again(make_config):
    engine = DetectionEngine(make_config(cooldown_seconds=0.0),
                             process_finder=lambda name: 0)
    assert engine.process_snapshot({}) is None  # baseline

    snapshot = {"doc%d.txt.locked" % i: (10, i) for i in range(6)}
    first = drive_to_fire(engine, snapshot)
    assert first is not None
    assert first["locked_files"] == 6

    snapshot["doc6.txt.locked"] = (10, 999)  # one more .locked file appears
    second = drive_to_fire(engine, snapshot)
    assert second is not None
    assert second["locked_files"] == 7
    # the new .locked COPY is a creation, not an in-place modification
    assert second["files_modified"] == 0
