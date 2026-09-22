"""Read-only polling directory monitor and detection heuristics.

The monitor never creates, modifies, deletes, or renames anything. It only
takes snapshots of one validated directory via ``os.scandir`` and compares
consecutive snapshots. Symlinks and NTFS reparse points are skipped, and
subdirectories are never descended into.
"""

import csv
import logging
import os
import subprocess
import time
from collections import deque
from datetime import datetime, timezone

log = logging.getLogger("detector.monitor")

RANSOM_NOTE_NAME = "README_RESTORE_FILES.txt"
LOCKED_SUFFIX = ".locked"

_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_TASKLIST_TIMEOUT_SECONDS = 10

# Risk weights mirror shared/CONTRACTS.md section 2. The backend owns the
# final score; this is only used for local log lines so an operator watching
# the console sees a live risk/severity estimate.
RISK_POINTS = {
    "rapid_file_modification": 30,
    "locked_extension_activity": 30,
    "ransom_note_detected": 25,
    "suspicious_process": 11,
}


def risk_assessment(detection_reasons):
    """Return (risk_score, severity) for local logging only."""
    score = min(100, sum(RISK_POINTS.get(code, 0) for code in detection_reasons))
    if score >= 85:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    else:
        severity = "low"
    return score, severity


def utc_now_iso():
    """UTC ISO 8601 with millisecond precision, e.g. 2026-08-29T10:32:01.124Z."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def find_demo_process(process_name):
    """Return the PID of ``process_name`` via tasklist, or 0 when not found.

    Non-Windows platforms (unit tests, CI) always return 0. ``tasklist``
    cannot show full image paths, so the event reports the configured
    ``process_path`` instead (documented in the README).
    """
    if os.name != "nt":
        return 0
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        completed = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq %s" % (process_name,),
             "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=_TASKLIST_TIMEOUT_SECONDS,
            creationflags=creationflags,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("process check for %s failed: %s", process_name, exc)
        return 0
    for row in csv.reader(completed.stdout.splitlines()):
        if len(row) >= 2 and row[0].strip().lower() == process_name.lower():
            try:
                return int(row[1])
            except ValueError:
                continue
    return 0


class DirectoryMonitor:
    """Read-only snapshotter for a single directory."""

    def __init__(self, directory):
        self.directory = directory
        self._warned_missing = False

    def snapshot(self):
        """Return {name: (size, mtime_ns)} for regular files in the directory.

        Symlinks and reparse points are skipped; subdirectories are ignored.
        A missing or unreadable directory yields {} (with a one-time warning).
        """
        try:
            entries = list(os.scandir(self.directory))
        except FileNotFoundError:
            if not self._warned_missing:
                log.warning("monitored directory is missing: %s", self.directory)
                self._warned_missing = True
            return {}
        except OSError as exc:
            log.warning("scan failed for %s: %s", self.directory, exc)
            return {}
        self._warned_missing = False

        files = {}
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                stat = entry.stat(follow_symlinks=False)
                if getattr(stat, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                files[entry.name] = (stat.st_size, stat.st_mtime_ns)
            except OSError:
                continue  # entry vanished mid-scan; harmless, skip it
        return files


class DetectionEngine:
    """Turn consecutive snapshots into ONE aggregated detection event.

    Detection is burst-based: once any heuristic threshold is crossed, the
    engine enters a "pending burst" state and keeps accumulating file events.
    The event fires only when the directory has been quiet for
    ``burst_quiet_scans`` consecutive scans (or ``max_burst_seconds`` elapse,
    so an endless-drip burst still reports). Firing at the end of the burst
    means all behavioral signals — rapid modification, ``.locked`` copies,
    ransom note — are observed together, instead of reporting a half-finished
    burst.

    Heuristics (reason codes from shared/CONTRACTS.md section 1):

    - ``rapid_file_modification``: MORE than ``rapid_change_threshold`` file
      create/modify events accumulated in the burst (within the sliding
      ``rapid_window_seconds`` window).
    - ``locked_extension_activity``: MORE than ``locked_files_threshold``
      files currently end in ``.locked`` (case-insensitive).
    - ``ransom_note_detected``: ``README_RESTORE_FILES.txt`` is present.
    - ``suspicious_process``: the known demo-simulator process is attributed
      to the activity — either the configured process is live (real PID via
      tasklist) or the demo ransom note (its unique signature in this lab) is
      present. Behavioral reasons alone are sufficient to fire.

    ``files_modified`` counts in-place modifications of existing non-``.locked``
    files (the demo simulator's rewrite phase); mass creation of the seed files
    and the ``.locked`` copies is reported via ``locked_files`` and the
    backend's file-manifest evidence instead.

    The very first snapshot only establishes a baseline (so pre-existing
    files never cause a false alarm at startup). After a report the change
    window is cleared and a baseline is recorded: persistent reasons without
    NEW activity do not re-fire even after ``cooldown_seconds``, which keeps
    the backend free of duplicate alerts while remaining alert to new
    activity.
    """

    def __init__(self, config, clock=time.monotonic, process_finder=find_demo_process):
        self._config = config
        self._clock = clock
        self._process_finder = process_finder
        self._previous = None          # last snapshot: {name: (size, mtime_ns)}
        self._events = deque()         # (monotonic_time, kind, name) in the burst
        self._last_report_at = None    # monotonic time of last fired event
        self._reported_locked = 0      # locked count at last report (baseline)
        self._reported_note = False    # note present at last report (baseline)
        self._burst_active = False     # thresholds crossed; accumulating burst
        self._burst_started_at = None  # monotonic time the burst began
        self._quiet_scans = 0          # consecutive scans without new events

    def process_snapshot(self, snapshot):
        """Diff ``snapshot`` against the previous one; return event dict or None."""
        now = self._clock()

        if self._previous is None:
            self._previous = dict(snapshot)
            log.debug(
                "baseline established: %d file(s) in %s",
                len(snapshot), self._config.monitor_dir,
            )
            return None

        created = modified = 0
        for name, stamp in snapshot.items():
            previous = self._previous.get(name)
            if previous is None:
                self._events.append((now, "created", name))
                created += 1
            elif previous != stamp:
                self._events.append((now, "modified", name))
                modified += 1
        self._previous = dict(snapshot)

        # Sliding window: drop events older than rapid_window_seconds.
        window = self._config.rapid_window_seconds
        while self._events and now - self._events[0][0] > window:
            self._events.popleft()

        locked_files = sum(
            1 for name in snapshot if name.lower().endswith(LOCKED_SUFFIX)
        )
        note_lower = RANSOM_NOTE_NAME.lower()
        note_detected = any(name.lower() == note_lower for name in snapshot)

        burst_reasons = []
        if len(self._events) > self._config.rapid_change_threshold:
            burst_reasons.append("rapid_file_modification")
        if locked_files > self._config.locked_files_threshold:
            burst_reasons.append("locked_extension_activity")
        if note_detected:
            burst_reasons.append("ransom_note_detected")

        if burst_reasons and not self._burst_active:
            self._burst_active = True
            self._burst_started_at = now
            self._quiet_scans = 0
            log.debug("burst started: %s", ",".join(burst_reasons))

        if not self._burst_active:
            log.debug(
                "scan %s: files=%d created=%d modified=%d window_events=%d locked=%d note=%s",
                self._config.monitor_dir, len(snapshot), created, modified,
                len(self._events), locked_files, note_detected,
            )
            return None

        # Burst pending: fire on quiet, or when the max burst window elapses.
        if created + modified == 0:
            self._quiet_scans += 1
        else:
            self._quiet_scans = 0

        burst_elapsed = now - self._burst_started_at
        burst_complete = (
            self._quiet_scans >= self._config.burst_quiet_scans
            or burst_elapsed >= self._config.max_burst_seconds
        )
        log.debug(
            "scan %s: files=%d created=%d modified=%d window_events=%d locked=%d "
            "note=%s quiet_scans=%d elapsed=%.1fs",
            self._config.monitor_dir, len(snapshot), created, modified,
            len(self._events), locked_files, note_detected,
            self._quiet_scans, burst_elapsed,
        )
        if not burst_complete:
            return None

        reasons = list(burst_reasons)
        if self._last_report_at is not None:
            if now - self._last_report_at < self._config.cooldown_seconds:
                log.debug(
                    "detection suppressed: cooldown (%.1fs remaining)",
                    self._config.cooldown_seconds - (now - self._last_report_at),
                )
                self._reset_burst(locked_files, note_detected)
                return None
            new_activity = (
                bool(self._events)
                or locked_files > self._reported_locked
                or (note_detected and not self._reported_note)
            )
            if not new_activity:
                log.debug("detection suppressed: no new activity since last report")
                self._reset_burst(locked_files, note_detected)
                return None

        process_id = self._process_finder(self._config.process_name)
        # The demo ransom note is the unique signature of the known demo
        # simulator in this lab, so its presence attributes the activity to
        # that process even when tasklist cannot observe it (e.g. the script
        # exited between scans). A live PID is still preferred when available.
        if process_id or note_detected:
            reasons.append("suspicious_process")

        note_name = RANSOM_NOTE_NAME.lower()
        files_modified = sum(
            1
            for _time, kind, name in self._events
            if kind == "modified"
            and not name.lower().endswith(LOCKED_SUFFIX)
            and name.lower() != note_name
        )
        event = self.build_event(
            reasons, files_modified, locked_files, note_detected, process_id
        )

        self._last_report_at = now
        self._reset_burst(locked_files, note_detected)
        log.debug(
            "detection fired: reasons=%s files_modified=%d locked_files=%d pid=%s",
            ",".join(reasons), files_modified, locked_files, process_id,
        )
        return event

    def _reset_burst(self, locked_files, note_detected):
        """Clear burst state and record post-report baselines."""
        self._burst_active = False
        self._burst_started_at = None
        self._quiet_scans = 0
        self._events.clear()
        self._reported_locked = locked_files
        self._reported_note = note_detected

    def build_event(self, reasons, files_modified, locked_files, note_detected,
                    process_id):
        """Build the detection event payload.

        Field names and order EXACTLY match shared/CONTRACTS.md section 1.
        """
        return {
            "event_type": "ransomware_behavior",
            "hostname": self._config.hostname,
            "ip_address": self._config.ip_address,
            "username": self._config.username,
            "process_name": self._config.process_name,
            "process_id": int(process_id or 0),
            "process_path": self._config.process_path,
            "target_directory": self._config.monitor_dir,
            "files_modified": int(files_modified),
            "locked_files": int(locked_files),
            "ransom_note_detected": bool(note_detected),
            "ransom_note_name": RANSOM_NOTE_NAME if note_detected else "",
            "detection_reasons": list(reasons),
            "timestamp": utc_now_iso(),
        }
