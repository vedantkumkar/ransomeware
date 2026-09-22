"""RansomGuard IR VM detection agent — entry point.

Run from vm-agent\\:

    python detector/main.py                 # continuous monitoring (Ctrl+C to stop)
    python detector/main.py --once          # single scan+report pass (tests/CI)
    python detector/main.py --max-scans 5   # bounded run, then exit
    python detector/main.py --verbose       # DEBUG on the console too

Also works from the repo root (python vm-agent/detector/main.py) and as
``python -m detector.main`` from vm-agent\\.

This agent is DEFENSIVE monitoring software: it reads one validated
directory, never modifies anything, and sends at most one aggregated HTTP
POST per detection (subject to cooldown) to the FastAPI backend.
"""

import argparse
import logging
import os
import sys
import threading
import time
from logging.handlers import RotatingFileHandler

# Allow "python detector/main.py" from vm-agent\ (or any cwd): make the
# vm-agent folder importable so "detector" resolves as a package.
if __package__ in (None, ""):
    _PACKAGE_PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PACKAGE_PARENT not in sys.path:
        sys.path.insert(0, _PACKAGE_PARENT)

from detector.config import ConfigError, load_config
from detector.monitor import DetectionEngine, DirectoryMonitor, risk_assessment
from detector.reporter import Reporter, ReporterError

LOG = logging.getLogger("detector")
LOG_FILE_NAME = "detector.log"


def app_data_dir():
    """Folder holding config.ini / detector.log.

    Next to the frozen executable when packaged with PyInstaller, otherwise
    the vm-agent folder that contains this package.
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def setup_logging(verbose=False):
    """Console (INFO, DEBUG with --verbose) + rotating file (DEBUG)."""
    log_file = os.path.join(app_data_dir(), LOG_FILE_NAME)
    logger = logging.getLogger("detector")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    logger.addHandler(console)

    try:
        file_handler = RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.warning("file logging disabled (%s): %s", log_file, exc)
    return log_file


def log_banner(config, once, max_scans, log_file):
    LOG.info("=" * 62)
    LOG.info("RansomGuard IR VM detection agent starting")
    if once:
        LOG.info("  mode: single pass (--once)")
    elif max_scans:
        LOG.info("  mode: bounded (%d scans)", max_scans)
    else:
        LOG.info("  mode: continuous (Ctrl+C to stop)")
    LOG.info("  config source: %s", config.source)
    LOG.info("  backend_url: %s", config.backend_url)
    LOG.info(
        "  monitor_dir: %s (%s)",
        config.monitor_dir,
        "TEST override - temp sandbox" if config.monitor_dir_is_test
        else "validated demo directory",
    )
    LOG.info("  scan_interval_seconds: %s", config.scan_interval_seconds)
    LOG.info(
        "  rapid rule: >%d file events in %.1fs window",
        config.rapid_change_threshold, config.rapid_window_seconds,
    )
    LOG.info("  locked rule: >%d '.locked' files present", config.locked_files_threshold)
    LOG.info("  cooldown_seconds: %s", config.cooldown_seconds)
    LOG.info(
        "  identity: %s (%s) user=%s",
        config.hostname, config.ip_address, config.username,
    )
    LOG.info(
        "  process watch: %s (reported path %s)",
        config.process_name, config.process_path,
    )
    LOG.info(
        "  report retries: up to %d attempt(s) with exponential backoff",
        config.max_report_attempts,
    )
    LOG.info("  log file: %s", log_file)
    LOG.info("=" * 62)


def ensure_monitor_dir(config):
    """Create the monitored directory if missing (path is already validated)."""
    if os.path.isdir(config.monitor_dir):
        return
    try:
        os.makedirs(config.monitor_dir)
    except OSError as exc:
        raise ConfigError(
            "monitored directory %r does not exist and could not be created: %s"
            % (config.monitor_dir, exc)
        )
    LOG.info(
        "created empty monitored directory (validated safe path): %s",
        config.monitor_dir,
    )


def _report_in_background(reporter, event):
    """Retry delivery on a daemon thread so monitoring keeps running."""
    try:
        reporter.report(event)
    except ReporterError as exc:
        LOG.error("backend unreachable, gave up on this detection event: %s", exc)
    except Exception:  # noqa: BLE001 - reporting thread must never crash the agent
        LOG.exception("unexpected error while reporting detection event")


def _report_budget_seconds(reporter):
    """Worst-case wall time of a full retry cycle for this reporter."""
    retries = max(0, reporter.max_attempts - 1)
    return reporter.timeout + sum(reporter.backoff[:retries])


def _finish_pending_reports(report_threads, reporter, interrupt):
    """Wait for in-flight detection reports so shutdown never drops an event."""
    alive = [t for t in report_threads if t.is_alive()]
    if not alive:
        return
    budget = _report_budget_seconds(reporter)
    wait = min(10.0, budget) if interrupt else budget
    LOG.info(
        "waiting up to %.0fs for %d pending detection report(s) before exit",
        wait, len(alive),
    )
    deadline = time.monotonic() + wait
    for thread in alive:
        thread.join(max(0.0, deadline - time.monotonic()))
    abandoned = sum(1 for t in report_threads if t.is_alive())
    if abandoned:
        LOG.warning(
            "%d detection report(s) still retrying; abandoning on exit "
            "(those events were NOT delivered)", abandoned,
        )


def run(config, once=False, max_scans=0):
    """Run the scan loop. Returns a process exit code."""
    ensure_monitor_dir(config)
    monitor = DirectoryMonitor(config.monitor_dir)
    engine = DetectionEngine(config)
    reporter = Reporter(config.backend_url, max_attempts=config.max_report_attempts)
    report_threads = []

    scans = 0
    try:
        while True:
            snapshot = monitor.snapshot()
            event = engine.process_snapshot(snapshot)

            if event:
                risk_score, severity = risk_assessment(event["detection_reasons"])
                LOG.info(
                    "DETECTION: reasons=%s files_modified=%d locked_files=%d "
                    "ransom_note=%s risk_score=%d severity=%s",
                    ",".join(event["detection_reasons"]),
                    event["files_modified"],
                    event["locked_files"],
                    event["ransom_note_detected"],
                    risk_score,
                    severity,
                )
                if once:
                    try:
                        reporter.report(event)
                    except ReporterError as exc:
                        LOG.error(
                            "backend unreachable, gave up on this detection event: %s",
                            exc,
                        )
                else:
                    thread = threading.Thread(
                        target=_report_in_background,
                        args=(reporter, event),
                        name="detector-report",
                        daemon=True,
                    )
                    thread.start()
                    report_threads.append(thread)

            scans += 1
            if once:
                LOG.info(
                    "single scan pass complete (%s)",
                    "detection dispatched" if event else "no detection",
                )
                return 0
            if max_scans and scans >= max_scans:
                _finish_pending_reports(report_threads, reporter, interrupt=False)
                LOG.info("completed %d scan(s), exiting", scans)
                return 0
            time.sleep(config.scan_interval_seconds)
    except KeyboardInterrupt:
        _finish_pending_reports(report_threads, reporter, interrupt=True)
        LOG.info("Detector stopped")
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="RansomGuard IR VM detection agent (defensive, read-only)."
    )
    parser.add_argument(
        "--config", default=None,
        help="path to config.ini (default: config.ini next to this folder)",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="run a single scan+report pass and exit (tests/CI)",
    )
    parser.add_argument(
        "--max-scans", type=int, default=0,
        help="stop after N scan cycles (0 = run until Ctrl+C)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="log DEBUG to the console too"
    )
    args = parser.parse_args(argv)

    log_file = setup_logging(verbose=args.verbose)
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        LOG.error("startup refused: %s", exc)
        print("ERROR: %s" % (exc,), file=sys.stderr)
        return 1

    log_banner(config, once=args.once, max_scans=max(0, args.max_scans),
               log_file=log_file)
    try:
        return run(config, once=args.once, max_scans=max(0, args.max_scans))
    except KeyboardInterrupt:
        LOG.info("Detector stopped")
        return 0


if __name__ == "__main__":
    sys.exit(main())
