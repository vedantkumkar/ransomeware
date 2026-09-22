"""HTTP reporting of detection events with retry/backoff.

Python stdlib only: ``urllib.request``. The backend endpoint is
``POST {backend_url}/api/events/detection`` (shared/CONTRACTS.md section 1)
and answers ``200 {"accepted": true, "incident_id": ..., "deduplicated": ...}``.
"""

import json
import logging
import time
import urllib.error
import urllib.request

log = logging.getLogger("detector.reporter")

DETECTION_PATH = "/api/events/detection"
DEFAULT_BACKOFF_SCHEDULE = (2.0, 4.0, 8.0, 16.0, 32.0, 60.0)
DEFAULT_TIMEOUT_SECONDS = 5.0


class ReporterError(RuntimeError):
    """The detection event could not be delivered after all retries."""


class ReportResult:
    """Parsed backend acknowledgement."""

    __slots__ = ("accepted", "incident_id", "deduplicated", "status_code")

    def __init__(self, accepted, incident_id, deduplicated, status_code):
        self.accepted = accepted
        self.incident_id = incident_id
        self.deduplicated = deduplicated
        self.status_code = status_code

    def __repr__(self):
        return "ReportResult(accepted=%r, incident_id=%r, deduplicated=%r)" % (
            self.accepted, self.incident_id, self.deduplicated,
        )


class Reporter:
    """POSTs detection events with exponential backoff retries."""

    def __init__(self, backend_url, timeout=DEFAULT_TIMEOUT_SECONDS,
                 backoff=DEFAULT_BACKOFF_SCHEDULE, sleep=time.sleep,
                 max_attempts=None):
        self.backend_url = backend_url.rstrip("/")
        self.url = self.backend_url + DETECTION_PATH
        self.timeout = timeout
        self.backoff = tuple(float(x) for x in backoff) or (0.0,)
        self.sleep = sleep
        # Default: 1 initial try + one retry per backoff step.
        self.max_attempts = (
            max_attempts if max_attempts and max_attempts > 0
            else len(self.backoff) + 1
        )

    def report(self, event):
        """Deliver ``event``; return ReportResult or raise ReporterError."""
        payload = json.dumps(event).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json",
                     "Accept": "application/json"},
            method="POST",
        )
        last_error = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = response.read()
                data = json.loads(body.decode("utf-8")) if body else {}
                result = ReportResult(
                    accepted=bool(data.get("accepted", False)),
                    incident_id=str(data.get("incident_id", "")),
                    deduplicated=bool(data.get("deduplicated", False)),
                    status_code=200,
                )
                # deduplicated=true is just logged: the backend folded the
                # event into an existing active incident, nothing to redo.
                log.info(
                    "Detection reported: incident_id=%s accepted=%s deduplicated=%s",
                    result.incident_id or "-", result.accepted, result.deduplicated,
                )
                return result
            except urllib.error.HTTPError as exc:
                last_error = exc
                detail = ""
                try:
                    detail = exc.read(500).decode("utf-8", "replace").strip()
                except OSError:
                    pass
                log.warning(
                    "report attempt %d/%d: backend returned HTTP %s %s",
                    attempt, self.max_attempts, exc.code, detail,
                )
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last_error = exc
                log.warning(
                    "report attempt %d/%d failed: %s",
                    attempt, self.max_attempts, exc,
                )
            if attempt < self.max_attempts:
                delay = self.backoff[min(attempt - 1, len(self.backoff) - 1)]
                log.info("backend unreachable, retrying in %.0fs", delay)
                self.sleep(delay)
        raise ReporterError(
            "could not report detection to %s after %d attempts: %s"
            % (self.url, self.max_attempts, last_error)
        )
