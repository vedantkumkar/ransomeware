"""Reporter tests against a local http.server, plus the backoff path."""

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from detector.reporter import Reporter, ReporterError

EVENT = {
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
    "detection_reasons": ["rapid_file_modification", "locked_extension_activity"],
    "timestamp": "2026-08-29T10:32:01.124Z",
}


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        server = self.server
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        server.received.append(
            (self.path, self.headers.get("Content-Type"), json.loads(body))
        )
        if getattr(server, "failures_remaining", 0) > 0:
            server.failures_remaining -= 1
            payload = json.dumps({"detail": "simulated backend error"}).encode()
            self.send_response(500)
        else:
            payload = json.dumps(
                {"accepted": True, "incident_id": "RAN-2026-001", "deduplicated": False}
            ).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence test output
        pass


@pytest.fixture
def test_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.received = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_report_success_posts_contract_payload(test_server):
    reporter = Reporter("http://127.0.0.1:%d" % server_port(test_server))
    result = reporter.report(EVENT)

    assert result.accepted is True
    assert result.incident_id == "RAN-2026-001"
    assert result.deduplicated is False

    path, content_type, body = test_server.received[0]
    assert path == "/api/events/detection"
    assert content_type == "application/json"
    assert body == EVENT  # exactly the payload the agent built


def test_report_retries_on_http_500_then_succeeds(test_server):
    test_server.failures_remaining = 2
    reporter = Reporter(
        "http://127.0.0.1:%d" % server_port(test_server),
        backoff=(0.01, 0.01, 0.01),
        sleep=lambda _seconds: None,
    )
    result = reporter.report(EVENT)
    assert result.accepted is True
    assert len(test_server.received) == 3  # 2 failures + 1 success


def test_report_connection_refused_runs_backoff_without_crashing():
    sleeps = []
    reporter = Reporter(_refused_url(), backoff=(2.0, 4.0), sleep=sleeps.append)
    with pytest.raises(ReporterError):
        reporter.report(EVENT)
    # 3 attempts (initial + 2 retries), sleeping the backoff schedule in order.
    assert sleeps == [2.0, 4.0]


def test_trailing_slash_backend_url_still_hits_endpoint(test_server):
    reporter = Reporter("http://127.0.0.1:%d/" % server_port(test_server))
    reporter.report(EVENT)
    assert test_server.received[0][0] == "/api/events/detection"


# --- helpers ---------------------------------------------------------------

def server_port(server):
    return server.server_address[1]


def _refused_url():
    """Grab a free port, close it, and return a URL that refuses connections."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return "http://127.0.0.1:%d" % port
