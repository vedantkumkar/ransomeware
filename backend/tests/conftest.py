"""Pytest fixtures: isolated temp DB + evidence dir per test."""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """TestClient backed by a per-test temp SQLite DB and evidence folder."""
    monkeypatch.setenv("RANSOMGUARD_DB_PATH", str(tmp_path / "test-ransomguard.db"))
    monkeypatch.setenv("RANSOMGUARD_EVIDENCE_DIR", str(tmp_path / "evidence_storage"))

    from app.db import reset_connection
    from app.main import app

    reset_connection()
    with TestClient(app) as test_client:
        yield test_client
    reset_connection()
