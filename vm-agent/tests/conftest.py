"""Shared pytest fixtures for the detector test suite."""

import os

import pytest

from detector.config import Config


@pytest.fixture(autouse=True)
def clean_agent_env(monkeypatch):
    """Remove every VM_AGENT_* variable so tests are hermetic."""
    for name in list(os.environ):
        if name.startswith("VM_AGENT_"):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture
def sandbox(tmp_path):
    """A directory inside the pytest temp tree (valid VM_AGENT_TEST_DIR target)."""
    directory = tmp_path / "sandbox"
    directory.mkdir()
    return directory


@pytest.fixture
def make_config(sandbox):
    """Build a Config pointing at the sandbox directory."""

    def _make(**overrides):
        values = dict(
            backend_url="http://127.0.0.1:1",
            monitor_dir=str(sandbox),
            monitor_dir_is_test=True,
            scan_interval_seconds=1.0,
            rapid_change_threshold=10,
            rapid_window_seconds=10.0,
            locked_files_threshold=5,
            cooldown_seconds=60.0,
            hostname="VICTIM-PC-01",
            ip_address="192.168.56.105",
            username="demo-user",
            process_name="DemoRansomware.exe",
            process_path=r"C:\RansomwareDemo\DemoRansomware.exe",
            max_report_attempts=6,
            source="<test>",
        )
        values.update(overrides)
        return Config(**values)

    return _make
