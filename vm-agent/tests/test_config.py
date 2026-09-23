"""Config loading and SAFETY BOUNDARY validation tests."""

import os

import pytest

from detector.config import (
    DEMO_MONITOR_DIR,
    ConfigError,
    load_config,
    validate_demo_dir,
    validate_test_dir,
)


class TestDemoDirBoundary:
    def test_default_config_uses_demo_dir(self):
        config = load_config()
        assert os.path.normcase(config.monitor_dir) == os.path.normcase(DEMO_MONITOR_DIR)
        assert config.monitor_dir_is_test is False

    def test_case_variant_of_demo_dir_accepted(self, monkeypatch):
        monkeypatch.setenv("VM_AGENT_MONITOR_DIR", r"c:\ransomwaredemo\TESTFILES")
        config = load_config()
        assert os.path.normcase(config.monitor_dir) == os.path.normcase(DEMO_MONITOR_DIR)
        assert config.monitor_dir_is_test is False

    def test_validate_demo_dir_accepts_forward_slashes(self):
        resolved = validate_demo_dir("C:/ransomwaredemo/testfiles")
        assert os.path.normcase(resolved) == os.path.normcase(DEMO_MONITOR_DIR)

    @pytest.mark.parametrize(
        "bad",
        [
            r"C:\Users\Public",
            r"C:\RansomwareDemo",  # parent, not the demo dir itself
            r"C:\RansomwareDemo\TestFiles\sub",
            r"D:\RansomwareDemo\TestFiles",
        ],
    )
    def test_any_other_path_refused(self, monkeypatch, bad):
        monkeypatch.setenv("VM_AGENT_MONITOR_DIR", bad)
        with pytest.raises(ConfigError):
            load_config()


class TestOverrideBoundary:
    @pytest.mark.parametrize(
        "bad",
        [
            "C:\\",
            "C:/",
            r"C:\Windows",
            r"C:\Windows\System32",
            r"C:\Users",
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
        ],
    )
    def test_dangerous_paths_refused(self, monkeypatch, bad):
        monkeypatch.setenv("VM_AGENT_TEST_DIR", bad)
        with pytest.raises(ConfigError):
            load_config()

    def test_home_directory_refused(self, monkeypatch):
        monkeypatch.setenv(
            "VM_AGENT_TEST_DIR", os.path.join(os.path.expanduser("~"), "agent-sandbox")
        )
        with pytest.raises(ConfigError):
            load_config()

    def test_non_temp_path_refused(self, monkeypatch):
        monkeypatch.setenv("VM_AGENT_TEST_DIR", r"C:\Definitely Not Temp\sandbox")
        with pytest.raises(ConfigError):
            load_config()

    def test_temp_root_itself_refused(self, monkeypatch):
        import tempfile

        monkeypatch.setenv("VM_AGENT_TEST_DIR", tempfile.gettempdir())
        with pytest.raises(ConfigError):
            load_config()

    def test_temp_sandbox_accepted(self, sandbox, monkeypatch):
        monkeypatch.setenv("VM_AGENT_TEST_DIR", str(sandbox))
        config = load_config()
        assert config.monitor_dir_is_test is True
        assert os.path.normcase(config.monitor_dir) == os.path.normcase(str(sandbox))

    def test_drive_root_refused_directly(self):
        with pytest.raises(ConfigError):
            validate_test_dir("C:\\")


class TestValueSources:
    def test_config_file_values_loaded(self, tmp_path):
        ini = tmp_path / "config.ini"
        ini.write_text(
            "[backend]\n"
            "url = http://127.0.0.1:9999\n"
            "[detection]\n"
            "rapid_change_threshold = 3\n"
            "[identity]\n"
            "hostname = TEST-BOX\n",
            encoding="utf-8",
        )
        config = load_config(str(ini))
        assert config.backend_url == "http://127.0.0.1:9999"
        assert config.rapid_change_threshold == 3
        assert config.hostname == "TEST-BOX"

    def test_env_overrides_config_file(self, tmp_path, monkeypatch):
        ini = tmp_path / "config.ini"
        ini.write_text(
            "[detection]\nrapid_change_threshold = 3\n", encoding="utf-8"
        )
        monkeypatch.setenv("VM_AGENT_RAPID_CHANGE_THRESHOLD", "7")
        config = load_config(str(ini))
        assert config.rapid_change_threshold == 7

    def test_missing_explicit_config_file_raises(self, tmp_path):
        with pytest.raises(ConfigError):
            load_config(str(tmp_path / "nope.ini"))

    def test_invalid_numeric_value_raises(self, tmp_path):
        ini = tmp_path / "config.ini"
        ini.write_text("[monitor]\nscan_interval_seconds = abc\n", encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(str(ini))

    def test_nonpositive_interval_raises(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VM_AGENT_SCAN_INTERVAL_SECONDS", "0")
        with pytest.raises(ConfigError):
            load_config()

    def test_invalid_max_report_attempts_raises(self, monkeypatch):
        monkeypatch.setenv("VM_AGENT_MAX_REPORT_ATTEMPTS", "zero")
        with pytest.raises(ConfigError):
            load_config()
