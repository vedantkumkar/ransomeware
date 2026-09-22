"""Configuration loading for the RansomGuard IR VM detection agent.

Configuration file: ``config.ini`` (INI format, see ``config.example.ini``).
It is looked up next to the vm-agent folder (or next to the frozen executable
when packaged with PyInstaller). Every value can be overridden through an
environment variable:

    VM_AGENT_BACKEND_URL            [backend] url
    VM_AGENT_MONITOR_DIR            [monitor] dir (must still be the demo dir)
    VM_AGENT_TEST_DIR               TEST-ONLY monitor dir override (temp only)
    VM_AGENT_SCAN_INTERVAL_SECONDS  [monitor] scan_interval_seconds
    VM_AGENT_RAPID_CHANGE_THRESHOLD [detection] rapid_change_threshold
    VM_AGENT_RAPID_WINDOW_SECONDS   [detection] rapid_window_seconds
    VM_AGENT_LOCKED_FILES_THRESHOLD [detection] locked_files_threshold
    VM_AGENT_COOLDOWN_SECONDS       [detection] cooldown_seconds
    VM_AGENT_HOSTNAME               [identity] hostname
    VM_AGENT_IP_ADDRESS             [identity] ip_address
    VM_AGENT_USERNAME               [identity] username
    VM_AGENT_PROCESS_NAME           [identity] process_name
    VM_AGENT_PROCESS_PATH           [identity] process_path
    VM_AGENT_MAX_REPORT_ATTEMPTS    reporter retry budget (see reporter.py)

SAFETY BOUNDARY (mandatory, enforced in this module):

* Without ``VM_AGENT_TEST_DIR`` the agent only ever monitors the exact demo
  directory ``C:\\RansomwareDemo\\TestFiles`` (case-insensitive comparison of
  the fully resolved path). Any other path raises :class:`ConfigError`.
* ``VM_AGENT_TEST_DIR`` exists for automated tests only. It is refused for
  drive roots and system directories (``C:\\Windows``, ``C:\\Users``,
  ``C:\\Program Files``, ...) and must resolve strictly *inside* the user's
  temp directory (``tempfile.gettempdir()``). Never set it in production.
"""

import configparser
import os
import sys
import tempfile
from dataclasses import dataclass

DEMO_MONITOR_DIR = r"C:\RansomwareDemo\TestFiles"
DEFAULT_BACKEND_URL = "http://192.168.56.1:8000"
DEFAULT_PROCESS_NAME = "DemoRansomware.exe"
DEFAULT_PROCESS_PATH = r"C:\RansomwareDemo\DemoRansomware.exe"

_ENV_PREFIX = "VM_AGENT_"


class ConfigError(Exception):
    """Configuration is invalid or the safety boundary is violated."""


def _resolved_normcase(path):
    """Fully resolved, case-normalized absolute path (Windows-safe compare)."""
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def validate_demo_dir(path):
    """Return the resolved path if it is exactly the demo dir, else raise."""
    resolved = os.path.realpath(os.path.abspath(path))
    if _resolved_normcase(path) != _resolved_normcase(DEMO_MONITOR_DIR):
        raise ConfigError(
            "SAFETY: monitor_dir must be exactly %r (got %r). The agent refuses "
            "to monitor any other directory; automated tests may use the "
            "VM_AGENT_TEST_DIR environment variable (temp directories only)."
            % (DEMO_MONITOR_DIR, resolved)
        )
    return resolved


_FORBIDDEN_TEST_PREFIXES = (
    r"C:\Windows",
    r"C:\Users",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\ProgramData",
)


def validate_test_dir(path):
    """Validate the VM_AGENT_TEST_DIR override for automated tests.

    Refuses drive roots, known system directories, and anything that is not
    strictly inside the user's temp directory. Returns the resolved path.
    """
    resolved = os.path.realpath(os.path.abspath(path))
    normalized = _resolved_normcase(path)

    # Allow list first: anything strictly inside the temp directory is fine,
    # even though temp itself usually lives under C:\Users.
    temp_root = _resolved_normcase(tempfile.gettempdir())
    if normalized != temp_root and normalized.startswith(temp_root + os.sep):
        return resolved

    # Not under temp: report the most specific refusal reason.
    drive, _rest = os.path.splitdrive(resolved)
    if drive and normalized == os.path.normcase(drive + os.sep):
        raise ConfigError(
            "SAFETY: VM_AGENT_TEST_DIR refuses drive roots (got %r)" % (resolved,)
        )

    for forbidden in _FORBIDDEN_TEST_PREFIXES:
        forbidden_norm = os.path.normcase(forbidden)
        if normalized == forbidden_norm or normalized.startswith(forbidden_norm + os.sep):
            raise ConfigError(
                "SAFETY: VM_AGENT_TEST_DIR refuses system directory %r (got %r)"
                % (forbidden, resolved)
            )

    raise ConfigError(
        "SAFETY: VM_AGENT_TEST_DIR must point strictly inside the temp "
        "directory %r (got %r)" % (tempfile.gettempdir(), resolved)
    )


# String defaults; numeric coercion happens in load_config().
_DEFAULTS = {
    "backend_url": DEFAULT_BACKEND_URL,
    "monitor_dir": DEMO_MONITOR_DIR,
    "scan_interval_seconds": "1.0",
    "rapid_change_threshold": "10",
    "rapid_window_seconds": "10.0",
    "locked_files_threshold": "5",
    "cooldown_seconds": "60",
    "burst_quiet_scans": "2",
    "max_burst_seconds": "30.0",
    "hostname": "VICTIM-PC-01",
    "ip_address": "192.168.56.105",
    "username": "demo-user",
    "process_name": DEFAULT_PROCESS_NAME,
    "process_path": DEFAULT_PROCESS_PATH,
}

# (ini section, ini key) -> internal field name
_INI_FIELDS = {
    ("backend", "url"): "backend_url",
    ("monitor", "dir"): "monitor_dir",
    ("monitor", "scan_interval_seconds"): "scan_interval_seconds",
    ("detection", "rapid_change_threshold"): "rapid_change_threshold",
    ("detection", "rapid_window_seconds"): "rapid_window_seconds",
    ("detection", "locked_files_threshold"): "locked_files_threshold",
    ("detection", "cooldown_seconds"): "cooldown_seconds",
    ("detection", "burst_quiet_scans"): "burst_quiet_scans",
    ("detection", "max_burst_seconds"): "max_burst_seconds",
    ("identity", "hostname"): "hostname",
    ("identity", "ip_address"): "ip_address",
    ("identity", "username"): "username",
    ("identity", "process_name"): "process_name",
    ("identity", "process_path"): "process_path",
}


@dataclass(frozen=True)
class Config:
    backend_url: str = DEFAULT_BACKEND_URL
    monitor_dir: str = DEMO_MONITOR_DIR
    monitor_dir_is_test: bool = False
    scan_interval_seconds: float = 1.0
    rapid_change_threshold: int = 10
    rapid_window_seconds: float = 10.0
    locked_files_threshold: int = 5
    cooldown_seconds: float = 60.0
    burst_quiet_scans: int = 2
    max_burst_seconds: float = 30.0
    hostname: str = "VICTIM-PC-01"
    ip_address: str = "192.168.56.105"
    username: str = "demo-user"
    process_name: str = DEFAULT_PROCESS_NAME
    process_path: str = DEFAULT_PROCESS_PATH
    max_report_attempts: int = 6
    source: str = "<defaults>"


def _candidate_config_paths(explicit):
    candidates = []
    if explicit:
        candidates.append(explicit)
    if getattr(sys, "frozen", False):  # PyInstaller onefile exe
        candidates.append(os.path.join(os.path.dirname(sys.executable), "config.ini"))
    package_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(package_parent, "config.ini"))
    return candidates


def _read_ini_file(ini_path):
    """Return {field: string value} from the INI file, or raise ConfigError."""
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parsed = parser.read(ini_path, encoding="utf-8")
    except configparser.Error as exc:
        raise ConfigError("cannot parse config file %s: %s" % (ini_path, exc))
    if not parsed:
        raise ConfigError("config file could not be read: %s" % (ini_path,))
    values = {}
    for (section, key), field in _INI_FIELDS.items():
        value = parser.get(section, key, fallback=None)
        if value is not None and value.strip() != "":
            values[field] = value.strip()
    return values


def load_config(config_path=None):
    """Load defaults <- config.ini <- environment variables, then validate."""
    values = dict(_DEFAULTS)
    source = "<defaults>"

    ini_path = None
    if config_path:
        # An explicit --config path is authoritative: no fallback.
        if not os.path.isfile(config_path):
            raise ConfigError("config file not found: %s" % (config_path,))
        ini_path = config_path
    else:
        for candidate in _candidate_config_paths(None):
            if os.path.isfile(candidate):
                ini_path = candidate
                break
    if ini_path:
        values.update(_read_ini_file(ini_path))
        source = ini_path

    # Environment overrides (highest precedence, except the test dir below).
    for field in values:
        env_value = os.environ.get(_ENV_PREFIX + field.upper())
        if env_value is not None and env_value.strip() != "":
            values[field] = env_value.strip()

    # SAFETY: resolve and validate the monitored directory first.
    test_dir = os.environ.get(_ENV_PREFIX + "TEST_DIR")
    monitor_dir_is_test = False
    if test_dir is not None and test_dir.strip() != "":
        monitor_dir = validate_test_dir(test_dir.strip())
        monitor_dir_is_test = True
        source = source + " + VM_AGENT_TEST_DIR"
    else:
        monitor_dir = validate_demo_dir(values["monitor_dir"])

    max_report_attempts = 6
    env_attempts = os.environ.get(_ENV_PREFIX + "MAX_REPORT_ATTEMPTS")
    if env_attempts is not None and env_attempts.strip() != "":
        try:
            max_report_attempts = int(env_attempts.strip())
        except ValueError:
            raise ConfigError(
                "invalid %sMAX_REPORT_ATTEMPTS: %r" % (_ENV_PREFIX, env_attempts)
            )
    if max_report_attempts < 1:
        raise ConfigError("max_report_attempts must be >= 1")

    try:
        scan_interval = float(values["scan_interval_seconds"])
        rapid_threshold = int(values["rapid_change_threshold"])
        rapid_window = float(values["rapid_window_seconds"])
        locked_threshold = int(values["locked_files_threshold"])
        cooldown = float(values["cooldown_seconds"])
        burst_quiet = int(values["burst_quiet_scans"])
        max_burst = float(values["max_burst_seconds"])
    except (KeyError, ValueError) as exc:
        raise ConfigError("invalid numeric configuration value: %s" % (exc,))

    if scan_interval <= 0:
        raise ConfigError("scan_interval_seconds must be > 0")
    if rapid_window <= 0:
        raise ConfigError("rapid_window_seconds must be > 0")
    if rapid_threshold < 0 or locked_threshold < 0:
        raise ConfigError("detection thresholds must be >= 0")
    if cooldown < 0:
        raise ConfigError("cooldown_seconds must be >= 0")
    if burst_quiet < 1:
        raise ConfigError("burst_quiet_scans must be >= 1")
    if max_burst <= 0:
        raise ConfigError("max_burst_seconds must be > 0")
    if not values["backend_url"].strip():
        raise ConfigError("backend_url must not be empty")

    return Config(
        backend_url=values["backend_url"].strip().rstrip("/"),
        monitor_dir=monitor_dir,
        monitor_dir_is_test=monitor_dir_is_test,
        scan_interval_seconds=scan_interval,
        rapid_change_threshold=rapid_threshold,
        rapid_window_seconds=rapid_window,
        locked_files_threshold=locked_threshold,
        cooldown_seconds=cooldown,
        burst_quiet_scans=burst_quiet,
        max_burst_seconds=max_burst,
        hostname=values["hostname"],
        ip_address=values["ip_address"],
        username=values["username"],
        process_name=values["process_name"],
        process_path=values["process_path"],
        max_report_attempts=max_report_attempts,
        source=source,
    )
