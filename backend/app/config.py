"""Environment-driven configuration for RansomGuard IR.

All values are read lazily (at call time) so tests can override them with
environment variables after the module has been imported.
"""

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent

DEFAULT_DB_FILENAME = "ransomguard.db"
DEFAULT_COOLDOWN_SECONDS = 300
DEFAULT_PORT = 8000


def db_path() -> Path:
    """SQLite database file location (env: RANSOMGUARD_DB_PATH)."""
    raw = os.getenv("RANSOMGUARD_DB_PATH", "")
    return Path(raw) if raw else BACKEND_DIR / DEFAULT_DB_FILENAME


def evidence_storage_dir() -> Path:
    """Root folder for stored forensic artifacts (env: RANSOMGUARD_EVIDENCE_DIR)."""
    raw = os.getenv("RANSOMGUARD_EVIDENCE_DIR", "")
    return Path(raw) if raw else BACKEND_DIR / "evidence_storage"


def detection_cooldown_seconds() -> int:
    """Per-host duplicate-detection cooldown window (env: DETECTION_COOLDOWN_SECONDS)."""
    raw = os.getenv("DETECTION_COOLDOWN_SECONDS", str(DEFAULT_COOLDOWN_SECONDS))
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_COOLDOWN_SECONDS


def host() -> str:
    """Bind address (env: HOST)."""
    return os.getenv("HOST", "0.0.0.0")


def port() -> int:
    """Bind port (env: PORT)."""
    raw = os.getenv("PORT", str(DEFAULT_PORT))
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_PORT


def cors_origins() -> list[str]:
    """Allowed CORS origins (env: CORS_ORIGINS, comma-separated; default: any)."""
    raw = os.getenv("CORS_ORIGINS", "*")
    origins = [origin.strip() for origin in raw.split(",") if origin.strip()]
    return origins or ["*"]
