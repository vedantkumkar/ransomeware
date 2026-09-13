"""Time formatting/parsing helpers matching the shared contract formats.

Formats (see shared/CONTRACTS.md):
- Incident.detectedAt / ActivityLogEntry.timestamp / EvidenceItem.collectedAt
  -> full ISO with Z suffix, e.g. "2026-08-29T10:32:01.124000Z"
- TimelineEvent.timestamp -> "HH:MM:SS.mmm" time-of-day string
- Alert.timestamp -> short display string, e.g. "10:32 AM"
"""

from datetime import datetime, timezone


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(dt: datetime) -> str:
    """Full ISO-8601 UTC string with Z suffix and microseconds."""
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def parse_iso(value: str | None) -> datetime:
    """Parse an ISO-8601 string; falls back to now when missing/invalid."""
    if not value:
        return utc_now()
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return utc_now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def time_of_day(dt: datetime) -> str:
    """Timeline timestamp: 'HH:MM:SS.mmm'."""
    return f"{dt:%H:%M:%S}.{dt.microsecond // 1000:03d}"


def short_time(dt: datetime) -> str:
    """Notification display timestamp: '10:32 AM'."""
    text = f"{dt:%I:%M %p}"
    return text[1:] if text.startswith("0") else text


def human_size(num_bytes: int) -> str:
    """Human-readable size string, e.g. '924 B' or '2.4 MB'."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
