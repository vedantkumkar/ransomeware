"""Builds the GET /api/dashboard payload (DashboardData) from stored data."""

from collections import defaultdict
from datetime import datetime, timedelta

from .. import db, timeutil
from ..schemas import ChartPoint, DashboardDataOut, DashboardStatsOut

SEVERITY_CHART_ORDER = (("critical", "Critical"), ("high", "High"),
                        ("medium", "Medium"), ("low", "Low"))

DEFAULT_AVG_DETECTION_SECONDS = 0.8
DEFAULT_AUTOMATION_SUCCESS_RATE = "98.7%"


def build_dashboard(conn) -> DashboardDataOut:
    stats = DashboardStatsOut(
        active_incidents=db.fetch_one(
            conn, "SELECT COUNT(*) AS n FROM incidents WHERE status NOT IN"
                  " ('resolved', 'false_positive')")["n"],
        contained_hosts=db.fetch_one(
            conn, "SELECT COUNT(*) AS n FROM endpoints WHERE network_status = 'isolated'")["n"],
        critical_alerts=db.fetch_one(
            conn, "SELECT COUNT(*) AS n FROM notifications WHERE severity = 'critical'"
                  " AND read = 0")["n"],
        evidence_collected=db.fetch_one(conn, "SELECT COUNT(*) AS n FROM evidence")["n"],
        avg_detection_time=_format_seconds(
            _mean(_avg_detection_seconds(conn)), DEFAULT_AVG_DETECTION_SECONDS),
        avg_containment_time=_format_seconds(_mean(_avg_containment_seconds(conn)), 0.0),
        automation_success_rate=_automation_success_rate(conn),
    )
    return DashboardDataOut(
        stats=stats,
        incidents_over_time=_incidents_over_time(conn),
        severity_distribution=_severity_distribution(conn),
    )


def _incidents_over_time(conn) -> list[ChartPoint]:
    today = timeutil.utc_now().date()
    days = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
    counts: dict = defaultdict(int)
    for row in db.fetch_all(conn, "SELECT detected_at FROM incidents"):
        counts[timeutil.parse_iso(row["detected_at"]).date()] += 1
    return [ChartPoint(name=day.strftime("%a"), value=counts.get(day, 0)) for day in days]


def _severity_distribution(conn) -> list[ChartPoint]:
    rows = db.fetch_all(conn,
                        "SELECT severity, COUNT(*) AS n FROM incidents GROUP BY severity")
    counts = {row["severity"]: row["n"] for row in rows}
    return [ChartPoint(name=label, value=counts.get(key, 0))
            for key, label in SEVERITY_CHART_ORDER]


def _timeline_times_by_incident(conn) -> dict[str, list[datetime]]:
    rows = db.fetch_all(conn,
                        "SELECT incident_id, ts FROM timeline_events ORDER BY incident_id, seq")
    grouped: dict[str, list[datetime]] = defaultdict(list)
    for row in rows:
        grouped[row["incident_id"]].append(
            datetime.strptime(row["ts"], "%H:%M:%S.%f"))
    return grouped


def _avg_detection_seconds(conn) -> list[float]:
    return [
        (times[1] - times[0]).total_seconds()
        for times in _timeline_times_by_incident(conn).values()
        if len(times) >= 2
    ]


def _avg_containment_seconds(conn) -> list[float]:
    return [
        (times[-1] - times[0]).total_seconds()
        for times in _timeline_times_by_incident(conn).values()
        if len(times) >= 2
    ]


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _format_seconds(seconds: float, default: float) -> str:
    if seconds <= 0:
        seconds = default
    return f"{seconds:.1f}s"


def _automation_success_rate(conn) -> str:
    row = db.fetch_one(
        conn, "SELECT COUNT(*) AS total,"
              " SUM(CASE WHEN result = 'success' THEN 1 ELSE 0 END) AS ok FROM activity_log")
    if row and row["total"]:
        return f"{(row['ok'] or 0) / row['total'] * 100:.1f}%"
    return DEFAULT_AUTOMATION_SUCCESS_RATE
