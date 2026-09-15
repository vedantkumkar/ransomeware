"""System routes: health, dashboard, activity log, notifications."""

from fastapi import APIRouter

from .. import db, serializers
from ..schemas import ActivityLogEntryOut, AlertOut, DashboardDataOut, HealthStatus
from ..services.dashboard import build_dashboard

router = APIRouter(prefix="/api")


@router.get("/health", response_model=HealthStatus)
def health() -> HealthStatus:
    return HealthStatus(status="ok")


@router.get("/dashboard", response_model=DashboardDataOut)
def dashboard() -> DashboardDataOut:
    conn = db.get_connection()
    return build_dashboard(conn)


@router.get("/activity", response_model=list[ActivityLogEntryOut])
def activity_log() -> list[ActivityLogEntryOut]:
    conn = db.get_connection()
    rows = db.fetch_all(conn, "SELECT * FROM activity_log ORDER BY seq DESC")
    return [serializers.activity_from_row(row) for row in rows]


@router.get("/notifications", response_model=list[AlertOut])
def notifications() -> list[AlertOut]:
    conn = db.get_connection()
    rows = db.fetch_all(conn, "SELECT * FROM notifications ORDER BY seq DESC")
    return [serializers.alert_from_row(row) for row in rows]
