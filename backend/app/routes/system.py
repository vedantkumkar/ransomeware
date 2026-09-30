"""System routes: health, dashboard, activity log, notifications."""

from fastapi import APIRouter

from .. import db, serializers
from ..schemas import (
    ActivityLogEntryOut,
    AlertOut,
    DashboardDataOut,
    HealthStatus,
    NotificationReadResultOut,
)
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


def _unread_count(conn) -> int:
    row = db.fetch_one(conn, "SELECT COUNT(*) AS n FROM notifications WHERE read = 0")
    return row["n"] if row else 0


@router.post("/notifications/mark-all-read", response_model=NotificationReadResultOut)
def mark_all_notifications_read() -> NotificationReadResultOut:
    """Persist read status for every notification."""
    conn = db.get_connection()
    cursor = conn.execute("UPDATE notifications SET read = 1 WHERE read = 0")
    conn.commit()
    return NotificationReadResultOut(updated=cursor.rowcount, unread=0)


@router.post("/notifications/{notification_id}/read", response_model=NotificationReadResultOut)
def mark_notification_read(notification_id: str) -> NotificationReadResultOut:
    """Persist read status for a single notification."""
    conn = db.get_connection()
    row = db.fetch_one(conn, "SELECT seq FROM notifications WHERE id = ?", (notification_id,))
    if row is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404,
                            detail=f"Notification {notification_id} not found")
    cursor = conn.execute("UPDATE notifications SET read = 1 WHERE id = ? AND read = 0",
                          (notification_id,))
    conn.commit()
    return NotificationReadResultOut(updated=cursor.rowcount, unread=_unread_count(conn))
