"""Incident routes: list, detail, timeline, evidence, analyst actions."""

from fastapi import APIRouter, HTTPException

from .. import db, serializers
from ..schemas import (
    ActionResultOut,
    EvidenceItemOut,
    IncidentOut,
    ManualCollectionIn,
    TimelineEventOut,
)
from ..services.containment import ContainmentService
from ..services.evidence_service import CollectionError, EvidenceCollectionService
from ..services.identity import IdentityResponseService
from ..services.incident_state import IncidentStateService

router = APIRouter(prefix="/api")

containment = ContainmentService()
identity = IdentityResponseService()
evidence_service = EvidenceCollectionService()
incident_state = IncidentStateService()

ANALYST = "SOC Analyst"


def _require_incident(conn, incident_id: str):
    incident = db.fetch_one(conn, "SELECT * FROM incidents WHERE id = ?", (incident_id,))
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


def _incident_with_timeline(conn, row) -> IncidentOut:
    timeline_rows = db.fetch_all(
        conn, "SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY seq",
        (row["id"],))
    return serializers.incident_from_row(row, timeline_rows)


# ── Reads ────────────────────────────────────────────────────────────────────

@router.get("/incidents", response_model=list[IncidentOut])
def list_incidents() -> list[IncidentOut]:
    conn = db.get_connection()
    rows = db.fetch_all(conn, "SELECT * FROM incidents ORDER BY detected_at DESC, id DESC")
    return [_incident_with_timeline(conn, row) for row in rows]


@router.get("/incidents/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str) -> IncidentOut:
    conn = db.get_connection()
    row = _require_incident(conn, incident_id)
    return _incident_with_timeline(conn, row)


@router.get("/incidents/{incident_id}/timeline", response_model=list[TimelineEventOut])
def get_incident_timeline(incident_id: str) -> list[TimelineEventOut]:
    conn = db.get_connection()
    _require_incident(conn, incident_id)
    rows = db.fetch_all(conn, "SELECT * FROM timeline_events WHERE incident_id = ? ORDER BY seq",
                        (incident_id,))
    return [serializers.timeline_from_row(row) for row in rows]


@router.get("/incidents/{incident_id}/evidence", response_model=list[EvidenceItemOut])
def get_incident_evidence(incident_id: str) -> list[EvidenceItemOut]:
    conn = db.get_connection()
    _require_incident(conn, incident_id)
    rows = db.fetch_all(conn, "SELECT * FROM evidence WHERE incident_id = ? ORDER BY id",
                        (incident_id,))
    return [serializers.evidence_from_row(row) for row in rows]


# ── Analyst actions ──────────────────────────────────────────────────────────

@router.post("/incidents/{incident_id}/isolate", response_model=ActionResultOut)
def isolate_host(incident_id: str) -> ActionResultOut:
    conn = db.get_connection()
    incident = _require_incident(conn, incident_id)
    containment.isolate(conn, incident, automated=False, actor=ANALYST)
    return ActionResultOut(success=True,
                           message=f"Host isolation simulated for {incident['hostname']}")


@router.post("/incidents/{incident_id}/release", response_model=ActionResultOut)
def release_host(incident_id: str) -> ActionResultOut:
    conn = db.get_connection()
    incident = _require_incident(conn, incident_id)
    containment.release(conn, incident, actor=ANALYST)
    return ActionResultOut(success=True,
                           message=f"Host release simulated successfully for {incident['hostname']}")


@router.post("/incidents/{incident_id}/suspend-user", response_model=ActionResultOut)
def suspend_user(incident_id: str) -> ActionResultOut:
    conn = db.get_connection()
    incident = _require_incident(conn, incident_id)
    identity.suspend(conn, incident, automated=False, actor=ANALYST)
    return ActionResultOut(success=True,
                           message=f"User suspension simulated for {incident['username'] or 'unknown-user'}")


@router.post("/incidents/{incident_id}/collect-evidence", response_model=ActionResultOut)
def collect_evidence(incident_id: str,
                     request: ManualCollectionIn | None = None) -> ActionResultOut:
    """Manual evidence collection. Creates a REAL artifact from a real source,
    hashes it, records chain-of-custody, and adds a MANUAL timeline entry.
    Fails with 400 (no record created) when the source cannot be read."""
    conn = db.get_connection()
    incident = _require_incident(conn, incident_id)
    body = request or ManualCollectionIn()
    try:
        evidence_id = evidence_service.collect_manual(
            conn, incident, body.evidence_type, actor=ANALYST,
            text_content=body.content)
    except CollectionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return ActionResultOut(success=True,
                           message=f"Evidence {evidence_id} collected for {incident_id}")


@router.post("/incidents/{incident_id}/false-positive", response_model=ActionResultOut)
def mark_false_positive(incident_id: str) -> ActionResultOut:
    conn = db.get_connection()
    incident = _require_incident(conn, incident_id)
    incident_state.mark_false_positive(conn, incident, actor=ANALYST)
    return ActionResultOut(success=True, message=f"{incident_id} marked as false positive")


@router.post("/incidents/{incident_id}/close", response_model=ActionResultOut)
def close_incident(incident_id: str) -> ActionResultOut:
    conn = db.get_connection()
    incident = _require_incident(conn, incident_id)
    incident_state.close(conn, incident, actor=ANALYST)
    return ActionResultOut(success=True, message=f"{incident_id} closed successfully")
