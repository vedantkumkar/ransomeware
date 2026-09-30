"""Evidence routes: list, detail, artifact inspection, integrity verification."""

from fastapi import APIRouter, HTTPException

from .. import db, serializers
from ..schemas import (
    ArtifactContentOut,
    EvidenceDetailOut,
    EvidenceItemOut,
    IntegrityVerificationOut,
)
from ..services.evidence_service import EvidenceCollectionService

router = APIRouter(prefix="/api")

evidence_service = EvidenceCollectionService()


def _require_evidence(conn, evidence_id: str):
    row = db.fetch_one(conn, "SELECT * FROM evidence WHERE id = ?", (evidence_id,))
    if row is None:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")
    return row


@router.get("/evidence", response_model=list[EvidenceItemOut])
def list_evidence() -> list[EvidenceItemOut]:
    conn = db.get_connection()
    rows = db.fetch_all(conn, "SELECT * FROM evidence ORDER BY id")
    return [serializers.evidence_from_row(row) for row in rows]


@router.get("/evidence/{evidence_id}", response_model=EvidenceDetailOut)
def get_evidence(evidence_id: str) -> EvidenceDetailOut:
    conn = db.get_connection()
    row = _require_evidence(conn, evidence_id)
    item = serializers.evidence_from_row(row)
    custody_rows = db.fetch_all(
        conn, "SELECT * FROM evidence_custody WHERE evidence_id = ? ORDER BY seq",
        (evidence_id,))
    return EvidenceDetailOut(**item.model_dump(), custody=[
        serializers.custody_from_row(c) for c in custody_rows])


@router.get("/evidence/{evidence_id}/artifact", response_model=ArtifactContentOut)
def get_evidence_artifact(evidence_id: str) -> ArtifactContentOut:
    conn = db.get_connection()
    row = _require_evidence(conn, evidence_id)
    try:
        artifact = evidence_service.read_artifact(row)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return ArtifactContentOut(**artifact)


@router.post("/evidence/{evidence_id}/verify", response_model=IntegrityVerificationOut)
def verify_evidence(evidence_id: str) -> IntegrityVerificationOut:
    """Recalculate SHA-256 from the stored artifact and compare with the
    recorded hash. Persists the new integrity state and a custody entry."""
    conn = db.get_connection()
    _require_evidence(conn, evidence_id)
    _, status, message = evidence_service.verify_integrity(conn, evidence_id)
    return IntegrityVerificationOut(evidence_id=evidence_id, integrity=status, message=message)
