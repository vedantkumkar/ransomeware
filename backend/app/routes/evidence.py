"""Evidence routes."""

from fastapi import APIRouter

from .. import db, serializers
from ..schemas import EvidenceItemOut

router = APIRouter(prefix="/api")


@router.get("/evidence", response_model=list[EvidenceItemOut])
def list_evidence() -> list[EvidenceItemOut]:
    conn = db.get_connection()
    rows = db.fetch_all(conn, "SELECT * FROM evidence ORDER BY id")
    return [serializers.evidence_from_row(row) for row in rows]
