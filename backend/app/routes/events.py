"""Detection event ingestion (vm-agent -> backend)."""

from fastapi import APIRouter

from ..schemas import DetectionEventIn, DetectionIngestionResult
from ..services.orchestrator import orchestrator

router = APIRouter(prefix="/api")


@router.post("/events/detection", response_model=DetectionIngestionResult)
def ingest_detection_event(event: DetectionEventIn) -> DetectionIngestionResult:
    """Ingest a detection event, run the risk engine and the automated
    orchestrator (with per-hostname duplicate protection)."""
    return orchestrator.process_detection(event)
