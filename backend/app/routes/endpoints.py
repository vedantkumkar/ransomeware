"""Endpoint registry routes."""

from fastapi import APIRouter, HTTPException

from .. import db, serializers
from ..schemas import EndpointOut

router = APIRouter(prefix="/api")


@router.get("/endpoints", response_model=list[EndpointOut])
def list_endpoints() -> list[EndpointOut]:
    conn = db.get_connection()
    rows = db.fetch_all(conn, "SELECT * FROM endpoints ORDER BY hostname")
    return [serializers.endpoint_from_row(row) for row in rows]


@router.get("/endpoints/{endpoint_id}", response_model=EndpointOut)
def get_endpoint(endpoint_id: str) -> EndpointOut:
    conn = db.get_connection()
    row = db.fetch_one(conn, "SELECT * FROM endpoints WHERE id = ?", (endpoint_id,))
    if row is None:
        raise HTTPException(status_code=404, detail=f"Endpoint {endpoint_id} not found")
    return serializers.endpoint_from_row(row)
