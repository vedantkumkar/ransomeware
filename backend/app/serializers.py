"""Row-to-model serializers for API responses (camelCase output)."""

import json
import sqlite3

from .schemas import (
    AlertOut,
    ActivityLogEntryOut,
    CustodyEntryOut,
    EndpointOut,
    EvidenceItemOut,
    IncidentOut,
    ThreatDetail,
    TimelineEventOut,
)


def timeline_from_row(row: sqlite3.Row) -> TimelineEventOut:
    return TimelineEventOut(
        id=row["id"],
        timestamp=row["ts"],
        title=row["title"],
        description=row["description"],
        type=row["type"],
        automated=bool(row["automated"]),
    )


def _threat_details_from_row(row: sqlite3.Row) -> ThreatDetail | None:
    if not row["threat_details"]:
        return None
    return ThreatDetail.model_validate(json.loads(row["threat_details"]))


def incident_from_row(row: sqlite3.Row, timeline_rows: list[sqlite3.Row]) -> IncidentOut:
    return IncidentOut(
        id=row["id"],
        threat_type=row["threat_type"],
        hostname=row["hostname"],
        ip_address=row["ip_address"],
        user=row["username"],
        department=row["department"],
        os=row["os"],
        severity=row["severity"],
        risk_score=row["risk_score"],
        status=row["status"],
        detected_at=row["detected_at"],
        detection_engine=row["detection_engine"],
        agent_status=row["agent_status"],
        network_status=row["network_status"],
        threat_details=_threat_details_from_row(row),
        timeline=[timeline_from_row(t) for t in timeline_rows],
    )


def endpoint_from_row(row: sqlite3.Row) -> EndpointOut:
    return EndpointOut(
        id=row["id"],
        hostname=row["hostname"],
        ip_address=row["ip_address"],
        user=row["username"],
        os=row["os"],
        agent_status=row["agent_status"],
        risk_score=row["risk_score"],
        severity=row["severity"],
        network_status=row["network_status"],
        last_seen=row["last_seen"],
        department=row["department"],
        incident_id=row["incident_id"],
    )


def evidence_from_row(row: sqlite3.Row) -> EvidenceItemOut:
    storage_path = row["storage_path"] if "storage_path" in row.keys() else ""
    return EvidenceItemOut(
        id=row["id"],
        incident_id=row["incident_id"],
        type=row["type"],
        source=row["source"],
        size=row["size"],
        sha256=row["sha256"],
        collected_at=row["collected_at"],
        integrity=row["integrity"],
        description=row["description"],
        artifact_name=row["artifact_name"] if "artifact_name" in row.keys() else "",
        mime_type=row["mime_type"] if "mime_type" in row.keys() else "",
        collection_method=row["collection_method"] if "collection_method" in row.keys() else "automated",
        collected_by=row["collected_by"] if "collected_by" in row.keys() else "",
        size_bytes=row["size_bytes"] if "size_bytes" in row.keys() else 0,
        has_artifact=bool(storage_path),
    )


def custody_from_row(row: sqlite3.Row) -> CustodyEntryOut:
    return CustodyEntryOut(
        timestamp=row["timestamp"],
        action=row["action"],
        actor=row["actor"],
        detail=row["detail"],
    )


def activity_from_row(row: sqlite3.Row) -> ActivityLogEntryOut:
    return ActivityLogEntryOut(
        id=row["id"],
        timestamp=row["timestamp"],
        event=row["event"],
        actor=row["actor"],
        actor_type=row["actor_type"],
        target=row["target"],
        result=row["result"],
        details=row["details"],
    )


def alert_from_row(row: sqlite3.Row) -> AlertOut:
    return AlertOut(
        id=row["id"],
        title=row["title"],
        description=row["description"],
        severity=row["severity"],
        timestamp=row["timestamp"],
        read=bool(row["read"]),
        incident_id=row["incident_id"],
    )
