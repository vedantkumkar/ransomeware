"""Row-to-model serializers for API responses (camelCase output)."""

import json
import sqlite3

from .schemas import (
    AlertOut,
    ActivityLogEntryOut,
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
