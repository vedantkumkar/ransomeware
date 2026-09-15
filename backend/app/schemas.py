"""Typed request/response models (Pydantic v2).

API responses serialize with camelCase aliases (frontend TypeScript contract,
frontend/src/types/index.ts). The detection-event ingestion payload stays
snake_case per the shared contract.
"""

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .services.risk_engine import ALLOWED_DETECTION_REASONS


def to_camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(part.title() for part in rest)


class CamelModel(BaseModel):
    """Base model serializing snake_case fields as camelCase."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


# ── Shared literal types (frontend/src/types/index.ts) ───────────────────────

Severity = Literal["critical", "high", "medium", "low"]
IncidentStatus = Literal["detected", "investigating", "contained", "resolved", "false_positive"]
AgentStatus = Literal["online", "offline", "degraded"]
NetworkStatus = Literal["connected", "isolated"]
EvidenceType = Literal[
    "process_snapshot", "file_manifest", "event_logs", "memory_metadata",
    "network_metadata", "ransom_note", "detection_log",
]
TimelineEventType = Literal["detection", "analysis", "action", "notification", "success", "evidence"]
ActorType = Literal["automation", "analyst", "agent"]
ActionResultValue = Literal["success", "failed", "pending"]
EvidenceIntegrity = Literal["verified", "pending", "failed"]


# ── Ingestion (vm-agent -> backend, snake_case per contract) ─────────────────

class DetectionEventIn(BaseModel):
    """POST /api/events/detection payload (snake_case, see CONTRACTS.md section 1)."""

    event_type: Literal["ransomware_behavior"] = "ransomware_behavior"
    hostname: str
    ip_address: str = ""
    username: str = ""
    process_name: str = ""
    process_id: int = 0
    process_path: str = ""
    target_directory: str = ""
    files_modified: int = 0
    locked_files: int = 0
    ransom_note_detected: bool = False
    ransom_note_name: str = ""
    detection_reasons: list[str] = Field(default_factory=list)
    timestamp: str = ""

    @field_validator("detection_reasons")
    @classmethod
    def _validate_reason_codes(cls, value: list[str]) -> list[str]:
        unknown = [code for code in value if code not in ALLOWED_DETECTION_REASONS]
        if unknown:
            raise ValueError(f"Unknown detection reason code(s): {', '.join(unknown)}")
        return value


class DetectionIngestionResult(BaseModel):
    """Response of POST /api/events/detection (snake_case keys per contract)."""

    accepted: bool
    incident_id: str
    deduplicated: bool


# ── API response models (camelCase) ──────────────────────────────────────────

class HealthStatus(CamelModel):
    status: str


class RiskBreakdownItem(CamelModel):
    label: str
    value: int


class ThreatDetail(CamelModel):
    process: str
    pid: int
    process_path: str
    target_directory: str
    files_modified: int
    files_locked: int
    ransom_note: str
    detection_reasons: list[str]
    risk_breakdown: list[RiskBreakdownItem]


class TimelineEventOut(CamelModel):
    id: str
    timestamp: str  # "HH:MM:SS.mmm" time-of-day string
    title: str
    description: str
    type: TimelineEventType
    automated: bool


class IncidentOut(CamelModel):
    id: str
    threat_type: str
    hostname: str
    ip_address: str
    user: str
    department: str
    os: str
    severity: Severity
    risk_score: int
    status: IncidentStatus
    detected_at: str  # full ISO
    detection_engine: str
    agent_status: AgentStatus
    network_status: NetworkStatus
    threat_details: Optional[ThreatDetail] = None
    timeline: list[TimelineEventOut] = []


class EndpointOut(CamelModel):
    id: str
    hostname: str
    ip_address: str
    user: str
    os: str
    agent_status: AgentStatus
    risk_score: int
    severity: Severity | Literal["none"]
    network_status: NetworkStatus
    last_seen: str
    department: str
    incident_id: Optional[str] = None


class EvidenceItemOut(CamelModel):
    id: str
    incident_id: str
    type: EvidenceType
    source: str
    size: str
    sha256: str
    collected_at: str  # full ISO
    integrity: EvidenceIntegrity
    description: str


class ActivityLogEntryOut(CamelModel):
    id: str
    timestamp: str  # full ISO
    event: str
    actor: str
    actor_type: ActorType
    target: str
    result: ActionResultValue
    details: str


class AlertOut(CamelModel):
    id: str
    title: str
    description: str
    severity: Severity
    timestamp: str  # short display string, e.g. "10:32 AM"
    read: bool
    incident_id: Optional[str] = None


class DashboardStatsOut(CamelModel):
    active_incidents: int
    contained_hosts: int
    critical_alerts: int
    evidence_collected: int
    avg_detection_time: str
    avg_containment_time: str
    automation_success_rate: str


class ChartPoint(CamelModel):
    name: str
    value: int


class DashboardDataOut(CamelModel):
    stats: DashboardStatsOut
    incidents_over_time: list[ChartPoint]
    severity_distribution: list[ChartPoint]


class ActionResultOut(CamelModel):
    success: bool
    message: str
