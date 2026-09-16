"""Deterministic risk engine (no ML) — shared/CONTRACTS.md section 2.

Points:
    rapid_file_modification   +30  (display: Rapid File Changes)
    locked_extension_activity +30  (display: Locked Extensions)
    ransom_note_detected      +25  (display: Ransom Note)
    suspicious_process        +11  (display: Suspicious Process)
Total capped at 100. Expected demo score: 96 -> critical.
Severity: 0-39 low, 40-59 medium, 60-84 high, 85-100 critical.
"""

from dataclasses import dataclass, field

REASON_POINTS = {
    "rapid_file_modification": 30,
    "locked_extension_activity": 30,
    "ransom_note_detected": 25,
    "suspicious_process": 11,
}

ALLOWED_DETECTION_REASONS = frozenset(REASON_POINTS)

# Fixed order used for riskBreakdown in API responses.
CANONICAL_ORDER = (
    "rapid_file_modification",
    "locked_extension_activity",
    "ransom_note_detected",
    "suspicious_process",
)

REASON_LABELS = {
    "rapid_file_modification": "Rapid File Changes",
    "locked_extension_activity": "Locked Extensions",
    "ransom_note_detected": "Ransom Note",
    "suspicious_process": "Suspicious Process",
}

REASON_DESCRIPTIONS = {
    "rapid_file_modification": "Rapid file modification detected",
    "locked_extension_activity": "Multiple .locked extensions created",
    "ransom_note_detected": "Ransom note creation detected",
    "suspicious_process": "Abnormal file activity threshold exceeded",
}


@dataclass
class RiskAssessment:
    score: int
    severity: str
    breakdown: list[dict] = field(default_factory=list)
    reasons_display: list[str] = field(default_factory=list)


def _severity_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def assess(detection_reasons: list[str]) -> RiskAssessment:
    """Score a detection event and produce display-ready breakdowns."""
    raw = sum(REASON_POINTS.get(code, 0) for code in detection_reasons)
    score = min(100, raw)
    breakdown = [
        {"label": REASON_LABELS[code], "value": REASON_POINTS[code]}
        for code in CANONICAL_ORDER
        if code in detection_reasons
    ]
    reasons_display = [
        REASON_DESCRIPTIONS.get(code, code) for code in detection_reasons
    ]
    return RiskAssessment(
        score=score,
        severity=_severity_for(score),
        breakdown=breakdown,
        reasons_display=reasons_display,
    )
