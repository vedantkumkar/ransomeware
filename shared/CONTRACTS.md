# RansomGuard IR — Shared Contracts

Single source of truth for data exchanged between components.
`backend/`, `vm-agent/`, and `simulator/` must all conform to this document.

All JSON field names are **camelCase** in API responses (frontend TypeScript contract)
and **snake_case** in the detection event ingestion payload (backend internal contract).

## 1. Detection Event — `POST /api/events/detection` (vm-agent → backend)

```json
{
  "event_type": "ransomware_behavior",
  "hostname": "VICTIM-PC-01",
  "ip_address": "192.168.56.105",
  "username": "demo-user",
  "process_name": "DemoRansomware.exe",
  "process_id": 4824,
  "process_path": "C:\\RansomwareDemo\\DemoRansomware.exe",
  "target_directory": "C:\\RansomwareDemo\\TestFiles",
  "files_modified": 37,
  "locked_files": 32,
  "ransom_note_detected": true,
  "ransom_note_name": "README_RESTORE_FILES.txt",
  "detection_reasons": [
    "rapid_file_modification",
    "locked_extension_activity",
    "ransom_note_detected",
    "suspicious_process"
  ],
  "timestamp": "2026-08-29T10:32:01.124Z"
}
```

`detection_reasons` allowed codes:
`rapid_file_modification`, `locked_extension_activity`, `ransom_note_detected`, `suspicious_process`

Response: `200` with `{"accepted": true, "incident_id": "RAN-2026-001", "deduplicated": false}`
(or `deduplicated: true` when folded into an existing active incident).

## 2. Risk Engine (backend, deterministic — no ML)

| Reason code | Points | Display label (riskBreakdown) |
|---|---|---|
| `rapid_file_modification` | +30 | Rapid File Changes |
| `locked_extension_activity` | +30 | Locked Extensions |
| `ransom_note_detected` | +25 | Ransom Note |
| `suspicious_process` | +11 | Suspicious Process |

Cap at 100. Expected demo score: **96**.
Severity: 0–39 low, 40–59 medium, 60–84 high, 85–100 critical.

Human-readable detection reasons (displayed in UI):
- `rapid_file_modification` → "Rapid file modification detected"
- `locked_extension_activity` → "Multiple .locked extensions created"
- `ransom_note_detected` → "Ransom note creation detected"
- `suspicious_process` → "Abnormal file activity threshold exceeded"

## 3. API Response Shapes (backend → frontend, all camelCase)

Frontend TypeScript source of truth: `frontend/src/types/index.ts`. Key shapes:

```ts
// GET /api/health
{ "status": "ok" }

// GET /api/dashboard  → DashboardData
{
  "stats": {                       // DashboardStats
    "activeIncidents": 1,          // status not resolved/false_positive
    "containedHosts": 7,           // endpoints with networkStatus "isolated"
    "criticalAlerts": 3,           // unread critical notifications
    "evidenceCollected": 24,       // total evidence records
    "avgDetectionTime": "1.2s",    // display string
    "avgContainmentTime": "3.4s",  // display string
    "automationSuccessRate": "98.7%"
  },
  "incidentsOverTime":     [{ "name": "Mon", "value": 2 }, ...],  // last 7 days
  "severityDistribution":  [{ "name": "Critical", "value": 3 }, ...]
}

// GET /api/incidents → Incident[]
// GET /api/incidents/{id} → Incident | 404
{
  "id": "RAN-2026-001",            // RAN-<year>-<NNN>, sequential
  "threatType": "Ransomware Behavior",
  "hostname": "VICTIM-PC-01",
  "ipAddress": "192.168.56.105",
  "user": "demo-user",
  "department": "Demo Lab",
  "os": "Windows 11 Pro",
  "severity": "critical",          // 'critical'|'high'|'medium'|'low'
  "riskScore": 96,
  "status": "contained",           // 'detected'|'investigating'|'contained'|'resolved'|'false_positive'
  "detectedAt": "2026-08-29T10:32:01.124000Z",   // full ISO
  "detectionEngine": "Behavioral Detection",
  "agentStatus": "online",         // 'online'|'offline'|'degraded'
  "networkStatus": "isolated",     // 'connected'|'isolated'
  "threatDetails": {               // ThreatDetail (nullable)
    "process": "DemoRansomware.exe",
    "pid": 4824,
    "processPath": "C:\\RansomwareDemo\\DemoRansomware.exe",
    "targetDirectory": "C:\\RansomwareDemo\\TestFiles",
    "filesModified": 37,
    "filesLocked": 32,
    "ransomNote": "README_RESTORE_FILES.txt",
    "detectionReasons": ["Rapid file modification detected", ...],
    "riskBreakdown": [{ "label": "Rapid File Changes", "value": 30 }, ...]
  },
  "timeline": [ TimelineEvent ]    // nullable / [] allowed
}

// TimelineEvent — timestamp MUST be "HH:MM:SS.mmm" (time-of-day string);
// the frontend parses this exact format to compute the response duration.
{
  "id": "tl-001",
  "timestamp": "10:32:01.124",
  "title": "Suspicious activity detected",
  "description": "...",
  "type": "detection",             // 'detection'|'analysis'|'action'|'notification'|'success'|'evidence'
  "automated": true
}

// GET /api/endpoints → Endpoint[]
// GET /api/endpoints/{id} → Endpoint | 404
{
  "id": "ep-001",
  "hostname": "VICTIM-PC-01",
  "ipAddress": "192.168.56.105",
  "user": "demo-user",
  "os": "Windows 11 Pro",
  "agentStatus": "online",
  "riskScore": 96,
  "severity": "critical",          // Severity | "none"
  "networkStatus": "isolated",
  "lastSeen": "Just now",          // human display string
  "department": "Demo Lab",
  "incidentId": "RAN-2026-001"     // nullable
}

// GET /api/evidence → EvidenceItem[]
// GET /api/incidents/{id}/evidence → EvidenceItem[]
{
  "id": "EVD-001",                 // EVD-<NNN>, sequential
  "incidentId": "RAN-2026-001",
  "type": "detection_log",         // 'process_snapshot'|'file_manifest'|'event_logs'|'memory_metadata'|'network_metadata'|'ransom_note'|'detection_log'
  "source": "VICTIM-PC-01",        // hostname
  "size": "2.4 MB",                // human display string
  "sha256": "8a14f832c4...0a9c912",// real hash where applicable
  "collectedAt": "2026-08-29T10:32:05Z",  // full ISO
  "integrity": "verified",         // 'verified'|'pending'|'failed'
  "description": "..."
}

// GET /api/activity → ActivityLogEntry[]
{
  "id": "act-001",
  "timestamp": "2026-08-29T10:32:01Z",  // full ISO
  "event": "Ransomware Behavior Detected",
  "actor": "Automation Engine",         // display name
  "actorType": "automation",            // 'automation'|'analyst'|'agent'
  "target": "VICTIM-PC-01",
  "result": "success",                  // 'success'|'failed'|'pending'
  "details": "..."
}

// GET /api/notifications → Alert[]
{
  "id": "notif-001",
  "title": "Critical ransomware detected on VICTIM-PC-01",
  "description": "...",
  "severity": "critical",
  "timestamp": "10:32 AM",         // short display string (rendered as-is)
  "read": false,
  "incidentId": "RAN-2026-001"     // nullable
}

// POST /api/incidents/{id}/isolate|release|suspend-user|collect-evidence|false-positive|close
{ "success": true, "message": "Host isolation simulated for VICTIM-PC-01" }
```

## 4. Automated Orchestrator Flow (backend, on accepted detection event)

Timeline sequence to generate (types in parentheses):

1. Suspicious activity detected (detection)
2. Risk score calculated: 96/100 (analysis)
3. Critical ransomware incident created (action)
4. Host isolation command initiated (action)
5. VICTIM-PC-01 successfully isolated (success)
6. User demo-user suspended (action)
7. Active sessions revoked (action)
8. Forensic collection started (evidence)
9. Evidence package secured — 4 artifacts (success)
10. SOC notification generated (notification)

Final incident state: `status: contained`, `networkStatus: isolated`, `agentStatus: online`.
Endpoint state: `riskScore: 96`, `severity: critical`, `networkStatus: isolated`, `incidentId` set.
Identity response state (simulated): user suspended, sessions revoked.
Evidence artifacts (4): `detection_log`, `file_manifest`, `ransom_note`, `process_snapshot`.
Notifications (3): critical detection, host isolated, evidence collection completed.

Service abstractions required: `ContainmentService`, `IdentityResponseService`,
`EvidenceCollectionService`, `NotificationService`.

## 5. Demo Values (must match everywhere)

- Incident: `RAN-2026-001` (first incident of year 2026)
- Host: `VICTIM-PC-01`, IP `192.168.56.105`, user `demo-user`, department `Demo Lab`, OS `Windows 11 Pro`
- Process: `DemoRansomware.exe`, target `C:\RansomwareDemo\TestFiles`
- Ransom note: `README_RESTORE_FILES.txt`, files modified 37, locked 32
- Risk 96, severity `critical`, final status `contained`

## 6. Safety Boundaries

- Simulator operates ONLY inside `C:\RansomwareDemo\TestFiles` (hard-validated).
- Detector monitors ONLY `C:\RansomwareDemo\TestFiles` (hard-validated; test override
  must point inside a designated temp sandbox and never at system directories).
- No real encryption, deletion of originals, persistence, network spreading, or
  security-tool tampering anywhere in this project.

## 7. Process Attribution (detector)

The detector reports `process_name`/`process_path` from its configured demo identity
and includes the `suspicious_process` reason when EITHER the demo process is live
(real PID via `tasklist`) OR the demo ransom note `README_RESTORE_FILES.txt` — the
known simulator's unique signature in this lab — is present in the monitored folder.
The detector also aggregates behavior into bursts and fires one event per burst
(after the directory is quiet for `burst_quiet_scans` scans, or after
`max_burst_seconds`), so a single simulator run produces ONE complete event
(files_modified 37, locked_files 32, note detected → backend risk score 96).
