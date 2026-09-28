# RansomGuard IR — Architecture

Automated Ransomware Containment & Incident Response Orchestrator (safe college/demo build).

> **Safety disclaimer:** This project contains **no real ransomware**. The simulator only
> creates harmless dummy files, plain-text `.locked` copies, and a demo note inside one
> validated folder (`C:\RansomwareDemo\TestFiles`). Nothing is encrypted, deleted, spread,
> or persisted. See `simulator/README.md` for the full safety model.

## Flow (the demo path)

```
Windows VM (VICTIM-PC-01)                      Host machine
└── simulator\ DemoRansomware                  ├── backend\  FastAPI + SQLite (port 8000)
    safe file activity ONLY inside             │    ├─ risk engine (deterministic, 0-100)
    C:\RansomwareDemo\TestFiles                │    ├─ orchestrator (Containment /
└── vm-agent\ detector                         │    │   Identity / Evidence / Notification
    polls the demo folder, detects behavior    │    └─ REST API (18 endpoints, camelCase)
    POSTs /api/events/detection ───────────────┤
                                              ├── frontend\ React/Vite SOC dashboard
                                              │    (VITE_USE_MOCK_API=false → live API,
                                              │     5s silent polling per page)
                                              └── scripts\ start-backend / frontend /
                                                  agent / reset-demo
```

1. The safe simulator produces rapid file modification, `.locked` copies, and a ransom
   note **inside the demo folder only**.
2. The detector (stdlib-only polling monitor) flags the behavior and reports one
   aggregated event to `POST /api/events/detection`.
3. The backend scores the event deterministically
   (rapid modification +30, `.locked` activity +30, ransom note +25, suspicious
   process +11 → **96/100 critical** for the standard demo run) and creates incident
   `RAN-2026-001`.
4. The orchestrator runs the automated response: isolation → user suspension/session
   revocation (simulated state) → evidence collection → notifications, with a full
   timeline and activity log. Duplicate detection events inside the cooldown window are
   folded into the existing incident.
5. The frontend polls the API every 5 s; the incident, endpoint state, evidence,
   timeline, notifications, and dashboard stats appear live.
6. The analyst can release the host, collect more evidence, mark false positive, or
   close the incident; `scripts\reset-demo.bat --with-db` resets everything.

## Folders

| Folder | Purpose | Owner |
|---|---|---|
| `frontend\` | Approved Bolt UI (React 19 + Vite + shadcn). Data access only via `src/services/api.ts`. | frozen |
| `backend\` | FastAPI + SQLite: storage, risk engine, orchestrator, REST API, CORS. | backend-api-agent |
| `vm-agent\` | Safe stdlib-only Windows detection agent (polling monitor + reporter). | vm-detection-agent |
| `simulator\` | Safe behavior simulator + reset script + safety tests. | coordinator |
| `shared\` | `CONTRACTS.md` — the binding data contracts between components. | coordinator |
| `scripts\` | One-click Windows batch files for the demo. | coordinator |
| `docs\` | This document and deployment notes. | coordinator |

## Contracts

All cross-component data shapes live in [`shared/CONTRACTS.md`](../shared/CONTRACTS.md).
Frontend TypeScript types: `frontend/src/types/index.ts`.
Detection event payload: section 1 of the contracts doc (snake_case ingestion).
API responses: camelCase, matching the frontend types field-for-field.

## Frontend modes

- `VITE_USE_MOCK_API=true` (default) — runs standalone on local mock data.
- `VITE_USE_MOCK_API=false` — all service calls hit the FastAPI backend at
  `VITE_API_BASE_URL` (default `http://localhost:8000`). Pages silently re-poll every
  5 s (notifications every 10 s) so live incidents appear without a refresh.

## Containment model (safe by design)

- **Isolation** is state-first: the backend marks the endpoint `isolated` and records
  the action with a full audit trail. `ContainmentService` is the single place that
  would issue a real lab command; the default implementation is the documented
  simulation, and a reversible lab hook (e.g. a VirtualBox host-only adapter toggle)
  can be added there without touching any other layer.
- **Identity response** (user suspension, session revocation) is simulated state
  (`user_status=suspended`, `sessions_revoked=true`) — no AD/Graph required.
- **Release** reverses isolation; **close / false-positive** close the incident.
