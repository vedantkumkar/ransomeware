# RansomGuard IR — Backend

FastAPI + SQLite backend for the Automated Ransomware Containment & Incident
Response Orchestrator. Implements the API contract in `../shared/CONTRACTS.md`.

## Run

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Or: `python app/main.py` (same defaults). The SQLite database
(`ransomguard.db`) and the `evidence_storage/` folder are created on startup.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address |
| `PORT` | `8000` | Bind port |
| `RANSOMGUARD_DB_PATH` | `backend/ransomguard.db` | SQLite database file |
| `RANSOMGUARD_EVIDENCE_DIR` | `backend/evidence_storage` | Forensic artifact storage root |
| `DETECTION_COOLDOWN_SECONDS` | `300` | Per-host duplicate detection window |

## Endpoints

- `GET  /api/health`
- `GET  /api/dashboard`
- `GET  /api/incidents`, `GET /api/incidents/{id}`, `.../timeline`, `.../evidence`
- `GET  /api/endpoints`, `GET /api/endpoints/{id}`
- `GET  /api/evidence`, `GET /api/activity`, `GET /api/notifications`
- `POST /api/events/detection` — vm-agent ingestion (snake_case payload)
- `POST /api/incidents/{id}/isolate | release | suspend-user | collect-evidence | false-positive | close`

All responses are camelCase. An accepted detection event runs the automated
orchestrator (containment, identity response, evidence collection, SOC
notifications) and generates the 10-step incident timeline. Duplicate
detections for the same host inside the cooldown window are folded into the
existing active incident (`deduplicated: true`).

## Tests

```bash
cd backend
python -m pytest
```

Tests use a temp database (`RANSOMGUARD_DB_PATH`) and never touch the real DB.

## Safety

All response actions are simulated state changes recorded in the database and
timeline. No OS commands, network blocks, or identity-provider calls are ever
executed by this backend.
