# RansomGuard IR
### Automated Ransomware Containment & Incident Response Orchestrator

A professional SOC-style ransomware detection and response platform, built as a
**safe, educational college demo**: a harmless behavior simulator inside a Windows
VM triggers automatic detection, risk scoring, incident creation, containment,
evidence collection, and live dashboard updates — with no manual "simulate attack"
button.

> ## ⚠️ Safety disclaimer — read this first
> **`DemoRansomware.exe` is a HARMLESS RANSOMWARE-BEHAVIOR SIMULATOR. It does NOT
> perform encryption.** It only creates dummy text files, plain-text `.locked`
> *copies*, and a demo note — **only** inside `C:\RansomwareDemo\TestFiles`, and
> only after refusing (with a `SAFETY REFUSAL` error) any other target. It never
> deletes, encrypts, spreads, persists, or touches anything outside that folder.
> The detector is read-only monitoring software. Safety rules are hard-coded and
> covered by automated tests.

## Overview

1. The safe simulator produces ransomware-*like* file activity in one validated folder.
2. The VM detector recognizes the behavior and reports one aggregated event.
3. The backend scores it deterministically (**96/100 → Critical**), creates incident
   `RAN-2026-001`, and runs the automated response: host isolation → user suspension
   (simulated) → session revocation → evidence collection → SOC notifications.
4. The dashboard shows the incident, timeline, evidence, and activity log live
   (5-second polling). The analyst can release the host, close the incident, or
   mark a false positive.

## Architecture

```
        Windows VM (VICTIM-PC-01)                      Host machine
┌─────────────────────────────────────┐   ┌────────────────────────────────────┐
│  simulator\  DemoRansomware.exe     │   │  backend\  FastAPI + SQLite (:8000)│
│   harmless activity ONLY inside     │   │   ├─ risk engine (deterministic)   │
│   C:\RansomwareDemo\TestFiles       │   │   ├─ response orchestrator         │
│                                     │   │   └─ REST API (18 endpoints)       │
│  vm-agent\  detector (read-only)    │   │            ▲        ▲              │
│   polls the demo folder, aggregates │   │   POST /api/       │ REST/camelCase│
│   one burst event, POSTs it ────────┼───┼─→ events/detection │               │
└─────────────────────────────────────┘   │  frontend\ React SPA (static)       │
                                          │   live mode: polls API every 5 s    │
                                          │   mock mode: standalone demo        │
                                          └────────────────────────────────────┘
                    release\  ready-to-copy distributables (exe + vm-agent)
                    scripts\  one-click Windows batch files
```

## Components & technology stack

| Component | Technology | Role |
|---|---|---|
| `frontend\` | React 19, TypeScript, Vite 7, Tailwind v4, shadcn/ui, Recharts | Approved SOC dashboard (all data via `src/services/api.ts`) |
| `backend\` | Python 3.11, FastAPI, Pydantic, SQLite | Storage, risk engine, orchestrator, REST API, CORS |
| `vm-agent\` | Python 3.11 **stdlib only** | Read-only directory monitor + HTTP reporter |
| `simulator\` | Python + PyInstaller | Safe behavior simulator (`DemoRansomware.exe`) |
| `shared\` | Markdown | Binding data contracts between components |
| `release\` | — | Distributable artifacts (EXE, VM agent package, demo files) |

## How detection works (risk score)

The backend scores each detection event with a simple deterministic ruleset
(**no machine learning**):

| Signal | Points |
|---|---|
| Rapid file modification | **+30** |
| Multiple `.locked` files | **+30** |
| Ransom note detected | **+25** |
| Simulator process signature | **+11** |
| **Demo total (all signals)** | **96 / 100 → CRITICAL** |

Severity bands: 0–39 Low · 40–59 Medium · 60–84 High · 85–100 Critical.
The detector aggregates one simulator run into a single "burst" event (firing
after the folder goes quiet) so the backend receives complete, non-duplicated
behavior. Full details: [`shared/CONTRACTS.md`](shared/CONTRACTS.md).

## Repository structure

```
frontend\    SOC dashboard (approved design — data access only via src/services/api.ts)
backend\     FastAPI + SQLite backend (app\, tests\, .env.example)
vm-agent\    Windows VM detection agent (detector\, tests\, config.example.ini)
simulator\   Safe simulator + reset script + safety tests (tests\)
shared\      CONTRACTS.md — cross-component data contracts
scripts\     start-backend.bat · start-frontend.bat · build-simulator-exe.bat · reset-demo.bat
release\     DemoRansomware.exe · README.txt · vm-agent\ (VM-ready) · demo-files\
docs\        ARCHITECTURE.md · DEPLOYMENT.md · DEMO_GUIDE.md
.github\     GitHub Actions workflow (frontend → GitHub Pages)
```

## Quick start (host only — 3 commands)

```bat
scripts\start-backend.bat     :: API on http://localhost:8000
scripts\start-frontend.bat    :: dashboard on http://localhost:5173
:: open http://localhost:5173 — mock mode: full clickable demo, no VM needed
```

## Full demo: laptop + Windows VM

### 0. One-time VM prep
- Windows 11 VM (VirtualBox, host-only network `192.168.56.x`), Python 3.11+
- Create the demo folder on the VM: `C:\RansomwareDemo\TestFiles`

### 1. Start the backend (host)
```bat
cd backend
pip install -r requirements.txt
scripts\start-backend.bat
```
Check `GET http://localhost:8000/api/health` → `{"status":"ok"}`.

### 2. Start the frontend (host)
```bat
cd frontend
npm install
npm run dev
```
**Live mode:** create `frontend\.env` —
```
VITE_USE_MOCK_API=false
VITE_API_BASE_URL=http://localhost:8000
```
— then restart the dev server (or `npm run build` + `npm run preview`).
Dashboard shows **VICTIM-PC-01 online/healthy** (backend seeds it).

### 3. Start the detector (inside the VM)
Copy `release\vm-agent\` to the VM, then:
```bat
copy config.example.ini config.ini
:: edit config.ini:  url = http://<HOST-LAN-IP>:8000
start-agent.bat
```
(For host-side testing set `url = http://localhost:8000` and run from the repo —
see `vm-agent\README.md`.)

### 4. Run the safe simulator (inside the VM)
```bat
DemoRansomware.exe
```
`release\DemoRansomware.exe` — harmless; see the safety disclaimer above and
`release\README.txt`. Within seconds:

### 5. Watch it happen automatically
- Dashboard: **RAN-2026-001** appears — risk **96/100 CRITICAL**
- Endpoint VICTIM-PC-01 becomes **isolated**; user **demo-user suspended**
- **Timeline** (10 events), **evidence** (4 verified artifacts), **activity log**,
  and **notifications** all populate live
- Analyst actions: release host → close incident → mark false positive

### 6. Reset and repeat
```bat
scripts\reset-demo.bat --with-db    :: stop the backend first, then re-run it
```

## Reset procedure (detail)

| What | Command |
|---|---|
| Demo folder only | `python simulator\reset_demo.py` |
| Demo folder + backend DB + evidence | `scripts\reset-demo.bat --with-db` (backend stopped) |
| Rebuild the EXE | `scripts\build-simulator-exe.bat` (requires PyInstaller) |

## GitHub / deployment

- **Repository:** push-ready — `node_modules`, `dist`, `.env`, `__pycache__`,
  `.venv`, runtime databases, evidence storage, PyInstaller build dirs, and logs
  are git-ignored; `.env.example` files included. The 7 MB `release\DemoRansomware.exe`
  is committed for reviewer convenience (rebuild anytime with
  `scripts\build-simulator-exe.bat`).
- **Frontend on GitHub Pages:** included workflow (`.github/workflows/`) deploys
  the frontend automatically; the repo name is read from the push event (nothing
  hardcoded), deep links work via the `404.html` fallback, and the default Pages
  build is a self-contained **mock-mode** demo. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).
- **Backend:** deployable separately to any Python host (start command
  `python -m app.main`); config via `HOST` / `PORT` / `CORS_ORIGINS` env vars.
  See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Testing results

| Suite | Command | Result |
|---|---|---|
| Backend API | `python -m pytest` (in `backend\`) | 20/20 pass |
| VM detector | `python -m pytest` (in `vm-agent\`) | 55/55 pass |
| Simulator safety | `python -m pytest` (in `simulator\`) | 9/9 pass |
| Frontend | `npm run typecheck` / `npm run build` (in `frontend\`) | clean |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `reset-demo.bat --with-db` says the DB is locked | Stop the backend first (Ctrl+C), then re-run |
| Dashboard shows "Failed to load data" in live mode | Backend not running / wrong `VITE_API_BASE_URL` — start it, check `:8000/api/health`, restart the dev server |
| Detector refuses to start ("SAFETY") | `config.ini` monitor dir must be exactly `C:\RansomwareDemo\TestFiles` |
| Detector can't reach backend | Wrong `url` in `config.ini` — use the host's LAN IP; check firewall on port 8000 |
| Simulator prints `SAFETY REFUSAL` | You aimed it outside the demo folder — run it with no arguments |
| Incident doesn't hit 96 | Run the packaged `DemoRansomware.exe` (activates the process signal) or check all four signals fired in the detector log |
| GitHub Pages assets 404 | Set **Settings → Pages → Source: GitHub Actions** and re-run the workflow |
| Port already in use | Stop the previous backend/preview process, or change `PORT` |

## Documentation

- [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md) — step-by-step review presentation guide
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — frontend/backend deployment
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design and safety model
- [`shared/CONTRACTS.md`](shared/CONTRACTS.md) — data contracts
- [`release/README.txt`](release/README.txt) — EXE usage · [`release/vm-agent/README.txt`](release/vm-agent/README.txt) — VM agent setup
