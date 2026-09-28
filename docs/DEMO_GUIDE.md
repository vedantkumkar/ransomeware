# RansomGuard IR — Review Demo Guide

A practical, step-by-step script for presenting the demo.
Total setup time: ~5 minutes (once components are installed).

---

## BEFORE the review — setup (do this before reviewers arrive)

| # | Step | Where | Check |
|---|---|---|---|
| 1 | Start the backend: `scripts\start-backend.bat` | Host | `http://localhost:8000/api/health` → `{"status":"ok"}` |
| 2 | Start the frontend: `scripts\start-frontend.bat` | Host | Dashboard loads at `http://localhost:5173` |
| 3 | Ensure the frontend is in **live mode**: `frontend\.env` has `VITE_USE_MOCK_API=false` + `VITE_API_BASE_URL=http://localhost:8000` | Host | Restart `npm run dev` after editing |
| 4 | Start the VM, then the detector: `start-agent.bat` (in the copied `release\vm-agent`, with `config.ini` pointing at the host IP) | VM | Banner shows `monitor_dir validated` and scan lines |
| 5 | Verify the healthy baseline on the dashboard | Host | **Endpoints** page: VICTIM-PC-01, Online, Connected, risk — |
| 6 | Reset beforehand if a previous demo ran: stop backend → `scripts\reset-demo.bat --with-db` → restart backend + detector | Host/VM | Endpoints list empty of incidents, `GET /api/incidents` = `[]` |

> Tip: the simulator needs the demo folder to exist on the machine it runs on
> (`C:\RansomwareDemo\TestFiles`). The EXE creates it automatically on first run.

---

## DURING the review — the automatic flow (~2 minutes, zero clicks)

**1. Show the normal state (host, dashboard → Endpoints).**
VICTIM-PC-01 is online, connected, healthy. Optionally open
`C:\RansomwareDemo\TestFiles` and show the harmless dummy files.

**2. Run the attack simulation (VM).**
Double-click `DemoRansomware.exe`. Point out the printed summary:
`files_modified=37 locked_files=32 note=README_RESTORE_FILES.txt`.

**3. Show what it really did (VM Explorer).**
The demo folder now contains `.locked` copies and `README_RESTORE_FILES.txt`.
Open one `.locked` file — it's plain text. Open the note — it says this is a
SAFE simulation. **Nothing was encrypted; originals are untouched.**

**4. The alert appears by itself (host, Dashboard — do not refresh).**
Within seconds, without any interaction:
- **ACTIVE CRITICAL INCIDENT** card appears — RAN-2026-001, VICTIM-PC-01
- Risk dial: **96/100 CRITICAL**
- "Detected at … — automated containment applied in …s"
- Stat cards update (Active Incidents 1, Contained Hosts, Critical Alerts, Evidence 4)

**5. Explain the risk score (Incidents → RAN-2026-001 → Risk Score Breakdown).**
+30 rapid changes, +30 locked activity, +25 ransom note, +11 simulator
signature = **96 → Critical**. Deterministic, explainable, no ML.

**6. Show the automated containment timeline.**
10 timestamped events: detection → risk score → incident → isolation command →
isolated → user suspended → sessions revoked → evidence started → secured →
SOC notified.

**7. Show the evidence (Evidence page).**
4 artifacts (detection log, file manifest, ransom note, process snapshot) —
each with SHA-256 hash and **verified** integrity.

**8. Show the activity log (Activity Log page).**
Chronological audit trail: automation engine and agent actions with results.

**9. Show notifications (bell icon).**
3 backend-driven notifications: critical detection, host isolated, evidence completed.

**10. Analyst response (Incident detail → Analyst Actions).**
- **Release Host** → confirm → network badge flips to **Connected** (reversible!)
- **Isolate Host** again, or **Close Incident** → status **Resolved**
- Every action lands in the Activity Log.

---

## AFTER the review — reset

```bat
:: 1. Stop the backend window (Ctrl+C)
scripts\reset-demo.bat --with-db
:: 2. Restart backend + detector; optionally delete C:\RansomwareDemo\TestFiles
```

The demo is now back to a clean state and can be repeated.

---

## Common hiccups during a review

| Symptom | Quick fix |
|---|---|
| Dashboard stuck on "Failed to load data" | Backend not running — restart it, hard-refresh the browser (Ctrl+Shift+R) |
| No incident appears after the EXE | Detector not running in the VM / wrong backend URL in `config.ini`; check the detector window and `detector.log` |
| Risk below 96 | An older detection was still inside the cooldown — wait 60 s (agent) / 300 s (backend) or reset |
| `reset-demo.bat` says DB locked | Stop the backend first |
