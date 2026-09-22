# RansomGuard IR — VM Detection Agent

Defensive, read-only ransomware-behavior detector for the demo Windows VM
(`VICTIM-PC-01`, `192.168.56.105`, user `demo-user`). Python 3.11, **stdlib
only** at runtime (zero third-party dependencies), so PyInstaller packaging
is trivial.

## What it does

1. Polls ONE validated directory (`C:\RansomwareDemo\TestFiles`) every
   `scan_interval_seconds` with `os.scandir` (read-only; symlinks, NTFS
   reparse points, and subdirectories are skipped).
2. Applies behavioral heuristics:
   - `rapid_file_modification` — MORE than `rapid_change_threshold` file
     create/modify events inside the sliding `rapid_window_seconds` window
     (accumulated across scans; renames/copies appear as create events).
   - `locked_extension_activity` — MORE than `locked_files_threshold` files
     currently end in `.locked`.
   - `ransom_note_detected` — `README_RESTORE_FILES.txt` is present.
   - `suspicious_process` — the known demo-simulator process is attributed:
     `DemoRansomware.exe` is live (`tasklist /FI "IMAGENAME eq ..." /FO CSV
     /NH` provides the real PID) OR the demo ransom note — the simulator's
     unique signature in this lab — is present (then `process_id` is `0`).
     The behavioral reasons alone are sufficient to fire.
3. Fires ONE aggregated event per behavior BURST: once a threshold is crossed
   the engine keeps accumulating until the directory is quiet for
   `burst_quiet_scans` consecutive scans (or `max_burst_seconds` elapse), so a
   single simulator run produces one complete event with all signals.
   The event is POSTed to `{backend_url}/api/events/detection` with exactly
   the snake_case payload from `shared/CONTRACTS.md` section 1. The backend
   computes the risk score.
4. Deduplicates: after a report the change window resets and a baseline is
   recorded; unchanged state will NOT re-fire even after `cooldown_seconds`.
   `deduplicated: true` responses are just logged. Failed delivery retries
   with exponential backoff (2s, 4s, 8s, ... max 60s) on a background thread,
   so monitoring continues while the backend is unavailable.

## Safety boundary

- The agent **never** modifies, deletes, or renames anything it monitors; it
  never writes into the monitored directory. It only reads directory
  metadata and sends one HTTP POST.
- Without `VM_AGENT_TEST_DIR` the monitor directory must resolve
  (case-insensitive) to exactly `C:\RansomwareDemo\TestFiles`; any other
  path refuses to start with a clear error.
- `VM_AGENT_TEST_DIR` (automated tests ONLY) may point elsewhere, but is
  refused for drive roots and system directories (`C:\Windows`, `C:\Users`,
  `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`) and must
  resolve strictly inside the user temp directory. Never set it in production.

## Layout

```
vm-agent/
  config.ini            # local config (gitignored; copy of config.example.ini)
  config.example.ini    # committed template
  detector/
    main.py             # entry point, logging, lifecycle
    monitor.py          # polling snapshots + heuristics + event builder
    reporter.py         # HTTP POST with retry/backoff (urllib)
    config.py           # config.ini + VM_AGENT_* env overrides + validation
  tests/                # pytest suite (pytest only, no httpx needed)
  detector.log          # rotating log (gitignored), DEBUG level
```

## Setup

```bat
cd vm-agent
copy config.example.ini config.ini
pip install -r requirements-dev.txt   # pytest only, for running the tests
```

No install step is needed to run the agent itself.

## Configuration

Values resolve as: defaults <- `config.ini` <- `VM_AGENT_*` environment
variables. Defaults match the demo contract (`shared/CONTRACTS.md` section 5).

| Key | Default | Env override |
|---|---|---|
| backend URL | `http://192.168.56.1:8000` | `VM_AGENT_BACKEND_URL` |
| monitor dir | `C:\RansomwareDemo\TestFiles` | `VM_AGENT_MONITOR_DIR` (must be the demo dir) |
| scan interval | `1.0` s | `VM_AGENT_SCAN_INTERVAL_SECONDS` |
| rapid threshold (events, strictly greater) | `10` | `VM_AGENT_RAPID_CHANGE_THRESHOLD` |
| rapid window (sliding, seconds) | `10.0` | `VM_AGENT_RAPID_WINDOW_SECONDS` |
| locked threshold (strictly greater) | `5` | `VM_AGENT_LOCKED_FILES_THRESHOLD` |
| cooldown between reports | `60` s | `VM_AGENT_COOLDOWN_SECONDS` |
| hostname / IP / username | `VICTIM-PC-01` / `192.168.56.105` / `demo-user` | `VM_AGENT_HOSTNAME` / `VM_AGENT_IP_ADDRESS` / `VM_AGENT_USERNAME` |
| demo process name / reported path | `DemoRansomware.exe` / `C:\RansomwareDemo\DemoRansomware.exe` | `VM_AGENT_PROCESS_NAME` / `VM_AGENT_PROCESS_PATH` |
| report retry budget | `6` attempts | `VM_AGENT_MAX_REPORT_ATTEMPTS` |
| test-only monitor dir | — | `VM_AGENT_TEST_DIR` |

Notes:
- On the host (outside the VM) set `VM_AGENT_BACKEND_URL=http://localhost:8000`
  and use `VM_AGENT_TEST_DIR` for any manual experiment; the agent will not
  monitor anything else.
- `process_path` is the configured path, not an observed one: `tasklist`
  cannot report full image paths. `process_id` is the real PID when the
  process is found, otherwise `0`.

## Run

```bat
cd vm-agent
python detector/main.py                 :: continuous monitoring
python detector/main.py --once          :: single scan+report pass (tests/CI)
python detector/main.py --max-scans 10  :: bounded run
python detector/main.py --verbose       :: DEBUG on console too
python -m detector.main                 :: also works
python vm-agent/detector/main.py        :: also works from the repo root
```

Startup logs the effective configuration; each scan cycle is logged at DEBUG
(`detector.log`); detections are logged at INFO with reasons and a local
risk/severity estimate (the backend computes the official score). Ctrl+C
stops cleanly ("Detector stopped"). If the monitored demo directory is the
validated path and missing, an empty one is created (safe).

## Tests

```bat
cd vm-agent
python -m pytest
```

The suite uses `VM_AGENT_TEST_DIR` sandboxes under the pytest temp tree and a
local `http.server` instance; it never touches the demo directory.

## Packaging (optional)

From `vm-agent\`:

```bat
pyinstaller --onefile --name RansomGuardAgent --paths . detector\main.py
```

`dist\RansomGuardAgent.exe` reads `config.ini` from its own folder (defaults
apply if absent) and writes `detector.log` next to the exe.
