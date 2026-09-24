# Safe Ransomware-Behavior Simulator (DemoRansomware)

**This is NOT ransomware.** It is an educational simulator that produces harmless,
observable file activity so the RansomGuard IR detection demo can run end-to-end.

## What it does (and never does)

| It MAY (inside the demo folder only) | It NEVER does |
|---|---|
| create dummy `.txt` demo documents | encrypt real files |
| rapidly rewrite dummy content (default 37 files) | delete files or originals |
| create `.locked` plain-text **copies** (default 32) | spread / scan other directories |
| create `README_RESTORE_FILES.txt` (harmless demo text) | touch the network, registry, startup, or system files |

The target directory is **hard-locked** to `C:\RansomwareDemo\TestFiles`.
Any other path is refused with a `SAFETY REFUSAL` error before any file I/O, and
every write is containment-checked (`safe_path`) against path traversal.

## Run

```bat
python simulator\demo_ransomware.py
```

Options: `--dir` (must be exactly `C:\RansomwareDemo\TestFiles`), `--modify-count`,
`--locked-count`, `--seed-files`, `--delay`, `--quiet`.

The folder is created and populated automatically if missing. Run it again any time;
originals are only ever modified in place, never deleted.

## Reset

```bat
python simulator\reset_demo.py            :: clears the demo folder
python simulator\reset_demo.py --with-db  :: also clears backend DB + evidence storage
```

## Package as DemoRansomware.exe (optional, for the VM demo)

Packaging makes the process name match what the detector looks for
(`DemoRansomware.exe`), which activates the `suspicious_process` risk signal (+11):

```bat
pip install pyinstaller
pyinstaller --onefile --name DemoRansomware simulator\demo_ransomware.py
:: output: dist\DemoRansomware.exe — copy into the VM, e.g. C:\RansomwareDemo\
```

Running the plain Python script works identically for the behavioral detection
signals (rapid modification, `.locked` activity, ransom note); only the process
signal requires the packaged exe name.

## Tests

```bat
python -m pytest simulator\tests -q
```

The suite covers: refusal of any path outside the boundary, path-traversal
containment, originals preserved, `.locked` copies are plain text, repeatable runs,
and boundary-locked reset. Tests use a temp sandbox via dependency injection —
they never touch the real demo folder.
