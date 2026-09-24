"""Reset the RansomGuard IR demo: clear the simulator folder (and optionally backend data)."""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from demo_ransomware import DEMO_BOUNDARY, SafetyViolation, reset_boundary  # noqa: E402

BACKEND_DIR = Path(__file__).resolve().parent.parent / "backend"


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset the RansomGuard IR demo state.")
    parser.add_argument(
        "--dir",
        default=str(DEMO_BOUNDARY),
        help=f"Simulator folder (must be exactly {DEMO_BOUNDARY}).",
    )
    parser.add_argument(
        "--with-db",
        action="store_true",
        help="Also delete the backend SQLite database, evidence storage, and logs.",
    )
    args = parser.parse_args()

    try:
        reset_boundary(Path(args.dir), DEMO_BOUNDARY)
    except SafetyViolation as exc:
        print(f"SAFETY REFUSAL: {exc}", file=sys.stderr)
        return 2

    if args.with_db:
        removed = []
        for path in [
            BACKEND_DIR / "ransomguard.db",
            BACKEND_DIR / "ransomguard.db-wal",
            BACKEND_DIR / "ransomguard.db-shm",
        ]:
            if not path.exists():
                continue
            try:
                path.unlink()
                removed.append(path.name)
            except PermissionError:
                print(
                    f"[reset] cannot delete {path.name} — the backend is still "
                    "running. Stop the backend (close its window / Ctrl+C), then "
                    "re-run: python simulator\\reset_demo.py --with-db"
                )
        evidence_dir = BACKEND_DIR / "evidence_storage"
        if evidence_dir.exists():
            shutil.rmtree(evidence_dir, ignore_errors=True)
            removed.append("evidence_storage/")
        if removed:
            print(f"[reset] backend data cleared: {', '.join(removed)}")

    print("[reset] demo reset complete — start the backend and simulator to run again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
