"""
RansomGuard IR — safe ransomware-behavior simulation core.

This module implements ONLY harmless, educational file activity inside a single
validated demo directory. It is deliberately NOT ransomware:

- it never encrypts anything (`.locked` entries are plain-text COPIES)
- it never deletes or overwrites files it did not create in this run
- it never touches anything outside the validated boundary directory
- it never spawns processes, touches the network, registry, or startup folders

Every filesystem operation passes through `safe_path()`, which resolves the path
and verifies containment inside the boundary before any I/O occurs.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Callable, List

# The single hard-coded safety boundary for the live demo.
DEMO_BOUNDARY = Path(r"C:\RansomwareDemo\TestFiles")

RANSOM_NOTE_NAME = "README_RESTORE_FILES.txt"

DEMO_NOTE_TEXT = (
    "README_RESTORE_FILES.txt\n"
    "========================\n\n"
    "This file was created by the RansomGuard IR educational demo simulator.\n"
    "This is a SAFE simulation: nothing was encrypted, nothing was deleted,\n"
    "and no real ransomware is present.\n\n"
    "The `.locked` files in this folder are harmless plain-text COPIES of the\n"
    "demo files. Originals are untouched. You can delete this entire folder\n"
    "at any time using the project reset script.\n"
)

SEED_NAMES = [
    "report_{:03d}.txt", "invoice_{:03d}.txt", "notes_{:03d}.txt",
    "budget_{:03d}.txt", "schedule_{:03d}.txt", "summary_{:03d}.txt",
    "draft_{:03d}.txt", "memo_{:03d}.txt",
]

SEED_CONTENT = (
    "RansomGuard IR demo file.\n"
    "This is harmless dummy content used to exercise the detection demo.\n"
    "File: {name}\n"
    "Revision: {rev}\n"
)


class SafetyViolation(Exception):
    """Raised when an operation would escape the validated demo boundary."""


def resolve_boundary(path: Path) -> Path:
    """Resolve a boundary path, creating the demo directory when allowed."""
    resolved = Path(path).resolve()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def validate_boundary(path: Path, expected: Path) -> Path:
    """CLI-level guard: the requested directory must equal the expected boundary."""
    if Path(path).resolve().as_posix().lower() != Path(expected).resolve().as_posix().lower():
        raise SafetyViolation(
            f"Refusing to run: target '{path}' is not the validated demo directory "
            f"'{expected}'. This simulator is hard-locked to a single folder."
        )
    return resolve_boundary(Path(path))


def safe_path(name: str, boundary: Path) -> Path:
    """Join a filename onto the boundary and prove containment before I/O."""
    candidate = (boundary / name).resolve()
    if not candidate.is_relative_to(Path(boundary).resolve()):
        raise SafetyViolation(f"Path escapes demo boundary: {name!r}")
    return candidate


def seed_files(boundary: Path, count: int) -> List[Path]:
    """Create the initial harmless demo documents (no-op for existing names)."""
    created: List[Path] = []
    for i in range(count):
        name = SEED_NAMES[i % len(SEED_NAMES)].format(i + 1)
        path = safe_path(name, boundary)
        if not path.exists():
            path.write_text(SEED_CONTENT.format(name=name, rev=0), encoding="utf-8")
        created.append(path)
    return created


def _seeded_names(count: int) -> List[str]:
    return [SEED_NAMES[i % len(SEED_NAMES)].format(i + 1) for i in range(count)]


def run_simulation(
    boundary: Path,
    modify_count: int = 37,
    locked_count: int = 32,
    delay_seconds: float = 0.02,
    progress: Callable[[str], None] = print,
) -> dict:
    """
    Run the safe demo behavior inside `boundary` and return a stats summary.

    Phase 1: rapid modification of existing demo documents (rewrite content).
    Phase 2: creation of `.locked` plain-text COPIES (originals preserved).
    Phase 3: creation of the demo ransom note.
    """
    boundary = resolve_boundary(boundary)
    names = _seeded_names(max(modify_count, locked_count, 1))
    seed_files(boundary, len(names))

    files_modified = 0
    for i, name in enumerate(names):
        if files_modified >= modify_count:
            break
        path = safe_path(name, boundary)
        rev = 1
        if path.exists():
            try:
                current = path.read_text(encoding="utf-8", errors="ignore")
                marker = "Revision:"
                if marker in current:
                    try:
                        rev = int(current.split(marker, 1)[1].splitlines()[0].strip()) + 1
                    except ValueError:
                        rev = 1
            except OSError:
                rev = 1
        path.write_text(SEED_CONTENT.format(name=name, rev=rev), encoding="utf-8")
        files_modified += 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        if files_modified % 10 == 0 or files_modified == modify_count:
            progress(f"[sim] files modified: {files_modified}/{modify_count}")

    files_locked = 0
    for name in names:
        if files_locked >= locked_count:
            break
        source = safe_path(name, boundary)
        locked_copy = safe_path(name + ".locked", boundary)
        locked_copy.write_text(
            source.read_text(encoding="utf-8", errors="ignore")
            + "\n[DEMO COPY] This `.locked` file is a harmless plain-text copy.\n",
            encoding="utf-8",
        )
        files_locked += 1
        if delay_seconds > 0:
            time.sleep(delay_seconds)
        if files_locked % 10 == 0 or files_locked == locked_count:
            progress(f"[sim] locked copies created: {files_locked}/{locked_count}")

    note_path = safe_path(RANSOM_NOTE_NAME, boundary)
    note_path.write_text(DEMO_NOTE_TEXT, encoding="utf-8")
    progress(f"[sim] demo note written: {RANSOM_NOTE_NAME}")

    return {
        "boundary": str(boundary),
        "files_modified": files_modified,
        "locked_files": files_locked,
        "ransom_note": RANSOM_NOTE_NAME,
    }


def reset_boundary(boundary: Path, expected: Path, progress: Callable[[str], None] = print) -> int:
    """Delete every file inside the validated demo boundary. Returns count removed."""
    target = Path(boundary).resolve()
    if target.as_posix().lower() != Path(expected).resolve().as_posix().lower():
        raise SafetyViolation(
            f"Refusing to reset: '{target}' is not the validated demo directory '{expected}'."
        )
    if not target.exists():
        progress(f"[reset] nothing to reset ({target} does not exist)")
        return 0
    removed = 0
    for entry in target.iterdir():
        if entry.is_file() or entry.is_symlink():
            entry.unlink()
            removed += 1
        elif entry.is_dir():
            # only empty demo subfolders are expected; refuse surprising trees
            raise SafetyViolation(
                f"Unexpected subdirectory in demo folder: {entry} — remove it manually."
            )
    progress(f"[reset] removed {removed} files from {target}")
    return removed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SAFE ransomware-behavior demo simulator (RansomGuard IR)."
    )
    parser.add_argument(
        "--dir",
        default=str(DEMO_BOUNDARY),
        help=f"Target directory (must be exactly {DEMO_BOUNDARY}).",
    )
    parser.add_argument("--modify-count", type=int, default=37)
    parser.add_argument("--locked-count", type=int, default=32)
    parser.add_argument("--seed-files", type=int, default=40)
    parser.add_argument("--delay", type=float, default=0.02, help="Seconds between file writes.")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress output.")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    def progress(message: str) -> None:
        if not args.quiet:
            print(message, flush=True)

    try:
        boundary = validate_boundary(Path(args.dir), DEMO_BOUNDARY)
        progress(f"[sim] safety boundary validated: {boundary}")
        if args.seed_files > 0:
            seed_files(boundary, args.seed_files)
        stats = run_simulation(
            boundary,
            modify_count=args.modify_count,
            locked_count=args.locked_count,
            delay_seconds=args.delay,
            progress=progress,
        )
        progress("[sim] DONE — safe simulation complete (nothing was encrypted)")
        print(
            f"summary: files_modified={stats['files_modified']} "
            f"locked_files={stats['locked_files']} note={stats['ransom_note']}"
        )
        return 0
    except SafetyViolation as exc:
        print(f"SAFETY REFUSAL: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
