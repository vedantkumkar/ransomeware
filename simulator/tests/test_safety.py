"""Safety tests for the safe demo simulator.

The core functions accept an injected boundary so tests run against a temp
sandbox; the CLI itself is hard-locked to C:\\RansomwareDemo\\TestFiles and is
tested for refusal separately (never touching the real path).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from demo_ransomware import (  # noqa: E402
    DEMO_BOUNDARY,
    RANSOM_NOTE_NAME,
    SafetyViolation,
    main,
    reset_boundary,
    run_simulation,
    safe_path,
    validate_boundary,
)


@pytest.fixture()
def sandbox(tmp_path: Path) -> Path:
    """A temp directory standing in for the real demo boundary."""
    return tmp_path / "RansomwareDemo" / "TestFiles"


def test_cli_refuses_any_directory_outside_boundary(tmp_path: Path):
    outside = tmp_path / "somewhere" / "else"
    outside.mkdir(parents=True)
    rc = main(["--dir", str(outside), "--quiet"])
    assert rc == 2, "simulator must refuse to run outside the demo boundary"
    assert list(outside.iterdir()) == [], "refused run must not create files"


def test_validate_boundary_rejects_lookalike_paths(tmp_path: Path):
    with pytest.raises(SafetyViolation):
        validate_boundary(tmp_path, DEMO_BOUNDARY)
    with pytest.raises(SafetyViolation):
        validate_boundary(DEMO_BOUNDARY.parent / "TestFiles2", DEMO_BOUNDARY)


def test_safe_path_blocks_path_traversal(sandbox: Path):
    boundary = sandbox
    boundary.mkdir(parents=True)
    with pytest.raises(SafetyViolation):
        safe_path("../escaped.txt", boundary)
    with pytest.raises(SafetyViolation):
        safe_path("..\\escaped.txt", boundary)
    with pytest.raises(SafetyViolation):
        safe_path("sub/../../../escaped.txt", boundary)
    # a path whose ".." segments cancel out resolves back INSIDE the boundary: allowed
    resolved = safe_path("a/b/../../kept.txt", boundary)
    assert resolved == (boundary / "kept.txt").resolve()


def test_simulation_stays_inside_boundary(sandbox: Path, tmp_path: Path):
    parent = tmp_path
    before = sorted(str(p) for p in parent.rglob("*") if p.is_file())
    stats = run_simulation(sandbox, modify_count=37, locked_count=32, delay_seconds=0)
    after_files = [p for p in parent.rglob("*") if p.is_file()]
    before_set = set(before)
    for path in after_files:
        assert str(path) not in before_set or path.is_relative_to(sandbox.resolve()), (
            f"file created outside boundary: {path}"
        )
        assert path.resolve().is_relative_to(sandbox.resolve())
    assert stats["files_modified"] == 37
    assert stats["locked_files"] == 32
    assert stats["ransom_note"] == RANSOM_NOTE_NAME


def test_simulation_preserves_originals_and_creates_copies(sandbox: Path):
    stats = run_simulation(sandbox, modify_count=37, locked_count=32, delay_seconds=0)
    files = {p.name for p in sandbox.iterdir()}
    assert RANSOM_NOTE_NAME in files
    locked = [n for n in files if n.endswith(".locked")]
    assert len(locked) == stats["locked_files"] == 32
    # originals were modified in place, never deleted
    assert "report_001.txt" in files
    assert (sandbox / "report_001.txt").read_text(encoding="utf-8").startswith(
        "RansomGuard IR demo file."
    )
    # a .locked file is a plain-text copy, not encrypted content
    assert (sandbox / "report_001.txt.locked").read_text(encoding="utf-8").startswith(
        "RansomGuard IR demo file."
    )


def test_note_is_explicitly_safe(sandbox: Path):
    run_simulation(sandbox, modify_count=5, locked_count=3, delay_seconds=0)
    note = (sandbox / RANSOM_NOTE_NAME).read_text(encoding="utf-8")
    assert "SAFE simulation" in note


def test_simulation_runs_repeatably(sandbox: Path):
    run_simulation(sandbox, modify_count=5, locked_count=3, delay_seconds=0)
    run_simulation(sandbox, modify_count=5, locked_count=3, delay_seconds=0)
    names = [p.name for p in sandbox.iterdir()]
    assert names.count("report_001.txt") == 1
    assert names.count("report_001.txt.locked") == 1


def test_reset_refuses_other_directories(tmp_path: Path):
    with pytest.raises(SafetyViolation):
        reset_boundary(tmp_path / "other", DEMO_BOUNDARY)


def test_reset_clears_only_demo_boundary(sandbox: Path, tmp_path: Path):
    run_simulation(sandbox, modify_count=5, locked_count=3, delay_seconds=0)
    sentinel = tmp_path / "keep_me.txt"
    sentinel.write_text("important")
    reset_boundary(sandbox, sandbox)
    assert list(sandbox.iterdir()) == []
    assert sentinel.read_text(encoding="utf-8") == "important"
