"""Shared export fixture for Team B witness tests."""

from __future__ import annotations

import json
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from scripts import riscv_team_b_witnesses as witnesses

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPORT_DIRECTORY = REPOSITORY_ROOT / "zig-out/team-b-ir"


_session_directory: tempfile.TemporaryDirectory | None = None
_session_export: Path | None = None


def export_air() -> Path:
    """Reuse a provenance-checked export or build once into an empty directory."""
    global _session_directory, _session_export
    for directory in (_session_export, EXPORT_DIRECTORY):
        if directory is not None and (directory / "load_store.json").is_file():
            try:
                witnesses.check_export_provenance(directory)
                return directory
            except witnesses.WitnessError:
                pass
    if shutil.which("zig") is None:
        raise FileNotFoundError("Zig is unavailable")
    directory = tempfile.TemporaryDirectory(prefix="stwo-team-b-witness-ir-")
    root = Path(directory.name)
    try:
        subprocess.run(
            [sys.executable, "scripts/zig_serial_build.py", "riscv-refinement-ir",
             f"-Driscv-refinement-ir-dir={root / 'symbolic'}",
             f"-Driscv-air-program-ir-dir={root / 'program'}"],
            cwd=REPOSITORY_ROOT, check=True, timeout=900,
        )
        witnesses.check_export_provenance(root / "symbolic")
    except BaseException:
        directory.cleanup()
        raise
    _session_directory = directory
    _session_export = root / "symbolic"
    return _session_export
