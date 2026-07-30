"""Shared export fixture for Team B witness tests."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts import riscv_team_b_witnesses as witnesses

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
EXPORT_DIRECTORY = REPOSITORY_ROOT / "zig-out/team-b-ir"


def export_air() -> Path:
    """Export the production symbolic AIR, or reuse a fresh existing export.

    Reuse is gated on the provenance check: an existing export is only
    trusted if no production AIR source is newer than it. A stale export is
    re-derived instead of silently evaluated.
    """
    if (EXPORT_DIRECTORY / "load_store.json").is_file():
        try:
            witnesses.check_export_provenance(EXPORT_DIRECTORY)
            return EXPORT_DIRECTORY
        except witnesses.WitnessError:
            pass  # Stale or unverifiable: fall through and re-export.
    subprocess.run(
        [
            "zig",
            "build",
            "riscv-refinement-ir",
            f"-Driscv-refinement-ir-dir={EXPORT_DIRECTORY.relative_to(REPOSITORY_ROOT)}",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        timeout=900,
    )
    return EXPORT_DIRECTORY
