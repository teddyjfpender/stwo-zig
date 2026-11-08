"""Pinned Stark-V source checks for trace-corpus attestation."""

from __future__ import annotations

import subprocess
from pathlib import Path


def validate_source(rust_source: Path, pinned_commit: str) -> str:
    """Require a clean Stark-V checkout at the repository's exact pin."""
    try:
        head = subprocess.run(
            ["git", "-C", str(rust_source), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(rust_source), "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError as error:
        raise SystemExit(f"cannot inspect Stark-V source checkout: {error}") from error
    if head != pinned_commit:
        raise SystemExit(f"Stark-V source is at {head}, expected exact pin {pinned_commit}")
    if status:
        raise SystemExit("Stark-V source checkout is dirty; refusing oracle attestation")
    return head
