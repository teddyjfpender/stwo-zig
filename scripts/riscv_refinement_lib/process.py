"""Subprocess boundary shared by refinement orchestration modules."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .model import RefinementError

def _run(argv: list[str], cwd: Path, timeout: int = 600) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        output = exc.stdout.strip() if isinstance(exc, subprocess.CalledProcessError) else ""
        if len(output) > 8000:
            output = "... " + output[-8000:]
        raise RefinementError(
            f"command failed: {' '.join(argv)}" + (f"\n{output}" if output else "")
        ) from exc
    return completed.stdout
