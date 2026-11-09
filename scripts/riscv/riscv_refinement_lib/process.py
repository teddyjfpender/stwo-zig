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


def _run_bridge(
    argv: list[str],
    cwd: Path,
    *,
    env: dict[str, str] | None = None,
    timeout: int = 1800,
) -> str:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RefinementError(
            f"generated Sail Lean bridge command timed out after {timeout}s: "
            + " ".join(argv)
        ) from exc
    except subprocess.CalledProcessError as exc:
        streams = [
            (name, output.strip())
            for name, output in (("stdout", exc.stdout or ""), ("stderr", exc.stderr or ""))
            if output.strip()
        ]
        limit = (8000 - 32) // max(1, len(streams))
        detail = "\n".join(
            f"{name}:\n" + (output if len(output) <= limit else "... " + output[-(limit - 4):])
            for name, output in streams
        )
        raise RefinementError(
            f"generated Sail Lean bridge command exited {exc.returncode}: "
            + " ".join(argv)
            + (f": {detail}" if detail else "")
        ) from exc
    except OSError as exc:
        raise RefinementError(
            "generated Sail Lean bridge command could not start: "
            + " ".join(argv)
        ) from exc
    return completed.stdout.strip()
