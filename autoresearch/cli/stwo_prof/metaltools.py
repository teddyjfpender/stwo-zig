"""Metal profiling: generic kernel runs, device caps, and trace wrapping."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from .scaffold import scratch_root
from .zigtools import ProfError

RUNNER_SOURCE = (
    Path(__file__).resolve().parents[2]
    / "tools"
    / "metal-prof-runner"
    / "runner.m"
)


def runner_binary() -> Path:
    """Compile the runner on first use; cache keyed by source digest."""
    if not RUNNER_SOURCE.exists():
        raise ProfError(f"runner source missing: {RUNNER_SOURCE}")
    digest = hashlib.sha256(RUNNER_SOURCE.read_bytes()).hexdigest()[:12]
    binary = scratch_root() / f"metal-prof-runner-{digest}"
    if binary.exists():
        return binary
    proc = subprocess.run(
        ["clang", "-fobjc-arc", "-O2", str(RUNNER_SOURCE), "-o", str(binary),
         "-framework", "Metal", "-framework", "Foundation"],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise ProfError(f"runner compile failed:\n{proc.stderr.strip()[-600:]}")
    return binary


def _run_json(cmd: list[str], timeout: int = 900) -> dict:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise ProfError(proc.stderr.strip()[-600:] or "runner failed")
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise ProfError(f"runner emitted non-JSON: {proc.stdout[:200]!r}") from exc


def caps() -> dict:
    return _run_json([str(runner_binary()), "--caps"], timeout=120)


def run_kernel(source: Path, entry: str, grid: int, tg: int, iters: int,
               buffers: str) -> dict:
    result = _run_json([
        str(runner_binary()),
        "--source", str(source), "--entry", entry,
        "--grid", str(grid), "--tg", str(tg), "--iters", str(iters),
        "--buffers", buffers,
    ])
    # Achieved bandwidth estimate: bytes touched per dispatch / gpu time.
    total_bytes = 0
    for spec in buffers.split(","):
        kind, _, elems = spec.partition(":")
        width = 8 if kind == "u64" else 4
        total_bytes += int(elems) * width
    if result.get("gpu_ms_median"):
        result["approx_gb_per_s"] = round(
            (total_bytes / 1e9) / (result["gpu_ms_median"] / 1e3), 2
        )
        result["approx_bandwidth_note"] = (
            "assumes each buffer element touched once per dispatch; adjust for "
            "the kernel's real access pattern"
        )
    return result


def trace(command: list[str], output: Path) -> Path:
    """Wrap an arbitrary command in a Metal System Trace capture."""
    xctrace = shutil.which("xctrace")
    if xctrace is None:
        raise ProfError(
            "xctrace not found — Metal System Trace requires full Xcode "
            "(xcode-select to the Xcode.app developer directory)"
        )
    proc = subprocess.run(
        [xctrace, "record", "--template", "Metal System Trace",
         "--output", str(output), "--launch", "--", *command],
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        raise ProfError(f"xctrace failed:\n{proc.stderr.strip()[-600:]}")
    return output
