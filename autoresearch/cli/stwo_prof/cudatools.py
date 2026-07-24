"""CUDA profiling wrappers with explicit tool, command, and artifact identity."""

from __future__ import annotations

import csv
import json
import shutil
import subprocess
from pathlib import Path

from .zigtools import ProfError


def _tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise ProfError(f"{name} is not installed or is absent from PATH")
    return path


def _command(arguments: list[str]) -> list[str]:
    command = list(arguments)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise ProfError("a command is required after --")
    return command


def _run(arguments: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "command failed"
        raise ProfError(detail[-1200:])
    return result


def caps() -> list[dict[str, str]]:
    query = (
        "index,name,uuid,compute_cap,memory.total,driver_version,"
        "clocks.max.sm,clocks.max.memory"
    )
    result = _run(
        [
            _tool("nvidia-smi"),
            f"--query-gpu={query}",
            "--format=csv,noheader,nounits",
        ],
        timeout=120,
    )
    fields = query.split(",")
    rows = csv.reader(result.stdout.splitlines(), skipinitialspace=True)
    devices = [dict(zip(fields, row, strict=True)) for row in rows if row]
    if not devices:
        raise ProfError("nvidia-smi reported no CUDA devices")
    return devices


def systems_trace(
    command: list[str],
    output: Path,
    *,
    timeout: int,
) -> Path:
    if output.exists():
        raise ProfError(f"refusing to overwrite profile artifact: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    target = output
    if target.suffix == ".nsys-rep":
        target = target.with_suffix("")
    _run(
        [
            _tool("nsys"),
            "profile",
            "--force-overwrite=false",
            "--sample=none",
            "--trace=cuda,nvtx,osrt",
            "--cuda-memory-usage=true",
            "--output",
            str(target),
            "--",
            *_command(command),
        ],
        timeout=timeout,
    )
    artifact = target.with_suffix(".nsys-rep")
    if not artifact.is_file():
        raise ProfError(f"Nsight Systems did not produce {artifact}")
    return artifact


def compute_profile(
    command: list[str],
    output: Path,
    *,
    kernel: str | None,
    set_name: str,
    launch_skip: int,
    launch_count: int,
    timeout: int,
) -> Path:
    if launch_skip < 0:
        raise ProfError("CUDA profile launch skip must be nonnegative")
    if launch_count <= 0:
        raise ProfError("CUDA profile launch count must be positive")
    if output.exists():
        raise ProfError(f"refusing to overwrite profile artifact: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    target = output
    if target.suffix == ".ncu-rep":
        target = target.with_suffix("")
    arguments = [
        _tool("ncu"),
        "--target-processes",
        "all",
        "--kernel-name-base",
        "demangled",
        "--replay-mode",
        "kernel",
        "--launch-skip",
        str(launch_skip),
        "--launch-count",
        str(launch_count),
        "--set",
        set_name,
        "--force-overwrite",
        "false",
        "--export",
        str(target),
    ]
    if kernel is not None:
        arguments.extend(["--kernel-name", f"regex:{kernel}"])
    arguments.extend(["--", *_command(command)])
    _run(arguments, timeout=timeout)
    artifact = target.with_suffix(".ncu-rep")
    if not artifact.is_file():
        raise ProfError(f"Nsight Compute did not produce {artifact}")
    return artifact


def load_stage_report(path: Path) -> dict:
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ProfError(f"cannot read CUDA proof report {path}: {error}") from error
    schema_version = report.get("schema_version")
    if schema_version not in (2, 3, 4, 5, 6) or report.get("backend") != "cuda":
        raise ProfError("input is not a CUDA proof report with stage timing")
    if schema_version == 6:
        plan = report.get("plan")
        semantic = plan.get("semantic_sha256") if isinstance(plan, dict) else None
        if (
            not isinstance(semantic, str)
            or len(semantic) != 64
            or any(byte not in "0123456789abcdef" for byte in semantic)
        ):
            raise ProfError("schema-v6 CUDA report has invalid semantic identity")
    timing = report.get("device_stage_timing_ns")
    if not isinstance(timing, dict) or not isinstance(timing.get("total"), int):
        raise ProfError("CUDA proof report has no device stage timing")
    return report
