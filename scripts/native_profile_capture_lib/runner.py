"""Bounded subprocess collectors for Native CPU and Metal profile lanes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if __package__.startswith("scripts."):
    from scripts.native_proof_matrix_lib.artifacts import (
        decode_report,
        lane_command,
        load_proof_artifact,
    )
    from scripts.native_proof_matrix_lib.model import Workload
else:
    from native_proof_matrix_lib.artifacts import (
        decode_report,
        lane_command,
        load_proof_artifact,
    )
    from native_proof_matrix_lib.model import Workload

from .evidence import write_bytes_exclusive
from .model import MAX_ARTIFACT_BYTES, CaptureError, CaptureSettings
from .sample_profile import build_sample_summary


ROOT = Path(
    os.environ.get("STWO_ZIG_EXECUTION_ROOT", Path(__file__).resolve().parents[2])
).resolve()
SAMPLE_BIN = Path("/usr/bin/sample")
METAL_REPORT_SCRIPT = ROOT / "scripts/metal_profile_report.py"


def _profile_command(
    binary: Path,
    workload: Workload,
    settings: CaptureSettings,
    proof_path: Path,
    *,
    metal: bool,
) -> list[str]:
    command = lane_command(
        binary,
        workload,
        settings.warmups,
        settings.samples,
        settings.protocol,
        proof_path,
        resource_profile="large",
        blake2_backend=settings.blake2_backend,
        metal_runtime=settings.metal_runtime if metal else None,
        metal_aot_bundle=settings.metal_aot_bundle,
        metal_aot_manifest_sha256=settings.metal_aot_manifest_sha256,
    )
    command.append("--profiled")
    return command


def _wait(process: subprocess.Popen[bytes], timeout: float, label: str) -> int:
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise CaptureError(f"{label} timed out after {timeout} seconds") from error


def _check_size(path: Path) -> None:
    if not path.is_file():
        raise CaptureError(f"expected profile artifact was not produced: {path}")
    if path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise CaptureError(f"profile artifact exceeds byte limit: {path}")


def _run_to_files(
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
    *,
    timeout: float,
    environment: dict[str, str],
    label: str,
) -> tuple[int, float]:
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        started = time.perf_counter()
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdout=stdout,
            stderr=stderr,
        )
        pid = process.pid
        returncode = _wait(process, timeout, label)
        elapsed = time.perf_counter() - started
    _check_size(stdout_path)
    _check_size(stderr_path)
    if returncode != 0:
        tail = stderr_path.read_bytes()[-4000:].decode("utf-8", errors="replace")
        raise CaptureError(f"{label} exited {returncode}; stderr tail:\n{tail}")
    return pid, elapsed


def run_cpu(
    binary: Path,
    workload: Workload,
    settings: CaptureSettings,
    lane_dir: Path,
) -> dict[str, Any]:
    if not SAMPLE_BIN.is_file() or not os.access(SAMPLE_BIN, os.X_OK):
        raise CaptureError("CPU profiler acceptance requires executable /usr/bin/sample")
    proof_path = lane_dir / "proof-artifact.json"
    stdout_path = lane_dir / "stdout.json"
    stderr_path = lane_dir / "stderr.txt"
    sample_path = lane_dir / "cpu.sample.txt"
    sample_stdout_path = lane_dir / "sample.stdout.txt"
    sample_stderr_path = lane_dir / "sample.stderr.txt"
    summary_path = lane_dir / "sample-summary.json"
    command = _profile_command(binary, workload, settings, proof_path, metal=False)
    environment = {**os.environ, "LC_ALL": "C"}
    lane_dir.mkdir(parents=True, exist_ok=True)
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        started = time.perf_counter()
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=environment,
            stdout=stdout,
            stderr=stderr,
        )
        sample_command = [
            str(SAMPLE_BIN),
            str(process.pid),
            str(settings.sample_duration_seconds),
            "-mayDie",
            "-file",
            str(sample_path),
        ]
        try:
            sampled = subprocess.run(
                sample_command,
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=settings.sample_duration_seconds + 30,
                check=False,
            )
            returncode = _wait(process, settings.timeout_seconds, "CPU profile lane")
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait()
            raise
        elapsed = time.perf_counter() - started
    write_bytes_exclusive(sample_stdout_path, sampled.stdout)
    write_bytes_exclusive(sample_stderr_path, sampled.stderr)
    for path in (stdout_path, stderr_path, sample_stdout_path, sample_stderr_path):
        _check_size(path)
    if sampled.returncode != 0:
        tail = sampled.stderr[-4000:].decode("utf-8", errors="replace")
        raise CaptureError(f"macOS sample exited {sampled.returncode}; stderr tail:\n{tail}")
    if returncode != 0:
        tail = stderr_path.read_bytes()[-4000:].decode("utf-8", errors="replace")
        raise CaptureError(f"CPU profile lane exited {returncode}; stderr tail:\n{tail}")
    _check_size(sample_path)
    sample_summary = build_sample_summary(sample_path)
    write_bytes_exclusive(
        summary_path,
        (json.dumps(sample_summary, indent=2, sort_keys=True) + "\n").encode(),
    )
    return {
        "lane": "cpu",
        "pid": process.pid,
        "command": command,
        "environment": {},
        "sample_command": sample_command,
        "process_wall_seconds": elapsed,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "proof_path": proof_path,
        "sample_path": sample_path,
        "sample_stdout_path": sample_stdout_path,
        "sample_stderr_path": sample_stderr_path,
        "sample_summary_path": summary_path,
        "sample_summary": sample_summary,
        "report": decode_report(stdout_path.read_bytes(), "cpu"),
        "proof_artifact": load_proof_artifact(proof_path, "cpu"),
    }


def run_metal(
    binary: Path,
    workload: Workload,
    settings: CaptureSettings,
    lane_dir: Path,
    *,
    counter_mode: str,
) -> dict[str, Any]:
    proof_path = lane_dir / "proof-artifact.json"
    stdout_path = lane_dir / "stdout.json"
    stderr_path = lane_dir / "stderr.txt"
    ndjson_path = lane_dir / "metal-profile.ndjson"
    aggregate_path = lane_dir / "metal-profile-aggregate.json"
    aggregate_stdout = lane_dir / "aggregate.stdout.txt"
    aggregate_stderr = lane_dir / "aggregate.stderr.txt"
    command = _profile_command(binary, workload, settings, proof_path, metal=True)
    overrides = {
        "STWO_ZIG_METAL_PROFILE_OUT": str(ndjson_path),
        "STWO_ZIG_METAL_PROFILE_ENCODER_COUNTERS": (
            "1" if counter_mode == "encoder-timestamps" else "0"
        ),
        "STWO_ZIG_METAL_PROFILE_MAX_ENCODERS": str(settings.metal_max_encoders),
    }
    environment = {**os.environ, "LC_ALL": "C", **overrides}
    pid, elapsed = _run_to_files(
        command,
        stdout_path,
        stderr_path,
        timeout=settings.timeout_seconds,
        environment=environment,
        label="Metal profile lane",
    )
    _check_size(ndjson_path)
    aggregate_command = [
        sys.executable,
        str(METAL_REPORT_SCRIPT),
        str(ndjson_path),
        "--json-out",
        str(aggregate_path),
        "--strict",
    ]
    _run_to_files(
        aggregate_command,
        aggregate_stdout,
        aggregate_stderr,
        timeout=60.0,
        environment={**os.environ, "LC_ALL": "C"},
        label="Metal profile aggregation",
    )
    _check_size(aggregate_path)
    return {
        "lane": "metal",
        "pid": pid,
        "command": command,
        "environment": overrides,
        "aggregate_command": aggregate_command,
        "counter_mode": counter_mode,
        "process_wall_seconds": elapsed,
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "proof_path": proof_path,
        "metal_profile_path": ndjson_path,
        "metal_aggregate_path": aggregate_path,
        "aggregate_stdout_path": aggregate_stdout,
        "aggregate_stderr_path": aggregate_stderr,
        "report": decode_report(stdout_path.read_bytes(), "metal"),
        "proof_artifact": load_proof_artifact(proof_path, "metal"),
    }
