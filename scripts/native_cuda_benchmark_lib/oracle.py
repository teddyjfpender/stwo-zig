"""Pinned Rust-oracle execution for Native CUDA benchmark artifacts."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any

from scripts.native_cuda_diagnostic_lib.model import (
    MAX_REPORT_BYTES,
    MAX_STDERR_BYTES,
)

from .model import BenchmarkError, Settings, Workload


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rust_oracle_receipt(
    settings: Settings,
    workload: Workload,
    artifact_path: Path,
) -> dict[str, Any]:
    if settings.rust_oracle_bin is None:
        return {
            "accepted": False,
            "reason": "pinned Rust oracle was not configured",
        }
    oracle = settings.rust_oracle_bin.resolve()
    if not oracle.is_file() or not os.access(oracle, os.X_OK):
        raise BenchmarkError(f"Rust oracle is not executable: {oracle}")
    oracle_sha256 = _sha256_file(oracle)
    if oracle_sha256 != settings.rust_oracle_sha256:
        raise BenchmarkError("CUDA Rust oracle binary differs from its SHA-256 pin")
    completed = subprocess.run(
        [
            str(oracle),
            "--mode",
            "verify",
            "--artifact",
            str(artifact_path),
        ],
        cwd=settings.repo_root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=settings.timeout_seconds,
        check=False,
    )
    if len(completed.stdout) > MAX_REPORT_BYTES:
        raise BenchmarkError("CUDA Rust oracle stdout exceeds the capture bound")
    if len(completed.stderr) > MAX_STDERR_BYTES:
        raise BenchmarkError("CUDA Rust oracle stderr exceeds the capture bound")
    if completed.returncode != 0:
        tail = completed.stderr[-4000:].decode("utf-8", errors="replace")
        raise BenchmarkError(
            f"{workload.workload_id} was rejected by the pinned Rust oracle; "
            f"stderr tail:\n{tail}"
        )
    if _sha256_file(oracle) != oracle_sha256:
        raise BenchmarkError("CUDA Rust oracle binary changed during verification")
    return {
        "accepted": True,
        "authority": "pinned-rust-stwo",
        "upstream_commit": (
            "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
        ),
        "oracle_binary_sha256": oracle_sha256,
        "artifact_sha256": _sha256_file(artifact_path),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }
