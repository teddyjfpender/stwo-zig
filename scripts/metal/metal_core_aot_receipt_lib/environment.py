"""Process, repository, host, and CI identity evidence."""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

from .artifacts import sha256_bytes
from .model import COMMIT_RE, DECIMAL_RE, ReceiptError

ROOT = Path(
    os.environ.get("STWO_ZIG_EXECUTION_ROOT", Path(__file__).resolve().parents[2])
).resolve()


def run(command: list[str], *, cwd: Path = ROOT) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)
    evidence = {
        "argv": command,
        "returncode": completed.returncode,
        "stdout_sha256": sha256_bytes(completed.stdout.encode()),
        "stderr_sha256": sha256_bytes(completed.stderr.encode()),
    }
    if completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, end="", file=sys.stderr)
        if completed.stderr:
            print(completed.stderr, end="", file=sys.stderr)
        raise ReceiptError(f"acceptance command failed: {command}")
    return evidence


def command_output(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError:
        return "unavailable"
    if completed.returncode != 0:
        return "unavailable"
    return (completed.stdout or completed.stderr).strip() or "unavailable"


def exact_commit(value: str | None) -> str:
    commit = value or command_output(["git", "rev-parse", "HEAD"])
    if COMMIT_RE.fullmatch(commit) is None:
        raise ReceiptError("receipt requires an exact lowercase 40-character commit")
    return commit


def host_identity(*, include_metal_device: bool) -> dict[str, Any]:
    identity = {
        "platform": platform.platform(),
        "macos": command_output(["sw_vers"]),
        "machine": platform.machine(),
    }
    if include_metal_device:
        identity["metal_device"] = command_output(
            ["system_profiler", "SPDisplaysDataType", "-json", "-detailLevel", "mini"]
        )
    return identity


def ci_identity() -> dict[str, str | None]:
    return {
        key: os.environ.get(key)
        for key in ("GITHUB_ACTIONS", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
    }


def require_hosted_ci_identity(ci: Any) -> None:
    if not isinstance(ci, dict):
        raise ReceiptError("hosted build receipt CI identity is missing")
    if ci.get("GITHUB_ACTIONS") != "true":
        raise ReceiptError("hosted build receipt is not from GitHub Actions")
    for field in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = ci.get(field)
        if not isinstance(value, str) or DECIMAL_RE.fullmatch(value) is None:
            raise ReceiptError(f"hosted build receipt has invalid {field}")
    if ci.get("GITHUB_JOB") != "metal-acceptance":
        raise ReceiptError("hosted build receipt job mismatch")
