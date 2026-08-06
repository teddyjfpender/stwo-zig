"""Strict subprocess and one-line JSON boundary for the H-010 child runner."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .cohort import SampleFailure
from .contract import (
    ARMS,
    BENCHMARK_ID,
    DIRECT_ROOTS,
    SAMPLE_SCHEMA,
    ContractError,
    decode_one_line_json,
    validate_sample,
)


CHECK_KEYS = frozenset(
    {
        "schema",
        "schema_version",
        "benchmark",
        "command",
        "status",
        "arms",
        "correctness_log_sizes",
        "measurement_logs_checked",
        "direct_roots_checked_per_row",
        "rss_probe_allocated_bytes",
        "rss_probe_delta_bytes",
        "rss_probe_source",
        "proof_executed",
        "metal_candidate_execution_supported",
        "production_layout_changed",
    }
)


class ChildResult:
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


ChildRunner = Callable[
    [Sequence[str], Path, float, Mapping[str, str]],
    ChildResult,
]


def child_environment() -> dict[str, str]:
    return {"LC_ALL": "C", "LANG": "C", "TZ": "UTC"}


def default_child_runner(
    command: Sequence[str],
    cwd: Path,
    timeout_seconds: float,
    environment: Mapping[str, str],
) -> ChildResult:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=dict(environment),
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise SampleFailure(
            "child-timeout",
            f"child exceeded the {timeout_seconds:g}-second timeout",
        ) from error
    except OSError as error:
        raise SampleFailure("child-launch-error", f"could not launch child: {error}") from error
    return ChildResult(completed.returncode, completed.stdout, completed.stderr)


def _invoke(
    executable: Path,
    repo_root: Path,
    timeout_seconds: float,
    command: Sequence[str],
    child_runner: ChildRunner,
) -> ChildResult:
    try:
        result = child_runner(
            command,
            repo_root,
            timeout_seconds,
            child_environment(),
        )
    except SampleFailure:
        raise
    except Exception as error:
        raise SampleFailure(
            "child-runner-error",
            f"child runner raised {type(error).__name__}: {error}",
        ) from error
    if not isinstance(result, ChildResult):
        raise SampleFailure("child-runner-contract", "child runner returned the wrong type")
    if type(result.returncode) is not int or result.returncode != 0:
        raise SampleFailure("child-nonzero-exit", f"child exit={result.returncode!r}")
    if result.stderr:
        raise SampleFailure("child-stderr", f"child stderr={result.stderr[:160]!r}")
    return result


def validate_check(raw: bytes) -> dict[str, object]:
    try:
        check = decode_one_line_json(raw)
    except ContractError as error:
        raise SampleFailure("preflight-schema", str(error)) from error
    return validate_check_object(check)


def validate_check_object(check: dict[str, object]) -> dict[str, object]:
    """Validate an already decoded check record for final-report replay."""

    actual_keys = frozenset(check)
    if actual_keys != CHECK_KEYS:
        missing = sorted(CHECK_KEYS - actual_keys)
        unknown = sorted(actual_keys - CHECK_KEYS)
        raise SampleFailure(
            "preflight-schema",
            f"check key set mismatch; missing={missing}, unknown={unknown}",
        )
    expected = {
        "schema": SAMPLE_SCHEMA,
        "schema_version": 1,
        "benchmark": BENCHMARK_ID,
        "command": "check",
        "status": "passed",
        "arms": len(ARMS),
        "correctness_log_sizes": [4, 6],
        "measurement_logs_checked": [10, 14],
        "direct_roots_checked_per_row": DIRECT_ROOTS,
        "rss_probe_allocated_bytes": 64 * 1024 * 1024,
        "proof_executed": False,
        "metal_candidate_execution_supported": False,
        "production_layout_changed": False,
    }
    for key, value in expected.items():
        if type(check[key]) is not type(value) or check[key] != value:
            raise SampleFailure(
                "preflight-identity",
                f"check field {key} must equal {value!r}",
            )
    delta = check["rss_probe_delta_bytes"]
    if type(delta) is not int or delta < 32 * 1024 * 1024:
        raise SampleFailure(
            "preflight-rss-probe",
            "check RSS probe delta is missing or below half the touched allocation",
        )
    if check["rss_probe_source"] not in {
        "getrusage-self-maxrss-native-bytes",
        "getrusage-self-maxrss-kib-normalized-bytes",
    }:
        raise SampleFailure("preflight-rss-probe", "check RSS source is unsupported")
    return check


def run_preflight(
    executable: Path,
    repo_root: Path,
    timeout_seconds: float,
    child_runner: ChildRunner,
) -> dict[str, object]:
    result = _invoke(
        executable,
        repo_root,
        timeout_seconds,
        (str(executable), "check"),
        child_runner,
    )
    return validate_check(result.stdout)


def run_sample(
    executable: Path,
    repo_root: Path,
    timeout_seconds: float,
    arm: str,
    log_size: int,
    child_runner: ChildRunner,
) -> dict[str, object]:
    result = _invoke(
        executable,
        repo_root,
        timeout_seconds,
        (str(executable), "sample", arm, str(log_size)),
        child_runner,
    )
    try:
        return validate_sample(
            result.stdout,
            expected_arm=arm,
            expected_log=log_size,
        )
    except ContractError as error:
        raise SampleFailure("sample-contract", str(error)) from error
