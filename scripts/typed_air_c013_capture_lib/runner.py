"""Serial fresh-process executor for one immutable C-013 CPU capture plan."""

from __future__ import annotations

import datetime as dt
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .child_report import command_for_attempt, validate_child_report
from .codec import (
    canonical_bytes,
    content_digest,
    sha256_bytes,
    sha256_file,
    write_new,
)
from .journal import AttemptJournal
from .model import CaptureError, ENVIRONMENT
from .plan import load_and_validate_plan, validate_plan
from .provenance import host_identity
from .statistics import evaluate_calibration, evaluate_m6_cpu


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class AttemptLaunchError(CaptureError):
    def __init__(self, code: str, message: str, stdout: bytes = b"", stderr: bytes = b""):
        super().__init__(message)
        self.code = code
        self.stdout = stdout
        self.stderr = stderr


@dataclass(frozen=True)
class CaptureSettings:
    repository: Path
    plan_path: Path
    bundle_path: Path
    timeout_seconds: float = 86_400.0


ChildRunner = Callable[[Sequence[str], Path, float, Mapping[str, str]], ProcessResult]
Sleeper = Callable[[float], None]
Monotonic = Callable[[], int]
UtcClock = Callable[[], dt.datetime]


def default_child_runner(
    command: Sequence[str],
    cwd: Path,
    timeout_seconds: float,
    environment: Mapping[str, str],
) -> ProcessResult:
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as error:
        raise AttemptLaunchError(
            "child-timeout",
            f"child exceeded {timeout_seconds:g} seconds",
            error.stdout or b"",
            error.stderr or b"",
        ) from error
    except OSError as error:
        raise AttemptLaunchError("child-launch", f"could not launch child: {error}") from error
    return ProcessResult(result.returncode, result.stdout, result.stderr)


def _utc(clock: UtcClock) -> str:
    value = clock()
    if value.tzinfo is None:
        raise CaptureError("capture clock returned a naive timestamp")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def run_attempt(
    *,
    repository: Path,
    plan: dict[str, Any],
    attempt: dict[str, Any],
    timeout_seconds: float,
    child_runner: ChildRunner = default_child_runner,
    monotonic: Monotonic = time.monotonic_ns,
    utc_clock: UtcClock = lambda: dt.datetime.now(dt.timezone.utc),
) -> tuple[dict[str, Any], bytes, bytes, dict[str, Any] | None]:
    command = command_for_attempt(plan, attempt)
    command_sha256 = sha256_bytes(canonical_bytes(list(command)))
    started_at = _utc(utc_clock)
    started_ns = monotonic()
    result: ProcessResult | None = None
    failure_code: str | None = None
    report: dict[str, Any] | None = None
    try:
        result = child_runner(command, repository, timeout_seconds, ENVIRONMENT)
        if not isinstance(result, ProcessResult):
            raise AttemptLaunchError("runner-contract", "child runner returned wrong type")
        if result.returncode != 0:
            failure_code = "child-nonzero-exit"
        elif result.stderr:
            failure_code = "child-stderr"
        else:
            try:
                report = validate_child_report(result.stdout, plan=plan, attempt=attempt)
            except CaptureError:
                failure_code = "child-report-invalid"
    except AttemptLaunchError as error:
        failure_code = error.code
        result = ProcessResult(-1, error.stdout, error.stderr)
    completed_ns = monotonic()
    if completed_ns < started_ns:
        raise CaptureError("capture monotonic clock regressed")
    assert result is not None
    record = {
        "schema": "stwo.typed-air.c013-attempt-result.v1",
        "global_ordinal": attempt["global_ordinal"],
        "kind": attempt["kind"],
        "sample_index": attempt["sample_index"],
        "status": "verified" if report is not None else "failed",
        "failure_code": failure_code,
        "started_at_utc": started_at,
        "completed_at_utc": _utc(utc_clock),
        "launcher_elapsed_ns": completed_ns - started_ns,
        "child_exit_code": result.returncode,
        "command_sha256": command_sha256,
        "report_sha256": sha256_bytes(result.stdout) if report is not None else None,
    }
    return record, result.stdout, result.stderr, report


def _calibration_failure(valid: int) -> dict[str, Any]:
    return {
        "schema": "stwo.typed-air.c013-aa-admission.v1",
        "attempts": 80,
        "verified_attempts": valid,
        "verdict": "NO_VERDICT",
        "reason": "one or more A/A children failed before statistical admission",
    }


def capture(
    settings: CaptureSettings,
    *,
    child_runner: ChildRunner = default_child_runner,
    sleeper: Sleeper = time.sleep,
    monotonic: Monotonic = time.monotonic_ns,
    utc_clock: UtcClock = lambda: dt.datetime.now(dt.timezone.utc),
) -> dict[str, Any]:
    if settings.timeout_seconds <= 0:
        raise CaptureError("child timeout must be positive")
    repository = settings.repository.resolve()
    plan = load_and_validate_plan(
        settings.plan_path,
        repository=repository,
        verify_local=True,
    )
    power = plan["host"]["power_state"]["operator_declaration"]
    if host_identity(power) != plan["host"]:
        raise CaptureError("capture host identity changed after planning")
    plan_bytes = settings.plan_path.read_bytes()
    calibration_captures: list[tuple[dict[str, Any], dict[str, Any]]] = []
    m6_captures: list[
        tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
    ] = []
    calibration: dict[str, Any] | None = None
    cpu_reduction: dict[str, Any] | None = None
    cpu_reduction_identity: dict[str, Any] | None = None
    verified = 0
    failed = 0
    recorded = 0
    started_at = _utc(utc_clock)

    journal = AttemptJournal(settings.bundle_path, plan, plan_bytes)
    try:
        for attempt in plan["attempts"]:
            record, stdout, stderr, report = run_attempt(
                repository=repository,
                plan=plan,
                attempt=attempt,
                timeout_seconds=settings.timeout_seconds,
                child_runner=child_runner,
                monotonic=monotonic,
                utc_clock=utc_clock,
            )
            record["streams"] = journal.retain_attempt_streams(
                attempt["global_ordinal"], stdout, stderr
            )
            journal.append(record)
            recorded += 1
            if report is None:
                failed += 1
            else:
                verified += 1
                if attempt["kind"] == "calibration":
                    calibration_captures.append((attempt, report))
                else:
                    m6_captures.append((attempt, record, report))

            if attempt["global_ordinal"] + 1 < len(plan["attempts"]):
                sleeper(plan["schedule"]["cooldown_ns"] / 1_000_000_000)

            if attempt["global_ordinal"] == 79:
                calibration = (
                    evaluate_calibration(repository, plan, calibration_captures)
                    if len(calibration_captures) == 80
                    else _calibration_failure(len(calibration_captures))
                )
                calibration_bytes = canonical_bytes(calibration)
                write_new(journal.bundle / "calibration.json", calibration_bytes)
                journal.append(
                    {
                        "schema": "stwo.typed-air.c013-aa-admission-record.v1",
                        "verdict": calibration["verdict"],
                        "artifact": {
                            "path": "calibration.json",
                            "bytes": len(calibration_bytes),
                            "sha256": sha256_bytes(calibration_bytes),
                        },
                    }
                )
                if calibration["verdict"] != "PASS":
                    break

        if recorded == len(plan["attempts"]) and failed == 0:
            cpu_reduction = evaluate_m6_cpu(repository, plan, m6_captures)
            cpu_reduction_bytes = canonical_bytes(cpu_reduction)
            write_new(journal.bundle / "cpu-reduction.json", cpu_reduction_bytes)
            cpu_reduction_identity = {
                "path": "cpu-reduction.json",
                "bytes": len(cpu_reduction_bytes),
                "sha256": sha256_bytes(cpu_reduction_bytes),
                "verdict": cpu_reduction["verdict"],
            }

        validate_plan(
            plan,
            repository=repository,
            verify_local=True,
        )
        if host_identity(power) != plan["host"]:
            raise CaptureError("capture host identity drifted during execution")
        journal_identity = journal.close()
    except BaseException:
        journal.abandon()
        raise

    if calibration is None or calibration["verdict"] != "PASS":
        status = "NO_VERDICT_AA_ADMISSION"
    elif recorded != len(plan["attempts"]):
        status = "INCOMPLETE"
    elif failed:
        status = "CAPTURE_COMPLETE_WITH_FAILURES"
    else:
        status = "CAPTURE_COMPLETE_AWAITING_RECEIPT_VALIDATION"
    calibration_size, calibration_sha = sha256_file(journal.bundle / "calibration.json")
    final = {
        "schema": "stwo.typed-air.c013-capture-bundle.v1",
        "status": status,
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "started_at_utc": started_at,
        "completed_at_utc": _utc(utc_clock),
        "planned_attempts": len(plan["attempts"]),
        "recorded_attempts": recorded,
        "verified_attempts": verified,
        "failed_attempts": failed,
        "journal": journal_identity,
        "calibration": {
            "path": "calibration.json",
            "bytes": calibration_size,
            "sha256": calibration_sha,
            "verdict": calibration["verdict"],
        },
        "cpu_reduction": cpu_reduction_identity,
        "performance_verdict": None,
    }
    final["content_sha256"] = content_digest(final)
    write_new(journal.bundle / "bundle.json", canonical_bytes(final))
    return final
