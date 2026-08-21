"""Fresh-process R-006 capture and independent raw-bundle validation."""

from __future__ import annotations

import datetime as dt
import os
import resource
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from .bundle_snapshot import attach_validation_snapshot
from .codec import (
    canonical_bytes,
    content_digest,
    decode_strict,
    exact_object,
    sha256_bytes,
    sha256_file,
    write_new,
)
from .contract import host_identity, load_plan, validate_plan
from .model import (
    BUNDLE_SCHEMA,
    DIGEST_RE,
    ENVIRONMENT,
    MAX_STREAM_BYTES,
    UTC_RE,
    CaptureError,
)
from .receipt import validate_receipt
from .report import validate_report
from .workload_profile import is_guest_workload, workload_for_attempt


JOURNAL_HEADER_SCHEMA = "stwo.typed-air.r006-journal-header.v1"
ATTEMPT_RESULT_SCHEMA = "stwo.typed-air.r006-attempt-result.v1"
FILE_FIELDS = {"path", "bytes", "sha256"}
ATTEMPT_RESULT_FIELDS = {
    "schema",
    "ordinal",
    "attempt_id",
    "status",
    "failure_code",
    "failure_detail",
    "started_at_utc",
    "completed_at_utc",
    "launcher_elapsed_ns",
    "process_cpu_ns",
    "child_exit_code",
    "command_sha256",
    "streams",
    "proof",
    "identity",
    "metrics",
    "independent_verification",
    "content_sha256",
}
VERIFY_FIELDS = {
    "status",
    "failure_code",
    "launcher_elapsed_ns",
    "process_cpu_ns",
    "child_exit_code",
    "command_sha256",
    "stdout",
    "stderr",
}
BUNDLE_FIELDS = {
    "schema",
    "schema_version",
    "status",
    "session_id",
    "plan_sha256",
    "started_at_utc",
    "completed_at_utc",
    "planned_attempts",
    "recorded_attempts",
    "verified_attempts",
    "failed_attempts",
    "journal",
    "content_sha256",
}


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    process_cpu_ns: int


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


def _rusage_cpu_ns(value: resource.struct_rusage) -> int:
    return int(round((value.ru_utime + value.ru_stime) * 1_000_000_000))


def default_child_runner(
    command: Sequence[str],
    cwd: Path,
    timeout_seconds: float,
    environment: Mapping[str, str],
) -> ProcessResult:
    before = resource.getrusage(resource.RUSAGE_CHILDREN)
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
        raise CaptureError(
            f"child-timeout: process exceeded {timeout_seconds:g}s; "
            f"stdout={len(error.stdout or b'')} bytes stderr={len(error.stderr or b'')} bytes"
        ) from error
    except OSError as error:
        raise CaptureError(f"child-launch: {error}") from error
    after = resource.getrusage(resource.RUSAGE_CHILDREN)
    process_cpu_ns = _rusage_cpu_ns(after) - _rusage_cpu_ns(before)
    if process_cpu_ns < 0:
        raise CaptureError("child process CPU counter regressed")
    if len(result.stdout) > MAX_STREAM_BYTES or len(result.stderr) > MAX_STREAM_BYTES:
        raise CaptureError("child output exceeds the retained-stream limit")
    return ProcessResult(result.returncode, result.stdout, result.stderr, process_cpu_ns)


def _utc(clock: UtcClock) -> str:
    value = clock()
    if value.tzinfo is None:
        raise CaptureError("capture clock returned a naive timestamp")
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def proof_command(plan: dict[str, Any], attempt: dict[str, Any]) -> tuple[str, ...]:
    workload = workload_for_attempt(plan, attempt)
    is_guest_workload(workload)
    arguments = [
        plan["build"]["executable_path"],
        "bench",
        "--elf",
        workload["elf"]["path"],
    ]
    if workload["input"] is not None:
        arguments.extend(("--input", workload["input"]["path"]))
    arguments.extend(
        (
            "--backend",
            plan["lane"]["cli_backend"],
            "--protocol",
            "secure",
            "--warmups",
            "0",
            "--samples",
            "1",
            "--profiled",
            "--proof-out",
            attempt["proof_path"],
        )
    )
    return tuple(arguments)


def verify_command(
    plan: dict[str, Any], attempt: dict[str, Any], statement_sha256: str
) -> tuple[str, ...]:
    workload = workload_for_attempt(plan, attempt)
    arguments = [
        plan["build"]["executable_path"],
        "verify",
        "--artifact",
        attempt["proof_path"],
        "--elf",
        workload["elf"]["path"],
    ]
    if is_guest_workload(workload):
        arguments.extend(("--input", workload["input"]["path"]))
    arguments.extend(
        (
            "--protocol",
            "secure",
            "--expect-statement-digest",
            statement_sha256,
        )
    )
    return tuple(arguments)


def _command_digest(command: Sequence[str]) -> str:
    return sha256_bytes(canonical_bytes(list(command)))


def _identity(path: Path, relative: str) -> dict[str, Any]:
    size, digest = sha256_file(path)
    return {"path": relative, "bytes": size, "sha256": digest}


class Journal:
    def __init__(self, bundle: Path, plan: dict[str, Any], plan_bytes: bytes):
        self.bundle = bundle.resolve()
        try:
            self.bundle.mkdir(mode=0o700, parents=False, exist_ok=False)
        except OSError as error:
            raise CaptureError(f"cannot create exclusive capture bundle: {self.bundle}") from error
        write_new(self.bundle / "plan.json", plan_bytes)
        (self.bundle / "attempts").mkdir(mode=0o700)
        self.path = self.bundle / "journal.ndjson"
        try:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as error:
            raise CaptureError("cannot create R-006 journal") from error
        self.output = os.fdopen(descriptor, "wb", buffering=0)
        self.closed = False
        self.records = 0
        self.append(
            {
                "schema": JOURNAL_HEADER_SCHEMA,
                "session_id": plan["session_id"],
                "plan_sha256": plan["content_sha256"],
                "planned_attempts": len(plan["attempts"]),
            }
        )

    def append(self, value: dict[str, Any]) -> dict[str, Any]:
        if self.closed:
            raise CaptureError("R-006 journal is already closed")
        record = dict(value)
        record["content_sha256"] = content_digest(record)
        try:
            self.output.write(canonical_bytes(record))
            os.fsync(self.output.fileno())
        except OSError as error:
            raise CaptureError("cannot durably append R-006 journal") from error
        self.records += 1
        return record

    def retain(self, relative: str, raw: bytes) -> dict[str, Any]:
        write_new(self.bundle / relative, raw)
        return _identity(self.bundle / relative, relative)

    def close(self) -> dict[str, Any]:
        if self.closed:
            raise CaptureError("R-006 journal closed twice")
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.closed = True
        size, digest = sha256_file(self.path)
        return {
            "path": "journal.ndjson",
            "bytes": size,
            "sha256": digest,
            "records": self.records,
        }

    def abandon(self) -> None:
        if self.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
        finally:
            self.closed = True


def _environment(plan: dict[str, Any], workers: int) -> dict[str, str]:
    result = dict(plan["environment"])
    result["STWO_ZIG_WORKERS"] = str(workers)
    result["STWO_ZIG_MERKLE_WORKERS"] = str(workers)
    # Deliberately absent: the production PoW lane reuses the request's proof
    # pool. An independent STWO_ZIG_POW_WORKERS width would oversubscribe the
    # host and invalidate the worker-scaling comparison.
    result.pop("STWO_ZIG_POW_WORKERS", None)
    return result


def _run_process(
    command: Sequence[str],
    *,
    bundle: Path,
    timeout_seconds: float,
    environment: Mapping[str, str],
    child_runner: ChildRunner,
    monotonic: Monotonic,
) -> tuple[ProcessResult, int]:
    started = monotonic()
    result = child_runner(command, bundle, timeout_seconds, environment)
    completed = monotonic()
    if not isinstance(result, ProcessResult):
        raise CaptureError("child runner returned an invalid result")
    if completed < started:
        raise CaptureError("capture monotonic clock regressed")
    if result.process_cpu_ns < 0:
        raise CaptureError("child runner returned negative process CPU work")
    return result, completed - started


def run_attempt(
    *,
    journal: Journal,
    plan: dict[str, Any],
    attempt: dict[str, Any],
    timeout_seconds: float,
    child_runner: ChildRunner,
    monotonic: Monotonic,
    utc_clock: UtcClock,
    record_stager: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    command = proof_command(plan, attempt)
    started_at = _utc(utc_clock)
    result: ProcessResult | None = None
    elapsed_ns = 0
    identity: dict[str, Any] | None = None
    metrics: dict[str, Any] | None = None
    failure_code: str | None = None
    failure_detail: str | None = None
    try:
        result, elapsed_ns = _run_process(
            command,
            bundle=journal.bundle,
            timeout_seconds=timeout_seconds,
            environment=_environment(plan, attempt["worker_count"]),
            child_runner=child_runner,
            monotonic=monotonic,
        )
    except CaptureError as error:
        result = ProcessResult(-1, b"", str(error).encode("utf-8")[:4096], 0)
        failure_code = "child-launch"
        failure_detail = str(error)[:1024]
    report_identity = journal.retain(attempt["report_path"], result.stdout)
    stderr_identity = journal.retain(attempt["stderr_path"], result.stderr)
    proof_path = journal.bundle / attempt["proof_path"]
    proof_identity: dict[str, Any] | None = None
    if proof_path.is_file() and not proof_path.is_symlink():
        proof_identity = _identity(proof_path, attempt["proof_path"])
    if failure_code is None:
        if result.returncode != 0:
            failure_code = "child-nonzero-exit"
            failure_detail = f"proof child exited {result.returncode}"
        elif result.stderr:
            failure_code = "child-stderr"
            failure_detail = "proof child wrote stderr"
        elif proof_identity is None:
            failure_code = "proof-missing"
            failure_detail = "proof child did not publish its artifact"
        else:
            try:
                identity, metrics = validate_report(
                    result.stdout,
                    plan=plan,
                    attempt=attempt,
                    proof_path=proof_path,
                )
            except CaptureError as error:
                failure_code = "profile-report-invalid"
                failure_detail = str(error)[:1024]

    verify_stdout = b""
    verify_stderr = b""
    verification: dict[str, Any]
    if failure_code is None:
        assert identity is not None
        verifier_command = verify_command(plan, attempt, identity["statement_sha256"])
        try:
            verify_result, verify_elapsed = _run_process(
                verifier_command,
                bundle=journal.bundle,
                timeout_seconds=timeout_seconds,
                environment=_environment(plan, attempt["worker_count"]),
                child_runner=child_runner,
                monotonic=monotonic,
            )
            verify_stdout = verify_result.stdout
            verify_stderr = verify_result.stderr
            verify_failure = None
            verify_failure_detail = None
            if verify_result.returncode != 0:
                verify_failure = "verifier-nonzero-exit"
            elif verify_stderr:
                verify_failure = "verifier-output"
                verify_failure_detail = "independent verifier wrote stderr"
            else:
                try:
                    validate_receipt(
                        verify_stdout,
                        plan=plan,
                        attempt=attempt,
                        identity=identity,
                    )
                except CaptureError as error:
                    verify_failure = "verifier-receipt-invalid"
                    verify_failure_detail = str(error)[:1024]
            verification = {
                "status": "verified" if verify_failure is None else "failed",
                "failure_code": verify_failure,
                "launcher_elapsed_ns": verify_elapsed,
                "process_cpu_ns": verify_result.process_cpu_ns,
                "child_exit_code": verify_result.returncode,
                "command_sha256": _command_digest(verifier_command),
            }
            if verify_failure is not None:
                failure_code = verify_failure
                failure_detail = verify_failure_detail or (
                    "independent verifier did not accept the retained proof"
                )
        except CaptureError as error:
            verification = {
                "status": "failed",
                "failure_code": "verifier-launch",
                "launcher_elapsed_ns": 0,
                "process_cpu_ns": 0,
                "child_exit_code": -1,
                "command_sha256": _command_digest(verifier_command),
            }
            verify_stderr = str(error).encode("utf-8")[:4096]
            failure_code = "verifier-launch"
            failure_detail = str(error)[:1024]
    else:
        verification = {
            "status": "skipped",
            "failure_code": "proof-attempt-failed",
            "launcher_elapsed_ns": 0,
            "process_cpu_ns": 0,
            "child_exit_code": None,
            "command_sha256": None,
        }
    verification["stdout"] = journal.retain(attempt["verify_stdout_path"], verify_stdout)
    verification["stderr"] = journal.retain(attempt["verify_stderr_path"], verify_stderr)
    record = {
        "schema": ATTEMPT_RESULT_SCHEMA,
        "ordinal": attempt["ordinal"],
        "attempt_id": attempt["attempt_id"],
        "status": "verified" if failure_code is None else "failed",
        "failure_code": failure_code,
        "failure_detail": failure_detail,
        "started_at_utc": started_at,
        "completed_at_utc": _utc(utc_clock),
        "launcher_elapsed_ns": elapsed_ns,
        "process_cpu_ns": result.process_cpu_ns,
        "child_exit_code": result.returncode,
        "command_sha256": _command_digest(command),
        "streams": {"report": report_identity, "stderr": stderr_identity},
        "proof": proof_identity,
        "identity": identity,
        "metrics": metrics,
        "independent_verification": verification,
    }
    if record_stager is not None:
        record_stager(record)
    return record


def _identity_consistent(records: list[dict[str, Any]], plan: dict[str, Any]) -> bool:
    expected: dict[str, dict[str, Any]] = {}
    for attempt, record in zip(plan["attempts"], records, strict=True):
        if record["status"] != "verified":
            continue
        workload = attempt["workload_id"]
        identity = record["identity"]
        prior = expected.setdefault(workload, identity)
        if identity != prior:
            return False
    return True


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
    plan = load_plan(settings.plan_path, repository=repository, verify_local=True)
    power_declaration = plan["host"]["power_state"]["operator_declaration"]
    if host_identity(power_declaration) != plan["host"]:
        raise CaptureError("capture host identity changed after planning")
    plan_bytes = settings.plan_path.read_bytes()
    started_at = _utc(utc_clock)
    records: list[dict[str, Any]] = []
    journal = Journal(settings.bundle_path, plan, plan_bytes)
    try:
        for index, attempt in enumerate(plan["attempts"]):
            record = run_attempt(
                journal=journal,
                plan=plan,
                attempt=attempt,
                timeout_seconds=settings.timeout_seconds,
                child_runner=child_runner,
                monotonic=monotonic,
                utc_clock=utc_clock,
            )
            journal.append(record)
            records.append(record)
            if index + 1 < len(plan["attempts"]):
                sleeper(plan["schedule"]["cooldown_ns"] / 1_000_000_000)
        validate_plan(plan, repository=repository, verify_local=True)
        if host_identity(power_declaration) != plan["host"]:
            raise CaptureError("capture host identity drifted during execution")
        journal_identity = journal.close()
    except BaseException:
        journal.abandon()
        raise
    verified = sum(record["status"] == "verified" for record in records)
    failed = len(records) - verified
    identity_consistent = _identity_consistent(records, plan)
    if failed:
        status = "CAPTURE_COMPLETE_WITH_FAILURES"
    elif not identity_consistent:
        status = "CAPTURE_COMPLETE_IDENTITY_MISMATCH"
    else:
        status = "CAPTURE_COMPLETE_AWAITING_STATISTICAL_RECEIPT"
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "schema_version": 1,
        "status": status,
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "started_at_utc": started_at,
        "completed_at_utc": _utc(utc_clock),
        "planned_attempts": len(plan["attempts"]),
        "recorded_attempts": len(records),
        "verified_attempts": verified,
        "failed_attempts": failed,
        "journal": journal_identity,
    }
    bundle["content_sha256"] = content_digest(bundle)
    write_new(journal.bundle / "bundle.json", canonical_bytes(bundle))
    return bundle


def _relative(value: Any, name: str) -> str:
    if type(value) is not str or not value or "\\" in value:
        raise CaptureError(f"{name} is not a normalized relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise CaptureError(f"{name} is not a normalized relative path")
    return value


class FileInventory:
    def __init__(self, root: Path):
        if root.is_symlink() or not root.is_dir():
            raise CaptureError("R-006 bundle must be a non-symlink directory")
        self.root = root.resolve()
        self.claimed: set[str] = set()
        self.identities: dict[str, tuple[int, str]] = {}

    def claim(self, identity: Any, name: str) -> Path:
        value = exact_object(identity, FILE_FIELDS, name)
        relative = _relative(value["path"], f"{name}.path")
        if relative in self.claimed:
            raise CaptureError(f"bundle file is claimed twice: {relative}")
        if type(value["bytes"]) is not int or value["bytes"] < 0:
            raise CaptureError(f"{name}.bytes is invalid")
        if type(value["sha256"]) is not str or DIGEST_RE.fullmatch(value["sha256"]) is None:
            raise CaptureError(f"{name}.sha256 is invalid")
        target = self.root.joinpath(*PurePosixPath(relative).parts)
        current = self.root
        for part in PurePosixPath(relative).parts:
            current /= part
            if current.is_symlink():
                raise CaptureError(f"bundle path traverses a symlink: {relative}")
        if not target.is_file() or target.is_symlink() or sha256_file(target) != (value["bytes"], value["sha256"]):
            raise CaptureError(f"{name} bytes or digest disagree")
        self.claimed.add(relative)
        self.identities[relative] = (value["bytes"], value["sha256"])
        return target

    def root_file(self, relative: str) -> bytes:
        if relative in self.claimed:
            raise CaptureError(f"bundle file is claimed twice: {relative}")
        target = self.root / relative
        if target.is_symlink() or not target.is_file():
            raise CaptureError(f"bundle root file is missing: {relative}")
        self.claimed.add(relative)
        raw = target.read_bytes()
        self.identities[relative] = (len(raw), sha256_bytes(raw))
        return raw

    def finish(self) -> None:
        actual: set[str] = set()
        directories: set[str] = set()
        for current, names, files in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            for name in names:
                child = current_path / name
                if child.is_symlink():
                    raise CaptureError("bundle contains a symlink")
                directories.add(child.relative_to(self.root).as_posix())
            for name in files:
                child = current_path / name
                if child.is_symlink() or not child.is_file():
                    raise CaptureError("bundle contains a non-regular file")
                actual.add(child.relative_to(self.root).as_posix())
        if directories != {"attempts"} or actual != self.claimed:
            raise CaptureError(
                f"bundle inventory drifted; unclaimed={sorted(actual - self.claimed)}, "
                f"missing={sorted(self.claimed - actual)}, directories={sorted(directories)}"
            )
        for relative, expected in self.identities.items():
            if sha256_file(self.root / relative) != expected:
                raise CaptureError(f"bundle file changed during validation: {relative}")


def _canonical_root(inventory: FileInventory, relative: str) -> dict[str, Any]:
    raw = inventory.root_file(relative)
    value = decode_strict(raw)
    if type(value) is not dict or raw != canonical_bytes(value):
        raise CaptureError(f"bundle {relative} is not canonical JSON")
    return value


def _journal(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        with path.open("rb") as source:
            while raw := source.readline(MAX_STREAM_BYTES + 1):
                if len(raw) > MAX_STREAM_BYTES or not raw.endswith(b"\n"):
                    raise CaptureError("R-006 journal record exceeds its bound")
                value = decode_strict(raw)
                if type(value) is not dict or raw != canonical_bytes(value):
                    raise CaptureError("R-006 journal is not canonical NDJSON")
                digest = value.get("content_sha256")
                if type(digest) is not str or digest != content_digest(value):
                    raise CaptureError("R-006 journal record digest mismatch")
                records.append(value)
    except OSError as error:
        raise CaptureError("cannot read R-006 journal") from error
    return records


def _validate_record(
    value: Any,
    *,
    plan: dict[str, Any],
    attempt: dict[str, Any],
    inventory: FileInventory,
) -> dict[str, Any] | None:
    record = exact_object(value, ATTEMPT_RESULT_FIELDS, "attempt result")
    if record["schema"] != ATTEMPT_RESULT_SCHEMA or record["ordinal"] != attempt["ordinal"] or record["attempt_id"] != attempt["attempt_id"]:
        raise CaptureError("attempt result identity differs from plan")
    for name in ("started_at_utc", "completed_at_utc"):
        if type(record[name]) is not str or UTC_RE.fullmatch(record[name]) is None:
            raise CaptureError(f"attempt result {name} is not canonical UTC")
    for name in ("launcher_elapsed_ns", "process_cpu_ns"):
        if type(record[name]) is not int or record[name] < 0:
            raise CaptureError(f"attempt result {name} is invalid")
    if type(record["child_exit_code"]) is not int:
        raise CaptureError("attempt child exit code is invalid")
    if record["command_sha256"] != _command_digest(proof_command(plan, attempt)):
        raise CaptureError("attempt command identity changed")
    streams = exact_object(record["streams"], {"report", "stderr"}, "attempt streams")
    expected_paths = {
        "report": attempt["report_path"],
        "stderr": attempt["stderr_path"],
    }
    for name, expected in expected_paths.items():
        if type(streams[name]) is not dict or streams[name].get("path") != expected:
            raise CaptureError(f"attempt {name} stream path differs from plan")
    report_path = inventory.claim(streams["report"], "attempt report stream")
    stderr_path = inventory.claim(streams["stderr"], "attempt stderr stream")
    verification = exact_object(record["independent_verification"], VERIFY_FIELDS, "independent verification")
    if (
        type(verification["stdout"]) is not dict
        or verification["stdout"].get("path") != attempt["verify_stdout_path"]
        or type(verification["stderr"]) is not dict
        or verification["stderr"].get("path") != attempt["verify_stderr_path"]
    ):
        raise CaptureError("independent verifier stream paths differ from plan")
    verify_stdout = inventory.claim(verification["stdout"], "verifier stdout")
    verify_stderr = inventory.claim(verification["stderr"], "verifier stderr")
    if record["status"] == "failed":
        if type(record["failure_code"]) is not str or not record["failure_code"]:
            raise CaptureError("failed attempt lacks a failure code")
        if type(record["failure_detail"]) is not str or not record["failure_detail"]:
            raise CaptureError("failed attempt lacks bounded failure detail")
        if record["identity"] is not None and record["metrics"] is None:
            raise CaptureError("failed verified profile lost its metrics")
        if record["proof"] is not None:
            if type(record["proof"]) is not dict or record["proof"].get("path") != attempt["proof_path"]:
                raise CaptureError("failed attempt proof path differs from plan")
            inventory.claim(record["proof"], "failed attempt proof")
        if verification["status"] == "verified":
            raise CaptureError("failed attempt claims successful independent verification")
        if verification["status"] not in {"failed", "skipped"}:
            raise CaptureError("failed attempt verifier status is invalid")
        if type(verification["failure_code"]) is not str or not verification["failure_code"]:
            raise CaptureError("failed attempt verifier receipt lacks a reason")
        return None
    if record["status"] != "verified" or record["failure_code"] is not None or record["failure_detail"] is not None:
        raise CaptureError("attempt result status envelope changed")
    if record["child_exit_code"] != 0 or stderr_path.read_bytes():
        raise CaptureError("verified proof child did not exit silently")
    if type(record["proof"]) is not dict or record["proof"].get("path") != attempt["proof_path"]:
        raise CaptureError("verified attempt proof path differs from plan")
    proof_path = inventory.claim(record["proof"], "verified attempt proof")
    identity, metrics = validate_report(
        report_path.read_bytes(), plan=plan, attempt=attempt, proof_path=proof_path
    )
    if record["identity"] != identity or record["metrics"] != metrics:
        raise CaptureError("attempt projection is not recomputable from raw report")
    if (
        verification["status"] != "verified"
        or verification["failure_code"] is not None
        or verification["child_exit_code"] != 0
        or type(verification["launcher_elapsed_ns"]) is not int
        or verification["launcher_elapsed_ns"] < 0
        or type(verification["process_cpu_ns"]) is not int
        or verification["process_cpu_ns"] < 0
        or verify_stderr.read_bytes()
        or verification["command_sha256"] != _command_digest(
            verify_command(plan, attempt, identity["statement_sha256"])
        )
    ):
        raise CaptureError("independent verification receipt is incomplete")
    validate_receipt(
        verify_stdout.read_bytes(),
        plan=plan,
        attempt=attempt,
        identity=identity,
    )
    if record["launcher_elapsed_ns"] == 0 or record["process_cpu_ns"] == 0:
        raise CaptureError("verified proof child lacks elapsed or process-CPU work")
    if verification["launcher_elapsed_ns"] == 0 or verification["process_cpu_ns"] == 0:
        raise CaptureError("independent verifier lacks elapsed or process-CPU work")
    return identity


def validate_bundle(
    repository: Path,
    bundle_path: Path,
    *,
    include_snapshot: bool = False,
) -> dict[str, Any]:
    inventory = FileInventory(bundle_path)
    plan_raw = inventory.root_file("plan.json")
    plan = decode_strict(plan_raw)
    if type(plan) is not dict or plan_raw != canonical_bytes(plan):
        raise CaptureError("bundle plan is not canonical JSON")
    validate_plan(plan, repository=repository.resolve(), verify_local=False)
    bundle = _canonical_root(inventory, "bundle.json")
    exact_object(bundle, BUNDLE_FIELDS, "bundle manifest")
    if (
        bundle["schema"] != BUNDLE_SCHEMA
        or bundle["schema_version"] != 1
        or bundle["session_id"] != plan["session_id"]
        or bundle["plan_sha256"] != plan["content_sha256"]
        or bundle["content_sha256"] != content_digest(bundle)
    ):
        raise CaptureError("bundle manifest identity changed")
    for name in ("started_at_utc", "completed_at_utc"):
        if type(bundle[name]) is not str or UTC_RE.fullmatch(bundle[name]) is None:
            raise CaptureError(f"bundle {name} is not canonical UTC")
    journal_identity = exact_object(bundle["journal"], FILE_FIELDS | {"records"}, "journal identity")
    journal_path = inventory.claim(
        {key: journal_identity[key] for key in FILE_FIELDS}, "attempt journal"
    )
    records = _journal(journal_path)
    if len(records) != journal_identity["records"] or not records:
        raise CaptureError("journal record count disagrees")
    header = exact_object(
        records[0],
        {"schema", "session_id", "plan_sha256", "planned_attempts", "content_sha256"},
        "journal header",
    )
    if (
        header["schema"] != JOURNAL_HEADER_SCHEMA
        or header["session_id"] != plan["session_id"]
        or header["plan_sha256"] != plan["content_sha256"]
        or header["planned_attempts"] != len(plan["attempts"])
    ):
        raise CaptureError("journal header differs from plan")
    if len(records) != len(plan["attempts"]) + 1:
        raise CaptureError("journal omits or duplicates attempts")
    identities: dict[str, dict[str, Any]] = {}
    verified = 0
    failed = 0
    for attempt, record in zip(plan["attempts"], records[1:], strict=True):
        identity = _validate_record(record, plan=plan, attempt=attempt, inventory=inventory)
        if identity is None:
            failed += 1
            continue
        verified += 1
        workload = attempt["workload_id"]
        prior = identities.setdefault(workload, identity)
        if identity != prior:
            raise CaptureError(
                f"proof/statement/transcript identity changed across workers for {workload}"
            )
    expected_status = (
        "CAPTURE_COMPLETE_WITH_FAILURES"
        if failed
        else "CAPTURE_COMPLETE_AWAITING_STATISTICAL_RECEIPT"
    )
    if bundle["status"] != expected_status:
        raise CaptureError("bundle status is not derivable from raw attempts")
    exact_counts = {
        "planned_attempts": len(plan["attempts"]),
        "recorded_attempts": verified + failed,
        "verified_attempts": verified,
        "failed_attempts": failed,
    }
    for name, expected in exact_counts.items():
        if bundle[name] != expected or type(bundle[name]) is not int:
            raise CaptureError(f"bundle {name} is not raw-derived")
    inventory.finish()
    result = {
        "schema": "stwo.typed-air.r006-bundle-validation.v1",
        "status": bundle["status"],
        "plan_sha256": plan["content_sha256"],
        "attempts": len(plan["attempts"]),
        "verified_attempts": verified,
        "failed_attempts": failed,
        "exact_identity_workloads": len(identities),
        "raw_bundle_valid": True,
        "normative_m7_receipt": False,
    }
    return attach_validation_snapshot(
        result,
        include=include_snapshot,
        plan=plan,
        bundle=bundle,
        records=records,
    )
