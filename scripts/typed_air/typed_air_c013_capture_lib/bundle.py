"""Independent, fail-closed validation of a retained C-013 CPU bundle.

This module authenticates capture evidence and independently recomputes the
CPU-lane reduction.  It deliberately does not render an M6 promotion verdict:
the bundle has no Metal cohort or protocol-complete receipt evidence, so
treating a sound CPU ledger as an M6 receipt would cross the claim boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .bundle_evidence import (
    FILE_IDENTITY_FIELDS,
    EvidenceFiles,
    canonical_document,
    digest,
    file_identity,
    integer,
    journal_records,
    record_digest,
    utc,
)
from .child_report import command_for_attempt, validate_child_report
from .codec import (
    canonical_bytes,
    content_digest,
    exact_object,
    sha256_bytes,
)
from . import schedule
from .model import CaptureError, SCHEDULE_SHA256
from .plan import validate_plan
from .statistics import CPU_REDUCTION_SCHEMA, evaluate_calibration, evaluate_m6_cpu


BUNDLE_SCHEMA = "stwo.typed-air.c013-capture-bundle.v1"
HEADER_SCHEMA = "stwo.typed-air.c013-attempt-journal-header.v1"
ATTEMPT_SCHEMA = "stwo.typed-air.c013-attempt-result.v1"
ADMISSION_RECORD_SCHEMA = "stwo.typed-air.c013-aa-admission-record.v1"
ADMISSION_SCHEMA = "stwo.typed-air.c013-aa-admission.v1"
EMPTY_SHA256 = sha256_bytes(b"")

BUNDLE_FIELDS = {
    "schema",
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
    "calibration",
    "cpu_reduction",
    "performance_verdict",
    "content_sha256",
}
FILE_IDENTITY_FIELDS = {"path", "bytes", "sha256"}
JOURNAL_IDENTITY_FIELDS = FILE_IDENTITY_FIELDS | {"records"}
CALIBRATION_IDENTITY_FIELDS = FILE_IDENTITY_FIELDS | {"verdict"}
CPU_REDUCTION_IDENTITY_FIELDS = FILE_IDENTITY_FIELDS | {"verdict"}
HEADER_FIELDS = {
    "schema",
    "session_id",
    "plan_sha256",
    "schedule_sha256",
    "planned_attempts",
    "content_sha256",
}
ATTEMPT_FIELDS = {
    "schema",
    "global_ordinal",
    "kind",
    "sample_index",
    "status",
    "failure_code",
    "started_at_utc",
    "completed_at_utc",
    "launcher_elapsed_ns",
    "child_exit_code",
    "command_sha256",
    "report_sha256",
    "streams",
    "content_sha256",
}
ADMISSION_RECORD_FIELDS = {
    "schema",
    "verdict",
    "artifact",
    "content_sha256",
}
FAILURE_CODES = {
    "child-timeout",
    "child-launch",
    "runner-contract",
    "child-nonzero-exit",
    "child-stderr",
    "child-report-invalid",
}
COMPLETE_STATUSES = {
    "CAPTURE_COMPLETE_WITH_FAILURES",
    "CAPTURE_COMPLETE_AWAITING_RECEIPT_VALIDATION",
}

NORMATIVE_RECEIPT_GAPS = (
    "repository-relative-artifact-paths-and-retained-byte-identities",
    "source-closure-and-releasefast-build-toolchain-target-identities",
    "cohort-thermal-and-unrelated-process-admission-evidence",
    "witness-proving-native-and-independent-verification-timing-partition",
    "base-profile-zero-call-reviewed-predecessor-cohort",
    "m6-zero-call-profile-descriptor-relation-and-transcript-exact-evidence",
    "cpu-m6-exact-gate-and-statistical-reduction",
    "metal-hybrid-capture-residency-fallback-and-gpu-timing-evidence",
    "cross-lane-functional-and-proof-invariant-validation",
    "normative-c013-receipt-schema-renderer-and-verdict",
)


@dataclass(frozen=True)
class BundleValidation:
    capture_status: str
    planned_attempts: int
    recorded_attempts: int
    verified_attempts: int
    failed_attempts: int
    calibration_verdict: str
    cpu_reduction_verdict: str | None
    m6_verdict: None
    normative_receipt: bool
    remaining_gaps: tuple[str, ...]
    bundle_file_sha256: str
    plan_file_sha256: str


def _stream_identity(
    record: dict[str, Any],
    ordinal: int,
    files: EvidenceFiles,
) -> tuple[bytes, bytes, dict[str, Any], dict[str, Any]]:
    streams = exact_object(record["streams"], {"stdout", "stderr"}, "attempt streams")
    stdout = file_identity(streams["stdout"], "attempt stdout")
    stderr = file_identity(streams["stderr"], "attempt stderr")
    exact_stdout = f"attempts/{ordinal:04d}.stdout.json"
    exact_stderr = f"attempts/{ordinal:04d}.stderr.bin"
    if stdout["path"] != exact_stdout or stderr["path"] != exact_stderr:
        raise CaptureError("attempt stream path differs from its global ordinal")
    stdout_path = files.claim(stdout, f"attempt {ordinal} stdout")
    stderr_path = files.claim(stderr, f"attempt {ordinal} stderr")
    return stdout_path.read_bytes(), stderr_path.read_bytes(), stdout, stderr


def _validate_attempt(
    record: dict[str, Any],
    plan: dict[str, Any],
    attempt: dict[str, Any],
    files: EvidenceFiles,
) -> dict[str, Any] | None:
    ordinal = attempt["global_ordinal"]
    exact_object(record, ATTEMPT_FIELDS, f"attempt record {ordinal}")
    expected = {
        "schema": ATTEMPT_SCHEMA,
        "global_ordinal": ordinal,
        "kind": attempt["kind"],
        "sample_index": attempt["sample_index"],
    }
    for key, value in expected.items():
        if type(record[key]) is not type(value) or record[key] != value:
            raise CaptureError(f"attempt {ordinal} {key} differs from the pinned plan")
    started = utc(record["started_at_utc"], f"attempt {ordinal} start")
    completed = utc(record["completed_at_utc"], f"attempt {ordinal} completion")
    if completed < started:
        raise CaptureError(f"attempt {ordinal} wall clock regressed")
    integer(record["launcher_elapsed_ns"], f"attempt {ordinal} launcher elapsed")
    if type(record["child_exit_code"]) is not int:
        raise CaptureError(f"attempt {ordinal} child exit code is not an integer")
    expected_command = sha256_bytes(canonical_bytes(list(command_for_attempt(plan, attempt))))
    if record["command_sha256"] != expected_command:
        raise CaptureError(f"attempt {ordinal} command identity drifted")

    stdout_raw, stderr_raw, stdout, stderr = _stream_identity(record, ordinal, files)
    status = record["status"]
    if status == "verified":
        if record["failure_code"] is not None or record["child_exit_code"] != 0:
            raise CaptureError(f"verified attempt {ordinal} has failure state")
        if stderr["bytes"] != 0 or stderr["sha256"] != EMPTY_SHA256 or stderr_raw:
            raise CaptureError(f"verified attempt {ordinal} retained non-empty stderr")
        report_sha = digest(record["report_sha256"], f"attempt {ordinal} report digest")
        if report_sha != stdout["sha256"]:
            raise CaptureError(f"attempt {ordinal} stdout/report identity mismatch")
        return validate_child_report(stdout_raw, plan=plan, attempt=attempt)

    if status != "failed" or record["report_sha256"] is not None:
        raise CaptureError(f"attempt {ordinal} status/report state is invalid")
    failure = record["failure_code"]
    if type(failure) is not str or failure not in FAILURE_CODES:
        raise CaptureError(f"attempt {ordinal} failure code is invalid")
    if failure == "child-nonzero-exit" and record["child_exit_code"] == 0:
        raise CaptureError(f"attempt {ordinal} nonzero-exit evidence is inconsistent")
    if failure == "child-stderr" and (
        record["child_exit_code"] != 0 or not stderr_raw
    ):
        raise CaptureError(f"attempt {ordinal} stderr failure evidence is inconsistent")
    if failure == "child-report-invalid":
        if record["child_exit_code"] != 0 or stderr_raw:
            raise CaptureError(f"attempt {ordinal} invalid-report state is inconsistent")
        try:
            validate_child_report(stdout_raw, plan=plan, attempt=attempt)
        except CaptureError:
            pass
        else:
            raise CaptureError(f"attempt {ordinal} labels a valid child report invalid")
    launch_failures = {"child-timeout", "child-launch", "runner-contract"}
    if failure in launch_failures and record["child_exit_code"] != -1:
        raise CaptureError(f"attempt {ordinal} launch-failure exit state is inconsistent")
    return None


def _expected_failed_calibration(verified: int) -> dict[str, Any]:
    return {
        "schema": ADMISSION_SCHEMA,
        "attempts": 80,
        "verified_attempts": verified,
        "verdict": "NO_VERDICT",
        "reason": "one or more A/A children failed before statistical admission",
    }


def _remaining_gaps(
    status: str,
    *,
    cpu_reduction_authenticated: bool,
) -> tuple[str, ...]:
    prefix: tuple[str, ...] = ()
    if status == "NO_VERDICT_AA_ADMISSION":
        prefix = ("passing-a-a-calibration-and-a-new-capture-session",)
    elif status == "INCOMPLETE":
        prefix = ("complete-frozen-cpu-attempt-schedule-in-a-new-session",)
    elif status == "CAPTURE_COMPLETE_WITH_FAILURES":
        prefix = ("failure-free-frozen-cpu-capture-in-a-new-session",)
    gaps = NORMATIVE_RECEIPT_GAPS
    if cpu_reduction_authenticated:
        gaps = tuple(
            gap
            for gap in gaps
            if gap != "cpu-m6-exact-gate-and-statistical-reduction"
        )
    return prefix + gaps


def validate_bundle(
    repository: Path,
    bundle_path: Path,
    *,
    verify_local_plan: bool = True,
) -> BundleValidation:
    """Authenticate a finalized CPU bundle without granting an M6 verdict."""

    repository = repository.resolve()
    files = EvidenceFiles(bundle_path)
    bundle, bundle_raw = canonical_document(files.root / "bundle.json", "bundle.json")
    files.bind_snapshot("bundle.json", bundle_raw)
    exact_object(bundle, BUNDLE_FIELDS, "capture bundle")
    if bundle["schema"] != BUNDLE_SCHEMA:
        raise CaptureError("capture bundle schema identity drifted")
    record_digest(bundle, "capture bundle")
    if bundle["performance_verdict"] is not None:
        raise CaptureError("capture bundle cannot carry an M6 performance verdict")
    started = utc(bundle["started_at_utc"], "capture start")
    completed = utc(bundle["completed_at_utc"], "capture completion")
    if completed < started:
        raise CaptureError("capture bundle wall clock regressed")

    plan, plan_raw = canonical_document(files.root / "plan.json", "plan.json")
    files.bind_snapshot("plan.json", plan_raw)
    if plan.get("content_sha256") != content_digest(plan):
        raise CaptureError("capture plan content digest mismatch")
    validate_plan(plan, repository=repository, verify_local=verify_local_plan)
    if (
        bundle["session_id"] != plan["session_id"]
        or bundle["plan_sha256"] != plan["content_sha256"]
    ):
        raise CaptureError("capture bundle does not bind the retained plan")
    attempts = plan["attempts"]
    if type(attempts) is not list or len(attempts) < 80:
        raise CaptureError("capture plan lacks the complete A/A prefix")
    if any(type(item) is not dict for item in attempts):
        raise CaptureError("capture plan attempt is not an object")
    if any(item.get("kind") != "calibration" for item in attempts[:80]) or any(
        item.get("kind") != "m6" for item in attempts[80:]
    ):
        raise CaptureError("capture plan phase order is invalid")
    for ordinal, attempt in enumerate(attempts):
        if (
            type(attempt.get("global_ordinal")) is not int
            or attempt["global_ordinal"] != ordinal
        ):
            raise CaptureError("capture plan global attempt order is invalid")

    journal_identity = exact_object(bundle["journal"], JOURNAL_IDENTITY_FIELDS, "journal identity")
    file_identity({key: journal_identity[key] for key in FILE_IDENTITY_FIELDS}, "journal identity")
    if journal_identity["path"] != "journal.ndjson":
        raise CaptureError("journal path identity drifted")
    journal_path = files.claim(journal_identity, "attempt journal")
    records = journal_records(journal_path)
    if integer(journal_identity["records"], "journal record count", minimum=1) != len(records):
        raise CaptureError("journal record cardinality mismatch")
    if not records:
        raise CaptureError("attempt journal has no header")
    header = exact_object(records[0], HEADER_FIELDS, "attempt journal header")
    expected_header = {
        "schema": HEADER_SCHEMA,
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "schedule_sha256": SCHEDULE_SHA256,
        "planned_attempts": len(attempts),
    }
    for key, value in expected_header.items():
        if type(header[key]) is not type(value) or header[key] != value:
            raise CaptureError(f"attempt journal header {key} drifted")

    calibration_identity = exact_object(
        bundle["calibration"], CALIBRATION_IDENTITY_FIELDS, "calibration identity"
    )
    file_identity(
        {key: calibration_identity[key] for key in FILE_IDENTITY_FIELDS},
        "calibration identity",
    )
    if calibration_identity["path"] != "calibration.json":
        raise CaptureError("calibration path identity drifted")
    calibration_path = files.claim(calibration_identity, "A/A calibration")

    next_ordinal = 0
    admission_record: dict[str, Any] | None = None
    reports: list[dict[str, Any] | None] = []
    m6_captures: list[
        tuple[dict[str, Any], dict[str, Any], dict[str, Any]]
    ] = []
    verified = 0
    failed = 0
    for journal_index, record in enumerate(records[1:], start=1):
        schema = record.get("schema")
        if schema == ADMISSION_RECORD_SCHEMA:
            if admission_record is not None or next_ordinal != 80:
                raise CaptureError("A/A admission record is duplicated or out of order")
            admission_record = exact_object(
                record, ADMISSION_RECORD_FIELDS, "A/A admission journal record"
            )
            artifact = file_identity(record["artifact"], "A/A admission artifact")
            if artifact != {key: calibration_identity[key] for key in FILE_IDENTITY_FIELDS}:
                raise CaptureError("A/A admission artifact identity drifted")
            if record["verdict"] != calibration_identity["verdict"]:
                raise CaptureError("A/A admission verdict identity drifted")
            continue
        if schema != ATTEMPT_SCHEMA:
            raise CaptureError(f"journal record {journal_index} has unknown schema")
        if next_ordinal >= len(attempts):
            raise CaptureError("journal contains more attempts than the plan")
        if next_ordinal >= 80 and admission_record is None:
            raise CaptureError("M6 attempt precedes A/A admission")
        attempt = attempts[next_ordinal]
        report = _validate_attempt(record, plan, attempt, files)
        reports.append(report)
        if report is None:
            failed += 1
        else:
            verified += 1
            if attempt["kind"] == "m6":
                m6_captures.append((attempt, record, report))
        next_ordinal += 1
    if admission_record is None:
        raise CaptureError("attempt journal lacks the required A/A admission record")

    calibration, _ = canonical_document(calibration_path, "calibration.json")
    calibration_reports = reports[:80]
    verified_calibration = sum(item is not None for item in calibration_reports)
    if verified_calibration == 80:
        captures = [
            (attempts[index], calibration_reports[index])
            for index in range(80)
        ]
        recomputed = evaluate_calibration(repository, plan, captures)  # type: ignore[arg-type]
    else:
        recomputed = _expected_failed_calibration(verified_calibration)
    if calibration != recomputed:
        raise CaptureError("retained A/A calibration differs from independent recomputation")
    calibration_verdict = calibration.get("verdict")
    if calibration_verdict not in {"PASS", "NO_VERDICT"}:
        raise CaptureError("A/A calibration verdict is invalid")
    if admission_record["verdict"] != calibration_verdict:
        raise CaptureError("journal and recomputed A/A verdict differ")

    planned = len(attempts)
    if calibration_verdict != "PASS":
        expected_status = "NO_VERDICT_AA_ADMISSION"
        if next_ordinal != 80:
            raise CaptureError("A/A rejection did not stop before M6")
    elif next_ordinal < planned:
        expected_status = "INCOMPLETE"
    elif next_ordinal == planned and failed:
        expected_status = "CAPTURE_COMPLETE_WITH_FAILURES"
    elif next_ordinal == planned:
        expected_status = "CAPTURE_COMPLETE_AWAITING_RECEIPT_VALIDATION"
    else:
        raise CaptureError("capture recorded more attempts than planned")
    if bundle["status"] != expected_status:
        raise CaptureError("capture status differs from the retained evidence")
    if expected_status in COMPLETE_STATUSES and next_ordinal != planned:
        raise CaptureError("complete capture status has incomplete attempt cardinality")

    exact_counts = {
        "planned_attempts": planned,
        "recorded_attempts": next_ordinal,
        "verified_attempts": verified,
        "failed_attempts": failed,
    }
    for key, value in exact_counts.items():
        if type(bundle[key]) is not int or bundle[key] != value:
            raise CaptureError(f"capture bundle {key} differs from the journal")
    if verified + failed != next_ordinal:
        raise CaptureError("capture attempt accounting does not close")
    if calibration_identity["verdict"] != calibration_verdict:
        raise CaptureError("capture calibration summary verdict drifted")

    cpu_reduction_verdict: str | None = None
    cpu_reduction_authenticated = False
    cpu_reduction_value = bundle["cpu_reduction"]
    requires_cpu_reduction = (
        expected_status == "CAPTURE_COMPLETE_AWAITING_RECEIPT_VALIDATION"
        and planned == schedule.GLOBAL_ATTEMPTS
    )
    if requires_cpu_reduction:
        identity = exact_object(
            cpu_reduction_value,
            CPU_REDUCTION_IDENTITY_FIELDS,
            "CPU reduction identity",
        )
        file_identity(
            {key: identity[key] for key in FILE_IDENTITY_FIELDS},
            "CPU reduction identity",
        )
        if identity["path"] != "cpu-reduction.json":
            raise CaptureError("CPU reduction path identity drifted")
        if identity["verdict"] not in {"PASS", "FAIL"}:
            raise CaptureError("CPU reduction verdict is invalid")
        reduction_path = files.claim(identity, "CPU reduction")
        reduction, _ = canonical_document(reduction_path, "cpu-reduction.json")
        if reduction.get("schema") != CPU_REDUCTION_SCHEMA:
            raise CaptureError("CPU reduction schema identity drifted")
        if reduction.get("content_sha256") != content_digest(reduction):
            raise CaptureError("CPU reduction content digest mismatch")
        recomputed = evaluate_m6_cpu(repository, plan, m6_captures)
        if reduction != recomputed:
            raise CaptureError(
                "retained CPU reduction differs from independent recomputation"
            )
        if reduction["verdict"] != identity["verdict"]:
            raise CaptureError("CPU reduction verdict identity drifted")
        cpu_reduction_verdict = reduction["verdict"]
        cpu_reduction_authenticated = True
    elif cpu_reduction_value is not None:
        raise CaptureError("non-complete capture cannot carry a CPU reduction")

    files.finish()
    return BundleValidation(
        capture_status=expected_status,
        planned_attempts=planned,
        recorded_attempts=next_ordinal,
        verified_attempts=verified,
        failed_attempts=failed,
        calibration_verdict=calibration_verdict,
        cpu_reduction_verdict=cpu_reduction_verdict,
        m6_verdict=None,
        normative_receipt=False,
        remaining_gaps=_remaining_gaps(
            expected_status,
            cpu_reduction_authenticated=cpu_reduction_authenticated,
        ),
        bundle_file_sha256=sha256_bytes(bundle_raw),
        plan_file_sha256=sha256_bytes(plan_raw),
    )
