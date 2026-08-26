"""Strict command construction and child-report authentication for C-013."""

from __future__ import annotations

from typing import Any

from .codec import decode_strict, exact_object
from .model import CaptureError, DIGEST_RE, SCHEDULE_SHA256


POSEIDON_SCHEMA = "stwo.c013.poseidon2-cpu-proof-child.v3"
CALIBRATION_SCHEMA = "stwo.c013.aa-proof-child.v2"
RESOURCE_SCOPE = "verified-arm:execution+proof+encoding+independent-verification"
SECURE_PCS = {
    "pow_bits": 26,
    "log_blowup_factor": 1,
    "queries": 70,
    "fold_step": 1,
}
METRIC_FIELDS = {
    "execution_steps",
    "execution_ns",
    "proving_ns",
    "proof_encoding_ns",
    "verification_ns",
    "verified_request_ns",
    "proof_wire_bytes",
    "preprocessed_cells",
    "main_cells",
    "interaction_cells",
}
RESOURCE_FIELDS = {
    "scope",
    "source",
    "lifetime_peak_physical_footprint_bytes",
    "process_cpu_ns",
    "energy_nj",
    "instructions",
    "cycles",
    "unavailable_reason",
}
COMMON_FIELDS = {
    "schema",
    "status",
    "security",
    "phase",
    "schedule_sha256",
    "sample_index",
    "max_steps",
    "input_bytes",
    "output_bytes",
    "input_sha256",
    "output_sha256",
    "elf_sha256",
    "executable_sha256",
    "proof_sha256",
    "implementation_commit",
    "implementation_tree",
    "implementation_dirty",
    "dirty_content_sha256",
    "pcs",
    "metrics",
    "resources",
}
POSEIDON_FIELDS = COMMON_FIELDS | {
    "arm",
    "shape",
    "background_permutations_per_call",
    "calls",
    "extension_calls",
}
CALIBRATION_FIELDS = COMMON_FIELDS | {"label", "workload"}
BACKGROUND = {
    "core_only": 15,
    "balanced_core_and_poseidon2": 1,
    "poseidon2_dominant": 0,
}


def command_for_attempt(
    plan: dict[str, Any], attempt: dict[str, Any]
) -> tuple[str, ...]:
    artifacts = plan["artifacts"]
    executable = artifacts[attempt["executable_id"]]
    elf = artifacts[attempt["elf_id"]]
    common = (
        "--security",
        "secure",
        "--phase",
        attempt["phase"],
        "--elf",
        elf["path"],
        "--sample-index",
        str(attempt["sample_index"]),
        "--schedule-sha256",
        SCHEDULE_SHA256,
        "--expected-elf-sha256",
        elf["sha256"],
        "--expected-executable-sha256",
        executable["sha256"],
    )
    if attempt["kind"] == "calibration":
        arguments = ("--label", attempt["arm"], *common)
    elif attempt["kind"] == "m6":
        arguments = (
            "--arm",
            attempt["arm"],
            *common,
            "--shape",
            attempt["shape"],
            "--calls",
            str(attempt["calls"]),
            "--expected-input-sha256",
            attempt["input_sha256"],
            "--expected-output-sha256",
            attempt["output_sha256"],
        )
    else:
        raise CaptureError("attempt kind has no child command")
    return (executable["path"], *arguments)


def _one_line(raw: bytes) -> dict[str, Any]:
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw:
        raise CaptureError("child stdout must contain exactly one JSON line")
    value = decode_strict(raw)
    if type(value) is not dict:
        raise CaptureError("child report root must be an object")
    return value


def _positive_integer(value: Any, name: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        raise CaptureError(f"child report {name} must be an integer >= {minimum}")
    return value


def _validate_common(
    report: dict[str, Any],
    plan: dict[str, Any],
    attempt: dict[str, Any],
) -> None:
    expected = {
        "status": "verified",
        "security": "secure",
        "phase": attempt["phase"],
        "schedule_sha256": SCHEDULE_SHA256,
        "sample_index": attempt["sample_index"],
        "input_bytes": attempt["input_bytes"],
        "output_bytes": attempt["output_bytes"],
        "input_sha256": attempt["input_sha256"],
        "output_sha256": attempt["output_sha256"],
        "elf_sha256": plan["artifacts"][attempt["elf_id"]]["sha256"],
        "executable_sha256": plan["artifacts"][attempt["executable_id"]]["sha256"],
        "implementation_commit": plan["source"]["commit"],
        "implementation_tree": plan["source"]["tree"],
        "implementation_dirty": False,
        "dirty_content_sha256": None,
        "pcs": SECURE_PCS,
    }
    for key, value in expected.items():
        if type(report[key]) is not type(value) or report[key] != value:
            raise CaptureError(f"child report {key} identity drifted")
    _positive_integer(report["max_steps"], "max_steps")
    if type(report["proof_sha256"]) is not str or DIGEST_RE.fullmatch(report["proof_sha256"]) is None:
        raise CaptureError("child proof digest is invalid")

    metrics = exact_object(report["metrics"], METRIC_FIELDS, "child metrics")
    for key in METRIC_FIELDS:
        _positive_integer(metrics[key], f"metrics.{key}")
    if metrics["verified_request_ns"] != (
        metrics["execution_ns"] + metrics["proving_ns"] + metrics["verification_ns"]
    ):
        raise CaptureError("child verified-request timing partition drifted")

    resources = exact_object(report["resources"], RESOURCE_FIELDS, "child resources")
    if (
        resources["scope"] != RESOURCE_SCOPE
        or resources["source"] != "darwin_proc_pid_rusage_v6"
        or resources["unavailable_reason"] is not None
    ):
        raise CaptureError("child resource adapter is unavailable or changed")
    for key in (
        "lifetime_peak_physical_footprint_bytes",
        "process_cpu_ns",
        "energy_nj",
        "instructions",
        "cycles",
    ):
        _positive_integer(resources[key], f"resources.{key}")


def validate_child_report(
    raw: bytes,
    *,
    plan: dict[str, Any],
    attempt: dict[str, Any],
) -> dict[str, Any]:
    report = _one_line(raw)
    if attempt["kind"] == "calibration":
        exact_object(report, CALIBRATION_FIELDS, "calibration child report")
        expected = {
            "schema": CALIBRATION_SCHEMA,
            "label": attempt["arm"],
            "workload": "multi_shard_addi",
            "max_steps": 262_144,
        }
    else:
        exact_object(report, POSEIDON_FIELDS, "Poseidon2 child report")
        calls = attempt["calls"]
        background = BACKGROUND[attempt["shape"]]
        expected = {
            "schema": POSEIDON_SCHEMA,
            "arm": attempt["arm"],
            "shape": attempt["shape"],
            "background_permutations_per_call": background,
            "calls": calls,
            "extension_calls": calls if attempt["arm"] == "precompile" else 0,
            "max_steps": 100_000 + calls * (background + 1) * 100_000,
        }
    for key, value in expected.items():
        if type(report[key]) is not type(value) or report[key] != value:
            raise CaptureError(f"child report {key} identity drifted")
    _validate_common(report, plan, attempt)
    return report
