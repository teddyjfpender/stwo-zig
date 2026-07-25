#!/usr/bin/env python3
"""Validate the fail-closed Native CUDA activation authority."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "stwo_zig_native_cuda_activation_state_v1"
BOARD = "core_cuda"
PINNED_RUST_COMMIT = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
DEFAULT_STATE_PATH = Path(
    "conformance/cuda-native-activation-state-v1.json"
)
REQUIRED_FAMILIES = (
    "wide_fibonacci",
    "blake",
    "poseidon",
    "plonk_logup",
    "state_machine",
    "xor_lookup",
)
REQUIRED_FAMILY_GATES = (
    "exact_trace_semantics",
    "exact_constraint_semantics",
    "exact_cpu_cuda_proof_bytes",
    "pinned_rust_verification",
    "zero_fallback",
    "complete_stage_telemetry",
)
REQUIRED_GLOBAL_GATES = (
    "complete_structural_coverage",
    "sustained_headline_calibrated",
    "locked_cuda_judge_host",
    "locked_host_aa_calibration",
    "candidate_dry_run",
    "predecessor_abba_rehearsal",
    "mutation_and_anti_forgery",
    "full_repository_gates",
)
REQUIRED_DEVICE_STAGES = (
    "ingress",
    "trace_generation",
    "trace_commit",
    "constraint_evaluation",
    "oods",
    "quotient",
    "fri_commit",
    "pow",
    "decommit",
    "proof_assembly",
    "total",
)


class ActivationError(RuntimeError):
    """Activation authority is malformed or contradicts its evidence."""


def _require_exact_keys(
    value: object,
    expected: tuple[str, ...],
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ActivationError(f"{label} must be an object")
    actual = set(value)
    required = set(expected)
    if actual != required:
        missing = sorted(required - actual)
        extra = sorted(actual - required)
        raise ActivationError(
            f"{label} keys differ; missing={missing}, extra={extra}"
        )
    return value


def _validate_evidence_path(root: Path, raw: object, label: str) -> None:
    if not isinstance(raw, str) or not raw.strip():
        raise ActivationError(f"{label} must be a nonempty repository path")
    path = Path(raw)
    if path.is_absolute() or ".." in path.parts:
        raise ActivationError(f"{label} escapes the repository: {raw}")
    if not (root / path).is_file():
        raise ActivationError(f"{label} does not exist: {raw}")


def _load_json_evidence(root: Path, raw: object) -> dict[str, Any] | None:
    if not isinstance(raw, str) or not raw.endswith(".json"):
        return None
    try:
        value = json.loads((root / raw).read_bytes())
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _valid_parity_receipt(document: dict[str, Any]) -> bool:
    if (
        document.get("schema") != "stwo-zig-cuda-parity-oracle-v1"
        or document.get("verdict") != "pass"
    ):
        return False
    proofs = document.get("proofs")
    residency = document.get("cuda_residency")
    products = document.get("products")
    verifications = document.get("verifications")
    if not all(
        isinstance(value, dict)
        for value in (proofs, residency, products)
    ) or not isinstance(verifications, list):
        return False
    cpu = proofs.get("cpu")
    cuda = proofs.get("cuda")
    rust = products.get("rust_verifier")
    if not all(isinstance(value, dict) for value in (cpu, cuda, rust)):
        return False
    if (
        proofs.get("canonical_byte_parity") is not True
        or cpu.get("proof_bytes") != cuda.get("proof_bytes")
        or cpu.get("proof_sha256") != cuda.get("proof_sha256")
        or not isinstance(cpu.get("proof_bytes"), int)
        or cpu["proof_bytes"] <= 0
        or not isinstance(rust.get("sha256"), str)
        or len(rust["sha256"]) != 64
        or residency.get("resident") is not True
        or residency.get("strict_aot") is not True
        or residency.get("cpu_fallbacks") != 0
    ):
        return False
    return any(
        isinstance(row, dict)
        and row.get("verifier") == "pinned-rust-stwo"
        and row.get("artifact") == "cuda-proof.json"
        and row.get("exit_code") == 0
        for row in verifications
    )


def _parity_verifier_digest(document: dict[str, Any]) -> str | None:
    if not _valid_parity_receipt(document):
        return None
    return document["products"]["rust_verifier"]["sha256"]


def _authority_verifier_digest(document: dict[str, Any]) -> str | None:
    oracle = document.get("oracle")
    if (
        document.get("schema")
        != "stwo-zig-cuda-structural-screen-receipt-v1"
        or not isinstance(oracle, dict)
        or oracle.get("authority") != "pinned-rust-stwo"
        or oracle.get("upstream_commit") != PINNED_RUST_COMMIT
        or oracle.get("all_accepted") is not True
        or oracle.get("artifacts_checked") != oracle.get("artifacts_accepted")
        or not isinstance(oracle.get("verifier_sha256"), str)
        or len(oracle["verifier_sha256"]) != 64
    ):
        return None
    return oracle["verifier_sha256"]


def _stage_map(document: dict[str, Any]) -> dict[str, Any] | None:
    direct = document.get("device_stage_timing_ns")
    if isinstance(direct, dict):
        return direct
    workloads = document.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        return None
    for workload in workloads:
        if not isinstance(workload, dict):
            return None
        sessions = workload.get("sessions")
        if not isinstance(sessions, list) or not sessions:
            return None
        for session in sessions:
            if not isinstance(session, dict):
                return None
            metrics = session.get("metrics")
            if not isinstance(metrics, dict):
                return None
            stages = metrics.get("stage_ms_last_steady_sample")
            if not _valid_stage_map(stages):
                return None
    first = workloads[0]["sessions"][0]["metrics"]
    return first["stage_ms_last_steady_sample"]


def _valid_stage_map(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    if set(value) != set(REQUIRED_DEVICE_STAGES):
        return False
    if any(
        isinstance(value[stage], bool)
        or not isinstance(value[stage], (int, float))
        or value[stage] < 0
        for stage in REQUIRED_DEVICE_STAGES
    ):
        return False
    return value["total"] > 0


def _is_hex_digest(value: object, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    return all(character in "0123456789abcdef" for character in value)


def _valid_candidate_dry_run(document: dict[str, Any]) -> bool:
    product = document.get("product")
    oracle = document.get("oracle")
    invariants = document.get("invariants")
    workloads = document.get("workloads")
    if (
        document.get("schema")
        != "stwo-zig-cuda-structural-screen-receipt-v1"
        or document.get("verdict") != "pass_diagnostic_only"
        or not all(
            isinstance(value, dict)
            for value in (product, oracle, invariants)
        )
        or not isinstance(workloads, list)
        or not workloads
    ):
        return False
    if (
        product.get("dirty") is not False
        or product.get("aot_only") is not True
        or not _is_hex_digest(product.get("commit"), 40)
        or not _is_hex_digest(product.get("binary_sha256"), 64)
        or oracle.get("authority") != "pinned-rust-stwo"
        or oracle.get("upstream_commit") != PINNED_RUST_COMMIT
        or oracle.get("all_accepted") is not True
        or oracle.get("artifacts_checked") != len(workloads)
        or oracle.get("artifacts_accepted") != len(workloads)
    ):
        return False
    required_invariants = (
        "all_proofs_zig_verified",
        "all_proofs_repeat_identical",
        "all_proofs_rust_oracle_accepted",
        "all_rows_resident",
        "all_rows_strict_aot",
        "all_rows_zero_cpu_fallback",
    )
    if any(invariants.get(key) is not True for key in required_invariants):
        return False
    for workload in workloads:
        if (
            not isinstance(workload, dict)
            or not _is_hex_digest(workload.get("proof_sha256"), 64)
            or not _is_hex_digest(workload.get("artifact_sha256"), 64)
            or not isinstance(workload.get("proof_bytes"), int)
            or workload["proof_bytes"] <= 0
            or not isinstance(workload.get("steady_verified_ms"), (int, float))
            or workload["steady_verified_ms"] <= 0
        ):
            return False
    return True


def _valid_predecessor_abba(document: dict[str, Any]) -> bool:
    measurement = document.get("measurement")
    correctness = document.get("correctness")
    predecessor = document.get("predecessor")
    candidate = document.get("candidate")
    portfolio = document.get("portfolio")
    if (
        document.get("schema") != "native_cuda_structural_verdict_v1"
        or document.get("status")
        not in ("qualified_checkpoint_not_promotion", "promotion")
        or not all(
            isinstance(value, dict)
            for value in (
                measurement,
                correctness,
                predecessor,
                candidate,
                portfolio,
            )
        )
    ):
        return False
    if (
        measurement.get("schedule") != "paired_counterbalanced_ABBA"
        or not isinstance(measurement.get("rounds"), int)
        or measurement["rounds"] < 7
        or not isinstance(measurement.get("regression_ceiling"), (int, float))
        or measurement["regression_ceiling"] > 1.05
    ):
        return False
    required_correctness = (
        "all_arms_byte_identical",
        "zig_verified",
        "rust_oracle_verified",
        "zero_cpu_fallbacks",
        "one_terminal_d2h",
    )
    if any(correctness.get(key) is not True for key in required_correctness):
        return False
    for identity in (predecessor, candidate):
        if (
            not _is_hex_digest(identity.get("commit"), 40)
            or not _is_hex_digest(identity.get("binary_sha256"), 64)
        ):
            return False
    if predecessor["commit"] == candidate["commit"]:
        return False
    interval = portfolio.get("confidence_interval_95")
    ratio = portfolio.get("ratio")
    if (
        not isinstance(interval, dict)
        or not all(
            isinstance(interval.get(bound), (int, float))
            for bound in ("low", "high")
        )
        or not isinstance(ratio, (int, float))
        or not interval["low"] <= ratio <= interval["high"]
        or not isinstance(portfolio.get("worst_workload_ratio"), (int, float))
        or portfolio["worst_workload_ratio"]
        > measurement["regression_ceiling"]
    ):
        return False
    return True


def _valid_structural_coverage(document: dict[str, Any]) -> bool:
    coverage = document.get("coverage")
    return (
        _valid_candidate_dry_run(document)
        and document.get("activation_eligible") is True
        and isinstance(coverage, dict)
        and coverage.get("activation_ready") is True
        and coverage.get("blocked") == []
    )


def _valid_named_release_receipt(
    document: dict[str, Any],
    schema: str,
) -> bool:
    return (
        document.get("schema") == schema
        and document.get("verdict") == "pass"
        and document.get("candidate_bound") is True
        and document.get("rust_oracle_verified") is True
        and document.get("zero_cpu_fallbacks") is True
        and _is_hex_digest(document.get("candidate_commit"), 40)
        and _is_hex_digest(document.get("candidate_binary_sha256"), 64)
    )


GLOBAL_RECEIPT_VALIDATORS = {
    "complete_structural_coverage": _valid_structural_coverage,
    "sustained_headline_calibrated": lambda document: _valid_named_release_receipt(
        document,
        "stwo-zig-cuda-sustained-judge-v1",
    ),
    "locked_cuda_judge_host": lambda document: _valid_named_release_receipt(
        document,
        "stwo-zig-cuda-judge-host-authority-v1",
    ),
    "locked_host_aa_calibration": lambda document: _valid_named_release_receipt(
        document,
        "stwo-zig-cuda-aa-calibration-v1",
    ),
    "candidate_dry_run": _valid_candidate_dry_run,
    "predecessor_abba_rehearsal": _valid_predecessor_abba,
    "mutation_and_anti_forgery": lambda document: _valid_named_release_receipt(
        document,
        "stwo-zig-cuda-anti-forgery-v1",
    ),
    "full_repository_gates": lambda document: _valid_named_release_receipt(
        document,
        "stwo-zig-cuda-release-gates-v1",
    ),
}


def _validate_global_receipts(
    root: Path,
    gates: dict[str, bool],
    evidence: dict[str, Any],
    label: str,
) -> None:
    for gate, validator in GLOBAL_RECEIPT_VALIDATORS.items():
        if not gates[gate]:
            continue
        if not any(
            document is not None and validator(document)
            for document in (
                _load_json_evidence(root, path)
                for path in evidence[gate]
            )
        ):
            raise ActivationError(
                f"{label}.{gate} has no valid parsed release receipt"
            )


def _validate_release_receipts(
    root: Path,
    gates: dict[str, bool],
    evidence: dict[str, Any],
    label: str,
) -> None:
    parity_gates = (
        "exact_cpu_cuda_proof_bytes",
        "zero_fallback",
    )
    for gate in parity_gates:
        if not gates[gate]:
            continue
        if not any(
            document is not None and _valid_parity_receipt(document)
            for document in (
                _load_json_evidence(root, path)
                for path in evidence[gate]
            )
        ):
            raise ActivationError(
                f"{label}.{gate} has no valid immutable parity receipt"
            )
    if gates["pinned_rust_verification"]:
        documents = [
            document
            for document in (
                _load_json_evidence(root, path)
                for path in evidence["pinned_rust_verification"]
            )
            if document is not None
        ]
        parity_digests = {
            digest
            for document in documents
            if (digest := _parity_verifier_digest(document)) is not None
        }
        authority_digests = {
            digest
            for document in documents
            if (digest := _authority_verifier_digest(document)) is not None
        }
        if not parity_digests.intersection(authority_digests):
            raise ActivationError(
                f"{label}.pinned_rust_verification has no matching "
                "pinned-commit authority and parity receipts"
            )
    if gates["complete_stage_telemetry"] and not any(
        document is not None and _valid_stage_map(_stage_map(document))
        for document in (
            _load_json_evidence(root, path)
            for path in evidence["complete_stage_telemetry"]
        )
    ):
        raise ActivationError(
            f"{label}.complete_stage_telemetry has no complete parsed report"
        )


def _validate_gate_set(
    root: Path,
    owner: dict[str, Any],
    required_gates: tuple[str, ...],
    label: str,
) -> tuple[dict[str, bool], list[str]]:
    gates = _require_exact_keys(owner.get("gates"), required_gates, f"{label}.gates")
    evidence = _require_exact_keys(
        owner.get("evidence"),
        required_gates,
        f"{label}.evidence",
    )
    blockers = _require_exact_keys(
        owner.get("blockers"),
        required_gates,
        f"{label}.blockers",
    )
    normalized: dict[str, bool] = {}
    blocked: list[str] = []
    for gate in required_gates:
        status = gates[gate]
        if type(status) is not bool:
            raise ActivationError(f"{label}.gates.{gate} must be boolean")
        paths = evidence[gate]
        if not isinstance(paths, list):
            raise ActivationError(f"{label}.evidence.{gate} must be a list")
        for index, path in enumerate(paths):
            _validate_evidence_path(
                root,
                path,
                f"{label}.evidence.{gate}[{index}]",
            )
        reason = blockers[gate]
        if status:
            if not paths:
                raise ActivationError(
                    f"{label}.{gate} passes without retained evidence"
                )
            if reason is not None:
                raise ActivationError(
                    f"{label}.{gate} passes but retains a blocker"
                )
        else:
            if not isinstance(reason, str) or not reason.strip():
                raise ActivationError(
                    f"{label}.{gate} is blocked without a reason"
                )
            blocked.append(f"{label}.{gate}: {reason}")
        normalized[gate] = status
    if required_gates == REQUIRED_FAMILY_GATES:
        _validate_release_receipts(root, normalized, evidence, label)
    elif required_gates == REQUIRED_GLOBAL_GATES:
        _validate_global_receipts(root, normalized, evidence, label)
    return normalized, blocked


def validate_state(root: Path, document: object) -> dict[str, Any]:
    """Validate and normalize one activation-state document."""
    if not isinstance(document, dict):
        raise ActivationError("CUDA activation state must be an object")
    if document.get("schema") != SCHEMA:
        raise ActivationError("CUDA activation state schema is unsupported")
    if document.get("board") != BOARD:
        raise ActivationError("CUDA activation state owns the wrong board")

    families = _require_exact_keys(
        document.get("families"),
        REQUIRED_FAMILIES,
        "families",
    )
    family_results: dict[str, Any] = {}
    blockers: list[str] = []
    for family in REQUIRED_FAMILIES:
        entry = families[family]
        if not isinstance(entry, dict):
            raise ActivationError(f"families.{family} must be an object")
        gates, family_blockers = _validate_gate_set(
            root,
            entry,
            REQUIRED_FAMILY_GATES,
            f"families.{family}",
        )
        ready = all(gates.values())
        if entry.get("release_ready") is not ready:
            raise ActivationError(
                f"families.{family}.release_ready contradicts its gates"
            )
        blockers.extend(family_blockers)
        family_results[family] = {
            "release_ready": ready,
            "gates": gates,
            "blockers": family_blockers,
        }

    global_entry = document.get("global")
    if not isinstance(global_entry, dict):
        raise ActivationError("global must be an object")
    global_gates, global_blockers = _validate_gate_set(
        root,
        global_entry,
        REQUIRED_GLOBAL_GATES,
        "global",
    )
    blockers.extend(global_blockers)

    computed_ready = (
        all(result["release_ready"] for result in family_results.values())
        and all(global_gates.values())
    )
    if document.get("activation_ready") is not computed_ready:
        raise ActivationError(
            "activation_ready contradicts family/global gate state"
        )
    return {
        "schema": SCHEMA,
        "board": BOARD,
        "activation_ready": computed_ready,
        "release_ready_family_count": sum(
            result["release_ready"] for result in family_results.values()
        ),
        "required_family_count": len(REQUIRED_FAMILIES),
        "families": family_results,
        "global_gates": global_gates,
        "blockers": blockers,
    }


def load_state(
    root: Path,
    relative_path: Path = DEFAULT_STATE_PATH,
) -> tuple[dict[str, Any], str]:
    path = root / relative_path
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except FileNotFoundError as error:
        raise ActivationError(
            f"CUDA activation state is missing: {relative_path}"
        ) from error
    except json.JSONDecodeError as error:
        raise ActivationError(
            f"CUDA activation state is invalid JSON: {error}"
        ) from error
    return validate_state(root, document), hashlib.sha256(raw).hexdigest()


def validate_manifest_activation(root: Path, manifest: dict[str, Any]) -> None:
    """Bind the staged board to the exact activation authority."""
    try:
        group = manifest["workload_registry"]["groups"]["cuda"]
    except (KeyError, TypeError) as error:
        raise ActivationError("manifest has no Native CUDA group") from error
    if group.get("board") != BOARD:
        raise ActivationError("manifest CUDA group owns the wrong board")
    oracle = group.get("correctness_oracle")
    if (
        not isinstance(oracle, dict)
        or oracle.get("authority") != "pinned-rust-stwo"
        or oracle.get("commit") != PINNED_RUST_COMMIT
        or oracle.get("final_validator") is not True
    ):
        raise ActivationError("manifest CUDA pinned Rust oracle differs")
    contract = group.get("activation_contract")
    if not isinstance(contract, dict):
        raise ActivationError("manifest CUDA group has no activation_contract")
    expected_keys = {
        "schema",
        "state_path",
        "state_sha256",
        "required_families",
        "required_family_gates",
        "required_global_gates",
    }
    if set(contract) != expected_keys:
        raise ActivationError(
            "manifest CUDA activation_contract fields are incomplete"
        )
    if contract["schema"] != SCHEMA:
        raise ActivationError("manifest CUDA activation schema differs")
    if tuple(contract["required_families"]) != REQUIRED_FAMILIES:
        raise ActivationError("manifest CUDA required family list differs")
    if tuple(contract["required_family_gates"]) != REQUIRED_FAMILY_GATES:
        raise ActivationError("manifest CUDA family gate list differs")
    if tuple(contract["required_global_gates"]) != REQUIRED_GLOBAL_GATES:
        raise ActivationError("manifest CUDA global gate list differs")
    relative = Path(contract["state_path"])
    if relative != DEFAULT_STATE_PATH:
        raise ActivationError("manifest CUDA activation state path differs")
    state, digest = load_state(root, relative)
    if contract["state_sha256"] != digest:
        raise ActivationError(
            "manifest CUDA activation state SHA-256 pin differs"
        )
    if (group.get("enabled") or group.get("promotion_eligible")) and not state[
        "activation_ready"
    ]:
        raise ActivationError(
            "core_cuda cannot be enabled or promotion eligible while "
            "activation gates are blocked"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    args = parser.parse_args(argv)
    root = args.repo_root.resolve()
    try:
        manifest = json.loads(
            (root / "autoresearch/MANIFEST.json").read_bytes()
        )
        validate_manifest_activation(root, manifest)
        state, digest = load_state(root)
    except (ActivationError, OSError, json.JSONDecodeError) as error:
        print(f"CUDA activation gate failed: {error}", file=sys.stderr)
        return 1
    print(
        "CUDA activation authority VALID: "
        f"ready={str(state['activation_ready']).lower()} "
        f"blockers={len(state['blockers'])} "
        f"families={state['release_ready_family_count']}/"
        f"{state['required_family_count']} state_sha256={digest}"
    )
    return 0
