"""Independent aggregate validator and architecture-consumable receipt binding."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .artifacts import require_artifact, validate_attempt_journal, validate_attempt_ledger, validate_bundle
from .builds import validate_builds
from .codec import content_digest, sha256_file, strict_json
from .model import EvidenceError, RECEIPT_SCHEMA, ValidatedReceipt, exact_object, require_hex, require_int, require_number
from .performance import validate_performance
from .session import FINAL_FAILURES, require_successful_attempt, validate_attempts, validate_sessions


RECEIPT_FIELDS = {
    "schema", "schema_version", "created_at_unix", "protocol_sha256", "authority",
    "plan_sha256", "sources", "sessions", "raw_bundle", "attempts",
    "build_comparisons", "performance_rows", "aot_checks", "riscv_challenge",
    "verdict", "content_sha256",
}
SOURCE_FIELDS = {"repository", "commit", "tree", "clean", "worktree_status"}
AOT_FIELDS = {
    "host_role", "backend", "runtime_mode", "attempt_sequence", "executable_artifact",
    "aot_identity_artifact", "proof_artifact", "verifier_artifact",
    "no_runtime_compilation", "metal_device_dispatches", "metal_fallback_count",
    "cold_initialization_seconds", "verdict",
}
CHALLENGE_FIELDS = {
    "host_role", "attempt_sequence", "trusted_bundle_identity",
    "trusted_bundle_artifact", "proof_artifact", "verifier_artifact", "total_seconds",
    "allocated_at_unix_ns", "verified_at_unix_ns", "complete_clock_scope",
    "locally_verified", "pinned_stark_v_verified", "verdict",
}


def _assert_exact_success_cardinality(value: dict[str, Any]) -> None:
    references: list[tuple[str, int]] = []
    for build in value["build_comparisons"]:
        for arm in ("baseline", "candidate"):
            product = build[arm]
            if product is not None:
                references.extend((build["host_role"], product[key]) for key in (
                    "cold_attempt_sequence", "warm_attempt_sequence",
                ))
    for row in value["performance_rows"]:
        role = row["host_role"]
        for arm in ("baseline", "candidate"):
            references.extend((role, sample["attempt_sequence"]) for sample in row["warmups"][arm])
        for paired in row["rounds"]:
            for arm in ("baseline", "candidate"):
                references.extend((role, sample["attempt_sequence"]) for sample in paired[arm])
    references.append(("macos", value["aot_checks"][0]["attempt_sequence"]))
    references.append(("linux", value["riscv_challenge"]["attempt_sequence"]))
    if len(references) != len(set(references)):
        raise EvidenceError("a successful attempt was reused by multiple evidence rows")
    successes = {
        (role, attempt["sequence"])
        for role, items in value["attempts"].items()
        for attempt in items
        if attempt["status"] == "success"
    }
    if set(references) != successes:
        raise EvidenceError("successful attempt cardinality differs from the evidence schedule")


def _validate_aot(
    values: object,
    *,
    builds: list[dict[str, Any]],
    attempts: dict[tuple[str, int], dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    raw_root: Path,
    max_bytes: int,
) -> None:
    if not isinstance(values, list) or len(values) != 1:
        raise EvidenceError("exactly one candidate AOT check is required")
    check = exact_object(values[0], AOT_FIELDS, "AOT check")
    if (check["host_role"], check["backend"], check["runtime_mode"]) != ("macos", "metal-hybrid", "authenticated-aot"):
        raise EvidenceError("AOT check lane is unsupported")
    attempt = require_successful_attempt(
        attempts, check["attempt_sequence"], role="macos", arm="candidate",
        command_id="aot:candidate:metal-hybrid", stage="aot-check",
    )
    metal_build = next(item for item in builds if item["id"] == "macos-native-metal")
    if check["executable_artifact"] != metal_build["candidate"]["executable_artifact"]:
        raise EvidenceError("AOT check executable differs from focused Metal build")
    require_artifact(artifacts, check["executable_artifact"], "executable", "AOT executable")
    identity_artifact = require_artifact(artifacts, check["aot_identity_artifact"], "aot-identity", "AOT identity")
    identity = strict_json(raw_root / identity_artifact["path"], max_bytes)
    exact_object(identity, {"schema", "source_sha256", "manifest_sha256", "metallib_sha256", "sdk", "metal_runtime"}, "AOT identity")
    if identity["schema"] != "metal-aot-identity-v1":
        raise EvidenceError("AOT identity schema is unsupported")
    for field in ("source_sha256", "manifest_sha256", "metallib_sha256"):
        require_hex(identity[field], 64, f"AOT {field}")
    proof = require_artifact(artifacts, check["proof_artifact"], "proof", "AOT proof")
    verifier = require_artifact(artifacts, check["verifier_artifact"], "verifier", "AOT verifier")
    if attempt["artifacts"]["proof"] != proof["id"] or attempt["artifacts"]["verifier"] != verifier["id"]:
        raise EvidenceError("AOT proof evidence is not bound to its attempt")
    verifier_value = strict_json(raw_root / verifier["path"], max_bytes)
    if verifier_value != {"schema": "proof-verifier-v1", "local_verified": True, "rust_oracle_verified": True, "canonical_proof_sha256": proof["sha256"]}:
        raise EvidenceError("AOT proof lacks local and pinned Rust verification")
    require_number(check["cold_initialization_seconds"], "AOT cold initialization")
    passed = (
        check["no_runtime_compilation"] is True
        and require_int(check["metal_device_dispatches"], "AOT Metal dispatches") > 0
        and require_int(check["metal_fallback_count"], "AOT fallback count") == 0
    )
    if check["verdict"] != ("PASS" if passed else "NO-GO") or not passed:
        raise EvidenceError("candidate AOT correctness/identity check failed")


def _validate_challenge(
    value: object,
    *,
    protocol: dict[str, Any],
    attempts: dict[tuple[str, int], dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    raw_root: Path,
) -> None:
    check = exact_object(value, CHALLENGE_FIELDS, "RISC-V challenge")
    if check["host_role"] != "linux":
        raise EvidenceError("RISC-V challenge must run on Linux")
    attempt = require_successful_attempt(
        attempts, check["attempt_sequence"], role="linux", arm="candidate",
        command_id="challenge:candidate:riscv", stage="riscv-challenge",
    )
    bundle_artifact = require_artifact(artifacts, check["trusted_bundle_artifact"], "trusted-bundle", "trusted Stark-V bundle")
    bundle = strict_json(raw_root / bundle_artifact["path"], protocol["limits"]["max_json_bytes"])
    exact_object(bundle, {"schema", "identity"}, "trusted bundle")
    if bundle["schema"] != "trusted-stark-v-bundle-v1" or bundle["identity"] != check["trusted_bundle_identity"]:
        raise EvidenceError("trusted Stark-V bundle identity mismatch")
    identity = exact_object(
        check["trusted_bundle_identity"],
        {"repository", "commit", "tree", "rust_toolchain", "executable_sha256", "manifest_sha256"},
        "trusted Stark-V identity",
    )
    if identity["repository"] != protocol["trusted_stark_v"]["repository"] or identity["commit"] != protocol["trusted_stark_v"]["commit"]:
        raise EvidenceError("trusted Stark-V source pin mismatch")
    for field in ("commit", "tree"):
        require_hex(identity[field], 40, f"Stark-V {field}")
    for field in ("executable_sha256", "manifest_sha256"):
        require_hex(identity[field], 64, f"Stark-V {field}")
    proof = require_artifact(artifacts, check["proof_artifact"], "proof", "challenge proof")
    verifier = require_artifact(artifacts, check["verifier_artifact"], "verifier", "challenge verifier")
    if attempt["artifacts"]["proof"] != proof["id"] or attempt["artifacts"]["verifier"] != verifier["id"]:
        raise EvidenceError("challenge evidence is not bound to its attempt")
    allocated = require_int(check["allocated_at_unix_ns"], "challenge allocation time", 1)
    verified = require_int(check["verified_at_unix_ns"], "challenge verification time", 1)
    if verified <= allocated:
        raise EvidenceError("challenge complete-clock interval is invalid")
    derived_total = (verified - allocated) / 1_000_000_000
    total = require_number(check["total_seconds"], "challenge seconds")
    if abs(total - derived_total) > 1e-9:
        raise EvidenceError("challenge total does not span allocation through verification")
    timing = require_artifact(artifacts, attempt["artifacts"]["timing"], "timing", "challenge timing")
    timing_value = strict_json(raw_root / timing["path"], protocol["limits"]["max_json_bytes"])
    if timing_value != {"schema": "process-timing-v1", "wall_seconds": check["total_seconds"]}:
        raise EvidenceError("challenge clock differs from raw timing")
    verifier_value = strict_json(raw_root / verifier["path"], protocol["limits"]["max_json_bytes"])
    passed = (
        check["complete_clock_scope"] is True
        and check["locally_verified"] is True
        and check["pinned_stark_v_verified"] is True
        and verifier_value == {"schema": "riscv-challenge-verifier-v1", "local_verified": True, "stark_v_verified": True, "proof_sha256": proof["sha256"]}
        and total <= protocol["budgets"]["riscv_hosted_challenge_seconds"]
    )
    if check["verdict"] != ("PASS" if passed else "NO-GO") or not passed:
        raise EvidenceError("RISC-V hosted challenge failed")


def validate_receipt(
    receipt: object,
    *,
    receipt_path: Path,
    root: Path,
    protocol: dict[str, Any],
    protocol_sha256: str,
    plans: dict[str, dict[str, Any]],
    plan_digests: dict[str, str],
    raw_root: Path,
    trusted_attestations: dict[str, str],
) -> ValidatedReceipt:
    value = exact_object(receipt, RECEIPT_FIELDS, "performance receipt")
    persisted = strict_json(receipt_path, protocol["limits"]["max_json_bytes"])
    if persisted != value:
        raise EvidenceError("validated receipt object differs from persisted receipt bytes")
    if value["schema"] != RECEIPT_SCHEMA or value["schema_version"] != 2:
        raise EvidenceError("performance receipt schema is unsupported")
    require_int(value["created_at_unix"], "receipt creation time", 1)
    if value["protocol_sha256"] != protocol_sha256 or value["authority"] != protocol["authority"]:
        raise EvidenceError("receipt authority or protocol mismatch")
    if value["plan_sha256"] != plan_digests:
        raise EvidenceError("receipt capture-plan identity mismatch")
    sources = exact_object(value["sources"], {"baseline", "candidate"}, "receipt sources")
    for arm in ("baseline", "candidate"):
        exact_object(sources[arm], SOURCE_FIELDS, f"{arm} source")
        if sources[arm] != plans["linux"]["sources"][arm] or sources[arm] != plans["macos"]["sources"][arm]:
            raise EvidenceError(f"{arm} source differs across plans and receipt")
    artifacts = validate_bundle(value["raw_bundle"], raw_root, protocol)
    sessions = validate_sessions(
        value["sessions"], plans, plan_digests, protocol, artifacts, trusted_attestations,
        value["raw_bundle"]["content_sha256"],
    )
    attempt_values, attempts = validate_attempts(
        value["attempts"], plans, artifacts, protocol, sessions, plan_digests,
    )
    for role, session in sessions.items():
        ledger = require_artifact(artifacts, session["attempt_ledger_artifact"], "attempt-ledger", f"{role} ledger")
        role_attempts = attempt_values[role]
        validate_attempt_ledger(raw_root, ledger, role_attempts, protocol["limits"]["max_json_bytes"])
        journal = require_artifact(artifacts, session["attempt_journal_artifact"], "attempt-journal", f"{role} journal")
        validate_attempt_journal(raw_root, journal, role_attempts)
    if any(attempt["status"] in FINAL_FAILURES for items in attempt_values.values() for attempt in items):
        raise EvidenceError("a product attempt failed, timed out, or was interrupted")
    builds = validate_builds(
        value["build_comparisons"], protocol, sources, artifacts, attempts, raw_root,
    )
    validate_performance(
        value["performance_rows"], root=root, protocol=protocol, builds=builds,
        attempts=attempts, artifacts=artifacts, raw_root=raw_root,
    )
    _validate_aot(
        value["aot_checks"], builds=builds, attempts=attempts, artifacts=artifacts,
        raw_root=raw_root, max_bytes=protocol["limits"]["max_json_bytes"],
    )
    _validate_challenge(
        value["riscv_challenge"], protocol=protocol, attempts=attempts,
        artifacts=artifacts, raw_root=raw_root,
    )
    _assert_exact_success_cardinality(value)
    require_hex(value["content_sha256"], 64, "receipt content digest")
    if value["content_sha256"] != content_digest(value):
        raise EvidenceError("receipt content digest mismatch")
    if value["verdict"] != "PASS":
        raise EvidenceError("performance receipt remains NO-GO")
    return ValidatedReceipt(
        path=receipt_path.resolve(), file_sha256=sha256_file(receipt_path),
        content_sha256=value["content_sha256"], protocol_sha256=protocol_sha256,
        candidate_commit=sources["candidate"]["commit"], verdict="PASS",
    )


def load_and_validate_receipt(path: Path, **kwargs) -> ValidatedReceipt:
    protocol = kwargs["protocol"]
    value = strict_json(path, protocol["limits"]["max_json_bytes"])
    return validate_receipt(value, receipt_path=path, **kwargs)
