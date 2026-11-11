"""Validate host sessions and the append-only command-attempt projection."""

from __future__ import annotations

from typing import Any

from .artifacts import require_artifact
from .codec import canonical_bytes, sha256_bytes
from .model import (
    EvidenceError,
    exact_object,
    require_bool,
    require_hex,
    require_int,
    require_number,
    require_string,
)


SESSION_FIELDS = {
    "host_role", "plan_sha256", "session_nonce", "started_at_unix_ns",
    "ended_at_unix_ns", "host", "toolchains", "conditions", "caches",
    "attempt_ledger_artifact", "attempt_journal_artifact", "producer_attestation",
}
HOST_FIELDS = {
    "runner_id", "os", "os_version", "kernel", "cpu", "logical_cpu_count",
    "gpu", "memory_bytes", "filesystem", "power_source", "thermal_state",
    "sdk", "metal_runtime",
}
TOOLCHAIN_FIELDS = {"zig", "python", "rust_toolchain", "rustc"}
CONDITION_FIELDS = {"profiler_attached", "unrelated_sustained_work", "power_source_changed", "thermal_throttling"}
CACHE_FIELDS = {"path", "initially_empty"}
ATTEMPT_FIELDS = {
    "sequence", "host_role", "command_id", "stage", "arm", "workload_id",
    "round_index", "order_position", "status", "failure_class", "started_at_unix_ns",
    "ended_at_unix_ns", "exit_code", "artifacts", "previous_attempt_sha256",
    "attempt_sha256",
}
ATTEMPT_ARTIFACT_FIELDS = {"stdout", "stderr", "proof", "verifier", "timing", "resource"}
FINAL_FAILURES = {"failed", "interrupted", "timed_out"}
STATUSES = {"success", "infrastructure_failure", *FINAL_FAILURES}
ATTESTATION_FIELDS = {
    "schema", "provider", "repository", "workflow_sha", "run_id", "run_attempt",
    "job", "artifact_name", "plan_sha256", "session_nonce", "attempt_count",
    "terminal_attempt_sha256", "host_sha256", "toolchains_sha256",
    "conditions_sha256", "caches_sha256", "raw_bundle_sha256", "attestation_sha256",
}


def _digest_without(value: dict[str, Any], field: str) -> str:
    return sha256_bytes(canonical_bytes({key: item for key, item in value.items() if key != field}))


def attempt_chain_seed(role: str, plan: dict[str, Any], plan_digest: str) -> str:
    return sha256_bytes(canonical_bytes({
        "domain": "performance-epoch-attempt-chain-v1",
        "host_role": role,
        "plan_sha256": plan_digest,
        "session_nonce": plan["session_nonce"],
    }))


def validate_sessions(
    sessions: object,
    plans: dict[str, dict[str, Any]],
    plan_digests: dict[str, str],
    protocol: dict[str, Any],
    artifacts: dict[str, dict[str, Any]],
    trusted_attestations: dict[str, str],
    raw_bundle_sha256: str,
) -> dict[str, dict[str, Any]]:
    value = exact_object(sessions, {"linux", "macos"}, "sessions")
    for role, item in value.items():
        session = exact_object(item, SESSION_FIELDS, f"{role} session")
        if session["host_role"] != role or session["plan_sha256"] != plan_digests[role]:
            raise EvidenceError(f"{role} session plan identity mismatch")
        if session["session_nonce"] != plans[role]["session_nonce"]:
            raise EvidenceError(f"{role} session nonce mismatch")
        start = require_int(session["started_at_unix_ns"], f"{role} start", 1)
        end = require_int(session["ended_at_unix_ns"], f"{role} end", 1)
        if end <= start:
            raise EvidenceError(f"{role} session time range is invalid")
        host = exact_object(session["host"], HOST_FIELDS, f"{role} host")
        for key in ("runner_id", "os", "os_version", "kernel", "cpu", "gpu", "filesystem", "power_source", "thermal_state", "sdk", "metal_runtime"):
            require_string(host[key], f"{role} host.{key}")
        require_int(host["logical_cpu_count"], f"{role} logical CPU count", 1)
        require_int(host["memory_bytes"], f"{role} memory", 1)
        if host["os"] != protocol["host_roles"][role]["os"]:
            raise EvidenceError(f"{role} OS mismatch")
        if protocol["host_roles"][role]["requires_metal"] and host["metal_runtime"] == "not_applicable":
            raise EvidenceError("macOS session lacks a Metal runtime identity")
        tools = exact_object(session["toolchains"], TOOLCHAIN_FIELDS, f"{role} toolchains")
        for key, tool in tools.items():
            require_string(tool, f"{role} toolchains.{key}")
        conditions = exact_object(session["conditions"], CONDITION_FIELDS, f"{role} conditions")
        for key, condition in conditions.items():
            require_bool(condition, f"{role} conditions.{key}")
            if condition:
                raise EvidenceError(f"{role} measured under invalid condition: {key}")
        cache_value = exact_object(session["caches"], {"baseline", "candidate"}, f"{role} caches")
        for arm, arm_caches in cache_value.items():
            exact_object(arm_caches, {"local", "global"}, f"{role} {arm} caches")
            for scope, cache in arm_caches.items():
                exact_object(cache, CACHE_FIELDS, f"{role} {arm} {scope} cache")
                if cache["path"] != plans[role]["paths"][f"{arm}_{scope}_cache"]:
                    raise EvidenceError(f"{role} cache path differs from capture plan")
                if cache["initially_empty"] is not True:
                    raise EvidenceError(f"{role} cache was not initially empty")
        require_artifact(artifacts, session["attempt_ledger_artifact"], "attempt-ledger", f"{role} ledger")
        require_artifact(artifacts, session["attempt_journal_artifact"], "attempt-journal", f"{role} journal")
        attestation = exact_object(
            session["producer_attestation"], ATTESTATION_FIELDS, f"{role} producer attestation",
        )
        if attestation["schema"] != "build-performance-producer-attestation-v1":
            raise EvidenceError("producer attestation schema is unsupported")
        if attestation["provider"] != "github-actions" or attestation["repository"] != protocol["repository"]:
            raise EvidenceError("producer attestation is not from the protected repository")
        require_hex(attestation["workflow_sha"], 40, "producer workflow SHA")
        require_int(attestation["run_id"], "producer run ID", 1)
        require_int(attestation["run_attempt"], "producer run attempt", 1)
        require_hex(attestation["terminal_attempt_sha256"], 64, "terminal attempt digest")
        if attestation["raw_bundle_sha256"] != raw_bundle_sha256:
            raise EvidenceError("producer attestation raw bundle mismatch")
        for field, bound in (
            ("host_sha256", session["host"]),
            ("toolchains_sha256", session["toolchains"]),
            ("conditions_sha256", session["conditions"]),
            ("caches_sha256", session["caches"]),
        ):
            require_hex(attestation[field], 64, f"producer {field}")
            if attestation[field] != sha256_bytes(canonical_bytes(bound)):
                raise EvidenceError(f"producer attestation {field} mismatch")
        require_hex(attestation["attestation_sha256"], 64, "producer attestation digest")
        if attestation["plan_sha256"] != plan_digests[role] or attestation["session_nonce"] != session["session_nonce"]:
            raise EvidenceError("producer attestation plan/session mismatch")
        if attestation["attestation_sha256"] != _digest_without(attestation, "attestation_sha256"):
            raise EvidenceError("producer attestation content digest mismatch")
        if trusted_attestations.get(role) != attestation["attestation_sha256"]:
            raise EvidenceError("producer attestation lacks an external trusted binding")
    return value


def validate_attempts(
    attempts: object,
    plans: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    protocol: dict[str, Any],
    sessions: dict[str, dict[str, Any]],
    plan_digests: dict[str, str],
) -> tuple[dict[str, list[dict[str, Any]]], dict[tuple[str, int], dict[str, Any]]]:
    attempt_groups = exact_object(attempts, {"linux", "macos"}, "attempt groups")
    if any(not isinstance(items, list) or not items for items in attempt_groups.values()):
        raise EvidenceError("each host must have a nonempty attempt list")
    if sum(len(items) for items in attempt_groups.values()) > protocol["limits"]["max_attempts"]:
        raise EvidenceError("too many attempts")
    by_sequence: dict[tuple[str, int], dict[str, Any]] = {}
    commands = {
        role: {command["id"]: command for command in plan["commands"]}
        for role, plan in plans.items()
    }
    previous = {
        role: attempt_chain_seed(role, plan, plan_digests[role])
        for role, plan in plans.items()
    }
    counts = {role: 0 for role in plans}
    for role_group in ("linux", "macos"):
        for index, item in enumerate(attempt_groups[role_group], 1):
            attempt = exact_object(item, ATTEMPT_FIELDS, f"attempt[{index}]")
            sequence = require_int(attempt["sequence"], "attempt sequence", 1)
            if sequence != index:
                raise EvidenceError("attempt sequence is not contiguous and ordered")
            role = attempt["host_role"]
            if role != role_group:
                raise EvidenceError("attempt is stored under the wrong host role")
            if role not in plans or attempt["command_id"] not in commands[role]:
                raise EvidenceError("attempt command is not in its capture plan")
            command = commands[role][attempt["command_id"]]
            if attempt["arm"] != command["arm"]:
                raise EvidenceError("attempt arm differs from its planned command")
            if attempt["status"] not in STATUSES:
                raise EvidenceError("attempt status is unsupported")
            start = require_int(attempt["started_at_unix_ns"], "attempt start", 1)
            end = require_int(attempt["ended_at_unix_ns"], "attempt end", 1)
            if end <= start:
                raise EvidenceError("attempt time range is invalid")
            if attempt["status"] == "success":
                if attempt["exit_code"] != 0 or attempt["failure_class"] is not None:
                    raise EvidenceError("successful attempt has failure metadata")
            else:
                require_string(attempt["failure_class"], "attempt failure class")
            refs = exact_object(attempt["artifacts"], ATTEMPT_ARTIFACT_FIELDS, "attempt artifacts")
            require_artifact(artifacts, refs["stdout"], "stdout", "attempt stdout")
            require_artifact(artifacts, refs["stderr"], "stderr", "attempt stderr")
            for key in ("proof", "verifier", "timing", "resource"):
                reference = refs[key]
                if reference is not None:
                    require_artifact(artifacts, reference, key, f"attempt {key}")
            require_hex(attempt["previous_attempt_sha256"], 64, "previous attempt digest")
            require_hex(attempt["attempt_sha256"], 64, "attempt digest")
            if attempt["previous_attempt_sha256"] != previous[role]:
                raise EvidenceError("attempt hash chain is broken or reordered")
            if attempt["attempt_sha256"] != _digest_without(attempt, "attempt_sha256"):
                raise EvidenceError("attempt digest mismatch")
            previous[role] = attempt["attempt_sha256"]
            counts[role] += 1
            by_sequence[(role, sequence)] = attempt
    for role, session in sessions.items():
        attestation = session["producer_attestation"]
        if attestation["attempt_count"] != counts[role]:
            raise EvidenceError(f"{role} attempt count differs from protected terminal binding")
        if attestation["terminal_attempt_sha256"] != previous[role]:
            raise EvidenceError(f"{role} terminal attempt digest differs from protected binding")
    return attempt_groups, by_sequence


def require_successful_attempt(
    by_sequence: dict[tuple[str, int], dict[str, Any]],
    sequence: object,
    *,
    role: str,
    arm: str,
    command_id: str,
    stage: str,
) -> dict[str, Any]:
    number = require_int(sequence, "attempt reference", 1)
    attempt = by_sequence.get((role, number))
    if attempt is None:
        raise EvidenceError("attempt reference is missing")
    expected = (role, arm, command_id, stage, "success")
    actual = (
        attempt["host_role"], attempt["arm"], attempt["command_id"],
        attempt["stage"], attempt["status"],
    )
    if actual != expected:
        raise EvidenceError("attempt reference does not match expected successful command")
    return attempt
