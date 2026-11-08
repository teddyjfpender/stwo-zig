"""GitHub artifact-channel attestation and trusted verifier policy."""

from __future__ import annotations

import os
from typing import Any, Mapping

from .model import (
    ReceiptError,
    exact_object,
    require_decimal,
    require_hex40,
    require_hex64,
    require_safe_component,
    require_string,
)


ATTESTATION_FIELDS = {"kind", "artifact_name"}
WORKFLOW_FIELDS = {"path", "definition_sha256", "ref", "sha"}
RUN_FIELDS = {
    "provider",
    "repository",
    "repository_id",
    "repository_owner_id",
    "run_id",
    "run_attempt",
    "job",
    "session_nonce",
}


def canonical_artifact_name(role: str, commit: str, run_id: str, attempt: str) -> str:
    return f"build-architecture-{role}-{commit}-{run_id}-{attempt}"


def _required_env(environment: Mapping[str, str], name: str) -> str:
    value = environment.get(name)
    if not value:
        raise ReceiptError(f"trusted workflow environment is missing {name}")
    return value


def workflow_and_run(
    *,
    mode: str,
    role: str,
    source: dict[str, Any],
    workflow_path: str,
    workflow_sha256: str,
    protocol: dict[str, Any],
    run_id: str,
    run_attempt: str,
    session_nonce: str,
    environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    environment = os.environ if environment is None else environment
    require_decimal(run_id, "run_id")
    require_decimal(run_attempt, "run_attempt")
    require_hex64(session_nonce, "session_nonce")
    policy = protocol["host_roles"][role]
    trust = protocol["trust"]
    if mode == "local-unsigned":
        workflow = {
            "path": workflow_path,
            "definition_sha256": workflow_sha256,
            "ref": "local",
            "sha": source["commit"],
        }
        run = {
            "provider": "local",
            "repository": trust["repository"],
            "repository_id": trust["repository_id"],
            "repository_owner_id": trust["repository_owner_id"],
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job": "local-diagnostic",
            "session_nonce": session_nonce,
        }
        return workflow, run, {"kind": "local-unsigned-v1", "artifact_name": None}

    if mode != "github-actions-artifact":
        raise ReceiptError(f"unsupported attestation mode: {mode}")
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": trust["repository"],
        "GITHUB_REPOSITORY_ID": str(trust["repository_id"]),
        "GITHUB_REPOSITORY_OWNER_ID": str(trust["repository_owner_id"]),
        "GITHUB_WORKFLOW_REF": trust["workflow_ref"],
        "GITHUB_RUN_ID": run_id,
        "GITHUB_RUN_ATTEMPT": run_attempt,
        "GITHUB_JOB": policy["producer_job"],
    }
    for name, expected_value in expected.items():
        if _required_env(environment, name) != expected_value:
            raise ReceiptError(f"trusted workflow environment mismatch: {name}")
    workflow_sha = require_hex40(
        _required_env(environment, "GITHUB_WORKFLOW_SHA"), "GITHUB_WORKFLOW_SHA",
    )
    artifact_name = canonical_artifact_name(role, source["commit"], run_id, run_attempt)
    workflow = {
        "path": workflow_path,
        "definition_sha256": workflow_sha256,
        "ref": trust["workflow_ref"],
        "sha": workflow_sha,
    }
    run = {
        "provider": "github-actions",
        "repository": trust["repository"],
        "repository_id": trust["repository_id"],
        "repository_owner_id": trust["repository_owner_id"],
        "run_id": run_id,
        "run_attempt": run_attempt,
        "job": policy["producer_job"],
        "session_nonce": session_nonce,
    }
    return workflow, run, {
        "kind": "github-actions-artifact-v1",
        "artifact_name": artifact_name,
    }


def validate_trusted_verifier_environment(
    protocol: dict[str, Any], environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    environment = os.environ if environment is None else environment
    trust = protocol["trust"]
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": trust["repository"],
        "GITHUB_REPOSITORY_ID": str(trust["repository_id"]),
        "GITHUB_REPOSITORY_OWNER_ID": str(trust["repository_owner_id"]),
        "GITHUB_WORKFLOW_REF": trust["workflow_ref"],
        "GITHUB_JOB": protocol["aggregate_job"],
    }
    for name, expected_value in expected.items():
        if _required_env(environment, name) != expected_value:
            raise ReceiptError(f"aggregate verifier environment mismatch: {name}")
    return {
        "workflow_sha": require_hex40(
            _required_env(environment, "GITHUB_WORKFLOW_SHA"), "GITHUB_WORKFLOW_SHA",
        ),
        "run_id": require_decimal(
            _required_env(environment, "GITHUB_RUN_ID"), "GITHUB_RUN_ID",
        ),
        "run_attempt": require_decimal(
            _required_env(environment, "GITHUB_RUN_ATTEMPT"), "GITHUB_RUN_ATTEMPT",
        ),
        "authority_commit": require_hex40(
            _required_env(environment, "STWO_ARCHITECTURE_AUTHORITY_COMMIT"),
            "STWO_ARCHITECTURE_AUTHORITY_COMMIT",
        ),
        "authority_tree": require_hex40(
            _required_env(environment, "STWO_ARCHITECTURE_AUTHORITY_TREE"),
            "STWO_ARCHITECTURE_AUTHORITY_TREE",
        ),
        "authority_plan_sha256": require_hex64(
            _required_env(environment, "STWO_ARCHITECTURE_AUTHORITY_PLAN_SHA256"),
            "STWO_ARCHITECTURE_AUTHORITY_PLAN_SHA256",
        ),
    }


def validate_workflow(value: object, label: str) -> dict[str, Any]:
    workflow = exact_object(value, WORKFLOW_FIELDS, label)
    require_string(workflow["path"], f"{label}.path")
    require_hex64(workflow["definition_sha256"], f"{label}.definition_sha256")
    require_string(workflow["ref"], f"{label}.ref")
    require_hex40(workflow["sha"], f"{label}.sha")
    return workflow


def validate_run(value: object, label: str) -> dict[str, Any]:
    run = exact_object(value, RUN_FIELDS, label)
    if run["provider"] not in {"local", "github-actions"}:
        raise ReceiptError(f"{label}.provider is unsupported")
    require_string(run["repository"], f"{label}.repository")
    for field in ("repository_id", "repository_owner_id"):
        if not isinstance(run[field], int) or isinstance(run[field], bool) or run[field] <= 0:
            raise ReceiptError(f"{label}.{field} must be a positive integer")
    require_decimal(run["run_id"], f"{label}.run_id")
    require_decimal(run["run_attempt"], f"{label}.run_attempt")
    require_safe_component(run["job"], f"{label}.job")
    require_hex64(run["session_nonce"], f"{label}.session_nonce")
    return run


def validate_attestation(value: object, label: str) -> dict[str, Any]:
    attestation = exact_object(value, ATTESTATION_FIELDS, label)
    if attestation["kind"] == "local-unsigned-v1":
        if attestation["artifact_name"] is not None:
            raise ReceiptError(f"{label} local receipt cannot name a trusted artifact")
    elif attestation["kind"] == "github-actions-artifact-v1":
        require_safe_component(attestation["artifact_name"], f"{label}.artifact_name")
    else:
        raise ReceiptError(f"{label}.kind is unsupported")
    return attestation
