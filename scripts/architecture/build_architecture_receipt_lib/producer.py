"""Host-local architecture evidence producer."""

from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path
from typing import Any

from .codec import (
    atomic_write,
    bounded_child,
    sha256_file,
    strict_json,
    with_content_digest,
)
from .model import (
    EVIDENCE_NAMES,
    HOST_SCHEMA,
    STATUS_NO_GO,
    STATUS_NOT_ALLOCATED,
    ReceiptError,
    require_decimal,
    require_hex40,
    require_hex64,
    require_safe_component,
)
from .protocol import load_protocol
from .receipt import validate_evidence_manifest, validate_host_receipt
from .source import host_identity, source_identity, toolchain_identity
from .trust import workflow_and_run


def detected_role() -> str:
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        return "linux"
    raise ReceiptError(f"unsupported architecture receipt host: {sys.platform}")


def empty_evidence() -> dict[str, Any]:
    return {
        "schema": "build-architecture-host-evidence-v1",
        "checkpoints": {},
        "products": [],
        "commands": [],
        "evidence": {
            name: {
                "status": STATUS_NO_GO,
                "reason": "evidence has not been produced",
                "sha256": None,
            }
            for name in EVIDENCE_NAMES
        },
    }


def expand_checkpoints(
    evidence: dict[str, Any], protocol: dict[str, Any], role: str,
) -> dict[str, Any]:
    allocated = set(protocol["host_roles"][role]["allocated_checkpoints"])
    supplied = evidence["checkpoints"]
    result: dict[str, Any] = {}
    for checkpoint in protocol["checkpoint_order"][:-1]:
        if checkpoint not in allocated:
            result[checkpoint] = {
                "status": STATUS_NOT_ALLOCATED,
                "reason": f"{checkpoint} is not allocated to {role}",
                "evidence_sha256": [],
            }
        elif checkpoint in supplied:
            result[checkpoint] = supplied[checkpoint]
        else:
            result[checkpoint] = {
                "status": STATUS_NO_GO,
                "reason": f"{checkpoint} evidence is incomplete on {role}",
                "evidence_sha256": [],
            }
    return result


def require_owned_file(root: Path, path: Path, label: str) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve(strict=True)
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ReceiptError(f"{label} must be a repository-owned file")
    return resolved


def produce(
    *,
    root: Path,
    authority_root: Path | None = None,
    protocol_path: Path,
    product_schema_path: Path,
    workflow_path: Path,
    evidence_path: Path | None,
    output_root: Path,
    role: str,
    candidate: str | None,
    run_id: str,
    run_attempt: str,
    session_nonce: str,
    attestation_mode: str,
    authority_commit: str | None = None,
    authority_tree: str | None = None,
    authority_plan_sha256: str | None = None,
    evidence_preimages_path: Path | None = None,
    now: int | None = None,
) -> tuple[Path, dict[str, Any], str]:
    authority_root = root if authority_root is None else authority_root.resolve()
    protocol_path = require_owned_file(authority_root, protocol_path, "protocol manifest")
    product_schema_path = require_owned_file(root, product_schema_path, "product schema")
    workflow_owner = authority_root if attestation_mode == "github-actions-artifact" else root
    workflow_path = require_owned_file(
        workflow_owner, workflow_path, "workflow definition",
    )
    protocol, protocol_sha256 = load_protocol(protocol_path)
    if role not in protocol["host_roles"]:
        raise ReceiptError(f"unsupported host role: {role}")
    require_decimal(run_id, "run_id")
    require_decimal(run_attempt, "run_attempt")
    require_hex64(session_nonce, "session_nonce")
    if candidate is not None:
        require_hex40(candidate, "candidate")
    source = source_identity(root, candidate, protocol["trust"]["repository"])
    if attestation_mode == "github-actions-artifact":
        require_hex40(authority_commit, "authority_commit")
        require_hex40(authority_tree, "authority_tree")
        require_hex64(authority_plan_sha256, "authority_plan_sha256")
        if authority_commit == source["commit"]:
            raise ReceiptError("trusted authority must be distinct from candidate")
        if evidence_preimages_path is None:
            raise ReceiptError("trusted host receipt requires evidence preimages")
    else:
        authority_commit = authority_commit or source["commit"]
        authority_tree = authority_tree or source["tree"]
        authority_plan_sha256 = authority_plan_sha256 or ("0" * 64)
    preimages_sha256 = (
        sha256_file(evidence_preimages_path.resolve(strict=True))
        if evidence_preimages_path is not None else "0" * 64
    )
    authority = {
        "repository": protocol["trust"]["repository"],
        "commit": authority_commit,
        "tree": authority_tree,
        "plan_sha256": authority_plan_sha256,
    }
    product_schema_sha256 = sha256_file(product_schema_path)
    workflow_sha256 = sha256_file(workflow_path)
    workflow_relative = workflow_path.relative_to(workflow_owner.resolve()).as_posix()
    if workflow_relative != protocol["trust"]["workflow_path"]:
        raise ReceiptError("workflow definition path differs from trusted protocol")
    workflow, run, attestation = workflow_and_run(
        mode=attestation_mode,
        role=role,
        source=source,
        workflow_path=workflow_relative,
        workflow_sha256=workflow_sha256,
        protocol=protocol,
        run_id=run_id,
        run_attempt=run_attempt,
        session_nonce=session_nonce,
    )
    if attestation_mode == "github-actions-artifact" and not source["clean"]:
        raise ReceiptError("trusted host receipts require a clean candidate checkout")

    if evidence_path is None:
        evidence = empty_evidence()
    else:
        evidence_path = require_owned_file(root, evidence_path, "host evidence manifest")
        evidence = strict_json(evidence_path, protocol["limits"]["max_json_bytes"])
    validate_evidence_manifest(evidence, protocol, role)
    toolchains = toolchain_identity()
    receipt_without_digest = {
        "schema": HOST_SCHEMA,
        "schema_version": 1,
        "created_at_unix": int(time.time()) if now is None else now,
        "source": source,
        "authority": authority,
        "evidence_preimages_sha256": preimages_sha256,
        "product_schema_sha256": product_schema_sha256,
        "protocol_manifest_sha256": protocol_sha256,
        "workflow": workflow,
        "run": run,
        "host": host_identity(role),
        "toolchains": toolchains,
        "checkpoints": expand_checkpoints(evidence, protocol, role),
        "products": evidence["products"],
        "commands": evidence["commands"],
        "evidence": evidence["evidence"],
        "attestation": attestation,
        "verdict": STATUS_NO_GO,
    }
    # Derive the verdict only after every evidence-bearing field is fixed.
    from .receipt import collection_verdict  # Avoid exporting construction internals.

    verdict = collection_verdict(
        source=receipt_without_digest["source"], host=receipt_without_digest["host"],
        attestation=receipt_without_digest["attestation"],
        checkpoints=receipt_without_digest["checkpoints"],
        products=receipt_without_digest["products"],
        commands=receipt_without_digest["commands"],
        evidence=receipt_without_digest["evidence"], protocol=protocol, role=role,
        toolchains=toolchains,
    )
    receipt_without_digest["verdict"] = verdict
    receipt = with_content_digest(receipt_without_digest)
    validate_host_receipt(receipt, protocol, expected_role=role)

    require_safe_component(source["commit"], "commit path")
    require_safe_component(role, "host role path")
    require_safe_component(run_id, "run ID path")
    output = bounded_child(output_root, source["commit"], role, f"{run_id}.json")
    digest = atomic_write(output, receipt, protocol["limits"]["max_json_bytes"])
    return output, receipt, digest


def default_run_id() -> str:
    return str(int(time.time()))


def default_session_nonce() -> str:
    return secrets.token_hex(32)
