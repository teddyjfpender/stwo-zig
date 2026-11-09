"""Trusted cross-host aggregate verifier and sole BG-15 GO authority."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Mapping

from .codec import (
    atomic_write,
    bounded_child,
    sha256_file,
    strict_json,
    with_content_digest,
)
from .model import (
    AGGREGATE_SCHEMA,
    STATUS_NO_GO,
    STATUS_PASS,
    ReceiptError,
    require_hex40,
    require_hex64,
    require_safe_component,
)
from .producer import require_owned_file
from .protocol import load_protocol
from .receipt import validate_aggregate_receipt, validate_host_receipt
from .source import source_identity
from .trust import canonical_artifact_name, validate_trusted_verifier_environment


def _validate_freshness(receipt: dict[str, Any], protocol: dict[str, Any], now: int) -> None:
    created = receipt["created_at_unix"]
    limits = protocol["limits"]
    if created > now + limits["future_clock_skew_seconds"]:
        raise ReceiptError("host receipt creation time is in the future")
    if now - created > limits["receipt_freshness_seconds"]:
        raise ReceiptError("host receipt is stale")


def _validate_trust(
    receipt: dict[str, Any],
    *,
    role: str,
    protocol: dict[str, Any],
    trusted: dict[str, str],
    workflow_sha256: str,
    session_nonce: str,
) -> None:
    source = receipt["source"]
    workflow = receipt["workflow"]
    run = receipt["run"]
    attestation = receipt["attestation"]
    policy = protocol["host_roles"][role]
    trust = protocol["trust"]
    if attestation["kind"] != "github-actions-artifact-v1":
        raise ReceiptError(f"{role} receipt is local unsigned diagnostic evidence")
    if source["clean"] is not True:
        raise ReceiptError(f"{role} receipt source is dirty")
    if workflow != {
        "path": trust["workflow_path"],
        "definition_sha256": workflow_sha256,
        "ref": trust["workflow_ref"],
        "sha": trusted["workflow_sha"],
    }:
        raise ReceiptError(f"{role} receipt workflow identity mismatch")
    expected_run = {
        "provider": "github-actions",
        "repository": trust["repository"],
        "repository_id": trust["repository_id"],
        "repository_owner_id": trust["repository_owner_id"],
        "run_id": trusted["run_id"],
        "run_attempt": trusted["run_attempt"],
        "job": policy["producer_job"],
        "session_nonce": session_nonce,
    }
    if run != expected_run:
        raise ReceiptError(f"{role} receipt run identity mismatch or replay")
    expected_artifact = canonical_artifact_name(
        role, source["commit"], trusted["run_id"], trusted["run_attempt"],
    )
    if attestation["artifact_name"] != expected_artifact:
        raise ReceiptError(f"{role} receipt artifact-channel name mismatch")
    if receipt["host"]["os"] != policy["os"]:
        raise ReceiptError(f"{role} receipt was produced on an unsupported host")


def _validate_receipt_suffix(path: Path, receipt: dict[str, Any], role: str) -> None:
    expected = (
        receipt["source"]["commit"], role, f"{receipt['run']['run_id']}.json",
    )
    if len(path.parts) < 3 or tuple(path.parts[-3:]) != expected:
        raise ReceiptError(f"{role} receipt path is not the canonical bounded layout")


def _checkpoint_verdicts(
    receipts: dict[str, dict[str, Any]], file_digests: dict[str, str],
    protocol: dict[str, Any],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for checkpoint in protocol["checkpoint_order"][:-1]:
        roles = [
            role for role, policy in protocol["host_roles"].items()
            if checkpoint in policy["allocated_checkpoints"]
        ]
        passed = all(
            receipts[role]["checkpoints"][checkpoint]["status"] == STATUS_PASS
            for role in roles
        )
        result[checkpoint] = {
            "status": STATUS_PASS if passed else STATUS_NO_GO,
            "reason": (
                f"{checkpoint} passed on allocated hosts {','.join(roles)}"
                if passed else f"{checkpoint} remains incomplete on an allocated host"
            ),
            "evidence_sha256": [file_digests[role] for role in roles],
        }
    earlier_passed = (
        all(item["status"] == STATUS_PASS for item in result.values())
        and all(receipt["verdict"] == STATUS_PASS for receipt in receipts.values())
    )
    result["BG-15"] = {
        "status": STATUS_PASS if earlier_passed else STATUS_NO_GO,
        "reason": (
            "trusted clean Linux and macOS integration receipts passed"
            if earlier_passed else "one or more mandatory checkpoints remain NO-GO"
        ),
        "evidence_sha256": [file_digests[role] for role in ("linux", "macos")],
    }
    return result


def verify(
    *,
    root: Path,
    authority_root: Path | None = None,
    protocol_path: Path,
    product_schema_path: Path,
    workflow_path: Path,
    linux_receipt_path: Path,
    macos_receipt_path: Path,
    output_root: Path,
    candidate: str,
    session_nonce: str,
    linux_preimages_path: Path | None = None,
    macos_preimages_path: Path | None = None,
    environment: Mapping[str, str] | None = None,
    now: int | None = None,
) -> tuple[Path, dict[str, Any], str]:
    require_hex40(candidate, "candidate")
    require_hex64(session_nonce, "session_nonce")
    authority_root = root if authority_root is None else authority_root.resolve()
    protocol_path = require_owned_file(authority_root, protocol_path, "protocol manifest")
    product_schema_path = require_owned_file(root, product_schema_path, "product schema")
    workflow_path = require_owned_file(
        authority_root, workflow_path, "authority workflow definition",
    )
    protocol, protocol_sha256 = load_protocol(protocol_path)
    trusted = validate_trusted_verifier_environment(protocol, environment)
    product_schema_sha256 = sha256_file(product_schema_path)
    workflow_sha256 = sha256_file(workflow_path)
    source = source_identity(root, candidate, protocol["trust"]["repository"])
    if not source["clean"]:
        raise ReceiptError("aggregate verifier requires a clean candidate checkout")

    paths = {"linux": linux_receipt_path.resolve(), "macos": macos_receipt_path.resolve()}
    if paths["linux"] == paths["macos"]:
        raise ReceiptError("host receipt replay: Linux and macOS paths are identical")
    receipts: dict[str, dict[str, Any]] = {}
    file_digests: dict[str, str] = {}
    current_time = int(time.time()) if now is None else now
    preimage_paths = {
        "linux": linux_preimages_path.resolve() if linux_preimages_path is not None else None,
        "macos": macos_preimages_path.resolve() if macos_preimages_path is not None else None,
    }
    expected_authority = {
        "repository": protocol["trust"]["repository"],
        "commit": trusted["authority_commit"],
        "tree": trusted["authority_tree"],
        "plan_sha256": trusted["authority_plan_sha256"],
    }
    if expected_authority["commit"] == candidate:
        raise ReceiptError("protected architecture authority equals candidate")
    for role, path in paths.items():
        receipt = strict_json(path, protocol["limits"]["max_json_bytes"])
        validate_host_receipt(receipt, protocol, expected_role=role)
        _validate_receipt_suffix(path, receipt, role)
        _validate_freshness(receipt, protocol, current_time)
        _validate_trust(
            receipt, role=role, protocol=protocol, trusted=trusted,
            workflow_sha256=workflow_sha256, session_nonce=session_nonce,
        )
        if receipt["source"] != source:
            raise ReceiptError(f"{role} receipt candidate commit/tree mismatch")
        if receipt["product_schema_sha256"] != product_schema_sha256:
            raise ReceiptError(f"{role} receipt product schema mismatch")
        if receipt["protocol_manifest_sha256"] != protocol_sha256:
            raise ReceiptError(f"{role} receipt protocol manifest mismatch")
        if receipt["authority"] != expected_authority:
            raise ReceiptError(f"{role} receipt authority identity mismatch")
        preimage_path = preimage_paths[role]
        if preimage_path is None or not preimage_path.is_file():
            raise ReceiptError(f"{role} bounded evidence preimages are missing")
        if sha256_file(preimage_path) != receipt["evidence_preimages_sha256"]:
            raise ReceiptError(f"{role} evidence preimage digest mismatch")
        receipts[role] = receipt
        file_digests[role] = sha256_file(path)
    if file_digests["linux"] == file_digests["macos"]:
        raise ReceiptError("host receipt replay: receipt byte digests are identical")
    if receipts["linux"]["content_sha256"] == receipts["macos"]["content_sha256"]:
        raise ReceiptError("host receipt replay: content identities are identical")

    checkpoints = _checkpoint_verdicts(receipts, file_digests, protocol)
    verdict = STATUS_PASS if checkpoints["BG-15"]["status"] == STATUS_PASS else STATUS_NO_GO
    aggregate_run = {
        "provider": "github-actions",
        "repository": protocol["trust"]["repository"],
        "repository_id": protocol["trust"]["repository_id"],
        "repository_owner_id": protocol["trust"]["repository_owner_id"],
        "run_id": trusted["run_id"],
        "run_attempt": trusted["run_attempt"],
        "job": protocol["aggregate_job"],
        "session_nonce": session_nonce,
    }
    aggregate = with_content_digest({
        "schema": AGGREGATE_SCHEMA,
        "schema_version": 1,
        "created_at_unix": current_time,
        "source": source,
        "authority": expected_authority,
        "product_schema_sha256": product_schema_sha256,
        "protocol_manifest_sha256": protocol_sha256,
        "workflow": receipts["linux"]["workflow"],
        "run": aggregate_run,
        "host_receipts": {
            role: {
                "file_sha256": file_digests[role],
                "content_sha256": receipts[role]["content_sha256"],
                "artifact_name": receipts[role]["attestation"]["artifact_name"],
                "evidence_preimages_sha256": receipts[role]["evidence_preimages_sha256"],
            }
            for role in ("linux", "macos")
        },
        "hosts": {role: receipts[role]["host"] for role in ("linux", "macos")},
        "toolchains": {role: receipts[role]["toolchains"] for role in ("linux", "macos")},
        "checkpoints": checkpoints,
        "products": {role: receipts[role]["products"] for role in ("linux", "macos")},
        "commands": {role: receipts[role]["commands"] for role in ("linux", "macos")},
        "evidence": {role: receipts[role]["evidence"] for role in ("linux", "macos")},
        "verdict": verdict,
    })
    validate_aggregate_receipt(aggregate, protocol)

    require_safe_component(candidate, "candidate output path")
    if verdict == STATUS_PASS:
        output = bounded_child(output_root, candidate, "receipt.json")
    else:
        run_component = f"{trusted['run_id']}-{trusted['run_attempt']}-NO-GO.json"
        require_safe_component(run_component, "NO-GO attempt path")
        output = bounded_child(output_root, candidate, "attempts", run_component)
    digest = atomic_write(output, aggregate, protocol["limits"]["max_json_bytes"])
    return output, aggregate, digest
