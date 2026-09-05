"""Protocol authority for resumable segmented Ethereum block proofs."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_DIR = REPO_ROOT / "autoresearch" / "benchmarks"
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))
import ethereum_block_benchmark_protocol as benchmark  # noqa: E402
from scripts import ethereum_block_proof_plan_authority as plan_authority


PLAN_SCHEMA = "stwo.ethereum.block-proof-plan.v4"
TASK_REQUEST_SCHEMA = "stwo.ethereum.block-proof-task-request.v5"
TASK_RECORD_SCHEMA = "stwo.ethereum.block-proof-task-record.v2"
EMPTY_AUTHORITY_SCHEMA = benchmark.EMPTY_AUTHORITY_SCHEMA
EMPTY_TASK_RECORD_SCHEMA = "stwo.ethereum.canonical-empty-leaf-task-record.v1"
CHILD_RESULT_SCHEMA = "stwo.ethereum.block-proof-child-result.v1"
VERIFY_RECEIPT_SCHEMA = "stwo.ethereum.block-proof-verification-receipt.v2"
CHECKPOINT_SCHEMA = "stwo.ethereum.block-proof-level-checkpoint.v2"
TOPOLOGY_TEST_MANIFEST_SCHEMA = "stwo.ethereum.block-proof-topology-test-publication.v1"
PROCESS_RECEIPT_SCHEMA = "stwo.ethereum.block-proof-subprocess-receipt.v1"
LEAF_PRODUCER_OBSERVATION_SCHEMA = (
    "stwo.ethereum.block-proof-leaf-stream-observation.v1"
)
LEAF_STREAM_SOURCE_SCHEMA = "stwo.ethereum.block-proof-leaf-stream-source.v2"
ATTEMPT_SUMMARY_SCHEMA = "stwo.ethereum.block-proof-attempt-summary.v2"
PARENT_EXECUTION_SCHEMA = plan_authority.PARENT_EXECUTION_SCHEMA
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TEST_ONLY_NODE_DESCRIPTOR = {
    "production_admissible": False,
    "schema": "stwo.ethereum.block-proof-test-node-descriptor.v1",
    "status": "test_only_verifier_minted_descriptor_unavailable",
}


class ProofProtocolError(ValueError):
    pass


class VerifierMintedDescriptorPlanUnavailable(ProofProtocolError):
    """Production launch is closed until typed node descriptors are admitted."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ProofProtocolError(message)


def exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


def canonical_bytes(value: Any) -> bytes:
    try:
        return (json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"),
        ) + "\n").encode("ascii")
    except (TypeError, ValueError) as error:
        raise ProofProtocolError("evidence is not canonical JSON") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def content_sha256(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("content_sha256", None)
    return sha256_bytes(canonical_bytes(unsigned))


def seal(value: dict[str, Any]) -> dict[str, Any]:
    result = dict(value)
    result["content_sha256"] = content_sha256(result)
    return result


def _sha(value: Any, where: str) -> str:
    require(type(value) is str and SHA256.fullmatch(value), f"{where} differs")
    return value


def _positive(value: Any, where: str) -> int:
    require(type(value) is int and value > 0, f"{where} must be positive")
    return value


def _identity(value: Any, where: str, *, path: bool = False) -> dict[str, Any]:
    keys = {"bytes", "sha256"} | ({"path"} if path else set())
    value = exact(value, keys, where)
    _positive(value["bytes"], f"{where}.bytes")
    _sha(value["sha256"], f"{where}.sha256")
    if path:
        require(type(value["path"]) is str and value["path"],
                f"{where}.path differs")
        relative = Path(value["path"])
        require(not relative.is_absolute() and ".." not in relative.parts,
                f"{where}.path differs")
    return value


def _typed_source_identity(value: Any, where: str) -> dict[str, Any]:
    value = exact(value, {"schema", "path", "bytes", "sha256"}, where)
    require(type(value["schema"]) is str and value["schema"],
            f"{where}.schema differs")
    _identity({key: value[key] for key in ("path", "bytes", "sha256")},
              where, path=True)
    return value


def validate_process_receipt(
    value: Any, expected_executable: dict[str, Any], expected_role: str,
) -> dict[str, Any]:
    value = exact(value, {
        "schema", "role", "executable", "argv", "exit_code", "stdout_bytes",
        "stderr_bytes", "timing",
    }, f"{expected_role} process receipt")
    require(value["schema"] == PROCESS_RECEIPT_SCHEMA
            and value["role"] == expected_role,
            f"{expected_role} process receipt schema differs")
    _identity(value["executable"], f"{expected_role} process executable")
    require(value["executable"] == expected_executable,
            f"{expected_role} process executable differs")
    require(type(value["argv"]) is list and len(value["argv"]) >= 2
            and all(type(argument) is str and argument for argument in value["argv"]),
            f"{expected_role} process argv differs")
    require(value["exit_code"] == 0 and value["stdout_bytes"] == 0
            and value["stderr_bytes"] == 0,
            f"{expected_role} process transport differs")
    timing = exact(value["timing"], {"wall_ns", "user_ns", "system_ns"},
                   f"{expected_role} process timing")
    require(all(type(item) is int and item >= 0 for item in timing.values()),
            f"{expected_role} process timing differs")
    return value


def validate_producer_custody(
    value: Any, expected_executable: dict[str, Any], request: dict[str, Any],
) -> dict[str, Any]:
    if request["task_kind"] != "real_leaf_proof":
        return validate_process_receipt(value, expected_executable, "proof_producer")
    value = exact(value, {
        "schema", "role", "executable", "argv", "stream_session_sha256",
        "segment_index", "progress_record_sha256", "prove_timing",
    }, "leaf stream producer observation")
    require(value["schema"] == LEAF_PRODUCER_OBSERVATION_SCHEMA
            and value["role"] == "leaf_stream_producer"
            and value["executable"] == expected_executable
            and value["segment_index"] == request["node_index"],
            "leaf stream producer observation authority differs")
    _identity(value["executable"], "leaf stream producer executable")
    require(type(value["argv"]) is list and len(value["argv"]) >= 2
            and all(type(item) is str and item for item in value["argv"]),
            "leaf stream producer argv differs")
    _sha(value["stream_session_sha256"], "leaf stream producer session")
    _sha(value["progress_record_sha256"], "leaf stream progress record")
    timing = exact(value["prove_timing"], {"wall_ns", "user_ns", "system_ns"},
                   "leaf stream producer timing")
    require(all(type(item) is int and item >= 0 for item in timing.values()),
            "leaf stream producer timing differs")
    return value


def _validate_attempt_history(value: Any, where: str) -> list[dict[str, Any]]:
    require(type(value) is list, f"{where} differs")
    for index, attempt in enumerate(value):
        attempt = exact(attempt, {
            "schema", "attempt_index", "attempt_path", "classification",
            "started_unix_ns", "ended_unix_ns", "observed_wall_ns", "clock_reliable",
            "inventory", "inventory_sha256",
        }, f"{where}[{index}]")
        require(attempt["schema"] == "stwo.ethereum.block-proof-attempt-custody.v1"
                and attempt["attempt_index"] == index
                and attempt["classification"]
                in ("failed_after_launch", "indeterminate_after_launch"),
                f"{where}[{index}] identity differs")
        require(type(attempt["clock_reliable"]) is bool
                and ((attempt["clock_reliable"] is True
                      and type(attempt["observed_wall_ns"]) is int
                      and attempt["observed_wall_ns"] >= 0)
                     or (attempt["clock_reliable"] is False
                         and attempt["observed_wall_ns"] is None)),
                f"{where}[{index}] wall custody differs")
        require(attempt["inventory_sha256"]
                == sha256_bytes(canonical_bytes(attempt["inventory"])),
                f"{where}[{index}] inventory differs")
    return value


def attempt_summary(
    successful_attempt_index: int, history: list[dict[str, Any]],
    prove_timing: dict[str, Any], verify_timing: dict[str, Any],
) -> dict[str, Any]:
    _validate_attempt_history(history, "proof attempt history")
    require(successful_attempt_index == len(history),
            "successful proof attempt index differs")
    operational_wall_ns = (
        sum(attempt["observed_wall_ns"] or 0 for attempt in history)
        + prove_timing["wall_ns"]
        + verify_timing["wall_ns"]
    )
    failed = [attempt for attempt in history
              if attempt["classification"] == "failed_after_launch"]
    indeterminate = [attempt for attempt in history
                     if attempt["classification"] == "indeterminate_after_launch"]
    return {
        "schema": ATTEMPT_SUMMARY_SCHEMA,
        "total_attempt_count": successful_attempt_index + 1,
        "successful_attempt_index": successful_attempt_index,
        "failed_attempt_count": len(failed),
        "indeterminate_attempt_count": len(indeterminate),
        "attempt_history": history,
        "observed_operational_wall_ns": operational_wall_ns,
        "successful_prove_verify_wall_ns": (
            prove_timing["wall_ns"] + verify_timing["wall_ns"]
        ),
        "performance_claim_eligible": len(history) == 0,
    }


def validate_attempt_summary(
    value: Any, prove_timing: dict[str, Any], verify_timing: dict[str, Any],
) -> dict[str, Any]:
    value = exact(value, {
        "schema", "total_attempt_count", "successful_attempt_index",
        "failed_attempt_count", "indeterminate_attempt_count", "attempt_history",
        "observed_operational_wall_ns", "successful_prove_verify_wall_ns",
        "performance_claim_eligible",
    }, "proof attempt summary")
    require(value["schema"] == ATTEMPT_SUMMARY_SCHEMA,
            "proof attempt summary schema differs")
    history = _validate_attempt_history(
        value["attempt_history"], "proof attempt history",
    )
    expected = attempt_summary(
        value["successful_attempt_index"], history, prove_timing, verify_timing,
    )
    require(value == expected, "proof attempt summary differs")
    return value


def validate_plan(value: Any) -> dict[str, Any]:
    from scripts import ethereum_block_proof_plan_validation as validation

    return validation.validate(value)


def recursive_statement_for(
    plan: dict[str, Any], level: int, node_index: int,
) -> str:
    offset = sum(plan["node_counts"][:level]) + node_index
    return plan["expected_statements"][offset]["recursive_statement_sha256"]


def proof_statement_for(plan: dict[str, Any], level: int, node_index: int) -> str:
    if level == 0 and node_index < plan["real_segment_count"]:
        return plan["segments"][node_index]["source_public_statement_sha256"]
    return recursive_statement_for(plan, level, node_index)


def _child_projection(record: dict[str, Any]) -> dict[str, Any]:
    if record["schema"] == EMPTY_TASK_RECORD_SCHEMA:
        authority = record["empty_authority"]
        return {
            "kind": "canonical_empty",
            "level": record["level"],
            "node_index": record["node_index"],
            "record_sha256": record["content_sha256"],
            "statement_sha256": authority["statement_sha256"],
            "authority_sha256": authority["authority_sha256"],
            "proof_sha256": None,
            "verification_receipt_sha256": None,
            "proof_profile_authority": {
                "entry_sha256": authority["proof_profile_entry_sha256"],
            },
        }
    artifact = record["proof_artifact"]
    return {
        "kind": record["record_kind"],
        "level": record["level"],
        "node_index": record["node_index"],
        "record_sha256": record["content_sha256"],
        "statement_sha256": artifact["statement_sha256"],
        "authority_sha256": artifact["root_sha256"],
        "proof_sha256": artifact["proof"]["sha256"],
        "verification_receipt_sha256": artifact["verification_receipt"]["sha256"],
        "proof_profile_authority": artifact["proof_profile_authority"],
    }


def task_request(
    plan: dict[str, Any], level: int, node_index: int,
    child_records: list[dict[str, Any]], *, test_only_descriptors: bool = False,
) -> dict[str, Any]:
    """Build one request from a plan already admitted by ``validate_plan``."""
    counts = plan["node_counts"]
    require(0 <= level <= plan["levels"] and 0 <= node_index < counts[level],
            "proof task lies outside plan topology")
    if level == 0:
        require(child_records == [], "leaf proof task has children")
        scope = "leaf"
        is_padding_leaf = node_index >= plan["real_segment_count"]
        covered = [] if is_padding_leaf else [node_index]
        children = []
        source = None if is_padding_leaf else plan["segments"][node_index]["source"]
        task_kind = ("canonical_empty_authority" if is_padding_leaf
                     else "real_leaf_proof")
        proof_profile_authority = (
            None if is_padding_leaf else
            plan["security_parameters"]["recursive_ethereum_leaf"]
        )
        verification_security = (
            None if is_padding_leaf else
            plan_authority.receipt_security(
                plan["security_parameters"], leaf=True,
            )
        )
    else:
        start = node_index * plan["arity"]
        stop = start + plan["arity"]
        require(stop <= counts[level - 1], "proof task has a ragged parent")
        expected_children = [(level - 1, index) for index in range(start, stop)]
        actual_children = [
            (record["level"], record["node_index"]) for record in child_records
        ]
        require(actual_children == expected_children, "proof task children differ")
        covered = []
        children = []
        for record in child_records:
            covered.extend(record["covered_segments"])
            children.append(_child_projection(record))
        require(covered == sorted(set(covered)), "proof task segment coverage overlaps")
        scope = "final_root" if level == plan["levels"] else "parent"
        source = None
        is_padding_leaf = False
        task_kind = "recursive_parent_proof"
        if not test_only_descriptors:
            raise VerifierMintedDescriptorPlanUnavailable(
                "verifier-minted node descriptor plan is not admitted"
            )
        proof_profile_authority = TEST_ONLY_NODE_DESCRIPTOR
        verification_security = plan_authority.receipt_security(
            plan["security_parameters"], leaf=False,
        )
    task_id = ((f"empty-leaf-{node_index:06d}" if is_padding_leaf
                else f"segment-{node_index:06d}") if level == 0
               else f"level-{level:04d}-node-{node_index:06d}")
    request = {
        "schema": TASK_REQUEST_SCHEMA,
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "task_id": task_id,
        "scope": scope,
        "level": level,
        "node_index": node_index,
        "task_kind": task_kind,
        "covered_segments": covered,
        "children": children,
        "source_segment": source,
        "expected_statement_sha256": proof_statement_for(plan, level, node_index),
        "recursive_statement_sha256": recursive_statement_for(
            plan, level, node_index,
        ),
        "proof_profile_authority": proof_profile_authority,
        "verification_security": verification_security,
    }
    if is_padding_leaf:
        request["authority_path"] = "empty-authority.json"
    else:
        request["proof_path"] = "proof.bin"
        request["receipt_path"] = "verify-receipt.json"
    return seal(request)


def empty_authority(
    plan: dict[str, Any], request: dict[str, Any],
) -> dict[str, Any]:
    require(request["task_kind"] == "canonical_empty_authority"
            and request["level"] == 0
            and plan["real_segment_count"] <= request["node_index"]
            < plan["slot_capacity"]
            and request["covered_segments"] == []
            and request["children"] == []
            and request["source_segment"] is None,
            "canonical empty leaf request differs")
    authority = {
        "schema": EMPTY_AUTHORITY_SCHEMA,
        "kind": "canonical_empty",
        "session_id": plan["session_id"],
        "job_sha256": plan["job_sha256"],
        "topology_sha256": plan["topology_sha256"],
        "segment_leaf_vk_sha256": sha256_bytes(
            b"stwo.ethereum.block-proof/test-only-empty-vk/v1"
        ),
        "recursive_parent_vk_sha256": sha256_bytes(
            b"stwo.ethereum.block-proof/test-only-parent-vk/v1"
        ),
        "level": 0,
        "node_index": request["node_index"],
        "slot_capacity": plan["slot_capacity"],
        "statement_sha256": request["expected_statement_sha256"],
        "proof_present": False,
        "proof_profile_entry_sha256": sha256_bytes(
            b"stwo.ethereum.block-proof/test-only-empty-descriptor/v1"
        ),
    }
    authority["authority_sha256"] = benchmark.canonical_empty_authority_sha256(authority)
    return authority


def validate_empty_authority(
    value: Any, plan: dict[str, Any], request: dict[str, Any],
) -> dict[str, Any]:
    value = exact(value, {
        "schema", "kind", "session_id", "job_sha256", "topology_sha256",
        "segment_leaf_vk_sha256", "recursive_parent_vk_sha256", "level",
        "node_index", "slot_capacity", "statement_sha256", "proof_present",
        "proof_profile_entry_sha256", "authority_sha256",
    }, "canonical empty leaf authority")
    expected = empty_authority(plan, request)
    require(value == expected, "canonical empty leaf authority differs")
    return value


def empty_task_record(
    plan: dict[str, Any], request: dict[str, Any], authority: dict[str, Any],
    authority_identity: dict[str, Any],
) -> dict[str, Any]:
    validate_empty_authority(authority, plan, request)
    _identity(authority_identity, "canonical empty leaf authority file")
    return seal({
        "schema": EMPTY_TASK_RECORD_SCHEMA,
        "record_kind": "canonical_empty",
        "task_id": request["task_id"],
        "request_sha256": request["content_sha256"],
        "scope": "leaf",
        "level": 0,
        "node_index": request["node_index"],
        "covered_segments": [],
        "source_segment": None,
        "children": [],
        "empty_authority": authority,
        "files": {
            "authority": {"path": request["authority_path"], **authority_identity},
        },
    })


def validate_empty_task_record(
    value: Any, plan: dict[str, Any], request: dict[str, Any],
) -> dict[str, Any]:
    value = exact(value, {
        "schema", "record_kind", "task_id", "request_sha256", "scope", "level",
        "node_index", "covered_segments", "source_segment", "children",
        "empty_authority", "files", "content_sha256",
    }, "canonical empty leaf task record")
    require(value["schema"] == EMPTY_TASK_RECORD_SCHEMA
            and value["record_kind"] == "canonical_empty",
            "canonical empty leaf task record schema differs")
    for field in (
        "task_id", "scope", "level", "node_index", "covered_segments",
        "source_segment", "children",
    ):
        require(value[field] == request[field],
                f"canonical empty leaf task record {field} differs")
    require(value["request_sha256"] == request["content_sha256"],
            "canonical empty leaf request digest differs")
    validate_empty_authority(value["empty_authority"], plan, request)
    files = exact(value["files"], {"authority"}, "canonical empty leaf files")
    _identity(files["authority"], "canonical empty leaf authority file", path=True)
    require(files["authority"]["path"] == request["authority_path"],
            "canonical empty leaf authority path differs")
    require(value["content_sha256"] == content_sha256(value),
            "canonical empty leaf task record digest differs")
    return value


def expected_receipt(
    request: dict[str, Any], proof: dict[str, Any], root_sha256: str,
    verifier: dict[str, Any], security_parameters: dict[str, Any],
) -> dict[str, Any]:
    expected_security = plan_authority.receipt_security(
        security_parameters, leaf=request["task_kind"] == "real_leaf_proof",
    )
    require(request["verification_security"] == expected_security,
            "proof request verification security differs")
    return {
        "schema": VERIFY_RECEIPT_SCHEMA,
        "status": "verified",
        "scope": request["scope"],
        "level": request["level"],
        "node_index": request["node_index"],
        "statement_sha256": request["expected_statement_sha256"],
        "root_sha256": root_sha256,
        "proof_bytes": proof["bytes"],
        "proof_sha256": proof["sha256"],
        "verifier_sha256": verifier["sha256"],
        "security": request["verification_security"],
        "proof_profile_authority": request["proof_profile_authority"],
        "fresh_verification": True,
    }


def task_record(
    plan: dict[str, Any], request: dict[str, Any], *, proof: dict[str, Any],
    receipt: dict[str, Any], receipt_identity: dict[str, Any], root_sha256: str,
    prove_timing: dict[str, Any], verify_timing: dict[str, Any], attempt_index: int,
    attempt_history: list[dict[str, Any]], producer_process: dict[str, Any],
    verifier_process: dict[str, Any], proof_path: str, receipt_path: str,
) -> dict[str, Any]:
    require(request["task_kind"] in ("real_leaf_proof", "recursive_parent_proof"),
            "proof task kind differs")
    _sha(root_sha256, "proof task root")
    expected = expected_receipt(
        request, proof, root_sha256, plan["verifier"],
        plan["security_parameters"],
    )
    require(receipt == expected, "proof verifier receipt differs")
    validate_producer_custody(producer_process, plan["prover"], request)
    validate_process_receipt(verifier_process, plan["verifier"], "fresh_verifier")
    require(verifier_process["timing"] == verify_timing,
            "fresh verifier timing differs from process custody")
    attempts = attempt_summary(
        attempt_index, attempt_history, prove_timing, verify_timing,
    )
    security = plan_authority.artifact_security(
        plan["security_parameters"],
        leaf=request["task_kind"] == "real_leaf_proof",
        proof_bytes=proof["bytes"],
    )
    artifact = {
        "scope": request["scope"],
        "level": request["level"],
        "node_index": request["node_index"],
        "child_nodes": [
            {"level": child["level"], "node_index": child["node_index"]}
            for child in request["children"]
        ],
        "covered_segments": request["covered_segments"],
        "statement_sha256": request["expected_statement_sha256"],
        "recursive_statement_sha256": request["recursive_statement_sha256"],
        "root_sha256": root_sha256,
        "proof": {"bytes": proof["bytes"], "sha256": proof["sha256"]},
        "prover": plan["prover"],
        "verifier": plan["verifier"],
        "verification_receipt": receipt_identity,
        "prove_timing": prove_timing,
        "fresh_verify_timing": verify_timing,
        "processes": {
            "producer": producer_process,
            "fresh_verifier": verifier_process,
        },
        "attempts": attempts,
        "security": security,
        "proof_profile_authority": request["proof_profile_authority"],
    }
    return seal({
        "schema": TASK_RECORD_SCHEMA,
        "record_kind": ("verified_real_leaf" if request["task_kind"] == "real_leaf_proof"
                        else "verified_recursive_parent"),
        "task_id": request["task_id"],
        "request_sha256": request["content_sha256"],
        "scope": request["scope"],
        "level": request["level"],
        "node_index": request["node_index"],
        "covered_segments": request["covered_segments"],
        "source_segment": request["source_segment"],
        "children": request["children"],
        "proof_artifact": artifact,
        "files": {
            "proof": {"path": proof_path, **proof},
            "verification_receipt": {"path": receipt_path, **receipt_identity},
        },
    })


def validate_task_record(
    value: Any, plan: dict[str, Any], request: dict[str, Any],
) -> dict[str, Any]:
    require(request["task_kind"] in ("real_leaf_proof", "recursive_parent_proof"),
            "proof task kind differs")
    value = exact(value, {
        "schema", "record_kind", "task_id", "request_sha256", "scope", "level",
        "node_index", "covered_segments", "source_segment", "children", "proof_artifact",
        "files", "content_sha256",
    }, "proof task record")
    require(value["schema"] == TASK_RECORD_SCHEMA, "proof task record schema differs")
    expected_kind = ("verified_real_leaf"
                     if request["task_kind"] == "real_leaf_proof"
                     else "verified_recursive_parent")
    require(value["record_kind"] == expected_kind, "proof task record kind differs")
    for field in (
        "task_id", "scope", "level", "node_index", "covered_segments",
        "source_segment", "children",
    ):
        require(value[field] == request[field], f"proof task record {field} differs")
    require(value["request_sha256"] == request["content_sha256"],
            "proof task request digest differs")
    artifact = value["proof_artifact"]
    exact(artifact, {
        "scope", "level", "node_index", "child_nodes", "covered_segments",
        "statement_sha256", "recursive_statement_sha256", "root_sha256", "proof", "prover", "verifier",
        "verification_receipt", "prove_timing", "fresh_verify_timing", "processes",
        "attempts", "security", "proof_profile_authority",
    }, "proof artifact")
    for field in ("scope", "level", "node_index", "covered_segments"):
        require(artifact[field] == request[field], f"proof artifact {field} differs")
    require(artifact["child_nodes"] == [
        {"level": child["level"], "node_index": child["node_index"]}
        for child in request["children"]
    ], "proof artifact child topology differs")
    require(artifact["statement_sha256"] == request["expected_statement_sha256"],
            "proof artifact statement differs")
    require(artifact["recursive_statement_sha256"]
            == request["recursive_statement_sha256"],
            "proof artifact recursive statement differs")
    _sha(artifact["root_sha256"], "proof artifact root")
    for field in ("proof", "prover", "verifier", "verification_receipt"):
        _identity(artifact[field], f"proof artifact {field}")
    require(artifact["prover"] == plan["prover"] and artifact["verifier"] == plan["verifier"],
            "proof artifact executable identity differs")
    processes = exact(
        artifact["processes"], {"producer", "fresh_verifier"},
        "proof artifact processes",
    )
    validate_producer_custody(processes["producer"], plan["prover"], request)
    validate_process_receipt(
        processes["fresh_verifier"], plan["verifier"], "fresh_verifier",
    )
    for timing_name in ("prove_timing", "fresh_verify_timing"):
        timing = exact(artifact[timing_name], {"wall_ns", "user_ns", "system_ns"},
                       f"proof artifact {timing_name}")
        require(all(type(item) is int and item >= 0 for item in timing.values()),
                f"proof artifact {timing_name} differs")
    require(processes["fresh_verifier"]["timing"] == artifact["fresh_verify_timing"],
            "proof artifact verifier timing custody differs")
    validate_attempt_summary(
        artifact["attempts"], artifact["prove_timing"],
        artifact["fresh_verify_timing"],
    )
    expected_security = plan_authority.artifact_security(
        plan["security_parameters"],
        leaf=request["task_kind"] == "real_leaf_proof",
        proof_bytes=artifact["proof"]["bytes"],
    )
    require(artifact["security"] == expected_security, "proof artifact security differs")
    require(artifact["proof_profile_authority"]
            == request["proof_profile_authority"],
            "proof artifact profile authority differs")
    files = exact(value["files"], {"proof", "verification_receipt"}, "proof task files")
    for name in files:
        _identity(files[name], f"proof task file {name}", path=True)
    attempt_index = artifact["attempts"]["successful_attempt_index"]
    expected_prefix = f"attempts/attempt-{attempt_index:06d}/"
    require(files["proof"]["path"] == expected_prefix + "proof.bin"
            and files["verification_receipt"]["path"]
            == expected_prefix + "verify-receipt.json",
            "proof task file path differs")
    require({key: files["proof"][key] for key in ("bytes", "sha256")}
            == artifact["proof"], "proof task proof file differs")
    require({key: files["verification_receipt"][key] for key in ("bytes", "sha256")}
            == artifact["verification_receipt"], "proof task receipt file differs")
    require(value["content_sha256"] == content_sha256(value), "proof task record digest differs")
    return value


def level_checkpoint(
    plan: dict[str, Any], level: int, records: list[dict[str, Any]],
    prior_checkpoint_sha256: str | None,
) -> dict[str, Any]:
    require(len(records) == plan["node_counts"][level], "proof level is incomplete")
    nodes = []
    for record in records:
        projection = _child_projection(record)
        nodes.append({
            **projection,
            "covered_segments": record["covered_segments"],
        })
    return seal({
        "schema": CHECKPOINT_SCHEMA,
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "level": level,
        "node_count": len(records),
        "nodes": nodes,
        "prior_checkpoint_sha256": prior_checkpoint_sha256,
    })


def final_result(
    plan: dict[str, Any], all_records: list[dict[str, Any]],
    producer_sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    proof_records = [
        record for record in all_records if record["schema"] == TASK_RECORD_SCHEMA
    ]
    empty_records = [
        record for record in all_records if record["schema"] == EMPTY_TASK_RECORD_SCHEMA
    ]
    artifacts = [record["proof_artifact"] for record in proof_records]
    empty_authorities = [record["empty_authority"] for record in empty_records]
    topology_artifacts = artifacts[:-1]
    topology_scope = (
        "parent" if any(artifact["scope"] == "parent" for artifact in topology_artifacts)
        else "leaf"
    )
    real_leaf_proofs = sum(record["record_kind"] == "verified_real_leaf"
                           for record in proof_records)
    recursive_parent_proofs = sum(
        record["record_kind"] == "verified_recursive_parent"
        for record in proof_records
    ) - 1
    custody = {
        "schema": benchmark.PROOF_CUSTODY_SCHEMA,
        "scope": topology_scope,
        "expected_segment_count": len(plan["segments"]),
        "covered_segments": list(range(len(plan["segments"]))),
        "segment_coverage_root_sha256": benchmark.segment_coverage_root_sha256(
            topology_artifacts,
        ),
        "empty_authority_root_sha256": benchmark.empty_authority_root_sha256(
            empty_authorities,
        ),
        "proof_counts": {
            "real_leaf_proofs": real_leaf_proofs,
            "proofless_empty_authorities": len(empty_authorities),
            "recursive_parent_proofs": recursive_parent_proofs,
            "total_proofs": len(topology_artifacts),
        },
        "topology": {
            "arity": plan["arity"],
            "levels": plan["levels"],
            "node_counts": plan["node_counts"],
            "real_segment_count": plan["real_segment_count"],
            "slot_capacity": plan["slot_capacity"],
            "padded_leaf_count": plan["padded_leaf_count"],
            "empty_leaf_count": plan["empty_leaf_count"],
            "topology_sha256": benchmark.topology_sha256(
                plan["arity"], plan["levels"], plan["node_counts"],
                plan["real_segment_count"],
            ),
        },
        "artifacts": topology_artifacts,
        "empty_authorities": empty_authorities,
        "producer_sessions": producer_sessions,
        "profile_policy_template": copy.deepcopy(plan["profile_policy_template"]),
        "statement_binding": copy.deepcopy(plan["statement_binding"]),
        "final_root": None,
    }
    result = copy.deepcopy(plan["result_template"])
    result["systems"]["stwo"]["proof_custody"] = custody
    try:
        benchmark.validate_result(result, {
            "statement_sha256": plan["benchmark_statement_sha256"],
            "matched_guest_statement_reproduced": plan["statement_binding"][
                "matched_guest_statement_reproduced"
            ],
            "promotion_ready": False,
        })
    except benchmark.BenchmarkProtocolError as error:
        raise ProofProtocolError(str(error)) from error
    require(result["systems"]["stwo"]["status"] == "incomplete"
            and result["comparison_ready"] is False,
            "final proof publication overstates benchmark completion")
    return result


def topology_test_manifest(
    plan: dict[str, Any], terminal_record: dict[str, Any], result_identity: dict[str, Any],
    checkpoint_identities: list[dict[str, Any]],
    producer_sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    return seal({
        "schema": TOPOLOGY_TEST_MANIFEST_SCHEMA,
        "status": "test_only_verifier_minted_descriptor_unavailable",
        "production_admissible": False,
        "session_id": plan["session_id"],
        "plan_sha256": plan["content_sha256"],
        "result_schema": benchmark.RESULT_SCHEMA,
        "result": result_identity,
        "terminal_task_record_sha256": terminal_record["content_sha256"],
        "benchmark_statement_sha256": plan["benchmark_statement_sha256"],
        "statement_binding_sha256": plan["statement_binding"]["content_sha256"],
        "level_checkpoints": checkpoint_identities,
        "producer_session_receipts": [session["file"] for session in producer_sessions],
        "proof_complete": False,
        "security_complete": False,
        "comparison_ready": False,
    })
