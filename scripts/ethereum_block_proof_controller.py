"""Crash-resumable, breadth-first Ethereum block proof orchestration."""

from __future__ import annotations

import concurrent.futures
import os
from pathlib import Path
from typing import Any, Callable

from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_attempts as attempts
from scripts import ethereum_block_proof_plan_authority as plan_authority
from scripts import ethereum_block_proof_profile_plan as profile_plan
from scripts import ethereum_block_proof_store as store
from scripts import ethereum_block_proof_stream_request as stream_request


ChildRunner = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
FaultHook = Callable[[str, dict[str, Any]], None]
MAX_PROOF_BYTES = 512 * 1024 * 1024
ROOT_ENTRIES = {
    ".staging", "plan.json", "leaves", "leaf-stream", "levels", "checkpoints",
    "final-result.json", "topology-test.json",
}


def _fault(hook: FaultHook | None, event: str, context: dict[str, Any]) -> None:
    if hook is not None:
        hook(event, context)


def _identity_without_path(value: dict[str, Any]) -> dict[str, Any]:
    return {"bytes": value["bytes"], "sha256": value["sha256"]}


def _task_directory(root: Path, request: dict[str, Any]) -> Path:
    if request["level"] == 0:
        parent = root / "leaves"
        store.require_directory(parent, "leaf proof directory", create=True)
        return parent / request["task_id"]
    levels = root / "levels"
    store.require_directory(levels, "recursive proof directory", create=True)
    level = levels / f"level-{request['level']:04d}"
    store.require_directory(level, "recursive proof level directory", create=True)
    return level / f"node-{request['node_index']:06d}"


def _child_input(root: Path, record: dict[str, Any]) -> dict[str, Any]:
    directory = _task_directory(root, record)
    if record["schema"] == protocol.EMPTY_TASK_RECORD_SCHEMA:
        return {
            "kind": "canonical_empty",
            "node_index": record["node_index"],
            "record_sha256": record["content_sha256"],
            "proof_path": None,
            "authority_path": directory / record["files"]["authority"]["path"],
            "verification_receipt_path": None,
        }
    return {
        "kind": record["record_kind"],
        "node_index": record["node_index"],
        "record_sha256": record["content_sha256"],
        "proof_path": directory / record["files"]["proof"]["path"],
        "authority_path": None,
        "verification_receipt_path": (
            directory / record["files"]["verification_receipt"]["path"]
        ),
    }


def _validate_external_identity(path: Path, expected: dict[str, Any], where: str) -> None:
    store.validate_file_identity(path, expected, where)


def _source_path(segment_root: Path, segment: dict[str, Any]) -> Path:
    store.require_directory(segment_root, "segment source root")
    relative = Path(segment["source"]["path"])
    cursor = segment_root
    for part in relative.parts[:-1]:
        cursor /= part
        store.require_directory(cursor, "segment source parent")
    path = segment_root / relative
    _validate_external_identity(
        path, _identity_without_path(segment["source"]),
        f"segment {segment['segment_index']} source",
    )
    return path


def _typed_source_path(
    segment_root: Path, source: dict[str, Any], where: str,
) -> Path:
    store.require_directory(segment_root, "segment source root")
    relative = Path(source["path"])
    cursor = segment_root
    for part in relative.parts[:-1]:
        cursor /= part
        store.require_directory(cursor, f"{where} parent")
    path = segment_root / relative
    _validate_external_identity(
        path, _identity_without_path(source), where,
    )
    return path


def _prepare_root(root: Path, plan: dict[str, Any]) -> Path:
    if not os.path.lexists(root):
        try:
            root.mkdir(mode=0o700)
            store._fsync_directory(root.parent)
        except OSError as error:
            raise protocol.ProofProtocolError("cannot create proof run root") from error
    store.require_directory(root, "proof run root")
    store.require_allowed_entries(root, ROOT_ENTRIES, "proof run root")
    staging = root / ".staging"
    store.require_directory(staging, "proof staging directory", create=True)
    store.publish_new_or_identical(
        root / "plan.json", protocol.canonical_bytes(plan), staging_directory=staging,
    )
    return staging


def _admit_parent_execution(plan: dict[str, Any]) -> int:
    authority = plan["parent_execution"]
    logical_cores = os.cpu_count() or 0
    try:
        physical_memory = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (OSError, ValueError) as error:
        raise protocol.ProofProtocolError(
            "cannot admit the parent-proof host envelope"
        ) from error
    protocol.require(logical_cores >= authority["admitted_host_logical_cores"]
                     and physical_memory >= authority["admitted_host_memory_bytes"],
                     "parent-proof host is smaller than the admitted envelope")
    return authority["max_workers"]


def _validate_child_result(
    value: Any, request: dict[str, Any], proof_identity: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "statement_sha256", "root_sha256", "proof_bytes",
        "verification_receipt", "prove_timing", "fresh_verify_timing",
        "producer_process", "verifier_process",
    }, "proof child result")
    protocol.require(value["schema"] == protocol.CHILD_RESULT_SCHEMA,
                     "proof child result schema differs")
    protocol.require(value["statement_sha256"] == request["expected_statement_sha256"],
                     "proof child statement differs")
    protocol.require(type(value["root_sha256"]) is str
                     and protocol.SHA256.fullmatch(value["root_sha256"]),
                     "proof child root differs")
    protocol.require(type(value["proof_bytes"]) is bytes
                     and 0 < len(value["proof_bytes"]) <= MAX_PROOF_BYTES,
                     "proof child artifact size differs")
    protocol.require(proof_identity == {
        "bytes": len(value["proof_bytes"]),
        "sha256": protocol.sha256_bytes(value["proof_bytes"]),
    }, "proof child artifact identity differs")
    expected = protocol.expected_receipt(
        request, proof_identity, value["root_sha256"], plan["verifier"],
        plan["security_parameters"],
    )
    protocol.require(value["verification_receipt"] == expected,
                     "proof child verifier receipt differs")
    for name in ("prove_timing", "fresh_verify_timing"):
        timing = protocol.exact(
            value[name], {"wall_ns", "user_ns", "system_ns"}, f"proof child {name}",
        )
        protocol.require(all(type(item) is int and item >= 0 for item in timing.values()),
                         f"proof child {name} differs")
    protocol.validate_producer_custody(
        value["producer_process"], plan["prover"], request,
    )
    protocol.validate_process_receipt(
        value["verifier_process"], plan["verifier"], "fresh_verifier",
    )
    protocol.require(value["verifier_process"]["timing"]
                     == value["fresh_verify_timing"],
                     "proof child fresh verifier timing differs")
    return value


def _validate_retained(
    task_directory: Path, record: dict[str, Any], plan: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    if request["task_kind"] == "canonical_empty_authority":
        protocol.validate_empty_task_record(record, plan, request)
        store.require_allowed_entries(
            task_directory,
            {store.JOURNAL_NAME, request["authority_path"]},
            "prepared canonical empty leaf directory",
        )
        expected = _identity_without_path(record["files"]["authority"])
        authority_path = task_directory / request["authority_path"]
        store.validate_file_identity(
            authority_path, expected, "retained canonical empty leaf authority",
        )
        authority = store.read_canonical_json(
            authority_path, "retained canonical empty leaf authority",
        )
        protocol.require(authority == record["empty_authority"],
                         "retained canonical empty leaf authority differs")
        return record
    protocol.validate_task_record(record, plan, request)
    store.require_allowed_entries(
        task_directory,
        {attempts.JOURNAL_NAME, attempts.ATTEMPTS_DIRECTORY},
        "prepared proof task directory",
    )
    for name in ("proof", "verification_receipt"):
        expected = _identity_without_path(record["files"][name])
        store.validate_file_identity(task_directory / record["files"][name]["path"], expected,
                                     f"retained proof task {name}")
    receipt = store.read_canonical_json(
        task_directory / record["files"]["verification_receipt"]["path"],
        "retained proof verification receipt",
    )
    artifact = record["proof_artifact"]
    expected_receipt = protocol.expected_receipt(
        request, artifact["proof"], artifact["root_sha256"], plan["verifier"],
        plan["security_parameters"],
    )
    protocol.require(receipt == expected_receipt,
                     "retained proof verification receipt differs")
    return record


def _run_task(
    root: Path, staging: Path, plan: dict[str, Any], request: dict[str, Any],
    child: ChildRunner, child_context: dict[str, Any], fault: FaultHook | None,
) -> dict[str, Any]:
    task_directory = _task_directory(root, request)
    if request["task_kind"] == "canonical_empty_authority":
        return _run_empty_task(
            task_directory, staging, plan, request, fault,
        )
    return _run_proof_task(
        task_directory, staging, plan, request, child, child_context, fault,
    )


def _run_empty_task(
    task_directory: Path, staging: Path, plan: dict[str, Any],
    request: dict[str, Any], fault: FaultHook | None,
) -> dict[str, Any]:
    with store.TaskJournal(
        task_directory, plan["content_sha256"], request, staging,
    ) as journal:
        state = journal.state()
        if state["phase"] in ("prepared", "committed"):
            record = _validate_retained(
                task_directory, state["task_record"], plan, request,
            )
            if state["phase"] == "prepared":
                journal.commit()
                _fault(fault, "after_committed", request)
            return record

        if state["phase"] == "empty":
            store.require_allowed_entries(
                task_directory, {store.JOURNAL_NAME}, "new proof task directory",
            )
            journal.begin()
            _fault(fault, "after_intent", request)
        else:
            protocol.require(state["phase"] == "intent",
                             "proof task publication state differs")
        authority = protocol.empty_authority(plan, request)
        authority_identity = store.publish_new_or_identical(
            task_directory / request["authority_path"],
            protocol.canonical_bytes(authority),
            staging_directory=staging,
        )
        _fault(fault, "after_authority", request)
        record = protocol.empty_task_record(
            plan, request, authority, authority_identity,
        )
        _validate_retained(task_directory, record, plan, request)
        journal.prepare(record)
        _fault(fault, "after_prepared", request)
        journal.commit()
        _fault(fault, "after_committed", request)
        return record


def _run_proof_task(
    task_directory: Path, staging: Path, plan: dict[str, Any],
    request: dict[str, Any], child: ChildRunner, child_context: dict[str, Any],
    fault: FaultHook | None,
) -> dict[str, Any]:
    with attempts.ProofTaskJournal(
        task_directory, plan["content_sha256"], request, staging,
    ) as journal:
        state = journal.state()
        journal.validate_indeterminate_inventories()
        if state["committed"] is not None:
            return _validate_retained(
                task_directory, state["committed"], plan, request,
            )
        if state["prepared"] is not None:
            record = _validate_retained(
                task_directory, state["prepared"], plan, request,
            )
            journal.commit()
            _fault(fault, "after_committed", request)
            return record
        if state["pending"] is not None:
            journal.seal_pending_indeterminate()
            state = journal.state()
        attempt_index, attempt_directory = journal.begin()
        _fault(fault, "after_intent", request)
        try:
            child_result = child(request, child_context)
            _fault(fault, "after_child", request)
            protocol.require(type(child_result) is dict,
                             "proof child result is not an object")
            proof_bytes = child_result.get("proof_bytes")
            protocol.require(type(proof_bytes) is bytes
                             and 0 < len(proof_bytes) <= MAX_PROOF_BYTES,
                             "proof child artifact size differs")
            proof_identity = {
                "bytes": len(proof_bytes),
                "sha256": protocol.sha256_bytes(proof_bytes),
            }
            child_result = _validate_child_result(
                child_result, request, proof_identity, plan,
            )
        except protocol.ProofProtocolError:
            journal.seal_pending_failed()
            raise
        proof_relative = f"{attempts.attempt_relative(attempt_index)}/proof.bin"
        receipt_relative = (
            f"{attempts.attempt_relative(attempt_index)}/verify-receipt.json"
        )
        published_proof = store.publish_new_or_identical(
            attempt_directory / "proof.bin", proof_bytes,
            staging_directory=staging,
        )
        protocol.require(published_proof == proof_identity,
                         "published proof identity differs")
        _fault(fault, "after_proof", request)
        receipt_bytes = protocol.canonical_bytes(child_result["verification_receipt"])
        receipt_identity = store.publish_new_or_identical(
            attempt_directory / "verify-receipt.json", receipt_bytes,
            staging_directory=staging,
        )
        _fault(fault, "after_receipt", request)
        record = protocol.task_record(
            plan, request,
            proof=proof_identity,
            receipt=child_result["verification_receipt"],
            receipt_identity=receipt_identity,
            root_sha256=child_result["root_sha256"],
            prove_timing=child_result["prove_timing"],
            verify_timing=child_result["fresh_verify_timing"],
            attempt_index=attempt_index,
            attempt_history=state["history"],
            producer_process=child_result["producer_process"],
            verifier_process=child_result["verifier_process"],
            proof_path=proof_relative,
            receipt_path=receipt_relative,
        )
        _validate_retained(task_directory, record, plan, request)
        journal.prepare(record, attempt_index)
        _fault(fault, "after_prepared", request)
        journal.commit()
        _fault(fault, "after_committed", request)
        return record


def _run_with_child(
    plan: dict[str, Any], run_root: Path, segment_root: Path, *,
    prover_path: Path, verifier_path: Path, child: ChildRunner,
    fault: FaultHook | None = None, test_only_descriptors: bool = False,
) -> dict[str, Any]:
    """Run or resume a complete breadth-first leaf-to-root proof schedule."""
    plan = protocol.validate_plan(plan)
    parent_workers = _admit_parent_execution(plan)
    run_root = run_root.absolute()
    staging = _prepare_root(run_root, plan)
    _validate_external_identity(prover_path, plan["prover"], "proof prover executable")
    _validate_external_identity(verifier_path, plan["verifier"],
                                "proof verifier executable")
    sources = {
        segment["segment_index"]: _source_path(segment_root, segment)
        for segment in plan["segments"]
    }
    leaf_stream_request_path = _typed_source_path(
        segment_root, plan["leaf_stream_request"], "leaf stream source request",
    )
    source_authority = stream_request.validate_source_file(
        leaf_stream_request_path, require_recursive=True,
    )
    profile_plan.reopen_binding(plan["profile_policy_template"], segment_root)
    protocol.require(source_authority["segment_count"] == plan["real_segment_count"],
                     "leaf stream source segment count differs")
    try:
        plan_authority.require_production_security(
            plan["security_parameters"], "proof plan security",
        )
        expected_leaf = plan_authority.recursive_leaf_from_source(
            source_authority["pcs"], source_authority["proof_profile"],
        )
    except plan_authority.PlanAuthorityError as error:
        raise protocol.ProofProtocolError(str(error)) from error
    protocol.require(
        plan["security_parameters"]["recursive_ethereum_leaf"] == expected_leaf,
                     "proof plan leaf security differs from SourceRequest PCS")
    binding = plan["statement_binding"]
    protocol.require(
        all(source_authority[field] == binding[field]
            for field in ("elf", "input", "expected_output")),
        "leaf stream source differs from benchmark statement binding",
    )
    checkpoints = run_root / "checkpoints"
    store.require_directory(checkpoints, "proof checkpoint directory", create=True)
    records_by_level: list[list[dict[str, Any]]] = []
    checkpoint_identities = []
    producer_sessions: list[dict[str, Any]] = []
    prior_checkpoint_sha256 = None
    for level, count in enumerate(plan["node_counts"]):
        def run_node(
            node_index: int, committed_prefix: list[dict[str, Any]],
        ) -> tuple[dict[str, Any], dict[str, Any]]:
            child_records = []
            if level > 0:
                start = node_index * plan["arity"]
                stop = start + plan["arity"]
                child_records = records_by_level[level - 1][start:stop]
            request = protocol.task_request(
                plan, level, node_index, child_records,
                test_only_descriptors=test_only_descriptors,
            )
            context = {
                "plan": plan,
                "run_root": run_root,
                "prover_path": prover_path,
                "verifier_path": verifier_path,
                "source_path": sources.get(node_index) if level == 0 else None,
                "leaf_stream_request_path": leaf_stream_request_path,
                "segment_authority_paths": [sources[index]
                                             for index in range(len(sources))],
                "committed_leaf_records": committed_prefix if level == 0 else [],
                "committed_leaf_inputs": [
                    _child_input(run_root, record) for record in committed_prefix
                ] if level == 0 else [],
                "scratch_root": staging,
                "child_inputs": [
                    _child_input(run_root, child_record)
                    for child_record in child_records
                ],
            }
            return _run_task(
                run_root, staging, plan, request, child, context, fault,
            ), context

        level_records: list[dict[str, Any]] = []
        context: dict[str, Any] | None = None
        if level == 0:
            for node_index in range(count):
                record, context = run_node(node_index, list(level_records))
                level_records.append(record)
                if node_index < plan["real_segment_count"]:
                    _validate_external_identity(
                        sources[node_index],
                        _identity_without_path(plan["segments"][node_index]["source"]),
                        f"segment {node_index} source after proof",
                    )
        else:
            levels_root = run_root / "levels"
            store.require_directory(levels_root, "recursive proof directory", create=True)
            store.require_directory(
                levels_root / f"level-{level:04d}",
                "recursive proof level directory", create=True,
            )
            ordered: list[dict[str, Any] | None] = [None] * count
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=min(parent_workers, count),
                thread_name_prefix=f"ethereum-parent-h{level}",
            ) as pool:
                futures = {
                    pool.submit(run_node, node_index, []): node_index
                    for node_index in range(count)
                }
                try:
                    for future in concurrent.futures.as_completed(futures):
                        node_index = futures[future]
                        ordered[node_index], _ = future.result()
                except BaseException:
                    for future in futures:
                        future.cancel()
                    raise
            protocol.require(all(record is not None for record in ordered),
                             "recursive proof level execution is incomplete")
            level_records = [record for record in ordered if record is not None]
        records_by_level.append(level_records)
        if level == 0 and hasattr(child, "finish_leaf_stream"):
            protocol.require(context is not None, "leaf stream context is absent")
            child.finish_leaf_stream(context)
            producer_sessions = child.session_publications()
        checkpoint = protocol.level_checkpoint(
            plan, level, level_records, prior_checkpoint_sha256,
        )
        checkpoint_path = checkpoints / f"level-{level:04d}.json"
        identity = store.publish_new_or_identical(
            checkpoint_path, protocol.canonical_bytes(checkpoint),
            staging_directory=staging,
        )
        checkpoint_identity = {
            "path": str(checkpoint_path.relative_to(run_root)), **identity,
        }
        checkpoint_identities.append(checkpoint_identity)
        prior_checkpoint_sha256 = identity["sha256"]
        _fault(fault, "after_checkpoint", {"level": level, "checkpoint": checkpoint})

    all_records = [record for level in records_by_level for record in level]
    result = protocol.final_result(plan, all_records, producer_sessions)
    result_path = run_root / "final-result.json"
    result_identity = store.publish_new_or_identical(
        result_path, protocol.canonical_bytes(result), staging_directory=staging,
    )
    result_identity = {"path": result_path.name, **result_identity}
    _fault(fault, "after_result", {"result": result})
    manifest = protocol.topology_test_manifest(
        plan, all_records[-1], result_identity, checkpoint_identities,
        producer_sessions,
    )
    manifest_path = run_root / "topology-test.json"
    manifest_identity = store.publish_new_or_identical(
        manifest_path, protocol.canonical_bytes(manifest), staging_directory=staging,
    )
    _fault(fault, "after_final_manifest", {"manifest": manifest})
    _validate_external_identity(
        leaf_stream_request_path,
        _identity_without_path(plan["leaf_stream_request"]),
        "leaf stream source request after proof",
    )
    profile_plan.reopen_binding(plan["profile_policy_template"], segment_root)
    return {
        "records": all_records,
        "checkpoints": checkpoint_identities,
        "result": result,
        "result_identity": result_identity,
        "manifest": manifest,
        "manifest_identity": {"path": manifest_path.name, **manifest_identity},
    }


def run(
    plan: dict[str, Any], run_root: Path, segment_root: Path, *,
    prover_path: Path, verifier_path: Path, timeout_seconds: int = 3600,
    fault: FaultHook | None = None,
) -> dict[str, Any]:
    """Run production proof subprocesses under the durable controller."""
    raise protocol.VerifierMintedDescriptorPlanUnavailable(
        "production block proving requires verifier-minted descriptor-plan admission"
    )


def run_subprocess_for_test(
    plan: dict[str, Any], run_root: Path, segment_root: Path, *,
    prover_path: Path, verifier_path: Path, timeout_seconds: int = 3600,
    fault: FaultHook | None = None,
) -> dict[str, Any]:
    """Exercise subprocess durability without claiming production admission."""
    from scripts.ethereum_block_proof_child import SubprocessChildAdapter

    with SubprocessChildAdapter(
        plan, run_root=run_root.absolute(), timeout_seconds=timeout_seconds,
    ) as child:
        return _run_with_child(
            plan, run_root, segment_root, prover_path=prover_path,
            verifier_path=verifier_path, child=child, fault=fault,
            test_only_descriptors=True,
        )


def run_for_test(
    plan: dict[str, Any], run_root: Path, segment_root: Path, *,
    prover_path: Path, verifier_path: Path, child: ChildRunner,
    fault: FaultHook | None = None,
) -> dict[str, Any]:
    """Exercise orchestration with an in-process deterministic test double."""
    return _run_with_child(
        plan, run_root, segment_root, prover_path=prover_path,
        verifier_path=verifier_path, child=child, fault=fault,
        test_only_descriptors=True,
    )


def replay(
    plan: dict[str, Any], run_root: Path, segment_root: Path, *,
    prover_path: Path, verifier_path: Path,
) -> dict[str, Any]:
    """Independently reopen a complete bundle without launching proof work."""
    raise protocol.VerifierMintedDescriptorPlanUnavailable(
        "production replay requires verifier-minted descriptor-plan admission"
    )


def replay_subprocess_for_test(
    plan: dict[str, Any], run_root: Path, segment_root: Path, *,
    prover_path: Path, verifier_path: Path,
) -> dict[str, Any]:
    """Replay a test-only subprocess durability bundle."""
    from scripts.ethereum_block_proof_child import SubprocessChildAdapter

    protocol.require(os.path.lexists(run_root / "final-result.json")
                     and os.path.lexists(run_root / "topology-test.json"),
                     "proof replay requires a finalized bundle")
    with SubprocessChildAdapter(
        plan, run_root=run_root.absolute(), replay_only=True,
    ) as child:
        return _run_with_child(
            plan, run_root, segment_root, prover_path=prover_path,
            verifier_path=verifier_path, child=child, fault=None,
            test_only_descriptors=True,
        )
