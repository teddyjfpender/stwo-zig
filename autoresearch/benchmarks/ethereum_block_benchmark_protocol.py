"""Fail-closed protocol authority for a comparable Ethereum-block benchmark."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

import ethereum_block_benchmark_measurements as measurements
import ethereum_block_benchmark_statement as statement_authority


PROTOCOL_SCHEMA = "stwo.ethereum.apples-to-apples-benchmark-protocol.v2"
STATEMENT_SCHEMA = statement_authority.STATEMENT_SCHEMA
RESULT_SCHEMA = "stwo.ethereum.apples-to-apples-benchmark-result.v3"
TRACE_GENERATION_SCHEMA = "stwo.ethereum.trace-generation-breakdown.v2"
EXECUTION_WORK_SCHEMA = "stwo.ethereum.execution-work-authority.v1"
PROOF_CUSTODY_SCHEMA = "stwo.ethereum.end-to-end-proof-custody.v3"
STATEMENT_BINDING_SCHEMA = statement_authority.BINDING_SCHEMA
EMPTY_AUTHORITY_SCHEMA = "stwo.ethereum.canonical-empty-leaf-authority.v1"
EMPTY_AUTHORITY_DOMAIN = b"stwo-zig/ethereum/canonical-empty-leaf-authority/v1\x00"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TIMING_BUCKETS = (
    {
        "name": "execution",
        "starts_at": "admitted-guest-and-input-ready",
        "ends_at": "final-machine-output-and-execution-custody-ready",
    },
    {
        "name": "witness_generation",
        "starts_at": "execution-custody-ready",
        "ends_at": "all-committed-witness-columns-ready",
    },
    {
        "name": "proving",
        "starts_at": "all-committed-witness-columns-ready",
        "ends_at": "serialized-proof-and-public-statement-ready",
    },
    {
        "name": "verification",
        "starts_at": "serialized-proof-and-public-statement-ready",
        "ends_at": "fresh-verifier-verdict-ready",
    },
)
GEOMETRY_FIELDS = (
    "isa_steps",
    "core_trace_rows",
    "external_trace_rows",
    "external_family_rows",
    "air_types",
    "component_instances",
    "padded_rows",
    "committed_cells",
    "constant_cells",
    "all_cells",
)
SECURITY_FIELDS = (
    "schema",
    "proof_profile",
    "native_blake_leaf",
    "recursive_ethereum_leaf",
    "recursive_node",
    "conservative_end_to_end_target_bits",
    "proof_bytes",
    "fresh_verification",
    "independent_verifier",
)
HARDWARE_FIELDS = (
    "machine_model",
    "cpu_model",
    "cpu_logical_cores",
    "gpu_model",
    "memory_bytes",
    "operating_system",
    "power_source",
    "thermal_state",
    "process_count",
    "thread_count",
    "process_workers",
    "accelerator_workers",
    "execution_multiplicity",
    "execution_strategy",
)


class BenchmarkProtocolError(ValueError):
    pass

measurements.MeasurementError = BenchmarkProtocolError


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BenchmarkProtocolError(message)


def _exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    return value


_sealed_sha256 = statement_authority.sealed_sha256


def validate_statement_binding(
    value: Any, expected_benchmark_statement_sha256: str, where: str,
) -> dict[str, Any]:
    try:
        return statement_authority.validate_binding(
            value, expected_benchmark_statement_sha256, where,
        )
    except statement_authority.StatementAuthorityError as error:
        raise BenchmarkProtocolError(str(error)) from error


def validate(protocol: Any, manifest: dict[str, Any]) -> None:
    """Cross-bind the benchmark protocol to the pinned evidence manifest."""
    protocol = _exact(protocol, {
        "schema", "statement", "statement_sha256", "result_contract", "promotion_ready",
    }, "benchmark_protocol")
    _require(protocol["schema"] == PROTOCOL_SCHEMA, "benchmark protocol schema differs")
    try:
        statement_authority.validate_statement(
            protocol["statement"], protocol["statement_sha256"], manifest,
            "benchmark_protocol.statement",
        )
    except statement_authority.StatementAuthorityError as error:
        raise BenchmarkProtocolError(str(error)) from error

    contract = _exact(protocol["result_contract"], {
        "schema", "timing_unit", "timing_fields", "timing_buckets", "total_wall_reconciliation",
        "trace_generation", "execution_work", "proof_custody", "geometry_fields",
        "security_fields", "hardware_fields", "requirements",
    }, "benchmark_protocol.result_contract")
    _require(contract["schema"] == RESULT_SCHEMA, "benchmark result schema differs")
    _require(contract["timing_unit"] == "nanoseconds", "benchmark timing unit differs")
    _require(contract["timing_fields"] == ["wall_ns", "user_ns", "system_ns"],
             "benchmark timing fields differ")
    _require(contract["timing_buckets"] == list(TIMING_BUCKETS),
             "benchmark timing buckets differ")
    _require(contract["total_wall_reconciliation"]
             == "total_wall_ns=execution_ns+witness_generation_ns+proving_ns+verification_ns",
             "benchmark total-wall reconciliation differs")
    _require(contract["trace_generation"] == {
        "schema": TRACE_GENERATION_SCHEMA,
        "modes": ["whole-program-repetitions", "sequential-capture-plus-parallel-replay"],
        "whole_program_strategy": "parallel-whole-program-repetitions",
        "capture_strategy": "sequential-authoritative-capture",
        "replay_strategy": "parallel-memoryless-replay",
        "rate_representation": "exact-cycles-over-wall-nanoseconds",
        "efficiency_representation": "replay-rate-over-capture-rate-times-workers-exact-rational",
        "total_wall_reconciliation": "mode-conditioned:whole_program_wall_ns-or-capture_wall_ns+replay_wall_ns",
        "authority_values": ["measured", "modeled"],
    }, "benchmark trace-generation contract differs")
    _require(contract["execution_work"] == {
        "schema": EXECUTION_WORK_SCHEMA,
        "reconciliation": "total_execution_isa_steps=per_execution_isa_steps*multiplicity;total_cpu_ns=user_ns+system_ns",
        "trace_binding": "strategy=trace_generation.mode;whole-program multiplicity matches;capture multiplicity=1",
        "hardware_binding": "multiplicity-and-strategy-match-hardware-envelope",
        "authority_values": ["measured", "modeled"],
    }, "benchmark execution-work contract differs")
    _require(contract["proof_custody"] == {
        "schema": PROOF_CUSTODY_SCHEMA,
        "scopes": ["leaf", "parent", "final_root"],
        "topology": "binary-next-power-of-two-with-trailing-canonical-empty-leaves",
        "empty_leaf_status": "proofless-height-zero-authority-without-verifier-receipt",
        "proof_counting": "real-leaf-proofs-plus-recursive-parent-proofs-only",
        "leaf_parent_status": "admissible-evidence-but-nonpromotable",
        "complete_requires": "all-real-leaf-proofs-all-empty-authorities-all-parent-proofs-and-freshly-verified-final-root",
        "statement_binding": {
            "schema": STATEMENT_BINDING_SCHEMA,
            "root_relation": "proved-root-statement-is-distinct-from-benchmark-statement",
            "authority": "block-plus-elf-plus-input-plus-output-plus-source-request",
            "promotion": "requires-matched-guest-statement-reproduced",
        },
    }, "benchmark proof-custody contract differs")
    _require(contract["geometry_fields"] == list(GEOMETRY_FIELDS),
             "benchmark geometry fields differ")
    _require(contract["security_fields"] == list(SECURITY_FIELDS),
             "benchmark security fields differ")
    _require(contract["hardware_fields"] == list(HARDWARE_FIELDS),
             "benchmark hardware fields differ")
    _require(contract["requirements"] == {
        "same_pinned_block": True,
        "matched_guest_statement": True,
        "mutually_exclusive_timing_buckets": True,
        "total_wall_reconciles_exactly": True,
        "same_hardware": True,
        "same_security_target": True,
        "complete_recursive_root": True,
        "fresh_verification": True,
    }, "benchmark result requirements differ")
    _require(protocol["promotion_ready"] is False,
             "benchmark protocol cannot be promoted before statement/proof closure")


def _nonnegative_or_null(value: Any, where: str) -> int | None:
    _require(value is None or (type(value) is int and value >= 0),
             f"{where} must be a nonnegative integer or null")
    return value


def _validate_timings(value: Any, where: str) -> bool:
    return measurements.validate_timing_buckets(
        value, tuple(bucket["name"] for bucket in TIMING_BUCKETS), where,
    )


def _positive_int(value: Any, where: str) -> int:
    _require(type(value) is int and value > 0, f"{where} must be a positive integer")
    return value


def _sha256_identity(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {"bytes", "sha256"}, where)
    _positive_int(value["bytes"], f"{where}.bytes")
    _require(type(value["sha256"]) is str and SHA256.fullmatch(value["sha256"]),
             f"{where}.sha256 differs")
    return value


def _timing(value: Any, where: str) -> dict[str, int]:
    value = _exact(value, {"wall_ns", "user_ns", "system_ns"}, where)
    for field in ("wall_ns", "user_ns", "system_ns"):
        _require(type(value[field]) is int and value[field] >= 0,
                 f"{where}.{field} must be a nonnegative integer")
    return value


def _projection_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _domain_projection_sha256(domain: bytes, value: Any) -> str:
    encoded = (json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


def _canonical_line_sha256(value: Any) -> str:
    encoded = (json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ) + "\n").encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def topology_sha256(
    arity: int, levels: int, node_counts: list[int], real_segment_count: int,
) -> str:
    """Digest the canonical recursive topology projection."""
    return _projection_sha256({
        "arity": arity,
        "levels": levels,
        "node_counts": node_counts,
        "real_segment_count": real_segment_count,
        "slot_capacity": node_counts[0],
        "padded_leaf_count": node_counts[0],
        "empty_leaf_count": node_counts[0] - real_segment_count,
    })


def segment_coverage_root_sha256(artifacts: list[dict[str, Any]]) -> str:
    """Digest the canonical, segment-indexed leaf proof custody projection."""
    leaves = []
    for artifact in artifacts:
        if artifact.get("scope") != "leaf":
            continue
        leaves.append({
            "segment_index": artifact["node_index"],
            "statement_sha256": artifact["statement_sha256"],
            "root_sha256": artifact["root_sha256"],
            "proof_sha256": artifact["proof"]["sha256"],
            "verification_receipt_sha256": artifact["verification_receipt"]["sha256"],
        })
    return _projection_sha256(leaves)


def empty_authority_root_sha256(authorities: list[dict[str, Any]]) -> str:
    """Digest the ordered proofless height-zero authority custody."""
    return _projection_sha256(authorities)


def canonical_empty_authority_sha256(authority: dict[str, Any]) -> str:
    """Domain-separated identity of an authority before its digest is attached."""
    return _domain_projection_sha256(EMPTY_AUTHORITY_DOMAIN, authority)


def _validate_empty_authority(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "kind", "session_id", "job_sha256", "topology_sha256",
        "segment_leaf_vk_sha256", "recursive_parent_vk_sha256", "level",
        "node_index", "slot_capacity", "statement_sha256", "proof_present",
        "proof_profile_entry_sha256", "authority_sha256",
    }, where)
    _require(value["schema"] == EMPTY_AUTHORITY_SCHEMA
             and value["kind"] == "canonical_empty",
             f"{where} schema or kind differs")
    for field in (
        "session_id", "job_sha256", "topology_sha256", "segment_leaf_vk_sha256",
        "recursive_parent_vk_sha256", "statement_sha256",
        "proof_profile_entry_sha256", "authority_sha256",
    ):
        _require(type(value[field]) is str and SHA256.fullmatch(value[field]),
                 f"{where}.{field} differs")
    _require(value["level"] == 0, f"{where}.level differs")
    _require(type(value["node_index"]) is int and value["node_index"] >= 0,
             f"{where}.node_index differs")
    _positive_int(value["slot_capacity"], f"{where}.slot_capacity")
    _require(value["proof_present"] is False, f"{where} is not proofless")
    projection = dict(value)
    authority_sha256 = projection.pop("authority_sha256")
    _require(authority_sha256 == canonical_empty_authority_sha256(projection),
             f"{where}.authority_sha256 differs")
    return value


def _validate_topology(value: Any, expected_segments: int, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "arity", "levels", "node_counts", "real_segment_count", "slot_capacity",
        "padded_leaf_count", "empty_leaf_count", "topology_sha256",
    }, where)
    arity = _positive_int(value["arity"], f"{where}.arity")
    _require(arity == 2, f"{where}.arity must be binary")
    levels = _positive_int(value["levels"], f"{where}.levels")
    counts = value["node_counts"]
    _require(type(counts) is list and len(counts) == levels + 1,
             f"{where}.node_counts differs")
    _require(all(type(count) is int and count > 0 for count in counts),
             f"{where}.node_counts differs")
    _require(value["real_segment_count"] == expected_segments,
             f"{where}.real_segment_count differs")
    expected_capacity = 1 << (expected_segments - 1).bit_length()
    _require(value["slot_capacity"] == counts[0]
             and counts[0] == expected_capacity,
             f"{where}.slot_capacity differs")
    _require(value["padded_leaf_count"] == counts[0],
             f"{where}.padded_leaf_count differs")
    _require(value["empty_leaf_count"] == counts[0] - expected_segments,
             f"{where}.empty_leaf_count differs")
    _require(counts[-1] == 1,
             f"{where}.node_counts endpoints differ")
    for previous, current in zip(counts, counts[1:]):
        _require(current == previous // arity,
                 f"{where}.node_counts reduction differs")
    _require(value["topology_sha256"]
             == topology_sha256(arity, levels, counts, expected_segments),
             f"{where}.topology_sha256 differs")
    return value


def _validate_process_receipt(
    value: Any, executable: dict[str, Any], role: str, where: str,
) -> dict[str, Any]:
    value = _exact(value, {
        "schema", "role", "executable", "argv", "exit_code", "stdout_bytes",
        "stderr_bytes", "timing",
    }, where)
    _require(value["schema"] == "stwo.ethereum.block-proof-subprocess-receipt.v1"
             and value["role"] == role and value["executable"] == executable,
             f"{where} authority differs")
    _sha256_identity(value["executable"], f"{where}.executable")
    _require(type(value["argv"]) is list and len(value["argv"]) >= 2
             and all(type(item) is str and item for item in value["argv"]),
             f"{where}.argv differs")
    _require(value["exit_code"] == 0 and value["stdout_bytes"] == 0
             and value["stderr_bytes"] == 0,
             f"{where} transport differs")
    _timing(value["timing"], f"{where}.timing")
    return value


def _validate_attempt_summary(
    value: Any, prove_timing: dict[str, Any], verify_timing: dict[str, Any], where: str,
) -> bool:
    value = _exact(value, {
        "schema", "total_attempt_count", "successful_attempt_index",
        "failed_attempt_count", "indeterminate_attempt_count", "attempt_history",
        "observed_operational_wall_ns", "successful_prove_verify_wall_ns",
        "performance_claim_eligible",
    }, where)
    _require(value["schema"] == "stwo.ethereum.block-proof-attempt-summary.v2",
             f"{where}.schema differs")
    history = value["attempt_history"]
    _require(type(history) is list, f"{where}.attempt_history differs")
    observed_history_wall = 0
    for index, attempt in enumerate(history):
        attempt = _exact(attempt, {
            "schema", "attempt_index", "attempt_path", "classification",
            "started_unix_ns", "ended_unix_ns", "observed_wall_ns", "clock_reliable",
            "inventory", "inventory_sha256",
        }, f"{where}.attempt_history[{index}]")
        _require(attempt["schema"] == "stwo.ethereum.block-proof-attempt-custody.v1"
                 and attempt["attempt_index"] == index
                 and attempt["attempt_path"] == f"attempts/attempt-{index:06d}"
                 and attempt["classification"]
                 in ("failed_after_launch", "indeterminate_after_launch"),
                 f"{where}.attempt_history[{index}] identity differs")
        _require(type(attempt["started_unix_ns"]) is int
                 and type(attempt["ended_unix_ns"]) is int
                 and attempt["started_unix_ns"] > 0 and attempt["ended_unix_ns"] > 0,
                 f"{where}.attempt_history[{index}] clock differs")
        if attempt["clock_reliable"] is True:
            _require(attempt["observed_wall_ns"]
                     == attempt["ended_unix_ns"] - attempt["started_unix_ns"] >= 0,
                     f"{where}.attempt_history[{index}] wall differs")
            observed_history_wall += attempt["observed_wall_ns"]
        else:
            _require(attempt["clock_reliable"] is False
                     and attempt["observed_wall_ns"] is None,
                     f"{where}.attempt_history[{index}] clock status differs")
        _require(attempt["inventory_sha256"]
                 == _canonical_line_sha256(attempt["inventory"]),
                 f"{where}.attempt_history[{index}] inventory differs")
    successful_wall = prove_timing["wall_ns"] + verify_timing["wall_ns"]
    failed_count = sum(
        attempt["classification"] == "failed_after_launch" for attempt in history
    )
    indeterminate_count = len(history) - failed_count
    _require(value["successful_attempt_index"] == len(history)
             and value["total_attempt_count"] == len(history) + 1
             and value["failed_attempt_count"] == failed_count
             and value["indeterminate_attempt_count"] == indeterminate_count
             and value["successful_prove_verify_wall_ns"] == successful_wall
             and value["observed_operational_wall_ns"]
             == observed_history_wall + successful_wall
             and value["performance_claim_eligible"] == (len(history) == 0),
             f"{where} reconciliation differs")
    return value["performance_claim_eligible"]


def _validate_proof_artifact(value: Any, where: str) -> dict[str, Any]:
    value = _exact(value, {
        "scope", "level", "node_index", "child_nodes", "covered_segments",
        "statement_sha256", "recursive_statement_sha256", "root_sha256",
        "proof", "prover", "verifier", "proof_profile_authority",
        "verification_receipt", "prove_timing", "fresh_verify_timing", "processes",
        "attempts", "security",
    }, where)
    _require(value["scope"] in ("leaf", "parent", "final_root"),
             f"{where}.scope differs")
    _require(type(value["level"]) is int and value["level"] >= 0,
             f"{where}.level differs")
    _require(type(value["node_index"]) is int and value["node_index"] >= 0,
             f"{where}.node_index differs")
    _require(type(value["child_nodes"]) is list, f"{where}.child_nodes differs")
    for index, child in enumerate(value["child_nodes"]):
        child = _exact(child, {"level", "node_index"}, f"{where}.child_nodes[{index}]")
        _require(type(child["level"]) is int and child["level"] >= 0,
                 f"{where}.child_nodes[{index}].level differs")
        _require(type(child["node_index"]) is int and child["node_index"] >= 0,
                 f"{where}.child_nodes[{index}].node_index differs")
    covered = value["covered_segments"]
    _require(type(covered) is list, f"{where}.covered_segments differs")
    _require(all(type(index) is int and index >= 0 for index in covered)
             and covered == sorted(set(covered)), f"{where}.covered_segments differs")
    for field in ("statement_sha256", "recursive_statement_sha256", "root_sha256"):
        _require(type(value[field]) is str and SHA256.fullmatch(value[field]),
                 f"{where}.{field} differs")
    for field in ("proof", "prover", "verifier", "verification_receipt"):
        _sha256_identity(value[field], f"{where}.{field}")
    processes = _exact(value["processes"], {"producer", "fresh_verifier"},
                       f"{where}.processes")
    if value["scope"] == "leaf":
        measurements.validate_leaf_producer_observation(
            processes["producer"], value["prover"], value["node_index"],
            f"{where}.processes.producer",
        )
    else:
        _validate_process_receipt(
            processes["producer"], value["prover"], "proof_producer",
            f"{where}.processes.producer",
        )
    _validate_process_receipt(
        processes["fresh_verifier"], value["verifier"], "fresh_verifier",
        f"{where}.processes.fresh_verifier",
    )
    _timing(value["prove_timing"], f"{where}.prove_timing")
    _timing(value["fresh_verify_timing"], f"{where}.fresh_verify_timing")
    _validate_attempt_summary(
        value["attempts"], value["prove_timing"], value["fresh_verify_timing"],
        f"{where}.attempts",
    )
    _require(value["fresh_verify_timing"] == processes["fresh_verifier"]["timing"],
             f"{where}.fresh_verify_timing differs from process custody")
    measurements.validate_security(
        value["security"], f"{where}.security", SECURITY_FIELDS, complete=True,
    )
    _require(value["security"]["proof_bytes"] == value["proof"]["bytes"],
             f"{where} proof bytes differ from security disclosure")
    _require(value["security"]["fresh_verification"] is True,
             f"{where} was not freshly verified")
    return value


def _validate_proof_custody(
    value: Any, expected_statement_sha256: str,
    expected_statement_matched: bool, where: str,
) -> tuple[bool, dict[str, Any] | None, bool, bool]:
    if value is None:
        return False, None, False, False
    value = _exact(value, {
        "schema", "scope", "expected_segment_count", "covered_segments",
        "segment_coverage_root_sha256", "empty_authority_root_sha256", "proof_counts",
        "topology", "artifacts", "empty_authorities", "producer_sessions", "final_root",
        "statement_binding", "profile_policy_template",
    }, where)
    _require(value["schema"] == PROOF_CUSTODY_SCHEMA, f"{where}.schema differs")
    statement_binding = validate_statement_binding(
        value["statement_binding"], expected_statement_sha256,
        f"{where}.statement_binding",
    )
    _require(statement_binding["matched_guest_statement_reproduced"]
             == expected_statement_matched,
             f"{where}.statement_binding match status differs")
    _require(value["scope"] in ("leaf", "parent", "final_root"),
             f"{where}.scope differs")
    expected_segments = _positive_int(
        value["expected_segment_count"], f"{where}.expected_segment_count",
    )
    _require(type(value["artifacts"]) is list and value["artifacts"],
             f"{where}.artifacts differs")
    artifacts = [
        _validate_proof_artifact(artifact, f"{where}.artifacts[{index}]")
        for index, artifact in enumerate(value["artifacts"])
    ]
    from scripts import ethereum_block_proof_profile_plan as profile_plan
    profile_plan.validate_binding(value["profile_policy_template"])
    for artifact in artifacts:
        if artifact["scope"] == "leaf":
            _require(artifact["proof_profile_authority"]
                     == artifact["security"]["recursive_ethereum_leaf"],
                     f"{where} leaf profile authority differs")
        else:
            _require(artifact["proof_profile_authority"] == {
                "production_admissible": False,
                "schema": "stwo.ethereum.block-proof-test-node-descriptor.v1",
                "status": "test_only_verifier_minted_descriptor_unavailable",
            }, f"{where} parent test descriptor authority differs")
    stream_performance_eligible = measurements.validate_leaf_stream_sessions(
        value["producer_sessions"], artifacts, expected_segments,
        f"{where}.producer_sessions",
    )
    _require(type(value["empty_authorities"]) is list,
             f"{where}.empty_authorities differs")
    empty_authorities = [
        _validate_empty_authority(authority, f"{where}.empty_authorities[{index}]")
        for index, authority in enumerate(value["empty_authorities"])
    ]
    _require(value["empty_authority_root_sha256"]
             == empty_authority_root_sha256(empty_authorities),
             f"{where}.empty_authority_root_sha256 differs")
    keys = [(artifact["level"], artifact["node_index"]) for artifact in artifacts]
    _require(keys == sorted(set(keys)), f"{where}.artifacts order or identity differs")
    artifact_by_key = dict(zip(keys, artifacts))
    empty_keys = [(authority["level"], authority["node_index"])
                  for authority in empty_authorities]
    _require(empty_keys == sorted(set(empty_keys)),
             f"{where}.empty_authorities order or identity differs")
    empty_by_key = dict(zip(empty_keys, empty_authorities))
    leaves = [artifact for artifact in artifacts if artifact["scope"] == "leaf"]
    _require(leaves, f"{where} has no leaf custody")

    topology = None
    if value["topology"] is not None:
        topology = _validate_topology(value["topology"], expected_segments,
                                      f"{where}.topology")
    for leaf in leaves:
        _require(leaf["level"] == 0 and leaf["child_nodes"] == [],
                 f"{where} leaf topology differs")
        _require(leaf["node_index"] < expected_segments
                 and leaf["covered_segments"] == [leaf["node_index"]],
                 f"{where} leaf segment binding differs")
    covered = sorted(index for leaf in leaves for index in leaf["covered_segments"])
    _require(value["covered_segments"] == covered,
             f"{where}.covered_segments differs from leaf custody")
    _require(value["segment_coverage_root_sha256"]
             == segment_coverage_root_sha256(artifacts),
             f"{where}.segment_coverage_root_sha256 differs")

    counts_disclosure = _exact(value["proof_counts"], {
        "real_leaf_proofs", "proofless_empty_authorities",
        "recursive_parent_proofs", "total_proofs",
    }, f"{where}.proof_counts")
    derived_parent_proofs = sum(artifact["scope"] != "leaf" for artifact in artifacts)
    expected_counts = {
        "real_leaf_proofs": len(leaves),
        "proofless_empty_authorities": len(empty_authorities),
        "recursive_parent_proofs": derived_parent_proofs,
        "total_proofs": len(artifacts),
    }
    _require(counts_disclosure == expected_counts, f"{where}.proof_counts differs")

    if empty_authorities or any(artifact["scope"] != "leaf" for artifact in artifacts):
        _require(topology is not None, f"{where} recursive artifact lacks topology")
    if topology is not None:
        counts = topology["node_counts"]
        arity = topology["arity"]
        levels = topology["levels"]
        common_empty_authority = None
        for authority in empty_authorities:
            index = authority["node_index"]
            _require(expected_segments <= index < topology["slot_capacity"],
                     f"{where} empty authority is not trailing")
            _require(authority["slot_capacity"] == topology["slot_capacity"]
                     and authority["topology_sha256"] == topology["topology_sha256"],
                     f"{where} empty authority topology differs")
            common = {
                field: authority[field]
                for field in (
                    "session_id", "job_sha256", "segment_leaf_vk_sha256",
                    "recursive_parent_vk_sha256", "proof_profile_entry_sha256",
                )
            }
            if common_empty_authority is None:
                common_empty_authority = common
            _require(common == common_empty_authority,
                     f"{where} empty authority context differs")
        for artifact in artifacts:
            level = artifact["level"]
            index = artifact["node_index"]
            _require(level <= levels and index < counts[level],
                     f"{where} artifact lies outside topology")
            if level == 0:
                _require(artifact["scope"] == "leaf",
                         f"{where} level-zero artifact is not a leaf")
                _require(index < expected_segments
                         and artifact["covered_segments"] == [index],
                         f"{where} real leaf coverage differs")
                continue
            start = index * arity
            stop = start + arity
            _require(stop <= counts[level - 1], f"{where} parent is ragged")
            expected_children = [
                {"level": level - 1, "node_index": child_index}
                for child_index in range(start, stop)
            ]
            _require(artifact["child_nodes"] == expected_children,
                     f"{where} child topology differs")
            children = []
            for child in expected_children:
                key = (child["level"], child["node_index"])
                if key in artifact_by_key:
                    children.extend(artifact_by_key[key]["covered_segments"])
                else:
                    _require(key in empty_by_key and child["level"] == 0,
                             f"{where} child custody is absent")
            _require(artifact["covered_segments"] == sorted(children)
                     and len(children) == len(set(children)),
                     f"{where} recursive segment coverage differs")
            expected_scope = "final_root" if level == levels else "parent"
            _require(artifact["scope"] == expected_scope,
                     f"{where} recursive scope differs")

    derived_scope = ("final_root" if any(a["scope"] == "final_root" for a in artifacts)
                     else "parent" if any(a["scope"] == "parent" for a in artifacts)
                     else "leaf")
    _require(value["scope"] == derived_scope, f"{where}.scope is overstated")
    if value["scope"] != "final_root":
        _require(value["final_root"] is None,
                 f"{where} non-final custody contains final root")
        return False, None, False, False

    _require(False, f"{where} verifier-minted descriptor admission is unavailable")

    _require(topology is not None, f"{where} final root lacks topology")
    expected_keys = (
        [(0, index) for index in range(expected_segments)]
        + [
            (level, index)
            for level, count in enumerate(topology["node_counts"][1:], 1)
            for index in range(count)
        ]
    )
    _require(keys == expected_keys, f"{where} final topology custody is incomplete")
    expected_empty_keys = [
        (0, index)
        for index in range(expected_segments, topology["slot_capacity"])
    ]
    _require(empty_keys == expected_empty_keys,
             f"{where} final empty-leaf custody is incomplete")
    _require(counts_disclosure == {
        "real_leaf_proofs": expected_segments,
        "proofless_empty_authorities": topology["empty_leaf_count"],
        "recursive_parent_proofs": topology["slot_capacity"] - 1,
        "total_proofs": expected_segments + topology["slot_capacity"] - 1,
    }, f"{where} final proof counts differ")
    root_artifact = artifact_by_key[(topology["levels"], 0)]
    _require(root_artifact["covered_segments"] == list(range(expected_segments)),
             f"{where} final root does not cover all segments")
    final_root = _exact(value["final_root"], {
        "level", "node_index", "statement_sha256", "root_sha256", "proof",
        "verification_receipt", "all_segments_covered", "fresh_verification",
    }, f"{where}.final_root")
    expected_final = {
        "level": topology["levels"],
        "node_index": 0,
        "statement_sha256": root_artifact["statement_sha256"],
        "root_sha256": root_artifact["root_sha256"],
        "proof": root_artifact["proof"],
        "verification_receipt": root_artifact["verification_receipt"],
        "all_segments_covered": True,
        "fresh_verification": True,
    }
    _require(final_root == expected_final, f"{where}.final_root differs")
    _require(final_root["statement_sha256"]
             == statement_binding["proved_root_statement_sha256"],
             f"{where} final statement differs from proved-root statement")
    performance_claim_eligible = all(
        artifact["attempts"]["performance_claim_eligible"] for artifact in artifacts
    ) and stream_performance_eligible
    return (
        True, root_artifact["security"], performance_claim_eligible,
        statement_binding["matched_guest_statement_reproduced"],
    )


def validate_result(result: Any, protocol: dict[str, Any]) -> None:
    """Validate a future two-system result against the frozen result contract."""
    result = _exact(result, {
        "schema", "statement_sha256", "systems", "comparison_ready",
    }, "benchmark result")
    _require(result["schema"] == RESULT_SCHEMA, "benchmark result schema differs")
    _require(result["statement_sha256"] == protocol["statement_sha256"],
             "benchmark result statement differs")
    statement = protocol.get("statement")
    if type(statement) is dict:
        expected_statement_matched = statement.get(
            "matched_guest_statement_reproduced",
        )
    else:
        expected_statement_matched = protocol.get(
            "matched_guest_statement_reproduced",
        )
    _require(type(expected_statement_matched) is bool,
             "benchmark statement match authority differs")
    systems = _exact(result["systems"], {"zisk", "stwo"}, "benchmark result systems")
    complete_systems = []
    for name in ("zisk", "stwo"):
        system = _exact(systems[name], {
            "status", "timings", "trace_generation", "execution_work", "proof_custody",
            "geometry", "security", "hardware",
        }, f"benchmark result {name}")
        _require(system["status"] in ("incomplete", "complete"),
                 f"benchmark result {name} status differs")
        timings_complete = _validate_timings(system["timings"], f"benchmark result {name} timings")
        trace = measurements.validate_trace_generation(
            system["trace_generation"], f"benchmark result {name} trace generation",
            TRACE_GENERATION_SCHEMA,
        )
        execution_work = measurements.validate_execution_work(
            system["execution_work"], f"benchmark result {name} execution work",
            EXECUTION_WORK_SCHEMA,
        )
        (proof_complete, final_security, proof_performance_complete,
         statement_matched) = _validate_proof_custody(
            system["proof_custody"], result["statement_sha256"],
            expected_statement_matched,
            f"benchmark result {name} proof custody",
        )
        geometry = _exact(system["geometry"], set(GEOMETRY_FIELDS),
                          f"benchmark result {name} geometry")
        for field in GEOMETRY_FIELDS:
            if field == "external_family_rows":
                _require(geometry[field] is None or type(geometry[field]) is list,
                         f"benchmark result {name} external families differ")
            else:
                _nonnegative_or_null(geometry[field], f"benchmark result {name}.{field}")
        security_complete = measurements.validate_security(
            system["security"], f"benchmark result {name} security", SECURITY_FIELDS,
            complete=False,
        )
        if not proof_complete:
            _require(all(value is None for value in system["security"].values()),
                     f"benchmark result {name} non-final security must be null")
            _require(system["timings"]["proving"] is None
                     and system["timings"]["verification"] is None,
                     f"benchmark result {name} non-final proof timings must be null")
        hardware_complete = measurements.validate_hardware(
            system["hardware"], f"benchmark result {name} hardware", HARDWARE_FIELDS,
        )
        execution_timing = system["timings"]["execution"]
        if execution_work is not None and execution_timing is not None:
            _require(execution_work["user_ns"] == execution_timing["user_ns"]
                     and execution_work["system_ns"] == execution_timing["system_ns"],
                     f"benchmark result {name} execution CPU work differs from timing")
        if execution_work is not None:
            hardware = system["hardware"]
            for field in ("execution_multiplicity", "execution_strategy"):
                if hardware[field] is not None:
                    expected = (execution_work["multiplicity"] if field.endswith("multiplicity")
                                else execution_work["strategy"])
                    _require(hardware[field] == expected,
                             f"benchmark result {name} hardware {field} differs")
            if trace is not None:
                _require(execution_work["strategy"] == trace["mode"],
                         f"benchmark result {name} execution strategy differs from trace mode")
                if trace["mode"] == "whole-program-repetitions":
                    _require(execution_work["multiplicity"]
                             == trace["whole_program"]["multiplicity"],
                             f"benchmark result {name} execution multiplicity differs")
                else:
                    _require(execution_work["multiplicity"] == 1,
                             f"benchmark result {name} capture multiplicity differs")
        if proof_complete:
            _require(system["security"] == final_security,
                     f"benchmark result {name} final security differs")
        complete = (timings_complete and trace is not None and execution_work is not None
                    and proof_complete and proof_performance_complete
                    and statement_matched
                    and all(value is not None for value in geometry.values())
                    and security_complete and hardware_complete)
        _require((system["status"] == "complete") == complete,
                 f"benchmark result {name} completion differs")
        if complete:
            _require(system["security"]["fresh_verification"] is True,
                     f"benchmark result {name} lacks fresh verification")
        complete_systems.append(complete)
    _require(type(result["comparison_ready"]) is bool, "benchmark comparison status differs")
    _require(result["comparison_ready"] is False,
             "frozen protocol cannot promote an apples-to-apples result")
    _require(not (all(complete_systems) and protocol["promotion_ready"]),
             "benchmark result requires a promoted protocol revision")
