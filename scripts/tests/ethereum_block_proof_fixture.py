"""Shared deterministic fixture authority for Ethereum proof-controller tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_profile_plan as profile_plan


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def native_id(value: int) -> str:
    return (value.to_bytes(4, "little") * 8).hex()


def recursive_leaf_profile() -> dict:
    return {
        "air_program_id_m31_le": native_id(11),
        "extension_component_count": 14,
        "configured_pcs_bits": 209, "conjectured_security_bits": 120,
        "hash_suite": "Poseidon2-M31", "interaction_pow_bits": 10,
        "child_air_manifest_sha256": digest("ethereum-child-air-manifest"),
        "leaf_verification_key_id_m31_le": native_id(12),
        "profile_id_m31_le": native_id(13),
        "profile_name": "stwo.ethereum-segment-v3-recursive-poseidon2-m31-v1",
        "proof_kind": "ethereum_segment_v3_poseidon2",
        "recursive_ingress": "ethereum_segment_v3_full",
        "security_identity_sha256": (
            "bc339bc9bcf2d57ed49caccff618e944ddd03b401d528e7b3cb0d2f514306b04"
        ),
    }


def proof_security(kind: str) -> dict:
    common = {
        "field_id": profile_plan.M31_FIELD_ID, "format_version": 1,
        "fri_log_blowup_factor": 1, "fri_log_last_layer_degree_bound": 0,
        "pcs_lifting_mode": 0, "schema_version": 1,
    }
    if kind == "ethereum_segment_v3_poseidon2":
        return {
            **common, "configured_pcs_bits": 209,
            "conjectured_security_bits": 120, "fri_fold_step": 4,
            "fri_query_count": 193, "hash_suite": "poseidon2_m31",
            "identity_sha256": profile_plan.LEAF_SECURITY_IDENTITY,
            "interaction_pow_bits": 10, "kind": kind, "pcs_pow_bits": 16,
            "proof_present": True,
            "recursive_ingress": "ethereum_segment_v3_full",
        }
    if kind == "proofless_empty":
        return {
            **common, "configured_pcs_bits": 0,
            "conjectured_security_bits": 0, "fri_fold_step": 0,
            "fri_query_count": 0, "hash_suite": "none",
            "identity_sha256": profile_plan.EMPTY_SECURITY_IDENTITY,
            "interaction_pow_bits": 0, "kind": kind, "pcs_pow_bits": 0,
            "proof_present": False, "recursive_ingress": "no_proof",
        }
    if kind == "recursive_parent_secure":
        return {
            **common, "configured_pcs_bits": 209,
            "conjectured_security_bits": 120, "fri_fold_step": 4,
            "fri_query_count": 193, "hash_suite": "poseidon2_m31",
            "identity_sha256": profile_plan.PARENT_SECURITY_IDENTITY,
            "interaction_pow_bits": 10, "kind": kind, "pcs_pow_bits": 16,
            "proof_present": True, "recursive_ingress": "recursive_parent",
        }
    raise AssertionError(f"unknown fixture security kind: {kind}")


def profile_plan_projection() -> dict:
    parent_security = proof_security("recursive_parent_secure")
    entries = []
    verification_keys = [digest(f"profile-vk-{index}") for index in range(9)]
    for ordinal in range(9):
        if ordinal == 0:
            entry_kind, parent_height = "real_h1", 1
            admitted = proof_security("ethereum_segment_v3_poseidon2")
            transcript_kind, domain, cohort_version = (
                "temporal_parent_v3", 0x5450_4333, 3,
            )
        elif ordinal == 1:
            entry_kind, parent_height = "empty_h1", 1
            admitted = proof_security("proofless_empty")
            transcript_kind, domain, cohort_version = (
                "empty_parent_v1", 0x4550_4331, 1,
            )
        else:
            entry_kind, parent_height = "upper", ordinal
            admitted = parent_security
            transcript_kind, domain, cohort_version = (
                "recursive_node_v1", 0x4C32_4331, 1,
            )
        next_vk = (verification_keys[2] if ordinal < 2
                   else verification_keys[min(ordinal + 1, 8)])
        entries.append({
            "admitted_child_security": admitted,
            "air_profile_sha256": digest(f"air-profile-{ordinal}"),
            "air_program_sha256": digest(f"air-program-{ordinal}"),
            "child_composition_manifest_sha256": digest(
                f"child-composition-manifest-{ordinal}",
            ),
            "entry_kind": entry_kind,
            "entry_sha256": digest(f"profile-entry-{ordinal}"),
            "next_parent_vk_sha256": next_vk,
            "node_profile_sha256": digest(f"node-profile-{ordinal}"),
            "ordinal": ordinal, "parent_height": parent_height,
            "parent_outer_manifest_sha256": digest(f"parent-manifest-{ordinal}"),
            "parent_proof_security": parent_security,
            "transcript": {
                "cohort_format_version": cohort_version,
                "cohort_schema_version": 1, "component_count": 36,
                "domain": domain, "format_version": 1,
                "identity_sha256": digest(f"transcript-{ordinal}"),
                "kind": transcript_kind, "schema_version": 1,
            },
            "verification_key_sha256": verification_keys[ordinal],
        })
    return {
        "entries": entries, "format_version": 1,
        "profile_plan_sha256": digest("profile-plan"),
        "schema": profile_plan.TRANSPORT_SCHEMA, "schema_version": 2,
    }


def security_parameters(leaf_pcs: dict, proof_profile: dict) -> dict:
    return {
        "schema": protocol.plan_authority.SECURITY_SCHEMA,
        "native_blake_leaf": None,
        "recursive_ethereum_leaf": {
            "pcs": leaf_pcs, "proof_profile": proof_profile,
        },
        "recursive_node": {
            **protocol.plan_authority.RECURSIVE_NODE_AUTHORITY,
            "security_identity_sha256": (
                "675ff4fd58923d26ae7f4573b19a53a268bcf27bf9ad96cb18a04bd845169e63"
            ),
        },
        "conservative_end_to_end_target_bits": 120,
        "independent_verifier": True,
    }


def empty_result(statement_sha256: str) -> dict:
    benchmark = protocol.benchmark
    systems = {}
    for name in ("zisk", "stwo"):
        systems[name] = {
            "status": "incomplete",
            "timings": {name: None for name in (
                "execution", "witness_generation", "proving", "verification",
                "total_wall_ns",
            )},
            "trace_generation": None, "execution_work": None, "proof_custody": None,
            "geometry": {field: None for field in benchmark.GEOMETRY_FIELDS},
            "security": {field: None for field in benchmark.SECURITY_FIELDS},
            "hardware": {field: None for field in benchmark.HARDWARE_FIELDS},
        }
    return {
        "schema": benchmark.RESULT_SCHEMA, "statement_sha256": statement_sha256,
        "systems": systems, "comparison_ready": False,
    }


def file_identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def build_plan(base: Path, segment_count: int = 6) -> tuple[dict, dict]:
    sources = base / "segments"
    binaries = base / "bin"
    sources.mkdir()
    binaries.mkdir()
    segments = []
    for index in range(segment_count):
        path = sources / f"segment-{index:06d}.bin"
        path.write_bytes(f"segment-{index}".encode("ascii"))
        segments.append({
            "segment_index": index,
            "source": {"path": path.name, **file_identity(path)},
            "source_public_statement_sha256": digest(f"source-public-{index}"),
            "recursive_statement_sha256": digest(f"statement-0-{index}"),
        })
    source_files = {}
    for name in ("guest.elf", "input.bin", "output.bin", "execution.ndjson"):
        path = sources / name
        path.write_bytes(f"fixture-{name}".encode("ascii"))
        source_files[name] = {"path": str(path), **file_identity(path)}
    leaf_stream_request = sources / "leaf-stream-request.json"
    source_request = {
        "clock_frame": "leaf_local", "elf": source_files["guest.elf"],
        "execution_journal": source_files["execution.ndjson"],
        "execution_profile": "rv32im-zkvm-ethereum-v1",
        "expected_output": source_files["output.bin"], "input": source_files["input.bin"],
        "pcs": protocol.plan_authority.pcs_from_profile(
            protocol.plan_authority.RECURSIVE_NODE_AUTHORITY
        ),
        "proof_profile": recursive_leaf_profile(), "profile_abi_version": 1,
        "profile_semantic_digest": (
            "fbe8833de35b29ab155afed58f593d44d2a7257ad4491d953742d394da66cfc2"
        ),
        "profile_wire_id": 3, "schema": protocol.LEAF_STREAM_SOURCE_SCHEMA,
        "segment_authority_magic": "STWESG31", "segment_authority_version": 1,
        "segment_count": segment_count, "segment_step_budget": 4_194_304,
        "strict_completion": True,
    }
    leaf_stream_request.write_bytes(protocol.canonical_bytes(source_request))
    profile_plan_path = sources / "profile-plan.json"
    profile_projection = profile_plan_projection()
    profile_plan_path.write_bytes(protocol.canonical_bytes(profile_projection))
    prover = binaries / "prover"
    verifier = binaries / "verifier"
    prover.write_bytes(b"deterministic-prover")
    verifier.write_bytes(b"deterministic-verifier")
    arity = 2
    slot_capacity = 1 << (segment_count - 1).bit_length()
    counts = [slot_capacity]
    while counts[-1] > 1:
        counts.append(counts[-1] // arity)
    benchmark_statement = digest("benchmark-statement")
    proved_root_statement = digest("proved-root-statement")
    statements = []
    for level, count in enumerate(counts):
        for node_index in range(count):
            statement = (proved_root_statement if level == len(counts) - 1
                         else digest(f"statement-{level}-{node_index}"))
            statements.append({
                "level": level, "node_index": node_index,
                "recursive_statement_sha256": statement,
            })
    binding = {
        "schema": protocol.benchmark.STATEMENT_BINDING_SCHEMA,
        "benchmark_statement_sha256": benchmark_statement,
        "proved_root_statement_sha256": proved_root_statement,
        "block_authority_sha256": digest("block-authority"),
        "elf": source_request["elf"], "input": source_request["input"],
        "expected_output": source_request["expected_output"],
        "source_request_sha256": file_identity(leaf_stream_request)["sha256"],
        "matched_guest_statement_reproduced": False,
    }
    binding["content_sha256"] = protocol.benchmark._sealed_sha256(binding)
    plan = protocol.seal({
        "schema": protocol.PLAN_SCHEMA, "session_id": digest("proof-session"),
        "benchmark_statement_sha256": benchmark_statement,
        "proved_root_statement_sha256": proved_root_statement,
        "statement_binding": binding, "arity": arity, "levels": len(counts) - 1,
        "node_counts": counts, "real_segment_count": segment_count,
        "slot_capacity": slot_capacity, "padded_leaf_count": slot_capacity,
        "empty_leaf_count": slot_capacity - segment_count,
        "topology_sha256": protocol.benchmark.topology_sha256(
            arity, len(counts) - 1, counts, segment_count,
        ),
        "job_sha256": digest("proof-job"),
        "profile_policy_template": {
            "schema": profile_plan.BINDING_SCHEMA,
            "artifact": {
                "schema": profile_plan.TRANSPORT_SCHEMA,
                "path": profile_plan_path.name, **file_identity(profile_plan_path),
            },
            "projection": profile_projection,
        },
        "segments": segments, "expected_statements": statements,
        "prover": file_identity(prover), "verifier": file_identity(verifier),
        "leaf_stream_request": {
            "schema": protocol.LEAF_STREAM_SOURCE_SCHEMA,
            "path": leaf_stream_request.name, **file_identity(leaf_stream_request),
        },
        "security_parameters": security_parameters(
            source_request["pcs"], source_request["proof_profile"],
        ),
        "parent_execution": {
            "schema": protocol.PARENT_EXECUTION_SCHEMA,
            "policy": "bounded-level-node-pool-v1", "max_workers": 1,
            "admitted_host_logical_cores": 1,
            "admitted_host_memory_bytes": 1024 * 1024 * 1024,
            "per_worker_memory_budget_bytes": 512 * 1024 * 1024,
            "total_worker_memory_budget_bytes": 512 * 1024 * 1024,
        },
        "result_template": empty_result(benchmark_statement),
    })
    return plan, {
        "segment_root": sources, "prover": prover, "verifier": verifier,
        "run_root": base / "run",
    }
