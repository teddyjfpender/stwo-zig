from __future__ import annotations

import copy
import hashlib
import json
import importlib.util
from pathlib import Path
import unittest

from scripts import ethereum_block_proof_profile_plan as profile_plan
from scripts.tests import ethereum_block_proof_fixture as proof_fixture


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "autoresearch/benchmarks/ethereum_block_comparison.py"
SPEC = importlib.util.spec_from_file_location("ethereum_block_comparison_protocol", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)
subject = comparison.benchmark_protocol


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def empty_result(protocol: dict) -> dict:
    systems = {}
    for name in ("zisk", "stwo"):
        systems[name] = {
            "status": "incomplete",
            "timings": {
                "execution": None,
                "witness_generation": None,
                "proving": None,
                "verification": None,
                "total_wall_ns": None,
            },
            "trace_generation": None,
            "execution_work": None,
            "proof_custody": None,
            "geometry": {field: None for field in subject.GEOMETRY_FIELDS},
            "security": {field: None for field in subject.SECURITY_FIELDS},
            "hardware": {field: None for field in subject.HARDWARE_FIELDS},
        }
    return {
        "schema": subject.RESULT_SCHEMA,
        "statement_sha256": protocol["statement_sha256"],
        "systems": systems,
        "comparison_ready": False,
    }


def capture_replay_trace() -> dict:
    return {
        "schema": subject.TRACE_GENERATION_SCHEMA,
        "mode": "sequential-capture-plus-parallel-replay",
        "whole_program": None,
        "capture": {
            "cycles": 100,
            "wall_ns": 10,
            "rate": {"cycles": 100, "nanoseconds": 10},
            "worker_count": 1,
            "strategy": "sequential-authoritative-capture",
            "authority": "measured",
        },
        "parallel_replay": {
            "cycles": 100,
            "wall_ns": 2,
            "rate": {"cycles": 100, "nanoseconds": 2},
            "worker_count": 8,
            "strategy": "parallel-memoryless-replay",
            "authority": "modeled",
            "efficiency": {"numerator": 1000, "denominator": 1600},
        },
        "total_trace_generation_wall_ns": 12,
        "total_authority": "modeled",
    }


def whole_program_trace(multiplicity: int = 16) -> dict:
    return {
        "schema": subject.TRACE_GENERATION_SCHEMA,
        "mode": "whole-program-repetitions",
        "whole_program": {
            "cycles": 1600,
            "wall_ns": 50,
            "rate": {"cycles": 1600, "nanoseconds": 50},
            "worker_count": multiplicity,
            "multiplicity": multiplicity,
            "strategy": "parallel-whole-program-repetitions",
            "authority": "measured",
        },
        "capture": None,
        "parallel_replay": None,
        "total_trace_generation_wall_ns": 50,
        "total_authority": "measured",
    }


def execution_work(strategy: str, multiplicity: int = 1) -> dict:
    return {
        "schema": subject.EXECUTION_WORK_SCHEMA,
        "multiplicity": multiplicity,
        "strategy": strategy,
        "per_execution_isa_steps": 100,
        "total_execution_isa_steps": 100 * multiplicity,
        "user_ns": 11,
        "system_ns": 21,
        "total_cpu_ns": 32,
        "authority": "measured",
    }


def security(proof_bytes: int, proof_profile: str) -> dict:
    return {
        "schema": "stwo.ethereum.block-proof-artifact-security.v2",
        "proof_profile": proof_profile,
        "native_blake_leaf": None,
        "recursive_ethereum_leaf": {
            "pcs": recursive_pcs(), "proof_profile": recursive_leaf_profile(),
        },
        "recursive_node": {
            **recursive_pcs(), "interaction_pow_bits": 10,
            "configured_pcs_bits": 209, "conjectured_security_bits": 120,
            "security_identity_sha256": (
                "675ff4fd58923d26ae7f4573b19a53a268bcf27bf9ad96cb18a04bd845169e63"
            ),
        },
        "conservative_end_to_end_target_bits": 120,
        "proof_bytes": proof_bytes,
        "fresh_verification": True,
        "independent_verifier": True,
    }


def recursive_pcs() -> dict:
    return {
        "field": "M31",
        "commitment_hash": "Poseidon2-M31", "transcript_hash": "Poseidon2-M31",
        "pow_bits": 16, "n_queries": 193, "log_blowup_factor": 1,
        "fold_step": 4, "log_last_layer_degree_bound": 0,
        "lifting_log_size": None,
    }


def recursive_leaf_profile() -> dict:
    native = (1).to_bytes(4, "little").hex() * 8
    return {
        "air_program_id_m31_le": native, "extension_component_count": 14,
        "configured_pcs_bits": 209, "conjectured_security_bits": 120,
        "hash_suite": "Poseidon2-M31", "interaction_pow_bits": 10,
        "leaf_verification_key_id_m31_le": native,
        "child_air_manifest_sha256": digest("child-air-manifest"),
        "profile_id_m31_le": native,
        "profile_name": "stwo.ethereum-segment-v3-recursive-poseidon2-m31-v1",
        "proof_kind": "ethereum_segment_v3_poseidon2",
        "recursive_ingress": "ethereum_segment_v3_full",
        "security_identity_sha256": (
            "bc339bc9bcf2d57ed49caccff618e944ddd03b401d528e7b3cb0d2f514306b04"
        ),
    }


def artifact(
    scope: str,
    level: int,
    node_index: int,
    covered_segments: list[int],
    child_nodes: list[dict] | None = None,
    statement_sha256: str | None = None,
) -> dict:
    label = f"{scope}-{level}-{node_index}"
    proof_bytes = 1000 + level * 10 + node_index
    prover = {"bytes": 2000, "sha256": digest("prover")}
    verifier = {"bytes": 3000, "sha256": digest("verifier")}
    prove_timing = {"wall_ns": 10, "user_ns": 9, "system_ns": 1}
    verify_timing = {"wall_ns": 2, "user_ns": 2, "system_ns": 0}
    processes = {
        "producer": {
            "schema": "stwo.ethereum.block-proof-subprocess-receipt.v1",
            "role": "proof_producer",
            "executable": prover,
            "argv": ["prover", label],
            "exit_code": 0,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "timing": prove_timing,
        },
        "fresh_verifier": {
            "schema": "stwo.ethereum.block-proof-subprocess-receipt.v1",
            "role": "fresh_verifier",
            "executable": verifier,
            "argv": ["verifier", label],
            "exit_code": 0,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "timing": verify_timing,
        },
    }
    if scope == "leaf":
        processes["producer"] = {
            "schema": "stwo.ethereum.block-proof-leaf-stream-observation.v1",
            "role": "leaf_stream_producer",
            "executable": prover,
            "argv": ["leaf-stream-producer", "fixture"],
            "stream_session_sha256": digest("leaf-stream-session"),
            "segment_index": node_index,
            "progress_record_sha256": digest(f"progress-{node_index}"),
            "prove_timing": prove_timing,
        }
    artifact_security = security(
        proof_bytes,
        "recursive_ethereum_leaf" if scope == "leaf" else "recursive_node",
    )
    return {
        "scope": scope,
        "level": level,
        "node_index": node_index,
        "child_nodes": child_nodes or [],
        "covered_segments": covered_segments,
        "statement_sha256": statement_sha256 or digest(f"statement-{label}"),
        "recursive_statement_sha256": digest(f"recursive-statement-{label}"),
        "root_sha256": digest(f"root-{label}"),
        "proof": {"bytes": proof_bytes, "sha256": digest(f"proof-{label}")},
        "prover": prover,
        "verifier": verifier,
        "verification_receipt": {
            "bytes": 400 + level,
            "sha256": digest(f"receipt-{label}"),
        },
        "prove_timing": prove_timing,
        "fresh_verify_timing": verify_timing,
        "processes": processes,
        "attempts": {
            "schema": "stwo.ethereum.block-proof-attempt-summary.v2",
            "total_attempt_count": 1,
            "successful_attempt_index": 0,
            "failed_attempt_count": 0,
            "indeterminate_attempt_count": 0,
            "attempt_history": [],
            "observed_operational_wall_ns": 12,
            "successful_prove_verify_wall_ns": 12,
            "performance_claim_eligible": True,
        },
        "security": artifact_security,
        "proof_profile_authority": (
            artifact_security["recursive_ethereum_leaf"] if scope == "leaf" else {
                "production_admissible": False,
                "schema": "stwo.ethereum.block-proof-test-node-descriptor.v1",
                "status": "test_only_verifier_minted_descriptor_unavailable",
            }
        ),
    }


def profile_policy_template() -> dict:
    projection = proof_fixture.profile_plan_projection()
    return {
        "schema": profile_plan.BINDING_SCHEMA,
        "artifact": {
            "schema": profile_plan.TRANSPORT_SCHEMA,
            "path": "profile-policy-template.json",
            "bytes": 1,
            "sha256": digest("profile-policy-template"),
        },
        "projection": projection,
    }


def canonical_empty_authority(
    node_index: int, slot_capacity: int, topology_sha256: str,
) -> dict:
    value = {
        "schema": subject.EMPTY_AUTHORITY_SCHEMA,
        "kind": "canonical_empty",
        "session_id": digest("empty-session"),
        "job_sha256": digest("empty-job"),
        "topology_sha256": topology_sha256,
        "segment_leaf_vk_sha256": digest("segment-leaf-vk"),
        "recursive_parent_vk_sha256": digest("recursive-parent-vk"),
        "level": 0,
        "node_index": node_index,
        "slot_capacity": slot_capacity,
        "statement_sha256": digest(f"statement-leaf-0-{node_index}"),
        "proof_present": False,
        "proof_profile_entry_sha256": digest("empty-h1-profile-entry"),
    }
    value["authority_sha256"] = subject.canonical_empty_authority_sha256(value)
    return value


def producer_sessions(indices: list[int]) -> list[dict]:
    receipt = {
        "schema": "stwo.ethereum.block-proof-leaf-session-receipt.v1",
        "classification": "complete",
        "session_index": 0,
        "stream_session_sha256": digest("leaf-stream-session"),
        "executable": {"bytes": 2000, "sha256": digest("prover")},
        "argv": ["leaf-stream-producer", "fixture"],
        "request": {"path": "stream-request.json", "bytes": 1,
                    "sha256": digest("stream-request")},
        "first_segment_index": 0,
        "published_segment_indices": indices,
        "exit_code": 0,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "timing": {"wall_ns": 10, "user_ns": None, "system_ns": None},
        "stream_result": {"path": "stream-result.json", "bytes": 1,
                          "sha256": digest("stream-result")},
    }
    unsigned = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    receipt["content_sha256"] = hashlib.sha256(unsigned).hexdigest()
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return [{
        "receipt": receipt,
        "file": {"path": "leaf-stream/session-receipt.json", "bytes": len(encoded),
                 "sha256": hashlib.sha256(encoded).hexdigest()},
    }]


def reseal_session(publication: dict) -> None:
    receipt = publication["receipt"]
    receipt.pop("content_sha256", None)
    raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    receipt["content_sha256"] = hashlib.sha256(raw).hexdigest()
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
    publication["file"]["bytes"] = len(encoded)
    publication["file"]["sha256"] = hashlib.sha256(encoded).hexdigest()


def statement_binding(benchmark_sha256: str, proved_sha256: str) -> dict:
    value = {
        "schema": subject.STATEMENT_BINDING_SCHEMA,
        "benchmark_statement_sha256": benchmark_sha256,
        "proved_root_statement_sha256": proved_sha256,
        "block_authority_sha256": digest("block-authority"),
        "elf": {"path": "/fixture/guest.elf", "bytes": 1,
                "sha256": digest("guest-elf")},
        "input": {"path": "/fixture/input.bin", "bytes": 1,
                  "sha256": digest("guest-input")},
        "expected_output": {"path": "/fixture/output.bin", "bytes": 1,
                            "sha256": digest("guest-output")},
        "source_request_sha256": digest("source-request"),
        "matched_guest_statement_reproduced": False,
    }
    value["content_sha256"] = subject._sealed_sha256(value)
    return value


def leaf_custody(benchmark_statement_sha256: str) -> dict:
    leaf = artifact("leaf", 0, 0, [0])
    artifacts = [leaf]
    return {
        "schema": subject.PROOF_CUSTODY_SCHEMA,
        "scope": "leaf",
        "expected_segment_count": 2,
        "covered_segments": [0],
        "segment_coverage_root_sha256": subject.segment_coverage_root_sha256(artifacts),
        "empty_authority_root_sha256": subject.empty_authority_root_sha256([]),
        "proof_counts": {
            "real_leaf_proofs": 1,
            "proofless_empty_authorities": 0,
            "recursive_parent_proofs": 0,
            "total_proofs": 1,
        },
        "topology": None,
        "artifacts": artifacts,
        "empty_authorities": [],
        "producer_sessions": producer_sessions([0]),
        "profile_policy_template": profile_policy_template(),
        "statement_binding": statement_binding(
            benchmark_statement_sha256, digest("proved-root-statement"),
        ),
        "final_root": None,
    }


def parent_custody(benchmark_statement_sha256: str) -> dict:
    leaves = [artifact("leaf", 0, index, [index]) for index in range(2)]
    parent = artifact(
        "parent", 1, 0, [0, 1],
        [{"level": 0, "node_index": 0}, {"level": 0, "node_index": 1}],
    )
    artifacts = leaves + [parent]
    topology = {
        "arity": 2,
        "levels": 2,
        "node_counts": [4, 2, 1],
        "real_segment_count": 4,
        "slot_capacity": 4,
        "padded_leaf_count": 4,
        "empty_leaf_count": 0,
        "topology_sha256": subject.topology_sha256(2, 2, [4, 2, 1], 4),
    }
    return {
        "schema": subject.PROOF_CUSTODY_SCHEMA,
        "scope": "parent",
        "expected_segment_count": 4,
        "covered_segments": [0, 1],
        "segment_coverage_root_sha256": subject.segment_coverage_root_sha256(artifacts),
        "empty_authority_root_sha256": subject.empty_authority_root_sha256([]),
        "proof_counts": {
            "real_leaf_proofs": 2,
            "proofless_empty_authorities": 0,
            "recursive_parent_proofs": 1,
            "total_proofs": 3,
        },
        "topology": topology,
        "artifacts": artifacts,
        "empty_authorities": [],
        "producer_sessions": producer_sessions([0, 1]),
        "profile_policy_template": profile_policy_template(),
        "statement_binding": statement_binding(
            benchmark_statement_sha256, digest("proved-root-statement"),
        ),
        "final_root": None,
    }


def final_custody(benchmark_statement_sha256: str) -> dict:
    proved_statement_sha256 = digest("proved-root-statement")
    leaves = [artifact("leaf", 0, index, [index]) for index in range(3)]
    parents = [
        artifact(
            "parent", 1, 0, [0, 1],
            [{"level": 0, "node_index": 0}, {"level": 0, "node_index": 1}],
        ),
        artifact(
            "parent", 1, 1, [2],
            [{"level": 0, "node_index": 2}, {"level": 0, "node_index": 3}],
        ),
    ]
    root = artifact(
        "final_root", 2, 0, [0, 1, 2],
        [{"level": 1, "node_index": 0}, {"level": 1, "node_index": 1}],
        proved_statement_sha256,
    )
    artifacts = leaves + parents + [root]
    topology = {
        "arity": 2,
        "levels": 2,
        "node_counts": [4, 2, 1],
        "real_segment_count": 3,
        "slot_capacity": 4,
        "padded_leaf_count": 4,
        "empty_leaf_count": 1,
        "topology_sha256": subject.topology_sha256(2, 2, [4, 2, 1], 3),
    }
    empty_authorities = [canonical_empty_authority(
        3, 4, topology["topology_sha256"],
    )]
    return {
        "schema": subject.PROOF_CUSTODY_SCHEMA,
        "scope": "final_root",
        "expected_segment_count": 3,
        "covered_segments": [0, 1, 2],
        "segment_coverage_root_sha256": subject.segment_coverage_root_sha256(artifacts),
        "empty_authority_root_sha256": subject.empty_authority_root_sha256(
            empty_authorities,
        ),
        "proof_counts": {
            "real_leaf_proofs": 3,
            "proofless_empty_authorities": 1,
            "recursive_parent_proofs": 3,
            "total_proofs": 6,
        },
        "topology": topology,
        "artifacts": artifacts,
        "empty_authorities": empty_authorities,
        "producer_sessions": producer_sessions([0, 1, 2]),
        "profile_policy_template": profile_policy_template(),
        "statement_binding": statement_binding(
            benchmark_statement_sha256, proved_statement_sha256,
        ),
        "final_root": {
            "level": 2,
            "node_index": 0,
            "statement_sha256": root["statement_sha256"],
            "root_sha256": root["root_sha256"],
            "proof": dict(root["proof"]),
            "verification_receipt": dict(root["verification_receipt"]),
            "all_segments_covered": True,
            "fresh_verification": True,
        },
    }


def fill_system(
    system: dict, custody: dict, *, status: str, proof_completion: bool = True,
) -> None:
    system["status"] = status
    system["timings"] = {
        "execution": {"wall_ns": 1, "user_ns": 11, "system_ns": 21},
        "witness_generation": {"wall_ns": 2, "user_ns": 2, "system_ns": 0},
        "proving": {"wall_ns": 3, "user_ns": 3, "system_ns": 0},
        "verification": {"wall_ns": 4, "user_ns": 4, "system_ns": 0},
        "total_wall_ns": 10,
    }
    system["trace_generation"] = capture_replay_trace()
    system["execution_work"] = execution_work("sequential-capture-plus-parallel-replay")
    system["proof_custody"] = custody
    system["geometry"] = {
        field: ([] if field == "external_family_rows" else 1)
        for field in subject.GEOMETRY_FIELDS
    }
    system["security"] = copy.deepcopy(custody["artifacts"][-1]["security"])
    if not proof_completion:
        system["timings"]["proving"] = None
        system["timings"]["verification"] = None
        system["timings"]["total_wall_ns"] = None
        system["security"] = {field: None for field in subject.SECURITY_FIELDS}
    system["hardware"] = {
        "machine_model": "test-machine",
        "cpu_model": "test-cpu",
        "cpu_logical_cores": 8,
        "gpu_model": "none",
        "memory_bytes": 16 * 1024 * 1024,
        "operating_system": "test-os",
        "power_source": "AC",
        "thermal_state": "nominal",
        "process_count": 1,
        "thread_count": 8,
        "process_workers": 8,
        "accelerator_workers": 0,
        "execution_multiplicity": 1,
        "execution_strategy": "sequential-capture-plus-parallel-replay",
    }


class EthereumBlockBenchmarkProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = comparison.load_manifest()
        self.protocol = self.manifest["benchmark_protocol"]

    def test_protocol_binds_block_codec_specific_io_and_measurement_contract(self) -> None:
        subject.validate(self.protocol, self.manifest)
        statement = self.protocol["statement"]
        self.assertFalse(statement["matched_guest_statement_reproduced"])
        self.assertNotEqual(
            statement["inputs"]["zisk_transport"]["sha256"],
            statement["inputs"]["stwo_transport"]["sha256"],
        )
        contract = self.protocol["result_contract"]
        self.assertEqual(
            [bucket["name"] for bucket in contract["timing_buckets"]],
            ["execution", "witness_generation", "proving", "verification"],
        )
        self.assertEqual(contract["proof_custody"]["scopes"],
                         ["leaf", "parent", "final_root"])
        self.assertIn("execution_multiplicity", contract["hardware_fields"])
        self.assertIn("proof_bytes", contract["security_fields"])

    def test_protocol_mutations_fail_closed(self) -> None:
        mutations = (
            lambda value: value["statement"]["block"].update({"number": 1}),
            lambda value: value["statement"]["inputs"]["stwo_transport"].update(
                {"sha256": "00" * 32},
            ),
            lambda value: value["statement"]["outputs"].update(
                {"equivalence_status": "same"},
            ),
            lambda value: value.update({"statement_sha256": "00" * 32}),
            lambda value: value["result_contract"]["timing_buckets"].reverse(),
            lambda value: value["result_contract"]["proof_custody"].update(
                {"complete_requires": "inner-proof-only"},
            ),
            lambda value: value.update({"promotion_ready": True}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.protocol)
                mutate(value)
                with self.assertRaises(subject.BenchmarkProtocolError):
                    subject.validate(value, self.manifest)

    def test_partial_result_cannot_claim_total_wall(self) -> None:
        result = empty_result(self.protocol)
        subject.validate_result(result, self.protocol)
        result["systems"]["stwo"]["timings"]["total_wall_ns"] = 1
        with self.assertRaisesRegex(subject.BenchmarkProtocolError, "partial timing"):
            subject.validate_result(result, self.protocol)

    def test_complete_timing_buckets_reconcile_exact_wall(self) -> None:
        timings = empty_result(self.protocol)["systems"]["stwo"]["timings"]
        for index, name in enumerate(
            ("execution", "witness_generation", "proving", "verification"), 1,
        ):
            timings[name] = {"wall_ns": index, "user_ns": index + 10, "system_ns": index + 20}
        timings["total_wall_ns"] = 10
        self.assertTrue(subject._validate_timings(timings, "fixture timings"))
        timings["total_wall_ns"] = 11
        with self.assertRaisesRegex(subject.BenchmarkProtocolError, "does not reconcile"):
            subject._validate_timings(timings, "fixture timings")

    def test_result_cannot_promote_under_unmatched_statement_protocol(self) -> None:
        result = empty_result(self.protocol)
        result["comparison_ready"] = True
        with self.assertRaisesRegex(subject.BenchmarkProtocolError, "cannot promote"):
            subject.validate_result(result, self.protocol)

    def test_capture_replay_binds_exact_rates_efficiency_and_authority(self) -> None:
        result = empty_result(self.protocol)
        trace = capture_replay_trace()
        result["systems"]["stwo"]["trace_generation"] = trace
        subject.validate_result(result, self.protocol)
        trace["parallel_replay"]["efficiency"]["numerator"] += 1
        with self.assertRaisesRegex(subject.BenchmarkProtocolError, "efficiency differs"):
            subject.validate_result(result, self.protocol)

    def test_whole_program_repetitions_are_distinct_and_bind_cpu_work(self) -> None:
        result = empty_result(self.protocol)
        system = result["systems"]["zisk"]
        system["trace_generation"] = whole_program_trace(16)
        system["execution_work"] = execution_work("whole-program-repetitions", 16)
        system["timings"]["execution"] = {"wall_ns": 50, "user_ns": 11, "system_ns": 21}
        system["hardware"]["execution_multiplicity"] = 16
        system["hardware"]["execution_strategy"] = "whole-program-repetitions"
        subject.validate_result(result, self.protocol)
        self.assertEqual(system["trace_generation"]["whole_program"]["multiplicity"], 16)
        self.assertIsNone(system["trace_generation"]["capture"])

        system["execution_work"]["total_cpu_ns"] += 1
        with self.assertRaisesRegex(subject.BenchmarkProtocolError, "CPU total"):
            subject.validate_result(result, self.protocol)

    def test_execution_multiplicity_and_strategy_cross_bind_trace_and_hardware(self) -> None:
        result = empty_result(self.protocol)
        system = result["systems"]["zisk"]
        system["trace_generation"] = whole_program_trace(16)
        system["execution_work"] = execution_work("whole-program-repetitions", 16)
        system["hardware"]["execution_multiplicity"] = 16
        system["hardware"]["execution_strategy"] = "whole-program-repetitions"
        subject.validate_result(result, self.protocol)
        for field, value in (("execution_multiplicity", 15),
                             ("execution_strategy", "serial")):
            with self.subTest(field=field):
                mutated = copy.deepcopy(result)
                mutated["systems"]["zisk"]["hardware"][field] = value
                with self.assertRaises(subject.BenchmarkProtocolError):
                    subject.validate_result(mutated, self.protocol)

    def test_leaf_and_parent_proofs_are_admitted_but_never_complete(self) -> None:
        for custody in (
            leaf_custody(self.protocol["statement_sha256"]),
            parent_custody(self.protocol["statement_sha256"]),
        ):
            with self.subTest(scope=custody["scope"]):
                result = empty_result(self.protocol)
                fill_system(
                    result["systems"]["stwo"], custody, status="incomplete",
                    proof_completion=False,
                )
                subject.validate_result(result, self.protocol)
                result["systems"]["stwo"]["status"] = "complete"
                with self.assertRaisesRegex(subject.BenchmarkProtocolError, "completion differs"):
                    subject.validate_result(result, self.protocol)

    def test_unavailable_descriptors_reject_populated_final_root(self) -> None:
        result = empty_result(self.protocol)
        custody = final_custody(self.protocol["statement_sha256"])
        fill_system(result["systems"]["stwo"], custody, status="incomplete")
        with self.assertRaisesRegex(
            subject.BenchmarkProtocolError, "descriptor admission is unavailable",
        ):
            subject.validate_result(result, self.protocol)

    def test_topology_only_custody_requires_null_completion_fields(self) -> None:
        result = empty_result(self.protocol)
        custody = parent_custody(self.protocol["statement_sha256"])
        system = result["systems"]["stwo"]
        fill_system(system, custody, status="incomplete", proof_completion=False)
        subject.validate_result(result, self.protocol)
        self.assertIsNone(custody["final_root"])
        self.assertTrue(all(value is None for value in system["security"].values()))

        for field, value in (
            ("security", copy.deepcopy(custody["artifacts"][-1]["security"])),
            ("proving", {"wall_ns": 1, "user_ns": 1, "system_ns": 0}),
            ("verification", {"wall_ns": 1, "user_ns": 1, "system_ns": 0}),
        ):
            with self.subTest(field=field):
                mutated = copy.deepcopy(result)
                target = mutated["systems"]["stwo"]
                if field == "security":
                    target["security"] = value
                else:
                    target["timings"][field] = value
                with self.assertRaisesRegex(
                    subject.BenchmarkProtocolError, "non-final",
                ):
                    subject.validate_result(mutated, self.protocol)

    def test_leaf_observation_is_bound_to_the_session_that_published_its_segment(self) -> None:
        result = empty_result(self.protocol)
        custody = parent_custody(self.protocol["statement_sha256"])
        first = custody["producer_sessions"][0]
        second = copy.deepcopy(first)
        first["receipt"]["published_segment_indices"] = [0]
        second["receipt"]["session_index"] = 1
        second["receipt"]["stream_session_sha256"] = digest("second-leaf-session")
        second["receipt"]["first_segment_index"] = 1
        second["receipt"]["published_segment_indices"] = [1]
        second["file"]["path"] = "leaf-stream/session-1-receipt.json"
        reseal_session(first)
        reseal_session(second)
        custody["producer_sessions"] = [first, second]
        for artifact in custody["artifacts"]:
            if artifact["scope"] == "leaf" and artifact["node_index"] == 1:
                artifact["processes"]["producer"]["stream_session_sha256"] = (
                    second["receipt"]["stream_session_sha256"]
                )
        fill_system(
            result["systems"]["stwo"], custody, status="incomplete",
            proof_completion=False,
        )
        subject.validate_result(result, self.protocol)
        custody["artifacts"][0]["processes"]["producer"][
            "stream_session_sha256"
        ] = second["receipt"]["stream_session_sha256"]
        with self.assertRaisesRegex(subject.BenchmarkProtocolError,
                                    "leaf-to-session binding"):
            subject.validate_result(result, self.protocol)

if __name__ == "__main__":
    unittest.main()
