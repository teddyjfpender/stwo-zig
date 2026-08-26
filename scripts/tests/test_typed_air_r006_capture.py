from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from scripts.riscv_csp_ab_benchmark_lib import runner as ab_runner
from scripts.riscv_csp_benchmark_lib.host import power_conditions_admissible
from scripts.typed_air_r006_capture_lib.codec import content_digest
from scripts.typed_air_r006_capture_lib.contract import (
    PlanSettings,
    WorkloadPaths,
    _require_binary_markers,
    build_plan,
    materialized_poseidon_input,
    validate_plan,
)
from scripts.typed_air_r006_capture_lib.controller import (
    proof_command,
)
from scripts.typed_air_r006_capture_lib.model import (
    GENERATED_WORKLOAD_PARAMETERS,
    PLAN_ATTEMPTS,
    PROTOCOL_SHA256,
    CaptureError,
)
from scripts.typed_air_r006_capture_lib.report import validate_report
from scripts.typed_air_r006_capture_lib.workload_profile import task_profile_example
from scripts.tests.typed_air_r006_base_fixture import (
    base_artifact,
    base_artifact_payload,
)


def preflight_host(
    *,
    logical_cpu_count: int = 18,
    power_source: str = "AC Power",
    low_power_mode: bool = False,
) -> dict[str, object]:
    return {
        "os": "Darwin",
        "os_version": "fixture",
        "kernel": "fixture",
        "architecture": "arm64",
        "host_architecture": "arm64",
        "cpu": "fixture-cpu",
        "logical_cpu_count": logical_cpu_count,
        "memory_bytes": 64 * 1024**3,
        "gpu": {
            "name": "fixture-gpu",
            "core_count": 40,
            "metal_support": "Metal fixture",
            "unified_memory": True,
        },
        "power_source": power_source,
        "low_power_mode": low_power_mode,
        "python": "fixture",
    }


def quiet_evidence(
    host: dict[str, object],
    *,
    idle_percent: tuple[float, ...] = (97.0, 98.0, 99.0),
    load_1m: tuple[float, ...] = (0.1, 0.1, 0.1),
    thermal_clear: bool = True,
) -> dict[str, object]:
    power_admissible, power_reasons = power_conditions_admissible(host)
    return ab_runner.classify_quiet_host(
        idle_percent=idle_percent,
        load_1m=load_1m,
        logical_cpu_count=host["logical_cpu_count"],
        thermal={
            "provider": "darwin_top_pmset_v1",
            "thermal_clear": thermal_clear,
            "thermal_output_sha256": hashlib.sha256(b"fixture-thermal").hexdigest(),
            "thermal_line_count": 3,
            "kernel_thermal_pressure": None,
        },
        power_admissible=power_admissible,
        power_reasons=power_reasons,
        enforce_load_threshold=True,
    )


class R006Fixture(unittest.TestCase):
    base_artifact = staticmethod(base_artifact)
    base_artifact_payload = staticmethod(base_artifact_payload)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.scratch = Path(self.temporary.name)
        self.repository = Path(__file__).resolve().parents[2]
        self.executable = self.scratch / "stwo-zig-riscv-cpu"
        self.executable.write_bytes(
            b"fixture\0riscv_profiled_proof_v4\0riscv_verified_request_attempt_v3\0"
            b"stwo.prover.logical-work-profile.v2\0"
        )
        self.executable.chmod(0o700)
        self.workloads: dict[str, WorkloadPaths] = {}
        for name in (
            "multi_shard_addi",
            "memcpy_loop",
            "balanced_core_and_poseidon2",
            "poseidon2_dominant",
        ):
            elf = self.scratch / f"{name}.elf"
            elf.write_bytes(f"elf:{name}".encode("ascii"))
            input_path = None
            if name in {"balanced_core_and_poseidon2", "poseidon2_dominant"}:
                input_path = self.scratch / f"{name}.input"
                input_path.write_bytes(
                    materialized_poseidon_input(
                        GENERATED_WORKLOAD_PARAMETERS[name]["calls"]
                    )
                )
            self.workloads[name] = WorkloadPaths(elf, input_path)
        self.plan = build_plan(
            PlanSettings(
                repository=self.repository,
                session_id="fixture-r006",
                lane="cpu-native",
                power_state="AC power; fixture",
                executable=self.executable,
                workloads=self.workloads,
                toolchain="zig:fixture",
                target="aarch64-macos",
                cpu_features="apple-m2",
            ),
            source_provider=self.source,
            host_provider=self.host,
            closure_provider=self.closure,
            clock=lambda: dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def source(_: Path) -> dict[str, object]:
        return {
            "repository": "https://github.com/teddyjfpender/stwo-zig",
            "commit": "1" * 40,
            "tree": "2" * 40,
            "clean_status": True,
            "source_closure_files": 123,
            "source_closure_sha256": "3" * 64,
        }

    @staticmethod
    def host(power_state: str) -> dict[str, object]:
        return {
            "os": "Darwin",
            "os_version": "fixture",
            "kernel_release": "fixture",
            "machine": "arm64",
            "cpu_model": "fixture-cpu",
            "logical_cores": 10,
            "physical_cores": 8,
            "memory_bytes": 16 * 1024**3,
            "power_state": {
                "operator_declaration": power_state,
                "machine_verified": True,
                "power_source": "AC Power",
                "low_power_mode": False,
            },
        }

    @staticmethod
    def closure(_: Path) -> dict[str, object]:
        complete = {"complete": 16, "partial": 0, "absent": 0}
        return {
            "schema": "stwo.typed-air.p003-global-exact-work-closure.v1",
            "schema_version": 1,
            "matrix": {
                "path": (
                    "design/typed-air/artifacts/"
                    "p003-work-profile-closure-v1/matrix-v1.json"
                ),
                "schema": "stwo.typed-air.p003-work-profile-closure-matrix.v1",
                "sha256": "9" * 64,
            },
            "inventory": {
                "path": "src/prover_api/work_profile_inventory.zig",
                "schema_version": 9,
                "site_count": 23,
                "source_bytes": 5_398,
                "source_sha256": "a" * 64,
            },
            "coverage": {
                "cpu": dict(complete),
                "metal": dict(complete),
                "joint": dict(complete),
                "family_count": 16,
                "whole_prover_exact": True,
            },
        }

    @staticmethod
    def verifier_receipt(
        plan: dict[str, object],
        *,
        statement_sha256: str = "4" * 64,
        transcript_state_blake2s: str = "5" * 64,
        proof_payload: bytes = b"verified-pcs-proof",
    ) -> bytes:
        receipt = {
            "schema": "riscv_verify_v1",
            "status": "verified",
            "artifact_kind": "stwo_riscv_proof",
            "artifact_schema_version": 4,
            "release_status": "release_gated",
            "security_policy": "secure",
            "statement_sha256": statement_sha256,
            "proof_bytes": len(proof_payload),
            "proof_sha256": hashlib.sha256(proof_payload).hexdigest(),
            "transcript_state_blake2s": transcript_state_blake2s,
            "implementation_commit": plan["source"]["commit"],
            "implementation_dirty": False,
            "executable_sha256": plan["build"]["executable_sha256"],
        }
        return json.dumps(receipt, separators=(",", ":")).encode("ascii") + b"\n"

    @staticmethod
    def report(
        plan: dict[str, object],
        attempt: dict[str, object],
        proof: bytes,
        *,
        exact_work: bool = True,
    ) -> bytes:
        workers = attempt["worker_count"]
        workload = next(
            item for item in plan["workloads"] if item["id"] == attempt["workload_id"]
        )
        event = {
            "key": {
                "epoch": 0,
                "stage_rank": 0,
                "component_registry_index": 0,
                "shard_or_chunk_index": 0,
            },
            "stage_id": "composition",
            "component_kind": "opcode",
            "task_class": "leaf",
            "dependencies": [
                {
                    "epoch": 0,
                    "stage_rank": 0,
                    "component_registry_index": 0,
                    "shard_or_chunk_index": 0,
                }
                for _ in range(8)
            ],
            "dependency_count": 0,
            "parallel_eligible": True,
            "contribution_range": {"start": 0, "len": 1},
            "submitted": True,
            "started": True,
            "finished": True,
            "submitted_ns": 2,
            "ready_ns": 1,
            "start_ns": 3,
            "finish_ns": 8,
            "configured_workers": workers,
            "worker_slot": 0,
            "worker_kind": "coordinator",
            "admission_wait_ns": 1,
            "queue_wait_ns": 1,
            "run_ns": 5,
            "resource_wait_ns": 0,
            "bytes": {
                "final_output_bytes": 16,
                "exclusive_scratch_bytes": 32,
                "shared_resident_bytes": 64,
                "device_resident_bytes": 0,
                "worker_stack_bytes": 0,
            },
            "terminal_status": "completed",
            "cleanup_complete": True,
            "work_estimate": 7,
            "planned_rows": 8,
            "planned_tiles": 1,
            "completed_rows": 8,
            "completed_tiles": 1,
        }
        contribution = {
            "component_registry_index": 0,
            "component_kind": "opcode",
            "role": "exclusive",
            "work_estimate": 7,
            "planned_rows": 8,
            "planned_tiles": 1,
            "completed_rows": 8,
            "completed_tiles": 1,
        }
        component = dict(contribution)
        component["task_count"] = 1
        graph = {
            "graph_id": "composition",
            "events": [event],
            "contributions": [contribution],
            "component_work": [component],
            "summary": {
                "requested_workers": workers,
                "admitted_workers": workers,
                "pool_capacity": workers,
                "worker_stack_bytes": 0,
                "peak_active_tasks": 1,
                "peak_active_workers": 1,
                "planned_tasks": 1,
                "submitted_tasks": 1,
                "completed_tasks": 1,
                "failed_tasks": 0,
                "cancelled_tasks": 0,
                "unsubmitted_cancelled_tasks": 0,
                "started_tasks": 1,
                "finished_tasks": 1,
                "duplicate_starts": 0,
                "duplicate_finishes": 0,
                "useful_task_work_ns": 5,
                "critical_path_ns": 5,
                "admission_wait_ns": 1,
                "queue_wait_ns": 1,
                "resource_wait_ns": 0,
                "task_run_ns": 5,
                "worker_busy_ns": 5,
                "worker_capacity_ns": workers * 10,
                "graph_elapsed_ns": 10,
                "parallel_eligible_ns": 5,
                "peak_reserved_bytes": 96,
                "total_work_estimate": 7,
                "completed_rows": 8,
                "completed_tiles": 1,
                "scheduler": "central_queue_no_steal",
                "steal_count": 0,
            },
        }
        verified_attempt = {
            "schema": "riscv_verified_request_attempt_v2",
            "status": "verified",
            "sample_index": 0,
            "timing_partition": (
                "protocol_complete:guest_execution+witness_materialization+proving+"
                "native_verification;proof_serialization_excluded"
            ),
            "protocol_partition_complete": True,
            "witness_materialization_regions": 5,
            "guest_execution_ns": 10,
            "witness_materialization_ns": 20,
            "proving_ns": 30,
            "proving_including_witness_ns": 50,
            "native_verification_ns": 10,
            "verified_request_ns": 70,
            "task_profile": {
                "schema_version": 2,
                "runtime": "ReleaseFast",
                "example": task_profile_example(workload),
                "graphs": [graph],
            },
        }
        if exact_work:
            counters = {
                "field_additions": 10_001,
                "field_multiplications": 8_003,
                "field_inversions": 17,
                "fft_butterflies": 4_096,
                "fri_folds": 2_048,
                "merkle_compressions": 1_023,
            }
            record_count = 19
            source_mask = 0x3F
            producer_counts = [3, 4, 2, 1, 4, 2, 3]
            digest_input = bytearray(
                b"stwo-zig/prover/logical-work-profile/v2\0"
            )
            digest_input.extend(struct.pack("<HBBQ", 2, 2, source_mask, record_count))
            digest_input.extend(struct.pack("<HB", 2, 1))
            for count in producer_counts:
                digest_input.extend(struct.pack("<Q", count))
            for count in producer_counts:
                digest_input.extend(struct.pack("<Q", count))
            for name in (
                "field_additions",
                "field_multiplications",
                "field_inversions",
                "fft_butterflies",
                "fri_folds",
                "merkle_compressions",
            ):
                digest_input.extend(struct.pack("<Q", counters[name]))
            verified_attempt["schema"] = "riscv_verified_request_attempt_v3"
            verified_attempt["work_profile"] = {
                "schema": "stwo.prover.logical-work-profile.v2",
                "schema_version": 2,
                "counter_semantics": (
                    "scalar_lane_completed_algorithm_boundaries_v1"
                ),
                "authority": "instrumented_exact",
                "source_mask": source_mask,
                "record_count": record_count,
                "producer_ledger_schema_version": 2,
                "expected_producer_counts": producer_counts,
                "completed_producer_counts": producer_counts,
                "producer_coverage_terminal_sealed": True,
                **counters,
                "profile_sha256": hashlib.sha256(digest_input).hexdigest(),
            }
        report = {
            "schema": (
                "riscv_profiled_proof_v4"
                if exact_work
                else "riscv_profiled_proof_v3"
            ),
            "release_status": "release_gated",
            "mode": "bench",
            "experimental": False,
            "profiled": True,
            "recursion_enabled": False,
            "warmups": 0,
            "samples": 1,
            "verified_samples": 1,
            "total_steps": 100,
            "n_components": 4,
            "throughput_numerator": "vm_steps",
            "median_seconds": 0.00000007,
            "throughput_mhz": 1.0,
            "mean_execution_seconds": 0.00000001,
            "mean_witness_seconds": 0.00000002,
            "mean_proving_seconds": 0.00000003,
            "mean_verification_seconds": 0.00000001,
            "sample_seconds": [0.00000007],
            "statement_sha256": "4" * 64,
            "transcript_state_blake2s": "5" * 64,
            "implementation_commit": plan["source"]["commit"],
            "implementation_dirty": False,
            "executable_sha256": plan["build"]["executable_sha256"],
            "artifact_sha256": hashlib.sha256(proof).hexdigest(),
            "proof_path": attempt["proof_path"],
            "resources": {
                "availability": "available",
                "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
                "scope": "self_process_lifetime",
                "before_warmups": {
                    "lifetime_max_phys_footprint_bytes": 100,
                    "energy_nj": 10,
                    "instructions": 20,
                    "cycles": 30,
                },
                "after_verified_samples": {
                    "lifetime_max_phys_footprint_bytes": 200,
                    "energy_nj": 14,
                    "instructions": 26,
                    "cycles": 38,
                },
                "interval_delta": {"energy_nj": 4, "instructions": 6, "cycles": 8},
            },
            "timing_authority": {
                "clock": "monotonic",
                "unit": "nanoseconds",
                "partition": "protocol_complete",
                "protocol_partition_complete": True,
                "witness_materialization_regions": 5,
                "authoritative_samples": "verified_request_attempts[*].verified_request_ns",
                "legacy_outer_samples": (
                    "sample_seconds_and_median_seconds_are_non_authoritative_compatibility_fields"
                ),
            },
            "verified_request_attempts": [verified_attempt],
        }
        if plan["lane"]["id"] == "metal-hybrid":
            report["resident_polynomial_telemetry"] = {
                "eligible_base_components": 4,
                "eligible_lookup_components": 2,
                "base_batch_dispatches": 1,
                "lookup_batch_dispatches": 1,
                "declines": 0,
                "verified_samples_with_dispatch": 1,
            }
        return json.dumps(report, separators=(",", ":")).encode("ascii") + b"\n"


class PlanTests(R006Fixture):
    def test_plan_freezes_protocol_worker_arms_and_complete_pairwise_schedule(self) -> None:
        self.assertEqual(self.plan["schema"], "stwo.typed-air.r006-capture-plan.v4")
        self.assertEqual(self.plan["schema_version"], 4)
        self.assertEqual(self.plan["protocol"]["sha256"], PROTOCOL_SHA256)
        closure = self.plan["global_exact_work_closure"]
        self.assertTrue(closure["coverage"]["whole_prover_exact"])
        self.assertEqual(closure["coverage"]["joint"]["complete"], 16)
        self.assertEqual(closure["inventory"]["site_count"], 23)
        self.assertEqual(len(self.plan["attempts"]), PLAN_ATTEMPTS)
        self.assertEqual(self.plan["worker_arms"]["max"], 8)
        first = self.plan["attempts"][0]
        self.assertEqual(first["comparison_id"], "aa-calibration")
        self.assertEqual(first["worker_count"], 1)
        comparisons = {item["comparison_id"] for item in self.plan["attempts"]}
        self.assertEqual(
            comparisons,
            {
                "aa-calibration",
                "two-workers-over-one",
                "four-workers-over-one",
                "max-workers-over-one",
            },
        )

    def test_plan_rejects_partial_global_matrix_before_scheduling(self) -> None:
        partial = self.closure(self.repository)
        partial["coverage"]["metal"] = {
            "complete": 15,
            "partial": 1,
            "absent": 0,
        }
        partial["coverage"]["joint"] = {
            "complete": 15,
            "partial": 1,
            "absent": 0,
        }
        partial["coverage"]["whole_prover_exact"] = False
        with self.assertRaisesRegex(CaptureError, "whole-prover exactness at 16/16"):
            build_plan(
                PlanSettings(
                    repository=self.repository,
                    session_id="fixture-r006-partial",
                    lane="cpu-native",
                    power_state="AC power; fixture",
                    executable=self.executable,
                    workloads=self.workloads,
                    toolchain="zig:fixture",
                    target="aarch64-macos",
                    cpu_features="apple-m2",
                ),
                source_provider=self.source,
                host_provider=self.host,
                closure_provider=lambda _: partial,
                clock=lambda: dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
            )

    def test_plan_replay_rejects_matrix_digest_and_inventory_source_drift(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["global_exact_work_closure"]["matrix"]["sha256"] = "b" * 64
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "changed after planning"):
            validate_plan(
                changed,
                repository=self.repository,
                verify_local=True,
                source_provider=self.source,
                closure_provider=self.closure,
            )

        def drifted_inventory(repository: Path) -> dict[str, object]:
            closure = self.closure(repository)
            closure["inventory"]["source_sha256"] = "c" * 64
            return closure

        with self.assertRaisesRegex(CaptureError, "changed after planning"):
            validate_plan(
                self.plan,
                repository=self.repository,
                verify_local=True,
                source_provider=self.source,
                closure_provider=drifted_inventory,
            )

    def test_attempt_reorder_rejects_even_after_resigning_plan(self) -> None:
        changed = copy.deepcopy(self.plan)
        changed["attempts"][80], changed["attempts"][81] = (
            changed["attempts"][81],
            changed["attempts"][80],
        )
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "frozen schedule"):
            validate_plan(changed, repository=self.repository, verify_local=False)

    def test_generated_input_is_exact_and_local_mutation_rejects(self) -> None:
        raw = materialized_poseidon_input(4096)
        self.assertEqual(len(raw), 262_148)
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "ff798e2438279ac57ab9ea8cb7d5816d4500f628850e00c02c202f2eb32455ca",
        )
        target = self.workloads["poseidon2_dominant"].input
        assert target is not None
        changed = bytearray(target.read_bytes())
        changed[-1] ^= 1
        target.write_bytes(changed)
        with self.assertRaisesRegex(CaptureError, "changed after plan"):
            validate_plan(
                self.plan,
                repository=self.repository,
                verify_local=True,
                source_provider=self.source,
                closure_provider=self.closure,
            )

    def test_linux_host_is_rejected_before_attempts_and_worker_policy_is_frozen(self) -> None:
        self.assertEqual(
            self.plan["worker_environment"],
            {
                "STWO_ZIG_WORKERS": "attempt.worker_count",
                "STWO_ZIG_MERKLE_WORKERS": "attempt.worker_count",
                "STWO_ZIG_POW_WORKERS": "unset:reuse-proof-pool",
            },
        )
        changed = copy.deepcopy(self.plan)
        changed["host"]["os"] = "Linux"
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "Darwin RUSAGE_INFO_V6"):
            validate_plan(changed, repository=self.repository, verify_local=False)

        changed = copy.deepcopy(self.plan)
        changed["worker_environment"]["STWO_ZIG_MERKLE_WORKERS"] = "host-default"
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaisesRegex(CaptureError, "worker-environment"):
            validate_plan(changed, repository=self.repository, verify_local=False)

    def test_metal_protocol_backend_and_cli_token_are_not_conflated(self) -> None:
        metal = build_plan(
            PlanSettings(
                repository=self.repository,
                session_id="fixture-r006-metal",
                lane="metal-hybrid",
                power_state="AC power; fixture",
                executable=self.executable,
                workloads=self.workloads,
                toolchain="zig:fixture",
                target="aarch64-macos",
                cpu_features="apple-m2",
            ),
            source_provider=self.source,
            host_provider=self.host,
            closure_provider=self.closure,
            clock=lambda: dt.datetime(2026, 8, 15, tzinfo=dt.timezone.utc),
        )
        self.assertEqual(metal["lane"]["backend"], "metal-hybrid")
        self.assertEqual(metal["lane"]["cli_backend"], "metal")
        command = proof_command(metal, metal["attempts"][0])
        self.assertEqual(command[command.index("--backend") + 1], "metal")
        self.assertNotIn("--experimental", command)

    def test_executable_marker_gate_accepts_only_complete_versioned_pairs(self) -> None:
        exact = self.scratch / "exact-work-binary"
        exact.write_bytes(
            b"fixture\0riscv_profiled_proof_v4\0"
            b"riscv_verified_request_attempt_v3\0"
            b"stwo.prover.logical-work-profile.v2\0"
        )
        _require_binary_markers(exact)

        legacy = self.scratch / "legacy-work-binary"
        legacy.write_bytes(
            b"fixture\0riscv_profiled_proof_v3\0riscv_verified_request_attempt_v2\0"
        )
        with self.assertRaisesRegex(CaptureError, "exact-work production schema"):
            _require_binary_markers(legacy)

        mixed = self.scratch / "mixed-schema-binary"
        mixed.write_bytes(
            b"fixture\0riscv_profiled_proof_v4\0"
            b"riscv_verified_request_attempt_v2\0"
            b"stwo.prover.logical-work-profile.v2\0"
        )
        with self.assertRaisesRegex(CaptureError, "exact-work production schema"):
            _require_binary_markers(mixed)




class ProfileValidationTests(R006Fixture):
    def setUp(self) -> None:
        super().setUp()
        self.attempt = self.plan["attempts"][80]
        self.proof_payload = b"deterministic-proof"
        self.proof = self.base_artifact(self.proof_payload)
        self.proof_path = self.scratch / self.attempt["proof_path"]
        self.proof_path.parent.mkdir(exist_ok=True)
        self.proof_path.write_bytes(self.proof)
        self.raw = self.report(self.plan, self.attempt, self.proof)

    def test_valid_profile_recomputes_timing_task_and_memory_disclosure(self) -> None:
        identity, metrics = validate_report(
            self.raw,
            plan=self.plan,
            attempt=self.attempt,
            proof_path=self.proof_path,
        )
        self.assertEqual(identity["proof_bytes"], len(self.proof))
        self.assertEqual(
            identity["verifier_proof_sha256"],
            hashlib.sha256(self.proof_payload).hexdigest(),
        )
        self.assertEqual(metrics["verified_request_ns"], 70)
        self.assertEqual(metrics["peak_rss_bytes"], 200)
        self.assertEqual(metrics["task_disclosure"]["queue_wait_ns"], 1)
        self.assertEqual(metrics["task_disclosure"]["peak_reserved_bytes"], 96)

    def mutate(self) -> dict[str, object]:
        return json.loads(self.raw)

    def assert_invalid(self, report: dict[str, object], pattern: str) -> None:
        raw = json.dumps(report, separators=(",", ":")).encode() + b"\n"
        with self.assertRaisesRegex(CaptureError, pattern):
            validate_report(
                raw,
                plan=self.plan,
                attempt=self.attempt,
                proof_path=self.proof_path,
            )

    def test_task_accounting_queue_and_worker_mutations_reject(self) -> None:
        changed = self.mutate()
        summary = changed["verified_request_attempts"][0]["task_profile"]["graphs"][0]["summary"]
        summary["submitted_tasks"] = 2
        self.assert_invalid(changed, "submitted_tasks")

        changed = self.mutate()
        event = changed["verified_request_attempts"][0]["task_profile"]["graphs"][0]["events"][0]
        event["queue_wait_ns"] = 2
        self.assert_invalid(changed, "queue-wait")

        changed = self.mutate()
        summary = changed["verified_request_attempts"][0]["task_profile"]["graphs"][0]["summary"]
        summary["peak_active_workers"] = self.attempt["worker_count"] + 1
        self.assert_invalid(changed, "worker bound")

    def test_contribution_proof_and_timing_mutations_reject(self) -> None:
        changed = self.mutate()
        component = changed["verified_request_attempts"][0]["task_profile"]["graphs"][0]["component_work"][0]
        component["work_estimate"] += 1
        self.assert_invalid(changed, "component-work")

        changed = self.mutate()
        changed["artifact_sha256"] = "0" * 64
        self.assert_invalid(changed, "proof bytes")

        changed = self.mutate()
        changed["verified_request_attempts"][0]["verified_request_ns"] += 1
        self.assert_invalid(changed, "timing partition")

    def test_exact_work_profile_is_complete_digest_bound_and_projected(self) -> None:
        raw = self.report(
            self.plan,
            self.attempt,
            self.proof,
            exact_work=True,
        )
        _, metrics = validate_report(
            raw,
            plan=self.plan,
            attempt=self.attempt,
            proof_path=self.proof_path,
        )
        work = metrics["work_disclosure"]
        self.assertEqual(work["source_mask"], 0x3F)
        self.assertEqual(work["record_count"], 19)
        self.assertEqual(work["producer_ledger_schema_version"], 2)
        self.assertEqual(work["producer_counts"], [3, 4, 2, 1, 4, 2, 3])
        self.assertTrue(work["producer_coverage_terminal_sealed"])
        self.assertEqual(work["fft_butterflies"], 4_096)
        self.assertEqual(work["merkle_compressions"], 1_023)
        self.assertEqual(
            work["profile_sha256"],
            "3d5e3440b801220b82e66699921209f3d2c782535dfab7571062b55cbc553f03",
        )

    def test_exact_work_profile_mutation_fleet_fails_closed(self) -> None:
        raw = self.report(
            self.plan,
            self.attempt,
            self.proof,
            exact_work=True,
        )
        baseline = json.loads(raw)
        mutations = (
            ("authority", "structural_estimate", "authority"),
            ("source_mask", 0x1F, "source_mask"),
            ("record_count", 0, "record count"),
            ("producer_ledger_schema_version", 3, "producer_ledger_schema_version"),
            ("producer_coverage_terminal_sealed", False, "producer_coverage_terminal_sealed"),
            ("fft_butterflies", -1, "fft_butterflies"),
            ("fri_folds", 1 << 64, "fri_folds"),
            ("profile_sha256", "0" * 64, "digest disagrees"),
        )
        for field, value, pattern in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(baseline)
                changed["verified_request_attempts"][0]["work_profile"][field] = value
                self.assert_invalid(changed, pattern)

        changed = copy.deepcopy(baseline)
        changed["verified_request_attempts"][0]["work_profile"][
            "completed_producer_counts"
        ][2] += 1
        self.assert_invalid(changed, "producer ledger is incomplete")

        changed = copy.deepcopy(baseline)
        changed["verified_request_attempts"][0]["work_profile"][
            "expected_producer_counts"
        ].pop()
        self.assert_invalid(changed, "producer ledger shape")

        changed = copy.deepcopy(baseline)
        del changed["verified_request_attempts"][0]["work_profile"]["fri_folds"]
        self.assert_invalid(changed, "logical work profile")

        changed = copy.deepcopy(baseline)
        changed["verified_request_attempts"][0]["work_profile"]["unknown"] = 1
        self.assert_invalid(changed, "logical work profile")

    def test_work_profile_requires_versioned_outer_and_attempt_schemas(self) -> None:
        exact = json.loads(
            self.report(
                self.plan,
                self.attempt,
                self.proof,
                exact_work=True,
            )
        )
        exact["schema"] = "riscv_profiled_proof_v3"
        self.assert_invalid(exact, "requires installed-binary exact-work schema v4")

        legacy = self.mutate()
        legacy["schema"] = "riscv_profiled_proof_v3"
        legacy["verified_request_attempts"][0].pop("work_profile")
        legacy["verified_request_attempts"][0]["schema"] = "riscv_verified_request_attempt_v2"
        self.assert_invalid(legacy, "requires installed-binary exact-work schema v4")




if __name__ == "__main__":
    unittest.main()
