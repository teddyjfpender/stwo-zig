from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from scripts.riscv_csp_benchmark_lib.contract import Case
from scripts.riscv_recursion_csp_benchmark_lib import (
    EvidenceError,
    atomic_write_new,
    build_comparison,
    build_plan,
    build_workload_request,
    canonical_bytes,
    collect_active_outer_probe,
    collect_canonical_outer_report,
    decode_json,
    load_json,
    parse_active_outer_output,
    validate_active_outer_probe,
    validate_canonical_attempt,
    validate_plan,
    validate_recursive_report,
    validate_shape_audit,
)
from scripts.riscv_recursion_csp_benchmark_lib.codec import content_digest, seal_document
from scripts.riscv_recursion_csp_benchmark_lib.contract import (
    GENERATION_PHASES,
    PHASES,
    RECURSIVE_ARTIFACT_CONTRACT,
    RECURSIVE_REPORT_SCHEMA,
    REPORT_CLASSIFICATION,
    SCHEMA_VERSION,
    available_metric,
)
from scripts.riscv_recursion_csp_benchmark import (
    CURRENT_SOURCE_CAPTURE_GUIDANCE,
    _has_source_alignment_failure,
)


PAIR_NODE = """//! It does **not** verify a STARK, build a recursive circuit,
//! or produce a recursive proof.
pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const RECURSIVE_PROOF_VERIFICATION = false;
pub const RECURSIVE_PROOF_PRODUCTION = false;
pub const PRODUCTION_ACTIVATION = false;
pub const AuthenticationPermutationCostV1 = struct {};
"""
AUDIT_FIXTURES = {
    "src/integrations/riscv_cpu/recursive_fri_outer.zig": (
        "//! This is deliberately a verifier-subsystem proof.\n"
        "//! Callers must not label this a complete recursive proof.\n"
        "const OUTER_CONFIG: stwo_core.pcs.PcsConfig = .{\n"
        "    .pow_bits = 0, .fri_config = .{ .n_queries = 3 },\n};\n"
    ),
    "src/integrations/riscv_cpu/universal_recursive_air_proof_test.zig": (
        "//! canonical inactive verifier schedule; it does not yet verify child proof\n"
        "//! bytes or claim a production recursive verifier.\n"
        "const FunctionalConfig: stwo_core.pcs.PcsConfig = .{\n"
        "    .pow_bits = 0, .fri_config = .{ .n_queries = 3 },\n};\n"
    ),
    "src/integrations/riscv_cpu/mod.zig": (
        'pub const recursive_fri_outer = @import("recursive_fri_outer.zig");\n'
    ),
    "src/integrations/riscv_cpu/build.zig": (
        'const root = .{ .root_source_file = '
        'b.path("universal_recursive_air_proof_test.zig") };\n'
        'const step = "test-recursion-full-air-proof";\n'
    ),
}


def _active_outer_output(workers: int = 4) -> bytes:
    return (
        "1/1 recursion test...OK\n"
        "  active FRI outer stage: capture=ok\n"
        "  A1_REAL mode=regression blowup_log=1 expansion=2 queries=70 security=100 "
        "column_log=20 proof_estimate=100 postcard=90 fixed_wire=80 sampled=10 "
        "prove_ns=10000000 serialize_ns=1000000 ingress_ns=1000000 "
        "decode_ns=1000000 verify_ns=5000000 total_ns=20000000 counters=true "
        "peak_bytes=123 cpu_ns=456 energy_nj=0 instructions=0 cycles=0\n"
        "  active FRI outer proof: "
        "logs(vm-input/composition-control/bits/map/root/trace/pcs/leaf/node/anchor/"
        "control/input/mul/inv/linear/path/poseidon)="
        "4/4/4/4/4/4/4/4/4/4/4/4/4/4/4/4/4 "
        "columns=10+20+30 constraints=40 proof_estimate=500 "
        "prove_ns=100000000 assembly_ns=30000000 stark_prove_ns=60000000 "
        f"verify_ns=20000000 poseidon_calls=99 workers={workers} draws=10 "
        "mutations=5/5\n"
        "    universal roster=36/36 active_verifier=34 active_provider=2\n"
        "All 1 tests passed.\n"
    ).encode()


def _initialize_probe_repository(root: Path) -> None:
    for relative in (
        "src/tests/riscv/recursion_poseidon_leaf_test.zig",
        "src/integrations/riscv_cpu/recursive_fri_outer.zig",
        "build_support/products/riscv_cpu.zig",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text(f"// fixture: {relative}\n", encoding="utf-8")
    commands = (
        ("git", "init", "-q"),
        ("git", "config", "user.email", "benchmark@example.invalid"),
        ("git", "config", "user.name", "Benchmark Fixture"),
        ("git", "add", "."),
        ("git", "commit", "-qm", "fixture"),
    )
    for command in commands:
        subprocess.run(command, cwd=root, check=True)


def _native_report() -> dict[str, object]:
    pcs = {
        "fri_config": {
            "fold_step": 1,
            "log_blowup_factor": 1,
            "log_last_layer_degree_bound": 0,
            "n_queries": 70,
        },
        "lifting_log_size": None,
        "pow_bits": 26,
    }
    proof_sha = "11" * 32
    return {
        "schema": "stwo_riscv_csp_benchmark_v4",
        "captured_at": "2026-08-14T12:00:00+04:00",
        "measurement_commit": "1" * 40,
        "repository_head": "1" * 40,
        "suite_manifest_sha256": "2" * 64,
        "result_class": "power-condition-non-publishable",
        "identities": {
            "prover_executable_sha256": "a" * 64,
            "trace_executable_sha256": "b" * 64,
            "zig_version": "0.15.2",
            "prover_build_identity": {
                "optimize": "ReleaseFast",
                "arch": "aarch64",
                "os": "macos",
            },
        },
        "host": {"os": "Darwin", "cpu": "test", "logical_cpu_count": 1},
        "run": {
            "backend": "cpu",
            "samples": 3,
            "warmups": 1,
            "complete_matrix": False,
            "recursion_enabled": False,
            "recursion_environment_prefix": "STWO_RECURSION_",
            "removed_recursion_environment_variables": [],
        },
        "security": {"profile": "secure", "pcs_config": pcs},
        "methodology": {
            "proof_duration": "mean execution + witness + proof generation",
            "verify_duration": "mean production verification",
            "proof_size": "Postcard proof bytes, excluding schema-v4 JSON framing",
            "num_constraints": "0 means not exposed; cycles are authoritative",
            "proof_scope": "native RISC-V leaf STARK; recursion and outer proving disabled",
        },
        "summary": {"all_recursion_disabled": True},
        "measurements": [
            {
                "system": "stwo-zig-riscv",
                "backend": "cpu",
                "recursion_enabled": False,
                "target": "sha256",
                "input_size": 128,
                "proof_duration": 6_000_000,
                "verify_duration": 4_000_000,
                "proof_size": 1_000,
                "peak_memory": 2_000,
                "cycles": 99,
                "num_constraints": 0,
                "protocol": {"name": "secure", "pcs_config": pcs},
                "memory": {
                    "scope": "self-process lifetime peak across verified samples",
                    "includes_mandatory_self_verification": True,
                    "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
                },
                "timing": {
                    "source": "production CLI internal stage timers",
                    "proof_definition": "execution + witness + proof generation",
                    "verify_definition": "production proof verification",
                    "mean_execution_seconds": Decimal("0.001"),
                    "mean_witness_seconds": Decimal("0.002"),
                    "mean_proving_seconds": Decimal("0.003"),
                    "mean_verification_seconds": Decimal("0.004"),
                    "verified_end_to_end_sample_seconds": [
                        Decimal("0.010"),
                        Decimal("0.011"),
                        Decimal("0.012"),
                    ],
                },
                "evidence": {
                    "status": "verified",
                    "input_sha256": "3" * 64,
                    "guest_sha256": "4" * 64,
                    "output_digest": "5" * 64,
                    "expected_output_digest": "5" * 64,
                    "public_values_sha256": "c" * 64,
                    "statement_sha256": "d" * 64,
                    "proof_sha256": proof_sha,
                    "artifact_sha256": "e" * 64,
                    "artifact_bytes": 2_500,
                    "retained_verify_receipt": {
                        "schema": "riscv_verify_v1",
                        "status": "verified",
                        "artifact_kind": "stwo_riscv_proof",
                        "artifact_schema_version": 4,
                        "executable_sha256": "a" * 64,
                        "proof_bytes": 1_000,
                        "proof_sha256": proof_sha,
                        "statement_sha256": "d" * 64,
                        "implementation_commit": "1" * 40,
                        "implementation_dirty": False,
                    },
                },
            }
        ],
    }


def _native_raw(report: dict[str, object] | None = None) -> bytes:
    # The source hash binds raw producer bytes. Decimal values are represented
    # exactly as JSON decimals when this unit fixture is serialized.
    quoted = json.dumps(report or _native_report(), default=str, sort_keys=True).encode()
    return re.sub(rb'"([0-9]+\.[0-9]+)"', rb"\1", quoted)


def _write_boundary(root: Path, text: str = PAIR_NODE) -> Path:
    path = root / "src/frontends/riscv/recursion/pair_node.zig"
    path.parent.mkdir(parents=True)
    path.write_text(text, encoding="utf-8")
    for relative, contents in AUDIT_FIXTURES.items():
        fixture = root / relative
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(contents, encoding="utf-8")
    return path


def _plan(root: Path) -> dict[str, object]:
    _write_boundary(root)
    report = _native_report()
    return build_plan(
        report,
        native_raw=_native_raw(report),
        repo_root=root,
    )


def _recursive_report(plan: dict[str, object]) -> dict[str, object]:
    invocation = {
        "argv": [
            "zig-out/bin/stwo-zig-riscv-recursive-csp",
            "--plan-digest",
            plan["canonical_digest"],
        ],
        "working_directory": ".",
        "environment": {"ZIG_GLOBAL_CACHE_DIR": ".zig-cache"},
    }
    artifact = {
        **RECURSIVE_ARTIFACT_CONTRACT,
        "payload_sha256": "6" * 64,
        "payload_bytes": 500,
        "artifact_sha256": "6" * 64,
        "artifact_bytes": 500,
    }
    samples = []
    for native in plan["native_samples"]:
        phases = {}
        for ordinal, phase in enumerate(PHASES, start=1):
            phases[phase] = {
                "duration_ns": available_metric(
                    ordinal * 1_000_000,
                    "ns",
                    "producer_internal_monotonic_timer",
                    "recursive benchmark child",
                ),
                "poseidon2_permutations": available_metric(
                    ordinal,
                    "permutations",
                    "instrumented_exact_counter",
                    "phase-scoped Poseidon2 counter",
                ),
            }
        generation_ns = sum(phases[name]["duration_ns"]["value"] for name in GENERATION_PHASES)
        generation_calls = sum(
            phases[name]["poseidon2_permutations"]["value"] for name in GENERATION_PHASES
        )
        aggregates = {
            "verified_end_to_end_ns": available_metric(
                37_000_000,
                "ns",
                "producer_internal_monotonic_timer",
                "recursive benchmark child",
            ),
            "published_proof_generation_ns": available_metric(
                generation_ns,
                "ns",
                "producer_internal_monotonic_timer",
                "recursive benchmark child",
            ),
            "published_proof_verification_ns": available_metric(
                phases["recursive_verify"]["duration_ns"]["value"],
                "ns",
                "producer_internal_monotonic_timer",
                "recursive benchmark child",
            ),
            "published_proof_bytes": available_metric(
                500,
                "bytes",
                "canonical_artifact_length",
                "recursive proof wire",
            ),
            "peak_rss_bytes": available_metric(
                1_000,
                "bytes",
                "os_process_lifetime_peak",
                "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
            ),
            "proof_generation_poseidon2_permutations": available_metric(
                generation_calls,
                "permutations",
                "instrumented_exact_counter",
                "phase-scoped Poseidon2 counter",
            ),
            "proof_verification_poseidon2_permutations": available_metric(
                phases["recursive_verify"]["poseidon2_permutations"]["value"],
                "permutations",
                "instrumented_exact_counter",
                "phase-scoped Poseidon2 counter",
            ),
        }
        samples.append(
            {
                "workload_id": native["workload_id"],
                "workload": dict(native["workload"]),
                "status": "verified",
                "artifact": dict(artifact),
                "attempts": [
                    {
                        "ordinal": ordinal,
                        "classification": (
                            "excluded_warmup" if ordinal == 0 else "measured"
                        ),
                        "status": "verified",
                        "workload_id": native["workload_id"],
                        "artifact": dict(artifact),
                        "verification_receipt": {
                            "schema": "riscv_recursive_verify_v1",
                            "status": "verified",
                            "workload_id": native["workload_id"],
                            "artifact_sha256": artifact["artifact_sha256"],
                            "payload_sha256": artifact["payload_sha256"],
                            "implementation_commit": "7" * 40,
                            "executable_sha256": "9" * 64,
                        },
                        "verified_end_to_end_ns": 37_000_000,
                        "phases": {
                            phase: {
                                metric: dict(value)
                                for metric, value in phase_metrics.items()
                            }
                            for phase, phase_metrics in phases.items()
                        },
                    }
                    for ordinal in range(4)
                ],
                "phases": phases,
                "aggregates": aggregates,
            }
        )
    return seal_document(
        {
            "schema": RECURSIVE_REPORT_SCHEMA,
            "schema_version": SCHEMA_VERSION,
            "classification": REPORT_CLASSIFICATION,
            "plan_digest": plan["canonical_digest"],
            "cohort_id": plan["cohort_id"],
            "host_identity_sha256": plan["host_identity_sha256"],
            "host": plan["native_host"],
            "producer": {
                "implementation_commit": "7" * 40,
                "implementation_tree": "8" * 40,
                "implementation_dirty": False,
                "executable_sha256": "9" * 64,
                "backend": "cpu",
                "optimization_mode": "ReleaseFast",
                "warmups": 1,
                "measured_samples": 3,
                "serial_execution": True,
                "automatic_retries": 0,
                "outlier_drops": 0,
                "timing_statistic": "arithmetic_mean_of_verified_samples_rounded_ns",
                "timer_source": "producer_internal_monotonic_timer",
                "poseidon_counter_scope": "phase_scoped_instrumented_exact_counter",
                "compiler_version": "0.15.2",
                "target_triple": "aarch64-macos-none",
                "rss_scope": (
                    "self_process_lifetime_peak_across_warmups_and_verified_samples_"
                    "including_verification"
                ),
                "attempt_isolation": (
                    "fresh_process_per_workload_serial_attempts_same_process"
                ),
                "invocation": invocation,
                "invocation_sha256": content_digest(invocation),
                "artifact_contract": dict(RECURSIVE_ARTIFACT_CONTRACT),
                "captured_at": "2026-08-14T13:00:00+04:00",
            },
            "security": plan["native_security"],
            "boundary": {
                "base_proof_produced": True,
                "base_proof_verified": True,
                "recursive_proof_produced": True,
                "recursive_proof_verified": True,
                "full_pipeline": True,
            },
            "samples": samples,
            "limitations": ["engineering diagnostic only"],
        }
    )


class RecursionCspBenchmarkTests(unittest.TestCase):
    def test_canonical_shape_audit_pins_exact_sixteen_case_matrix(self) -> None:
        root = Path(__file__).resolve().parents[2]
        audit, _ = load_json(
            root / "vectors/riscv_csp/recursion-shape-audit-v2.json"
        )
        validate_shape_audit(audit, repo_root=root)
        self.assertEqual(
            audit["coverage"],
            {
                "case_count": 16,
                "admissible_count": 0,
                "incompatible_count": 16,
                "all_canonical_cases_admissible": False,
                "fixed_profile_admissible_count": 0,
                "fixed_profile_incompatible_count": 16,
                "profile_registry_matched_count": 16,
                "profile_registry_unknown_count": 0,
                "outer_executable_count": 0,
                "outer_unavailable_count": 16,
                "all_canonical_cases_registry_matched": True,
                "all_canonical_cases_outer_executable": False,
            },
        )
        self.assertEqual(len(audit["profile_matrix"]), 9)
        self.assertEqual(
            [row["observed_canonical_case_count"] for row in audit["profile_matrix"]],
            [8, 1, 1, 1, 1, 1, 1, 1, 1],
        )
        self.assertTrue(audit["coverage"]["all_canonical_cases_registry_matched"])
        matrix = [
            (
                row["target"],
                row["input_size"],
                row["facts"]["component_count"],
                row["facts"]["preprocessed_column_count"],
                row["facts"]["main_column_count"],
                row["facts"]["interaction_column_count"],
                row["facts"]["maximum_column_log_degree"],
            )
            for row in audit["cases"]
        ]
        self.assertEqual(
            matrix,
            [
                ("sha256", 128, 12, 54, 916, 444, 20),
                ("sha256", 256, 12, 54, 916, 444, 20),
                ("sha256", 512, 12, 54, 916, 444, 20),
                ("sha256", 1024, 12, 54, 916, 444, 20),
                ("sha256", 2048, 13, 56, 951, 480, 20),
                ("keccak", 128, 12, 54, 916, 444, 20),
                ("keccak", 256, 12, 54, 916, 444, 20),
                ("keccak", 512, 12, 54, 916, 444, 20),
                ("keccak", 1024, 12, 54, 916, 444, 20),
                ("keccak", 2048, 14, 58, 999, 512, 20),
                ("poseidon2_m31", 2, 13, 56, 953, 468, 20),
                ("poseidon2_m31", 4, 14, 58, 988, 504, 20),
                ("poseidon2_m31", 8, 15, 60, 1023, 540, 20),
                ("poseidon2_m31", 12, 18, 66, 1144, 644, 20),
                ("poseidon2_m31", 16, 21, 72, 1271, 740, 20),
                ("ecdsa_secp256k1", 32, 94, 218, 4444, 3624, 20),
            ],
        )

        forged = json.loads(json.dumps(audit))
        del forged["canonical_digest"]
        forged["cases"][0]["facts"]["fixed_profile_admissible"] = True
        forged["cases"][0]["facts"]["admission"] = "admitted"
        forged["cases"][0]["status"] = "admissible"
        forged["coverage"]["admissible_count"] = 1
        forged["coverage"]["incompatible_count"] = 15
        forged = seal_document(forged)
        with self.assertRaisesRegex(EvidenceError, "contradicts exact geometry"):
            validate_shape_audit(forged)

    def test_plan_without_shape_audit_is_explicitly_zero_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
        coverage = plan["recursive_shape_coverage"]
        self.assertEqual(coverage["audit_status"], "unavailable")
        self.assertEqual(coverage["admissible_count"], 0)
        self.assertFalse(coverage["all_planned_workloads_admissible"])
        self.assertEqual(coverage["cases"][0]["status"], "unaudited")

    def test_shape_audit_rejects_profile_and_registry_relabeling(self) -> None:
        root = Path(__file__).resolve().parents[2]
        audit, _ = load_json(
            root / "vectors/riscv_csp/recursion-shape-audit-v2.json"
        )

        relabeled = json.loads(json.dumps(audit))
        del relabeled["canonical_digest"]
        relabeled["cases"][0]["selected_profile"]["profile_id"] = "sha256_2048"
        relabeled["cases"][0]["selected_profile"]["profile_shape_sha256"] = (
            relabeled["profile_matrix"][1]["profile_shape_sha256"]
        )
        relabeled["cases"][0]["selected_profile"]["canonical_case_count"] = 1
        relabeled = seal_document(relabeled)
        with self.assertRaisesRegex(EvidenceError, "exact statement facts"):
            validate_shape_audit(relabeled)

        stale_registry = json.loads(json.dumps(audit))
        del stale_registry["canonical_digest"]
        stale_registry["profile_registry"]["registry_sha256"] = "00" * 32
        stale_registry = seal_document(stale_registry)
        with self.assertRaisesRegex(EvidenceError, "registry seal drifted"):
            validate_shape_audit(stale_registry)

    def test_canonical_collector_refuses_incompatible_shape_before_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            artifacts = root / "must-not-exist"
            with self.assertRaisesRegex(EvidenceError, "0/1 planned workloads"):
                collect_canonical_outer_report(
                    plan,
                    repo_root=root,
                    producer=root / "missing-producer",
                    artifact_directory=artifacts,
                    worker_count=8,
                    timeout_seconds=1,
                )
            self.assertFalse(artifacts.exists())

    def test_source_alignment_failure_prints_exact_recapture_prerequisite(self) -> None:
        report = {
            "samples": [
                {
                    "attempts": [
                        {
                            "record": {
                                "failure": {
                                    "stage": "source_admission",
                                    "error_name": "NativeMeasurementCommitMismatch",
                                }
                            }
                        }
                    ]
                }
            ]
        }
        self.assertTrue(_has_source_alignment_failure(report))
        self.assertIn("git status --porcelain=v1", CURRENT_SOURCE_CAPTURE_GUIDANCE)
        self.assertIn("riscv_csp_benchmark.py --backend cpu", CURRENT_SOURCE_CAPTURE_GUIDANCE)

    def test_canonical_child_request_binds_manifest_and_plan_row(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guest = root / "vectors/riscv_csp/guests/sha256.elf"
            input_path = root / "vectors/riscv_csp/inputs/msg_128.bin"
            guest.parent.mkdir(parents=True)
            input_path.parent.mkdir(parents=True)
            guest.write_bytes(b"guest")
            input_path.write_bytes(b"input")
            guest_sha = __import__("hashlib").sha256(b"guest").hexdigest()
            input_sha = __import__("hashlib").sha256(b"input").hexdigest()
            output_digest = "ab" * 32
            case = Case(
                target="sha256",
                input_size=128,
                input_path=input_path,
                input_sha256=input_sha,
                expected_digest=output_digest,
                expected_cycles=99,
                guest_path=guest,
                guest_sha256=guest_sha,
                guest_bytes=5,
                uses_precompile=False,
            )
            workload = {
                "target": "sha256",
                "input_size": 128,
                "input_sha256": input_sha,
                "guest_sha256": guest_sha,
                "expected_output_digest": output_digest,
                "public_values_sha256": "cd" * 32,
                "statement_sha256": "ef" * 32,
            }
            workload_id = content_digest(workload)
            request = build_workload_request(
                {
                    "canonical_digest": "12" * 32,
                    "native_source": {"measurement_commit": "1" * 40},
                    "recursive_shape_coverage": {
                        "profile_registry": {
                            "registry_sha256": (
                                "eea4c311bbc25150b8166f89e4c80c5b"
                                "b67a9938b8497fefe0d72c75d701beef"
                            )
                        },
                        "cases": [
                            {
                                "workload_id": workload_id,
                                "selected_profile": {
                                    "profile_id": "hash_compact",
                                    "profile_shape_sha256": (
                                        "048c89b15bba53ad0e6b5c3bf6dda9ed"
                                        "89a5cb7c3429910ff9024a91a259df85"
                                    ),
                                },
                            }
                        ],
                    },
                },
                {
                    "workload_id": workload_id,
                    "workload": workload,
                    "evidence": {"cycles": 99},
                },
                case,
                repo_root=root,
                worker_count=4,
            )
        self.assertEqual(request["schema"], "stwo.riscv.recursion-csp-workload.v3")
        self.assertEqual(request["schema_version"], 3)
        self.assertEqual(request["native_measurement_commit"], "1" * 40)
        self.assertEqual(request["workload_id"], workload_id)
        self.assertEqual(request["guest_path"], "vectors/riscv_csp/guests/sha256.elf")
        self.assertEqual(request["worker_count"], 4)
        self.assertEqual(request["expected_recursive_profile_id"], "hash_compact")

    def test_canonical_child_failure_never_substitutes_metrics(self) -> None:
        request = {
            "plan_digest": "12" * 32,
            "workload_id": "34" * 32,
        }
        request_raw = canonical_bytes(request)
        failure = {
            "schema": "stwo.riscv.recursion-csp-attempt.v3",
            "schema_version": 3,
            "status": "failed",
            "classification": "failed_recursive_csp_attempt_not_performance_evidence",
            "comparison_eligible": False,
            "request": {
                "path": "request.json",
                "request_sha256": __import__("hashlib").sha256(request_raw).hexdigest(),
                "plan_digest": request["plan_digest"],
                "workload_id": request["workload_id"],
            },
            "requested_artifact_path": "artifact.bin",
            "failure": {"stage": "base_verify", "error_name": "InvalidProof"},
        }
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary) / "artifact.bin"
            validate_canonical_attempt(
                failure,
                request=request,
                request_raw=request_raw,
                artifact_path=artifact,
                producer_sha256="56" * 32,
            )
            artifact.write_bytes(b"untrusted")
            with self.assertRaisesRegex(EvidenceError, "contradictory"):
                validate_canonical_attempt(
                    failure,
                    request=request,
                    request_raw=request_raw,
                    artifact_path=artifact,
                    producer_sha256="56" * 32,
                )

    def test_plan_maps_only_measured_native_values(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            validate_plan(plan, repo_root=root)
        sample = plan["native_samples"][0]
        self.assertEqual(sample["aggregates"]["published_proof_generation_ns"]["value"], 6_000_000)
        self.assertEqual(sample["aggregates"]["published_proof_bytes"]["value"], 1_000)
        self.assertEqual(sample["aggregates"]["peak_rss_bytes"]["value"], 2_000)
        self.assertEqual(sample["sampling"]["warmups_excluded"], 1)
        self.assertEqual(sample["sampling"]["measured_samples"], 3)
        self.assertEqual(len(sample["sampling"]["verified_end_to_end_sample_ns"]), 3)
        self.assertEqual(sample["artifact"]["artifact_schema_version"], 4)
        self.assertEqual(
            plan["native_source"]["reproducibility"]["prover_build_identity"][
                "optimize"
            ],
            "ReleaseFast",
        )
        self.assertEqual(
            sample["aggregates"]["proof_generation_poseidon2_permutations"]["status"],
            "unavailable",
        )
        self.assertIn(
            "num_constraints",
            sample["phases"]["base_prove"]["poseidon2_permutations"]["reason"],
        )
        self.assertFalse(
            plan["recursive_source_boundary"][
                "end_to_end_recursive_proof_evidence_available"
            ]
        )
        self.assertEqual(
            len(plan["recursive_source_boundary"]["source_evidence"]),
            5,
        )

    def test_boundary_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_boundary(
                root,
                PAIR_NODE.replace(
                    "RECURSIVE_PROOF_PRODUCTION = false",
                    "RECURSIVE_PROOF_PRODUCTION = true",
                ),
            )
            with self.assertRaisesRegex(EvidenceError, "PRODUCTION"):
                build_plan(_native_report(), native_raw=_native_raw(), repo_root=root)

    def test_native_object_must_match_hashed_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_boundary(root)
            report = _native_report()
            raw = _native_raw(report)
            report["result_class"] = "mutated-after-read"
            with self.assertRaisesRegex(EvidenceError, "hashed source bytes"):
                build_plan(report, native_raw=raw, repo_root=root)

    def test_superseded_native_schema_cannot_enter_recursive_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_boundary(root)
            report = _native_report()
            report["schema"] = "stwo_riscv_csp_benchmark_v2"
            report["identities"].pop("prover_build_identity")
            report["measurements"][0]["peak_memory"] = None
            with self.assertRaisesRegex(EvidenceError, "unsupported native CSP schema"):
                build_plan(
                    report,
                    native_raw=_native_raw(report),
                    repo_root=root,
                )

    def test_plan_recheck_rejects_stale_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan = _plan(root)
            path = (
                root
                / plan["recursive_source_boundary"]["source_evidence"][0][
                    "source_path"
                ]
            )
            path.write_text(PAIR_NODE + "// drift\n", encoding="utf-8")
            with self.assertRaisesRegex(EvidenceError, "stale"):
                validate_plan(plan, repo_root=root)

    def test_strict_json_rejects_duplicate_and_non_finite_values(self) -> None:
        with self.assertRaisesRegex(EvidenceError, "duplicate"):
            decode_json(b'{"schema":1,"schema":2}', label="test")
        with self.assertRaisesRegex(EvidenceError, "non-standard"):
            decode_json(b'{"value":NaN}', label="test")



if __name__ == "__main__":
    unittest.main()
