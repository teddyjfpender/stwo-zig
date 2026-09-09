from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "autoresearch/benchmarks"
import sys
if str(BENCHMARK) not in sys.path:
    sys.path.insert(0, str(BENCHMARK))

import ethereum_block_optimization_evidence as evidence  # noqa: E402
import ethereum_block_incremental_cost_evidence as incremental  # noqa: E402
import ethereum_block_optimization_protocol as subject  # noqa: E402
import ethereum_block_optimization_runner as runner  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def zig_seal(value: dict) -> dict:
    unsigned = json.dumps(value, ensure_ascii=True, allow_nan=False,
                          separators=(",", ":")).encode("ascii")
    return {
        "content_sha256": hashlib.sha256(unsigned + b"\n").hexdigest(),
        **value,
    }


def zig_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("ascii")


class EthereumBlockOptimizationLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.staging = self.root / "staging"
        self.binary = self.root / "candidate-bin"
        self.binary.write_bytes(b"candidate")
        self.peer_receipt = self.root / "zisk-receipt.json"
        self.peer_receipt.write_bytes(b"peer\n")
        self.peer = {
            "kind": "zisk-vadcop-final-proof-evidence-v1",
            "receipt": {
                "path": str(self.peer_receipt),
                "bytes": len(b"peer\n"),
                "sha256": hashlib.sha256(b"peer\n").hexdigest(),
            },
            "projection": {
                "fixture_id": "mainnet-24628607-representative-medium",
            },
        }
        self.input_evidence_path = self.root / "input-evidence.json"
        self.input_evidence_path.write_bytes(b"diagnostic evidence\n")
        fixture = subject.corpus_protocol.load()["fixtures"][0]
        transports = fixture["semantic_io"]["guest_transports"]
        self.input_evidence = {
            "status": "diagnostic-inputs-replayed-nonpromotable",
            "content_sha256": digest("input-evidence"),
            "corpus_workload": {
                "fixture": {
                    "fixture_id": fixture["fixture_id"],
                    "stwo_input": transports["stwo_input"],
                    "stwo_output": transports["stwo_output"],
                },
                "segment_count": 210,
                "total_cycles": 880_760_229,
            },
            "zisk_peer": self.peer,
            "optimization_boundary": {
                "production_promotion_eligible": False,
            },
        }
        self.candidate = {
            "source": {"commit": "a" * 40, "tree": "b" * 40, "clean": True},
            "binary": {
                "path": str(self.binary),
                "bytes": len(b"candidate"),
                "sha256": hashlib.sha256(b"candidate").hexdigest(),
            },
            "configuration": {
                "scope": "global-corpus-policy",
                "optimization_family": "bounded-provider-sharding",
                "engine_profile": "ethereum-recursive-poseidon-v1",
                "backend": "cpu",
                "worker_envelope": {
                    "processes": 1, "threads": 18, "accelerator_workers": 0,
                },
                "memory_budget_bytes": 48 * 1024**3,
                "trial_timeout_seconds": 120,
                "feature_flags": ["degree6", "provider-shards"],
            },
        }
        self.peer_patch = mock.patch.object(
            subject.zisk_evidence, "evidence", return_value=self.peer,
        )
        self.peer_patch.start()
        self.input_patch = mock.patch.object(
            subject.input_evidence, "load", return_value=self.input_evidence,
        )
        self.input_patch.start()
        self.plan = subject.build_plan(
            corpus_path=subject.corpus_protocol.DEFAULT_CORPUS,
            zisk_receipt=self.peer_receipt,
            trial_class="diagnostic",
            candidate=self.candidate,
            baseline_result=None,
            security_target_bits=120,
            input_evidence_path=self.input_evidence_path,
        )
        self.plan_path = self.root / "plan.json"
        self.plan_path.write_bytes(protocol.canonical_bytes(self.plan))

    def tearDown(self) -> None:
        self.input_patch.stop()
        self.peer_patch.stop()
        self.temporary.cleanup()

    def _observation(self, task: dict, *, attempts: int = 1,
                     indeterminate: int = 0) -> tuple[Path, dict]:
        result_path = self.root / f"source-{attempts}.json"
        result_path.write_bytes(protocol.canonical_bytes({
            "schema": "test.optimization-adapter-result.v1",
            "task_id": task["task_id"],
        }))
        fixture = self.plan["corpus"]["fixtures"][task["fixture_index"]]
        host_policy = self.plan["host_policy"]
        value = protocol.seal({
            "schema": subject.OBSERVATION_SCHEMA,
            "plan_sha256": self.plan["content_sha256"],
            "task": task,
            "adapter": {
                "kind": "test-only-combined-result-adapter-v1",
                "production_admitted": False,
                "validator_identity": digest("validator"),
            },
            "subject_identity": self.plan["candidate"]["binary"]["sha256"],
            "source_result": {
                "path": str(result_path),
                "bytes": result_path.stat().st_size,
                "sha256": hashlib.sha256(result_path.read_bytes()).hexdigest(),
            },
            "correctness": {
                "semantic_input_sha256": fixture["semantic_input"]["sha256"],
                "semantic_output_sha256": fixture["semantic_output"]["sha256"],
                "execution_complete": True,
                "output_matched": True,
                "proof_scope": "final_root",
                "proof_complete": True,
                "fresh_verification": True,
                "security_target_bits": 120,
                "passed": True,
            },
            "measurements": {
                "eligible": False,
                "stage_timings": {name: None for name in subject.STAGE_NAMES},
                "end_to_end": None,
                "peak_rss_bytes": None,
            },
            "host": {
                "machine_model": host_policy["machine_model"],
                "cpu_model": host_policy["cpu"],
                "memory_bytes": host_policy["memory_bytes"],
                "operating_system": host_policy["operating_system"],
                "power_source": "AC Power",
                "thermal_warning": False,
                "interference_observed": False,
                "matched": True,
            },
            "attempt_custody": {
                "attempt_count": attempts,
                "failed_count": 0,
                "indeterminate_count": indeterminate,
            },
        })
        path = self.root / f"observation-{attempts}.json"
        path.write_bytes(protocol.canonical_bytes(value))
        return path, value

    def test_plan_is_global_resumable_and_current_corpus_is_nonpromotable(self) -> None:
        subject.validate_plan(self.plan)
        self.assertEqual(5, self.plan["corpus"]["fixture_count"])
        self.assertEqual(1, self.plan["corpus"]["materialized_fixture_count"])
        self.assertEqual(1, len(self.plan["tasks"]))
        self.assertEqual(120, self.plan["measurement_policy"][
            "per_trial_timeout_seconds"
        ])
        self.assertEqual("none", self.plan["peer_context"]["timing_role"])
        self.assertEqual(210, self.plan["diagnostic_inputs"]["segment_count"])
        self.assertEqual("diagnostic-context-only",
                         self.plan["diagnostic_inputs"]["ranking_role"])
        self.assertFalse(self.plan["diagnostic_inputs"][
            "production_promotion_eligible"
        ])
        self.assertEqual([], self.plan["diagnostic_rankings"])
        self.assertFalse(self.plan["baseline"]["production_admitted"])
        with self.assertRaisesRegex(subject.OptimizationProtocolError,
                                    "promotion trial lacks"):
            subject.build_plan(
                corpus_path=subject.corpus_protocol.DEFAULT_CORPUS,
                zisk_receipt=self.peer_receipt,
                trial_class="promotion", candidate=self.candidate,
                baseline_result=None, security_target_bits=120,
                input_evidence_path=self.input_evidence_path,
            )

    def test_fixture_specific_or_over_cap_configuration_rejects(self) -> None:
        mutations = (
            lambda value: value["configuration"]["feature_flags"].append(
                "mainnet-24628113-keccak-candidate"
            ),
            lambda value: value["configuration"].__setitem__(
                "trial_timeout_seconds", 121,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = copy.deepcopy(self.candidate)
                mutation(candidate)
                candidate["configuration"]["feature_flags"].sort()
                with self.assertRaises(subject.OptimizationProtocolError):
                    subject.build_plan(
                        corpus_path=subject.corpus_protocol.DEFAULT_CORPUS,
                        zisk_receipt=self.peer_receipt,
                        trial_class="diagnostic", candidate=candidate,
                        baseline_result=None, security_target_bits=120,
                        input_evidence_path=self.input_evidence_path,
                    )

    def test_crash_after_intent_retains_attempt_and_resumes_without_rerun(self) -> None:
        run_root = self.root / "run"
        runner.initialize(self.plan_path, run_root, self.staging)
        first = runner.begin_next(run_root)
        self.assertEqual(0, first["attempt_index"])
        resumed = runner.begin_next(run_root)
        self.assertEqual(1, resumed["attempt_index"])
        self.assertTrue((run_root / "tasks" / first["task"]["task_id"]
                         / "attempt-000" / "indeterminate.json").is_file())
        observation_path, _ = self._observation(
            resumed["task"], attempts=2, indeterminate=1,
        )
        runner.admit(run_root, observation_path)
        self.assertIsNone(runner.begin_next(run_root))
        result = runner.finalize(run_root, run_root / "result.json")
        self.assertTrue(result["correctness_passed"])
        self.assertFalse(result["measurement_complete"])
        self.assertFalse(result["promotion"]["eligible"])
        self.assertIn("trial-class-is-nonpromotable", result["promotion"]["blockers"])
        self.assertIn("five-fixture-authority-incomplete",
                      result["promotion"]["blockers"])
        subject.validate_result(result, self.plan)

    def test_metrics_cannot_precede_production_adapter_and_correctness(self) -> None:
        task = self.plan["tasks"][0]
        _, value = self._observation(task)
        value["measurements"] = {
            "eligible": True,
            "stage_timings": {
                name: {"wall_ns": 1, "user_ns": 1, "system_ns": 0}
                for name in subject.STAGE_NAMES
            },
            "end_to_end": {"wall_ns": len(subject.STAGE_NAMES),
                            "user_ns": len(subject.STAGE_NAMES), "system_ns": 0},
            "peak_rss_bytes": 10,
        }
        value["content_sha256"] = protocol.content_sha256(value)
        with self.assertRaisesRegex(subject.OptimizationProtocolError,
                                    "measurement eligibility"):
            subject.validate_observation(value, self.plan, task)

    def _execution_bundle(self) -> tuple[Path, dict]:
        bundle = self.root / "execution-bundle"
        bundle.mkdir()
        fixture = evidence.corpus_protocol.load()["fixtures"][0]
        stwo = fixture["semantic_io"]["guest_transports"]
        plan = {
            "execution_profile": "rv32im-zkvm-ethereum-v1",
            "input": {
                "path": str(self.root / "input.bin"),
                "bytes": stwo["stwo_input"]["bytes"],
                "sha256": stwo["stwo_input"]["sha256"],
            },
        }
        (bundle / "plan.json").write_text(
            json.dumps(plan, separators=(",", ":")) + "\n"
        )
        (bundle / "receipt.json").write_text("{}\n")
        cycles = [4_194_304] * 209 + [4_150_693]
        records = [{"payload": {"schema": "test.header"}}]
        for index, cycle_count in enumerate(cycles):
            records.append({"payload": {
                "schema": "test.segment",
                "segment_index": index,
                "cycle_count": cycle_count,
                "entry": {
                    "rw_memory_nonzero_words": 898_968_604 if index == 0 else 0,
                    "memory_access_clock_entries": 0,
                },
                "exit": {
                    "rw_memory_nonzero_words": 0,
                    "memory_access_clock_entries": 6_541_934 if index == 0 else 0,
                },
            }})
        records.append({"payload": {
            "schema": "test.summary",
            "opcode_family_rows": [
                {"family": "load_store", "rows": 280_225_149},
                {"family": "base_alu_imm", "rows": 250_128_062},
                {"family": "branch_lt", "rows": 114_034_466},
                {"family": "branch_eq", "rows": 112_500_693},
            ],
        }})
        journal = "".join(
            json.dumps(record, separators=(",", ":")) + "\n"
            for record in records
        )
        (bundle / "execution.ndjson").write_text(journal)
        receipt = {
            "segment_count": 210,
            "total_cycles": 880_760_229,
            "total_core_trace_rows": 880_727_328,
            "total_external_trace_rows": 32_901,
            "output_sha256": stwo["stwo_output"]["sha256"],
        }
        return bundle, receipt

    def _input_evidence(self) -> tuple[tuple[Path, ...], dict]:
        geometry_path = self.root / "geometry.json"
        calls_path = self.root / "calls.bin"
        calls_path.write_bytes(b"calls")
        geometry = zig_seal({
            "schema": evidence.GEOMETRY_SCHEMA,
            "status": "diagnostic-nonpromotable",
            "segment_index": 0,
            "engine_initialized": False,
            "proof_started": False,
            "recursive_admissible": False,
            "legacy_poseidon": {
                "main_column_count": 445, "log_size": 24, "n_rows": 7,
            },
            "candidate_degree5": {
                "candidate_identity_sha256": digest("d5"),
                "geometry": {"main_columns": 239, "maximum_constraint_degree": 5},
                "residency": {
                    "staged_peak_lower_bound_bytes": 55,
                    "retention_policy": "never",
                },
            },
            "candidate_degree6": {
                "candidate_identity_sha256": digest("d6"),
                "geometry": {"main_columns": 161, "maximum_constraint_degree": 6},
                "residency": {
                    "staged_peak_lower_bound_bytes": 39,
                    "retention_policy": "never",
                },
            },
        })
        geometry_path.write_bytes(zig_bytes(geometry))
        call_artifact_path = self.root / "call-artifact.json"
        call_artifact = zig_seal({
            "schema": evidence.CALL_ARTIFACT_SCHEMA,
            "status": "authenticated-call-custody-nonproduction",
            "segment_index": 0,
            "ordered_calls_air_bound": False,
            "production_eligible": False,
            "recursive_admissible": False,
            "geometry_snapshot": {
                "path": str(geometry_path), "bytes": geometry_path.stat().st_size,
                "sha256": hashlib.sha256(geometry_path.read_bytes()).hexdigest(),
            },
            "geometry_snapshot_content_sha256": geometry["content_sha256"],
            "calls": {
                "path": str(calls_path), "bytes": calls_path.stat().st_size,
                "sha256": hashlib.sha256(calls_path.read_bytes()).hexdigest(),
            },
            "call_count": 7,
            "call_list_commitment_sha256": digest("call-list"),
        })
        call_artifact_path.write_bytes(zig_bytes(call_artifact))
        failed = self.root / "failed.time"
        failed.write_text(
            "error: InvalidStatement\nreal 140.00\nuser 100.00\nsys 4.00\n"
            "  10  maximum resident set size\n  0  swaps\n"
            "  12  peak memory footprint\n"
        )
        bundle, receipt = self._execution_bundle()
        return (
            geometry_path, call_artifact_path, failed, self.peer_receipt, bundle,
        ), receipt

    def test_retained_geometry_calls_and_failed_prove_are_nonranking(self) -> None:
        paths, receipt = self._input_evidence()
        with mock.patch.object(
            evidence.segmented, "validate_bundle", return_value=receipt,
        ):
            value = evidence.extract(*paths)
            evidence.validate(value)
        self.assertEqual(445, value["segment_geometry"]["legacy_poseidon"][
            "main_column_count"
        ])
        self.assertEqual(7, value["provider_calls"]["call_count"])
        failed = value["failed_combined_prove"]
        self.assertEqual("InvalidStatement", failed["error"])
        self.assertFalse(failed["within_trial_cap"])
        self.assertFalse(failed["correctness_passed"])
        self.assertFalse(failed["ranking_eligible"])
        workload = value["corpus_workload"]
        self.assertEqual(210, workload["segment_count"])
        self.assertEqual(880_760_229, workload["total_cycles"])
        self.assertEqual(898_968_604,
                         workload["entry_exit_nonzero_word_inclusions"])
        self.assertEqual(6_541_934, workload["touched_transitions"])
        self.assertEqual("137.4163", workload[
            "boundary_to_touched_amplification"
        ]["multiple_rounded_4dp"])
        self.assertEqual("31.817", workload["opcode_mix"]["load_store"][
            "percent_rounded_3dp"
        ])
        geometry_path = paths[0]
        geometry_path.write_bytes(geometry_path.read_bytes().replace(
            b'"segment_index":0', b'"segment_index":1', 1,
        ))
        with mock.patch.object(
            evidence.segmented, "validate_bundle", return_value=receipt,
        ), self.assertRaisesRegex(evidence.OptimizationEvidenceError,
                                  "content authority"):
            evidence.extract(*paths)

    def test_microbench_ranking_is_correctness_first_then_e2e_rss_throughput(self) -> None:
        result_a = self.root / "provider-a.json"
        result_b = self.root / "provider-b.json"
        result_c = self.root / "provider-c.json"
        for path in (result_a, result_b, result_c):
            path.write_bytes(b"result\n")
        a = evidence.normalize_microbench(
            family="provider", source_result=result_a,
            configuration_sha256=digest("a"), correctness_passed=True,
            fresh_verification=True, work_unit="poseidon-calls", work_count=100,
            wall_ns=10, peak_rss_bytes=100, estimated_e2e_wall_ns=1000,
        )
        b = evidence.normalize_microbench(
            family="provider", source_result=result_b,
            configuration_sha256=digest("b"), correctness_passed=True,
            fresh_verification=True, work_unit="poseidon-calls", work_count=100,
            wall_ns=9, peak_rss_bytes=90, estimated_e2e_wall_ns=900,
        )
        invalid = evidence.normalize_microbench(
            family="precompile", source_result=result_c,
            configuration_sha256=digest("c"), correctness_passed=False,
            fresh_verification=False, work_unit="external-calls", work_count=1000,
            wall_ns=1, peak_rss_bytes=1, estimated_e2e_wall_ns=1,
        )
        ranked = evidence.rank_microbenches([a, invalid, b])
        self.assertEqual([digest("b"), digest("a")],
                         [item["configuration_sha256"] for item in ranked])
        self.assertTrue(all(item["promotion_eligible"] is False for item in ranked))

    def test_incremental_cost_capture_replays_but_cannot_promote(self) -> None:
        tool = self.root / "incremental-cost"
        tool.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "for index,path in enumerate(sys.argv[1:]):\n"
            " total=17+index\n"
            " value={'segment_index':index,'touched_words':10+index,"
            "'changed_words':3,'changed_bytes':7,'entry_hash_calls':10,"
            "'exit_hash_calls':total-10,'total_hash_calls':total,"
            "'provider_log_size':max(4,(total-1).bit_length()),'path':path}\n"
            " sys.stderr.write(json.dumps(value,separators=(',',':'))+'\\n')\n"
        )
        tool.chmod(0o755)
        tool_source = self.root / "incremental-cost.zig"
        tool_source.write_text("// test source\n")
        tapes = self.root / "tapes"
        tapes.mkdir()
        for index in range(3):
            (tapes / f"segment-{index:06d}.stwemt01").write_bytes(
                f"tape-{index}".encode("ascii")
            )
        output = self.root / "incremental-evidence.json"
        value = incremental.capture(
            tool=tool, tool_source=tool_source, tape_directory=tapes,
            segment_count=3, timeout_seconds=2, output=output,
            staging=self.staging,
        )
        self.assertEqual(value, incremental.load(output))
        self.assertTrue(value["ranking"]["diagnostic_eligible"])
        self.assertFalse(value["ranking"]["reference_65_admitted"])
        self.assertFalse(value["ranking"]["production_promotion_eligible"])
        self.assertIsNone(value["models"]["estimated_end_to_end_wall_ns"])
        ranking = incremental.ranking_record(output)
        ranking_path = self.root / "incremental-ranking.json"
        ranking_path.write_bytes(protocol.canonical_bytes(ranking))
        self.assertEqual(ranking, incremental.load_ranking(ranking_path))
        self.assertEqual(
            ["degree6-161-incremental", "legacy-445-incremental",
             "legacy-445-fixed-log24"],
            [item["model"] for item in ranking["ranked_alternatives"]],
        )
        self.assertIsNone(ranking["measurement"]["estimated_end_to_end_wall_ns"])
        self.assertFalse(ranking["eligibility"]["production_promotion"])
        bridge = ranking["implemented_proof_bridge"]
        self.assertEqual("2*entry_hash_calls", bridge["per_leaf_call_formula"])
        self.assertTrue(bridge["proof_bridge_source_green"])
        self.assertFalse(bridge["fresh_stark"])
        self.assertFalse(bridge["production_eligible"])
        legacy_ranking = incremental._ranking_record_v1(output)
        legacy_path = self.root / "incremental-ranking-v1.json"
        legacy_path.write_bytes(protocol.canonical_bytes(legacy_ranking))
        self.assertEqual(legacy_ranking, incremental.load_ranking(legacy_path))
        with self.assertRaisesRegex(incremental.IncrementalCostEvidenceError,
                                    "timeout"):
            incremental.capture(
                tool=tool, tool_source=tool_source, tape_directory=tapes,
                segment_count=3, timeout_seconds=121,
                output=self.root / "over-cap.json", staging=self.staging,
            )
        stderr = Path(value["transport"]["stderr"]["path"])
        stderr.write_bytes(stderr.read_bytes() + b" ")
        with self.assertRaisesRegex(incremental.IncrementalCostEvidenceError,
                                    "identity"):
            incremental.load(output)


if __name__ == "__main__":
    unittest.main()
