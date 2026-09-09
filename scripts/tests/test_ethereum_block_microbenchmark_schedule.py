from __future__ import annotations

import copy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "autoresearch/benchmarks"
if str(BENCHMARK) not in sys.path:
    sys.path.insert(0, str(BENCHMARK))

import ethereum_block_incremental_profile_v2_evidence as profile  # noqa: E402
import ethereum_block_microbenchmark_schedule as schedule  # noqa: E402
import ethereum_block_optimization_protocol as optimization  # noqa: E402
import ethereum_block_provider_raw_batch_evidence as batch  # noqa: E402
import ethereum_block_provider_raw_pair_evidence as pair  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {
        "path": str(path.absolute()),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def zig_bytes(value: dict) -> bytes:
    unsigned = (json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")
    sealed = {"content_sha256": hashlib.sha256(unsigned).hexdigest(), **value}
    return (json.dumps(
        sealed, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")


class MicrobenchmarkScheduleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.staging = self.root / "staging"
        self.staging.mkdir()
        self.tapes = self.root / "tapes"
        self.tapes.mkdir()
        for index in range(3):
            (self.tapes / f"segment-{index:06d}.stwemt01").write_bytes(
                f"tape-{index}".encode("ascii")
            )
        self.profile_source = self.root / "profile.zig"
        self.profile_source.write_text("// profile source\n")
        self.profile_tool = self.root / "profile-tool"
        self.profile_tool.write_text(
            "#!/usr/bin/env python3\n"
            "import json,sys\n"
            "for i,path in enumerate(sys.argv[1:]):\n"
            " total=17+i; bridge=11+i; plog=max(4,(total-1).bit_length()); "
            "blog=max(4,(bridge-1).bit_length())\n"
            " value={'schema':'stwo.ethereum.incremental-memory-profile-v2',"
            "'segment_index':i,'touched_words':10,'changed_words':3,"
            "'changed_bytes':7,'entry_hash_calls':10,'exit_hash_calls':total-10,"
            "'total_hash_calls':total,'bridge_rows':bridge,"
            "'provider_log_size':plog,'bridge_log_size':blog,"
            "'d6_poseidon_main_cells':(1<<plog)*161,"
            "'bridge_main_cells':(1<<blog)*7,"
            "'d6_committed_cells':(1<<plog)*169+(1<<blog)*11,"
            "'production':False,'path':path}\n"
            " sys.stderr.write(json.dumps(value,separators=(',',':'))+'\\n')\n"
        )
        self.profile_tool.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _profile_evidence(self) -> Path:
        path = self.root / "profile-evidence.json"
        profile.capture(
            tool=self.profile_tool,
            tool_source=self.profile_source,
            tape_directory=self.tapes,
            segment_count=3,
            timeout_seconds=2,
            output=path,
            staging=self.staging,
        )
        return path

    def _raw_batch_receipt(self) -> tuple[Path, Path, list[Path]]:
        executable = self.root / "provider-benchmark"
        executable.write_bytes(b"provider benchmark executable")
        executable.chmod(0o500)
        raw_calls = self.root / "calls.stwepc01"
        raw_calls.write_bytes(b"raw calls")
        call_artifact = self.root / "call-artifact.json"
        call_value = {
            "schema": pair.provider_support.CALL_SCHEMA,
            "calls": identity(raw_calls),
            "call_count": 1000,
            "call_list_commitment_sha256": digest("full-calls"),
            "session_sha256": digest("session"),
            "producer_sha256": digest("producer"),
        }
        call_artifact.write_bytes(zig_bytes(call_value))
        call_seal = json.loads(call_artifact.read_text())["content_sha256"]
        serial = []
        concurrent = []
        proof_paths = []
        for index in range(2):
            left = self.root / f"serial-{index}.stw"
            right = self.root / f"concurrent-{index}.stw"
            payload = f"proof-{index}".encode("ascii")
            left.write_bytes(payload)
            right.write_bytes(payload)
            serial.append(identity(left))
            concurrent.append(identity(right))
            proof_paths.extend((left, right))

        def admission(jobs: int) -> dict:
            return {
                "admitted_concurrent_jobs": jobs,
                "aggregate_engine_stack_reservation_bytes": jobs * 10,
                "aggregate_engine_workers": jobs * 2,
                "aggregate_rss_reservation_bytes": jobs * 100,
                "available_cpu_workers": 8,
                "controller_reserve_bytes": 100,
                "host_byte_budget": 1000,
                "identity_sha256": digest(f"admission-{jobs}"),
                "per_job_engine_workers": 2,
                "per_job_rss_budget_bytes": 100,
                "requested_concurrent_jobs": jobs,
                "work_items": 2,
            }

        correctness = {
            "exact_serial_parallel_proof_bytes_equal": [True, True],
            "parallel_canonical_proof_bytes_equal": [True, True],
            "parallel_fresh_verified": [True, True],
            "parallel_roots_equal_proof": [True, True],
            "serial_canonical_proof_bytes_equal": [True, True],
            "serial_fresh_verified": [True, True],
            "serial_roots_equal_proof": [True, True],
            "stage_a_serial_parallel_roots_equal": True,
            "statement_identities_equal": [True, True],
            "native_claims_equal": [True, True],
            "ordered_claims_equal": [True, True],
        }
        value = {
            "benchmark_executable": identity(executable),
            "concurrent_admission": admission(2),
            "correctness": correctness,
            "parallel_proof_speedup_milli": 2000,
            "parallel_stage_a_speedup_milli": 2000,
            "performance_claim_eligible": True,
            "production_eligible": False,
            "profile": {
                "build_mode": "ReleaseFast",
                "composition_columns": 8,
                "coefficient_retention": "never",
                "host_power_classification": "ac-high-power-pinned",
                "main_columns": 445,
                "preprocessed_columns": 2,
                "provider_profile": "ordered-provider-v2",
                "synthetic_core_stage_a": True,
                "tree2_columns": 12,
            },
            "proofs": {"concurrent": concurrent, "serial": serial},
            "recursive_admissible": False,
            "resource_usage": {
                "availability": "available",
                "cycles": 1,
                "energy_nj": 1,
                "instructions": 1,
                "lifetime_peak_physical_footprint_bytes": 500,
                "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
            },
            "schema": batch.RECEIPT_SCHEMA,
            "serial_admission": admission(1),
            "status": "diagnostic-batch-fresh-verified",
            "timing_scope": "retained-provider-batch-self-process",
            "timings": {
                "concurrent_cold_verify_wall_ns": 10,
                "concurrent_proof_batch_wall_ns": 100,
                "concurrent_stage_a": {
                    "wall_ns": 50, "user_ns": 40, "system_ns": 1,
                },
                "serial_cold_verify_wall_ns": 10,
                "serial_proof_batch_wall_ns": 200,
                "serial_stage_a": {
                    "wall_ns": 100, "user_ns": 80, "system_ns": 1,
                },
                "total_wall_ns": 500,
            },
            "workload": {
                "batch_size": 2,
                "call_artifact": identity(call_artifact),
                "call_artifact_content_sha256": call_seal,
                "full_call_count": 1000,
                "full_call_list_commitment_sha256": digest("full-calls"),
                "log_size": 4,
                "ordinals": [0, 1],
                "raw_call_file": identity(raw_calls),
                "session_sha256": digest("session"),
                "shard_count": 2,
                "slice_call_count": 32,
                "slice_call_list_commitment_sha256": digest("slice-calls"),
                "slice_offset": 0,
                "source_producer_sha256": digest("producer"),
            },
        }
        receipt = self.root / "raw-batch-receipt.json"
        receipt.write_bytes(zig_bytes(value))
        return receipt, executable, proof_paths

    def _batch_evidence(self) -> tuple[Path, Path, list[Path]]:
        receipt, executable, proofs = self._raw_batch_receipt()
        output = self.root / "raw-batch-evidence.json"
        batch.capture(receipt, output, self.staging)
        return output, executable, proofs

    def _excluded(self) -> tuple[Path, Path]:
        raw_pair = self.root / "raw-pair.json"
        raw_pair.write_bytes(zig_bytes({"schema": pair.RECEIPT_SCHEMA}))
        keccak = self.root / "keccak.json"
        keccak.write_text(json.dumps({
            "schema": "stwo.riscv.keccak-adaptive-corpus-projection.v1",
            "production_active": False,
            "proof_or_fresh_verification": False,
        }, separators=(",", ":")) + "\n")
        return raw_pair, keccak

    def test_profile_capture_replays_and_rejects_geometry_mutation(self) -> None:
        path = self._profile_evidence()
        value = profile.load(path)
        self.assertEqual(3, value["aggregate"]["segment_count"])
        self.assertFalse(value["ranking"]["production_promotion_eligible"])
        self.assertIsNone(value["models"]["estimated_end_to_end_wall_ns"])
        with self.assertRaisesRegex(
            profile.IncrementalProfileV2EvidenceError, "timeout",
        ):
            profile.capture(
                tool=self.profile_tool,
                tool_source=self.profile_source,
                tape_directory=self.tapes,
                segment_count=3,
                timeout_seconds=61,
                output=self.root / "over-cap.json",
                staging=self.staging,
            )
        stderr = Path(value["transport"]["stderr"]["path"])
        stderr.write_bytes(stderr.read_bytes().replace(
            b'"d6_committed_cells":5584', b'"d6_committed_cells":5585', 1,
        ))
        with self.assertRaisesRegex(
            (profile.IncrementalProfileV2EvidenceError,
             protocol.ProofProtocolError), "identity",
        ):
            profile.load(path)

    def test_batch_custody_survives_declared_executable_overwrite(self) -> None:
        path, declared, proofs = self._batch_evidence()
        value = batch.load(path)
        self.assertEqual(2, value["measured"]["batch_size"])
        self.assertEqual(2000, value["measured"]["proof_batch_speedup"]["milli"])
        self.assertFalse(value["ranking"]["production_promotion_eligible"])
        declared.chmod(0o700)
        declared.write_bytes(b"later unrelated executable")
        self.assertEqual(value, batch.load(path))
        proofs[0].write_bytes(b"mutated proof")
        with self.assertRaisesRegex(
            (batch.ProviderRawBatchEvidenceError, protocol.ProofProtocolError),
            "identity",
        ):
            batch.load(path)

    def test_scheduler_ranks_replayed_inputs_and_forbids_full_proof(self) -> None:
        profile_path = self._profile_evidence()
        batch_path, _, _ = self._batch_evidence()
        raw_pair, keccak = self._excluded()
        value = schedule.build(
            profile_path, batch_path, self.root / "runs", [raw_pair, keccak],
        )
        output = self.root / "schedule.json"
        output.write_bytes(protocol.canonical_bytes(value))
        self.assertEqual(value, schedule.load(output))
        self.assertEqual(
            ["incremental-memory-changed-only-v2",
             "provider-raw-batch-concurrency-v2"],
            [item["candidate_id"] for item in value["ranked_leads"]],
        )
        self.assertTrue(all(
            item["measurement"]["estimated_end_to_end_wall_ns"] is None
            and item["production_promotion_eligible"] is False
            for item in value["ranked_leads"]
        ))
        self.assertEqual(
            ["executable-custody-overwritten-no-immutable-copy",
             "digest-only-source-authorities-and-no-content-seal"],
            [item["reason"] for item in value["excluded_inputs"]],
        )
        opportunity = value["opportunity_model"]
        self.assertEqual(
            "conditional-provider-stage-upper-bound-only",
            opportunity["status"],
        )
        geometry = opportunity["factors"][0]
        concurrency = opportunity["factors"][1]
        combined = Fraction(
            geometry["numerator"], geometry["denominator"],
        ) * Fraction(concurrency["numerator"], concurrency["denominator"])
        self.assertEqual({
            "numerator": combined.numerator,
            "denominator": combined.denominator,
        }, opportunity["conditional_remaining_provider_stage_fraction"])
        self.assertEqual(
            (combined.denominator - combined.numerator) * 1_000_000
            // combined.denominator,
            opportunity["conditional_reduction_millionths"],
        )
        self.assertFalse(opportunity["measured_provider_stage_combination"])
        self.assertIsNone(opportunity["measured_end_to_end_wall_ns"])
        self.assertIsNone(opportunity["modeled_end_to_end_wall_ns"])
        admitted = optimization._diagnostic_rankings([output])
        self.assertEqual(schedule.SCHEMA, admitted[0]["schema"])
        self.assertEqual("diagnostic-context-only", admitted[0]["ranking_role"])
        self.assertFalse(admitted[0]["production_promotion_eligible"])
        with self.assertRaisesRegex(
            schedule.MicrobenchmarkScheduleError, "forbidden full-proof",
        ):
            schedule._safe_argv(
                ["tool", "--proof", "whole-block"],
                ["tool", "--proof", "whole-block"],
                "test schedule",
            )
        mutated = copy.deepcopy(value)
        mutated["ranked_leads"][0]["execution"]["timeout_seconds"] = 61
        mutated["content_sha256"] = protocol.content_sha256(mutated)
        with self.assertRaisesRegex(
            schedule.MicrobenchmarkScheduleError, "execution",
        ):
            schedule.validate(mutated)
        modeled_e2e = copy.deepcopy(value)
        modeled_e2e["opportunity_model"]["modeled_end_to_end_wall_ns"] = 1
        modeled_e2e["content_sha256"] = protocol.content_sha256(modeled_e2e)
        with self.assertRaisesRegex(
            schedule.MicrobenchmarkScheduleError, "opportunity model",
        ):
            schedule.validate(modeled_e2e)


if __name__ == "__main__":
    unittest.main()
