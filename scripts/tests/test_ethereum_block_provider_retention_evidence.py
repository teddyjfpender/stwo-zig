from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARKS = ROOT / "autoresearch/benchmarks"
import sys
if str(BENCHMARKS) not in sys.path:
    sys.path.insert(0, str(BENCHMARKS))

import ethereum_block_provider_hpc_evidence as provider_support  # noqa: E402
import ethereum_block_provider_retention_evidence as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {
        "path": str(path.absolute()), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def zig_bytes(value: dict) -> bytes:
    unsigned = json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ).encode("ascii") + b"\n"
    sealed = {"content_sha256": hashlib.sha256(unsigned).hexdigest(), **value}
    return (json.dumps(
        sealed, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")


def timing(wall: int) -> dict:
    return {"wall_ns": wall, "user_ns": wall * 2, "system_ns": 1}


class ProviderRetentionEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.executable = self.root / "benchmark"
        self.executable.write_bytes(b"retention benchmark executable")
        self.executable.chmod(0o500)
        self.raw_calls = self.root / "calls.stwepc01"
        self.raw_calls.write_bytes(b"canonical raw calls")
        self.call_artifact = self.root / "call-artifact.json"
        call_value = {
            "schema": provider_support.CALL_SCHEMA,
            "calls": identity(self.raw_calls),
            "call_count": 1024,
            "call_list_commitment_sha256": digest("full calls"),
            "session_sha256": digest("session"),
            "producer_sha256": digest("producer"),
        }
        self.call_artifact.write_bytes(zig_bytes(call_value))
        self.call_seal = json.loads(
            self.call_artifact.read_text(encoding="ascii")
        )["content_sha256"]
        self.proofs = []
        for policy in subject.POLICIES:
            arm = []
            for ordinal in range(4):
                path = self.root / f"{policy}-{ordinal}.stw"
                path.write_bytes(f"proof-{ordinal}".encode("ascii"))
                arm.append(path)
            self.proofs.append(arm)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def admission(self) -> dict:
        return {
            "admitted_concurrent_jobs": 4,
            "aggregate_engine_stack_reservation_bytes": 400,
            "aggregate_engine_workers": 8,
            "aggregate_rss_reservation_bytes": 4000,
            "available_cpu_workers": 8,
            "controller_reserve_bytes": 1000,
            "host_byte_budget": 5000,
            "identity_sha256": digest("admission"),
            "per_job_engine_workers": 2,
            "per_job_rss_budget_bytes": 1000,
            "requested_concurrent_jobs": 4,
            "work_items": 4,
        }

    def proof(self, policy_index: int, ordinal: int) -> dict:
        policy = subject.POLICIES[policy_index]
        return {
            "canonical_proof_bytes_equal": True,
            "cold_verify": timing(10),
            "committed_column_count": 455,
            "exact_cross_retention_proof_bytes_equal": True,
            "fresh_verified": True,
            "ordinal": ordinal,
            "proof": identity(self.proofs[policy_index][ordinal]),
            "prove_wall_ns": 50 if policy == "always" else 100,
            "retained_coefficient_columns": 455 if policy == "always" else 0,
            "roots_equal_cross_retention": True,
            "roots_equal_proof": True,
            "statement_identity_sha256": digest(f"statement-{ordinal}"),
            "statement_equal_cross_retention": True,
        }

    def arm(self, index: int) -> dict:
        policy = subject.POLICIES[index]
        batch = 100 if policy == "always" else 230
        cold = 50
        return {
            "arm_index": index,
            "cold_verify_wall_ns": cold,
            "hard_cap_ns": 50_000_000_000,
            "policy": policy,
            "proof_batch_wall_ns": batch,
            "proofs": [self.proof(index, ordinal) for ordinal in range(4)],
            "resource_usage": {
                "availability": "available",
                "cycles": 10,
                "energy_nj": 20,
                "instructions": 30,
                "lifetime_peak_after_bytes": 2000,
                "lifetime_peak_before_bytes": 1000,
                "rss_scope": "self-process-lifetime-peak-before-after-arm",
                "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
            },
            "total": timing(batch + cold),
        }

    def receipt(self) -> Path:
        path = self.root / "receipt.json"
        value = {
            "admission": self.admission(),
            "arms": [self.arm(0), self.arm(1)],
            "benchmark_executable": identity(self.executable),
            "performance_claim_eligible": True,
            "production_eligible": False,
            "profile": {
                "build_mode": "ReleaseFast",
                "composition_columns": 8,
                "coefficient_retention": "sweep(always,never)",
                "host_power_classification": "ac-high-power-pinned",
                "main_columns": 445,
                "preprocessed_columns": 2,
                "provider_profile": "standalone-provider-v1",
                "synthetic_core_stage_a": False,
                "tree2_columns": 8,
            },
            "recursive_admissible": False,
            "retention_speedup_milli": 2300,
            "schema": subject.RECEIPT_SCHEMA,
            "status": "diagnostic-retention-sweep-fresh-verified",
            "timing_scope": "retained-provider-retention-sweep-self-process",
            "total_hard_cap_ns": 118_000_000_000,
            "total_wall_ns": 500,
            "workload": {
                "batch_size": 4,
                "call_artifact": identity(self.call_artifact),
                "call_artifact_content_sha256": self.call_seal,
                "full_call_count": 1024,
                "full_call_list_commitment_sha256": digest("full calls"),
                "log_size": 4,
                "ordinals": [0, 1, 2, 3],
                "raw_call_file": identity(self.raw_calls),
                "session_sha256": digest("session"),
                "shard_count": 4,
                "slice_call_count": 64,
                "slice_call_list_commitment_sha256": digest("slice calls"),
                "slice_offset": 0,
                "source_producer_sha256": digest("producer"),
            },
        }
        path.write_bytes(zig_bytes(value))
        return path

    def test_captures_replays_and_ranks_only_stage_local_policy(self) -> None:
        receipt = self.receipt()
        output = self.root / "evidence.json"
        staging = self.root / "staging"
        value = subject.capture(receipt, output, staging)
        self.assertEqual(value, subject.load(output))
        self.assertEqual(value["ranking"]["best_policy"], "always")
        self.assertEqual(value["measured_retention_speedup_milli"], 2300)
        self.assertIsNone(value["ranking"]["estimated_end_to_end_wall_ns"])
        self.assertFalse(value["ranking"]["production_promotion_eligible"])

    def test_bool_as_int_speedup_and_proof_mutations_reject(self) -> None:
        receipt = self.receipt()
        raw = json.loads(receipt.read_text(encoding="ascii"))
        unsigned = {key: value for key, value in raw.items() if key != "content_sha256"}
        unsigned["performance_claim_eligible"] = 1
        receipt.write_bytes(zig_bytes(unsigned))
        with self.assertRaises(subject.ProviderRetentionEvidenceError):
            subject.capture(receipt, self.root / "bad.json", self.root / "staging")

        receipt = self.receipt()
        output = self.root / "evidence.json"
        value = subject.capture(receipt, output, self.root / "staging")
        self.assertEqual(value, subject.load(output))
        self.proofs[0][0].write_bytes(b"mutated")
        with self.assertRaises((subject.ProviderRetentionEvidenceError,
                                protocol.ProofProtocolError)):
            subject.load(output)


if __name__ == "__main__":
    unittest.main()
