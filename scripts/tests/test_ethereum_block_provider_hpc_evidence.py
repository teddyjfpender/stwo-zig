from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "autoresearch/benchmarks"
import sys
if str(BENCHMARK) not in sys.path:
    sys.path.insert(0, str(BENCHMARK))

import ethereum_block_provider_hpc_evidence as subject  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {
        "path": str(path), "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def zig_bytes(value: dict) -> bytes:
    unsigned = json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ).encode("ascii")
    sealed = {
        "content_sha256": hashlib.sha256(unsigned + b"\n").hexdigest(),
        **value,
    }
    return (json.dumps(
        sealed, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ) + "\n").encode("ascii")


class ProviderHpcEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.executable = self.root / "benchmark"
        self.executable.write_bytes(b"benchmark executable")
        self.executable.chmod(0o500)
        self.proof = self.root / "proof.stw"
        self.proof.write_bytes(b"canonical proof")
        self.raw_calls = self.root / "calls.stwepc01"
        self.raw_calls.write_bytes(b"canonical calls")
        self.call_artifact = self.root / "call-artifact.json"
        self.call_content = {
            "schema": subject.CALL_SCHEMA,
            "calls": identity(self.raw_calls),
            "call_count": 8,
            "call_list_commitment_sha256": digest("full calls"),
            "session_sha256": digest("session"),
            "producer_sha256": digest("producer"),
        }
        self.call_artifact.write_bytes(zig_bytes(self.call_content))
        self.call_seal = json.loads(self.call_artifact.read_text())["content_sha256"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def receipt(self, workers: int, parallel_wall: int) -> Path:
        path = self.root / f"receipt-w{workers}.json"
        prove_wall = 50
        shard_count = 2
        serial_wall = 100
        value = {
            "admission": {
                "admitted_workers": workers,
                "available_cpu_workers": 4,
                "concurrent_worker_reservation_bytes": 1000,
                "controller_reserve_bytes": 100,
                "host_byte_budget": 2000,
                "identity_sha256": digest(f"admission-{workers}"),
                "requested_workers": workers,
                "worker_rss_budget_bytes": 500,
                "work_items": shard_count,
            },
            "benchmark_executable_sha256": identity(self.executable)["sha256"],
            "candidate": {
                "ideal_parallel_batch_wall_ns": prove_wall * shard_count // workers,
                "ideal_parallel_speedup_milli": workers * 1000,
                "model": "single-shard-linear-upper-bound",
                "parallel_stage_a_speedup_milli": serial_wall * 1000 // parallel_wall,
            },
            "correctness": {
                "canonical_proof_bytes_equal": True,
                "fresh_verified": True,
                "native_claim_equal": True,
                "ordered_claim_equal": True,
                "stage_a_parallel_roots_equal": True,
                "stage_a_roots_equal_proof": True,
                "statement_identity_equal": True,
            },
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
            "proof": identity(self.proof),
            "proof_statement_identity_sha256": digest(f"statement-{workers}"),
            "provider_claim_identity_sha256": digest(f"claim-{workers}"),
            "recursive_admissible": False,
            "resource_usage": {
                "availability": "available",
                "cycles": 1000,
                "energy_nj": 2000,
                "instructions": 3000,
                "lifetime_peak_physical_footprint_bytes": 4000 + workers,
                "source": "darwin.proc_pid_rusage.RUSAGE_INFO_V6",
            },
            "schema": subject.RECEIPT_SCHEMA,
            "status": "diagnostic-fresh-verified",
            "timing_scope": "retained-provider-slice-self-process",
            "timings": {
                "cold_verify": {"wall_ns": 10, "user_ns": 9, "system_ns": 1},
                "parallel_stage_a": {
                    "wall_ns": parallel_wall, "user_ns": 70, "system_ns": 2,
                },
                "provider_prove_wall_ns": prove_wall,
                "serial_stage_a": {
                    "wall_ns": serial_wall, "user_ns": 90, "system_ns": 2,
                },
                "total_wall_ns": 300,
            },
            "workload": {
                "call_artifact": identity(self.call_artifact),
                "call_artifact_content_sha256": self.call_seal,
                "full_call_count": 8,
                "full_call_list_commitment_sha256": digest("full calls"),
                "log_size": 4,
                "proved_ordinal": 0,
                "raw_call_file": identity(self.raw_calls),
                "session_sha256": digest("session"),
                "shard_count": shard_count,
                "slice_call_count": 4,
                "slice_call_list_commitment_sha256": digest("slice calls"),
                "slice_offset": 0,
                "source_producer_sha256": digest("producer"),
            },
        }
        path.write_bytes(zig_bytes(value))
        return path

    def test_adapts_replays_and_ranks_only_measured_stage_a(self) -> None:
        evidence_paths = []
        for workers, parallel_wall in ((1, 110), (2, 50)):
            value = subject.adapt(self.receipt(workers, parallel_wall), self.executable)
            path = self.root / f"evidence-w{workers}.json"
            path.write_bytes(protocol.canonical_bytes(value))
            self.assertEqual(value, subject.load(path))
            self.assertFalse(value["modeled"]["ranking_eligible"])
            self.assertIsNone(value["ranking"]["estimated_end_to_end_wall_ns"])
            evidence_paths.append(path)
        ranking = subject.rank(evidence_paths)
        ranking_path = self.root / "ranking.json"
        ranking_path.write_bytes(protocol.canonical_bytes(ranking))
        self.assertEqual(ranking, subject.load_ranking(ranking_path))
        self.assertEqual([2, 1], [entry["admitted_workers"]
                                 for entry in ranking["entries"]])
        self.assertTrue(all(entry["raw_proof_concurrency_measured"] is False
                            for entry in ranking["entries"]))
        self.proof.write_bytes(b"mutated")
        with self.assertRaisesRegex(
            (subject.ProviderHpcEvidenceError, protocol.ProofProtocolError),
            "identity",
        ):
            subject.load(evidence_paths[0])


if __name__ == "__main__":
    unittest.main()
