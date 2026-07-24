import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

from scripts import cuda_proof_parity_gate as gate


FAKE_PRODUCT = textwrap.dedent(
    r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
name = Path(sys.argv[0]).name

def value(flag):
    return args[args.index(flag) + 1]

def artifact(proof):
    return {
        "schema_version": 1,
        "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
        "exchange_mode": "proof_exchange_json_wire_v1",
        "generator": "zig",
        "example": "wide_fibonacci",
        "prove_mode": "prove",
        "pcs_config": {
            "pow_bits": 10,
            "fri_config": {
                "log_blowup_factor": 1,
                "log_last_layer_degree_bound": 0,
                "n_queries": 3,
                "fold_step": 1,
            },
            "lifting_log_size": None,
        },
        "blake_statement": None,
        "plonk_statement": None,
        "poseidon_statement": None,
        "state_machine_statement": None,
        "wide_fibonacci_statement": {
            "log_n_rows": int(value("--log-n-rows")),
            "sequence_len": int(value("--sequence-len")),
        },
        "xor_statement": None,
        "proof_bytes_hex": proof,
    }

if name == "rust":
    if os.environ.get("FAIL_RUST") == "1":
        raise SystemExit(9)
    raise SystemExit(0)

if args[0] == "verify":
    raise SystemExit(0)

proof = "deadbeef"
if name == "cuda" and os.environ.get("MISMATCH_CUDA") == "1":
    proof = "feedface"
output = Path(value("--output"))
output.write_text(json.dumps(artifact(proof)) + "\n")

if name == "cuda":
    report = Path(value("--report-out"))
    repeats = int(value("--repeat"))
    report.write_text(json.dumps({
        "schema_version": (
            2 if os.environ.get("OLD_CUDA_REPORT_SCHEMA") == "1" else 5
        ),
        "product": "stwo-native-cuda",
        "backend": "cuda",
        "application": "wide_fibonacci",
        "protocol": "raw-stwo-wide-v1",
        "statement": {
            "log_n_rows": int(value("--log-n-rows")),
            "sequence_len": int(value("--sequence-len")),
        },
        "proof": {
            "canonical_bytes": 4,
            "canonical_sha256": __import__("hashlib").sha256(
                bytes.fromhex(proof)
            ).hexdigest(),
            "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
            "zig_verified": True,
        },
        "residency": {
            "resident": os.environ.get("BAD_RESIDENCY") != "1",
            "strict_aot": True,
            "all_stages_complete_once": True,
            "terminal_d2h_operations": 1,
            "terminal_d2h_bytes": 4,
            "cpu_fallback_attempts": 0,
            "cpu_fallbacks_completed": 0,
            "device_timing_intervals": 10,
            "device_elapsed_ns": 10,
            "graph_launches": 2,
            "graph_cache_hits": 2 if repeats > 1 else 0,
            "graph_cache_misses": 0 if repeats > 1 else 2,
            "persistent_bytes": 4096,
            "pool_used_bytes": 4096,
        },
        "device_stage_timing_ns": {
            "ingress": 1,
            "trace_generation": 1,
            "trace_commit": 1,
            "constraint_evaluation": 1,
            "oods": 1,
            "quotient": 1,
            "fri_commit": 1,
            "pow": 1,
            "decommit": 1,
            "proof_assembly": 1,
            "total": 10,
        },
        "process_repetition": {
            "count": repeats,
            "persistent_session": True,
            "all_canonical_bytes_identical": True,
            "stable_launch_topology": True,
            "request_allocations_released": True,
            "bounded_persistent_pool_usage": True,
            "graph_cache_hits_total": 2 * (repeats - 1),
            "graph_cache_misses_total": 2,
            "resident_prove_ns": [10] * repeats,
            "terminal_decode_ns": [2] * repeats,
            "device_elapsed_ns": [10] * repeats,
            "runtime_proof_indices": list(range(1, repeats + 1)),
        },
    }) + "\n")
"""
)


class CudaProofParityGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        for name in ("cuda", "cpu", "rust"):
            path = self.root / name
            path.write_text(FAKE_PRODUCT)
            path.chmod(0o755)
        self.rust_sha = hashlib.sha256(
            (self.root / "rust").read_bytes()
        ).hexdigest()

    def tearDown(self):
        self.temporary.cleanup()

    def arguments(self, name="evidence", cpu_artifact=None):
        return argparse.Namespace(
            cuda_product=self.root / "cuda",
            native_cpu_product=self.root / "cpu",
            cpu_artifact=cpu_artifact,
            rust_verifier=self.root / "rust",
            rust_verifier_sha256=self.rust_sha,
            log_n_rows=5,
            sequence_len=8,
            repeat=3,
            out_dir=self.root / name,
            timeout_seconds=10,
        )

    def test_emits_receipt_after_exact_parity_and_four_verifications(self):
        receipt_path = gate.gate(self.arguments())
        receipt = json.loads(receipt_path.read_text())
        self.assertEqual("pass", receipt["verdict"])
        self.assertTrue(receipt["proofs"]["canonical_byte_parity"])
        self.assertEqual(4, len(receipt["verifications"]))
        self.assertEqual(3, receipt["challenge"]["process_repetitions"])
        self.assertTrue(receipt["cuda_residency"]["resident"])

    def test_accepts_known_cpu_artifact_without_skipping_verifiers(self):
        initial = gate.gate(self.arguments("initial"))
        cpu_artifact = initial.parent / "cpu-proof.json"
        receipt = json.loads(
            gate.gate(self.arguments("provided", cpu_artifact)).read_text()
        )
        self.assertEqual("provided", receipt["proofs"]["cpu"]["source"])
        self.assertEqual(4, len(receipt["verifications"]))

    def test_rejects_canonical_proof_mismatch(self):
        with mock.patch.dict(os.environ, {"MISMATCH_CUDA": "1"}):
            with self.assertRaisesRegex(gate.GateError, "proof bytes differ"):
                gate.gate(self.arguments("mismatch"))

    def test_rejects_failed_rust_verification(self):
        with mock.patch.dict(os.environ, {"FAIL_RUST": "1"}):
            with self.assertRaisesRegex(gate.GateError, "rejected evidence"):
                gate.gate(self.arguments("rust-failure"))

    def test_rejects_nonresident_cuda_report(self):
        with mock.patch.dict(os.environ, {"BAD_RESIDENCY": "1"}):
            with self.assertRaisesRegex(gate.GateError, "residency contract"):
                gate.gate(self.arguments("nonresident"))

    def test_rejects_obsolete_cuda_report_schema(self):
        with mock.patch.dict(os.environ, {"OLD_CUDA_REPORT_SCHEMA": "1"}):
            with self.assertRaisesRegex(gate.GateError, "schema_version"):
                gate.gate(self.arguments("obsolete-report-schema"))

    def test_rejects_unpinned_rust_verifier(self):
        args = self.arguments("bad-pin")
        args.rust_verifier_sha256 = "0" * 64
        with self.assertRaisesRegex(gate.GateError, "explicit pin"):
            gate.gate(args)

    def test_release_gate_requires_three_repetitions(self):
        args = self.arguments("too-few-repetitions")
        args.repeat = 2
        with self.assertRaisesRegex(gate.GateError, "invalid workload"):
            gate.gate(args)


if __name__ == "__main__":
    unittest.main()
