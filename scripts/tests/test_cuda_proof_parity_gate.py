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
    air = value("--air") if "--air" in args else value("--example")
    poseidon = (
        {"log_n_instances": int(value("--log-n-instances"))}
        if air == "poseidon" else None
    )
    wide = (
        {
            "log_n_rows": int(value("--log-n-rows")),
            "sequence_len": int(value("--sequence-len")),
        }
        if air == "wide_fibonacci" else None
    )
    if air == "state_machine":
        log_n_rows = int(value("--log-n-rows"))
        initial_x = int(value("--initial-x"))
        initial_y = int(value("--initial-y"))
        rows = 1 << log_n_rows
        state_machine = {
            "public_input": [
                [initial_x, initial_y],
                [initial_x + rows, initial_y + rows // 2],
            ],
            "stmt0": {"m": log_n_rows - 1, "n": log_n_rows},
            "stmt1": {
                "x_axis_claimed_sum": [1, 2, 3, 4],
                "y_axis_claimed_sum": [5, 6, 7, 8],
            },
        }
    else:
        state_machine = None
    return {
        "schema_version": 1,
        "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
        "exchange_mode": "proof_exchange_json_wire_v1",
        "generator": "zig",
        "example": air,
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
        "poseidon_statement": poseidon,
        "state_machine_statement": state_machine,
        "wide_fibonacci_statement": wide,
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
    requested_execution_mode = value("--execution-mode")
    reported_execution_mode = (
        "direct"
        if os.environ.get("MISREPORT_EXECUTION_MODE") == "1"
        else requested_execution_mode
    )
    graph_launches = 2 if requested_execution_mode == "graphs" else 0
    air = value("--air")
    poseidon = air == "poseidon"
    state_machine = air == "state_machine"
    if poseidon:
        protocol = "raw-stwo-poseidon-v1"
        statement = (
        {
            "log_n_instances": int(value("--log-n-instances")),
            "trace_rows": 1 << (int(value("--log-n-instances")) - 3),
            "trace_cells": (
                1 << (int(value("--log-n-instances")) - 3)
            ) * 1264,
        }
        )
    elif state_machine:
        log_n_rows = int(value("--log-n-rows"))
        protocol = "raw-stwo-state-machine-v1"
        statement = {
            "log_n_rows": log_n_rows,
            "initial_x": int(value("--initial-x")),
            "initial_y": int(value("--initial-y")),
            "trace_rows": 1 << log_n_rows,
            "trace_cells": (1 << log_n_rows) * 3,
        }
    else:
        protocol = "raw-stwo-wide-v1"
        statement = {
            "log_n_rows": int(value("--log-n-rows")),
            "sequence_len": int(value("--sequence-len")),
        }
    report.write_text(json.dumps({
        "schema_version": (
            2 if os.environ.get("OLD_CUDA_REPORT_SCHEMA") == "1" else 6
        ),
        "product": "stwo-native-cuda",
        "backend": "cuda",
        "application": air,
        "protocol": protocol,
        "execution_mode": reported_execution_mode,
        "plan": {
            "program_sha256": "a" * 64,
            "semantic_sha256": (
                "not-a-digest"
                if os.environ.get("BAD_CUDA_SEMANTIC") == "1"
                else "b" * 64
            ),
            "cache_key_sha256": "c" * 64,
        },
        "statement": statement,
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
            "graph_launches": graph_launches,
            "graph_cache_hits": graph_launches if repeats > 1 else 0,
            "graph_cache_misses": 0 if repeats > 1 else graph_launches,
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
        "aot": {
            "entries": 6,
            "loads": (
                1
                if os.environ.get("BAD_AOT_LOADS") == "1"
                else (3 if state_machine else 2)
            ),
            "cache_hits": 0,
            "misses": 0,
            "launches": 3 if state_machine else 2,
            "launch_failures": 0,
            "build_identity_sha256": "d" * 64,
        },
        "process_repetition": {
            "count": repeats,
            "persistent_session": True,
            "all_canonical_bytes_identical": True,
            "stable_launch_topology": True,
            "request_allocations_released": True,
            "bounded_persistent_pool_usage": True,
            "graph_cache_hits_total": graph_launches * (repeats - 1),
            "graph_cache_misses_total": graph_launches,
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
            air="wide_fibonacci",
            log_n_rows=5,
            sequence_len=8,
            log_n_instances=None,
            initial_x=None,
            initial_y=None,
            repeat=3,
            execution_mode="graphs",
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
        self.assertEqual("graphs", receipt["challenge"]["cuda_execution_mode"])

    def test_direct_execution_uses_same_product_and_oracles(self):
        args = self.arguments("direct")
        args.execution_mode = "direct"
        receipt = json.loads(gate.gate(args).read_text())

        self.assertEqual("direct", receipt["challenge"]["cuda_execution_mode"])
        self.assertEqual("direct", receipt["cuda_residency"]["execution_mode"])
        self.assertIn(
            ["--execution-mode", "direct"],
            [
                receipt["commands"][0]["argv"][index : index + 2]
                for index in range(len(receipt["commands"][0]["argv"]) - 1)
            ],
        )

    def test_poseidon_requires_real_hash_statement_and_aot_kernels(self):
        args = self.arguments("poseidon")
        args.air = "poseidon"
        args.log_n_rows = None
        args.sequence_len = None
        args.log_n_instances = 10
        receipt = json.loads(gate.gate(args).read_text())

        self.assertEqual("poseidon", receipt["challenge"]["air"])
        self.assertEqual(10, receipt["challenge"]["log_n_instances"])
        self.assertEqual(
            "d" * 64,
            receipt["cuda_residency"]["aot_build_sha256"],
        )

    def test_state_machine_is_blocked_on_exact_protocol_mismatch(self):
        args = self.arguments("state-machine")
        args.air = "state_machine"
        args.sequence_len = None
        args.initial_x = 9
        args.initial_y = 3
        with self.assertRaisesRegex(
            gate.GateError,
            "legacy raw-stwo-state-machine-v1.*exact "
            "raw-stwo-state-machine-v2",
        ):
            gate.gate(args)

    def test_rejects_incomplete_aot_kernel_activation(self):
        with mock.patch.dict(os.environ, {"BAD_AOT_LOADS": "1"}):
            with self.assertRaisesRegex(gate.GateError, "AOT witness"):
                gate.gate(self.arguments("bad-aot"))

    def test_rejects_reported_execution_mode_mismatch(self):
        with mock.patch.dict(os.environ, {"MISREPORT_EXECUTION_MODE": "1"}):
            with self.assertRaisesRegex(gate.GateError, "execution_mode"):
                gate.gate(self.arguments("mode-mismatch"))

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

    def test_rejects_spoofed_cuda_semantic_digest(self):
        with mock.patch.dict(os.environ, {"BAD_CUDA_SEMANTIC": "1"}):
            with self.assertRaisesRegex(gate.GateError, "semantic ProofProgram"):
                gate.gate(self.arguments("spoofed-semantic"))

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
