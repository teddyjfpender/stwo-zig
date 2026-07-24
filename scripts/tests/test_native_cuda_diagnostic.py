from __future__ import annotations

import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.native_cuda_diagnostic_lib import (  # noqa: E402
    DEFAULT_SHAPES,
    DiagnosticError,
    Settings,
    Shape,
    run_diagnostic,
)


FAKE_PRODUCT = r"""
#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument("--air", required=True)
parser.add_argument("--backend", required=True)
parser.add_argument("--protocol", required=True)
parser.add_argument("--log-n-rows", required=True, type=int)
parser.add_argument("--sequence-len", required=True, type=int)
parser.add_argument("--output", required=True)
parser.add_argument("--report-out", required=True)
parser.add_argument("--repeat", required=True, type=int)
args = parser.parse_args()

mode = os.environ.get("FAKE_CUDA_MODE", "valid")
sample = Path(args.output).parent.name
proof_value = {
    "backend": "cuda",
    "log_n_rows": args.log_n_rows,
    "sequence_len": args.sequence_len,
}
if mode == "proof-drift" and sample.endswith("001"):
    proof_value["poison"] = True
proof_bytes = json.dumps(
    proof_value,
    sort_keys=True,
    separators=(",", ":"),
).encode()
proof_sha256 = hashlib.sha256(proof_bytes).hexdigest()

artifact = {
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
        "log_n_rows": args.log_n_rows,
        "sequence_len": args.sequence_len,
    },
    "xor_statement": None,
    "proof_bytes_hex": proof_bytes.hex(),
}
Path(args.output).write_text(
    json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n"
)

rows = 1 << args.log_n_rows
resident_ns = rows * args.sequence_len + 1_000_000
fallbacks = 1 if mode == "fallback" else 0
resident = mode != "nonresident"
report = {
    "schema_version": 2,
    "product": "stwo-native-cuda",
    "backend": "cuda",
    "application": "wide_fibonacci",
    "protocol": "raw-stwo-wide-v1",
    "statement": {
        "log_n_rows": args.log_n_rows,
        "sequence_len": args.sequence_len,
        "trace_rows": rows,
        "trace_cells": rows * args.sequence_len,
    },
    "proof": {
        "path": args.output,
        "format": "proof_exchange_json_wire_v1",
        "canonical_bytes": len(proof_bytes),
        "canonical_sha256": proof_sha256,
        "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
        "zig_verified": True,
    },
    "timing_ns": {
        "runtime_init": 1000,
        "resident_prove": resident_ns,
        "terminal_decode": 1000,
        "runtime_teardown": 1000,
        "total_before_publication": resident_ns + 4000,
    },
    "process_repetition": {
        "count": args.repeat,
        "persistent_session": True,
        "all_canonical_bytes_identical": True,
        "stable_launch_topology": True,
        "zero_final_pool_usage": True,
        "resident_prove_ns": [resident_ns],
        "terminal_decode_ns": [1000],
        "device_elapsed_ns": [10000],
        "runtime_proof_indices": [1],
    },
    "residency": {
        "resident": resident,
        "strict_aot": True,
        "all_stages_complete_once": True,
        "terminal_d2h_operations": 1,
        "terminal_d2h_bytes": len(proof_bytes),
        "h2d_bytes": rows * args.sequence_len * 4,
        "d2d_bytes": rows * args.sequence_len * 8,
        "cpu_fallback_attempts": fallbacks,
        "cpu_fallbacks_completed": fallbacks,
        "kernel_launches": 30,
        "graph_launches": 2,
        "sync_calls": 4,
        "device_timing_intervals": 10,
        "device_elapsed_ns": 10000,
        "peak_live_bytes": 4096,
        "pool_used_bytes": 0,
        "pool_reserved_bytes": 8192,
    },
    "device_stage_timing_ns": {
        "ingress": 1000,
        "trace_generation": 1000,
        "trace_commit": 1000,
        "constraint_evaluation": 1000,
        "oods": 1000,
        "quotient": 1000,
        "fri_commit": 1000,
        "pow": 1000,
        "decommit": 1000,
        "proof_assembly": 1000,
        "total": 10000,
    },
    "aot": {
        "entries": 1,
        "loads": 1,
        "cache_hits": 0,
        "misses": 0,
        "launches": 1,
        "launch_failures": 0,
        "build_identity_sha256": "a" * 64,
    },
    "device": {
        "ordinal": 0,
        "sm_major": 8,
        "sm_minor": 9,
        "uuid": "b" * 32,
        "driver_version": 13000,
        "runtime_version": 12080,
        "toolkit_version": 12080,
        "global_memory_bytes": 24 * 1024 * 1024 * 1024,
        "multiprocessors": 128,
    },
}
encoded = json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n"
Path(args.report_out).write_text(encoded)
print(encoded, end="")
"""


class NativeCudaDiagnosticTests(unittest.TestCase):
    def test_default_matrix_covers_wide_and_saturation_shapes(self) -> None:
        self.assertEqual(
            DEFAULT_SHAPES,
            (
                Shape(14, 100),
                Shape(16, 100),
                Shape(18, 100),
                Shape(20, 100),
                Shape(22, 100),
                Shape(20, 128),
                Shape(21, 128),
                Shape(22, 128),
            ),
        )

    def make_product(self, root: Path) -> Path:
        product = root / "fake-native-cuda"
        product.write_text(textwrap.dedent(FAKE_PRODUCT).lstrip())
        product.chmod(0o755)
        return product

    def settings(
        self,
        root: Path,
        product: Path,
        *,
        samples: int = 2,
    ) -> Settings:
        return Settings(
            product_bin=product,
            output_path=root / "summary.json",
            repo_root=REPO_ROOT,
            cold_samples=samples,
            cooldown_seconds=0.0,
            timeout_seconds=10.0,
            device_ordinal="0",
            shapes=(Shape(5, 8), Shape(6, 16)),
        )

    def test_fake_product_emits_stable_cold_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root, self.make_product(root))
            document, encoded = run_diagnostic(settings)

            self.assertEqual(
                document["schema"],
                "native_cuda_cold_diagnostic_v2",
            )
            self.assertEqual(
                document["evidence_class"],
                "diagnostic_cold_process_stage_attributed",
            )
            self.assertFalse(document["headline_eligible"])
            self.assertFalse(
                document["measurement_contract"]["warm_request_measured"]
            )
            self.assertEqual(document["summary"]["workload_shapes"], 2)
            self.assertEqual(document["summary"]["cold_processes"], 4)
            self.assertTrue(document["summary"]["all_samples_zero_fallback"])
            self.assertEqual(settings.output_path.read_bytes(), encoded)
            self.assertEqual(
                encoded,
                (json.dumps(document, indent=2, sort_keys=True) + "\n").encode(),
            )

            for workload in document["workloads"]:
                statement = workload["statement"]
                resident = workload["metrics"][
                    "resident_committed_mcells_per_second"
                ]["median"]
                resident_ns = workload["metrics"]["resident_prove_ms"]["median"]
                expected = (
                    statement["trace_cells"]
                    / (resident_ns / 1000.0)
                    / 1_000_000.0
                )
                self.assertAlmostEqual(resident, expected)
                self.assertTrue(
                    workload["proof_identity"]["all_samples_identical"]
                )
                self.assertEqual(workload["cold_samples"], 2)

    def test_fallback_telemetry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root),
                samples=1,
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_MODE": "fallback"},
            ), self.assertRaisesRegex(DiagnosticError, "fallback"):
                run_diagnostic(settings)
            self.assertFalse(settings.output_path.exists())

    def test_nonresident_telemetry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root),
                samples=1,
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_MODE": "nonresident"},
            ), self.assertRaisesRegex(DiagnosticError, "resident"):
                run_diagnostic(settings)

    def test_proof_identity_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root, self.make_product(root))
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_MODE": "proof-drift"},
            ), self.assertRaisesRegex(DiagnosticError, "proof identity changed"):
                run_diagnostic(settings)


if __name__ == "__main__":
    unittest.main()
