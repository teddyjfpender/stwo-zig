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
    StateMachineShape,
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
parser.add_argument("--log-n-rows", type=int)
parser.add_argument("--sequence-len", type=int)
parser.add_argument("--n-rounds", type=int)
parser.add_argument("--log-n-instances", type=int)
parser.add_argument("--log-size", type=int)
parser.add_argument("--log-step", type=int)
parser.add_argument("--offset", type=int)
parser.add_argument("--initial-x", type=int)
parser.add_argument("--initial-y", type=int)
parser.add_argument("--output", required=True)
parser.add_argument("--report-out", required=True)
parser.add_argument("--repeat", required=True, type=int)
parser.add_argument(
    "--execution-mode",
    choices=("graphs", "direct"),
    default="graphs",
)
args = parser.parse_args()

if args.air == "wide_fibonacci":
    if args.log_n_rows is None or args.sequence_len is None:
        parser.error("wide_fibonacci shape is incomplete")
    rows = 1 << args.log_n_rows
    trace_cells = rows * args.sequence_len
    artifact_statement_key = "wide_fibonacci_statement"
    artifact_statement = {
        "log_n_rows": args.log_n_rows,
        "sequence_len": args.sequence_len,
    }
    report_statement = {
        **artifact_statement,
        "trace_rows": rows,
        "trace_cells": trace_cells,
    }
elif args.air == "xor":
    if args.log_size is None or args.log_step is None or args.offset is None:
        parser.error("xor shape is incomplete")
    rows = 1 << args.log_size
    trace_cells = rows * 3
    artifact_statement_key = "xor_statement"
    artifact_statement = {
        "log_size": args.log_size,
        "log_step": args.log_step,
        "offset": args.offset,
    }
    report_statement = {
        **artifact_statement,
        "trace_rows": rows,
        "trace_cells": trace_cells,
    }
elif args.air == "plonk":
    if args.log_n_rows is None:
        parser.error("plonk shape is incomplete")
    rows = 1 << args.log_n_rows
    trace_cells = rows * 8
    artifact_statement_key = "plonk_statement"
    artifact_statement = {"log_n_rows": args.log_n_rows}
    report_statement = {
        **artifact_statement,
        "trace_rows": rows,
        "trace_cells": trace_cells,
    }
elif args.air == "blake":
    if args.log_n_rows is None or args.n_rounds is None:
        parser.error("blake shape is incomplete")
    rows = 1 << args.log_n_rows
    trace_cells = rows * args.n_rounds * 96
    artifact_statement_key = "blake_statement"
    artifact_statement = {
        "log_n_rows": args.log_n_rows,
        "n_rounds": args.n_rounds,
    }
    report_statement = {
        **artifact_statement,
        "trace_rows": rows,
        "trace_cells": trace_cells,
    }
elif args.air == "poseidon":
    if args.log_n_instances is None or args.log_n_instances < 3:
        parser.error("poseidon shape is incomplete")
    rows = 1 << (args.log_n_instances - 3)
    trace_cells = rows * 1264
    artifact_statement_key = "poseidon_statement"
    artifact_statement = {
        "log_n_instances": args.log_n_instances,
    }
    report_statement = {
        **artifact_statement,
        "trace_rows": rows,
        "trace_cells": trace_cells,
    }
elif args.air == "state_machine":
    if (
        args.log_n_rows is None
        or args.initial_x is None
        or args.initial_y is None
    ):
        parser.error("state-machine shape is incomplete")
    rows = 1 << args.log_n_rows
    trace_cells = rows * 3
    artifact_statement_key = "state_machine_statement"
    artifact_statement = {
        "public_input": [
            [args.initial_x, args.initial_y],
            [args.initial_x + rows, args.initial_y + rows // 2],
        ],
        "stmt0": {
            "m": args.log_n_rows - 1,
            "n": args.log_n_rows,
        },
        "stmt1": {
            "x_axis_claimed_sum": [1, 2, 3, 4],
            "y_axis_claimed_sum": [5, 6, 7, 8],
        },
    }
    report_statement = {
        "log_n_rows": args.log_n_rows,
        "initial_x": args.initial_x,
        "initial_y": args.initial_y,
        "trace_rows": rows,
        "trace_cells": trace_cells,
    }
else:
    parser.error("unsupported AIR")

mode = os.environ.get("FAKE_CUDA_MODE", "valid")
sample = Path(args.output).parent.name
proof_value = {
    "backend": "cuda",
    "air": args.air,
    "statement": artifact_statement,
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
    "example": args.air,
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
    "blake_statement": (
        artifact_statement if artifact_statement_key == "blake_statement" else None
    ),
    "plonk_statement": (
        artifact_statement if artifact_statement_key == "plonk_statement" else None
    ),
    "poseidon_statement": (
        artifact_statement
        if artifact_statement_key == "poseidon_statement"
        else None
    ),
    "state_machine_statement": (
        artifact_statement
        if artifact_statement_key == "state_machine_statement"
        else None
    ),
    "wide_fibonacci_statement": (
        artifact_statement
        if artifact_statement_key == "wide_fibonacci_statement"
        else None
    ),
    "xor_statement": (
        artifact_statement if artifact_statement_key == "xor_statement" else None
    ),
    "proof_bytes_hex": proof_bytes.hex(),
}
Path(args.output).write_text(
    json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n"
)

binary_scale = 2 if "baseline" in Path(__file__).name else 1
resident_ns = (trace_cells + 1_000_000) * binary_scale
fallbacks = 1 if mode == "fallback" else 0
resident = mode != "nonresident"
historical_v4 = "schema-v4" in Path(__file__).name
historical_v5 = "schema-v5" in Path(__file__).name
graph_launches = 2 if args.execution_mode == "graphs" else 0
graph_hits = graph_launches if args.repeat > 1 else 0
graph_misses = 0 if args.repeat > 1 else graph_launches
program_sha256 = (
    "d" * 64 if "program-drift" in Path(__file__).name else "c" * 64
)
if (
    os.environ.get("FAKE_FULL_PROGRAM_DRIFT") == "1"
    and Path(args.output).parent.parent.name == "steady"
):
    program_sha256 = "d" * 64
semantic_sha256 = (
    "f" * 64 if "semantic-drift" in Path(__file__).name else "e" * 64
)
aot_loads = int(os.environ.get("FAKE_CUDA_AOT_LOADS", "1"))
report = {
    "schema_version": 6,
    "product": "stwo-native-cuda",
    "backend": "cuda",
    "application": args.air,
    "protocol": args.protocol,
    "execution_mode": args.execution_mode,
    "product_identity": {
        "schema_version": 2,
        "name": "stwo-native-cuda",
        "frontend": "native-examples",
        "backend": "cuda",
        "role": "cli",
        "protocol_features": (
            "native-examples-v1+cuda-resident-proof-v1+"
            "explicit-toolchain-v1"
        ),
        "protocol_manifest_sha256": hashlib.sha256(
            b"native-examples-v1+cuda-resident-proof-v1+"
            b"explicit-toolchain-v1"
        ).hexdigest(),
        "identity_sha256": "1" * 64,
        "implementation_repository": (
            "https://github.com/teddyjfpender/stwo-zig"
        ),
        "implementation_commit": "2" * 40,
        "implementation_tree": "3" * 40,
        "implementation_dirty": False,
        "dirty_content_sha256": None,
        "zig_version": "0.15.2",
        "target_arch": "x86_64",
        "target_os": "linux",
        "target_abi": "gnu",
        "cpu_model": "baseline",
        "cpu_features_sha256": "4" * 64,
        "optimize": "ReleaseFast",
        "runtime_manifest": "cuda-process-runtime-v1",
        "sdk_manifest": "cuda-explicit-toolchain-v1",
        "aot_manifest": "cuda-authenticated-native-pack-v1",
    },
    "statement": report_statement,
    "plan": {
        "program_sha256": program_sha256,
        "semantic_sha256": semantic_sha256,
        "cache_key_sha256": "d" * 64,
        "schedule_version": 1,
        "compiled_once": True,
        "reuse_count": args.repeat,
        "node_count": 8,
        "request_bytes": 4096,
        "persistent_bytes": 4096,
        "predicted_minimum_launches": 8,
        "transcript_barriers": 40,
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
        "shape_prepare": 1000,
        "resident_prove": resident_ns,
        "terminal_decode": 1000,
        "independent_verification": 1000,
        "verified_request": resident_ns + 3000,
        "runtime_teardown": 1000,
        "total_before_publication": resident_ns + 7000,
    },
    "process_repetition": {
        "count": args.repeat,
        "persistent_session": True,
        "all_canonical_bytes_identical": True,
        "stable_launch_topology": True,
        "request_allocations_released": True,
        "bounded_persistent_pool_usage": True,
        "graph_cache_hits_total": graph_launches * (args.repeat - 1),
        "graph_cache_misses_total": graph_launches,
        "resident_prove_ns": [resident_ns] * args.repeat,
        "terminal_decode_ns": [1000] * args.repeat,
        "independent_verification_ns": [1000] * args.repeat,
        "verified_request_ns": [resident_ns + 3000] * args.repeat,
        "device_elapsed_ns": [10000] * args.repeat,
        "runtime_proof_indices": list(range(1, args.repeat + 1)),
    },
    "residency": {
        "resident": resident,
        "strict_aot": True,
        "all_stages_complete_once": True,
        "terminal_d2h_operations": 1,
        "terminal_d2h_bytes": len(proof_bytes),
        "h2d_bytes": trace_cells * 4,
        "d2d_bytes": trace_cells * 8,
        "cpu_fallback_attempts": fallbacks,
        "cpu_fallbacks_completed": fallbacks,
        "kernel_launches": 30,
        "graph_launches": graph_launches,
        "graph_cache_hits": graph_hits,
        "graph_cache_misses": graph_misses,
        "sync_calls": 4,
        "device_timing_intervals": 10,
        "device_elapsed_ns": 10000,
        "peak_live_bytes": 4096,
        "persistent_bytes": 4096,
        "pool_used_bytes": 4096,
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
        "entries": max(6, aot_loads),
        "loads": aot_loads,
        "cache_hits": (
            0
            if args.execution_mode == "graphs"
            else aot_loads * (args.repeat - 1)
        ),
        "misses": 0,
        "launches": (
            aot_loads
            if args.execution_mode == "graphs"
            else aot_loads * args.repeat
        ),
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
if historical_v4:
    report["schema_version"] = 4
    report.pop("execution_mode")
    report["plan"].pop("semantic_sha256")
    repetition = report["process_repetition"]
    repetition.pop("request_allocations_released")
    repetition.pop("bounded_persistent_pool_usage")
    repetition.pop("graph_cache_hits_total")
    repetition.pop("graph_cache_misses_total")
    repetition["zero_final_pool_usage"] = True
    residency = report["residency"]
    residency.pop("graph_cache_hits")
    residency.pop("graph_cache_misses")
    residency.pop("persistent_bytes")
    residency["graph_launches"] = (
        1 if os.environ.get("FAKE_V4_GRAPH_ACTIVITY") == "1" else 0
    )
    if os.environ.get("FAKE_V4_GRAPH_CACHE_FIELD") == "1":
        residency["graph_cache_hits"] = 0
    residency["pool_used_bytes"] = 0
    report["aot"]["cache_hits"] = args.repeat - 1
    report["aot"]["launches"] = args.repeat
elif historical_v5:
    report["schema_version"] = 5
    report["plan"].pop("semantic_sha256")
elif mode == "missing-execution-mode":
    report.pop("execution_mode")
elif mode == "inconsistent-graph-telemetry":
    report["residency"]["graph_cache_hits"] = 0
    report["residency"]["graph_cache_misses"] = 0
elif mode == "missing-semantic-digest":
    report["plan"].pop("semantic_sha256")
elif mode == "invalid-semantic-digest":
    report["plan"]["semantic_sha256"] = "not-a-digest"
elif mode == "invalid-aot-lifecycle":
    report["aot"]["launches"] += 1
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
        execution_mode: str = "graphs",
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
            execution_mode=execution_mode,
        )

    def test_fake_product_emits_stable_cold_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(root, self.make_product(root))
            document, encoded = run_diagnostic(settings)

            self.assertEqual(
                document["schema"],
                "native_cuda_cold_diagnostic_v3",
            )
            self.assertEqual(
                document["evidence_class"],
                "diagnostic_cold_process_plan_and_stage_attributed",
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

    def test_direct_execution_is_explicit_and_has_no_graph_activity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root),
                samples=1,
                execution_mode="direct",
            )
            document, _ = run_diagnostic(settings)

            self.assertEqual(
                "direct",
                document["measurement_contract"]["execution_mode"],
            )
            sample = document["workloads"][0]["samples"][0]
            self.assertEqual("direct", sample["execution_mode"])
            self.assertEqual(0, sample["residency"]["graph_launches"])
            self.assertEqual(
                0,
                sample["process_repetition"]["graph_cache_misses_total"],
            )

    def test_multiple_aot_functions_obey_direct_repetition_arithmetic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root),
                samples=1,
                execution_mode="direct",
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_AOT_LOADS": "2"},
            ):
                document, _ = run_diagnostic(settings)

            aot = document["workloads"][0]["samples"][0]["aot"]
            self.assertEqual(2, aot["loads"])
            self.assertEqual(2, aot["launches"])
            self.assertEqual(0, aot["cache_hits"])

    def test_state_machine_rejects_legacy_cuda_protocol(self) -> None:
        with self.assertRaisesRegex(
            DiagnosticError,
            "legacy raw-stwo-state-machine-v1.*raw-stwo-state-machine-v2",
        ):
            StateMachineShape(14, 9, 3).validate()

    def test_invalid_multi_function_aot_lifecycle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root),
                samples=1,
            )
            with mock.patch.dict(
                os.environ,
                {
                    "FAKE_CUDA_AOT_LOADS": "2",
                    "FAKE_CUDA_MODE": "invalid-aot-lifecycle",
                },
            ), self.assertRaisesRegex(DiagnosticError, "AOT lifecycle"):
                run_diagnostic(settings)

    def test_schema_v6_requires_explicit_execution_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root),
                samples=1,
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_MODE": "missing-execution-mode"},
            ), self.assertRaisesRegex(DiagnosticError, "execution_mode"):
                run_diagnostic(settings)

    def test_schema_v6_requires_consistent_graph_telemetry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root),
                samples=1,
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_MODE": "inconsistent-graph-telemetry"},
            ), self.assertRaisesRegex(DiagnosticError, "cache provenance"):
                run_diagnostic(settings)

    def test_schema_v6_requires_valid_semantic_digest(self) -> None:
        for fault in ("missing-semantic-digest", "invalid-semantic-digest"):
            with self.subTest(fault=fault):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    settings = self.settings(
                        root,
                        self.make_product(root),
                        samples=1,
                    )
                    with mock.patch.dict(
                        os.environ,
                        {"FAKE_CUDA_MODE": fault},
                    ), self.assertRaisesRegex(
                        DiagnosticError,
                        "semantic_sha256|semantic-program",
                    ):
                        run_diagnostic(settings)

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
