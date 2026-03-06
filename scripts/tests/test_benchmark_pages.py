#!/usr/bin/env python3
"""Unit tests for fib5000 benchmark page flow payloads."""

from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "benchmark_pages.py"


def load_module():
    spec = importlib.util.spec_from_file_location("benchmark_pages", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage(stage_id: str, seconds: float, children: list[dict] | None = None) -> dict:
    payload = {
        "id": stage_id,
        "label": stage_id.replace("_", " "),
        "seconds": seconds,
    }
    if children:
        payload["children"] = children
    return payload


class BenchmarkPagesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_module()
        self.family_report = {
            "status": "ok",
            "summary": {},
            "families": [],
        }
        rust_top = [
            stage("channel_and_scheme_init", 0.10),
            stage("preprocessed_commit", 0.02),
            stage("trace_generation", 0.30),
            stage("main_trace_commit", 0.40),
            stage("statement_mix", 0.01),
            stage("core_prove", 0.90),
            stage("proof_wire_encode", 0.03),
            stage("artifact_write", 0.02),
        ]
        zig_top = [
            stage("channel_and_scheme_init", 0.12),
            stage("preprocessed_commit", 0.03),
            stage("trace_generation", 0.34),
            stage(
                "main_trace_commit",
                0.55,
                [
                    stage("interpolate_columns", 0.19),
                    stage("evaluate_extended_domain", 0.22),
                    stage("merkle_commit", 0.14),
                ],
            ),
            stage("statement_mix", 0.01),
            stage(
                "core_prove",
                1.15,
                [
                    stage("draw_random_coeff", 0.01),
                    stage("composition_trace_extract", 0.06),
                    stage("composition_evaluation", 0.09),
                    stage("composition_interpolate_and_split", 0.12),
                    stage("composition_commit", 0.11),
                    stage("oods_point_and_mask_points", 0.08),
                    stage("sampled_value_evaluation", 0.24),
                    stage("sampled_value_channel_mix", 0.01),
                    stage("fri_quotient_build", 0.16),
                    stage("fri_commit", 0.08),
                    stage("proof_of_work", 0.0),
                    stage("fri_decommit", 0.05),
                    stage("trace_decommit", 0.10),
                    stage("constraint_check_and_assembly", 0.05),
                ],
            ),
            stage("proof_wire_encode", 0.05),
            stage("artifact_write", 0.02),
        ]
        self.examples_report = {
            "status": "ok",
            "summary": {},
            "workloads": [
                {
                    "name": "wide_fibonacci_fib5000",
                    "example": "wide_fibonacci",
                    "rust": {
                        "prove": {
                            "avg_seconds": 1.78,
                            "rss_peak_kb": 1000,
                            "stage_flow": {
                                "schema_version": 1,
                                "runtime": "rust",
                                "example": "wide_fibonacci",
                                "stages": rust_top,
                            },
                        },
                        "verify": {"avg_seconds": 0.01, "rss_peak_kb": 100},
                    },
                    "zig": {
                        "prove": {
                            "avg_seconds": 2.27,
                            "rss_peak_kb": 1400,
                            "stage_flow": {
                                "schema_version": 1,
                                "runtime": "zig",
                                "example": "wide_fibonacci",
                                "stages": zig_top,
                            },
                        },
                        "verify": {"avg_seconds": 0.01, "rss_peak_kb": 110},
                    },
                    "ratios": {
                        "zig_over_rust_prove": 1.275281,
                        "zig_over_rust_verify": 1.0,
                        "zig_over_rust_proof_wire_bytes": 1.0,
                    },
                }
            ],
        }

    def test_build_payload_includes_fib5000_flow(self) -> None:
        payload = self.mod.build_payload(
            self.family_report,
            ROOT / "vectors" / "reports" / "benchmark_full_report.json",
            self.examples_report,
            ROOT / "vectors" / "reports" / "benchmark_contrast_long_report.json",
        )
        self.assertEqual(payload["schema_version"], 3)
        flow = payload["fib5000_flow"]
        self.assertEqual(flow["workload"], "wide_fibonacci_fib5000")
        self.assertEqual(
            [row["id"] for row in flow["top_level_rows"]],
            self.mod.FLOW_TOP_LEVEL_STAGE_IDS,
        )
        self.assertEqual(
            [row["id"] for row in flow["zig_main_trace_commit"]],
            self.mod.FLOW_MAIN_TRACE_STAGE_IDS,
        )
        self.assertEqual(
            [row["id"] for row in flow["zig_core_prove"]],
            self.mod.FLOW_CORE_PROVE_STAGE_IDS,
        )

    def test_missing_fib5000_stage_flow_raises(self) -> None:
        broken_report = copy.deepcopy(self.examples_report)
        del broken_report["workloads"][0]["zig"]["prove"]["stage_flow"]
        with self.assertRaisesRegex(RuntimeError, "fib5000 stage flow"):
            self.mod.build_payload(
                self.family_report,
                ROOT / "vectors" / "reports" / "benchmark_full_report.json",
                broken_report,
                ROOT / "vectors" / "reports" / "benchmark_contrast_long_report.json",
            )


if __name__ == "__main__":
    unittest.main()
