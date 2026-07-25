from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "benchmark_delta.py"
SPEC = importlib.util.spec_from_file_location("benchmark_delta", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)

TIMESTAMP = "2026-07-17T12:00:00Z"


def summary(value: float) -> dict[str, float]:
    return {"median": value, "min": value, "max": value, "mad": 0.0}


def native_report(commit: str, binary_suffix: str) -> dict[str, object]:
    metrics = {
        "prove_seconds": summary(2.0),
        "request_seconds": summary(2.5),
        "native_mhz": summary(3.0),
        "committed_mcells_per_second": summary(4.0),
    }
    provenance = {
        "git_commit": commit,
        "git_dirty": False,
        "zig_version": "0.15.2",
        "optimization": "ReleaseFast",
        "target_os": "macos",
        "target_arch": "aarch64",
        "cpu_count": 18,
        "simd_pack_width": 4,
        "single_threaded": False,
        "thread_parallelism_enabled": True,
        "environment_overrides": [],
        "complete": True,
    }
    row = {
        "index": 0,
        "descriptor_sha256": "1" * 64,
        "lane_order": ["cpu", "metal"],
        "workload": {
            "name": "plonk",
            "parameters": {"log_n_rows": 10},
            "trace_rows": 1024,
        },
        "proof_digest_sha256": "2" * 64,
        "proof_bytes": 4096,
        "headline_eligible": True,
        "headline_blockers": [],
        "rust_oracle": {
            "verified": True,
            "status": "passed",
            "toolchain": "nightly-2025-07-14",
            "upstream_commit": "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2",
            "binary_sha256": "f" * 64,
        },
        "lanes": {
            "cpu": {"backend": "cpu_native", "metrics": copy.deepcopy(metrics)},
            "metal": {"backend": "metal_hybrid", "metrics": copy.deepcopy(metrics)},
        },
    }
    return {
        "schema_version": 3,
        "protocol": MODULE.NATIVE_PROTOCOL,
        "generated_at": "ignored",
        "correctness_scope": {
            "classification": "pinned_rust_stwo_oracle",
            "cpu_metal_canonical_proof_equality": True,
            "pinned_rust_stwo_oracle_checked": True,
            "final_correctness_oracle": "pinned Rust Stwo",
        },
        "configuration": {
            "proof_protocol": "functional",
            "warmups_per_lane": 10,
            "samples_per_lane": 5,
            "cooldown_seconds": 1.0,
            "timeout_seconds": 120.0,
            "execution": "sequential_alternating_lane_order",
            "formal": True,
            "bounds": {"max_matrix_rows": 12},
            "binaries": {
                "cpu": {"path": "/tmp/cpu", "sha256": binary_suffix * 64},
                "metal": {"path": "/tmp/metal", "sha256": binary_suffix * 64},
            },
            "provenance": provenance,
        },
        "summary": {},
        "rows": [row],
    }


def upstream_report(prove: float, rss: int) -> dict[str, object]:
    lane = {
        "prove": {"avg_seconds": prove},
        "verify": {"avg_seconds": prove / 10},
        "peak_rss_kb": rss,
    }
    return {
        "protocol": MODULE.UPSTREAM_PROTOCOL,
        "status": "ok",
        "settings": {"warmups": 3, "repeats": 5, "rust_toolchain": "nightly"},
        "upstream_families": ["pcs"],
        "families": [
            {
                "family": "pcs",
                "mapped_workload": {
                    "example": "plonk",
                    "args": ["--log-n-rows", "10"],
                    "prove_mode": "prove",
                },
                "rust": copy.deepcopy(lane),
                "zig": copy.deepcopy(lane),
            }
        ],
    }


def write_json(path: Path, document: dict[str, object]) -> bytes:
    raw = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    path.write_bytes(raw)
    return raw


class BenchmarkDeltaTests(unittest.TestCase):
    def compare(
        self,
        directory: Path,
        baseline: dict[str, object],
        current: dict[str, object],
    ) -> dict[str, object]:
        baseline_path = directory / "baseline.json"
        current_path = directory / "current.json"
        write_json(baseline_path, baseline)
        write_json(current_path, current)
        result, _, _ = MODULE.compare_reports(
            baseline_path, current_path, TIMESTAMP
        )
        return result

    def test_native_medians_compare_while_revision_hashes_may_differ(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            baseline = native_report("a" * 40, "3")
            current = native_report("b" * 40, "4")
            for lane in ("cpu", "metal"):
                current["rows"][0]["lanes"][lane]["metrics"]["prove_seconds"] = summary(1.0)
                current["rows"][0]["lanes"][lane]["metrics"]["native_mhz"] = summary(6.0)
            result = self.compare(directory, baseline, current)

        self.assertEqual(result["status"], "comparable")
        self.assertEqual(result["generated_at"], TIMESTAMP)
        self.assertEqual(result["revisions"]["baseline"]["git_commit"], "a" * 40)
        self.assertEqual(result["revisions"]["current"]["git_commit"], "b" * 40)
        self.assertTrue(result["comparisons"][0]["evidence"]["stable_for_claim"])
        cpu_metrics = {
            metric["metric"]: metric
            for metric in result["comparisons"][0]["metrics"]
        }
        prove = cpu_metrics["prove_seconds"]
        self.assertEqual(prove["absolute_delta"], -1.0)
        self.assertEqual(prove["percent_delta"], -50.0)
        self.assertEqual(prove["improvement_percent"], 50.0)
        self.assertEqual(prove["speedup"], 2.0)
        self.assertEqual(prove["classification"], "improvement")
        self.assertEqual(prove["noise_band"], 0.0)
        mhz = cpu_metrics["native_mhz"]
        self.assertEqual(mhz["percent_delta"], 100.0)
        self.assertEqual(mhz["improvement_percent"], 100.0)
        self.assertEqual(mhz["speedup"], 2.0)
        self.assertEqual(mhz["classification"], "improvement")
        for metric in cpu_metrics.values():
            self.assertTrue(metric["stable_for_claim"])
            self.assertEqual(metric["evidence_class"], "headline")
            self.assertTrue(
                {
                    "baseline",
                    "current",
                    "absolute_delta",
                    "percent_delta",
                    "improvement_percent",
                    "speedup",
                }.issubset(metric)
            )

    def test_native_semantic_or_sampling_drift_is_explicitly_incomparable(self) -> None:
        for mutation, expected in (
            (
                lambda report: report["rows"][0].__setitem__(
                    "proof_digest_sha256", "9" * 64
                ),
                "proof identity differs",
            ),
            (
                lambda report: report["configuration"].__setitem__(
                    "samples_per_lane", 21
                ),
                "sampling settings differ",
            ),
            (
                lambda report: report["rows"][0].__setitem__(
                    "descriptor_sha256", "8" * 64
                ),
                "descriptor/order differs",
            ),
            (
                lambda report: report["rows"][0]["rust_oracle"].__setitem__(
                    "binary_sha256", "7" * 64
                ),
                "Rust oracle contract differs",
            ),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as raw_directory:
                baseline = native_report("a" * 40, "3")
                current = native_report("b" * 40, "4")
                mutation(current)
                result = self.compare(Path(raw_directory), baseline, current)
                self.assertEqual(result["status"], "incomparable")
                self.assertEqual(result["comparisons"], [])
                self.assertIn(expected, result["incompatibilities"][0])

    def test_state_machine_v1_and_v2_evidence_cannot_compare(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            baseline = native_report("a" * 40, "3")
            current = native_report("b" * 40, "4")
            state_workload = {
                "name": "state_machine",
                "parameters": {
                    "log_n_rows": 10,
                    "initial_x": 9,
                    "initial_y": 3,
                },
                "trace_rows": 1024,
            }
            baseline["rows"][0]["workload"] = copy.deepcopy(state_workload)
            current["rows"][0]["workload"] = copy.deepcopy(state_workload)
            baseline["rows"][0]["descriptor_sha256"] = (
                "2aef739c7447cb192da8648b7a4b539cc"
                "b86c1f532de7de986287cb89844b8a7"
            )
            current["rows"][0]["descriptor_sha256"] = (
                "90501fb81745fd984bd8186e5750f9b7"
                "ff6bf2017b0df4df869f313299b771e9"
            )
            result = self.compare(Path(raw_directory), baseline, current)
        self.assertEqual(result["status"], "incomparable")
        self.assertIn("descriptor/order differs", result["incompatibilities"][0])

    def test_native_unstable_rows_retain_deltas_as_diagnostic_only(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            baseline = native_report("a" * 40, "3")
            current = native_report("b" * 40, "4")
            baseline["rows"][0]["headline_eligible"] = False
            baseline["rows"][0]["headline_blockers"] = [
                "cpu_ordered_prove_time_drift"
            ]
            result = self.compare(Path(raw_directory), baseline, current)
        self.assertEqual(result["status"], "comparable")
        self.assertEqual(result["comparison_summary"]["diagnostic_only_rows"], [0])
        evidence = result["comparisons"][0]["evidence"]
        self.assertFalse(evidence["stable_for_claim"])
        self.assertEqual(
            evidence["baseline"]["headline_blockers"],
            ["cpu_ordered_prove_time_drift"],
        )
        for comparison in result["comparisons"]:
            for metric in comparison["metrics"]:
                self.assertFalse(metric["stable_for_claim"])
                self.assertEqual(metric["evidence_class"], "diagnostic_only")
                self.assertEqual(metric["classification"], "diagnostic_unstable")

    def test_native_change_inside_combined_mad_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            baseline = native_report("a" * 40, "3")
            current = native_report("b" * 40, "4")
            baseline_prove = baseline["rows"][0]["lanes"]["cpu"]["metrics"][
                "prove_seconds"
            ]
            current_prove = current["rows"][0]["lanes"]["cpu"]["metrics"][
                "prove_seconds"
            ]
            baseline_prove["mad"] = 0.08
            current_prove.update({"median": 1.9, "min": 1.9, "max": 1.9, "mad": 0.04})
            result = self.compare(Path(raw_directory), baseline, current)
        metric = next(
            metric
            for metric in result["comparisons"][0]["metrics"]
            if metric["metric"] == "prove_seconds"
        )
        self.assertAlmostEqual(metric["noise_band"], 0.12)
        self.assertAlmostEqual(metric["absolute_delta"], -0.1)
        self.assertEqual(metric["classification"], "inconclusive")

    def test_upstream_family_lanes_compare_time_and_rss(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            result = self.compare(
                Path(raw_directory), upstream_report(2.0, 1000), upstream_report(1.0, 800)
            )
        self.assertEqual(result["status"], "comparable")
        self.assertEqual(len(result["comparisons"]), 2)
        metrics = {
            metric["metric"]: metric
            for metric in result["comparisons"][1]["metrics"]
        }
        self.assertEqual(metrics["prove_avg_seconds"]["speedup"], 2.0)
        self.assertEqual(metrics["peak_rss_kb"]["improvement_percent"], 20.0)
        self.assertEqual(metrics["prove_avg_seconds"]["classification"], "unclassified")

    def test_archive_is_content_addressed_and_preserves_prior_runs(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            baseline_path = directory / "baseline.json"
            current_path = directory / "current.json"
            output_path = directory / "delta.json"
            archive_dir = directory / "archive"
            baseline_raw = write_json(baseline_path, upstream_report(2.0, 1000))
            first_current_raw = write_json(current_path, upstream_report(1.0, 800))
            self.assertEqual(
                MODULE.main(
                    [
                        "--baseline",
                        str(baseline_path),
                        "--current",
                        str(current_path),
                        "--output",
                        str(output_path),
                        "--archive-dir",
                        str(archive_dir),
                        "--timestamp",
                        "2026-07-17T12:00:00Z",
                    ]
                ),
                0,
            )
            second_current_raw = write_json(current_path, upstream_report(0.5, 700))
            self.assertEqual(
                MODULE.main(
                    [
                        "--baseline",
                        str(baseline_path),
                        "--current",
                        str(current_path),
                        "--output",
                        str(output_path),
                        "--archive-dir",
                        str(archive_dir),
                        "--timestamp",
                        "2026-07-18T12:00:00Z",
                    ]
                ),
                0,
            )
            index = json.loads((archive_dir / "index.json").read_text())
            self.assertEqual(len(index["artifacts"]), 3)
            self.assertEqual(len(index["deltas"]), 2)
            self.assertEqual(len(index["comparisons"]), 2)
            for raw in (baseline_raw, first_current_raw, second_current_raw):
                digest = hashlib.sha256(raw).hexdigest()
                artifact = archive_dir / index["artifacts"][digest]["path"]
                self.assertEqual(artifact.read_bytes(), raw)
            for comparison in index["comparisons"]:
                delta_path = archive_dir / comparison["delta_path"]
                delta_raw = delta_path.read_bytes()
                self.assertEqual(
                    hashlib.sha256(delta_raw).hexdigest(), comparison["delta_sha256"]
                )
                self.assertNotIn("archive", json.loads(delta_raw))

    def test_cli_writes_incomparable_report_and_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            baseline_path = directory / "baseline.json"
            current_path = directory / "current.json"
            output_path = directory / "delta.json"
            write_json(baseline_path, native_report("a" * 40, "3"))
            current = native_report("b" * 40, "4")
            current["rows"][0]["proof_bytes"] = 8192
            write_json(current_path, current)
            exit_code = MODULE.main(
                [
                    "--baseline",
                    str(baseline_path),
                    "--current",
                    str(current_path),
                    "--output",
                    str(output_path),
                    "--timestamp",
                    TIMESTAMP,
                ]
            )
            result = json.loads(output_path.read_text())
        self.assertEqual(exit_code, 2)
        self.assertEqual(result["status"], "incomparable")
        self.assertEqual(result["comparisons"], [])


if __name__ == "__main__":
    unittest.main()
