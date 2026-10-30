"""Boundary validation for the daily benchmark runner; no prover invocation."""
from __future__ import annotations

import contextlib
import csv
import io
import json
import importlib.util
from pathlib import Path
import tempfile
import unittest

FILE = Path(__file__).resolve().parents[1] / "benchmark_riscv_ethereum.py"
SPEC = importlib.util.spec_from_file_location("daily_ethereum", FILE)
bench = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench)


def node(name, seconds, children=None):
    return {"id": name, "label": name, "seconds": seconds, "children": children}


def valid_report():
    core = node("multi_core_proof", 1, [
        node("composition_evaluation", .4), node("sampled_value_evaluation", .1),
        node("fri_quotient_build_and_commit", .2), node("trace_decommit", .1)])
    profile = {"schema_version": 1, "stages": [node("request", 3, [
        node("multi_prove", 2, [core]), node("serialization", .1),
        node("independent_verification", .5)])]}
    return {"schema": 1, "workload": "memory_heavy", "iterations": 64,
            "source": "synthetic_complete_execution", "verified": True, "producers_destroyed": True,
            "canonical_security": True, "query_count": 70, "pow_bits": 26,
            "oracle_enabled": False, "oracle_ns": 0, "recursive_reduction_ns": None,
            "end_to_end_ns": 3_000_000_000, "prove_ns": 2_000_000_000, "verification_ns": 500_000_000,
            "setup_ns": 100_000_000, "cycles": 526, "native_windows": 4, "window_cut": 132,
            "caller_windows": 0, "ram_events": 128, "checkpoint_read_bytes": 0, "checkpoint_write_bytes": 0,
            "proof_bytes": 1234, "tracked_peak_bytes": 12345, "process_peak_rss_bytes": 123456,
            "elf_sha256": "a" * 64, "proof_sha256": "b" * 64,
            "producer_stats": {"union_allocator_peak_cumulative": 12345}, "profile": profile}


class Validation(unittest.TestCase):
    def test_deep_group_budget_requires_attestation_and_separate_rankings(self):
        report = valid_report()
        with self.assertRaises(bench.InvalidReport):
            bench.validate_report(report, "memory_heavy", 64, None, deep_group_mib=4)
        for cap in (1, 4, 8):
            report["deep_group_mib"] = cap
            bench.validate_report(report, "memory_heavy", 64, None, deep_group_mib=cap)
            _, settings = bench.environment("memory_heavy", 64, Path("/report.json"), 4, None, deep_group_mib=cap)
            self.assertEqual(settings["STWO_PCS_DEEP_GROUP_MIB"], str(cap))
        for bad in (0, 2, 3, 16, True, "4"):
            report["deep_group_mib"] = bad
            with self.assertRaises(bench.InvalidReport):
                bench.validate_report(report, "memory_heavy", 64, None, deep_group_mib=4)
        rows = [{"workload": "mixed_ethereum", "iterations": 8, "window_cut": 8204,
                 "deep_group_mib": cap, "run_id": str(cap), "stage_id": "fri_quotient_build_and_commit",
                 "exclusive_seconds": seconds} for cap, seconds in ((1, 4), (4, 1))]
        ranked = bench.rankings(rows)
        self.assertEqual({r["deep_group_mib"]: r["median_exclusive_seconds"] for r in ranked}, {1: 4, 4: 1})
        self.assertTrue(all(r["runs"] == 1 for r in ranked))

    def test_cache_budget_requires_matching_report_and_does_not_pool(self):
        report = valid_report()
        bench.validate_report(report, "memory_heavy", 64, None)
        with self.assertRaises(bench.InvalidReport):
            bench.validate_report(report, "memory_heavy", 64, None, native_main_cache_mib=1024)
        for cap in (0, 256, 1024, 2048):
            report["native_main_cache_mib"] = cap
            bench.validate_report(report, "memory_heavy", 64, None, native_main_cache_mib=cap)
            _, settings = bench.environment("memory_heavy", 64, Path("/report.json"), 4, None, native_main_cache_mib=cap)
            self.assertEqual(settings["STWO_V7_NATIVE_MAIN_CACHE_MIB"], str(cap))
        for bad in (-1, 2049, True, "256"):
            report["native_main_cache_mib"] = bad
            with self.assertRaises(bench.InvalidReport):
                bench.validate_report(report, "memory_heavy", 64, None)
        rows = [{"workload": "mixed_ethereum", "iterations": 8, "window_cut": 8204,
                 "native_main_cache_mib": cap, "run_id": str(cap), "stage_id": "composition_evaluation",
                 "exclusive_seconds": seconds} for cap, seconds in ((256, 4), (1024, 1))]
        ranked = bench.rankings(rows)
        self.assertEqual({r["native_main_cache_mib"]: r["median_exclusive_seconds"] for r in ranked}, {256: 4, 1024: 1})
        self.assertTrue(all(r["runs"] == 1 for r in ranked))

    def test_worker_admission_distinguishes_legacy_four_worker_binary(self):
        report = valid_report()
        bench.validate_report(report, "memory_heavy", 64, None, workers=4)
        with self.assertRaises(bench.InvalidReport):
            bench.validate_report(report, "memory_heavy", 64, None, workers=8)
        report["worker_count"] = 8
        bench.validate_report(report, "memory_heavy", 64, None, workers=8)
        for invalid in (0, 33, True, "8"):
            report["worker_count"] = invalid
            with self.assertRaises(bench.InvalidReport):
                bench.validate_report(report, "memory_heavy", 64, None, workers=8)
        _, settings = bench.environment("memory_heavy", 64, Path("/report.json"), 4, None, workers=8)
        self.assertEqual(settings["STWO_V7_BENCH_WORKERS"], "8")

    def test_rankings_do_not_pool_distinct_worker_counts(self):
        rows = [{"workload": "mixed_ethereum", "iterations": 8, "window_cut": 8204,
                 "worker_count": workers, "run_id": str(workers), "stage_id": "composition_evaluation",
                 "exclusive_seconds": seconds} for workers, seconds in ((1, 4), (8, 1))]
        ranked = bench.rankings(rows)
        self.assertEqual({r["worker_count"]: r["median_exclusive_seconds"] for r in ranked}, {1: 4, 8: 1})
        self.assertTrue(all(r["runs"] == 1 for r in ranked))

    def test_complete_partition_sums_exclusive_not_inclusive(self):
        rows = bench.validate_report(valid_report(), "memory_heavy", 64, None)
        self.assertAlmostEqual(sum(row["exclusive_seconds"] for row in rows), 3)
        self.assertGreater(sum(row["inclusive_seconds"] for row in rows), 3)
        self.assertTrue(next(row for row in rows if row["stage_id"] == "trace_decommit")["is_leaf"])

    def test_changed_authority_and_missing_measurements_reject(self):
        for key, value in [("verified", False), ("producers_destroyed", False), ("canonical_security", False),
                           ("query_count", 8), ("pow_bits", 0), ("oracle_enabled", True), ("oracle_ns", 1),
                           ("recursive_reduction_ns", 0), ("source", "ethereum_block"), ("iterations", 65),
                           ("window_cut", 7), ("tracked_peak_bytes", True), ("end_to_end_ns", -1),
                           ("proof_sha256", "z" * 64), ("producer_stats", None)]:
            with self.subTest(key=key):
                report = valid_report()
                report[key] = value
                with self.assertRaises(bench.InvalidReport):
                    bench.validate_report(report, "memory_heavy", 64, None)
        report = valid_report()
        del report["profile"]["stages"][0]["children"][2]
        with self.assertRaises(bench.InvalidReport):
            bench.validate_report(report, "memory_heavy", 64, None)

    def test_shared_architecture_requires_explicit_contract_and_stage_boundary(self):
        report = valid_report()
        report.update(workload="keccak_heavy", architecture="shared_keccak", proof_contract="original_complete_stark",
                      statement_sha256="c" * 64, output_sha256="d" * 64, program_fetches=529,
                      memory_event_limit=1048576, events_per_ram_shard=4096)
        root = report["profile"]["stages"][0]
        root["children"][0]["id"] = "keccak_union_prove"
        root["children"][0]["children"][0]["id"] = "keccak_union_core_proof"
        bench.validate_report(report, "keccak_heavy", 64, None, shared_keccak=True)
        with self.assertRaises(bench.InvalidReport):
            bench.validate_report(report, "keccak_heavy", 64, None)
        report["proof_contract"] = "partial_scoped_proof"
        with self.assertRaises(bench.InvalidReport):
            bench.validate_report(report, "keccak_heavy", 64, None, shared_keccak=True)
        env, _ = bench.environment("keccak_heavy", 8, Path("/report.json"), 4, None, True)
        self.assertEqual(env["STWO_V7_BENCH_SHARED_KECCAK"], "1")

    def test_stage_overlap_and_nonfinite_durations_reject(self):
        for duration in [-1, float("nan"), float("inf"), True]:
            with self.assertRaises(bench.InvalidReport):
                bench.stage_rows({"schema_version": 1, "stages": [node("bad", duration)]})
        with self.assertRaises(bench.InvalidReport):
            bench.stage_rows({"schema_version": 1, "stages": [node("parent", 1, [node("a", .7), node("b", .7)])]})
        rows = bench.stage_rows({"schema_version": 1, "stages": [node("parent", 1, [node("a", .500001), node("b", .5)])]})
        self.assertGreater(rows[-1]["rounding_clamp_seconds"], 0)
        self.assertEqual(rows[-1]["exclusive_seconds"], 0)

    def test_repeated_stage_ids_keep_distinct_paths_and_group_per_run(self):
        profile = {"schema_version": 1, "stages": [node("parent", 3, [node("native", 1), node("native", 2)])]}
        rows = bench.stage_rows(profile)
        self.assertEqual(len({r["stage_path"] for r in rows}), len(rows))
        for row in rows:
            row.update(workload="memory_heavy", iterations=64, window_cut=132, run_id="one")
        ranked = bench.rankings(rows)
        self.assertEqual(next(r for r in ranked if r["stage_id"] == "native")["median_exclusive_seconds"], 3)
        self.assertEqual(next(r for r in ranked if r["stage_id"] == "parent")["median_exclusive_seconds"], 0)

    def test_environment_does_not_inherit_hidden_fixture_flags(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"STWO_V7_MULTI_UNION_ISOLATE_CALLERS": "1", "STWO_BAD": "1"}):
            env, declared = bench.environment("memory_heavy", 64, Path("/report.json"), 4, None)
        self.assertNotIn("STWO_BAD", env)
        self.assertNotIn("STWO_V7_MULTI_UNION_ISOLATE_CALLERS", env)
        self.assertEqual(env["STWO_V7_MULTI_UNION_CANONICAL"], "1")
        self.assertEqual({k: v for k, v in env.items() if k.startswith("STWO_")}, declared)

    def test_csv_preserves_failed_rows_and_null_recursion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "runs.csv"
            bench.write_csv(path, [{"run_id": "ok", "status": "passed", "recursive_reduction_ns": None},
                                   {"run_id": "bad", "status": "failed", "error": "timeout"}], ("run_id", "status"))
            text = path.read_text()
            self.assertIn("bad,failed", text)
            self.assertIn("timeout", text)
            self.assertNotIn("recursive_reduction_ns,0", text)

    def test_campaign_persists_failure_then_success_without_fabricated_source(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            binary = parent / "existing-binary"
            binary.write_text("external executable fixture")
            binary.chmod(0o700)
            out = parent / "campaign"
            calls = []

            def fake_execute(command, log, env, timeout):
                calls.append(command)
                log.write_text("bounded fixture run\n")
                if len(calls) == 2:
                    Path(env["STWO_V7_BENCH_REPORT"]).write_text(json.dumps(valid_report()))
                return {"process_status": "completed", "returncode": 1 if len(calls) == 1 else 0,
                        "command_wall_seconds": 4, "process_error": None}

            with patch.object(bench, "source_manifest", return_value={"source_sha256": "c" * 64, "head": "d" * 40}), \
                 patch.object(bench, "machine", return_value={"os": "test"}), \
                 patch.object(bench, "execute", side_effect=fake_execute), contextlib.redirect_stdout(io.StringIO()):
                status = bench.main(["--binary", str(binary), "--out", str(out), "--case", "memory_heavy:64",
                                     "--repeats", "2", "--lock", str(parent / "lock")])
            self.assertEqual(status, 1)
            with (out / "runs.csv").open() as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([r["status"] for r in rows], ["failed", "passed"])
            self.assertTrue(all(r["source_sha256"] == "" for r in rows))
            self.assertTrue(all(r["binary_source_binding"] == "external_unattested" for r in rows))
            self.assertEqual(json.loads((out / "manifest.json").read_text())["failed_runs"], 1)
            run = json.loads((out / "00-memory_heavy-64-r02" / "run.json").read_text())
            self.assertEqual(run["status"], "passed")
            self.assertTrue((out / "stage-rankings.csv").is_file())


if __name__ == "__main__":
    unittest.main()
