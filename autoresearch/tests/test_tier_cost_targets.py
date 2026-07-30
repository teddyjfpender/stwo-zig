"""Tier cost targets are CI-checked per track (TRACKS §3.6).

This module is also the CI wiring for scripts/check_tier_cost_targets.py: the
autoresearch-validate workflow runs `python3 -m unittest discover -s
autoresearch/tests`, so `test_repository_is_within_its_tier_cost_targets`
enforces the targets on every PR without an extra workflow step.
"""

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from scripts.check_tier_cost_targets import (  # noqa: E402
    T0_SCHEMA,
    T1_SCHEMA,
    TierCostError,
    collect_observations,
    evaluate,
    load_policy,
    main,
)


def ladder_manifest() -> dict:
    return {
        "gates_policy": {
            "confirmation_ladder": {
                "tiers": {
                    "T0": {"cost_target_seconds": 30},
                    "T1": {"cost_target_seconds": 300},
                    "T2": {"cost_target_seconds": 2700},
                    "T3": {"cost_target_seconds": None},
                },
                "cost_telemetry": {"statistic": "median", "window": 5},
            },
        },
        "workload_registry": {
            "groups": {
                "native": {"board": "core_cpu"},
                "cairo": {"board": "cairo_cpu"},
            },
        },
    }


class TierCostTargetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "autoresearch").mkdir()
        self.write_manifest(ladder_manifest())
        self.telemetry = self.root / "autoresearch" / "submissions"
        self.telemetry.mkdir()

    def write_manifest(self, document: dict) -> None:
        (self.root / "autoresearch" / "MANIFEST.json").write_text(
            json.dumps(document), encoding="utf-8",
        )

    def write_ladder_doc(self, name: str, schema: str, board: str,
                         seconds: float) -> None:
        (self.telemetry / name).write_text(json.dumps({
            "schema": schema,
            "tier": "T1" if schema == T1_SCHEMA else "T0",
            "board": board,
            "workload_class": "small",
            "measurement_seconds": seconds,
        }), encoding="utf-8")

    def write_verdict(self, name: str, board: str, seconds: float,
                      kind: str = "claimed") -> None:
        (self.telemetry / name).write_text(json.dumps({
            "schema_version": 1,
            "kind": kind,
            "declared_objective": {
                "board": board, "workload_class": "small", "dimension": "time",
            },
            "score": {"portfolio": {"measurement_seconds": seconds}},
        }), encoding="utf-8")

    def run_main(self, *argv) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = main(["--repo-root", str(self.root), *argv])
        return code, buffer.getvalue()

    def test_absent_telemetry_passes_with_a_loud_note(self):
        code, output = self.run_main()
        self.assertEqual(0, code)
        self.assertIn("core_cpu T1 has no recorded telemetry yet", output)
        self.assertIn("cairo_cpu T2 has no recorded telemetry yet", output)
        self.assertIn("passing an unmeasured track", output)

    def test_tier_within_its_target_passes(self):
        for index in range(3):
            self.write_ladder_doc(f"t1-{index}.json", T1_SCHEMA, "core_cpu", 120.0)
        code, output = self.run_main()
        self.assertEqual(0, code)
        self.assertIn("ok core_cpu T1", output)

    def test_tier_over_its_target_fails_closed(self):
        for index in range(3):
            self.write_ladder_doc(f"t1-{index}.json", T1_SCHEMA, "core_cpu", 600.0)
        code, output = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("core_cpu T1 exceeds its 300s target", output)
        self.assertIn("shrink the proxy, not the honesty", output)

    def test_one_slow_outlier_does_not_condemn_a_track(self):
        for index in range(4):
            self.write_ladder_doc(f"t1-{index}.json", T1_SCHEMA, "core_cpu", 100.0)
        self.write_ladder_doc("t1-9.json", T1_SCHEMA, "core_cpu", 5000.0)
        code, output = self.run_main()
        self.assertEqual(0, code)
        self.assertIn("worst=5000.0s", output)

    def test_t0_and_t2_tiers_are_checked_independently(self):
        for index in range(3):
            self.write_ladder_doc(f"t0-{index}.json", T0_SCHEMA, "cairo_cpu", 90.0)
            self.write_verdict(f"v-{index}.json", "cairo_cpu", 100.0)
        code, output = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("cairo_cpu T0 exceeds its 30s target", output)
        self.assertIn("ok cairo_cpu T2", output)

    def test_judged_tier_has_no_cost_target(self):
        for index in range(3):
            self.write_verdict(f"j-{index}.json", "core_cpu", 99999.0, kind="judged")
        code, output = self.run_main()
        self.assertEqual(0, code)
        self.assertNotIn("T3", output)

    def test_tracks_are_enumerated_from_the_manifest_groups(self):
        policy = load_policy(self.root)
        self.assertEqual(["cairo_cpu", "core_cpu"], policy["tracks"])

    def test_unregistered_ladder_fails_closed(self):
        self.write_manifest({"gates_policy": {}, "workload_registry": {"groups": {}}})
        code, output = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("not registered", output)

    def test_extra_telemetry_directories_are_scanned(self):
        extra = self.root / "elsewhere"
        extra.mkdir()
        (extra / "t1.json").write_text(json.dumps({
            "schema": T1_SCHEMA,
            "board": "core_cpu",
            "measurement_seconds": 400.0,
        }), encoding="utf-8")
        code, _ = self.run_main()
        self.assertEqual(0, code)
        code, output = self.run_main("--telemetry-dir", str(extra))
        self.assertEqual(1, code)
        self.assertIn("core_cpu T1 exceeds", output)

    def test_unrelated_json_is_ignored(self):
        (self.telemetry / "note.json").write_text(
            json.dumps({"hello": "world"}), encoding="utf-8",
        )
        (self.telemetry / "broken.json").write_text("{not json", encoding="utf-8")
        self.assertEqual({}, collect_observations(self.root))

    def test_report_is_written_when_requested(self):
        self.write_ladder_doc("t1.json", T1_SCHEMA, "core_cpu", 42.0)
        report_path = self.root / "report" / "tier-costs.json"
        code, _ = self.run_main("--report", str(report_path))
        self.assertEqual(0, code)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual("stwo_perf_tier_cost_report_v1", report["schema"])
        rows = {(row["track"], row["tier"]): row for row in report["rows"]}
        self.assertAlmostEqual(42.0, rows[("core_cpu", "T1")]["statistic"])
        self.assertEqual([], report["violations"])

    def test_max_statistic_is_supported(self):
        document = ladder_manifest()
        ladder = document["gates_policy"]["confirmation_ladder"]
        ladder["cost_telemetry"]["statistic"] = "max"
        self.write_manifest(document)
        for index in range(4):
            self.write_ladder_doc(f"t1-{index}.json", T1_SCHEMA, "core_cpu", 10.0)
        self.write_ladder_doc("t1-9.json", T1_SCHEMA, "core_cpu", 600.0)
        code, output = self.run_main()
        self.assertEqual(1, code)
        self.assertIn("core_cpu T1 exceeds", output)

    def test_malformed_cost_telemetry_is_refused(self):
        document = ladder_manifest()
        document["gates_policy"]["confirmation_ladder"]["cost_telemetry"] = {
            "statistic": "mean", "window": 5,
        }
        self.write_manifest(document)
        with self.assertRaises(TierCostError):
            load_policy(self.root)

    def test_window_bounds_the_recency_slice(self):
        policy = load_policy(self.root)
        observations = {("core_cpu", "T1"): [
            (f"run-{index}", float(index)) for index in range(20)
        ]}
        report = evaluate(policy, observations)
        row = next(
            row for row in report["rows"]
            if (row["track"], row["tier"]) == ("core_cpu", "T1")
        )
        self.assertEqual(5, row["observations"])
        self.assertAlmostEqual(17.0, row["statistic"])


class RepositoryTierCostTest(unittest.TestCase):
    """The check itself, over the real repository (§3.6 acceptance)."""

    def test_repository_is_within_its_tier_cost_targets(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(buffer):
            code = main(["--repo-root", str(REPO_ROOT), "--quiet-absent"])
        self.assertEqual(0, code, buffer.getvalue())

    def test_recorded_verdict_telemetry_is_actually_found(self):
        observations = collect_observations(REPO_ROOT)
        t2_tracks = {
            track for (track, tier) in observations if tier == "T2"
        }
        self.assertIn("core_cpu", t2_tracks)
        self.assertIn("riscv", t2_tracks)


if __name__ == "__main__":
    unittest.main()
