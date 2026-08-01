#!/usr/bin/env python3
"""Tests for the formal benchmark publication catalog and authored shell."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.benchmark_pages_lib.catalog import CatalogError, build_catalog
from scripts.benchmark_pages_lib.controller import encoded_json, run


ROOT = Path(__file__).resolve().parents[2]
HISTORY = ROOT / "vectors" / "reports" / "benchmark_history"
LATEST = (
    HISTORY
    / "runs"
    / "2026-07-20-221601-matrix-v6-e78cca6f"
    / "report.json"
)


class BenchmarkPagesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = json.loads(LATEST.read_text(encoding="utf-8"))

    def write_history(self, root: Path, report: dict | None = None) -> Path:
        report = copy.deepcopy(report or self.report)
        history = root / "history"
        report_path = history / "runs" / "formal-run" / "report.json"
        report_path.parent.mkdir(parents=True)
        raw = encoded_json(report)
        report_path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        index = {
            "schema_version": 2,
            "runs": {
                "formal-run": {
                    "kind": report["protocol"],
                    "report": {
                        "path": "runs/formal-run/report.json",
                        "sha256": digest,
                        "bytes": len(raw),
                    },
                    "bundle": None,
                    "deltas": [],
                }
            },
            "artifacts": {
                digest: {
                    "path": "runs/formal-run/report.json",
                    "sha256": digest,
                    "bytes": len(raw),
                    "run": "formal-run",
                }
            },
            "deltas": {},
            "bundles": {},
            "comparisons": [],
        }
        (history / "index.json").write_bytes(encoded_json(index))
        return history

    def append_run(
        self,
        history: Path,
        run_id: str,
        report: dict,
        **entry_fields: object,
    ) -> None:
        report_path = history / "runs" / run_id / "report.json"
        report_path.parent.mkdir(parents=True)
        raw = encoded_json(report)
        report_path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        index_path = history / "index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        index["runs"][run_id] = {
            "kind": report["protocol"],
            "report": {
                "path": f"runs/{run_id}/report.json",
                "sha256": digest,
                "bytes": len(raw),
            },
            "bundle": None,
            "deltas": [],
            **entry_fields,
        }
        index["artifacts"][digest] = {
            "path": f"runs/{run_id}/report.json",
            "bytes": len(raw),
            "run": run_id,
        }
        index_path.write_bytes(encoded_json(index))

    def test_real_history_publishes_only_complete_runs(self) -> None:
        catalog = build_catalog(HISTORY)
        index = json.loads((HISTORY / "index.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["schema"], "stwo_benchmark_catalog_v1")
        self.assertEqual(
            len(catalog["runs"]) + len(catalog["excluded_runs"]),
            len(index["runs"]),
        )
        self.assertGreater(len(catalog["runs"]), 0)
        latest = catalog["runs"][0]
        self.assertEqual(
            latest["captured_at"],
            max(run["captured_at"] for run in catalog["runs"]),
        )
        self.assertEqual(latest["machine"]["chip"], "Apple M5 Max")
        expected_verified = sum(
            row["lanes"][lane]["proof"]["verified_samples"]
            for row in latest["rows"]
            for lane in ("cpu", "metal")
        )
        self.assertEqual(latest["summary"]["verified_proofs"], expected_verified)
        self.assertTrue(all(row["proof"]["rust_oracle_verified"] for row in latest["rows"]))

    def test_catalog_generation_is_deterministic(self) -> None:
        self.assertEqual(encoded_json(build_catalog(HISTORY)), encoded_json(build_catalog(HISTORY)))

    def test_missing_or_explicit_active_status_is_publishable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            history = self.write_history(Path(temporary))
            catalog = build_catalog(history)
            self.assertEqual(catalog["latest_run_id"], "formal-run")

            index_path = history / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["runs"]["formal-run"]["status"] = "active"
            index_path.write_bytes(encoded_json(index))
            catalog = build_catalog(history)
            self.assertEqual(catalog["latest_run_id"], "formal-run")

    def test_invalidated_and_superseded_runs_are_retained_but_not_published(self) -> None:
        for status in ("invalidated", "superseded"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                history = self.write_history(Path(temporary))
                report = copy.deepcopy(self.report)
                report["generated_at"] = "2030-01-01T00:00:00+00:00"
                fields: dict[str, object] = {
                    "status": status,
                    "status_reason": f"{status} by benchmark correction",
                }
                if status == "superseded":
                    fields["superseded_by"] = "formal-run"
                self.append_run(history, "excluded-run", report, **fields)

                catalog = build_catalog(history)

                self.assertEqual(catalog["latest_run_id"], "formal-run")
                self.assertEqual([run["id"] for run in catalog["runs"]], ["formal-run"])
                excluded = next(
                    run for run in catalog["excluded_runs"] if run["id"] == "excluded-run"
                )
                self.assertEqual(excluded["status"], status)
                self.assertEqual(
                    excluded["superseded_by"],
                    "formal-run" if status == "superseded" else None,
                )
                self.assertIn(fields["status_reason"], excluded["reasons"][0])

    def test_inactive_status_metadata_fails_closed(self) -> None:
        cases = (
            ({"status": "withdrawn", "status_reason": "bad"}, "status"),
            ({"status": "invalidated"}, "status_reason"),
            (
                {
                    "status": "invalidated",
                    "status_reason": "bad capture",
                    "superseded_by": "formal-run",
                },
                "superseded_by is forbidden",
            ),
            (
                {
                    "status": "superseded",
                    "status_reason": "replaced",
                    "superseded_by": "missing-run",
                },
                "names an unknown run",
            ),
        )
        for fields, message in cases:
            with self.subTest(fields=fields), tempfile.TemporaryDirectory() as temporary:
                history = self.write_history(Path(temporary))
                index_path = history / "index.json"
                index = json.loads(index_path.read_text(encoding="utf-8"))
                index["runs"]["formal-run"].update(fields)
                index_path.write_bytes(encoded_json(index))
                with self.assertRaisesRegex(CatalogError, message):
                    build_catalog(history)

    def test_invalidated_report_still_requires_archive_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            history = self.write_history(Path(temporary))
            index_path = history / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["runs"]["formal-run"].update(
                {"status": "invalidated", "status_reason": "bad capture"}
            )
            index_path.write_bytes(encoded_json(index))
            report_path = history / "runs" / "formal-run" / "report.json"
            report_path.write_bytes(report_path.read_bytes() + b"\n")
            with self.assertRaisesRegex(CatalogError, "digest mismatch"):
                build_catalog(history)

    def test_request_resources_are_retained_without_replacing_process_rss(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = copy.deepcopy(self.report)
            lane = report["rows"][0]["lanes"]["cpu"]
            lane["request_resources"] = {
                "measurement_scope": "verified_process_request_batch",
                "source": "darwin_proc_pid_rusage_v6",
                "measured_warmups": 10,
                "measured_samples": 10,
                "lifetime_peak_physical_footprint_bytes": 64 * 1024 * 1024,
                "energy_nj": 1_000_000,
                "instructions": 2_000_000,
                "cycles": 1_000_000,
                "canonical_proof_bytes": lane["proof"]["bytes"],
                "complete": True,
                "unavailable_reason": None,
            }
            history = self.write_history(Path(temporary), report)
            published = build_catalog(history)["runs"][0]["rows"][0]["lanes"]["cpu"]
            self.assertEqual(published["resources"], lane["resources"])
            self.assertEqual(
                published["request_resources"], lane["request_resources"]
            )

    def test_malformed_request_resources_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = copy.deepcopy(self.report)
            lane = report["rows"][0]["lanes"]["cpu"]
            lane["request_resources"] = {
                "measurement_scope": "verified_process_request_batch",
                "source": "darwin_proc_pid_rusage_v6",
                "measured_warmups": 10,
                "measured_samples": 10,
                "lifetime_peak_physical_footprint_bytes": 64 * 1024 * 1024,
                "energy_nj": 1_000_000,
                "instructions": 2_000_000,
                "cycles": 1_000_000,
                "canonical_proof_bytes": lane["proof"]["bytes"] + 1,
                "complete": True,
                "unavailable_reason": None,
            }
            history = self.write_history(Path(temporary), report)
            with self.assertRaisesRegex(CatalogError, "proof"):
                build_catalog(history)

    def test_dirty_measurement_is_not_publishable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = copy.deepcopy(self.report)
            report["configuration"]["provenance"]["git_dirty"] = True
            history = self.write_history(Path(temporary), report)
            with self.assertRaisesRegex(CatalogError, "no provenance-complete runs"):
                build_catalog(history)

    def test_missing_machine_identity_is_not_publishable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = copy.deepcopy(self.report)
            del report["configuration"]["host_environment"]["hardware"]["machine_model"]
            history = self.write_history(Path(temporary), report)
            with self.assertRaisesRegex(CatalogError, "no provenance-complete runs"):
                build_catalog(history)

    def test_naive_timestamp_is_not_publishable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = copy.deepcopy(self.report)
            report["generated_at"] = "2026-07-18T06:43:34"
            history = self.write_history(Path(temporary), report)
            with self.assertRaisesRegex(CatalogError, "no provenance-complete runs"):
                build_catalog(history)

    def test_proof_parity_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = copy.deepcopy(self.report)
            report["rows"][0]["proof_parity"] = False
            history = self.write_history(Path(temporary), report)
            with self.assertRaisesRegex(CatalogError, "does not have CPU/Metal proof parity"):
                build_catalog(history)

    def test_rust_oracle_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = copy.deepcopy(self.report)
            report["rows"][0]["rust_oracle"]["verified"] = False
            history = self.write_history(Path(temporary), report)
            with self.assertRaisesRegex(CatalogError, "did not pass the Rust oracle"):
                build_catalog(history)

    def test_index_digest_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            history = self.write_history(Path(temporary))
            index_path = history / "index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["runs"]["formal-run"]["report"]["sha256"] = "0" * 64
            index_path.write_bytes(encoded_json(index))
            with self.assertRaisesRegex(CatalogError, "disagrees with its run"):
                build_catalog(history)

    def test_generate_then_validate_site_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            history = self.write_history(root)
            site = root / "site"
            (site / "assets").mkdir(parents=True)
            (site / "index.html").write_text(
                '<div role="tablist"></div><main id="overview-panel"></main>'
                '<aside id="provenance-panel"></aside>',
                encoding="utf-8",
            )
            (site / "assets" / "styles.css").write_text("body{}", encoding="utf-8")
            (site / "assets" / "responsive.css").write_text("", encoding="utf-8")
            (site / "assets" / "app.js").write_text('"use strict";', encoding="utf-8")
            self.assertEqual(run(["--history-dir", str(history), "--site-dir", str(site)]), 0)
            self.assertEqual(
                run(
                    [
                        "--history-dir",
                        str(history),
                        "--site-dir",
                        str(site),
                        "--validate",
                    ]
                ),
                0,
            )

    def test_authored_shell_is_fixed_viewport_and_accessible(self) -> None:
        html = (ROOT / "bench" / "site" / "index.html").read_text(encoding="utf-8")
        css = (ROOT / "bench" / "site" / "assets" / "styles.css").read_text(
            encoding="utf-8"
        )
        app = (ROOT / "bench" / "site" / "assets" / "app.js").read_text(encoding="utf-8")
        self.assertIn('role="tablist"', html)
        self.assertIn('role="tabpanel"', html)
        self.assertIn("height: 100dvh", css)
        self.assertIn("overflow: hidden", css)
        self.assertNotIn("innerHTML", app)

    def test_pages_workflow_template_validates_prs_and_publishes_changed_nightlies(self) -> None:
        workflow = (ROOT / "autoresearch" / "workflows" / "benchmark-pages.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn('cron: "17 03 * * *"', workflow)
        self.assertIn("pull_request:", workflow)
        self.assertIn("vectors/reports/benchmark_history/**", workflow)
        self.assertIn("python3 scripts/benchmark_pages.py --validate", workflow)
        self.assertIn("event=schedule&per_page=1", workflow)
        self.assertIn('git diff --quiet "$previous_sha" HEAD', workflow)
        self.assertIn("needs.validate.outputs.publish == 'true'", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        self.assertIn("name: benchmark-site-${{ github.sha }}", workflow)
        self.assertIn("retention-days: 30", workflow)
        self.assertIn("vars.BENCHMARK_PAGES_ENABLED == 'true'", workflow)
        self.assertIn("path: bench/site", workflow)
        self.assertNotIn("bench/dev/bench", workflow)

    def test_pages_build_target_does_not_run_benchmarks(self) -> None:
        build = (ROOT / "build_support" / "benchmarks" / "native.zig").read_text(
            encoding="utf-8"
        )
        pages_start = build.index("const bench_pages_cmd")
        pages_end = build.index("// Profiling smoke gate", pages_start)
        pages_block = build[pages_start:pages_end]
        self.assertNotIn("bench_pages_cmd.step.dependOn", pages_block)
        self.assertIn("bench_full_step.dependOn(&bench_full_cmd.step)", pages_block)
        self.assertIn("bench_full_step.dependOn(&bench_contrast_long_cmd.step)", pages_block)


if __name__ == "__main__":
    unittest.main()
