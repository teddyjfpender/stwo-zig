import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "cli"))
from stwo_perf import feed, manifest as manifest_mod

REPO_ROOT = Path(__file__).resolve().parents[2]

REQUIRED_KEYS = {
    "feed_schema_version", "project", "provenance", "anchor", "epoch",
    "boards", "metal_resident_progress", "latest_matrix", "history",
    "submissions", "notes_count", "search_health",
}


class FeedTest(unittest.TestCase):
    def setUp(self):
        self.m = manifest_mod.load(REPO_ROOT)
        self.feed = feed.build_feed(self.m, allow_dirty=True)

    def test_required_keys_present(self):
        self.assertEqual(REQUIRED_KEYS - set(self.feed), set())

    def test_deterministic(self):
        again = feed.build_feed(self.m, allow_dirty=True)
        self.assertEqual(feed.encode(self.feed), feed.encode(again))

    def test_legacy_search_health_is_honestly_unavailable(self):
        health = self.feed["search_health"]
        self.assertEqual(health["policy"]["gradient_snr_threshold"], 2.0)
        # Pre-Metrics-v2 rows must be honestly unavailable; rows recorded
        # after the merge legitimately carry evidence and are available. An
        # unavailable claimed v3 row (missing/invalid evidence) is also
        # legitimate — the taxonomy below is the closed set of honest
        # reasons, so this test never breaks on ledger growth.
        all_points = [
            point
            for board in health["boards"].values()
            for cls in board["classes"].values()
            for point in cls["time_series"]
        ]
        legacy_points = [
            p for p in all_points
            if p.get("unavailable_reason") == "legacy_row_has_no_search_health_evidence"
        ]
        self.assertTrue(legacy_points)
        self.assertTrue(all(not p["available"] for p in legacy_points))
        known_reasons = (
            "legacy_row_has_no_search_health_evidence",
            "verdict_bound_by_ledger_evidence_is_missing",
            "invalid_search_health_evidence:",
        )
        for point in (p for p in all_points if not p["available"]):
            self.assertTrue(
                str(point["unavailable_reason"]).startswith(known_reasons),
                f"unknown unavailable_reason: {point['unavailable_reason']}",
            )
        for point in (p for p in all_points if p["available"]):
            self.assertIsNone(point.get("unavailable_reason"))

    def test_provenance_digests_verify(self):
        import hashlib
        for rel, digest in self.feed["provenance"]["inputs_sha256"].items():
            actual = hashlib.sha256((REPO_ROOT / rel).read_bytes()).hexdigest()
            self.assertEqual(actual, digest, rel)

    def test_boards_cover_all_declared(self):
        from stwo_perf import ledger
        self.assertEqual(set(self.feed["boards"]), set(ledger.BOARDS))

    def test_v3_promotion_scope_partitions_the_board_universe(self):
        from stwo_perf import ledger
        self.assertEqual(self.feed["feed_schema_version"], 4)
        scope = self.feed["promotion_scope"]
        owned = set(scope["owned_boards"])
        future = set(scope["future_boards"])
        # TRACKS §6: retired boards are completed, not future. They leave
        # `owned_boards` with the retirement flip but must never be rendered
        # out-of-scope, so they partition out separately.
        retired = set(scope["retired_boards"])
        self.assertEqual(owned | future | retired, set(ledger.BOARDS))
        self.assertEqual(owned & future, set())
        self.assertEqual(retired & future, set())
        self.assertEqual(retired & owned, set())
        # Promotion-ineligible dark boards are staged, not smuggled into the
        # live ledger universe.
        self.assertEqual(
            owned,
            {
                g["board"] for g in scope["groups"].values()
                if g["promotion_eligible"]
            },
        )
        self.assertEqual(
            set(scope["staged_boards"]),
            {
                g["board"] for g in scope["groups"].values()
                if not g["promotion_eligible"]
            },
        )
        self.assertIn("pr6_supremacy", scope["staged_boards"])
        for group in scope["groups"].values():
            self.assertIn("enabled", group)
            self.assertIn("promotion_eligible", group)
            self.assertTrue(group["workloads"])
            for workload in group["workloads"].values():
                self.assertIn(workload["class"], scope["class_registry"])

    def test_scored_classes_and_suite_score_are_manifest_owned(self):
        expected_native = ["small", "wide", "deep", "xlarge", "huge"]
        self.assertEqual(self.feed["boards"]["core_cpu"]["scored_classes"], expected_native)
        self.assertEqual(self.feed["boards"]["core_metal"]["scored_classes"], expected_native)
        self.assertEqual(
            self.feed["boards"]["riscv"]["scored_classes"],
            ["small", "wide", "deep"],
        )
        for board in ("core_cpu", "core_metal", "riscv"):
            score = self.feed["boards"][board]["suite_score"]
            self.assertEqual(score["classes"], self.feed["boards"][board]["scored_classes"])
            self.assertEqual(score["epoch"], self.feed["epoch"]["number"])
            self.assertEqual(score["method"], "metrics_v2_scored_class_geomean_v2")
            self.assertIn("audited_ratio_geomean", score)

    def test_live_classes_publish_complete_audit_state(self):
        for board in ("core_cpu", "core_metal", "riscv"):
            for class_state in self.feed["boards"][board]["frontier_by_class"].values():
                audit = class_state["audit"]
                self.assertIn("effective_score", audit)
                self.assertIn("audited_through", audit)
                self.assertIn("audit_age", audit)
                self.assertIn("unaudited_tail", audit)
                self.assertIn("due", audit)
                self.assertIn("overdue", audit)
                self.assertIn("span_coverage", audit)
                self.assertIn("evidence_share", audit)
                age = audit["audit_age"]
                self.assertTrue(
                    isinstance(age.get("commits"), int)
                    or age.get("unavailable_reason")
                    == "audit_base_not_present_in_repository_history"
                )

    def test_empty_boards_render_empty_not_invented(self):
        for board, data in self.feed["boards"].items():
            for entry in data["entries"]:
                self.assertIn(entry["outcome"], ("promoted", "neutral", "rejected"))

    def test_baseline_matrix_is_the_earliest_run(self):
        baseline = self.feed["baseline_matrix"]
        latest = self.feed["latest_matrix"]
        self.assertIsNotNone(baseline)
        self.assertLessEqual(baseline["run_id"], latest["run_id"])
        self.assertTrue(baseline["rows"])

    def test_submissions_carry_attribution_and_record(self):
        for sub in self.feed["submissions"]:
            self.assertIn("solver", sub)
            self.assertIn("verdict_kind", sub)
            self.assertIn("note", sub)
            self.assertIn("transcripts", sub)
            for ref in sub["transcripts"]:
                self.assertTrue(ref["label"])
                self.assertTrue(ref["sha256"])
                self.assertIn(ref["captured_by"], ("harness", "submitter"))

    def test_latest_matrix_rows_have_lane_medians(self):
        latest = self.feed["latest_matrix"]
        if latest is None:
            self.skipTest("no matrix runs archived")
        self.assertGreater(len(latest["rows"]), 0)
        row = latest["rows"][0]
        self.assertIn("cpu", row["lanes"])
        self.assertIsNotNone(row["lanes"]["cpu"]["prove_ms"])
        self.assertIsNotNone(row["native_unit"])

    def test_request_resources_are_retained_without_zero_filling_legacy_rows(self):
        legacy = {"metrics": {}, "proof": {"bytes": 123}}
        self.assertNotIn("request_resources", feed._lane_summary(legacy))

        measured = {
            **legacy,
            "request_resources": {
                "measurement_scope": "verified_process_request_batch",
                "source": "darwin_proc_pid_rusage_v6",
                "measured_warmups": 1,
                "measured_samples": 2,
                "lifetime_peak_physical_footprint_bytes": 64 * 1024 * 1024,
                "energy_nj": 1_000_000,
                "instructions": 2_000_000,
                "cycles": 1_000_000,
                "canonical_proof_bytes": 123,
                "complete": True,
                "unavailable_reason": None,
            },
        }
        self.assertEqual(
            feed._lane_summary(measured)["request_resources"],
            measured["request_resources"],
        )

    def test_request_resource_proof_mismatch_fails_feed_closed(self):
        lane = {
            "metrics": {},
            "proof": {"bytes": 123},
            "request_resources": {
                "measurement_scope": "verified_process_request_batch",
                "source": "unsupported",
                "measured_warmups": 1,
                "measured_samples": 2,
                "lifetime_peak_physical_footprint_bytes": None,
                "energy_nj": None,
                "instructions": None,
                "cycles": None,
                "canonical_proof_bytes": 124,
                "complete": False,
                "unavailable_reason": "unsupported platform",
            },
        }
        with self.assertRaisesRegex(feed.FeedError, "proof bytes"):
            feed._lane_summary(lane)

    def test_reference_backends_are_distinct_and_peer_series_is_discoverable(self):
        references = self.feed["references"]
        scalar = references["peer_rust_scalar"]
        simd = references["peer_rust_simd"]
        self.assertEqual(
            scalar["rust_reference"]["backend_type"],
            "stwo::prover::backend::cpu::CpuBackend",
        )
        self.assertEqual(
            simd["rust_reference"]["backend_type"],
            "stwo::prover::backend::simd::SimdBackend",
        )
        self.assertTrue(scalar["proof_equivalence_receipt"]["all_equal"])
        self.assertTrue(simd["proof_equivalence_receipt"]["all_equal"])
        self.assertEqual(
            references["peer_relative_series"]["peer_source"]["commit"],
            "07ea1ccca13351028da94e66babf79e7ce91437f",
        )

    def test_reference_files_are_bound_into_feed_provenance(self):
        inputs = self.feed["provenance"]["inputs_sha256"]
        self.assertIn("autoresearch/reference/peer-rust-scalar.json", inputs)
        self.assertIn("autoresearch/reference/peer-rust-simd.json", inputs)
        self.assertIn("autoresearch/reference/peer-relative-series.json", inputs)

    def test_reference_discovery_rejects_scalar_labeled_as_simd(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            references = root / "autoresearch/reference"
            references.mkdir(parents=True)
            (references / "peer-rust-simd.json").write_text(json.dumps({
                "schema": "autoresearch-reference-v2",
                "reference_kind": "upstream-rust-backend",
                "name": "peer-rust-simd",
                "rust_reference": {
                    "backend_id": "simd",
                    "backend_type": "stwo::prover::backend::cpu::CpuBackend",
                },
            }))
            with self.assertRaisesRegex(feed.FeedError, "backend identity mismatch"):
                feed._references(root)


class FeedGuaranteeTest(unittest.TestCase):
    """Fixture-based tests that exercise the contract, not the happy path."""

    def _bootstrap(self, tmp: Path) -> Path:
        import subprocess
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp, check=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=tmp, check=True)
        ar = tmp / "autoresearch"
        (ar / "ledger").mkdir(parents=True)
        manifest_raw = json.loads((REPO_ROOT / "autoresearch/MANIFEST.json").read_text())
        (ar / "MANIFEST.json").write_text(json.dumps(manifest_raw))
        header = (REPO_ROOT / "autoresearch/ledger/promotions.tsv").read_text().splitlines()[0]
        (ar / "ledger" / "promotions.tsv").write_text(header + "\n")
        (ar / "ledger" / "epochs.json").write_text(
            (REPO_ROOT / "autoresearch/ledger/epochs.json").read_text()
        )
        subprocess.run(["git", "add", "-A"], cwd=tmp, check=True)
        subprocess.run(["git", "commit", "-qm", "bootstrap"], cwd=tmp, check=True)
        return tmp

    def test_bootstrap_project_builds_a_feed(self):
        """The generic-contract claim: no history, submissions, or notes."""
        import tempfile
        from stwo_perf.manifest import Manifest
        with tempfile.TemporaryDirectory() as raw:
            root = self._bootstrap(Path(raw))
            m = Manifest(root=root, raw=json.loads((root / "autoresearch/MANIFEST.json").read_text()))
            built = feed.build_feed(m)
            self.assertIsNone(built["latest_matrix"])
            self.assertEqual(built["submissions"], [])
            self.assertEqual(built["notes_count"], 0)
            self.assertEqual(built["history"]["runs"], [])
            self.assertEqual(built["provenance"]["dirty_inputs"], [])

    def test_dirty_input_refused(self):
        """Guarantee 1: uncommitted input changes must not publish under HEAD."""
        import tempfile
        from stwo_perf.manifest import Manifest
        with tempfile.TemporaryDirectory() as raw:
            root = self._bootstrap(Path(raw))
            epochs = root / "autoresearch/ledger/epochs.json"
            epochs.write_text(epochs.read_text() + "\n")  # valid but uncommitted
            m = Manifest(root=root, raw=json.loads((root / "autoresearch/MANIFEST.json").read_text()))
            with self.assertRaises(feed.FeedError):
                feed.build_feed(m)
            dirty = feed.build_feed(m, allow_dirty=True)
            self.assertEqual(
                dirty["provenance"]["dirty_inputs"],
                ["autoresearch/ledger/epochs.json"],
            )

    def test_matrix_report_is_digested_and_verified(self):
        """Guarantee 3: the rendered report is in inputs_sha256."""
        m = manifest_mod.load(REPO_ROOT)
        built = feed.build_feed(m, allow_dirty=True)
        latest = built["latest_matrix"]
        if latest is None:
            self.skipTest("no matrix runs archived")
        report_inputs = [k for k in built["provenance"]["inputs_sha256"]
                         if k.endswith("/report.json")]
        self.assertEqual(len(report_inputs), 1)


if __name__ == "__main__":
    unittest.main()
