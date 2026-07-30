"""TRACKS §6 retire-and-complete: the native era is banked, not deleted.

Retirement means exactly three things, and each has a test here: new
promotions refuse with a legible reason, the full history keeps being served
(board names, ledger rows, scores, feed entries all survive), and the closing
audit that stamps the final audited score is still runnable until it lands.
"""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "autoresearch" / "cli"))
sys.path.insert(0, str(ROOT))  # runner imports scripts.* from the repo root

from stwo_perf import (  # noqa: E402
    audits, feed, ledger, manifest as manifest_mod, promotion,
)

RETIRED = {"native": "core_cpu", "metal": "core_metal"}


def raw_manifest() -> dict:
    return json.loads((ROOT / "autoresearch" / "MANIFEST.json").read_text())


class RetirementManifestTest(unittest.TestCase):
    def setUp(self):
        self.m = manifest_mod.load(ROOT)
        self.groups = {group.group_id: group for group in self.m.groups()}

    def test_native_groups_are_retired_but_stay_enabled(self):
        for group_id, board in RETIRED.items():
            group = self.groups[group_id]
            self.assertEqual(group.board, board)
            # Enabled: history, guard workloads, and the PR6-supremacy cells
            # keep running. Not promotion eligible: the era is banked.
            self.assertTrue(group.enabled, group_id)
            self.assertFalse(group.promotion_eligible, group_id)
            self.assertTrue(group.promotion_blocked_reason, group_id)
            self.assertIsNone(group.disabled_reason, group_id)

    def test_retirement_block_is_complete_and_the_closing_audit_is_pending(self):
        for group_id in RETIRED:
            retirement = self.groups[group_id].retirement
            self.assertEqual(
                set(retirement), set(manifest_mod.RETIREMENT_KEYS), group_id,
            )
            self.assertEqual(
                retirement["retired_at_utc"], "2026-07-29T00:00:00Z", group_id,
            )
            self.assertIn("TRACKS §6", retirement["reason"], group_id)
            # The closing audit runs on the M5 judge host; nothing may claim it
            # happened before its evidence lands.
            self.assertIsNone(retirement["closing_audit"], group_id)

    def test_no_other_group_is_retired(self):
        for group in self.m.groups():
            if group.group_id not in RETIRED:
                self.assertFalse(group.retirement, group.group_id)

    def test_history_is_never_dropped_from_the_board_universe(self):
        for board in RETIRED.values():
            self.assertIn(board, ledger.BOARDS)
        # And the retired boards still own their five scored classes, so their
        # final scores stay computable.
        for board in RETIRED.values():
            self.assertEqual(
                self.m.class_names(board=board, scored_only=True, include_disabled=True),
                ["small", "wide", "deep", "xlarge", "huge"],
            )


class RetirementValidationTest(unittest.TestCase):
    """A retirement block cannot be half-declared."""

    def _rejects(self, mutate, needle: str) -> None:
        raw = raw_manifest()
        mutate(raw["workload_registry"]["groups"]["native"])
        with self.assertRaises(manifest_mod.ManifestError) as ctx:
            manifest_mod.Manifest(ROOT, manifest_mod._validate(raw) or raw)
        self.assertIn(needle, str(ctx.exception))

    def test_a_retired_group_cannot_be_promotion_eligible(self):
        def mutate(group):
            group["promotion_eligible"] = True
        self._rejects(mutate, "retired group cannot be promotion eligible")

    def test_a_retired_group_must_explain_its_refusal(self):
        def mutate(group):
            group["promotion_blocked_reason"] = "   "
        self._rejects(mutate, "must state a promotion_blocked_reason")

    def test_retirement_keys_are_exact(self):
        def mutate(group):
            group["retirement"].pop("closing_audit")
        self._rejects(mutate, "'retirement' must contain exactly")

        def extra(group):
            group["retirement"]["celebrated"] = True
        self._rejects(extra, "'retirement' must contain exactly")

    def test_retirement_timestamp_and_reason_are_validated(self):
        def mutate(group):
            group["retirement"]["retired_at_utc"] = "yesterday"
        self._rejects(mutate, "retired_at_utc must be ISO-8601 UTC")

        def blank(group):
            group["retirement"]["reason"] = ""
        self._rejects(blank, "reason must be a non-empty string")

    def test_a_recorded_closing_audit_must_name_its_evidence(self):
        def mutate(group):
            group["retirement"]["closing_audit"] = {"completed_utc": "2026-08-01T00:00:00Z"}
        self._rejects(mutate, "closing_audit must be null or contain exactly")

        def bad_ids(group):
            group["retirement"]["closing_audit"] = {
                "completed_utc": "2026-08-01T00:00:00Z",
                "bundle_sha256": "sha256:" + "a" * 64,
                "row_ids": [],
            }
        self._rejects(bad_ids, "row_ids must be a unique non-empty list")

    def test_a_well_formed_closing_audit_is_accepted(self):
        raw = raw_manifest()
        raw["workload_registry"]["groups"]["native"]["retirement"]["closing_audit"] = {
            "completed_utc": "2026-08-01T00:00:00Z",
            "bundle_sha256": "sha256:" + "a" * 64,
            "row_ids": ["sha256:" + "b" * 64],
        }
        manifest_mod._validate(raw)  # must not raise

    def test_scored_dimension_is_validated_and_defaults_to_todays_boundary(self):
        raw = raw_manifest()
        self.assertEqual(
            manifest_mod.load(ROOT).group("riscv").scored_dimension, "prove_ms",
        )
        raw["workload_registry"]["groups"]["riscv"]["scored_dimension"] = "vibes"
        with self.assertRaises(manifest_mod.ManifestError) as ctx:
            manifest_mod._validate(raw)
        self.assertIn("'scored_dimension' must be one of", str(ctx.exception))
        raw["workload_registry"]["groups"]["riscv"]["scored_dimension"] = "request_ms"
        manifest_mod._validate(raw)  # the staged TRACKS §3.1 value is declarable


class RetiredPromotionRefusalTest(unittest.TestCase):
    def setUp(self):
        self.m = manifest_mod.load(ROOT)

    def test_promotion_on_a_retired_board_refuses_with_a_retirement_reason(self):
        for board in RETIRED.values():
            with self.assertRaises(promotion.PromotionError) as ctx:
                promotion.require_board_promotion_eligible(self.m, board)
            message = str(ctx.exception)
            self.assertIn("retired", message, board)
            self.assertIn("2026-07-29T00:00:00Z", message, board)
            self.assertIn("history stays served", message, board)
            # The generic contract still holds, so existing callers matching on
            # the old text keep working.
            self.assertIn("not promotion eligible", message, board)

    def test_a_verdict_declaring_a_retired_board_is_refused(self):
        verdict = {
            "declared_objective": {"board": "core_cpu", "workload_class": "small"},
        }
        with self.assertRaises(promotion.PromotionError) as ctx:
            promotion.require_verdict_promotion_eligible(ROOT, verdict)
        self.assertIn("retired", str(ctx.exception))

    def test_a_live_board_still_promotes(self):
        promotion.require_board_promotion_eligible(self.m, "riscv")

    def test_a_merely_staged_board_keeps_the_plain_refusal(self):
        with self.assertRaises(promotion.PromotionError) as ctx:
            promotion.require_board_promotion_eligible(self.m, "cairo_cpu")
        self.assertNotIn("retired", str(ctx.exception))


class ClosingAuditReachabilityTest(unittest.TestCase):
    """A retired board still owes its closing audit (TRACKS §6)."""

    def _item(self, manifest, retirement_state) -> dict:
        from test_audits import ANCHOR, CANDIDATE, parsed, promotion as promo

        rows = parsed(*[
            promo(f"n-{index}", index, outcome="neutral",
                  judged_r=0.999, ci_low=0.98, ci_high=1.01)
            for index in range(1, 5)
        ])
        return audits._item(
            manifest, rows, 2, "core_cpu", "small", CANDIDATE,
            "sha256:" + "a" * 64,
            lambda value: ANCHOR if value.endswith("^1") else value,
        )

    def test_a_retired_board_audit_is_still_runnable(self):
        item = self._item(manifest_mod.load(ROOT), None)
        self.assertIsNotNone(item)
        self.assertTrue(
            item["runnable"],
            f"retired boards must keep their closing audit reachable: "
            f"{item['blocked_reason']}",
        )

    def test_a_recorded_closing_audit_closes_the_cell(self):
        raw = raw_manifest()
        raw["workload_registry"]["groups"]["native"]["retirement"]["closing_audit"] = {
            "completed_utc": "2026-08-01T00:00:00Z",
            "bundle_sha256": "sha256:" + "a" * 64,
            "row_ids": ["sha256:" + "b" * 64],
        }
        item = self._item(manifest_mod.Manifest(ROOT, raw), "recorded")
        self.assertFalse(item["runnable"])
        self.assertIn("already recorded its closing audit", item["blocked_reason"])

    def test_a_staged_never_calibrated_board_stays_blocked(self):
        raw = raw_manifest()
        raw["workload_registry"]["groups"]["native"].pop("retirement")
        item = self._item(manifest_mod.Manifest(ROOT, raw), None)
        self.assertFalse(item["runnable"])
        self.assertIn("promotion eligible", item["blocked_reason"])


class RetirementFeedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feed = feed.build_feed(manifest_mod.load(ROOT), allow_dirty=True)

    def test_feed_declares_schema_v4(self):
        self.assertEqual(self.feed["feed_schema_version"], 4)
        self.assertEqual(feed.FEED_SCHEMA_VERSION, 4)

    def test_global_epoch_publishes_when_and_why_it_opened(self):
        epoch = self.feed["epoch"]
        self.assertEqual(epoch["number"], 2)
        self.assertEqual(epoch["opened_utc"], "2026-07-21T16:00:00Z")
        self.assertIn("Metrics v2", epoch["reason"])

    def test_every_board_publishes_an_era(self):
        for board, entry in self.feed["boards"].items():
            era = entry["era"]
            self.assertEqual(
                set(era),
                {
                    "number", "epoch", "opened_utc", "reason", "status",
                    "banked", "closed_utc", "scored_dimension", "note", "source",
                },
                board,
            )
            self.assertIsInstance(era["number"], int, board)
            self.assertTrue(era["opened_utc"], board)
            self.assertTrue(era["reason"], board)
            self.assertIn(era["source"], ("board_era", "global_epoch"), board)
            self.assertEqual(era["banked"], era["status"] == "banked", board)

    def test_retired_boards_publish_a_banked_era_and_a_retirement_block(self):
        for board in RETIRED.values():
            entry = self.feed["boards"][board]
            era = entry["era"]
            self.assertEqual(era["source"], "board_era", board)
            self.assertEqual(era["number"], 2, board)
            self.assertEqual(era["status"], "banked", board)
            self.assertTrue(era["banked"], board)
            self.assertEqual(era["closed_utc"], "2026-07-29T00:00:00Z", board)
            self.assertEqual(
                entry["retirement"]["retired_at_utc"], "2026-07-29T00:00:00Z", board,
            )
            self.assertIsNone(entry["retirement"]["closing_audit"], board)
            # History stays fully served.
            self.assertTrue(entry["entries"], board)
            self.assertIsNotNone(entry["suite_score"], board)

    def test_live_boards_publish_an_open_era_and_no_retirement(self):
        riscv = self.feed["boards"]["riscv"]
        self.assertEqual(riscv["era"]["source"], "board_era")
        self.assertFalse(riscv["era"]["banked"])
        self.assertIsNone(riscv["era"]["closed_utc"])
        self.assertIsNone(riscv["retirement"])

    def test_a_board_without_an_era_sequence_falls_back_to_the_global_epoch(self):
        cairo = self.feed["boards"]["cairo_cpu"]
        self.assertEqual(cairo["era"]["source"], "global_epoch")
        self.assertEqual(cairo["era"]["number"], self.feed["epoch"]["number"])
        self.assertEqual(cairo["era"]["opened_utc"], self.feed["epoch"]["opened_utc"])

    def test_retired_boards_are_never_rendered_out_of_scope(self):
        scope = self.feed["promotion_scope"]
        self.assertEqual(set(scope["retired_boards"]), set(RETIRED.values()))
        for board in RETIRED.values():
            self.assertNotIn(board, scope["future_boards"])
            self.assertNotIn(board, scope["owned_boards"])
            self.assertIn(board, scope["staged_boards"])
        self.assertEqual(
            scope["groups"]["native"]["retirement"]["retired_at_utc"],
            "2026-07-29T00:00:00Z",
        )
        self.assertIsNone(scope["groups"]["riscv"]["retirement"])

    def test_phase_telemetry_is_exported_only_from_committed_evidence(self):
        # TRACKS §3.2 machinery lands with the drop point empty: no committed
        # artifact carries per-phase cutpoints yet, so every board is honestly
        # absent rather than zero-filled.
        for board, entry in self.feed["boards"].items():
            self.assertIn("phase_telemetry", entry, board)
        self.assertEqual(feed._phase_telemetry(ROOT), {})

    def test_matrix_lanes_carry_their_backend_identity_and_board(self):
        rows = self.feed["latest_matrix"]["rows"]
        self.assertTrue(rows)
        lanes = rows[0]["lanes"]
        self.assertEqual(lanes["cpu"]["backend"], "cpu_native")
        self.assertEqual(lanes["cpu"]["board"], "core_cpu")
        # schema/scoring.md Board 5: today's metal lane is hybrid, and it must
        # never be attributed to the zero-fallback Board 4.
        self.assertEqual(lanes["metal"]["backend"], "metal_hybrid")
        self.assertEqual(lanes["metal"]["board"], "core_hybrid")

    def test_an_unknown_lane_backend_publishes_no_board(self):
        summary = feed._lane_summary({"backend": "quantum_native", "metrics": {}})
        self.assertEqual(summary["backend"], "quantum_native")
        self.assertIsNone(summary["board"])


if __name__ == "__main__":
    unittest.main()
