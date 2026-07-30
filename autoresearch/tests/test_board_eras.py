"""TRACKS §7 per-board eras: bookkeeping, global fallback, and back-compat.

The hard requirement these tests exist to defend: adding per-board eras changes
NOTHING for a consumer that never asked for one. Every assertion below either
pins the fallback to the pre-era behaviour or pins a per-board override to data
that is explicitly declared — never inferred.
"""

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "autoresearch" / "cli"))

from stwo_perf import ledger, metrics  # noqa: E402

ANCHOR = "8e58d7015e28a312eddc6f1eacc10e0c08ea85cc"
OTHER_ANCHOR = "1" * 40


def committed_document() -> dict:
    return json.loads(ledger.epochs_path(ROOT).read_text())


class _Repo:
    """A throwaway repository root holding only ledger/epochs.json."""

    def __init__(self, document: dict):
        self._tmp = tempfile.TemporaryDirectory(prefix="stwo-eras-")
        self.root = Path(self._tmp.name)
        path = ledger.epochs_path(self.root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(document, indent=2) + "\n")

    def __enter__(self) -> Path:
        return self.root

    def __exit__(self, *exc) -> None:
        self._tmp.cleanup()


def with_eras(boards: dict) -> _Repo:
    document = committed_document()
    document["board_eras"] = {"note": "test fixture", "boards": boards}
    return _Repo(document)


def era(number: int, epoch_ref: int, opened: str, **extra) -> dict:
    record = {
        "era": number,
        "epoch_ref": epoch_ref,
        "opened_utc": opened,
        "reason": f"test era {number}",
    }
    record.update(extra)
    return record


class CommittedEraSequenceTest(unittest.TestCase):
    """The era sequences this PR commits, read back through the resolver."""

    def test_native_boards_are_banked_at_era_two(self):
        for board in ("core_cpu", "core_metal"):
            current = ledger.current_era(ROOT, board)
            self.assertIsNotNone(current, board)
            self.assertEqual(current["era"], 2, board)
            self.assertEqual(current["epoch_ref"], 2, board)
            self.assertEqual(current["status"], "banked", board)
            self.assertEqual(current["closed_utc"], "2026-07-29T00:00:00Z", board)
            self.assertEqual(len(ledger.board_eras(ROOT, board)), 2, board)

    def test_riscv_era_two_is_open_and_still_scores_prove_ms(self):
        current = ledger.current_era(ROOT, "riscv")
        self.assertEqual(current["era"], 2)
        self.assertEqual(current["status"], "open")
        self.assertIsNone(current["closed_utc"])
        # TRACKS §3.1 re-scores RISC-V at its NEXT era; era 2 must not move.
        self.assertEqual(ledger.scored_dimension(ROOT, "riscv"), "prove_ms")

    def test_boards_without_an_era_sequence_declare_none(self):
        for board in ("cairo_cpu", "cairo_metal", "stream", "heavy_native"):
            self.assertEqual(ledger.board_eras(ROOT, board), (), board)
            self.assertIsNone(ledger.current_era(ROOT, board), board)

    def test_every_committed_era_sequence_names_a_registered_board(self):
        declared = set(
            json.loads(ledger.epochs_path(ROOT).read_text())["board_eras"]["boards"]
        )
        self.assertTrue(declared)
        self.assertEqual(declared - set(ledger.BOARDS), set())


class BackCompatGoldenTest(unittest.TestCase):
    """Absent per-board data reproduces today's behaviour exactly."""

    def setUp(self):
        self.document = committed_document()
        self.global_epoch = max(
            int(spec["epoch"]) for spec in self.document["epochs"]
        )

    def test_global_epochs_one_and_two_are_readable_unchanged(self):
        epochs = ledger.known_epochs(ROOT)
        self.assertEqual(sorted(epochs), [1, 2])
        self.assertEqual(epochs[1]["opened_utc"], "2026-07-18T00:00:00Z")
        self.assertEqual(epochs[2]["metrics_v2"]["audit_anchor_commit"], ANCHOR)
        self.assertEqual(ledger.current_epoch(ROOT)["epoch"], self.global_epoch)

    def test_board_scoped_resolution_matches_the_global_epoch_today(self):
        # Every committed era references the newest global epoch, so no board
        # may resolve to anything else while that stays true.
        global_spec = ledger.current_epoch(ROOT)
        for board in ledger.BOARDS:
            spec = ledger.current_epoch(ROOT, board=board)
            self.assertEqual(int(spec["epoch"]), self.global_epoch, board)
            self.assertEqual(
                spec["metrics_v2"]["audit_anchor_commit"],
                global_spec["metrics_v2"]["audit_anchor_commit"],
                board,
            )
            self.assertEqual(
                spec["aa_dispersion"].get(board),
                global_spec["aa_dispersion"].get(board),
                board,
            )

    def test_dispersion_and_budgets_are_unchanged_for_every_board_and_class(self):
        epoch = ledger.known_epochs(ROOT)[self.global_epoch]
        for board, classes in epoch["aa_dispersion"].items():
            if board == "note":
                continue
            for workload_class, expected in classes.items():
                self.assertEqual(
                    ledger.aa_dispersion(ROOT, board, workload_class),
                    float(expected) if expected is not None else None,
                    f"{board}/{workload_class}",
                )
        for workload_class, expected in epoch["metrics_v2"]["resource_budgets"].items():
            self.assertEqual(
                ledger.resource_budgets(ROOT, workload_class),
                {key: float(value) for key, value in expected.items()},
                workload_class,
            )

    def test_a_document_without_board_eras_behaves_identically(self):
        document = committed_document()
        document.pop("board_eras", None)
        with _Repo(document) as repo:
            self.assertEqual(ledger.board_eras(repo, "core_cpu"), ())
            self.assertIsNone(ledger.current_era(repo, "core_cpu"))
            self.assertEqual(
                ledger.current_epoch(repo, board="core_cpu"),
                ledger.current_epoch(repo),
            )
            self.assertEqual(
                ledger.aa_dispersion(repo, "core_cpu", "small"), 0.018654,
            )
            self.assertEqual(
                ledger.resource_budgets(repo, "small", board="core_cpu"),
                ledger.resource_budgets(repo, "small"),
            )

    def test_a_board_with_no_era_falls_back_to_the_newest_global_epoch(self):
        with with_eras({"riscv": [era(1, 1, "2026-07-18T00:00:00Z")]}) as repo:
            self.assertEqual(
                ledger.current_epoch(repo, board="cairo_cpu"),
                ledger.current_epoch(repo),
            )
            # An unknown board never invents an era; it falls back too.
            self.assertEqual(ledger.board_eras(repo, "stream"), ())


class EraResolutionTest(unittest.TestCase):
    def test_a_banked_board_stays_pinned_when_a_later_epoch_opens(self):
        document = committed_document()
        document["epochs"].append({
            "epoch": 3,
            "opened_utc": "2026-08-01T00:00:00Z",
            "reason": "a later global epoch that the retired board never joins",
            "harness_commit": None,
            "metrics_v2": copy.deepcopy(document["epochs"][1]["metrics_v2"]),
            "aa_dispersion": {},
        })
        with _Repo(document) as repo:
            # The global epoch advanced...
            self.assertEqual(ledger.current_epoch(repo)["epoch"], 3)
            # ...but a banked board's scoring is frozen at its own era.
            self.assertEqual(
                ledger.current_epoch(repo, board="core_cpu")["epoch"], 2,
            )
            self.assertEqual(
                ledger.current_epoch(repo, board="core_cpu")["era"]["status"],
                "banked",
            )
            # A board with no era sequence follows the global epoch.
            self.assertEqual(
                ledger.current_epoch(repo, board="cairo_cpu")["epoch"], 3,
            )

    def test_epoch_for_board_resolves_a_named_epoch_not_only_the_newest(self):
        self.assertEqual(
            ledger.epoch_for_board(ROOT, 1, "core_cpu")["era"]["era"], 1,
        )
        self.assertEqual(
            ledger.epoch_for_board(ROOT, 2, "core_cpu")["era"]["era"], 2,
        )
        # No board argument, or no covering era, returns the global record.
        self.assertEqual(
            ledger.epoch_for_board(ROOT, 1), ledger.known_epochs(ROOT)[1],
        )
        self.assertEqual(
            ledger.epoch_for_board(ROOT, 1, "cairo_cpu"),
            ledger.known_epochs(ROOT)[1],
        )
        with self.assertRaises(ledger.LedgerError):
            ledger.epoch_for_board(ROOT, 99, "core_cpu")

    def test_per_board_audit_anchor_overrides_the_epoch_anchor(self):
        boards = {
            "riscv": [
                era(1, 1, "2026-07-18T00:00:00Z", status="banked",
                    closed_utc="2026-07-21T16:00:00Z"),
                era(2, 2, "2026-07-21T16:00:00Z",
                    audit_anchor_commit=OTHER_ANCHOR),
            ],
        }
        with with_eras(boards) as repo:
            board_policy = metrics.policy_from_epoch(
                ledger.current_epoch(repo, board="riscv")
            )
            self.assertEqual(board_policy.audit_anchor_commit, OTHER_ANCHOR)
            self.assertEqual(board_policy.board, "riscv")
            self.assertEqual(board_policy.era, 2)
            # The global epoch's anchor is untouched, and stays the fallback
            # for every board that pins none.
            self.assertEqual(
                metrics.policy_from_epoch(
                    ledger.current_epoch(repo)
                ).audit_anchor_commit,
                ANCHOR,
            )
            fallback = metrics.policy_from_epoch(
                ledger.current_epoch(repo, board="cairo_cpu")
            )
            self.assertEqual(fallback.audit_anchor_commit, ANCHOR)
            self.assertIsNone(fallback.board)
            self.assertIsNone(fallback.era)

    def test_per_board_dispersion_override_is_merged_not_replaced(self):
        boards = {
            "riscv": [
                era(1, 1, "2026-07-18T00:00:00Z", status="banked",
                    closed_utc="2026-07-21T16:00:00Z"),
                era(2, 2, "2026-07-21T16:00:00Z",
                    aa_dispersion={"small": 0.004, "deep": None}),
            ],
        }
        with with_eras(boards) as repo:
            self.assertEqual(ledger.aa_dispersion(repo, "riscv", "small"), 0.004)
            self.assertIsNone(ledger.aa_dispersion(repo, "riscv", "deep"))
            # A class the era does not pin still inherits the epoch value.
            self.assertEqual(ledger.aa_dispersion(repo, "riscv", "wide"), 0.014801)
            # Another board is untouched.
            self.assertEqual(
                ledger.aa_dispersion(repo, "core_cpu", "small"), 0.018654,
            )


class ResourceBudgetKeyTest(unittest.TestCase):
    """TRACKS §8: budgets keyed (board, class), falling back to class-only."""

    def setUp(self):
        self.boards = {
            "riscv": [
                era(1, 1, "2026-07-18T00:00:00Z", status="banked",
                    closed_utc="2026-07-21T16:00:00Z"),
                era(2, 2, "2026-07-21T16:00:00Z", resource_budgets={
                    "small": {
                        "peak_rss_mib": 1.20,
                        "energy_j": 1.10,
                        "proof_bytes": 1.00,
                    },
                }),
            ],
        }

    def test_board_keyed_budget_wins_for_that_board_and_class(self):
        with with_eras(self.boards) as repo:
            self.assertEqual(
                ledger.resource_budgets(repo, "small", board="riscv"),
                {"peak_rss_mib": 1.20, "energy_j": 1.10, "proof_bytes": 1.00},
            )

    def test_unpinned_class_falls_back_to_the_class_only_budget(self):
        with with_eras(self.boards) as repo:
            class_only = ledger.resource_budgets(repo, "wide")
            self.assertEqual(
                ledger.resource_budgets(repo, "wide", board="riscv"), class_only,
            )

    def test_other_boards_and_the_global_call_are_unaffected(self):
        with with_eras(self.boards) as repo:
            class_only = ledger.resource_budgets(repo, "small")
            self.assertEqual(class_only["peak_rss_mib"], 1.05)
            self.assertEqual(
                ledger.resource_budgets(repo, "small", board="core_cpu"),
                class_only,
            )

    def test_a_legacy_epoch_without_metrics_v2_still_returns_none(self):
        document = {"epochs": [{"epoch": 1, "opened_utc": "2026-07-18T00:00:00Z",
                                "reason": "legacy", "aa_dispersion": {}}]}
        with _Repo(document) as repo:
            self.assertIsNone(ledger.resource_budgets(repo, "small"))
            self.assertIsNone(
                ledger.resource_budgets(repo, "small", board="core_cpu")
            )


class EraValidationTest(unittest.TestCase):
    """Fail closed: a malformed era is an error, never a silent default."""

    def _rejects(self, boards: dict, needle: str, board: str = "riscv") -> None:
        with with_eras(boards) as repo:
            with self.assertRaises(ledger.LedgerError) as ctx:
                ledger.board_eras(repo, board)
            self.assertIn(needle, str(ctx.exception))

    def test_unregistered_board_is_rejected(self):
        self._rejects(
            {"invented_board": [era(1, 1, "2026-07-18T00:00:00Z")]},
            "not a registered scoring board",
            board="invented_board",
        )

    def test_unknown_epoch_reference_is_rejected(self):
        self._rejects(
            {"riscv": [era(1, 9, "2026-07-18T00:00:00Z")]},
            "must name a global epoch",
        )

    def test_era_numbers_must_be_contiguous_and_ascending(self):
        self._rejects(
            {"riscv": [
                era(1, 1, "2026-07-18T00:00:00Z", status="banked",
                    closed_utc="2026-07-21T16:00:00Z"),
                era(3, 2, "2026-07-21T16:00:00Z"),
            ]},
            "numbered 1..n",
        )

    def test_only_the_newest_era_may_stay_open(self):
        self._rejects(
            {"riscv": [
                era(1, 1, "2026-07-18T00:00:00Z"),
                era(2, 2, "2026-07-21T16:00:00Z"),
            ]},
            "only the newest era may stay open",
        )

    def test_banked_era_must_record_when_it_closed(self):
        self._rejects(
            {"riscv": [era(1, 1, "2026-07-18T00:00:00Z", status="banked")]},
            "must record 'closed_utc'",
        )

    def test_open_era_must_not_record_a_close(self):
        self._rejects(
            {"riscv": [
                era(1, 1, "2026-07-18T00:00:00Z", closed_utc="2026-07-19T00:00:00Z")
            ]},
            "must not record 'closed_utc'",
        )

    def test_unknown_status_and_unknown_keys_are_rejected(self):
        self._rejects(
            {"riscv": [era(1, 1, "2026-07-18T00:00:00Z", status="paused")]},
            "'status' must be one of",
        )
        self._rejects(
            {"riscv": [era(1, 1, "2026-07-18T00:00:00Z", smuggled=True)]},
            "unknown key(s)",
        )

    def test_missing_reason_and_malformed_timestamps_are_rejected(self):
        boards = {"riscv": [era(1, 1, "2026-07-18T00:00:00Z")]}
        boards["riscv"][0]["reason"] = "  "
        self._rejects(boards, "'reason' must be a non-empty string")
        self._rejects(
            {"riscv": [era(1, 1, "18 July 2026")]}, "must be ISO-8601 UTC",
        )

    def test_an_era_may_not_open_before_the_epoch_it_inherits(self):
        self._rejects(
            {"riscv": [era(1, 2, "2026-07-19T00:00:00Z")]},
            "precedes the global epoch it inherits",
        )

    def test_opened_utc_must_strictly_increase(self):
        self._rejects(
            {"riscv": [
                era(1, 1, "2026-07-21T16:00:00Z", status="banked",
                    closed_utc="2026-07-21T16:00:00Z"),
                era(2, 2, "2026-07-21T16:00:00Z"),
            ]},
            "opened_utc must strictly increase",
        )

    def test_malformed_overrides_are_rejected(self):
        self._rejects(
            {"riscv": [era(1, 1, "2026-07-18T00:00:00Z", audit_anchor_commit="abc")]},
            "must be a 40-hex commit",
        )
        self._rejects(
            {"riscv": [era(1, 1, "2026-07-18T00:00:00Z", aa_dispersion={"small": 0})]},
            "must be positive and finite, or null",
        )
        self._rejects(
            {"riscv": [era(1, 1, "2026-07-18T00:00:00Z", resource_budgets={
                "small": {"peak_rss_mib": 1.0},
            })]},
            "must contain exactly",
        )

    def test_board_eras_block_shape_is_fail_closed(self):
        document = committed_document()
        document["board_eras"] = {"boards": {}, "unexpected": 1}
        with _Repo(document) as repo:
            with self.assertRaises(ledger.LedgerError):
                ledger.board_eras(repo, "riscv")
        document["board_eras"] = {"boards": {"riscv": []}}
        with _Repo(document) as repo:
            with self.assertRaises(ledger.LedgerError):
                ledger.board_eras(repo, "riscv")


class ScoredDimensionGateTest(unittest.TestCase):
    """TRACKS §3.1 staging: the boundary switch cannot open uncalibrated."""

    def test_default_is_todays_boundary_everywhere(self):
        self.assertEqual(ledger.DEFAULT_SCORED_DIMENSION, "prove_ms")
        for board in ledger.BOARDS:
            self.assertEqual(ledger.scored_dimension(ROOT, board), "prove_ms", board)
        self.assertEqual(ledger.scored_dimension(ROOT), "prove_ms")

    def test_switching_the_boundary_requires_a_recalibrated_era(self):
        with with_eras({"riscv": [
            era(1, 1, "2026-07-18T00:00:00Z", scored_dimension="request_ms"),
        ]}) as repo:
            with self.assertRaises(ledger.LedgerError) as ctx:
                ledger.board_eras(repo, "riscv")
            self.assertIn("must declare its own measured aa_dispersion", str(ctx.exception))

    def test_an_unknown_boundary_is_refused(self):
        with with_eras({"riscv": [
            era(1, 1, "2026-07-18T00:00:00Z", scored_dimension="vibes"),
        ]}) as repo:
            with self.assertRaises(ledger.LedgerError):
                ledger.board_eras(repo, "riscv")

    def test_a_recalibrated_era_may_declare_the_request_boundary(self):
        with with_eras({"riscv": [
            era(1, 1, "2026-07-18T00:00:00Z", scored_dimension="request_ms",
                aa_dispersion={"small": 0.003, "wide": 0.009, "deep": 0.006}),
        ]}) as repo:
            self.assertEqual(ledger.scored_dimension(repo, "riscv"), "request_ms")
            # Nothing else moves: other boards keep today's boundary.
            self.assertEqual(ledger.scored_dimension(repo, "core_cpu"), "prove_ms")


if __name__ == "__main__":
    unittest.main()
