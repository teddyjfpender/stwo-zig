from __future__ import annotations

import copy
import unittest

from scripts.typed_air_r006_capture_lib.model import (
    ATTEMPTS_PER_COMPARISON,
    WORKLOAD_IDS,
    CaptureError,
)
from scripts.typed_air_r006_capture_lib.pair import PAIR_LANE_ORDER
from scripts.typed_air_r006_capture_lib.pair_prefix import select_complete_blocks
from scripts.typed_air_r006_capture_lib.reduction import SCALING_COMPARISONS, _groups


def plan() -> dict[str, object]:
    attempts: list[dict[str, object]] = []

    def block(workload: str, comparison: str) -> None:
        for ordinal in range(ATTEMPTS_PER_COMPARISON):
            attempts.append(
                {
                    "attempt_id": f"{workload}-{comparison}-{ordinal}",
                    "workload_id": workload,
                    "comparison_id": comparison,
                }
            )

    block("multi_shard_addi", "aa-calibration")
    for workload in WORKLOAD_IDS:
        for comparison in SCALING_COMPARISONS:
            block(workload, comparison)
    return {
        "lanes": {
            lane: {"attempts": copy.deepcopy(attempts)} for lane in PAIR_LANE_ORDER
        }
    }


class CompleteBlockPrefixTests(unittest.TestCase):
    def test_selects_three_complete_matrices_and_excludes_partial_tail(self) -> None:
        selected = select_complete_blocks(
            plan(), {"cpu-native": 877, "metal-hybrid": 877}
        )
        self.assertEqual(selected["statistical_attempts_per_lane"], 800)
        self.assertEqual(selected["statistical_attempts"], 1_600)
        self.assertEqual(
            selected["included_workloads"], list(WORKLOAD_IDS[:3])
        )
        self.assertEqual(selected["omitted_workloads"], [WORKLOAD_IDS[3]])
        self.assertEqual(selected["retained_but_unscored_attempts"], 154)
        self.assertEqual(selected["not_executed_attempts"], 326)

    def test_uneven_append_prefix_uses_only_common_complete_blocks(self) -> None:
        selected = select_complete_blocks(
            plan(), {"cpu-native": 881, "metal-hybrid": 879}
        )
        self.assertEqual(selected["statistical_attempts_per_lane"], 800)
        self.assertEqual(selected["retained_but_unscored_attempts"], 160)

    def test_prefix_requires_two_whole_workload_matrices(self) -> None:
        with self.assertRaisesRegex(CaptureError, "at least two"):
            select_complete_blocks(
                plan(), {"cpu-native": 559, "metal-hybrid": 559}
            )

    def test_reduction_groups_accept_exact_selected_view_only(self) -> None:
        selected = copy.deepcopy(plan()["lanes"]["cpu-native"])
        selected["attempts"] = selected["attempts"][:800]
        records = [{"status": "verified"} for _ in range(800)]
        groups = _groups(selected, records)
        self.assertEqual(len(groups[("multi_shard_addi", "aa-calibration")]), 80)
        with self.assertRaisesRegex(CaptureError, "selected attempts"):
            _groups(selected, records[:-1])


if __name__ == "__main__":
    unittest.main()
