from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.typed_air_r006_capture_lib.codec import canonical_bytes
from scripts.typed_air_r006_capture_lib import exact_work_cells as cells
from scripts.typed_air_r006_capture_lib import reduction
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.typed_air_r006_capture_lib.report import U64_MAX


LANES = ("cpu-native", "metal-hybrid")
COUNTERS = (
    "field_additions",
    "field_multiplications",
    "field_inversions",
    "fft_butterflies",
    "fri_folds",
    "merkle_compressions",
)


def disclosure(*, digest: str = "3", additions: int = 10_001) -> dict[str, object]:
    return {
        "schema": "stwo.prover.logical-work-profile.v2",
        "source_mask": 0x3F,
        "record_count": 19,
        "producer_ledger_schema_version": 2,
        "producer_counts": [3, 4, 2, 1, 4, 2, 3],
        "producer_coverage_terminal_sealed": True,
        "field_additions": additions,
        "field_multiplications": 8_003,
        "field_inversions": 17,
        "fft_butterflies": 4_096,
        "fri_folds": 2_048,
        "merkle_compressions": 1_023,
        "profile_sha256": digest * 64,
    }


def fixture() -> tuple[dict[str, object], dict[str, list[dict[str, object]]]]:
    plan: dict[str, object] = {"lanes": {}}
    records: dict[str, list[dict[str, object]]] = {}
    for lane in LANES:
        attempts: list[dict[str, object]] = []
        lane_records: list[dict[str, object]] = []
        for workers, repeats in ((1, 3), (2, 2)):
            for ordinal in range(repeats):
                attempts.append(
                    {
                        "attempt_id": f"{lane}-{workers}-{ordinal}",
                        "workload_id": "fixture-workload",
                        "worker_count": workers,
                    }
                )
                lane_records.append(
                    {
                        "status": "verified",
                        "metrics": {"work_disclosure": disclosure()},
                    }
                )
        plan["lanes"][lane] = {"attempts": attempts}
        records[lane] = lane_records
    return plan, records


def mutate_cell(
    plan: dict[str, object],
    records: dict[str, list[dict[str, object]]],
    *,
    lane: str,
    workers: int,
    additions: int,
    digest: str,
) -> None:
    for attempt, record in zip(
        plan["lanes"][lane]["attempts"], records[lane], strict=True
    ):
        if attempt["worker_count"] != workers:
            continue
        work = record["metrics"]["work_disclosure"]
        work["field_additions"] = additions
        work["profile_sha256"] = digest * 64


class ExactWorkCellTests(unittest.TestCase):
    def test_authority_is_plan_derived_deterministic_and_byte_stable(self) -> None:
        plan, records = fixture()
        first = cells.validate_cell_authority(plan, records, LANES)
        second = cells.validate_cell_authority(plan, records, LANES)
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        self.assertTrue(first["every_attempt_complete_exact_work"])
        self.assertTrue(first["every_cell_deterministic"])
        self.assertEqual(first["expected_attempts"], 10)
        self.assertEqual(first["expected_cells"], 4)
        self.assertEqual(first["complete_cells"], 4)
        index = cells.cell_index(first)
        self.assertEqual(index[("cpu-native", "fixture-workload", 1)]["verified_records"], 3)
        self.assertEqual(index[("metal-hybrid", "fixture-workload", 2)]["verified_records"], 2)

    def test_failed_attempt_is_valid_but_nonnormative(self) -> None:
        plan, records = fixture()
        records["cpu-native"][0] = {"status": "failed", "metrics": None}
        authority = cells.validate_cell_authority(plan, records, LANES)
        self.assertFalse(authority["every_attempt_complete_exact_work"])
        self.assertTrue(authority["every_cell_deterministic"])
        self.assertEqual(authority["verified_exact_attempts"], 9)
        self.assertEqual(authority["complete_cells"], 3)

    def test_verified_attempt_without_exact_profile_rejects(self) -> None:
        plan, records = fixture()
        records["cpu-native"][0]["metrics"] = {}
        with self.assertRaisesRegex(CaptureError, "lacks exact V2"):
            cells.validate_cell_authority(plan, records, LANES)

    def test_one_repeat_drifting_inside_cell_rejects(self) -> None:
        plan, records = fixture()
        records["cpu-native"][1]["metrics"]["work_disclosure"][
            "field_additions"
        ] += 1
        with self.assertRaisesRegex(CaptureError, "within execution cell"):
            cells.validate_cell_authority(plan, records, LANES)

    def test_cross_worker_and_cross_lane_execution_work_may_differ(self) -> None:
        plan, records = fixture()
        mutate_cell(
            plan,
            records,
            lane="cpu-native",
            workers=2,
            additions=10_001 + 2_981_970,
            digest="4",
        )
        for attempt, record in zip(
            plan["lanes"]["cpu-native"]["attempts"],
            records["cpu-native"],
            strict=True,
        ):
            if attempt["worker_count"] == 2:
                work = record["metrics"]["work_disclosure"]
                work["field_multiplications"] += 164
                work["field_inversions"] += 3
        mutate_cell(
            plan,
            records,
            lane="metal-hybrid",
            workers=2,
            additions=10_001 + 41,
            digest="5",
        )
        authority = cells.validate_cell_authority(plan, records, LANES)
        index = cells.cell_index(authority)
        one, two = cells.require_cells(
            index,
            (
                ("cpu-native", "fixture-workload", 1),
                ("cpu-native", "fixture-workload", 2),
            ),
        )
        comparison = cells.compare_cells(
            one,
            two,
            relation="subject_worker_minus_lane_local_one_worker",
            blocking=False,
        )
        additions = comparison["counter_comparisons"]["field_additions"]
        self.assertEqual(additions["signed_delta"], 2_981_970)
        self.assertEqual(
            comparison["counter_comparisons"]["field_multiplications"][
                "signed_delta"
            ],
            164,
        )
        self.assertEqual(
            comparison["counter_comparisons"]["field_inversions"][
                "signed_delta"
            ],
            3,
        )
        self.assertEqual(additions["ratio"]["numerator"], 2_991_971)
        self.assertEqual(additions["ratio"]["denominator"], 10_001)
        self.assertFalse(comparison["blocking"])

        cpu, metal = cells.require_cells(
            index,
            (
                ("cpu-native", "fixture-workload", 2),
                ("metal-hybrid", "fixture-workload", 2),
            ),
        )
        observational = cells.compare_cells(
            cpu, metal, relation="metal_minus_cpu", blocking=False
        )
        self.assertLess(
            observational["counter_comparisons"]["field_additions"]["signed_delta"],
            0,
        )

    def test_cell_coverage_geometry_is_observational_across_cells(self) -> None:
        plan, records = fixture()
        for attempt, record in zip(
            plan["lanes"]["cpu-native"]["attempts"],
            records["cpu-native"],
            strict=True,
        ):
            if attempt["worker_count"] == 2:
                work = record["metrics"]["work_disclosure"]
                work["record_count"] = 20
                work["producer_counts"][0] += 1
                work["profile_sha256"] = "6" * 64
        authority = cells.validate_cell_authority(plan, records, LANES)
        index = cells.cell_index(authority)
        one = index[("cpu-native", "fixture-workload", 1)]
        two = index[("cpu-native", "fixture-workload", 2)]
        self.assertNotEqual(one["coverage_sha256"], two["coverage_sha256"])

    def test_zero_reference_ratios_and_full_u64_signed_deltas_are_canonical(self) -> None:
        zero = cells.counter_comparison(0, 7)
        self.assertEqual(zero["signed_delta"], 7)
        self.assertEqual(zero["ratio"]["availability"], "undefined_zero_reference")
        self.assertEqual(zero["ratio"]["denominator"], 0)
        self.assertEqual(
            cells.counter_comparison(U64_MAX, 0)["signed_delta"], -U64_MAX
        )
        self.assertEqual(
            cells.counter_comparison(0, U64_MAX)["signed_delta"], U64_MAX
        )
        for invalid in (-1, U64_MAX + 1, True):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                CaptureError, "unsigned 64-bit"
            ):
                cells.counter_comparison(invalid, 0)

    def test_cell_inventory_rejects_missing_duplicate_and_wrong_lane_authority(self) -> None:
        plan, records = fixture()
        authority = cells.validate_cell_authority(plan, records, LANES)
        duplicated = copy.deepcopy(authority)
        duplicated["cells"].append(copy.deepcopy(duplicated["cells"][0]))
        with self.assertRaisesRegex(CaptureError, "repeats a cell"):
            cells.cell_index(duplicated)
        index = cells.cell_index(authority)
        with self.assertRaisesRegex(CaptureError, "lacks cell"):
            cells.require_cells(index, (("cpu-native", "fixture-workload", 8),))
        wrong_lanes = copy.deepcopy(records)
        wrong_lanes["cuda"] = wrong_lanes.pop("metal-hybrid")
        with self.assertRaisesRegex(CaptureError, "lane inventory"):
            cells.validate_cell_authority(plan, wrong_lanes, LANES)

    def test_disclosure_shape_and_coverage_are_revalidated(self) -> None:
        invalids = (
            ("source_mask", 0x1F),
            ("producer_coverage_terminal_sealed", False),
            ("profile_sha256", "A" * 64),
            ("field_additions", U64_MAX + 1),
        )
        for field, value in invalids:
            with self.subTest(field=field):
                work = disclosure()
                work[field] = value
                with self.assertRaises(CaptureError):
                    cells.validate_disclosure(work)

    def test_independent_reduction_replay_rejects_every_comparison_mutation(self) -> None:
        expected = {
            "schema": "stwo.typed-air.r006-paired-scaling-reduction.v2",
            "schema_version": 2,
            "plan_sha256": "1" * 64,
            "bundle_sha256": "2" * 64,
            "scaling_verdict": "PASS",
            "m7_verdict": "NO_VERDICT_MISSING_PREDECESSOR_ONE_WORKER_COHORT",
            "rows": [
                {
                    "executed_work_comparison": {
                        "counter_comparisons": {
                            "field_additions": cells.counter_comparison(10, 12)
                        }
                    }
                }
            ],
            "cross_lane_executed_work_observations": [],
        }
        with tempfile.TemporaryDirectory() as temporary:
            receipt = Path(temporary) / "reduction.json"
            receipt.write_bytes(canonical_bytes(expected))
            with mock.patch.object(
                reduction, "evaluate_pair_scaling", return_value=expected
            ):
                validated = reduction.validate_pair_reduction(
                    Path(temporary), Path(temporary), receipt
                )
                self.assertEqual(validated["schema_version"], 2)
                mutations = []
                for field, value in (
                    ("reference", 11),
                    ("signed_delta", -2),
                ):
                    changed = copy.deepcopy(expected)
                    changed["rows"][0]["executed_work_comparison"][
                        "counter_comparisons"
                    ]["field_additions"][field] = value
                    mutations.append(changed)
                changed = copy.deepcopy(expected)
                changed["rows"][0]["executed_work_comparison"][
                    "counter_comparisons"
                ]["field_additions"]["ratio"]["numerator"] = 13
                mutations.append(changed)
                changed = copy.deepcopy(expected)
                del changed["rows"][0]["executed_work_comparison"][
                    "counter_comparisons"
                ]["field_additions"]
                mutations.append(changed)
                changed = copy.deepcopy(expected)
                changed["rows"].append(copy.deepcopy(changed["rows"][0]))
                mutations.append(changed)
                for index, changed in enumerate(mutations):
                    with self.subTest(mutation=index):
                        receipt.write_bytes(canonical_bytes(changed))
                        with self.assertRaisesRegex(CaptureError, "differs"):
                            reduction.validate_pair_reduction(
                                Path(temporary), Path(temporary), receipt
                            )


if __name__ == "__main__":
    unittest.main()
