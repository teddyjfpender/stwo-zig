from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from scripts.typed_air_c013_capture_lib import schedule
from scripts.typed_air_c013_capture_lib.codec import content_digest
from scripts.typed_air_c013_capture_lib.model import (
    CORPUS_DIGESTS,
    CaptureError,
    SCHEDULE_SHA256,
)
from scripts.typed_air_c013_capture_lib.statistics import (
    calibration_gate,
    evaluate_calibration,
    evaluate_m6_cpu,
)


class CalibrationStatisticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[2]
        cls.plan = {"calibration_gate": calibration_gate(cls.root)}

    @staticmethod
    def _report() -> dict[str, object]:
        return {
            "proof_sha256": "ab" * 32,
            "metrics": {
                "execution_steps": 131_078,
                "proof_wire_bytes": 123_456,
                "preprocessed_cells": 100,
                "main_cells": 200,
                "interaction_cells": 300,
                "verified_request_ns": 1_000,
                "proving_ns": 800,
            },
            "resources": {
                "lifetime_peak_physical_footprint_bytes": 1_000_000,
            },
        }

    def _captures(self) -> list[tuple[dict[str, object], dict[str, object]]]:
        return [
            (attempt.__dict__, self._report())
            for attempt in schedule.all_attempts()[:80]
        ]

    def test_identical_labels_pass_every_calibration_metric(self) -> None:
        result = evaluate_calibration(self.root, self.plan, self._captures())
        self.assertEqual(result["verdict"], "PASS")
        for metric in result["metrics"].values():
            self.assertEqual(metric["round_ratios"], [1.0, 1.0, 1.0])
            self.assertEqual(metric["ci_lower"], 1.0)
            self.assertEqual(metric["ci_upper"], 1.0)
            self.assertTrue(metric["pass"])

    def test_large_label_bias_yields_no_verdict(self) -> None:
        captures = self._captures()
        for attempt, report in captures:
            if attempt["arm"] == "a_control":
                report["metrics"]["verified_request_ns"] *= 2
                report["metrics"]["proving_ns"] *= 2
        result = evaluate_calibration(self.root, self.plan, captures)
        self.assertEqual(result["verdict"], "NO_VERDICT")
        self.assertFalse(result["metrics"]["verified_request_ns"]["contains_one"])

    def test_proof_identity_drift_rejects_before_statistics(self) -> None:
        captures = self._captures()
        captures[-1][1]["proof_sha256"] = "cd" * 32
        with self.assertRaisesRegex(Exception, "proof or geometry"):
            evaluate_calibration(self.root, self.plan, captures)


class M6CpuStatisticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).resolve().parents[2]

    @staticmethod
    def _attempts() -> list[dict[str, object]]:
        return [dict(item.__dict__) for item in schedule.all_attempts()]

    def _captures(
        self,
    ) -> tuple[
        dict[str, object],
        list[tuple[dict[str, object], dict[str, object], dict[str, object]]],
    ]:
        attempts = self._attempts()
        plan = {
            "content_sha256": "ab" * 32,
            "schedule": {"sha256": SCHEDULE_SHA256},
            "protocol": {"sha256": "10" * 32},
            "source": {"commit": "1" * 40, "tree": "2" * 40},
            "host": {"cpu_model": "fixture"},
            "environment": {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
            "artifacts": {"fixture": {"sha256": "20" * 32}},
            "corpus_manifest": {"document_sha256": "30" * 32},
            "calibration_gate": calibration_gate(self.root),
            "attempts": attempts,
        }
        captures = []
        for attempt in attempts[schedule.CALIBRATION_ATTEMPTS :]:
            calls = attempt["calls"]
            arm = attempt["arm"]
            assert isinstance(calls, int) and isinstance(arm, str)
            if calls == 0:
                precompile_duration = 2_000
                precompile_cells = 1_200
            elif calls == 1:
                precompile_duration = 2_000
                precompile_cells = 1_100
            elif calls == 8:
                precompile_duration = 1_500
                precompile_cells = 900
            elif calls == 512:
                precompile_duration = 1_000
                precompile_cells = 800
            elif calls == 4096:
                precompile_duration = 1_000
                precompile_cells = 700
            else:
                precompile_duration = 1_000
                precompile_cells = 900
            duration = 2_000 if arm == "software" else precompile_duration
            committed_cells = 1_000 if arm == "software" else precompile_cells
            main_cells = committed_cells // 2
            interaction_cells = committed_cells - 100 - main_cells
            resource = 1_000 if arm == "software" else 900
            verification = 200 if arm == "software" else 180
            execution = duration // 4
            proving = duration - execution - verification
            proof_bytes = 1_000 if arm == "software" else 1_050
            identity = (
                f"{attempt['shape']}:{calls}:{arm}".encode("ascii")
            )
            input_digest, output_digest = CORPUS_DIGESTS[calls]
            report = {
                "status": "verified",
                "input_sha256": input_digest,
                "output_sha256": output_digest,
                "proof_sha256": hashlib.sha256(identity).hexdigest(),
                "metrics": {
                    "execution_steps": 100 if arm == "software" else 80,
                    "execution_ns": execution,
                    "proving_ns": proving,
                    "proof_encoding_ns": duration // 8,
                    "verification_ns": verification,
                    "verified_request_ns": duration,
                    "proof_wire_bytes": proof_bytes,
                    "preprocessed_cells": 100,
                    "main_cells": main_cells,
                    "interaction_cells": interaction_cells,
                },
                "resources": {
                    "lifetime_peak_physical_footprint_bytes": resource,
                    "process_cpu_ns": resource,
                    "energy_nj": resource,
                    "instructions": resource,
                    "cycles": resource,
                },
            }
            record = {
                "global_ordinal": attempt["global_ordinal"],
                "status": "verified",
                "launcher_elapsed_ns": duration,
            }
            captures.append((attempt, record, report))
        return plan, captures

    def test_complete_cpu_cohort_reduces_every_cell_and_discloses_boundary(
        self,
    ) -> None:
        plan, captures = self._captures()
        result = evaluate_m6_cpu(self.root, plan, captures)
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(len(result["cells"]), 18)
        self.assertEqual(
            [item["first_qualifying_calls"] for item in result["crossovers"]],
            [8, 8, 8],
        )
        self.assertGreaterEqual(result["primary_target"]["ci_lower"], 1.10)
        self.assertFalse(result["claim_boundary"]["promotion_receipt"])
        self.assertEqual(
            result["claim_boundary"]["missing_required_lanes"],
            ["metal-hybrid"],
        )
        self.assertEqual(result["content_sha256"], content_digest(result))
        self.assertEqual(result, evaluate_m6_cpu(self.root, plan, captures))

    def test_total_work_regression_is_a_cpu_lane_failure(self) -> None:
        plan, captures = self._captures()
        for attempt, _, report in captures:
            if (
                attempt["shape"] == "poseidon2_dominant"
                and attempt["calls"] == 4096
                and attempt["arm"] == "precompile"
            ):
                report["resources"]["process_cpu_ns"] = 2_000
        result = evaluate_m6_cpu(self.root, plan, captures)
        self.assertEqual(result["verdict"], "FAIL")
        primary = next(
            cell
            for cell in result["cells"]
            if cell["shape"] == "poseidon2_dominant"
            and cell["calls"] == 4096
        )
        self.assertFalse(primary["gates"]["process_cpu_work"]["pass"])

    def test_geometry_drift_and_attempt_reordering_fail_closed(self) -> None:
        plan, captures = self._captures()
        captures[0][2]["metrics"]["main_cells"] += 1
        with self.assertRaisesRegex(CaptureError, "main_cells changed"):
            evaluate_m6_cpu(self.root, plan, captures)

        plan, captures = self._captures()
        captures[0], captures[1] = captures[1], captures[0]
        with self.assertRaisesRegex(CaptureError, "differs from its plan"):
            evaluate_m6_cpu(self.root, plan, captures)


if __name__ == "__main__":
    unittest.main()
