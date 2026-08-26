from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scripts.riscv_csp_ab_benchmark_lib import runner as ab_runner
from scripts.riscv_csp_benchmark_lib.host import power_conditions_admissible
from scripts.typed_air_p003_completion import (
    BLOCKER_SCHEMA,
    DEFAULT_MATRIX,
    FAMILY_IDS,
    SITE_IDS,
    CompletionError,
    _inventory_authority,
    build_blocker_receipt,
    main,
    validate_blocker_receipt,
    validate_matrix,
)
from scripts.typed_air_r006_capture_lib.codec import canonical_bytes, decode_strict
from scripts.typed_air_r006_capture_lib.model import CaptureError
from scripts.typed_air_r006_capture_lib.orchestration import host_preflight


class P003CompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.scratch = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _preflight(*, admitted: bool) -> dict[str, object]:
        host = {
            "os": "Darwin",
            "os_version": "fixture",
            "kernel": "fixture",
            "architecture": "arm64",
            "host_architecture": "arm64",
            "cpu": "fixture-cpu",
            "logical_cpu_count": 18,
            "memory_bytes": 64 * 1024**3,
            "power_source": "AC Power" if admitted else "Battery Power",
            "low_power_mode": False if admitted else True,
            "python": "fixture",
            "gpu": {
                "name": "fixture-gpu",
                "core_count": 40,
                "metal_support": "Metal fixture",
                "unified_memory": True,
            },
        }
        power_admissible, power_reasons = power_conditions_admissible(host)
        quiet = ab_runner.classify_quiet_host(
            idle_percent=(97.0, 98.0, 99.0),
            load_1m=(0.1, 0.1, 0.1),
            logical_cpu_count=18,
            thermal={
                "provider": "darwin_top_pmset_v1",
                "thermal_clear": True,
                "thermal_output_sha256": "0" * 64,
                "thermal_line_count": 3,
                "kernel_thermal_pressure": None,
            },
            power_admissible=power_admissible,
            power_reasons=power_reasons,
            enforce_load_threshold=True,
        )
        return host_preflight(
            host_provider=lambda: host,
            quiet_provider=lambda _: quiet,
        )

    def _matrix_value(self) -> dict[str, object]:
        value = decode_strict(DEFAULT_MATRIX.read_bytes())
        self.assertIs(type(value), dict)
        return value

    def _write_matrix(self, value: dict[str, object], name: str) -> Path:
        path = self.scratch / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_tracked_matrix_pins_sixteen_families_and_all_twenty_three_sites(self) -> None:
        report = validate_matrix()
        self.assertEqual(len(report["coverage"]["families"]), len(FAMILY_IDS))
        self.assertEqual(report["inventory"]["site_count"], len(SITE_IDS))
        self.assertEqual(
            report["coverage"]["cpu"],
            {"complete": 16, "partial": 0, "absent": 0},
        )
        self.assertEqual(
            report["coverage"]["metal"],
            {"complete": 16, "partial": 0, "absent": 0},
        )
        self.assertEqual(
            report["coverage"]["joint"],
            {"complete": 16, "partial": 0, "absent": 0},
        )
        self.assertTrue(report["coverage"]["whole_prover_exact"])

    def test_family_deletion_and_site_substitution_fail_closed(self) -> None:
        for mutation, expected in (
            (
                lambda value: value["families"].pop(),
                "exactly sixteen families",
            ),
            (
                lambda value: value["families"][0]["typed_sites"].__setitem__(
                    0, "invented_site"
                ),
                "unknown typed sites",
            ),
        ):
            value = self._matrix_value()
            mutation(value)
            with self.subTest(expected=expected), self.assertRaisesRegex(
                CompletionError, expected
            ):
                validate_matrix(self._write_matrix(value, f"{expected[:4]}.json"))

    def test_status_and_blockers_cannot_disagree(self) -> None:
        value = self._matrix_value()
        value["families"][0]["cpu"]["blockers"] = ["fictional blocker"]
        with self.assertRaisesRegex(CompletionError, "exactly when status is complete"):
            validate_matrix(self._write_matrix(value, "complete-with-blocker.json"))

        value = self._matrix_value()
        value["families"][8]["metal"]["status"] = "partial"
        with self.assertRaisesRegex(CompletionError, "exactly when status is complete"):
            validate_matrix(self._write_matrix(value, "partial-without-blocker.json"))

    def test_inventory_parser_rejects_order_and_schema_drift(self) -> None:
        source = Path(
            "src/prover_api/work_profile_inventory.zig"
        ).read_text(encoding="utf-8")
        for old, new in (
            ("SCHEMA_VERSION: u16 = 9", "SCHEMA_VERSION: u16 = 10"),
            ("column_passthrough_fft = 0", "column_passthrough_fft = 1"),
        ):
            path = self.scratch / f"inventory-{new[-1]}.zig"
            path.write_text(source.replace(old, new, 1), encoding="utf-8")
            with self.subTest(new=new), self.assertRaisesRegex(
                CompletionError, "inventory schema, order, or total mapping drifted"
            ):
                _inventory_authority(path)

    def test_admitted_host_and_complete_closure_require_scaling_capture(self) -> None:
        with self.assertRaisesRegex(CompletionError, "run the existing R-006 capture"):
            build_blocker_receipt(DEFAULT_MATRIX, self._preflight(admitted=True))

    def test_rejected_host_and_matrix_recompute_to_identical_blocker(self) -> None:
        receipt = build_blocker_receipt(DEFAULT_MATRIX, self._preflight(admitted=False))
        path = self.scratch / "blocker.json"
        path.write_bytes(canonical_bytes(receipt))
        replayed = validate_blocker_receipt(DEFAULT_MATRIX, path)
        self.assertEqual(replayed, receipt)
        self.assertIn(
            "R006_HOST_PREFLIGHT_REJECTED",
            {blocker["code"] for blocker in receipt["blockers"]},
        )
        self.assertNotIn(
            "P003_CPU_CLOSURE_INCOMPLETE",
            {blocker["code"] for blocker in receipt["blockers"]},
        )
        self.assertTrue(receipt["coverage"]["whole_prover_exact"])

        changed = copy.deepcopy(receipt)
        changed["coverage"]["joint"]["complete"] += 1
        changed_path = self.scratch / "mutated.json"
        changed_path.write_bytes(canonical_bytes(changed))
        with self.assertRaisesRegex(CompletionError, "authority changed"):
            validate_blocker_receipt(DEFAULT_MATRIX, changed_path)

    def test_tracked_legacy_blocker_replays_without_admitting_v1_capture(self) -> None:
        path = Path(
            "design/typed-air/artifacts/p003-work-profile-closure-v1/"
            "scaling-blocker-v1.json"
        )
        receipt = validate_blocker_receipt(DEFAULT_MATRIX, path)
        self.assertEqual(receipt["host_preflight"]["schema_version"], 1)
        with self.assertRaisesRegex(CaptureError, "host-preflight authority changed"):
            build_blocker_receipt(DEFAULT_MATRIX, receipt["host_preflight"])

    def test_cli_emits_create_only_blocker_and_replays_it(self) -> None:
        preflight = self.scratch / "preflight.json"
        preflight.write_bytes(canonical_bytes(self._preflight(admitted=False)))
        receipt = self.scratch / "receipt.json"
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(
                main(
                    [
                        "emit-blocker",
                        "--host-preflight",
                        str(preflight),
                        "--output",
                        str(receipt),
                    ]
                ),
                2,
            )
        self.assertTrue(receipt.is_file())
        self.assertEqual(stderr.getvalue(), "")
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(["validate-blocker", str(receipt)]), 0)
            self.assertEqual(
                main(
                    [
                        "emit-blocker",
                        "--host-preflight",
                        str(preflight),
                        "--output",
                        str(receipt),
                    ]
                ),
                2,
            )
        self.assertIn("refusing to replace existing evidence", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
