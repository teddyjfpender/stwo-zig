from __future__ import annotations

import copy
import contextlib
import datetime as dt
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import typed_air_c013_capture as capture_cli
from scripts.typed_air_c013_capture_lib import schedule
from scripts.typed_air_c013_capture_lib.bundle import BundleValidation
from scripts.typed_air_c013_capture_lib.codec import content_digest
from scripts.typed_air_c013_capture_lib.model import CaptureError
from scripts.typed_air_c013_capture_lib.model import CORPUS_DIGESTS
from scripts.typed_air_c013_capture_lib.plan import (
    ARTIFACT_IDS,
    REQUIRED_EXECUTABLE_MARKERS,
    PlanSettings,
    build_plan,
    validate_plan,
    write_plan_new,
)


class ScheduleTests(unittest.TestCase):
    def test_digest_matches_zig_authority(self) -> None:
        schedule.validate_authority()
        self.assertEqual(schedule.schedule_digest(), schedule.SCHEDULE_SHA256)

    def test_global_schedule_starts_with_complete_calibration(self) -> None:
        attempts = schedule.all_attempts()
        self.assertEqual(len(attempts), 1_520)
        self.assertTrue(all(item.kind == "calibration" for item in attempts[:80]))
        self.assertTrue(all(item.kind == "m6" for item in attempts[80:]))
        self.assertEqual(attempts[0].arm, "a")
        self.assertEqual(attempts[1].arm, "a_control")
        self.assertEqual(attempts[2].arm, "a_control")
        self.assertEqual(attempts[3].arm, "a")

    def test_m6_cells_are_shape_major_call_minor_and_balanced(self) -> None:
        attempts = schedule.all_attempts()[80:]
        cells = [attempts[index : index + 80] for index in range(0, 1_440, 80)]
        identities = [(cell[0].shape, cell[0].calls) for cell in cells]
        self.assertEqual(
            identities,
            [
                (shape, calls)
                for shape in schedule.SHAPES
                for calls in schedule.CALL_COUNTS
            ],
        )
        for cell in cells:
            self.assertEqual(sum(item.arm == "software" for item in cell), 40)
            self.assertEqual(sum(item.arm == "precompile" for item in cell), 40)
            self.assertEqual(sum(item.phase == "warmup" for item in cell), 20)
            self.assertEqual(sum(item.phase == "measured" for item in cell), 60)


class PlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(__file__).resolve().parents[2]
        artifact_root = Path(self.temporary.name) / "artifacts"
        artifact_root.mkdir()
        self.artifacts: dict[str, Path] = {}
        for index, name in enumerate(sorted(ARTIFACT_IDS)):
            path = artifact_root / name
            path.write_bytes(
                f"artifact:{index}:{name}".encode("ascii")
                + REQUIRED_EXECUTABLE_MARKERS.get(name, b"")
            )
            if name.endswith("child") or name.endswith("tool"):
                path.chmod(0o700)
            self.artifacts[name] = path

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _source(_: Path) -> dict[str, object]:
        return {
            "repository": "https://github.com/teddyjfpender/stwo-zig",
            "commit": "1" * 40,
            "tree": "2" * 40,
            "clean": True,
            "status_porcelain": [],
        }

    @staticmethod
    def _host(power_state: str) -> dict[str, object]:
        return {
            "os": "Darwin",
            "os_version": "fixture",
            "kernel_release": "fixture",
            "machine": "arm64",
            "cpu_model": "fixture-cpu",
            "logical_cores": 8,
            "physical_cores": 4,
            "memory_bytes": 16 * 1024**3,
            "power_state": {
                "operator_declaration": power_state,
                "machine_verified": False,
            },
        }

    @staticmethod
    def _corpus(_: Path, __: Path) -> bytes:
        records = []
        for calls in schedule.CALL_COUNTS:
            input_digest, output_digest = CORPUS_DIGESTS[calls]
            records.append(
                {
                    "calls": calls,
                    "input_bytes": 4 + calls * 64,
                    "output_bytes": calls * 64,
                    "input_sha256": input_digest,
                    "output_sha256": output_digest,
                }
            )
        document = {
            "schema": "stwo.c013.poseidon2-corpus-manifest.v1",
            "generator": "poseidon2-software-precompile-equivalence-v1",
            "seed": "stwo-typed-air-m6-poseidon2-v1",
            "call_counts": list(schedule.CALL_COUNTS),
            "records": records,
        }
        return json.dumps(document, separators=(",", ":")).encode() + b"\n"

    def _plan(self) -> dict[str, object]:
        return build_plan(
            PlanSettings(
                repository=self.root,
                session_id="fixture-session",
                power_state="AC power; fixture",
                artifacts=self.artifacts,
            ),
            source_provider=self._source,
            host_provider=self._host,
            tool_runner=self._corpus,
            clock=lambda: dt.datetime(2026, 8, 11, tzinfo=dt.timezone.utc),
        )

    def test_plan_closes_all_artifacts_corpus_and_attempts(self) -> None:
        plan = self._plan()
        self.assertEqual(len(plan["attempts"]), 1_520)
        self.assertEqual(plan["attempts"][79]["kind"], "calibration")
        self.assertEqual(plan["attempts"][80]["kind"], "m6")
        self.assertEqual(plan["attempts"][-1]["calls"], 4096)
        self.assertEqual(plan["content_sha256"], content_digest(plan))
        validate_plan(
            plan,
            repository=self.root,
            verify_local=True,
            source_provider=self._source,
        )

    def test_attempt_reorder_rejects_even_with_recomputed_content_digest(self) -> None:
        plan = copy.deepcopy(self._plan())
        plan["attempts"][80], plan["attempts"][81] = (
            plan["attempts"][81],
            plan["attempts"][80],
        )
        plan["content_sha256"] = content_digest(plan)
        with self.assertRaisesRegex(CaptureError, "frozen schedule"):
            validate_plan(plan, repository=self.root, verify_local=False)

    def test_artifact_mutation_rejects_and_plan_publish_is_create_only(self) -> None:
        plan = self._plan()
        output = Path(self.temporary.name) / "plan.json"
        first = write_plan_new(output, plan)
        self.assertEqual(output.read_bytes(), first)
        with self.assertRaisesRegex(CaptureError, "refusing to replace"):
            write_plan_new(output, plan)

        calibration = self.artifacts["calibration_elf"]
        with calibration.open("ab") as destination:
            destination.write(b"drift")
        with self.assertRaisesRegex(CaptureError, "changed after plan"):
            validate_plan(
                plan,
                repository=self.root,
                verify_local=True,
                source_provider=self._source,
            )

    def test_stale_installed_capture_child_rejects_before_plan_publication(
        self,
    ) -> None:
        self.artifacts["poseidon2_proof_child"].write_bytes(
            b"stwo.c013.poseidon2-cpu-proof-child.v1"
        )
        with self.assertRaisesRegex(CaptureError, "current protocol marker"):
            self._plan()


class CommandTests(unittest.TestCase):
    def test_validate_bundle_command_exposes_cpu_and_m6_claim_boundaries(
        self,
    ) -> None:
        result = BundleValidation(
            capture_status="CAPTURE_COMPLETE_AWAITING_RECEIPT_VALIDATION",
            planned_attempts=1_520,
            recorded_attempts=1_520,
            verified_attempts=1_520,
            failed_attempts=0,
            calibration_verdict="PASS",
            cpu_reduction_verdict="PASS",
            m6_verdict=None,
            normative_receipt=False,
            remaining_gaps=("metal-hybrid",),
            bundle_file_sha256="aa" * 32,
            plan_file_sha256="bb" * 32,
        )
        raw_output = io.BytesIO()
        output = io.TextIOWrapper(raw_output, encoding="utf-8")
        with (
            mock.patch.object(capture_cli, "validate_bundle", return_value=result),
            contextlib.redirect_stdout(output),
        ):
            status = capture_cli.main(
                [
                    "--repository",
                    str(Path(__file__).resolve().parents[2]),
                    "validate-bundle",
                    "/capture/bundle",
                ]
            )
        self.assertEqual(status, 0)
        output.flush()
        document = json.loads(raw_output.getvalue())
        self.assertEqual(document["cpu_reduction_verdict"], "PASS")
        self.assertIsNone(document["m6_verdict"])
        self.assertFalse(document["normative_receipt"])


if __name__ == "__main__":
    unittest.main()
