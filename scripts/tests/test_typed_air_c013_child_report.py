from __future__ import annotations

import copy
import json
import unittest

from scripts.typed_air_c013_capture_lib.child_report import (
    CALIBRATION_SCHEMA,
    POSEIDON_SCHEMA,
    RESOURCE_SCOPE,
    SECURE_PCS,
    command_for_attempt,
    validate_child_report,
)
from scripts.typed_air_c013_capture_lib.model import CaptureError, SCHEDULE_SHA256


DIGEST = "ab" * 32


def _plan() -> dict[str, object]:
    return {
        "source": {"commit": "1" * 40, "tree": "2" * 40},
        "artifacts": {
            "calibration_child": {
                "path": "/capture/calibration-child",
                "sha256": "10" * 32,
            },
            "calibration_elf": {
                "path": "/capture/calibration.elf",
                "sha256": "11" * 32,
            },
            "poseidon2_proof_child": {
                "path": "/capture/poseidon-child",
                "sha256": "20" * 32,
            },
            "poseidon2_dominant_precompile_elf": {
                "path": "/capture/precompile.elf",
                "sha256": "21" * 32,
            },
        },
    }


def _metrics() -> dict[str, int]:
    return {
        "execution_steps": 10,
        "execution_ns": 11,
        "proving_ns": 13,
        "proof_encoding_ns": 17,
        "verification_ns": 19,
        "verified_request_ns": 43,
        "proof_wire_bytes": 23,
        "preprocessed_cells": 29,
        "main_cells": 31,
        "interaction_cells": 37,
    }


def _resources() -> dict[str, object]:
    return {
        "scope": RESOURCE_SCOPE,
        "source": "darwin_proc_pid_rusage_v6",
        "lifetime_peak_physical_footprint_bytes": 101,
        "process_cpu_ns": 102,
        "energy_nj": 103,
        "instructions": 107,
        "cycles": 109,
        "unavailable_reason": None,
    }


def _common(attempt: dict[str, object], plan: dict[str, object]) -> dict[str, object]:
    artifacts = plan["artifacts"]
    return {
        "status": "verified",
        "security": "secure",
        "phase": attempt["phase"],
        "schedule_sha256": SCHEDULE_SHA256,
        "sample_index": attempt["sample_index"],
        "max_steps": 262_144,
        "input_bytes": attempt["input_bytes"],
        "output_bytes": attempt["output_bytes"],
        "input_sha256": attempt["input_sha256"],
        "output_sha256": attempt["output_sha256"],
        "elf_sha256": artifacts[attempt["elf_id"]]["sha256"],
        "executable_sha256": artifacts[attempt["executable_id"]]["sha256"],
        "proof_sha256": DIGEST,
        "implementation_commit": plan["source"]["commit"],
        "implementation_tree": plan["source"]["tree"],
        "implementation_dirty": False,
        "dirty_content_sha256": None,
        "pcs": dict(SECURE_PCS),
        "metrics": _metrics(),
        "resources": _resources(),
    }


def _encoded(report: dict[str, object]) -> bytes:
    return json.dumps(report, separators=(",", ":")).encode() + b"\n"


class ChildReportTests(unittest.TestCase):
    def test_calibration_command_and_report_bind_every_identity(self) -> None:
        plan = _plan()
        attempt = {
            "kind": "calibration",
            "phase": "calibration",
            "arm": "a_control",
            "sample_index": 79,
            "input_bytes": 0,
            "output_bytes": 0,
            "input_sha256": "e3" * 32,
            "output_sha256": "e3" * 32,
            "executable_id": "calibration_child",
            "elf_id": "calibration_elf",
        }
        command = command_for_attempt(plan, attempt)
        self.assertEqual(command[0], "/capture/calibration-child")
        self.assertIn("a_control", command)
        self.assertIn(SCHEDULE_SHA256, command)
        self.assertIn("10" * 32, command)
        self.assertIn("11" * 32, command)

        report = {
            "schema": CALIBRATION_SCHEMA,
            "label": "a_control",
            "workload": "multi_shard_addi",
            **_common(attempt, plan),
        }
        self.assertEqual(
            validate_child_report(_encoded(report), plan=plan, attempt=attempt),
            report,
        )

        drifted = copy.deepcopy(report)
        drifted["implementation_dirty"] = True
        with self.assertRaisesRegex(CaptureError, "implementation_dirty"):
            validate_child_report(_encoded(drifted), plan=plan, attempt=attempt)

    def test_poseidon_report_rejects_schedule_resource_and_geometry_drift(self) -> None:
        plan = _plan()
        attempt = {
            "kind": "m6",
            "phase": "measured",
            "arm": "precompile",
            "shape": "poseidon2_dominant",
            "calls": 8,
            "sample_index": 1_439,
            "input_bytes": 516,
            "output_bytes": 512,
            "input_sha256": "30" * 32,
            "output_sha256": "31" * 32,
            "executable_id": "poseidon2_proof_child",
            "elf_id": "poseidon2_dominant_precompile_elf",
        }
        report = {
            "schema": POSEIDON_SCHEMA,
            "arm": "precompile",
            "shape": "poseidon2_dominant",
            "background_permutations_per_call": 0,
            "calls": 8,
            "extension_calls": 8,
            **_common(attempt, plan),
        }
        report["max_steps"] = 900_000
        validate_child_report(_encoded(report), plan=plan, attempt=attempt)

        for mutate, message in (
            (lambda item: item.update(schedule_sha256="00" * 32), "schedule"),
            (
                lambda item: item["resources"].update(source="unsupported"),
                "resource adapter",
            ),
            (
                lambda item: item["resources"].update(process_cpu_ns=0),
                "process_cpu_ns",
            ),
            (lambda item: item.update(extension_calls=7), "extension_calls"),
        ):
            drifted = copy.deepcopy(report)
            mutate(drifted)
            with self.assertRaisesRegex(CaptureError, message):
                validate_child_report(_encoded(drifted), plan=plan, attempt=attempt)

    def test_child_stdout_must_be_exactly_one_line(self) -> None:
        with self.assertRaisesRegex(CaptureError, "exactly one"):
            validate_child_report(b"{}\n{}\n", plan={}, attempt={})


if __name__ == "__main__":
    unittest.main()
