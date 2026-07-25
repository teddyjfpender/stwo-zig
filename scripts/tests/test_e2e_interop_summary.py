#!/usr/bin/env python3
"""Unit tests for e2e interop summary accounting."""

from __future__ import annotations

import importlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def load_module():
    return importlib.import_module("scripts.e2e_interop_lib.controller")


class ComputeSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = load_module()

    def test_full_success_accounting(self) -> None:
        examples = ["plonk", "xor"]
        steps = [
            {"name": "plonk_rust_to_zig_verify", "status": "ok"},
            {"name": "plonk_zig_to_rust_verify", "status": "ok"},
            {"name": "xor_rust_to_zig_verify", "status": "ok"},
            {"name": "xor_zig_to_rust_verify", "status": "ok"},
            {
                "name": "plonk_rust_to_zig_tamper_reject",
                "status": "ok",
                "expect_failure": True,
                "rejection_class": self.mod.REJECTION_CLASS_VERIFIER,
            },
            {
                "name": "plonk_rust_to_zig_generator_tamper_reject",
                "status": "ok",
                "expect_failure": True,
                "rejection_class": self.mod.REJECTION_CLASS_METADATA,
            },
        ]

        summary = self.mod.compute_summary(examples=examples, steps=steps)
        self.assertEqual(summary["cases_total"], 4)
        self.assertEqual(summary["cases_executed"], 4)
        self.assertEqual(summary["cases_passed"], 4)
        self.assertEqual(summary["cases_failed"], 0)
        self.assertEqual(
            summary["tamper_cases_total"],
            sum(len(self.mod.mutations_for_example(example)) * 2 for example in examples),
        )
        self.assertEqual(summary["tamper_cases_executed"], 2)
        self.assertEqual(summary["tamper_cases_passed"], 2)
        self.assertEqual(summary["tamper_cases_failed"], 0)
        self.assertEqual(
            summary["tamper_rejection_classes"],
            {
                self.mod.REJECTION_CLASS_VERIFIER: 1,
                self.mod.REJECTION_CLASS_METADATA: 1,
            },
        )

    def test_partial_failure_accounting(self) -> None:
        examples = ["state_machine", "wide_fibonacci"]
        steps = [
            {"name": "state_machine_rust_to_zig_verify", "status": "ok"},
            {"name": "state_machine_zig_to_rust_verify", "status": "failed"},
            {
                "name": "state_machine_zig_to_rust_tamper_reject",
                "status": "failed",
                "expect_failure": True,
                "rejection_class": self.mod.REJECTION_CLASS_OTHER,
            },
            {
                "name": "state_machine_zig_to_rust_statement_tamper_reject",
                "status": "ok",
                "expect_failure": True,
                "rejection_class": self.mod.REJECTION_CLASS_VERIFIER,
            },
        ]

        summary = self.mod.compute_summary(examples=examples, steps=steps)
        self.assertEqual(summary["cases_total"], 4)
        self.assertEqual(summary["cases_executed"], 2)
        self.assertEqual(summary["cases_passed"], 1)
        self.assertEqual(summary["cases_failed"], 1)
        self.assertEqual(
            summary["tamper_cases_total"],
            sum(len(self.mod.mutations_for_example(example)) * 2 for example in examples),
        )
        self.assertEqual(summary["tamper_cases_executed"], 2)
        self.assertEqual(summary["tamper_cases_passed"], 1)
        self.assertEqual(summary["tamper_cases_failed"], 1)
        self.assertEqual(
            summary["tamper_rejection_classes"],
            {
                self.mod.REJECTION_CLASS_OTHER: 1,
                self.mod.REJECTION_CLASS_VERIFIER: 1,
            },
        )

    def test_panics_and_signals_are_robustness_failures(self) -> None:
        panic = self.mod.classify_rejection(
            "",
            "thread 'main' panicked at verifier.rs:1: index out of bounds",
            return_code=101,
        )
        signal = self.mod.classify_rejection("", "", return_code=-6)
        self.assertEqual(panic, self.mod.REJECTION_CLASS_ROBUSTNESS)
        self.assertEqual(signal, self.mod.REJECTION_CLASS_ROBUSTNESS)

    def test_controlled_verifier_error_remains_semantic_rejection(self) -> None:
        rejection = self.mod.classify_rejection(
            "",
            "Error: malformed proof rejected at verifier safety boundary",
            return_code=1,
        )
        self.assertEqual(rejection, self.mod.REJECTION_CLASS_VERIFIER)
        zig_claim = self.mod.classify_rejection(
            "",
            "error: InvalidClaimedSum",
            return_code=1,
        )
        rust_claim = self.mod.classify_rejection(
            "",
            "Error: invalid xor claimed_sum",
            return_code=1,
        )
        self.assertEqual(zig_claim, self.mod.REJECTION_CLASS_VERIFIER)
        self.assertEqual(rust_claim, self.mod.REJECTION_CLASS_VERIFIER)
        invalid_log_size = self.mod.classify_rejection(
            "",
            "error: InvalidLogSize",
            return_code=1,
        )
        self.assertEqual(
            invalid_log_size,
            self.mod.REJECTION_CLASS_VERIFIER,
        )
        rust_state_statement = self.mod.classify_rejection(
            "",
            "Error: invalid state_machine statement m",
            return_code=1,
        )
        self.assertEqual(
            rust_state_statement,
            self.mod.REJECTION_CLASS_VERIFIER,
        )
        rust_poseidon_oods = self.mod.classify_rejection(
            "",
            "Error: exact Poseidon split-depth-2 OODS evaluation does not match",
            return_code=1,
        )
        self.assertEqual(
            rust_poseidon_oods,
            self.mod.REJECTION_CLASS_VERIFIER,
        )

    def test_run_step_refuses_to_accept_a_verifier_panic(self) -> None:
        steps = []
        process = subprocess.CompletedProcess(
            ["verifier"],
            101,
            stdout="",
            stderr="thread 'main' panicked at verifier.rs:1: index out of bounds",
        )
        with mock.patch.object(self.mod.subprocess, "run", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "expected non-zero exit code"):
                self.mod.run_step(
                    name="panic_is_not_rejection",
                    cmd=["verifier"],
                    steps=steps,
                    expect_failure=True,
                    required_rejection_class=self.mod.REJECTION_CLASS_VERIFIER,
                )
        self.assertEqual(steps[0]["status"], "failed")
        self.assertEqual(
            steps[0]["rejection_class"],
            self.mod.REJECTION_CLASS_ROBUSTNESS,
        )

    def test_failure_diagnostics_exposes_last_failed_step(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "interop.json"
            diagnostics = self.mod.failure_diagnostics(
                {
                    "failure": {"message": "hosted build failed"},
                    "steps": [
                        {
                            "name": "rust_interop_tool_build",
                            "status": "failed",
                            "return_code": 101,
                            "stdout_tail": "",
                            "stderr_tail": "linker unavailable",
                        }
                    ],
                },
                report_path,
            )

        self.assertIn("hosted build failed", diagnostics)
        self.assertIn(str(report_path), diagnostics)
        self.assertIn("rust_interop_tool_build return_code=101", diagnostics)
        self.assertIn("linker unavailable", diagnostics)

    def test_failure_diagnostics_handles_precondition_failure(self) -> None:
        diagnostics = self.mod.failure_diagnostics(
            {"failure": {"message": "repository is dirty"}, "steps": []},
            Path("report.json"),
        )
        self.assertIn("repository is dirty", diagnostics)
        self.assertIn("failed step: none recorded", diagnostics)

    def test_generated_artifact_is_retired_before_exclusive_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "wide_fibonacci_zig_to_rust.json"
            artifact.write_text("stale", encoding="utf-8")

            self.mod.prepare_generated_artifact(artifact)
            self.assertFalse(artifact.exists())
            self.mod.prepare_generated_artifact(artifact)


if __name__ == "__main__":
    unittest.main()
