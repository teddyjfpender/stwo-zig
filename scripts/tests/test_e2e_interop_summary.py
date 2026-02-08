#!/usr/bin/env python3
"""Unit tests for e2e interop summary accounting."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "e2e_interop.py"


def load_module():
    spec = importlib.util.spec_from_file_location("e2e_interop", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load module from {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
        self.assertEqual(summary["tamper_cases_total"], 16)
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
        self.assertEqual(summary["tamper_cases_total"], 16)
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


if __name__ == "__main__":
    unittest.main()
