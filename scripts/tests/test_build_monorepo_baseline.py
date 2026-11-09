from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.repo import check_build_monorepo_baseline as baseline
class BuildMonorepoBaselineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.receipt = baseline.load(baseline.DEFAULT_BASELINE)

    def test_checked_in_baseline_is_valid(self) -> None:
        self.assertEqual([], baseline.validate(baseline.ROOT, self.receipt))

    def test_tree_substitution_is_rejected(self) -> None:
        changed = copy.deepcopy(self.receipt)
        changed["source"]["tree"] = "0" * 40
        errors = baseline.validate(baseline.ROOT, changed)
        self.assertIn("source tree does not match source commit", errors)

    def test_archived_performance_evidence_is_outside_architecture_gate(self) -> None:
        changed = copy.deepcopy(self.receipt)
        del changed["benchmark_baselines"]
        del changed["statistical_policy"]
        del changed["aggregate_product"]["cold_build"]
        del changed["aggregate_product"]["warm_noop_build"]
        del changed["aggregate_product"]["binary"]["bytes"]
        self.assertEqual([], baseline.validate(baseline.ROOT, changed))

    def test_architecture_proof_substitution_is_rejected(self) -> None:
        changed = copy.deepcopy(self.receipt)
        changed["proof_baselines"]["native_cpu"]["proof_artifact_sha256"] = "not-a-digest"
        errors = baseline.validate(baseline.ROOT, changed)
        self.assertIn(
            "proof_baselines.native_cpu.proof_artifact_sha256 is not canonical lowercase hex",
            errors,
        )

    def test_duplicate_json_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "duplicate.json"
            path.write_text('{"schema":"a","schema":"b"}', encoding="utf-8")
            with self.assertRaises(baseline.DuplicateKeyError):
                baseline.load(path)


if __name__ == "__main__":
    unittest.main()
