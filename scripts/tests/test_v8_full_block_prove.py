"""Artifact audit tests. Synthetic bytes are never treated as crypto proofs."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))
import v8_full_block_prove as prove


class ArtifactAuditTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.plan = {"total_cycles": 7, "elf_sha256": "11" * 32, "input_sha256": "22" * 32, "output_sha256": "33" * 32,
                     "windows": [{"kind": "native", "skip_cycles": 0, "cycles": 4}, {"kind": "mixed", "skip_cycles": 4, "cycles": 3}]}
        root = b"synthetic artifact audit fixture"
        self.report = {"schema": "stwo-b8-complete-execution-root-v1", "proof_verified": True, "cycles": 7, "windows": 2, "folds": 1,
                       "elf_sha256": list(bytes.fromhex(self.plan["elf_sha256"])), "input_sha256": list(bytes.fromhex(self.plan["input_sha256"])),
                       "expected_output_sha256": list(bytes.fromhex(self.plan["output_sha256"])), "root_bytes": len(root),
                       "root_sha256": list(hashlib.sha256(root).hexdigest().encode()), "initial_policy_id": [1] * 32, "terminal_policy_id": [2] * 32}
        self.catalog = {"window_count": 2, "root_index": 2, "nodes": [
            {"kind": 0, "index": 0, "children": []}, {"kind": 1, "index": 1, "children": []}, {"kind": 2, "index": 2, "children": [0, 1]}]}
        (self.directory / "root.proof").write_bytes(root)
        self.publish()

    def publish(self):
        (self.directory / "report.json").write_text(json.dumps(self.report))
        (self.directory / "benchmark-report.json").write_text(json.dumps({"schema": "stwo-b8-full-block-one-root-benchmark-v1", "independent_root_verified": True,
            "queries": 70, "pow_bits": 26, "unique_snapshot_decodes": 3, "pipeline": self.report}))
        (self.directory / "catalog.json").write_text(json.dumps(self.catalog))

    def test_complete_artifact_audit(self):
        self.assertEqual(prove.validate_result(self.directory, self.plan), self.report)

    def test_proof_bytes_changed(self):
        (self.directory / "root.proof").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            prove.validate_result(self.directory, self.plan)

    def test_duplicate_or_swapped_fold(self):
        for children in ([0, 0], [1, 0]):
            with self.subTest(children=children):
                self.catalog["nodes"][2]["children"] = children
                self.publish()
                with self.assertRaises(ValueError):
                    prove.validate_result(self.directory, self.plan)

    def test_missing_terminal_or_source_binding(self):
        self.report["terminal_policy_id"] = [0] * 32
        self.publish()
        with self.assertRaises(ValueError):
            prove.validate_result(self.directory, self.plan)

    def test_missing_fresh_verification(self):
        self.report["proof_verified"] = False
        self.publish()
        with self.assertRaises(ValueError):
            prove.validate_result(self.directory, self.plan)

    def test_resume_cannot_claim_fresh_complete_timing(self):
        self.report.update(resumed_windows=1, fresh_complete_run=False,
                           timing_scope="resume invocation; previously completed proving excluded")
        self.publish()
        with self.assertRaises(ValueError):
            prove.validate_result(self.directory, self.plan)
        prove.validate_result(self.directory, self.plan, resume_allowed=True)
        self.report["fresh_complete_run"] = True
        self.publish()
        with self.assertRaises(ValueError):
            prove.validate_result(self.directory, self.plan, resume_allowed=True)

    def test_requested_cohort_geometry_must_match_report(self):
        with self.assertRaises(ValueError):
            prove.validate_result(self.directory, self.plan, native_cohort_cycles=4194304)

    def test_digest_representations(self):
        self.assertEqual(prove.digest_text([1] * 32, 64), "01" * 32)
        self.assertEqual(prove.digest_text(list(b"a" * 64), 64), "a" * 64)
        with self.assertRaises(ValueError):
            prove.digest_text("g" * 64, 64)


if __name__ == "__main__":
    unittest.main()
