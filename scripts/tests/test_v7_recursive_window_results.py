import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.v7_real_window_results import recursive_rows


class RecursiveWindowResultsTest(unittest.TestCase):
    def fixture(self, base):
        folder = base / "large-partition-variant"
        folder.mkdir()
        proof = b"fixture-root-bytes"
        (folder / "root.proof").write_bytes(proof)
        profile = dict(stages=[dict(id="parent.core", seconds=0.05, children=[
            dict(id="composition_evaluation", seconds=0.03, children=None)])])
        (folder / "qualification.log").write_text("verified fixture\nBLAKE3_PARENT_STAGE_PROFILE " + json.dumps(profile) + "\n")
        case = dict(case="fixture", capture_manifest_sha256="11" * 32,
                    elf_sha256="22" * 32, incoming_sha256="33" * 32,
                    outgoing_sha256="44" * 32,
                    window=dict(cycles=1048576, skip_cycles=1))
        report = dict(scope="declared_nonterminal_window_to_complete_recursive_root",
                      cycles=1048576, skip_cycles=1, verified=True,
                      originals_destroyed=True, complete_global_closure=True,
                      canonical_security=True,
                      root_sha256=hashlib.sha256(proof).hexdigest(), root_bytes=len(proof),
                      source=dict(whole_ns=100, consumer_ns=80, original_proofs=4,
                                  checkpoint_bytes=10, native_proof_ns=12),
                      recursive=None, recursive_shared=dict(proof_ns=50,
                                                           family_preparation=dict(families=[])),
                      **{key: case[key] for key in ("elf_sha256", "incoming_sha256", "outgoing_sha256")})
        (folder / "report.json").write_text(json.dumps(report))
        invocation = dict(returncode=0, build_manifest_sha256="55" * 32,
                          binary_sha256="66" * 32,
                          capture_sha256=case["capture_manifest_sha256"])
        (folder / "invocation.json").write_text(json.dumps(invocation))
        return folder, report, {"cases": [case]}, {"55" * 32: {"binary_sha256": "66" * 32}}

    def test_checked_scope_includes_unsuffixed_shared_root_and_stage_breakdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            _, _, corpus, builds = self.fixture(base)
            rows = recursive_rows(base, corpus, builds)
            self.assertEqual(1, len(rows))
            self.assertEqual(50, rows[0]["recursive_proof_ns"])
            self.assertEqual(12, rows[0]["source_native_proof_ns"])
            self.assertEqual(20, rows[0]["source_excluding_consumer_ns"])
            self.assertNotIn("recursive_family_preparation", rows[0])
            self.assertIsNone(rows[0]["source_sha256"])
            self.assertTrue((base / "recursive-window-times.csv").is_file())
            self.assertTrue((base / "recursive-parent-stages.csv").is_file())
            self.assertTrue((base / "large-partition-variant/parent-stage-profile.json").is_file())

    def test_rejects_changed_proof_and_incomplete_closure(self):
        for changed in ("proof", "closure"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                folder, report, corpus, builds = self.fixture(base)
                if changed == "proof":
                    (folder / "root.proof").write_bytes(b"different-root")
                else:
                    report["complete_global_closure"] = False
                    (folder / "report.json").write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    recursive_rows(base, corpus, builds)


if __name__ == "__main__":
    unittest.main()
