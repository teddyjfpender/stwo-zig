"""Measurement rows preserve theorem scope and immutable artifact identity."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
from v7_shared_recursive_results import record


class SharedRecursiveResultsTests(unittest.TestCase):
    def make_case(self, folder):
        scope = "declared_nonterminal_window_to_shared_recursive_root"
        report = dict(schema="stwo-real-window-shared-union-root-v1", scope=scope,
                      canonical_security=True, complete_global_closure=True,
                      complete_recursive_root=True, union_proof=True, verified=True, ethereum_block=False,
                      skipped_prefix_proved=False, query_count=70, pow_bits=26,
                      window=dict(cycles=4, skip_cycles=1), stats=dict(segments=1,
                      callers=0, events=2, whole_ns=10, memory_preparation=dict(witness_ns=3)),
                      worker_count=8, native_layout_mode="degree_bounded_q2_v1",
                      whole_request_ns=20, charged_peak_including_detached_verification=30)
        detail = dict(scope=scope, verified=dict(scope="declared_window"),
                      original_proofs_destroyed=True, producer_capture_destroyed=True,
                      producer_parent_rows_destroyed=True, independent_fixed_key_reconstructed=True,
                      source_stark_count=1, recursive_stark_count=1, recursive=dict(proof_ns=4),
                      original_verification_ns=1, recursive_production_ns=5, fresh_verification_ns=2)
        for name, prefix in (("root.proof", "root"), ("union.claims", "claims"), ("union-public.json", "metadata")):
            content = name.encode()
            (folder / name).write_bytes(content)
            detail[prefix + "_bytes"] = len(content)
            detail[prefix + "_sha256"] = hashlib.sha256(content).hexdigest()
        invocation = dict(returncode=0, report_checked=True, binary_sha256="binary", capture_sha256="capture")
        for name, data in (("report.json", report), ("union-root-verification.json", detail), ("invocation.json", invocation)):
            (folder / name).write_text(json.dumps(data))
        return report, detail

    def test_checked_artifacts_and_raw_stages(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            self.make_case(folder)
            row = record(folder)
            self.assertEqual(row["recursive_proof_ns"], 4)
            self.assertEqual(row["memory_preparation_witness_ns"], 3)
            (folder / "root.proof").write_bytes(b"different proof")
            with self.assertRaisesRegex(ValueError, "artifact mismatch"):
                record(folder)

    def test_no_relabelled_block_or_unreconstructed_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            report, detail = self.make_case(folder)
            report["ethereum_block"] = True
            (folder / "report.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "complete-block label"):
                record(folder)
            report["ethereum_block"] = False
            (folder / "report.json").write_text(json.dumps(report))
            detail["independent_fixed_key_reconstructed"] = False
            (folder / "union-root-verification.json").write_text(json.dumps(detail))
            with self.assertRaisesRegex(ValueError, "receiver boundary"):
                record(folder)

    def test_incomplete_run_is_not_a_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            self.assertIsNone(record(Path(temporary)))


if __name__ == "__main__":
    unittest.main()
