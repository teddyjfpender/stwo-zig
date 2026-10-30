"""A saved union proof cannot be relabelled a root or detached from its bytes."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
from v7_shared_original_results import collect


class SharedOriginalResultsTests(unittest.TestCase):
    def test_preserves_theorem_and_rejects_changed_saved_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            folder = base / "one-window"
            folder.mkdir()
            case = dict(case="input", capture_manifest_sha256="capture", window=dict(skip_cycles=1, cycles=3),
                        elf_sha256="elf", incoming_sha256="in", outgoing_sha256="out")
            report = dict(schema="stwo-real-window-shared-union-v1", scope="declared_nonterminal_window_to_shared_original_stark",
                          query_count=70, pow_bits=26, verified=True, canonical_security=True, complete_global_closure=True,
                          complete_recursive_root=False, ethereum_block=False, skipped_prefix_proved=False,
                          window=case["window"], elf_sha256="elf", incoming_sha256="in", outgoing_sha256="out",
                          artifacts=dict(proof_count=1), segment_cycles=3, native_layout_mode="canonical_v1", worker_count=8,
                          whole_request_ns=10, charged_peak_including_detached_verification=100, stats={})
            invocation = dict(returncode=0, report_checked=True, shared_original_union=True, binary_sha256="binary",
                              capture_sha256="capture", build_manifest_sha256="build")
            proof = b"saved original union"
            detail = dict(producer_proof_destroyed=True, verified=dict(scope="declared_window"),
                          verification_ns=2, proof_sha256=hashlib.sha256(proof).hexdigest(), proof_bytes=len(proof))
            for name, value in [("report.json", report), ("invocation.json", invocation), ("union-verification.json", detail)]:
                (folder / name).write_text(json.dumps(value))
            (folder / "union.proof").write_bytes(proof)
            (folder / "qualification.log").write_text("100 maximum resident set size")
            args = base, dict(cases=[case]), dict(build=dict(binary_sha256="binary"))
            rows = collect(*args)
            self.assertEqual(1, len(rows))
            self.assertIs(rows[0]["recursive_root"], False)
            report["complete_recursive_root"] = True
            (folder / "report.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "closure boundary"):
                collect(*args)
            report["complete_recursive_root"] = False
            (folder / "report.json").write_text(json.dumps(report))
            (folder / "union.proof").write_bytes(proof + b"tampered")
            with self.assertRaisesRegex(ValueError, "proof mismatch"):
                collect(*args)


if __name__ == "__main__":
    unittest.main()
