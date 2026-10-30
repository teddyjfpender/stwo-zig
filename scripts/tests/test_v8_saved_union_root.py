"""A recursive-stage observation cannot become a source/block timing claim."""
import hashlib
import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
from v8_saved_union_root import validate_report


class SavedUnionRootContractTests(unittest.TestCase):
    def fixture(self, folder):
        capture = dict(window=dict(skip_cycles=1, cycles=4), elf_sha256="elf", incoming_sha256="in", outgoing_sha256="out")
        report = dict(schema="stwo-v8-saved-original-closed-root-v1",
                      scope="saved_canonical_original_to_in_proof_closed_declared_window_root",
                      verified=True, canonical_security=True, closure_in_proof=True,
                      source_original_fresh_verified=True, original_proof_objects_destroyed=True,
                      original_capture_destroyed=True, producer_parent_rows_destroyed=True,
                      fresh_metadata_independently_reconstructed=True,
                      host_global_closure_used_by_root_receiver=False, source_proving_performed=False,
                      ethereum_block=False, skipped_prefix_proved=False, terminal=False,
                      query_count=70, pow_bits=26, worker_count=8, source_stark_count=1,
                      recursive_stark_count=1, callers=0, source_proof_sha256="source",
                      metadata_sha256="metadata", whole_request_ns=10, recursive=dict(proof_ns=3), **capture)
        for filename, prefix in (("root.proof", "root"), ("union.claims", "claims")):
            content = filename.encode()
            (folder / filename).write_bytes(content)
            report[prefix + "_bytes"] = len(content)
            report[prefix + "_sha256"] = hashlib.sha256(content).hexdigest()
        return report, capture

    def test_checked_saved_original_root_and_no_source_time_relabelling(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            report, capture = self.fixture(folder)
            validate_report(report, capture, "source", "metadata", 8, folder)
            for key in ("source_proving_performed", "ethereum_block", "host_global_closure_used_by_root_receiver"):
                report[key] = True
                with self.assertRaisesRegex(ValueError, "incorrect claimed scope"):
                    validate_report(report, capture, "source", "metadata", 8, folder)
                report[key] = False
            report["pow_bits"] = 25
            with self.assertRaisesRegex(ValueError, "security"):
                validate_report(report, capture, "source", "metadata", 8, folder)

    def test_changed_proof_and_missing_receiver_boundary_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            report, capture = self.fixture(folder)
            report["fresh_metadata_independently_reconstructed"] = False
            with self.assertRaisesRegex(ValueError, "qualification boundary"):
                validate_report(report, capture, "source", "metadata", 8, folder)
            report["fresh_metadata_independently_reconstructed"] = True
            (folder / "root.proof").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "artifact mismatch"):
                validate_report(report, capture, "source", "metadata", 8, folder)


if __name__ == "__main__":
    unittest.main()
