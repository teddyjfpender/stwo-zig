"""Report acceptance and on-disk inventory only; no prover executable runs."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "autoresearch/notes/2026-09-24-ethereum-block-delivery/run_block_v5_measurements.py"
spec = importlib.util.spec_from_file_location("block_v5_measurements", SOURCE)
measurements = importlib.util.module_from_spec(spec)
spec.loader.exec_module(measurements)


class CapacityMeasurements(unittest.TestCase):
    def test_archived_legacy_report_is_not_a_current_capacity_measurement(self):
        legacy = dict(format_version=1,
                      architecture="block-v5-native-v3-fused-v2-open-exact-streaming",
                      complete_block_verified=True, queries=70, pow_bits=26,
                      profile="csp_q70_pow26", native_projection_protocol_version=2)
        with self.assertRaisesRegex(RuntimeError, "capacity architecture"):
            measurements.require_capacity_report(legacy, producer=True)

    def test_current_report_security_profile_and_fresh_receiver_are_required(self):
        report = dict(format_version=2, architecture=measurements.CAPACITY_ARCHITECTURE,
                      complete_block_verified=True, queries=70, pow_bits=26,
                      profile="csp_q70_pow26", native_capacity_protocol_version=1,
                      native_projection_protocol_version=1)
        measurements.require_capacity_report(report, producer=True)
        for field, value in (("queries", 8), ("pow_bits", 0),
                             ("profile", "diagnostic_q8_pow0"),
                             ("native_capacity_protocol_version", 2),
                             ("native_projection_protocol_version", 2),
                             ("complete_block_verified", 1)):
            with self.subTest(field=field):
                with self.assertRaises(RuntimeError):
                    measurements.require_capacity_report(dict(report, **{field: value}), producer=True)
        with self.assertRaisesRegex(RuntimeError, "fresh process"):
            measurements.require_capacity_report(report, producer=False)
        measurements.require_capacity_report(dict(report, fresh_process=True), producer=False)

    def test_capacity_base_artifacts_and_exact_forest_keep_separate_size_scopes(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            # Literal bytes are inventory fixtures, never proof authority.
            (bundle / "block-v5-capacity-native-0.proof").write_bytes(b"base")
            (bundle / "block-v5-capacity-native_fused-0.proof").write_bytes(b"fused")
            (bundle / "block-v5-open-native-leaf-0.proof").write_bytes(b"leaf")
            (bundle / "v5-input-words.bin").write_bytes(b"source")
            (bundle / "block-v5-cpu-report.json").write_bytes(b"excluded")
            (bundle / "artifact-link.proof").symlink_to("block-v5-capacity-native-0.proof")
            inventory = measurements.inventory(bundle)
            self.assertEqual(inventory["base_proofs"], dict(files=2, bytes=9))
            self.assertEqual(inventory["recursive_proofs"], dict(files=1, bytes=4))
            self.assertEqual(inventory["public_source_files"], dict(files=1, bytes=6))
            self.assertEqual(inventory["all_regular_files_excluding_report"], dict(files=4, bytes=19))


if __name__ == "__main__":
    unittest.main()
