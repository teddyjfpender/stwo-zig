from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.tests.native_proof_matrix_support import MODULE, args, make_report
import scripts.native.native_proof_matrix_lib.artifacts as matrix_artifacts


class NativeMatrixCaptureTests(unittest.TestCase):
    def test_host_lock_excludes_live_capture_and_reclaims_stale_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            host_lock = root / "host.lock"
            with mock.patch.object(
                matrix_artifacts, "HOST_MEASUREMENT_LOCK", host_lock
            ):
                with matrix_artifacts.host_measurement_lock(root):
                    self.assertTrue(
                        host_lock.read_text().endswith(f" {root.resolve()}\n")
                    )
                    with self.assertRaisesRegex(MODULE.MatrixError, "held by pid"):
                        with matrix_artifacts.host_measurement_lock(root):
                            self.fail("second host lock unexpectedly succeeded")
                self.assertFalse(host_lock.exists())

                host_lock.write_text(f"999999999 {root}\n")
                with matrix_artifacts.host_measurement_lock(root):
                    self.assertTrue(host_lock.exists())
                self.assertFalse(host_lock.exists())

    def test_runtime_source_digest_must_match_product_identity(self) -> None:
        workload = MODULE.Workload.wide_fibonacci(10, 8)
        report = make_report("metal", workload)
        report["runtime_admission"]["source_sha256"] = "ab" * 32
        with self.assertRaisesRegex(MODULE.MatrixError, "product identity"):
            MODULE.validate_report(report, "metal", workload, args())


if __name__ == "__main__":
    unittest.main()
