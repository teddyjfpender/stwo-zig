from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from cuda_recorded_witness_product import (  # noqa: E402
    EXPECTED_SOURCES,
    recorded_entries,
    verify,
)


class CudaRecordedWitnessProductTests(unittest.TestCase):
    def test_manifest_keeps_every_authenticated_identity_pin(self) -> None:
        self.assertEqual(EXPECTED_SOURCES, len(recorded_entries()))

    def test_generated_cuda_is_not_checked_in(self) -> None:
        self.assertEqual(EXPECTED_SOURCES, verify())


if __name__ == "__main__":
    unittest.main()
