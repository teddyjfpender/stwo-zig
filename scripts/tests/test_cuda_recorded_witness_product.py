from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from cuda_recorded_witness_product import (  # noqa: E402
    INLINE_MUL,
    ISOLATED_MUL,
    ProductError,
    derive_source,
    verify,
)


class CudaRecordedWitnessProductTests(unittest.TestCase):
    def test_derivation_is_exact_and_single_boundary(self) -> None:
        authority = b"prefix\n" + INLINE_MUL + b"suffix\n"
        self.assertEqual(
            b"prefix\n" + ISOLATED_MUL + b"suffix\n",
            derive_source(authority),
        )
        self.assertEqual(b"unaffected\n", derive_source(b"unaffected\n"))
        for malformed in (authority + INLINE_MUL, authority + ISOLATED_MUL):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ProductError):
                    derive_source(malformed)

    def test_checked_product_matches_immutable_authority(self) -> None:
        self.assertEqual(33, verify())


if __name__ == "__main__":
    unittest.main()
