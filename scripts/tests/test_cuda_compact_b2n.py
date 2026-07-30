from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "src/backends/cuda/native/transform/b2n_retained.cu"
ABI = ROOT / "src/backends/cuda/abi/stages/transform.zig"
SMOKE = ROOT / "tests/cuda/native_transform_smoke.cpp"


class CudaCompactB2nTests(unittest.TestCase):
    def test_compact_and_retained_entries_share_one_normalized_core(self) -> None:
        source = NATIVE.read_text(encoding="utf-8")
        self.assertIn("launch_columns<DuplicateToRetained>", source)
        self.assertIn("b2n_columns_entry<false>", source)
        self.assertIn("b2n_columns_entry<true>", source)
        self.assertIn(
            "DuplicateToRetained ? 2u * values : values",
            source,
        )
        self.assertIn("b2n_stage<DuplicateToRetained>", source)
        self.assertNotIn("cudaDeviceSynchronize", source)

    def test_checked_abi_exposes_both_output_policies(self) -> None:
        abi = ABI.read_text(encoding="utf-8")
        self.assertIn("stwo_ntt_b2n_columns_compact_on", abi)
        self.assertIn("stwo_ntt_b2n_columns_to_retained_on", abi)
        self.assertEqual(6, abi.count("launches_out: *u32"))

    def test_device_smoke_pins_first_n_and_write_extent(self) -> None:
        smoke = SMOKE.read_text(encoding="utf-8")
        self.assertIn("compact/retained B2N compatibility", smoke)
        self.assertIn("compact B2N wrote beyond N words", smoke)
        self.assertIn("kCompactGuard", smoke)
        self.assertIn("reject partial compact B2N alias", smoke)
        self.assertIn("reject short compact B2N stride", smoke)


if __name__ == "__main__":
    unittest.main()
