from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = (
    ROOT
    / "src/backends/cuda/authority/active/witness_edge_gather.cu"
)
ABI = ROOT / "src/backends/cuda/abi/stages/cairo_witness.zig"
OVERLAY = ROOT / "src/backends/cuda/native/cairo/witness_compact_v2.cu"
SMOKE = ROOT / "tests/cuda/native_witness_compact_v2_smoke.cpp"


class CudaWitnessCompactV2Tests(unittest.TestCase):
    def test_native_authority_preserves_v1(self) -> None:
        source = AUTHORITY.read_text(encoding="utf-8")
        self.assertIn(
            'extern "C" int stwo_witness_input_compact_on(',
            source,
        )
        self.assertNotIn("compact_v2", source)

    def test_v2_separates_logical_rows_from_physical_stride(self) -> None:
        source = OVERLAY.read_text(encoding="utf-8")
        self.assertIn("#define STWO_COMPACT_V2_DESC_WORDS 6u", source)
        self.assertIn("uint32_t stride_rows = desc[0];", source)
        self.assertIn("uint32_t real_rows = desc[1];", source)
        self.assertIn(
            "uint32_t edge_rows = real_rows * desc[4];",
            source,
        )
        self.assertIn(
            "source_word * stride_rows + producer_row",
            source,
        )
        self.assertIn(
            'extern "C" int stwo_witness_input_compact_v2_on(',
            source,
        )

    def test_checked_abi_and_device_smoke_pin_v2(self) -> None:
        abi = ABI.read_text(encoding="utf-8")
        smoke = SMOKE.read_text(encoding="utf-8")
        self.assertIn(
            "pub extern \"c\" fn stwo_witness_input_compact_v2_on(",
            abi,
        )
        self.assertIn("kStrideRows = 32", smoke)
        self.assertIn("kRealRows = 17", smoke)
        self.assertIn("1000 + row", smoke)
        self.assertIn("expected_multiplicity = row == 0 ? 2 : 1", smoke)


if __name__ == "__main__":
    unittest.main()
