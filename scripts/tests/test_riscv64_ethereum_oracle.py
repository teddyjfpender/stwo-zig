import importlib.util
import struct
import unittest
from unittest import mock

from scripts import riscv64_ethereum_oracle as oracle

SYMBOLS = dict(input_start=0x800000, input_end=0xc00000, halt_flag=0xc00000,
               output_len=0xc00004, output_data=0xc00008, output_end=0x1000000,
               stack_bottom=0x1000000, stack_top=0x2000000,
               heap_start=0x2001000, heap_end=0x2002000)


def fixture():
    # Publish output success byte, output length43, then halt1 in six retiring
    # RV64I instructions. Everything else begins zero in mapped memory.
    def store(rs, offset, funct3):
        return ((offset >> 5) << 25) | (rs << 20) | (6 << 15) | (funct3 << 12) | ((offset & 31) << 7) | 0x23
    words = [0x00c00337, 0x00100293, store(5, 40, 0), 0x02b00393, store(7, 4, 2), store(5, 0, 2)]
    code = struct.pack("<6I", *words)
    expected = bytes(32) + b"\1" + bytes(10)
    return 0x400, {"__" + k: v for k, v in SYMBOLS.items()}, [(0x400, len(code), code, 5)], b"x", expected


class EthereumOracleContractTests(unittest.TestCase):
    def test_layout_rejects_overlap_and_stack_drift(self):
        _, symbols, segments, payload, _ = fixture()
        oracle.validate_layout(symbols, segments, len(payload))
        bad = dict(symbols, __stack_top=SYMBOLS["stack_top"] + 16)
        with self.assertRaisesRegex(ValueError, "layout"):
            oracle.validate_layout(bad, segments, 1)
        with self.assertRaisesRegex(ValueError, "overlaps"):
            oracle.validate_layout(symbols, [(SYMBOLS["input_start"], 4, b"bad!", 4)], 1)

    @unittest.skipUnless(importlib.util.find_spec("unicorn"), "requires pinned Unicorn2.1.4 environment")
    def test_native_budget_exact_boundary_and_negative_counts(self):
        config = {"symbols": SYMBOLS, "max_steps": 10, "elf_sha256": "fixture"}
        with mock.patch.object(oracle, "checked_inputs", return_value=fixture()):
            result = oracle.execute(config, expected_steps=6)
            self.assertTrue(result["verified_output"])
            self.assertEqual(result["exact_steps_verified"], 6)
            self.assertEqual(result["observed_pc"], 0x414)
            self.assertEqual(result["architectural_post_store_pc"], 0x418)
            self.assertEqual(result["halt_flag"], 1)  # write actually committed
            for count in (5, 7):
                with self.assertRaises(ValueError):
                    oracle.execute(config, expected_steps=count)
            limited = oracle.execute(dict(config, max_steps=5))
            self.assertFalse(limited["completed"])
            self.assertIsNone(limited["exact_steps_verified"])

    @unittest.skipUnless(importlib.util.find_spec("unicorn"), "requires pinned Unicorn2.1.4 environment")
    def test_changed_expected_output_cannot_pass_exact_budget(self):
        values = list(fixture())
        values[4] = b"\x02" + values[4][1:]
        with mock.patch.object(oracle, "checked_inputs", return_value=tuple(values)):
            with self.assertRaisesRegex(ValueError, "exactly expected"):
                oracle.execute({"symbols": SYMBOLS, "max_steps": 10, "elf_sha256": "fixture"}, 6)


if __name__ == "__main__":
    unittest.main()
