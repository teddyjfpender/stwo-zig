import importlib.util
import struct
import unittest
from unittest import mock

from scripts import riscv64_ethereum_services_oracle as oracle

SYMBOLS = dict(input_start=0x800000, input_end=0xc00000, halt_flag=0xc00000,
               output_len=0xc00004, output_data=0xc00008, output_end=0x1000000,
               stack_bottom=0x1000000, stack_top=0x2000000,
               heap_start=0x2001000, heap_end=0x2002000)
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G2X = 0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5
G3X = 0xF9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9


def affine_x(point):
    x, _, z = point
    return x * pow(z, oracle.FIELD_MODULUS - 2, oracle.FIELD_MODULUS) % oracle.FIELD_MODULUS


def fixture():
    # One Keccak service call on the zeroed heap, then the six-instruction
    # publication sequence of the software oracle fixture: success byte, length43, halt1.
    def store(rs, offset, funct3):
        return ((offset >> 5) << 25) | (rs << 20) | (6 << 15) | (funct3 << 12) | ((offset & 31) << 7) | 0x23
    words = [
        0x02001537,  # lui a0, 0x2001      (heap_start)
        0x000108b7,  # lui a7, 0x10
        0x00188893,  # addi a7, a7, 1      (KECCAK_TAG = 0x10001)
        0x00000073,  # ecall
        0x00c00337, 0x00100293, store(5, 40, 0), 0x02b00393, store(7, 4, 2), store(5, 0, 2),
    ]
    code = struct.pack("<10I", *words)
    expected = bytes(32) + b"\1" + bytes(10)
    return 0x400, {"__" + k: v for k, v in SYMBOLS.items()}, [(0x400, len(code), code, 5)], b"x", expected


class ServicesOracleTests(unittest.TestCase):
    def test_keccak_f_zero_state_vector(self):
        state = oracle.keccak_f1600([0] * 25)
        self.assertEqual(state[0], 0xF1258F7940E1DDE7)
        self.assertEqual(state[1], 0x84D5CCF933C0478A)
        self.assertEqual(state[24], 0xEAF1FF7B5CECA249)

    def test_secp_programs_match_known_multiples_and_reduce_once(self):
        double = oracle.secp_double(GX, GY, 1)
        self.assertEqual(affine_x(double), G2X)
        self.assertEqual(affine_x(oracle.secp_add(GX, GY, 1, *double)), G3X)
        # Identity (0 : 1 : 0) is absorbed by the complete formulas.
        self.assertEqual(affine_x(oracle.secp_add(0, 1, 0, GX, GY, 1)), GX)
        p = oracle.FIELD_MODULUS
        self.assertEqual(oracle.reduce_once(p), 0)
        self.assertEqual(oracle.reduce_once(p - 1), p - 1)
        self.assertEqual(oracle.reduce_once(2 * p - 1), p - 1)

    def test_compare_rejects_any_field_drift(self):
        report = {"output": "aa", "pc": 4, "instructions": 9, "final_registers": [0] * 32, "elf_sha256": "e", "input_sha256": "i",
                  "keccak_calls": 1, "secp_add_calls": 0, "secp_double_calls": 0, "service_ram_word_transitions": 50}
        oracle.compare(report, dict(report))
        for key in report:
            drifted = dict(report)
            drifted[key] = "x"
            with self.assertRaisesRegex(ValueError, key):
                oracle.compare(report, drifted)

    @unittest.skipUnless(importlib.util.find_spec("unicorn"), "requires pinned Unicorn2.1.4 environment")
    def test_keccak_service_retires_as_one_instruction(self):
        config = {"symbols": SYMBOLS, "max_steps": 100, "elf_sha256": "fixture", "input_sha256": "fixture",
                  "execution_profile": "ethereum_services_v2", "elf": __file__}
        with mock.patch.object(oracle, "checked_inputs", return_value=fixture()), \
                mock.patch.object(oracle, "function_entries", return_value={}):
            result = oracle.execute(config, timeout_seconds=10)
        self.assertTrue(result["verified_output"])
        self.assertEqual(result["keccak_calls"], 1)
        self.assertEqual(result["instructions"], 10)
        self.assertEqual(result["service_ram_word_transitions"], 25)
        self.assertEqual(result["pc"], 0x400 + 4 * 10)


if __name__ == "__main__":
    unittest.main()
