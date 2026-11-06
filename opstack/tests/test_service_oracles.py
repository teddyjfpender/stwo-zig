"""Boundary checks for the independently implemented execution service oracle."""

import unittest

from opstack.oracle import bn254_affine, jumpdest_bitmap

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583


def packet(*values):
    return b"".join(x.to_bytes(32, "little") for x in values)


class ServiceOracles(unittest.TestCase):
    def test_g1_double_and_add_have_consistent_group_law(self):
        two = bn254_affine(packet(1, 2), True)
        x, y = [int.from_bytes(two[i : i + 32], "little") for i in (0, 32)]
        self.assertEqual((y * y - x * x * x) % P, 3)
        three = bn254_affine(packet(1, 2, x, y), False)
        self.assertEqual(three, bn254_affine(packet(x, y, 1, 2), False))
        with self.assertRaisesRegex(ValueError, "denominator"):
            bn254_affine(packet(1, 2, 1, 2), False)
        with self.assertRaisesRegex(ValueError, "denominator"):
            bn254_affine(packet(1, 0), True)
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            bn254_affine(packet(P, 2), True)
        with self.assertRaisesRegex(ValueError, "size"):
            bn254_affine(bytes(63), True)

    def test_jumpdest_push_payload_and_word_boundaries(self):
        self.assertEqual(jumpdest_bitmap(b""), b"")
        for width in range(1, 33):
            code = bytes([0x5F + width]) + bytes([0x5B]) * width + b"\x5b"
            bits = int.from_bytes(jumpdest_bitmap(code), "little")
            self.assertEqual(bits, 1 << (width + 1))
            self.assertEqual(jumpdest_bitmap(code[:width]), bytes(8))
        code = bytes(63) + b"\x5b\x5b" + bytes(6) + b"\x5b"
        self.assertEqual(
            int.from_bytes(jumpdest_bitmap(code), "little"),
            (1 << 63) | (1 << 64) | (1 << 71),
        )
