"""Boundary checks for the independently implemented execution service oracle."""

import unittest

from opstack.oracle import bn254_affine, bn254_fp2, bn254_sparse034, jumpdest_bitmap

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

    def test_fp2_plain_representation_and_full_width_reduction(self):
        self.assertEqual(bn254_fp2(packet(1, 2, 3, 4)), packet(P - 5, 10))
        for a, b, c, d in [
            (0, 0, 0, 0),
            (P - 1, P - 1, P - 1, P - 1),
            ((1 << 256) - 1, 3, P, 4),
        ]:
            actual = bn254_fp2(packet(a, b, c, d))
            self.assertEqual(actual, packet((a * c - b * d) % P, (a * d + b * c) % P))
        with self.assertRaisesRegex(ValueError, "size"):
            bn254_fp2(bytes(127))

    def test_sparse034_basis_placement_and_full_width_reduction(self):
        # Multiplication by 1 preserves every accumulator coordinate.
        a = list(range(1,13))
        self.assertEqual(bn254_sparse034(packet(*a,1,0,0,0,0,0)),packet(*a))
        # w * (u*w) = u², and u² * (u*w) = (9+i)*w.
        a = [0]*12; a[6]=1
        expected = [0]*12; expected[4]=1
        self.assertEqual(bn254_sparse034(packet(*a,0,0,0,0,1,0)),packet(*expected))
        a = [0]*12; a[4]=1
        expected = [0]*12; expected[6]=9; expected[7]=1
        self.assertEqual(bn254_sparse034(packet(*a,0,0,0,0,1,0)),packet(*expected))
        # i²=-1, including representatives at and above p.
        a=[0]*12; a[1]=(1<<256)-1
        expected=[0]*12; expected[0]=(-a[1]*(P+1))%P
        self.assertEqual(bn254_sparse034(packet(*a,0,P+1,0,0,0,0)),packet(*expected))
        with self.assertRaisesRegex(ValueError,"size"):
            bn254_sparse034(bytes(575))

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
