"""Independent arithmetic oracle across degenerate and full-width moduli."""

import random
import unittest

from opstack.oracle import arith256


class ArithmeticOracle(unittest.TestCase):
    def test_full_width_and_zero_modulus(self):
        rng = random.Random(31822)
        maximum = (1 << 256) - 1
        cases = [(maximum, maximum, maximum, m) for m in [0, 1, 2, maximum]]
        cases += [tuple(rng.getrandbits(256) for _ in range(4)) for _ in range(64)]
        for a, b, c, m in cases:
            packet = b"".join(x.to_bytes(32, "little") for x in [a, b, c, m, maximum])
            value = int.from_bytes(arith256(packet), "little")
            self.assertEqual(value, (a * b + c) % m if m else 0)
        with self.assertRaisesRegex(ValueError, "size"):
            arith256(bytes(159))


if __name__ == "__main__":
    unittest.main()


class MontgomeryOracle(unittest.TestCase):
    def test_bn254_residue_shift_and_noncanonical_operands(self):
        from opstack.oracle import mont384

        p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
        rng = random.Random(384256)
        for a, b in [(0, 0), (p - 1, p - 1)] + [
            (rng.randrange(p), rng.randrange(p)) for _ in range(64)
        ]:
            raw_a, raw_b = (a * (1 << 256)) % p, (b * (1 << 256)) % p
            packet = b"".join(
                x.to_bytes(48, "little") for x in [raw_a << 128, raw_b, p]
            ) + bytes(16)
            self.assertEqual(
                int.from_bytes(mont384(packet), "little"), (a * b * (1 << 256)) % p
            )
        for m in [1, 3, (1 << 383) - 1]:
            packet = b"".join(
                x.to_bytes(48, "little") for x in [(1 << 384) - 1, 2, m]
            ) + bytes(16)
            self.assertLess(int.from_bytes(mont384(packet), "little"), m)
        with self.assertRaisesRegex(ValueError, "odd"):
            mont384(bytes(160))
