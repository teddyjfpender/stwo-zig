import hashlib
import random
import struct
import unittest

from opstack.sha_oracle import Compressor

IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)


class ShaCompression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compressor = Compressor()

    def test_public_compression_abi_matches_full_hash_at_padding_boundaries(self):
        rng = random.Random(20261106)
        for length in [
            0,
            1,
            2,
            54,
            55,
            56,
            57,
            63,
            64,
            65,
            119,
            120,
            127,
            128,
            129,
            255,
            256,
            257,
            1024,
            4096,
        ]:
            message = rng.randbytes(length)
            padded = message + b"\x80"
            padded += bytes((56 - len(padded) % 64) % 64) + (length * 8).to_bytes(
                8, "big"
            )
            state = IV
            for offset in range(0, len(padded), 64):
                state = self.compressor.compress(state, padded[offset : offset + 64])
            with self.subTest(length=length):
                self.assertEqual(
                    struct.pack(">8I", *state), hashlib.sha256(message).digest()
                )

    def test_input_bounds_and_state_ownership(self):
        state = list(IV)
        first = self.compressor.compress(state, bytes(64))
        second = self.compressor.compress(state, bytes(64))
        self.assertEqual(first, second)
        self.assertEqual(state, list(IV))
        for bad_state, block in [
            (IV[:7], bytes(64)),
            (IV, bytes(63)),
            ([1 << 32] * 8, bytes(64)),
            ([-1] * 8, bytes(64)),
        ]:
            with self.assertRaises(ValueError):
                self.compressor.compress(bad_state, block)


if __name__ == "__main__":
    unittest.main()
