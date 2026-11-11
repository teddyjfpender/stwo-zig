"""The retained PC census keeps complete profile and static ELF admission."""
import copy
import hashlib
import struct
import unittest

from opstack.miller_packet_census import functions, validate_complete_profile


def image():
    raw = bytearray(353)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", raw, 16, 2, 243)
    struct.pack_into("<Q", raw, 40, 64)
    struct.pack_into("<HH", raw, 58, 64, 4)
    struct.pack_into("<IIQQQQIIQQ", raw, 128, 0, 1, 6, 0x1000, 349, 4, 0, 0, 4, 0)
    struct.pack_into("<IIQQQQIIQQ", raw, 192, 0, 3, 0, 0, 320, 5, 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", raw, 256, 0, 2, 0, 0, 325, 24, 2, 0, 8, 24)
    raw[320:325] = b"\0fun\0"
    struct.pack_into("<IBBHQQ", raw, 325, 1, 2, 0, 1, 0x1000, 4)
    return bytes(raw)


class ProfileAuthority(unittest.TestCase):
    def test_complete_profile_and_exact_static_function_range(self):
        raw = image()
        self.assertEqual(functions(raw), [(0x1000, 4, "fun")])
        request = dict(status="completed", verified_output=True,
                       elf_sha256=hashlib.sha256(raw).hexdigest(), instructions=1,
                       pc_profile=dict(start=0x1000, end=0x1004, counts=[1], outside=0))
        validate_complete_profile(request, raw)
        for key, value in (("status", "prefix"), ("verified_output", False),
                           ("elf_sha256", "0"*64), ("instructions", True), ("instructions", 2)):
            changed = copy.deepcopy(request)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                validate_complete_profile(changed, raw)
        for key, value in (("outside", 1), ("counts", [True]), ("counts", [1, 0]), ("start", 0x1001)):
            changed = copy.deepcopy(request)
            changed["pc_profile"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_complete_profile(changed, raw)

    def test_malformed_symbol_authority_rejects(self):
        for offset, value in ((325, 99), (329, 0x12), (331, 5)):
            raw = bytearray(image())
            if offset == 329:
                # Explicitly exceed the executable section instead of changing binding.
                struct.pack_into("<Q", raw, 341, 8)
            else:
                raw[offset] = value
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                functions(raw)
