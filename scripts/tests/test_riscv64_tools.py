"""Guard the independent ELF32/ELF64 boundary used by the CSP comparison."""
import struct
import tempfile
import unittest
from pathlib import Path
from scripts.riscv64_csp_compare import ROOT, elf_info


class ElfBoundaryTests(unittest.TestCase):
    def test_committed_rv32_guest_symbols_and_payload(self):
        entry, symbols, segments = elf_info(ROOT / 'vectors/riscv_csp/guests/sha256.elf')
        self.assertEqual(entry, 1024)
        self.assertEqual(symbols['__input_start'], 0x100000)
        self.assertEqual(symbols['__halt_flag'] - symbols['__input_start'], 4096)
        self.assertTrue(any(address <= entry < address + size and data
                            for address, size, data, flags in segments))

    def test_elf64_retains_high_address_and_symbol_bits(self):
        data = bytearray(384)
        data[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQ', data, 16, 2, 243, 1, 0x100001000, 64, 128)
        struct.pack_into('<HHHHHH', data, 52, 64, 56, 1, 64, 3, 2)
        struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 320, 0x100001000, 0, 4, 4096, 1)
        struct.pack_into('<IIQQQQIIQQ', data, 128 + 64, 0, 2, 0, 0, 328, 24, 2, 0, 8, 24)
        struct.pack_into('<IIQQQQIIQQ', data, 128 + 128, 0, 3, 0, 0, 352, 14, 0, 0, 1, 0)
        struct.pack_into('<IBBHQQ', data, 328, 1, 0, 0, 0, 0x200000008, 0)
        data[352:366] = b'\0__halt_flag\0\0'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'guest.elf'
            path.write_bytes(data)
            entry, symbols, segments = elf_info(path)
        self.assertEqual(entry, 0x100001000)
        self.assertEqual(symbols['__halt_flag'], 0x200000008)
        self.assertEqual(segments[0][:2], (0x100001000, 4096))

    def test_invalid_class_and_truncated_header_fail_closed(self):
        original = (ROOT / 'vectors/riscv_csp/guests/sha256.elf').read_bytes()
        cases = [original[:n] for n in (0, 4, 8, 51)]
        bad_class = bytearray(original)
        bad_class[4] = 3
        cases.append(bad_class)
        bad_table = bytearray(original)
        struct.pack_into('<I', bad_table, 28, 0xfffffff0)
        cases.append(bad_table)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.elf'
            for data in cases:
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    elf_info(path)


if __name__ == '__main__':
    unittest.main()
