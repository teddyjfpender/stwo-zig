import copy
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'riscv64_ethereum_profile.py'
SPEC = importlib.util.spec_from_file_location('rv64_eth_profile', SCRIPT)
profile = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(profile)


def elf():
    names = b'\0broad\0z_alias\0a_alias\0sha256_compress\0zero\0'
    entries = [(b'broad', 0x1000, 24), (b'z_alias', 0x1004, 8),
               (b'a_alias', 0x1004, 8), (b'sha256_compress', 0x100c, 4),
               (b'zero', 0x1018, 0)]
    symbols = bytes(24) + b''.join(struct.pack('<IBBHQQ', names.index(name), 2, 0, 1, start, size)
                                         for name, start, size in entries)
    string_offset = 96
    symbol_offset = string_offset + len(names)
    section_offset = symbol_offset + len(symbols)
    raw = bytearray(section_offset + 4 * 64)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HH', raw, 16, 2, 243)
    struct.pack_into('<Q', raw, 40, section_offset)
    struct.pack_into('<HH', raw, 58, 64, 4)
    raw[string_offset:string_offset + len(names)] = names
    raw[symbol_offset:symbol_offset + len(symbols)] = symbols
    for index, section in enumerate([(0,) * 10,
            (0, 1, 6, 0x1000, 64, 32, 0, 0, 4, 0),
            (0, 3, 0, 0, string_offset, len(names), 0, 0, 1, 0),
            (0, 2, 0, 0, symbol_offset, len(symbols), 2, 0, 8, 24)]):
        struct.pack_into('<IIQQQQIIQQ', raw, section_offset + index * 64, *section)
    return bytes(raw)


class EthereumProfileTests(unittest.TestCase):
    def setUp(self):
        self.raw = elf()
        self.execution = dict(status='completed', verified_output=True, instructions=36,
                              elf_sha256=profile.sha(self.raw), input_sha256='1' * 64, output='abcd',
                              pc_profile=dict(start=0x1000, end=0x1020,
                                              counts=list(range(1, 9)), outside=0))

    def test_exact_boundaries_aliases_zero_size_and_model(self):
        report = profile.build(self.execution, self.raw)
        rows = {row['name']: row['instructions'] for row in report['functions']}
        self.assertEqual(rows, {'broad': 12, 'a_alias': 5, 'sha256_compress': 4})
        self.assertEqual(report['accounting']['unknown_instructions'], 15)
        self.assertEqual(report['accounting']['total'], 36)
        self.assertEqual(report['classification']['groups'], {'crypto': 4, 'other': 17})
        self.assertEqual(report['proof_cost_model']['padding_rows'], 28)
        self.assertFalse(report['proof_verified'])

    def test_refuses_unverified_hash_mismatch_and_incomplete_counts(self):
        mutations = [lambda d: d.update(verified_output=False),
                     lambda d: d.update(status='step_limit'),
                     lambda d: d.update(elf_sha256='0' * 64),
                     lambda d: d.update(instructions=37),
                     lambda d: d['pc_profile'].update(outside=1),
                     lambda d: d['pc_profile'].update(end=0x1024),
                     lambda d: d['pc_profile'].update(start=0x1001),
                     lambda d: d['pc_profile']['counts'].__setitem__(0, True),
                     lambda d: d['pc_profile']['counts'].__setitem__(0, -1)]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                data = copy.deepcopy(self.execution)
                mutate(data)
                with self.assertRaises(ValueError):
                    profile.build(data, self.raw)

    def test_truncated_symbol_data_and_wrong_isa_are_rejected(self):
        for raw in (self.raw[:63], self.raw[:-1], self.raw[:18] + b'\x3e\0' + self.raw[20:]):
            with self.assertRaises(ValueError):
                profile.functions(raw)

    def test_cli_pins_source_and_elf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            execution, program, output = [root / name for name in ('execution.json', 'guest.elf', 'profile.json')]
            execution.write_text(json.dumps(self.execution))
            program.write_bytes(self.raw)
            subprocess.run([sys.executable, str(SCRIPT), '--execution', str(execution),
                            '--elf', str(program), '--output', str(output)], check=True)
            report = json.loads(output.read_text())
            self.assertEqual(report['sources']['profiler']['sha256'], profile.sha(SCRIPT.read_bytes()))
            self.assertEqual(report['sources']['execution']['sha256'], profile.sha(execution.read_bytes()))
            report_id = report.pop('report_id')
            self.assertEqual(report_id, profile.sha(json.dumps(report, sort_keys=True, separators=(',', ':')).encode()))


if __name__ == '__main__':
    unittest.main()
