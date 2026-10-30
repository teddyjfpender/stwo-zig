"""Native codec trust-boundary checks; build the experiment binary first."""
from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from autoresearch.tests import test_keth_stwo_bridge as fixtures
from autoresearch.experiments.evm_keth.legacy_input import convert, write_compact

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / 'autoresearch/experiments/evm_keth/legacy_input_rs/target/release/keth-legacy-input'


@unittest.skipUnless(BINARY.is_file(), 'build keth-legacy-input to run native codec tests')
class NativeConverterTests(unittest.TestCase):
    def invoke(self, directory, data, compiled):
        root = Path(directory)
        (root / 'source.json').write_text(json.dumps(data))
        (root / 'compiled.json').write_text(json.dumps(compiled))
        return subprocess.run([str(BINARY), '--source', str(root / 'source.json'),
            '--compiled', str(root / 'compiled.json'), '--target', str(root / 'input.cpi'),
            '--receipt', str(root / 'receipt.json')], capture_output=True, text=True)

    def test_exact_wire_bytes_with_u128_values_and_f252_pool(self):
        data = fixtures.LegacyInputTests().fixture()
        data['memory']['small_values'].append((1 << 72) - 1)
        data['memory']['f252_values'].append([0xffffffff] * 7 + [0x07ffffff])
        data['memory']['address_to_id'].extend([1, 0x40000000])
        data['public_memory_addresses'].extend([2, 3])
        expected = io.BytesIO()
        write_compact(expected, convert(copy.deepcopy(data), {'data': ['0x2a']})[0])
        with tempfile.TemporaryDirectory() as directory:
            result = self.invoke(directory, data, {'data': ['0x2a']})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((Path(directory) / 'input.cpi').read_bytes(), expected.getvalue())

    def test_mismatched_program_cache_and_unknown_schema_are_rejected_before_publication(self):
        for mutation in ('program', 'cache', 'duplicate', 'coverage', 'public', 'unknown', 'context', 'memory_id'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                data = fixtures.LegacyInputTests().fixture()
                compiled = {'data': ['0x2a']}
                if mutation == 'program':
                    compiled['data'] = ['0x2b']
                elif mutation == 'cache':
                    data['inst_cache'][0][1] = 43
                elif mutation == 'duplicate':
                    data['inst_cache'].append([1, 42])
                elif mutation == 'coverage':
                    data['state_transitions']['casm_states_by_opcode']['generic_opcode'] = [{'pc': 2, 'ap': 2, 'fp': 2}]
                elif mutation == 'public':
                    data['public_memory_addresses'] = []
                elif mutation == 'unknown':
                    data['extra'] = 0
                elif mutation == 'context':
                    data['public_segment_context']['present'] = [1] * 11
                else:
                    data['memory']['address_to_id'][1] = 123
                result = self.invoke(directory, data, compiled)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((Path(directory) / 'input.cpi').exists())
                self.assertFalse((Path(directory) / 'receipt.json').exists())


if __name__ == '__main__':
    unittest.main()
