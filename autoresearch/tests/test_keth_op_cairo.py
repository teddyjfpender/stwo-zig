"""Constrained OP fee kernels against pinned op-geth, using Keth's Rust VM.

Run with the pinned Keth Python; build the owned fee oracle first. These tests
execute the Cairo constraints directly without exporting large trace JSONs.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import random
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import keth_types.patches
from cairo_addons.compiler import cairo_compile, implement_hints
from cairo_addons.rust_bindings.vm import Program as RustProgram
from cairo_addons.testing.runner import run_rust_vm
from dotenv import load_dotenv
from ethereum_types.bytes import Bytes
from ethereum_types.numeric import U256

from autoresearch.experiments.evm_keth.bridge import PINS, authenticate

ROOT = Path(__file__).resolve().parents[2]
KETH = ROOT.parent / 'keth-pinned'
OVERLAY = ROOT / 'autoresearch/experiments/evm_keth/cairo'
ORACLE = ROOT / 'block-data/keth-integration-20261029/op-fee-oracle'


@unittest.skipUnless(ORACLE.is_file(), 'build the pinned op-geth fee oracle first')
class OpCairoKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        authenticate(KETH, PINS['keth'])
        load_dotenv(KETH / '.env')
        os.environ['CAIRO_PATH'] = str(OVERLAY) + ':' + os.environ.get('CAIRO_PATH', '')
        source = OVERLAY / 'op_stack/fees_main.cairo'
        program = cairo_compile(source, proof_mode=True)
        program.hints = implement_hints(program)
        rust = RustProgram.from_bytes(json.dumps(program.Schema().dump(program)).encode(), 'main')
        request = SimpleNamespace(config=SimpleNamespace(getoption=lambda name: {
            'layout': 'all_cairo_instance', 'no_coverage': True}.get(name, False)),
            node=SimpleNamespace(path=Path('/tmp/test_keth_op_cairo.py')))
        cls.cairo = staticmethod(run_rust_vm([program], [rust], [source], [('op_stack', 'fees_main')], request, None))

    def reference(self, data, **overrides):
        value = dict(transactions=['0x' + raw.hex() for raw in data], gas_limits=[1_000_000] * len(data),
                     gas_used=[45000] * len(data), base_fee=10**9, blob_fee=10**6, base_scalar=5227,
                     blob_scalar=1014213, operator_scalar=1500, operator_constant=17, jovian=1, da_scalar=400)
        value.update(overrides)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'input.json').write_text(json.dumps(value))
            subprocess.run([str(ORACLE), '--input', str(root / 'input.json'), '--output', str(root / 'result.json')], check=True)
            result = json.loads((root / 'result.json').read_text())
        self.assertEqual(result['geth_module']['Replace']['Version'], PINS['op_reference']['op_geth_version'])
        return value, result['rows']

    def test_fastlz_short_long_matches_window_boundary_and_random_inputs(self):
        rng = random.Random(304)
        data = [b'a' * n for n in (0, 1, 12, 13, 14, 16, 31, 32, 33, 261, 262, 263, 524, 9000)]
        data += [bytes(range(256)) * 40, bytes(rng.getrandbits(8) for _ in range(8193))]
        data += [data[-1] + data[-1][:512]]
        data += [bytes(rng.getrandbits(8) for _ in range(rng.randrange(1, 2000))) for _ in range(20)]
        _, rows = self.reference(data)
        for raw, row in zip(data, rows):
            with self.subTest(bytes=len(raw), hash=row['hash']):
                self.assertEqual(self.cairo('flz_length', data=Bytes(raw), verify_squashed_dicts=True), row['fastlz_size'])

    def test_all_real_sequencer_transaction_compression_lengths(self):
        from autoresearch.experiments.evm_keth.op_encoding import op_transaction_bytes
        block = json.loads((ROOT / 'autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/optimism-observation/block.json').read_text())['result']
        data = [op_transaction_bytes(tx) for tx in block['transactions'][1:]]
        _, rows = self.reference(data)
        for raw, row in zip(data, rows):
            with self.subTest(transaction=row['hash']):
                self.assertEqual(self.cairo('flz_length', data=Bytes(raw), verify_squashed_dicts=True), row['fastlz_size'])

    def test_full_uint256_fee_arithmetic_carries_and_overflow(self):
        for base, blob in [(0, 0), (10**9, 10**6), ((1 << 220) + (1 << 128) - 1, (1 << 210) + 1234567), ((1 << 256) - 1, 0)]:
            params, rows = self.reference([b'x' * 300], base_fee=base, blob_fee=blob,
                                          base_scalar=0xffffffff, blob_scalar=0xffffffff)
            row = rows[0]
            args = dict(fastlz_size=row['fastlz_size'], base_fee=U256(base), blob_fee=U256(blob),
                        base_scalar=params['base_scalar'], blob_scalar=params['blob_scalar'])
            if row['l1_fee_overflow']:
                with self.assertRaises(Exception):
                    self.cairo('fjord_fee', **args)
            else:
                self.assertEqual(self.cairo('fjord_fee', **args), int(row['l1_fee'], 16))

    def test_isthmus_and_jovian_operator_cost_at_uint_limits(self):
        for jovian in (0, 1):
            params, rows = self.reference([b'x'], gas_limits=[2**64 - 1], gas_used=[2**63 + 1],
                                          operator_scalar=0xffffffff, operator_constant=2**64 - 1, jovian=jovian)
            for gas, name in ((params['gas_limits'][0], 'operator_reserve'), (params['gas_used'][0], 'operator_fee')):
                self.assertEqual(self.cairo('operator_fee', gas=gas, scalar=params['operator_scalar'],
                                           constant=params['operator_constant'], jovian=jovian), int(rows[0][name], 16))
        for mutation in ({'gas': 2**64}, {'scalar': 2**32}, {'constant': 2**64}, {'jovian': 2}):
            args = dict(gas=100, scalar=1, constant=0, jovian=1)
            args.update(mutation)
            with self.assertRaises(Exception):
                self.cairo('operator_fee', **args)


if __name__ == '__main__':
    unittest.main()
