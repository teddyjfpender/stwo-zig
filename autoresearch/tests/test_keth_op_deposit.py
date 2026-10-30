"""OP deposit codec and execution against unmodified pinned op-geth."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import keth_types.patches
import rlp
from eth_hash.auto import keccak
from cairo_addons.compiler import cairo_compile, implement_hints
from cairo_addons.rust_bindings.vm import Program as RustProgram
from cairo_addons.testing.runner import run_rust_vm
from dotenv import load_dotenv
from ethereum.prague.vm import BlockEnvironment
from ethereum.prague.fork_types import Address
from ethereum_types.bytes import Bytes, Bytes32
from ethereum_types.numeric import U64, U256, Uint
from mpt.ethereum_tries import PreState

from autoresearch.experiments.evm_keth.bridge import PINS, authenticate
from autoresearch.experiments.evm_keth.op_execution_workload import view_hash
from autoresearch.experiments.evm_keth.op_compiler import compile_owned
from autoresearch.experiments.evm_keth.state_proofs import EMPTY_CODE_HASH, EMPTY_ROOT

ROOT = Path(__file__).resolve().parents[2]
KETH = ROOT.parent / 'keth-pinned'
OVERLAY = ROOT / 'autoresearch/experiments/evm_keth/cairo'
ORACLE = ROOT / 'block-data/keth-integration-20261029/op-deposit-oracle-2'
SENDER, TARGET, COINBASE = ['0x' + x * 20 for x in ('22', '11', '33')]
SLOT = '0x' + '00' * 32


def envelope(*, mint=0, value=0, gas=100000, data=b'', to=TARGET):
    return b'\x7e' + rlp.encode([bytes(32), bytes.fromhex(SENDER[2:]), bytes.fromhex(to[2:]) if to else b'',
                                 mint, value, gas, b'', data])


def environment(value):
    state = PreState.from_data({'extra': {'preState': value['pre_state'], 'accessList': value['access_list']}})
    e = value['environment']
    return BlockEnvironment(chain_id=U64(e['chain_id']), state=state, block_gas_limit=Uint(e['gas_limit']),
                            block_hashes=[Bytes32.fromhex(h[2:]) for h in e['block_hashes']],
                            coinbase=Address.fromhex(e['coinbase'][2:]), number=Uint(e['number']),
                            base_fee_per_gas=Uint(e['base_fee']), time=U256(e['timestamp']),
                            prev_randao=Bytes32.fromhex(e['prev_randao'][2:]), excess_blob_gas=U64(0),
                            parent_beacon_block_root=Bytes32.fromhex(e['parent_beacon_block_root'][2:]))


@unittest.skipUnless(ORACLE.is_file(), 'build the pinned deposit oracle first')
class OpDepositTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        authenticate(KETH, PINS['keth'])
        load_dotenv(KETH / '.env')
        os.environ['CAIRO_PATH'] = str(OVERLAY) + ':' + os.environ.get('CAIRO_PATH', '')
        source = OVERLAY / 'op_stack/deposit_harness.cairo'
        program = compile_owned(source, proof_mode=False)
        program.hints = implement_hints(program)
        rust = RustProgram.from_bytes(json.dumps(program.Schema().dump(program)).encode(), 'transition')
        request = SimpleNamespace(config=SimpleNamespace(getoption=lambda name: {
            'layout': 'all_cairo_instance', 'no_coverage': True}.get(name, False)),
            node=SimpleNamespace(path=Path('/tmp/test_keth_op_deposit.py')))
        cls.cairo = staticmethod(run_rust_vm([program], [rust], [source], [('op_stack', 'deposit_harness')], request, None))

    def test_canonical_codec_and_uint_limits(self):
        raw = envelope(mint=2**256-1, value=2**255, gas=2**64-1, data=b'\x00\xff')
        result = self.cairo('deposit_fields', raw=Bytes(raw))
        self.assertEqual(result, [bytes(32), bytes.fromhex(SENDER[2:]), 2**256-1, 2**255, 2**64-1, b'\x00\xff'])

    def test_malformed_noncanonical_and_system_deposits_reject(self):
        fields = rlp.decode(envelope()[1:])
        invalid = [b'\x02' + envelope()[1:], envelope() + b'\x80', b'\x7e' + rlp.encode(fields[:-1])]
        for index, bad in ((0, bytes(31)), (1, bytes(19)), (2, bytes(19)), (3, bytes(33)),
                           (4, b'\x00\x01'), (5, b'\x01' * 9), (6, b'\x01'), (6, b'\x00'), (7, [])):
            changed = fields[:]
            changed[index] = bad
            invalid.append(b'\x7e' + rlp.encode(changed))
        for raw in invalid:
            with self.subTest(raw=raw.hex()), self.assertRaises(Exception):
                self.cairo('deposit_fields', raw=Bytes(raw))

    def fixture(self, *, balance=10, nonce=7, mint=20, value=7, gas=100000, data=b'', code=b'', slot=0, to=TARGET):
        code_hash = '0x' + keccak(code).hex()
        def account(n, b, h, storage):
            return dict(nonce=hex(n), balance=hex(b), codeHash=h,
                        storageHash='0x' + EMPTY_ROOT.hex(), storage=storage)
        return dict(pre_state={SENDER: account(nonce, balance, '0x' + EMPTY_CODE_HASH.hex(), {}),
                               TARGET: account(0, 1, code_hash, {SLOT: '0x' + slot.to_bytes(32, 'big').hex()}), COINBASE: None},
                    access_list=[dict(address=a, storageKeys=[SLOT] if a == TARGET else []) for a in (SENDER, TARGET, COINBASE)],
                    codes={'0x' + EMPTY_CODE_HASH.hex(): '0x', code_hash: '0x' + code.hex()},
                    transaction='0x' + envelope(mint=mint, value=value, gas=gas, data=data, to=to).hex(),
                    environment=dict(chain_id=10, number=158839441, gas_limit=60000000, timestamp=1793278000,
                                     base_fee=1000000, coinbase=COINBASE, prev_randao='0x' + '00'*32,
                                     parent_beacon_block_root='0x' + '00'*32, block_hashes=[]))

    def differential(self, value):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'input.json').write_text(json.dumps(value))
            subprocess.run([str(ORACLE), '--input', str(path / 'input.json'), '--output', str(path / 'output.json')], check=True)
            expected = json.loads((path / 'output.json').read_text())
        codes = {tuple(int.from_bytes(bytes.fromhex(h[2:])[i:i+16], 'little') for i in (0, 16)):
                 Bytes.fromhex(c[2:]) for h, c in value['codes'].items()}
        actual, (used, success, nonce, after) = self.cairo('transition', raw=Bytes.fromhex(value['transaction'][2:]),
            block_env=environment(value), codehash_to_code=codes, access_list=value['access_list'])
        self.assertEqual((used, success, nonce), (expected['gas_used'], int(expected['success']), expected['nonce']))
        self.assertEqual(after, b''.join(v.to_bytes(16, 'little') for v in view_hash(expected['post_state'], value['access_list'], version=2)))
        for address, reference in expected['post_state'].items():
            cairo_account = actual.state._main_trie._data.get(Address.fromhex(address[2:]))
            if reference is None:
                self.assertIsNone(cairo_account)
                continue
            self.assertEqual((cairo_account.nonce, cairo_account.balance, cairo_account.code_hash),
                             (int(reference['nonce'], 16), int(reference['balance'], 16), bytes.fromhex(reference['codeHash'][2:])))
            for key, value in reference['storage'].items():
                trie = actual.state._storage_tries.get(Address.fromhex(address[2:]))
                slot = trie._data.get(Bytes32.fromhex(key[2:])) if trie else 0
                self.assertEqual(slot or 0, int(value, 16))

    def test_mint_nonce_wrap_failures_revert_refund_and_calldata_floor(self):
        cases = [dict(), dict(balance=2**256-1, mint=1, value=0), dict(nonce=2**64-1),
                 dict(balance=2**256-1, mint=1, nonce=2**64-1, value=0),
                 dict(gas=20000), dict(value=31), dict(code=bytes.fromhex('60006000fd')),
                 dict(code=b'\xfe'), dict(code=bytes.fromhex('5b600056'), gas=25000),
                 dict(code=bytes.fromhex('600060005500'), slot=1), dict(slot=17), dict(data=b'a'*1000),
                 dict(code=bytes.fromhex('60005c60005500')),
                 dict(code=bytes.fromhex('602a60005d60005c60005500'))]
        for case in cases:
            with self.subTest(case=case):
                self.differential(self.fixture(**case))

    def test_initial_cached_code_cannot_bypass_code_hash_check(self):
        value = self.fixture()
        value['pre_state'][TARGET]['code'] = '0xfe'
        with self.assertRaises(Exception):
            self.cairo('transition', raw=Bytes.fromhex(value['transaction'][2:]), block_env=environment(value),
                       codehash_to_code={}, access_list=value['access_list'])

    def test_p256_staticcall_output_is_bound_to_persistent_storage(self):
        from autoresearch.tests.test_keth_op_p256 import vectors
        code = bytes.fromhex('3660006000376020610100366000610100612710fa506101005160005500')
        selected = {'valid-0', 'high-s-1', 'x-above-order', 'wrong-hash-0', 'off-curve', 'short'}
        for name, data, _ in vectors():
            if name not in selected:
                continue
            value = self.fixture(code=code, data=data)
            precompile = '0x' + '00'*18 + '0100'
            value['pre_state'][precompile] = None
            value['access_list'].append(dict(address=precompile, storageKeys=[]))
            with self.subTest(name=name):
                self.differential(value)

    def test_creation_success_revert_invalid_intrinsic_and_nonce_wrap(self):
        cases = [dict(), dict(nonce=2**64-1), dict(gas=30000),
                 dict(data=bytes.fromhex('60006000fd')),
                 dict(data=bytes.fromhex('6001600c60003960016000f300'))]
        for case in cases:
            value = self.fixture(to=None, **case)
            nonce = int(value['pre_state'][SENDER]['nonce'], 16)
            target = '0x' + keccak(rlp.encode([bytes.fromhex(SENDER[2:]), nonce]))[-20:].hex()
            del value['pre_state'][TARGET]
            value['pre_state'][target] = None
            value['access_list'][1] = dict(address=target, storageKeys=[])
            with self.subTest(case=case):
                self.differential(value)

    def test_evm_reads_outside_the_committed_view_reject(self):
        hidden = '0x' + '44' * 20
        cases = [self.fixture(code=bytes.fromhex('6000545000'), slot=17),
                 self.fixture(code=bytes.fromhex('73' + hidden[2:] + '315000'))]
        cases[0]['access_list'][1]['storageKeys'] = []
        cases[1]['pre_state'][hidden] = dict(nonce='0x0', balance='0x7b', codeHash='0x' + EMPTY_CODE_HASH.hex(),
                                            storageHash='0x' + EMPTY_ROOT.hex(), storage={})
        for value in cases:
            codes = {tuple(int.from_bytes(bytes.fromhex(h[2:])[i:i+16], 'little') for i in (0, 16)):
                     Bytes.fromhex(c[2:]) for h, c in value['codes'].items()}
            with self.subTest(transaction=value['transaction']), self.assertRaisesRegex(Exception, 'outside committed view'):
                self.cairo('transition', raw=Bytes.fromhex(value['transaction'][2:]), block_env=environment(value),
                           codehash_to_code=codes, access_list=value['access_list'])

    def test_initial_transaction_created_marker_cannot_change_selfdestruct(self):
        value = self.fixture(code=bytes.fromhex('73' + SENDER[2:] + 'ff'))
        self.differential(value)
        env = environment(value)
        env.state.created_accounts.add(Address.fromhex(TARGET[2:]))
        codes = {tuple(int.from_bytes(bytes.fromhex(h[2:])[i:i+16], 'little') for i in (0, 16)):
                 Bytes.fromhex(c[2:]) for h, c in value['codes'].items()}
        with self.assertRaises(Exception):
            self.cairo('transition', raw=Bytes.fromhex(value['transaction'][2:]), block_env=env,
                       codehash_to_code=codes, access_list=value['access_list'])


if __name__ == '__main__':
    unittest.main()
