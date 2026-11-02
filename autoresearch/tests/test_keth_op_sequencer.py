"""Signed sequencer execution, OP fees and receipts against pinned op-geth."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from autoresearch.tests.test_keth_op_deposit import (
    KETH, OVERLAY, ROOT, TARGET, COINBASE, SLOT, environment, Bytes,
)
from autoresearch.experiments.evm_keth.op_compiler import compile_owned
from autoresearch.experiments.evm_keth.op_execution_workload import view_hash
from autoresearch.experiments.evm_keth.state_proofs import EMPTY_CODE_HASH, EMPTY_ROOT
from cairo_addons.compiler import implement_hints
from cairo_addons.rust_bindings.vm import Program as RustProgram
from cairo_addons.testing.runner import run_rust_vm
from eth_hash.auto import keccak
from eth_keys import keys
from ethereum.prague.transactions import LegacyTransaction
from ethereum_rlp.rlp import decode_to, encode
from ethereum_types.numeric import Uint
import rlp

ORACLE = ROOT / 'block-data/keth-integration-20261029/op-transaction-oracle-3'
KEY = keys.PrivateKey(bytes.fromhex('01' * 32))
AUTH_KEY = keys.PrivateKey(bytes.fromhex('03' * 32))
SENDER = '0x' + KEY.public_key.to_canonical_address().hex()
AUTHORITY = '0x' + AUTH_KEY.public_key.to_canonical_address().hex()
L1_BLOCK = '0x4200000000000000000000000000000000000015'
VAULTS = ['0x42000000000000000000000000000000000000' + x for x in ('19', '1a', '1b')]


def sign(kind, *, nonce=7, gas=150000, value=7, data=b'', authorization_nonce=0):
    to = bytes.fromhex((AUTHORITY if kind == 4 else TARGET)[2:])
    if kind == 0:
        payload = [nonce, 3000000, gas, to, value, data]
        signature = KEY.sign_msg_hash(keccak(rlp.encode(payload + [10, 0, 0])))
        return rlp.encode(payload + [signature.v + 55, signature.r, signature.s])
    payload = [10, nonce]
    payload += [3000000] if kind == 1 else [1000000, 3000000]
    payload += [gas, to, value, data, []]
    if kind == 4:
        auth = [10, bytes.fromhex(TARGET[2:]), authorization_nonce]
        signature = AUTH_KEY.sign_msg_hash(keccak(b'\x05' + rlp.encode(auth)))
        payload.append([auth + [signature.v, signature.r, signature.s]])
    signature = KEY.sign_msg_hash(keccak(bytes([kind]) + rlp.encode(payload)))
    return bytes([kind]) + rlp.encode(payload + [signature.v, signature.r, signature.s])


def fixture(kind, *, code=bytes.fromhex('602a60005500'), zero_fees=False, **options):
    def account(nonce, balance, code=b'', storage=None):
        return dict(nonce=hex(nonce), balance=hex(balance), codeHash='0x' + keccak(code).hex(),
                    storageHash='0x' + EMPTY_ROOT.hex(), storage=storage or {})
    def slot(n):
        return '0x' + n.to_bytes(32, 'big').hex()
    fees = {slot(1): slot(10**9), slot(3): slot(10**6 << 96), slot(7): slot(10**9),
            slot(8): slot((400 << 96) + (3 << 64) + 7)}
    if zero_fees:
        fees = {key: slot(0) for key in fees}
    pre = {SENDER: account(7, 10**20), TARGET: account(1, 1, code, {SLOT: slot(0)}),
           COINBASE: None, L1_BLOCK: account(1, 0, storage=fees), **{a: None for a in VAULTS}}
    if kind == 4:
        pre[AUTHORITY] = account(0, 1, storage={SLOT: slot(0)})
    access = [dict(address=a, storageKeys=list(v['storage']) if v else []) for a, v in pre.items()]
    return dict(pre_state=pre, access_list=access, previous_gas=21000,
                codes={'0x' + EMPTY_CODE_HASH.hex(): '0x', '0x' + keccak(code).hex(): '0x' + code.hex()},
                transaction='0x' + sign(kind, **options).hex(),
                environment=dict(chain_id=10, number=158839441, gas_limit=60000000, timestamp=1793278000,
                                 base_fee=1000000, coinbase=COINBASE, prev_randao='0x' + '00'*32,
                                 parent_beacon_block_root='0x' + '00'*32, block_hashes=[]))


@unittest.skipUnless(ORACLE.is_file(), 'build the pinned transaction oracle first')
class OpSequencerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = OVERLAY / 'op_stack/sequencer_harness.cairo'
        program = compile_owned(source, proof_mode=False)
        program.hints = implement_hints(program)
        rust = RustProgram.from_bytes(json.dumps(program.Schema().dump(program)).encode(), 'transition')
        request = SimpleNamespace(config=SimpleNamespace(getoption=lambda name: {
            'layout': 'all_cairo_instance', 'no_coverage': True}.get(name, False)),
            node=SimpleNamespace(path=Path('/tmp/test_keth_op_sequencer.py')))
        cls.cairo = staticmethod(run_rust_vm([program], [rust], [source], [('op_stack', 'sequencer_harness')], request, None))

    def run_cairo(self, value, raw=None):
        raw = raw or bytes.fromhex(value['transaction'][2:])
        encoded = Bytes(raw) if raw[0] < 0x80 else decode_to(LegacyTransaction, Bytes(raw))
        codes = {tuple(int.from_bytes(bytes.fromhex(h[2:])[i:i+16], 'little') for i in (0, 16)):
                 Bytes.fromhex(c[2:]) for h, c in value['codes'].items()}
        return self.cairo('transition', raw=Bytes(raw), encoded=encoded, index=Uint(1),
                          previous_gas=Uint(value['previous_gas']), block_env=environment(value),
                          codehash_to_code=codes, access_list=value['access_list'])

    def test_signed_types_fees_refunds_delegation_and_receipts(self):
        cases = [(kind, {}) for kind in (0, 1, 2, 4)]
        cases += [(2, dict(zero_fees=True)), (2, dict(code=bytes.fromhex('60006000fd'))),
                  (4, dict(authorization_nonce=1)), (2, dict(data=b'a' * 1000))]
        for kind, options in cases:
            value = fixture(kind, **options)
            with self.subTest(kind=kind, options=options), tempfile.TemporaryDirectory() as directory:
                path = Path(directory)
                (path / 'input.json').write_text(json.dumps(value))
                subprocess.run([str(ORACLE), '--input', str(path / 'input.json'), '--output', str(path / 'result.json')], check=True)
                expected = json.loads((path / 'result.json').read_text())
                _, (output, tx_hash, gas, view, _) = self.run_cairo(value)
                self.assertEqual(gas, expected['gas_used'])
                self.assertEqual(tx_hash, keccak(bytes.fromhex(value['transaction'][2:])))
                self.assertEqual(view, b''.join(v.to_bytes(16, 'little') for v in view_hash(expected['post_state'], value['access_list'], version=2)))
                receipt = output.receipts_trie._data[rlp.encode(1)]
                if kind == 0:
                    receipt = encode(receipt)
                self.assertEqual(receipt, bytes.fromhex(expected['encoded_receipt'][2:]))

    def test_invalid_nonce_balance_signature_and_trailing_bytes_reject(self):
        bad_nonce = fixture(2, nonce=8)
        low_balance = fixture(2)
        low_balance['pre_state'][SENDER]['balance'] = '0x1'
        bad_signature = fixture(2)
        fields = rlp.decode(bytes.fromhex(bad_signature['transaction'][4:]))
        fields[-1] = b''
        bad_signature['transaction'] = '0x02' + rlp.encode(fields).hex()
        trailing = fixture(2)
        trailing['transaction'] += '80'
        for value in (bad_nonce, low_balance, bad_signature, trailing):
            with self.subTest(transaction=value['transaction']), self.assertRaises(Exception):
                self.run_cairo(value)


if __name__ == '__main__':
    unittest.main()
