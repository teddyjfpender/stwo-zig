"""Cairo membership and non-membership against independently encoded tries."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

import keth_types.patches
import rlp
from eth_hash.auto import keccak
from cairo_addons.compiler import implement_hints
from cairo_addons.rust_bindings.vm import Program as RustProgram
from cairo_addons.testing.runner import run_rust_vm
from ethereum.crypto.hash import Hash32
from ethereum_types.bytes import Bytes
from mpt.ethereum_tries import PreState

from autoresearch.experiments.evm_keth.op_compiler import compile_owned
from autoresearch.experiments.evm_keth.state_proofs import EMPTY_ROOT, EMPTY_CODE_HASH, lookup_nodes

ROOT = Path(__file__).resolve().parents[2]


def trie(entries, nodes):
    """Small canonical hexary trie encoder, independent of Keth's trie code."""
    if not entries:
        return EMPTY_ROOT
    def compact(path, leaf):
        prefix = [2 * int(leaf) + len(path) % 2]
        digits = prefix + ([0] if len(path) % 2 == 0 else []) + path
        return bytes(digits[i] * 16 + digits[i+1] for i in range(0, len(digits), 2))
    def store(node):
        encoded = rlp.encode(node)
        nodes[keccak(encoded)] = encoded
        return node if len(encoded) < 32 else keccak(encoded)
    def build(rows):
        if len(rows) == 1:
            path, value = rows[0]
            return [compact(path, True), value]
        common = 0
        while all(len(p) > common and p[common] == rows[0][0][common] for p, _ in rows):
            common += 1
        if common:
            return [compact(rows[0][0][:common], False), store(build([(p[common:], v) for p, v in rows]))]
        branches = [b''] * 17
        for digit in range(16):
            children = [(p[1:], v) for p, v in rows if p and p[0] == digit]
            if children:
                branches[digit] = store(build(children))
        for path, value in rows:
            if not path:
                branches[16] = value
        return branches
    rows = [([h for byte in key for h in (byte >> 4, byte & 15)], value) for key, value in entries.items()]
    encoded = rlp.encode(build(rows))
    nodes[keccak(encoded)] = encoded
    return keccak(encoded)


def fixture():
    nodes, accounts, access, leaves = {}, {}, [], {}
    for suffix in (0x11, 0x22):
        address = '0x' + bytes([suffix] * 20).hex()
        slots = {f'0x{k:064x}': hex(v) for k, v in ((0, 7), (1, 0), (2, 99))}
        root = trie({keccak(bytes.fromhex(k[2:])): rlp.encode(int(v, 16))
                     for k, v in slots.items() if int(v, 16)}, nodes)
        account = dict(nonce='0x3', balance='0x1234', codeHash='0x' + EMPTY_CODE_HASH.hex(),
                       storageHash='0x' + root.hex(), storage=slots)
        accounts[address] = account
        access.append(dict(address=address, storageKeys=list(slots)))
        leaves[keccak(bytes.fromhex(address[2:]))] = rlp.encode([3, 0x1234, root, EMPTY_CODE_HASH])
    absent = '0x' + '33' * 20
    accounts[absent] = None
    access.append(dict(address=absent, storageKeys=[f'0x{0:064x}']))
    return trie(leaves, nodes), nodes, accounts, access


class OpStateAuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = ROOT / 'autoresearch/experiments/evm_keth/cairo/op_stack/state_authentication_harness.cairo'
        program = compile_owned(source, proof_mode=False)
        program.hints = implement_hints(program)
        rust = RustProgram.from_bytes(json.dumps(program.Schema().dump(program)).encode(), 'read')
        request = SimpleNamespace(config=SimpleNamespace(getoption=lambda name: {
            'layout': 'all_cairo_instance', 'no_coverage': True}.get(name, False)),
            node=SimpleNamespace(path=Path('/tmp/test_keth_op_state_authentication.py')))
        cls.cairo = staticmethod(run_rust_vm([program], [rust], [source],
                                            [('op_stack', 'state_authentication_harness')], request, None))

    def authenticate(self, root, nodes, accounts, accesses):
        state = PreState.from_data(dict(extra=dict(preState=accounts, accessList=accesses)))
        return self.cairo('authenticate', root=Hash32(root), node_store=nodes, state=state, access_list=accesses)

    def test_account_storage_membership_and_absence(self):
        root, nodes, accounts, accesses = fixture()
        self.authenticate(root, nodes, accounts, accesses)
        for address in accounts:
            key = keccak(bytes.fromhex(address[2:]))
            actual = self.cairo('read', root=Hash32(root), secure_key=Hash32(key), node_store=nodes)[-1]
            self.assertEqual(actual, lookup_nodes(root, key, nodes) or b'')

    def test_wrong_account_fields_and_unchanged_slots_reject(self):
        root, nodes, accounts, accesses = fixture()
        address = accesses[0]['address']
        changes = [dict(nonce='0x4'), dict(balance='0x1235'), dict(codeHash='0x' + 'ff'*32),
                   dict(storageHash='0x' + EMPTY_ROOT.hex()),
                   dict(storage={**accounts[address]['storage'], f'0x{0:064x}': '0x8'}),
                   dict(storage={**accounts[address]['storage'], f'0x{1:064x}': '0x1'})]
        for change in changes:
            mutated = copy.deepcopy(accounts)
            mutated[address].update(change)
            with self.subTest(change=change), self.assertRaises(Exception):
                self.authenticate(root, nodes, mutated, accesses)

    def test_forged_presence_and_absence_reject(self):
        root, nodes, accounts, accesses = fixture()
        absent = accesses[-1]['address']
        for address, account in ((accesses[0]['address'], None), (absent, accounts[accesses[0]['address']])):
            mutated = copy.deepcopy(accounts)
            mutated[address] = copy.deepcopy(account)
            with self.subTest(address=address), self.assertRaises(Exception):
                self.authenticate(root, nodes, mutated, accesses)

    def test_missing_and_wrong_node_preimages_reject(self):
        root, nodes, accounts, accesses = fixture()
        for value in (None, nodes[root][:-1] + bytes([nodes[root][-1] ^ 1])):
            mutated = dict(nodes)
            if value is None:
                del mutated[root]
            else:
                mutated[root] = value
            with self.subTest(missing=value is None), self.assertRaises(Exception):
                self.authenticate(root, mutated, accounts, accesses)


if __name__ == '__main__':
    unittest.main()
