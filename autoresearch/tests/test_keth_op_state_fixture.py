"""OP state adaptation stays authenticated and outside Ethereum-only admission."""
from __future__ import annotations

import gzip
import json
from pathlib import Path
import tempfile
import unittest

from eth_hash.auto import keccak

from autoresearch.experiments.evm_keth.bridge import validate_zkpi
from autoresearch.experiments.evm_keth.op_state_fixture import convert, state_at
from autoresearch.experiments.evm_keth.state_proofs import EMPTY_CODE_HASH, lookup_nodes

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / 'autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max/native-reference'


class OpStateFixtureTests(unittest.TestCase):
    def test_real_pre_post_fixture_loads_keth_types_and_rejects_ethereum_admission(self):
        import keth_types.patches
        from mpt.ethereum_tries import ZkPi
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / '1/158839441'
            directory.mkdir(parents=True)
            out = directory / 'zkpi.json'
            receipt = convert(EVIDENCE / 'optimism-input.json.gz', EVIDENCE / 'optimism-access-list.json',
                              EVIDENCE / 'provenance.json', EVIDENCE / 'optimism/qualification.json', out)
            self.assertEqual((receipt['accounts'], receipt['storage_slots']), (280, 1555))
            zkpi = ZkPi.from_data(json.loads(out.read_text()))
            accounts, storage = zkpi.state_diff.get_diff_segments()
            self.assertEqual((len(accounts), len(storage)), (36, 105))
            self.assertFalse(receipt['cairo_execution_proved'])
            with self.assertRaises(ValueError):
                validate_zkpi(root, 158839441)

    def test_shared_trie_database_rejects_a_corrupted_node_under_a_valid_hash_key(self):
        data = json.loads(gzip.decompress((EVIDENCE / 'optimism-input.json.gz').read_bytes()))
        nodes = {keccak(bytes.fromhex(raw[2:])): bytes.fromhex(raw[2:]) for raw in data['witness']['state']}
        root = bytes.fromhex(data['witness']['headers'][0]['stateRoot'][2:])
        nodes[root] = b'corrupted-node'
        with self.assertRaisesRegex(ValueError, 'node hash mismatch'):
            lookup_nodes(root, keccak(bytes(20)), nodes)

    def test_missing_contract_code_is_not_substituted_with_empty_code(self):
        data = json.loads(gzip.decompress((EVIDENCE / 'optimism-input.json.gz').read_bytes()))
        nodes = {keccak(bytes.fromhex(raw[2:])): bytes.fromhex(raw[2:]) for raw in data['witness']['state']}
        accesses = [dict(address='0x4200000000000000000000000000000000000015', storageKeys=[])]
        with self.assertRaisesRegex(ValueError, 'code missing'):
            state_at(data['witness']['headers'][0]['stateRoot'], accesses, nodes, {EMPTY_CODE_HASH: b''})


if __name__ == '__main__':
    unittest.main()
