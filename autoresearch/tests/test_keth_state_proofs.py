"""Root-bound state witness verification; run with pinned Keth Python."""
from __future__ import annotations

import copy
import bz2
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import rlp
from eth_hash.auto import keccak

from autoresearch.experiments.evm_keth.state_proofs import EMPTY_ROOT, integer, lookup, verify_account
from autoresearch.experiments.evm_keth.collect_state_witness import candidate_accesses, collect
from autoresearch.experiments.evm_keth.witness_nodes import encode_path, recover_compressed_siblings
from autoresearch.experiments.evm_keth.bridge import digest

EVIDENCE = Path(__file__).resolve().parents[1] / 'experiments/evm_keth/evidence/2026-10-29-m5-max/optimism-account-sample'


class StateProofTests(unittest.TestCase):
    def test_v2_deposit_proofs_bind_initial_roots_and_persistent_read_coverage(self):
        from autoresearch.experiments.evm_keth.op_execution_workload import view_hash
        directory = EVIDENCE.parent / 'op-deposit-kernel-v2'
        provenance = json.loads((directory / 'provenance.json').read_text())
        proof = directory / 'deposit.proof.json.bz2'
        self.assertEqual(digest(proof), provenance['retained_proof_sha256'])
        raw_hash = hashlib.sha256(bz2.decompress(proof.read_bytes())).hexdigest()
        self.assertEqual(raw_hash, provenance['uncompressed_proof_sha256'])
        value = json.loads(gzip.decompress((directory / 'workload-input.json.gz').read_bytes()))
        expected = json.loads((directory / 'workload-expected-output.json').read_text())
        self.assertEqual(expected[6:8], view_hash(value['pre_state'], value['access_list'], version=2, initial=True))
        changed = copy.deepcopy(value['pre_state'])
        address = next(a for a, account in changed.items() if account is not None)
        changed[address]['storageHash'] = '0x' + '55' * 32
        self.assertNotEqual(expected[6:8], view_hash(changed, value['access_list'], version=2, initial=True))
        self.assertTrue(provenance['claims']['persistent_account_and_storage_access_keys_bound_to_view'])
        self.assertFalse(provenance['claims']['cairo_mpt_authentication_proved'])
        self.assertFalse(provenance['claims']['all_transaction_local_state_soundness_audited'])
        for backend in ('cpu', 'metal'):
            result = json.loads((directory / backend / 'kernel-results.json').read_text())
            self.assertEqual(result['conversion']['execution_steps'], 4937468)
            self.assertEqual(result['expected_output'], expected)
            for entry in result['proofs']:
                self.assertEqual(entry['proof_sha256'], raw_hash)
                official = json.loads((directory / backend / f"trial-{entry['index']}.official.json").read_text())
                self.assertTrue(official['verified'])
                self.assertEqual(official['proof_sha256'], raw_hash)

    def test_retained_real_deposit_proofs_match_reference_and_keep_partial_scope(self):
        from autoresearch.experiments.evm_keth.op_execution_workload import view_hash
        directory = EVIDENCE.parent / 'op-deposit-kernel'
        provenance = json.loads((directory / 'provenance.json').read_text())
        proof = directory / 'l1-attributes-deposit.proof.json.bz2'
        self.assertEqual(digest(proof), provenance['retained_proof_sha256'])
        raw = bz2.decompress(proof.read_bytes())
        raw_hash = hashlib.sha256(raw).hexdigest()
        self.assertEqual(raw_hash, provenance['uncompressed_proof_sha256'])
        self.assertEqual(json.loads(raw)['stark_proof']['config']['fri_config']['n_queries'], 70)
        expected = json.loads((directory / 'workload-expected-output.json').read_text())
        value = json.loads(gzip.decompress((directory / 'workload-input.json.gz').read_bytes()))
        reference = json.loads(gzip.decompress((directory / 'reference-result.json.gz').read_bytes()))
        self.assertEqual(expected[6:8], view_hash(value['pre_state'], value['access_list']))
        self.assertEqual(expected[8:10], view_hash(reference['post_state'], value['access_list']))
        self.assertEqual(expected[10:13], [reference['gas_used'], int(reference['success']), reference['nonce']])
        self.assertEqual(expected[10:13], [46230, 1, 53604410])
        self.assertTrue(provenance['claims']['deposit_execution_kernel_proved'])
        self.assertTrue(all(v is False for k, v in provenance['claims'].items() if k != 'deposit_execution_kernel_proved'))
        for backend in ('cpu', 'metal'):
            result = json.loads((directory / backend / 'kernel-results.json').read_text())
            self.assertEqual(result['status'], 'qualified-kernel')
            self.assertEqual(result['expected_output'], expected)
            self.assertEqual(result['conversion']['execution_steps'], 4057477)
            self.assertFalse(result['op_block_execution_proved'])
            for entry in result['proofs']:
                self.assertEqual(entry['proof_sha256'], raw_hash)
                official = json.loads((directory / backend / f"trial-{entry['index']}.official.json").read_text())
                self.assertTrue(official['verified'])
                self.assertEqual(official['proof_sha256'], raw_hash)

    def test_retained_op_fee_proofs_bind_exact_outputs_without_promoting_block_claims(self):
        directory = EVIDENCE.parent / 'op-fee-kernel'
        provenance = json.loads((directory / 'provenance.json').read_text())
        proof = directory / 'sequencer-fees.proof.json.bz2'
        self.assertEqual(digest(proof), provenance['retained_proof_sha256'])
        raw_hash = hashlib.sha256(bz2.decompress(proof.read_bytes())).hexdigest()
        self.assertEqual(raw_hash, provenance['uncompressed_proof_sha256'])
        expected = json.loads((directory / 'workload-expected-output.json').read_text())
        self.assertEqual(len(expected), 419)
        for backend in ('cpu', 'metal'):
            result = json.loads((directory / backend / 'kernel-results.json').read_text())
            self.assertTrue(result['kernel_proof_verified'])
            self.assertEqual(result['expected_output'], expected)
            self.assertEqual(result['conversion']['execution_steps'], 3130693)
            for key in ('op_block_execution_proved', 'op_derivation_proved', 'public_block_statement_bound'):
                self.assertIs(result[key], False)
            for proof_entry in result['proofs']:
                self.assertEqual(proof_entry['proof_sha256'], raw_hash)
                official = json.loads((directory / backend / f"trial-{proof_entry['index']}.official.json").read_text())
                self.assertTrue(official['verified'])
                self.assertEqual(official['proof_sha256'], raw_hash)

    def test_extra_intermediate_siblings_come_from_root_verified_queries(self):
        directory = EVIDENCE.parent / 'op-fee-kernel'
        pre = json.loads((EVIDENCE / 'pre-header.json').read_text())['stateRoot']
        post = json.loads((EVIDENCE / 'post-header.json').read_text())['stateRoot']
        authenticated = set()
        for path in directory.glob('*proof*.json'):
            response = json.loads(path.read_text())['result']
            root = pre if '-pre-' in path.name else post
            verify_account(root, response['address'], response)
            authenticated.update(response['accountProof'])
            for item in response['storageProof']:
                authenticated.update(item['proof'])
        extra = set(json.loads((directory / 'supplemental-nodes.json').read_text()))
        self.assertEqual(len(extra), 3)
        self.assertTrue(extra <= authenticated)

    def test_retained_full_reference_inputs_and_positive_negative_receipts(self):
        directory = EVIDENCE.parent / 'native-reference'
        provenance = json.loads((directory / 'provenance.json').read_text())
        for name, identity in provenance['archives'].items():
            path = directory / name
            self.assertEqual(digest(path), identity['sha256'])
            self.assertEqual(hashlib.sha256(gzip.decompress(path.read_bytes())).hexdigest(), identity['uncompressed_sha256'])
        for chain in ('ethereum', 'optimism'):
            qualification = json.loads((directory / chain / 'qualification.json').read_text())
            self.assertEqual(qualification['status'], 'qualified')
            self.assertEqual(qualification['binary_sha256'], provenance['reference_binary_sha256'])
            self.assertEqual(qualification['input_sha256'], provenance['archives'][chain + '-input.json.gz']['uncompressed_sha256'])
            self.assertEqual(len(qualification['trials']), 3)
            self.assertEqual(len(qualification['negative_checks']), 4)
            for trial in qualification['trials'] + qualification['negative_checks']:
                path = directory / chain / (trial['name'] + '.json')
                self.assertEqual(digest(path), trial['result_sha256'])
                receipt = json.loads(path.read_text())
                self.assertEqual(receipt['offline_execution_checked'], trial in qualification['trials'])
                for key in ('cairo_execution_proved', 'derivation_proved', 'consensus_authenticated'):
                    self.assertIs(receipt[key], False)
        self.assertTrue(all(provenance['execution_fork_times_match_retained_config'].values()))

    def test_real_pre_and_post_state_and_code_are_bound_to_distinct_roots(self):
        roots = []
        for label in ('pre', 'post'):
            root = json.loads((EVIDENCE / (label + '-header.json')).read_text())['stateRoot']
            proof = json.loads((EVIDENCE / (label + '-proof.json')).read_text())['result']
            code = json.loads((EVIDENCE / (label + '-code.json')).read_text())['result']
            result = verify_account(root, proof['address'], proof, code)
            self.assertTrue(result['code_checked'])
            self.assertEqual(result['storage_slots'], 8)
            roots.append(root)
        self.assertNotEqual(*roots)

    def test_tampered_proofs_values_code_and_addresses_rejected(self):
        root = json.loads((EVIDENCE / 'pre-header.json').read_text())['stateRoot']
        source = json.loads((EVIDENCE / 'pre-proof.json').read_text())['result']
        code = json.loads((EVIDENCE / 'pre-code.json').read_text())['result']
        for mutation in ('root', 'address', 'nonce', 'account_nodes', 'storage_value', 'storage_nodes', 'code', 'duplicate'):
            with self.subTest(mutation=mutation):
                proof, expected, bytecode = copy.deepcopy(source), root, code
                if mutation == 'root':
                    expected = '0x' + '00' * 32
                elif mutation == 'address':
                    proof['address'] = '0x' + '00' * 20
                elif mutation == 'nonce':
                    proof['nonce'] = hex(int(proof['nonce'], 16) + 1)
                elif mutation == 'account_nodes':
                    proof['accountProof'] = proof['accountProof'][1:]
                elif mutation == 'storage_value':
                    proof['storageProof'][0]['value'] = hex(int(proof['storageProof'][0]['value'], 16) + 1)
                elif mutation == 'storage_nodes':
                    proof['storageProof'][0]['proof'] = []
                elif mutation == 'code':
                    bytecode += '00'
                else:
                    proof['storageProof'].append(proof['storageProof'][0])
                with self.assertRaises(ValueError):
                    verify_account(expected, source['address'], proof, bytecode)

    def test_secure_path_membership_nonmembership_and_inline_children(self):
        key = bytes.fromhex('12' * 32)
        leaf = rlp.encode([b'\x20' + key, b'value'])
        self.assertEqual(lookup(keccak(leaf), key, [leaf]), b'value')
        self.assertIsNone(lookup(keccak(leaf), bytes(32), [leaf]))
        self.assertIsNone(lookup(EMPTY_ROOT, key, []))
        with self.assertRaises(ValueError):
            lookup(keccak(leaf), key, [])
        # Extension consumes 63 nibbles; its inline branch consumes the final
        # nibble and then an inline zero-path leaf returns the value.
        branch = [b''] * 17
        branch[2] = [b'\x20', b'v']
        extension = rlp.encode([bytes.fromhex('1' + key.hex()[:-1]), branch])
        self.assertEqual(lookup(keccak(extension), key, [extension]), b'v')
        for malformed in (b'\x00', b'\x00\x01'):
            with self.assertRaises(ValueError):
                integer(malformed)

    def test_collection_reuse_rechecks_witness_files_before_acceptance(self):
        # A bounded real account collection exercises exact storage coverage,
        # content-addressed code reuse and immutable restart behavior offline.
        address = '0x4200000000000000000000000000000000000015'
        observations = EVIDENCE.parent / 'optimism-observation'
        proofs = {label: json.loads((EVIDENCE / (label + '-proof.json')).read_text()) for label in ('pre', 'post')}
        code = json.loads((EVIDENCE / 'pre-code.json').read_text())['result']
        slots = {s['key'] for s in proofs['pre']['result']['storageProof']}
        parent_number = json.loads((EVIDENCE / 'pre-header.json').read_text())['number']

        def request(endpoint, method, params):
            if method == 'eth_chainId':
                return {'result': '0xa'}
            if method == 'eth_getProof':
                return copy.deepcopy(proofs['pre' if params[-1] == parent_number else 'post'])
            self.fail('proof-bound trace code should avoid additional code requests')

        with tempfile.TemporaryDirectory() as tmp, patch(
                'autoresearch.experiments.evm_keth.collect_state_witness.candidate_accesses',
                return_value={address: slots}), patch(
                'autoresearch.experiments.evm_keth.collect_state_witness.rpc', side_effect=request), patch(
                'autoresearch.experiments.evm_keth.collect_state_witness.time.sleep'):
            tmp = Path(tmp)
            trace = tmp / 'trace.json'
            trace.write_text(json.dumps({'result': [{'result': {address: {'code': code}}}]}))
            arguments = ('offline://fixture', 10, observations / 'block.json', observations / 'parent.json', trace)
            with patch('builtins.print'):
                first = collect(*arguments, tmp / 'first')
                second = collect(*arguments, tmp / 'second', reuse=tmp / 'first')
            self.assertEqual(first['status'], 'verified_candidate_accesses')
            self.assertTrue(second['accounts'][0]['reused'])
            path = tmp / 'first' / address / 'pre-proof-0.json'
            path.write_text('{}')
            with self.assertRaises(ValueError):
                collect(*arguments, tmp / 'tampered', reuse=tmp / 'first')

    def test_trace_candidate_order_errors_are_rejected(self):
        with self.assertRaises(ValueError):
            candidate_accesses({'transactions': [{'hash': 'a'}]}, [])
        with self.assertRaises(ValueError):
            candidate_accesses({'transactions': [{'hash': 'a'}]}, [{'txHash': 'b', 'result': {}}])

    def test_post_deletion_sibling_recovery_requires_exact_referenced_hash(self):
        short = rlp.encode([encode_path(True, [2, 3, 4]), b'v' * 32])
        combined = rlp.encode([encode_path(True, [7, 2, 3, 4]), b'v' * 32])
        branch = [b''] * 17
        branch[7] = keccak(short)
        branch = rlp.encode(branch)
        supplied = {'0x' + raw.hex() for raw in (branch, combined)}
        recovered, receipt = recover_compressed_siblings(supplied)
        self.assertIn('0x' + short.hex(), recovered)
        self.assertEqual(receipt['recovered_node_hashes'], ['0x' + keccak(short).hex()])
        different_value = rlp.encode([encode_path(True, [7, 2, 3, 4]), b'w' * 32])
        recovered, receipt = recover_compressed_siblings({'0x' + raw.hex() for raw in (branch, different_value)})
        self.assertNotIn('0x' + short.hex(), recovered)
        self.assertEqual(receipt['recovered_nodes'], 0)


if __name__ == '__main__':
    unittest.main()
