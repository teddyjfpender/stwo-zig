"""Trust-boundary tests for the experimental Keth PIE orchestration."""
from __future__ import annotations

import argparse
import bz2
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
from autoresearch.experiments.evm_keth import bridge
from autoresearch.experiments.evm_keth.op_stack_journal import OpStackRangeJournal
from autoresearch.experiments.evm_keth.legacy_input import convert, write_compact, OPCODES, BUILTINS
from autoresearch.experiments.evm_keth.limits import address_space_limit
from autoresearch.experiments.evm_keth.verify_bundle import check_manifest, expected_specs, state_root_commitment_limbs
from autoresearch.experiments.evm_keth import collect_rpc


class KethBridgeTests(unittest.TestCase):
    def test_source_lane_and_claim_defaults(self):
        self.assertEqual(bridge.PINS["keth"]["supported_chain_id"], 1)
        self.assertTrue(all(value is False for value in bridge.claims().values()))

    def test_committed_smoke_fixture_matches_source_receipt(self):
        evidence = ROOT / "autoresearch/experiments/evm_keth/evidence"
        receipt = json.loads((evidence / "smoke-provenance.json").read_text())
        self.assertEqual(receipt["source"]["revision"], bridge.PINS["keth"]["revision"])
        self.assertEqual(receipt["pie_sha256"], bridge.digest(evidence / "keth_fibonacci.pie.zip"))
        self.assertEqual(receipt["scope"], "keth-fibonacci-pie-transport-only")
        self.assertEqual(receipt["expected_output"], [144])
        validation = json.loads((evidence / "validation.json").read_text())
        self.assertEqual(validation["proof"]["retained_binary_proof_sha256"],
                         bridge.digest(evidence / "keth_fibonacci.proof.bz2"))
        self.assertTrue(all(value is False for value in validation["claims"].values()))

    def test_wrong_revision_and_dirty_source_rejected(self):
        with patch.object(bridge, "git", return_value="0" * 40):
            with self.assertRaisesRegex(ValueError, "revision mismatch"):
                bridge.authenticate(Path("keth"), bridge.PINS["keth"])
        with patch.object(bridge, "git", side_effect=[bridge.PINS["keth"]["revision"], " M source.cairo"]):
            with self.assertRaisesRegex(ValueError, "dirty"):
                bridge.authenticate(Path("keth"), bridge.PINS["keth"])

    def test_op_stack_cannot_be_smuggled_into_ethereum_data_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            block = bridge.PINS["keth"]["minimum_block"]
            path = base / "1" / str(block) / "zkpi.json"
            path.parent.mkdir(parents=True)
            for chain_id in (5000, 5003, "1", True):
                path.write_text(json.dumps({"chainConfig": {"chainId": chain_id}}))
                with self.assertRaisesRegex(ValueError, "chain ID 1"):
                    bridge.validate_zkpi(base, block)
            path.write_text(json.dumps({"chainConfig": {"chainId": 1}}))
            self.assertEqual(bridge.validate_zkpi(base, block), path)
            with self.assertRaisesRegex(ValueError, "Prague"):
                bridge.validate_zkpi(base, block - 1)

    def test_receipt_cannot_replace_existing_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "receipt.json"
            bridge.write_new(path, {"value": "original"})
            with self.assertRaises(FileExistsError):
                bridge.write_new(path, {"value": "replacement"})
            self.assertEqual(json.loads(path.read_text()), {"value": "original"})

    def test_failed_verification_does_not_publish_bridge_acceptance(self):
        from scripts import benchmark_cairo
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pie = base / "input.zip"
            pie.write_bytes(b"fixture")
            args = argparse.Namespace(pie=pie, product=pie, oracle=pie, trials=1, out=base / "out")
            with patch.object(benchmark_cairo, "run_benchmark", side_effect=RuntimeError("verifier rejected")):
                with self.assertRaisesRegex(RuntimeError, "verifier rejected"):
                    bridge.prove(args)
            self.assertFalse((args.out / "receipt.json").exists())

    def test_cairo_acceptance_never_implies_op_stack_or_ethereum_statement(self):
        from scripts import benchmark_cairo
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            pie = base / "input.zip"
            pie.write_bytes(b"fixture")
            args = argparse.Namespace(pie=pie, product=pie, oracle=pie, trials=1, out=base / "out")
            with patch.object(benchmark_cairo, "run_benchmark", return_value={"status": "qualified"}):
                result = bridge.prove(args)
            self.assertTrue(result["cairo_proof_verified"])
            self.assertTrue(all(value is False for value in result["claims"].values()))
            self.assertEqual(result["application_program_provenance"], "not-established-by-this-command")


class LegacyInputTests(unittest.TestCase):
    def test_compact_encoder_matches_existing_official_wire_vector(self):
        fixture = ROOT / 'vectors/cairo/official/all_opcodes.prover_input'
        out = io.BytesIO()
        write_compact(out, json.loads(fixture.with_suffix('.prover_input.json').read_text()))
        self.assertEqual(out.getvalue(), fixture.with_suffix('.prover_input.cpi').read_bytes())

    def fixture(self):
        return {'state_transitions': {'initial_state': {'pc': 1, 'ap': 2, 'fp': 2},
                'final_state': {'pc': 1, 'ap': 2, 'fp': 2},
                'casm_states_by_opcode': {k: [] for k in OPCODES}},
                'memory': {'config': {'small_max': (1 << 72) - 1, 'log_small_value_capacity': 24},
                           'address_to_id': [0x3fffffff, 0], 'small_values': [42], 'f252_values': []},
                'inst_cache': [[1, 42]], 'public_memory_addresses': [1],
                'builtin_segments': {k: None for k in BUILTINS},
                'public_segment_context': {'present': [True] * 11}}

    def test_witness_preserved_and_pinned_schema_names_translated(self):
        old = self.fixture()
        memory = old['memory']
        translated, receipt = convert(old, {'data': ['0x2a']})
        self.assertIs(translated['memory'], memory)
        self.assertEqual(translated['pc_count'], 1)
        self.assertNotIn('inst_cache', translated)
        self.assertIn('jnz_opcode_non_taken', translated['state_transitions']['casm_states_by_opcode'])
        self.assertEqual(receipt['compiled_program_cells_checked'], 1)

    def test_different_program_unknown_schema_and_inconsistent_cache_rejected(self):
        with self.assertRaisesRegex(ValueError, 'compiled program not bound'):
            convert(self.fixture(), {'data': ['0x2b']})
        old = self.fixture()
        old['builtin_segments']['ec_op'] = None
        with self.assertRaisesRegex(ValueError, 'unsupported schema'):
            convert(old, {'data': ['0x2a']})
        old = self.fixture()
        old['inst_cache'][0][1] = 43
        with self.assertRaisesRegex(ValueError, 'cache disagrees'):
            convert(old, {'data': ['0x2a']})
        old = self.fixture()
        old['public_memory_addresses'] = []
        with self.assertRaisesRegex(ValueError, 'compiled program not bound'):
            convert(old, {'data': ['0x2a']})


class RealBundleBoundaryTests(unittest.TestCase):
    def test_complete_real_block_checks_trie_coverage_roots_and_consistency(self):
        path = ROOT / 'autoresearch/experiments/evm_keth/evidence/ethereum-22615247-bundle.json'
        complete = json.loads(path.read_text())
        check_manifest(complete)
        self.assertEqual(len(complete['segments']), 45)
        mutations = [
            ('verified trie outputs', lambda m: m['segments'][28]['expected_public_output'].__setitem__(3, 0)),
            ('missing, reordered', lambda m: m['segments'].pop(29)),
            ('consistency proof', lambda m: m['segments'][-1]['expected_public_output'].__setitem__(0, 0)),
            ('unexpected program identity', lambda m: m['segments'][0]['public_statement'].__setitem__('program_root_blake2s', '0' * 64)),
        ]
        for expected_error, mutate in mutations:
            with self.subTest(expected_error=expected_error):
                changed = copy.deepcopy(complete)
                mutate(changed)
                with self.assertRaisesRegex(ValueError, expected_error):
                    check_manifest(changed)

    def test_real_verified_prefix_cannot_be_reported_as_complete_and_links_are_checked(self):
        path = ROOT / 'autoresearch/experiments/evm_keth/evidence/capacity/single-transaction-disk-interruption.json'
        failed = json.loads(path.read_text())
        with self.assertRaisesRegex(ValueError, 'not qualified'):
            check_manifest(failed)
        prefix = copy.deepcopy(failed)
        prefix['segments'] = [s for s in prefix['segments'] if s['status'] == 'qualified']
        prefix['program_roots_blake2s'] = {s['role']: s['public_statement']['program_root_blake2s'] for s in prefix['segments']}
        check_manifest(prefix, prefix=True)
        changed = copy.deepcopy(prefix)
        changed['segments'][1]['expected_public_output'][0] ^= 1
        with self.assertRaisesRegex(ValueError, 'transaction commitment chain'):
            check_manifest(changed, prefix=True)
        changed = copy.deepcopy(prefix)
        changed['segments'][2], changed['segments'][3] = changed['segments'][3], changed['segments'][2]
        with self.assertRaisesRegex(ValueError, 'reordered'):
            check_manifest(changed, prefix=True)


class OpStackJournalTests(unittest.TestCase):
    def test_solidity_abi_field_order_and_uint64_padding(self):
        journal = OpStackRangeJournal(b"\x11" * 32, b"\x22" * 32, b"\x33" * 32,
                                     94355445, b"\x44" * 32)
        encoded = journal.encode()
        # Independently specified five-word BootInfoStruct ABI, not a generated golden file.
        expected = bytes.fromhex("11" * 32 + "22" * 32 + "33" * 32
                                 + "00000000000000000000000000000000000000000000000000000000059fbff5"
                                 + "44" * 32)
        self.assertEqual(encoded, expected)
        self.assertEqual(OpStackRangeJournal.decode(encoded), journal)

    def test_uint64_noncanonical_padding_and_wrong_journal_rejected(self):
        journal = OpStackRangeJournal(bytes(32), bytes(32), bytes(32), 0, bytes(32))
        mutated = bytearray(journal.encode())
        mutated[96] = 1
        with self.assertRaisesRegex(ValueError, "uint64"):
            OpStackRangeJournal.decode(bytes(mutated))
        for data in (bytes(159), bytes(192), bytes(161)):
            with self.assertRaisesRegex(ValueError, "five ABI words"):
                OpStackRangeJournal.decode(data)
        for value in (-1, 1 << 64, True):
            with self.assertRaises(ValueError):
                OpStackRangeJournal(bytes(32), bytes(32), bytes(32), value, bytes(32))
        with self.assertRaisesRegex(ValueError, "32 bytes"):
            OpStackRangeJournal(bytes(31), bytes(32), bytes(32), 0, bytes(32))


class BundleBoundaryTests(unittest.TestCase):
    def manifest(self):
        roots = ['0x' + '11' * 32, '0x' + '22' * 32]
        manifest = {'status': 'qualified-segmented-keth-block-workload',
                    'workload': {'transactions': 2, 'pre_state_root': roots[0], 'post_state_root': roots[1]},
                    'body_chunk_size': 1, 'segments': [],
                    'program_roots_blake2s': {}, 'program_poseidon_hashes': {}}
        joined = []
        for role, indices in expected_specs(2, 1):
            manifest['program_roots_blake2s'][role] = '0x' + '33' * 32
            manifest['program_poseidon_hashes'][role + '_compiled.json'] = 123
            public = [7, 8]
            if role == 'init':
                public = [7, 8, 11, 12]
            elif role == 'body':
                public = [7, 8, 7, 8]
            elif role == 'teardown':
                public = [11, 12, 7, 8, 7, 8]
            if role == 'mpt_diff':
                public = [7, 8, indices[0], *state_root_commitment_limbs(roots[0]),
                          *state_root_commitment_limbs(roots[1]), 7, 8]
            if role == 'aggregator':
                public = joined[:]
            else:
                joined.extend([len(public) + 2, 123, *public])
            manifest['segments'].append({'name': role + ''.join('_' + str(i) for i in indices),
                'role': role, 'indices': indices, 'status': 'qualified', 'public_output_matches': True,
                'expected_public_output': public, 'conversion': {'compiled_program_cells_checked': 20},
                'public_statement': {'program_len': 20, 'output_len': len(public),
                                     'program_root_blake2s': '0x' + '33' * 32}})
        return manifest

    def test_complete_coverage_and_exact_linker_output_required(self):
        manifest = self.manifest()
        check_manifest(manifest)
        for mutation in ('missing', 'reordered', 'duplicate', 'linker', 'identity', 'state_root', 'name', 'field'):
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(manifest)
                if mutation == 'missing':
                    del bad['segments'][1]
                elif mutation == 'reordered':
                    bad['segments'][1:3] = bad['segments'][1:3][::-1]
                elif mutation == 'duplicate':
                    bad['segments'].insert(1, bad['segments'][1])
                elif mutation == 'linker':
                    bad['segments'][-1]['expected_public_output'][3] += 1
                elif mutation == 'identity':
                    bad['segments'][1]['public_statement']['program_root_blake2s'] = '0x' + '44' * 32
                elif mutation == 'state_root':
                    bad['workload']['post_state_root'] = '0x' + '55' * 32
                elif mutation == 'name':
                    bad['segments'][0]['name'] = '../outside'
                else:
                    bad['segments'][0]['expected_public_output'][0] = True
                with self.assertRaises(ValueError):
                    check_manifest(bad)

    def test_invalid_counts_and_state_roots_rejected(self):
        for count, chunk in ((0, 1), (-1, 1), (True, 1), (1, 0), (1, True)):
            with self.assertRaises(ValueError):
                expected_specs(count, chunk)
        for root in ('0x1', '11' * 32, '0x' + '11' * 33):
            with self.assertRaises(ValueError):
                state_root_commitment_limbs(root)

    def test_darwin_limit_is_explicit_and_disabled_limit_does_not_mutate_process(self):
        with patch('resource.setrlimit') as setting:
            with address_space_limit(0) as policy:
                self.assertFalse(policy['enforced'])
            setting.assert_not_called()

    def test_empty_prefix_is_resumable_and_rss_guard_rejects_darwin_before_running(self):
        manifest = self.manifest()
        manifest['status'] = 'failed'
        manifest['segments'] = []
        check_manifest(manifest, prefix=True)
        with self.assertRaisesRegex(ValueError, 'not qualified'):
            check_manifest(manifest)
        from autoresearch.experiments.evm_keth import guarded_benchmark
        with patch('sys.platform', 'darwin'), patch.object(guarded_benchmark, 'run_benchmark') as benchmark:
            with self.assertRaisesRegex(ValueError, 'requires Linux'):
                guarded_benchmark.run(argparse.Namespace())
            benchmark.assert_not_called()
        with patch('sys.platform', 'darwin'), patch('resource.setrlimit') as setting:
            with self.assertRaisesRegex(ValueError, 'only on Linux'):
                with address_space_limit(8):
                    self.fail('unsupported limit was silently accepted')
            setting.assert_not_called()


class RpcObservationTests(unittest.TestCase):
    def responses(self):
        return [{'result': '0xa'}, {'result': {'hash': '0x' + '11' * 32,
                'parentHash': '0x' + '22' * 32, 'number': '0x2', 'gasUsed': '0x5208',
                'transactions': [{'hash': '0x' + '33' * 32, 'type': '0x7e'}]}},
                {'result': {'hash': '0x' + '22' * 32, 'number': '0x1'}}]

    def test_observed_op_deposit_is_not_a_proof(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(collect_rpc, 'rpc', side_effect=self.responses()) as rpc:
            result = collect_rpc.collect('https://example.invalid', 10, 'finalized', Path(tmp) / 'out')
            self.assertEqual(result['status'], 'observed')
            self.assertEqual(result['deposit_transactions'], 1)
            self.assertTrue(result['first_transaction_is_deposit'])
            self.assertFalse(result['op_stack_execution_proved'])
            self.assertEqual(rpc.call_args_list[-1].args[-1], ['0x' + '22' * 32, False])

    def test_failed_receipt_collection_keeps_block_and_failure_evidence(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(collect_rpc, 'rpc', side_effect=self.responses() + [OSError('unavailable')]):
            out = Path(tmp) / 'out'
            with self.assertRaises(OSError):
                collect_rpc.collect('https://example.invalid', 10, 'finalized', out, receipts=True)
            result = json.loads((out / 'observation.json').read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertEqual(result['files']['block.json'], bridge.digest(out / 'block.json'))

    def test_chain_mismatch_is_not_an_observation(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(collect_rpc, 'rpc', return_value={'result': '0x1'}):
            out = Path(tmp) / 'out'
            with self.assertRaisesRegex(ValueError, 'chain ID mismatch'):
                collect_rpc.collect('https://example.invalid', 10, 'finalized', out)
            self.assertEqual(json.loads((out / 'observation.json').read_text())['status'], 'failed')


class FullBlockEvidenceTests(unittest.TestCase):
    evidence = ROOT / 'autoresearch/experiments/evm_keth/evidence/2026-10-29-m5-max'

    def test_complete_cpu_and_metal_evidence_matches_independent_receipts(self):
        manifests = []
        for name in ('ethereum-cpu-w4-chunk1', 'ethereum-metal-w4-chunk1'):
            path = self.evidence / (name + '-manifest.json')
            manifest = json.loads(path.read_text())
            check_manifest(manifest)
            receipt = json.loads((self.evidence / (name + '-reverification.json')).read_text())
            self.assertIs(receipt['verified'], True)
            self.assertEqual(receipt['manifest_sha256'], bridge.digest(path))
            self.assertEqual(receipt['proof_count'], 45)
            self.assertEqual([p['proof_sha256'] for p in receipt['proofs']],
                             [s['trial']['proof_sha256'] for s in manifest['segments']])
            self.assertEqual(manifest['source']['revision'], bridge.PINS['keth']['revision'])
            self.assertTrue(all(value is False for value in manifest['claims'].values()))
            manifests.append(manifest)
        self.assertEqual([s['trial']['proof_sha256'] for s in manifests[0]['segments']],
                         [s['trial']['proof_sha256'] for s in manifests[1]['segments']])

    def test_retained_real_evm_init_proof_matches_complete_bundle(self):
        manifest = json.loads((self.evidence / 'ethereum-cpu-w4-chunk1-manifest.json').read_text())
        proof = self.evidence / 'ethereum-init.proof.json.bz2'
        self.assertEqual(bridge.digest(proof), manifest['segments'][0]['compressed_proof_sha256'])
        import hashlib
        self.assertEqual(hashlib.sha256(bz2.decompress(proof.read_bytes())).hexdigest(),
                         manifest['segments'][0]['trial']['proof_sha256'])

    def test_op_workload_observations_remain_unproved_and_hash_bound(self):
        from autoresearch.experiments.evm_keth.assess_op_stack import assess
        for name, config in (('optimism', 'op'), ('unichain', 'unichain')):
            observation = self.evidence / (name + '-observation')
            receipt = json.loads((observation / 'observation.json').read_text())
            for file, expected in receipt['files'].items():
                self.assertEqual(bridge.digest(observation / file), expected)
            actual = assess(observation, self.evidence / ('reference-' + config + '.toml'))
            expected = json.loads((self.evidence / (name + '-assessment.json')).read_text())
            self.assertEqual(actual, expected)
            self.assertFalse(actual['op_stack_execution_proved'])
            self.assertIn('0x7e', actual['unsupported_keth_transaction_types'])


if __name__ == "__main__":
    unittest.main()
