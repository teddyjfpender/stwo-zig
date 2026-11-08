import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_validation as validation
import rv64_gate as gate
import rv64_m7_integration_stack as stack
import rv64_m8_bench15 as basket
import rv64_m5_negative_corpus as corpus


class ValidationTests(unittest.TestCase):
    @staticmethod
    def corpus_receipt():
        rows = [{'id': name, 'passed': True, 'status': 'ran', 'expect': 'reject',
                 'verdict': 'reject', 'exit_code': 1, 'reject_class': 'semantic',
                 'first_error': 'error: InvalidProof'} for name in validation.CASES]
        rows[0].update(expect='accept', verdict='accept', exit_code=0, reject_class=None,
                       first_error=None, same_statement_as_control=True)
        return {'results': rows, 'receiver_sha256': 'a' * 64,
                'receiver_env': {'CUDA_VISIBLE_DEVICES': '', 'STWO_RV64_GPU_PCS_HELPER': '/bin/false',
                                 'STWO_ZIG_RV64_SETUP_CACHE': 'unset', 'STWO_RV64_FOLD_CLASS_CACHE': '0',
                                 'STWO_RV64_OUTER_PLAN_CLASS_STORE': 'unset'}}

    def test_gate_comparison_and_basket_share_the_authority(self):
        self.assertIs(gate.frozen_parity, validation.frozen_parity)
        self.assertIs(gate.check_corpus, validation.check_corpus)
        self.assertIs(basket.frozen_parity, validation.frozen_parity)
        self.assertIs(stack.sha, validation.sha)
        self.assertIs(stack.fingerprints, validation.fingerprints)
        self.assertIs(corpus.reject_class, validation.reject_class)

    def test_source_freeze_covers_validation_policy_and_workflow_inputs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in ('build.zig', 'build.zig.zon', '.gitignore', 'CONTRIBUTING.md',
                         'conformance/ci-touchpoints-v1.json', '.github/workflows/ci.yml',
                         '.githooks/pre-push', 'src/probe.zig'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original')
            frozen = stack.source_hashes(root)
            policy = root / 'conformance/ci-touchpoints-v1.json'
            policy.write_text('changed')
            current = stack.source_hashes(root)
            self.assertEqual({name for name in frozen if frozen[name] != current[name]},
                             {'conformance/ci-touchpoints-v1.json'})
            self.assertIn('.github/workflows/ci.yml', frozen)
            self.assertIn('.githooks/pre-push', frozen)
            self.assertIn('.gitignore', frozen)
            self.assertIn('CONTRIBUTING.md', frozen)

    def test_optional_capture_guard_preserves_scope_and_rejects_malformed_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            proof = Path(tmp)
            (proof / 'bundle.json').write_text('{}')
            report = proof / 'report.json'
            report.write_text(json.dumps({'captured_values_sha256': 'a' * 64}))
            row = {'proof': str(proof), 'leaves': 1}
            with patch('rv64_resident_basket.recursive_snapshot', return_value={'tree_sha256': 'tree', 'proof_sha256': {}}):
                self.assertNotIn('captured_values_sha256', validation.fingerprints(row))
                self.assertEqual(validation.fingerprints(row, True)['captured_values_sha256'], 'a' * 64)
                report.write_text(json.dumps({'captured_values_sha256': 'z' * 64}))
                with self.assertRaisesRegex(RuntimeError, 'SHA256 guard'):
                    validation.fingerprints(row, True)

    def test_assets_refuse_missing_pins_and_file_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'driver'
            binary.write_bytes(b'pinned')
            assets = {'driver': binary}
            pins = {'driver': validation.sha(binary)}
            validation.validate_assets(assets, pins)
            for bad in ({}, {'driver': '*'}, {'driver': pins['driver'].upper()}):
                with self.assertRaises(RuntimeError):
                    validation.validate_assets(assets, bad)
            binary.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                validation.validate_assets(assets, pins)

    def test_library_overrides_and_preloads_must_resolve_to_pinned_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            library = Path(tmp) / 'pinned.so'
            other = Path(tmp) / 'other.so'
            library.write_bytes(b'pinned')
            other.write_bytes(b'other')
            assets = {'library': library}
            pins = {'library': validation.sha(library)}
            validation.validate_library_environment({'STWO_X_LIBRARY': str(library), 'LD_PRELOAD': str(library)}, assets, pins)
            for environment in ({'STWO_X_LIBRARY': str(other)}, {'LD_PRELOAD': f'{library}:{other}'}):
                with self.assertRaisesRegex(RuntimeError, 'not a pinned asset'):
                    validation.validate_library_environment(environment, assets, pins)
            library.write_bytes(b'drift')
            with self.assertRaisesRegex(RuntimeError, 'changed'):
                validation.validate_library_environment({'STWO_X_LIBRARY': str(library)}, assets, pins)

    def test_resource_rejections_are_never_semantic_coverage(self):
        receipt = self.corpus_receipt()
        self.assertEqual(validation.check_corpus(receipt, 'a' * 64)['status'], 'PASS')
        receipt['results'][7]['reject_class'] = 'resource'
        receipt['results'][7]['first_error'] = 'error: FileTooBig'
        result = validation.check_corpus(receipt, 'a' * 64)
        self.assertEqual(result['status'], 'PASS_WITH_LIMITATIONS')
        self.assertFalse(result['semantic_rejection_complete'])
        self.assertEqual(result['nonsemantic_rejects'], {'V04-cross-block-root': 'resource'})
        receipt['pending'] = [{'id': 'future-unselected-case'}]
        self.assertEqual(validation.check_corpus(receipt, 'a' * 64)['out_of_scope_pending_cases'], 1)
        receipt['pending'] = [{'id': 'V04-cross-block-root'}]
        with self.assertRaises(RuntimeError):
            validation.check_corpus(receipt, 'a' * 64)

    def test_corpus_refuses_omitted_duplicate_or_unrun_cases(self):
        good = self.corpus_receipt()
        for changes in ({'results': []}, {'results': good['results'][:-1]},
                        {'results': good['results'] + good['results'][:1]},
                        {'unsupported': [{'id': validation.CASES[0]}]}, {'crashes': ['C00-control']}):
            with self.subTest(changes=changes):
                with self.assertRaises(RuntimeError):
                    validation.check_corpus(dict(good, **changes), 'a' * 64)

    def test_corpus_rejects_incomplete_or_contradictory_evidence_even_with_passed_flag(self):
        mutations = [('reject_class', None), ('reject_class', 'resource'),
                     ('first_error', None), ('first_error', 'panic: invalid input'),
                     ('status', 'timeout'), ('verdict', 'accept'), ('expect', 'accept'),
                     ('exit_code', 0), ('exit_code', -9), ('exit_code', True), ('passed', 1)]
        for key, value in mutations:
            receipt = self.corpus_receipt()
            receipt['results'][1][key] = value
            with self.subTest(key=key, value=value):
                with self.assertRaises(RuntimeError):
                    validation.check_corpus(receipt, 'a' * 64)
        for changes in ({'receiver_sha256': 'b' * 64}, {'receiver_env': {}},
                        {'nonsemantic_rejects': {'S08-coherent-permute-native': 'resource'}}):
            with self.assertRaises(RuntimeError):
                validation.check_corpus(dict(self.corpus_receipt(), **changes), 'a' * 64)
        receipt = self.corpus_receipt()
        receipt['results'][0]['same_statement_as_control'] = False
        with self.assertRaises(RuntimeError):
            validation.check_corpus(receipt, 'a' * 64)

    def test_corpus_isolation_drops_producer_cache_environment(self):
        with patch.dict('os.environ', {'STWO_RV64_OUTER_PLAN_CLASS_STORE': 'stale',
                                      'STWO_ZIG_RV64_SETUP_CACHE': 'stale'}):
            environment = corpus.environment()
        self.assertNotIn('STWO_RV64_OUTER_PLAN_CLASS_STORE', environment)
        self.assertNotIn('STWO_ZIG_RV64_SETUP_CACHE', environment)
        self.assertEqual(validation.reject_class(None), 'unclassified')

    @staticmethod
    def receiver(proof='proof-0'):
        return {'accepted': True, 'status': 'accepted', 'proof': proof,
                'receiver_sha256': 'a' * 64, 'process': {'exit_code': 0},
                'store_present_during_receive': False,
                'isolation': {'CUDA_VISIBLE_DEVICES': '', 'STWO_RV64_GPU_PCS_HELPER': '/bin/false',
                              'STWO_RV64_FOLD_CLASS_CACHE': '0', 'STWO_ZIG_RV64_SETUP_CACHE': 'unset',
                              'STWO_RV64_OUTER_PLAN_CLASS_STORE': 'unset'}}

    def test_receiver_requires_complete_isolated_acceptance_of_exact_proofs(self):
        rows = [self.receiver(), self.receiver('proof-1')]
        result = validation.validate_receivers(rows, ['proof-0', 'proof-1'], 'a' * 64)
        self.assertEqual(result['proofs'], 2)
        mutations = [('accepted', 1), ('status', 'running'), ('receiver_sha256', 'b' * 64),
                     ('proof', 'some-other-proof'), ('store_present_during_receive', True),
                     ('process', {'exit_code': False}), ('isolation', {}), ('error', 'rejected')]
        for key, value in mutations:
            with self.subTest(key=key):
                changed = copy.deepcopy(rows)
                changed[0][key] = value
                with self.assertRaises(RuntimeError):
                    validation.validate_receivers(changed, ['proof-0', 'proof-1'], 'a' * 64)
        with self.assertRaises(RuntimeError):
            validation.validate_receivers([rows[0], rows[0]], ['proof-0', 'proof-1'], 'a' * 64)
        with self.assertRaises(RuntimeError):
            validation.validate_receivers([], [], 'a' * 64)


if __name__ == '__main__':
    unittest.main()
