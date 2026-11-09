import copy
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rv64 import rv64_validation as validation
from scripts.rv64 import rv64_gate as gate
from scripts.rv64 import rv64_m7_integration_stack as stack
import rv64_m8_bench15 as basket
from scripts.rv64 import rv64_m5_negative_corpus as corpus


class ValidationTests(unittest.TestCase):
    def test_native_comparison_freezes_addons_and_rejects_missing_or_changed_inputs(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            names = (*stack.RUNTIME_ASSETS, 'driver', 'receiver', *validation.NATIVE_LIBRARIES)
            for name in (*names, 'build.zig', 'build.zig.zon'):
                (root / name).write_bytes(name.encode())
            assets = {name: str(root / name) for name in names}
            jobs = {name: assets[name] for name in validation.NATIVE_LIBRARIES}
            runtime = {'assets': {k: assets[k] for k in stack.RUNTIME_ASSETS},
                       'asset_sha256': {k: validation.sha(assets[k]) for k in stack.RUNTIME_ASSETS},
                       'jobs_env': jobs, 'jobs_env_sha256': {k: validation.sha(v) for k, v in jobs.items()}}
            preset_bytes = stack.DEFAULT_PRESET.read_bytes()
            (root / 'preset.json').write_bytes(preset_bytes)
            args = SimpleNamespace(source_root=root, runtime=root / 'runtime.json', preset=root / 'preset.json',
                                   source_commit='host-fixture', driver=root / 'driver', receiver=root / 'receiver',
                                   native_hooks_commit='host-fixture', device_hooks_commit='host-fixture',
                                   block=24628607, allow_block=[], out=root / 'manifest.json')
            for name in stack.RUNTIME_ASSETS:
                setattr(args, name, None)
            args.runtime.write_text(json.dumps(runtime))
            with patch('builtins.print'):
                stack.prepare(args)
            original = args.out.read_bytes()
            manifest = json.loads(original)
            stack.validate_manifest(manifest)
            self.assertTrue(set(jobs) <= manifest['assets'].keys())
            argv, _ = stack.command(manifest, 'fullstack', 1, 'fixture', False)
            self.assertIn('--process-budget-guard', argv)
            self.assertIn('STWO_RV64_M8_GPU_NATIVE=1', argv)
            with self.assertRaises(FileExistsError):
                stack.prepare(args)
            with self.assertRaises(FileExistsError):
                stack.write(args.out, {'overwrite': True}, exclusive=True)
            self.assertEqual(args.out.read_bytes(), original)
            args.preset.write_bytes(preset_bytes + b' ')
            with self.assertRaisesRegex(RuntimeError, 'preset changed'):
                stack.validate_manifest(manifest)
            args.preset.write_bytes(preset_bytes)
            addon = root / validation.NATIVE_LIBRARIES[0]
            addon.write_bytes(b'changed')
            with self.assertRaisesRegex(RuntimeError, 'pinned asset changed'):
                stack.validate_manifest(manifest)
            addon.write_bytes(addon.name.encode())
            args.runtime.write_text(json.dumps(runtime) + ' ')
            with self.assertRaisesRegex(RuntimeError, 'runtime changed'):
                stack.validate_manifest(manifest)
            runtime['jobs_env'] = {}
            args.runtime.write_text(json.dumps(runtime))
            args.out = root / 'missing-addon.json'
            with self.assertRaisesRegex(RuntimeError, 'requires pinned'):
                stack.prepare(args)
            self.assertFalse(args.out.exists())

    def test_native_comparison_refuses_wrong_arms_and_incomplete_order(self):
        preset = json.loads(stack.DEFAULT_PRESET.read_text())
        assets = {k: '/fixture/' + k for k in stack.RUNTIME_ASSETS}
        for arm, key, value in (('baseline', 'STWO_RV64_M8_JOBS', '1'),
                                ('fullstack', 'STWO_RV64_M8_GPU_NATIVE', '0')):
            changed = copy.deepcopy(preset)
            changed['arms'][arm][key] = value
            with self.subTest(arm=arm), self.assertRaises(RuntimeError):
                stack.native_comparison_environment(changed, assets)
        preset['measurement']['order'] = ['baseline', 'fullstack']
        with self.assertRaisesRegex(RuntimeError, 'six-service'):
            stack.native_comparison_environment(preset, assets)

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
            immutable = ('conformance/ci-touchpoints-v1.json', 'conformance/rv64-productionisation-budget.json',
                         'vectors/riscv/fixtures/frozen.json', 'AGENTS.md')
            workflow = ('.github/workflows/ci.yml', '.githooks/pre-push', '.gitignore', 'CONTRIBUTING.md')
            for name in (*immutable, *workflow, 'build.zig', 'build.zig.zon', 'src/probe.zig',
                         'vectors/reports/rv64-productionisation/current.json'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('original')
            frozen = stack.source_hashes(root)
            (root / 'vectors/reports/rv64-productionisation/current.json').write_text('new result')
            self.assertEqual(frozen, stack.source_hashes(root))
            for name in immutable:
                (root / name).write_text('changed')
                current = stack.source_hashes(root)
                self.assertEqual({key for key in frozen if frozen[key] != current[key]}, {name})
                (root / name).write_text('original')
            for name in workflow:
                self.assertIn(name, frozen)

    def test_optional_capture_guard_preserves_scope_and_rejects_malformed_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            proof = Path(tmp)
            (proof / 'bundle.json').write_text('{}')
            report = proof / 'report.json'
            report.write_text(json.dumps({'captured_values_sha256': 'a' * 64}))
            row = {'proof': str(proof), 'leaves': 1}
            with patch('scripts.rv64.rv64_resident_basket.recursive_snapshot', return_value={'tree_sha256': 'tree', 'proof_sha256': {}}):
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
