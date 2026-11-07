import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_gate as gate
import rv64_m5_negative_corpus as corpus
import rv64_m4_resident as resident
from types import SimpleNamespace


class GateTests(unittest.TestCase):
    def test_parity_refuses_missing_extra_and_changed_proofs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proof = root / 'recursion-om31/root.proof'
            proof.parent.mkdir()
            proof.write_bytes(b'accepted')
            golden = {'recursion-om31/root.proof': {'sha256': gate.stack.sha(proof), 'bytes': 8}}
            self.assertTrue(gate.frozen_parity(root, golden)['byte_identical'])
            # Diagnostics can change without changing the proof.
            (root / 'report.json').write_text('{}')
            (root / 'physical-0000.stages.json').write_text('{"seconds": 1}')
            (root / 'candidate-fixed-setup.json').write_text('{"source_validations": 11}')
            self.assertTrue(gate.frozen_parity(root, golden)['byte_identical'])
            extra = root / 'cpu-9.bin'
            extra.write_bytes(b'extra')
            with self.assertRaises(RuntimeError): gate.frozen_parity(root, golden)
            extra.unlink()
            proof.write_bytes(b'mutated!')
            with self.assertRaises(RuntimeError): gate.frozen_parity(root, golden)
            proof.unlink()
            with self.assertRaises(RuntimeError): gate.frozen_parity(root, golden)

    def test_extra_environment_accepts_only_unique_stwo_keys(self):
        self.assertEqual(gate.extra_environment(['STWO_RV64_M8_JOBS=1', 'STWO_X=a=b']),
                         {'STWO_RV64_M8_JOBS': '1', 'STWO_X': 'a=b'})
        self.assertEqual(gate.extra_environment([]), {})
        for bad in (['PATH=/tmp'], ['STWO_RV64_M8_JOBS'], ['stwo_x=1'], ['STWO_A=1', 'STWO_A=2'], ['STWO_A-B=1']):
            with self.assertRaises(ValueError): gate.extra_environment(bad)

    def test_corpus_cannot_pass_by_running_nothing_or_skipping(self):
        good = {'results': [{'id': name, 'passed': True} for name in gate.CASES]}
        gate.check_corpus(good)
        for bad in ({'results': []}, {'results': good['results'][:-1]},
                    dict(good, unsupported=[{'id': gate.CASES[0]}]),
                    dict(good, crashes=['C00-control']),
                    {'results': good['results'] + good['results'][:1]}):
            with self.assertRaises(RuntimeError): gate.check_corpus(bad)
        known = {c['id'] for c in corpus.CASES if 'mutate' in c}
        self.assertLessEqual(set(gate.CASES), known)

    def test_resident_corpus_selects_cold_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proof = root / 'actual-proof'
            proof.mkdir()
            (proof / 'bundle.json').write_text('{}')
            (root / 'plan.json').write_text(json.dumps({'jobs': [{'block': 26235156}]}))
            (root / 'receipt.json').write_text(json.dumps({'requests': [
                {'block': 26235156, 'trial': 0, 'proof': str(proof)},
                {'block': 26235156, 'trial': 1, 'proof': 'not-cold'}]}))
            self.assertEqual(corpus.proof_dir(root)[2], proof)


    def test_default_runtime_is_the_source_built_image(self):
        self.assertEqual(gate.RUNTIME, gate.stack.DEFAULT_RUNTIME)
        default = json.loads(gate.stack.DEFAULT_RUNTIME.read_text())
        frozen = json.loads(gate.stack.FROZEN_P0_RUNTIME.read_text())
        self.assertEqual(default['schema'], frozen['schema'])
        self.assertEqual(set(default['assets']), set(frozen['assets']))
        self.assertTrue(default['asset_sha256']['library'].startswith('25d0e62f'))
        self.assertTrue(frozen['asset_sha256']['library'].startswith('a25cc3b2'))

    def test_runner_owner_rule_needs_explicit_block_opt_in(self):
        stack = gate.stack
        self.assertFalse(stack.check_block(24628607, []))
        self.assertFalse(stack.check_block(26235156, [26235159]))
        with self.assertRaises(RuntimeError): stack.check_block(26235159, [])
        with self.assertRaises(RuntimeError): stack.check_block(26235159, [24697070])
        self.assertTrue(stack.check_block(26235159, [26235159]))
        preset = json.loads(stack.DEFAULT_PRESET.read_text())
        assets = {k: '/x/' + k for k in ('driver', 'receiver', 'library', 'sparse', 'observer', 'process_budget_guard')}
        manifest = {'source_root': '/s', 'assets': assets, 'preset': preset, 'block': 26235159, 'allowed_block': True}
        argv, _ = stack.command(manifest, 'baseline', 0, 'r', False)
        self.assertEqual(argv[argv.index('--allow-block') + 1], '26235159')
        self.assertIn('--coalesce-truth-families', argv)
        argv, _ = stack.command(dict(manifest, block=24628607, allowed_block=False,
                                     preset=dict(preset, coalesce_truth_families=False)), 'baseline', 0, 'r', False)
        self.assertNotIn('--allow-block', argv)
        self.assertNotIn('--coalesce-truth-families', argv)

    def test_daemon_owner_rule_needs_explicit_block_opt_in(self):
        def args(blocks, repeat=2, allow=(), probe=False):
            return SimpleNamespace(blocks=list(blocks), repeat=repeat, allow_block=list(allow), allow_scale_probe=probe)
        resident.require_measurement_blocks(args([24628607]), {})
        with self.assertRaises(SystemExit): resident.require_measurement_blocks(args([26235159]), {})
        resident.require_measurement_blocks(args([26235159], allow=[26235159]), {})
        resident.require_measurement_blocks(args([26235159]), {resident.ALLOW_BLOCKS_ENV: '26235159,24697070'})
        for bad in (args([26235159], repeat=3, allow=[26235159]), args([26235159, 24628611], allow=[26235159, 24628611]),
                    args([26235159], allow=[24697070]), args([26235159, 24628607], allow=[26235159])):
            with self.assertRaises(SystemExit): resident.require_measurement_blocks(bad, {})
        resident.require_measurement_blocks(args([24697070], repeat=1, probe=True), {})

if __name__ == '__main__':
    unittest.main()
