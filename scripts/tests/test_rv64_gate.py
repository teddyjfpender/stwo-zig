import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rv64 import rv64_gate as gate
from scripts.rv64 import rv64_m5_negative_corpus as corpus
from scripts.rv64 import rv64_m4_resident as resident
from types import SimpleNamespace


class GateTests(unittest.TestCase):
    def test_equal_output_basenames_keep_independent_service_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / 'batch-1' / 'default'
            second = Path(tmp) / 'batch-2' / 'default'
            self.assertNotEqual(gate.service_label(first), gate.service_label(second))
            self.assertEqual(gate.service_label(first), gate.service_label(first.resolve()))

    def test_nsys_storage_keeps_run_paths_and_refuses_existing_trace_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            run = base / 'runs' / 'stream-a' / 'run-1'
            run.mkdir(parents=True)
            link = resident.nsys_directory(run, base / 'raw')
            target = (base / 'raw' / 'stream-a' / 'run-1').resolve()
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(), target)
            (link / 'timeline.nsys-rep').write_bytes(b'preserved')
            with self.assertRaises(FileExistsError):
                resident.nsys_directory(run, base / 'other')
            self.assertEqual((target / 'timeline.nsys-rep').read_bytes(), b'preserved')
            other = base / 'runs' / 'stream-b' / 'run-1'
            other.mkdir(parents=True)
            self.assertNotEqual(resident.nsys_directory(other, base / 'raw').resolve(), target)
            regular = base / 'regular'
            regular.mkdir()
            self.assertFalse(resident.nsys_directory(regular).is_symlink())

    def test_service_rejection_preserves_the_producer_error(self):
        for service in ({'ok': False, 'error': 'GpuNativeClassNotWarmed'},
                        {'accepted': False, 'error': 'GpuNativeClassNotWarmed', 'request_wall_ns': 1}):
            with self.assertRaisesRegex(RuntimeError, '0000.*GpuNativeClassNotWarmed'):
                resident.service_wall_ns('0000', service)
        for wall in (None, 0, -1, True, 1.5):
            with self.assertRaisesRegex(RuntimeError, 'no valid request_wall_ns'):
                resident.service_wall_ns('0000', {'request_wall_ns': wall})
        self.assertEqual(resident.service_wall_ns('0000', {'ok': True, 'request_wall_ns': 12}), 12)
        self.assertEqual(resident.service_wall_ns('0000', {'accepted': True, 'request_wall_ns': 15}), 15)

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

    def test_jobs_environment_only_on_job_paths_and_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            lib = Path(tmp) / 'libjobs.so'
            lib.write_bytes(b'addon')
            runtime = {'jobs_env': {'STWO_RV64_M8_JOBS_LIBRARY': str(lib), 'STWO_RV64_M8_JOBS_PINNED_BYTES': '1'},
                       'jobs_env_sha256': {'STWO_RV64_M8_JOBS_LIBRARY': gate.stack.sha(lib)}}
            self.assertEqual(gate.jobs_environment(runtime, {}), {})
            self.assertEqual(gate.jobs_environment(runtime, {'STWO_RV64_M8_JOBS': '0'}), {})
            self.assertEqual(gate.jobs_environment(runtime, {'STWO_RV64_M8_JOBS': '1'}), runtime['jobs_env'])
            # An explicit --env wins over the shipped value.
            got = gate.jobs_environment(runtime, {'STWO_RV64_M8_JOBS': '1', 'STWO_RV64_M8_JOBS_PINNED_BYTES': '2'})
            self.assertEqual(got, {'STWO_RV64_M8_JOBS_LIBRARY': str(lib)})
            self.assertEqual(gate.jobs_environment({}, {'STWO_RV64_M8_JOBS': '1'}), {})
            other = Path(tmp) / 'unrecorded.so'
            other.write_bytes(b'unrecorded')
            for selected in ('0', '1'):
                with self.assertRaisesRegex(RuntimeError, 'not a pinned asset'):
                    gate.jobs_environment(runtime, {'STWO_RV64_M8_JOBS': selected,
                                                    'STWO_RV64_M8_JOBS_LIBRARY': str(other)})
            lib.write_bytes(b'changed')
            with self.assertRaises(RuntimeError): gate.jobs_environment(runtime, {'STWO_RV64_M8_JOBS': '1'})
            unpinned = {'jobs_env': {'STWO_RV64_M8_JOBS_LIBRARY': str(lib)}}
            with self.assertRaises(RuntimeError): gate.jobs_environment(unpinned, {'STWO_RV64_M8_JOBS': '1'})

    def test_gate_corpus_cases_have_executable_mutations(self):
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
        resident.require_measurement_blocks(args([24628607]))
        with self.assertRaises(SystemExit): resident.require_measurement_blocks(args([26235159]))
        resident.require_measurement_blocks(args([26235159], allow=[26235159]))
        with patch.dict(resident.os.environ, {"STWO_RV64_HARNESS_ALLOW_BLOCKS": "26235159,24697070"}):
            with self.assertRaises(SystemExit):
                resident.require_measurement_blocks(args([26235159]))
        for bad in (args([26235159], repeat=3, allow=[26235159]), args([26235159, 24628611], allow=[26235159, 24628611]),
                    args([26235159], allow=[24697070]), args([26235159, 24628607], allow=[26235159])):
            with self.assertRaises(SystemExit): resident.require_measurement_blocks(bad)
        resident.require_measurement_blocks(args([24697070], repeat=1, probe=True))

if __name__ == '__main__':
    unittest.main()
