import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rv64 import rv64_gate as gate
from scripts.rv64 import rv64_validation as validation
from scripts.rv64 import rv64_m5_negative_corpus as corpus
from scripts.rv64 import rv64_m4_resident as resident
from types import SimpleNamespace


class GateTests(unittest.TestCase):
    def test_resident_gpu_count_binds_schedule_caps_and_guard(self):
        for count, lane_workers in ((1, [2, 2, 2, 2]), (2, [2, 2, 2, 2]),
                                    (4, [2, 2, 2, 2]), (1, [0, 2])):
            with self.subTest(gpus=count, lane_workers=lane_workers), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                requests = base / 'inputs/requests'
                requests.mkdir(parents=True)
                (requests / '24628607.json').write_text('{"expected_output":"bound"}')
                resources = {'schedule': dict(resident.P.DEFAULT_NATIVE_SCHEDULE, lane_workers=lane_workers)}
                template = {'profile': 'test', 'device_cap_bytes': 24000000000,
                            'jobs': [{'block': 24628607, 'segments': 7, 'resources': resources}]}
                cap = (40 << 30) if count == 1 else (28 << 30)
                args = SimpleNamespace(gpus=count, repeat=1, env=[], no_default_env=True, device_cap_bytes=cap)
                assets = {name: base / name for name in ('driver', 'library', 'receiver')}
                with patch.object(resident, 'M3', base), \
                        patch.object(resident.P, 'plan_template', return_value=template):
                    plan = resident.plan_for([24628607], args, base, assets, Path.cwd())
                job = plan['jobs'][0]
                self.assertEqual(list(range(count)), job['devices'])
                self.assertEqual(count, job['device_count'])
                schedule = job['resources']['schedule']
                self.assertEqual(8, sum(schedule['lane_workers']))
                self.assertEqual(1 if count == 1 else 4, schedule['lanes'])
                self.assertEqual(0 if count == 1 else count, schedule.get('device_affinity', 0))
                if count == 2:
                    self.assertEqual(resident.P.DEFAULT_NATIVE_SCHEDULE, schedule)
                worker = resident.service_worker(plan)
                environment = resident.B.worker_environment(worker, {})
                self.assertEqual(','.join(map(str, range(count))), environment['CUDA_VISIBLE_DEVICES'])
                self.assertEqual([cap] * count, worker['device_caps_bytes'])
                self.assertEqual(','.join([str(cap)] * count), environment['STWO_RV64_GPU_DEVICE_CAPS'])
                self.assertEqual(24000000000, template['device_cap_bytes'])
                self.assertEqual('7', environment['STWO_RV64_GPU_PLANNED_CPU_WORKERS'])
                self.assertEqual(list(range(count)), resident.PhysicalBudgetGuard.selected_devices(environment))

    def test_resident_gpu_cli_defaults_and_refusals(self):
        for command in ('serve', 'daemon'):
            for values, count in (([], 2), (['--gpus', '1'], 1), (['--gpus', '4'], 4)):
                with patch.object(sys, 'argv', ['resident', command, '24628607', '--tag', 'unit', *values]), \
                        patch.object(resident, command) as dispatch:
                    resident.main()
                    self.assertEqual(count, dispatch.call_args.args[0].gpus)
                    self.assertEqual(28 << 30, dispatch.call_args.args[0].device_cap_bytes)
        with patch.object(sys, 'argv', ['resident', 'daemon', '24628607', '--tag', 'unit', '--device-cap-bytes', str(40 << 30)]), \
                patch.object(resident, 'daemon') as dispatch:
            resident.main()
            self.assertEqual(40 << 30, dispatch.call_args.args[0].device_cap_bytes)
        for invalid in ('0', '-1'):
            with patch.object(sys, 'argv', ['resident', 'daemon', '24628607', '--tag', 'unit', '--device-cap-bytes', invalid]), \
                    self.assertRaises(SystemExit):
                resident.main()
        for invalid in ('3', '0', '-1'):
            with patch.object(sys, 'argv', ['resident', 'daemon', '24628607', '--tag', 'unit', '--gpus', invalid]), \
                    self.assertRaises(SystemExit):
                resident.main()
        self.assertEqual([0, 1], resident.PhysicalBudgetGuard.selected_devices({}))
        for invalid in ('', '0,0', '1', '0,1,2', '0,x'):
            with self.assertRaises(ValueError):
                resident.PhysicalBudgetGuard.selected_devices({'STWO_RV64_GPU_DEVICES': invalid})

    def test_physical_guard_passes_selected_devices_and_rejects_other_ready_set(self):
        # This executable tests the host protocol only; it never allocates CUDA memory.
        for count, wrong in ((1, False), (2, False), (4, False), (1, True)):
            with self.subTest(gpus=count, wrong=wrong), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                binary = base / 'guard-protocol'
                binary.write_text(f'#!{sys.executable}\n' +
                    'import json,sys\n'
                    'devices=list(map(int,sys.argv[sys.argv.index("--devices")+1].split(",")))\n' +
                    ('devices=[0,1]\n' if wrong else '') +
                    'print(json.dumps({"schema":"rv64-physical-budget-guard/v1","ready":True,'
                    '"requested_limit_bytes":28000000000,"fixture_only":True,"argv":sys.argv[1:],'
                    '"devices":[{"device":d,"total_bytes":32000000000,"held_physical_bytes":4000000000,'
                    '"prover_physical_ceiling_bytes":28000000000} for d in devices]}),flush=True)\n'
                    'sys.stdin.readline()\n')
                binary.chmod(0o755)
                environment = resident.B.worker_environment(
                    {'device': ','.join(map(str, range(count))), 'device_caps_bytes': [24000000000] * count,
                     'planned_cpu_workers': 7, 'retained_scopes': 64}, {})
                if wrong:
                    with self.assertRaisesRegex(RuntimeError, 'invalid physical budget guard ready'):
                        resident.PhysicalBudgetGuard(binary, base, environment)
                    continue
                guard = resident.PhysicalBudgetGuard(binary, base, environment)
                try:
                    ready = guard.record['ready']
                    self.assertTrue(ready['fixture_only'])
                    self.assertEqual(['--limit-bytes', '28000000000', '--devices',
                                      ','.join(map(str, range(count)))], ready['argv'])
                    guard.check()
                finally:
                    guard.close()
                self.assertEqual('RELEASED', guard.record['status'])

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
        self.assertEqual(gate.extra_environment(['STWO_RV64_M8_GPU_NATIVE=1', 'STWO_X=a=b']),
                         {'STWO_RV64_M8_GPU_NATIVE': '1', 'STWO_X': 'a=b'})
        self.assertEqual(gate.extra_environment([]), {})
        for bad in (['PATH=/tmp'], ['STWO_RV64_M8_GPU_NATIVE'], ['stwo_x=1'], ['STWO_A=1', 'STWO_A=2'], ['STWO_A-B=1']):
            with self.assertRaises(ValueError): gate.extra_environment(bad)

    def test_jobs_environment_only_on_job_paths_and_pinned(self):
        with tempfile.TemporaryDirectory() as tmp:
            libraries = {}
            for name in validation.NATIVE_LIBRARIES:
                path = Path(tmp) / name
                path.write_bytes(name.encode())
                libraries[name] = str(path)
            runtime = {'jobs_env': {**libraries, 'STWO_RV64_M8_JOBS_PINNED_BYTES': '1'},
                       'jobs_env_sha256': {k: gate.stack.sha(v) for k, v in libraries.items()}}
            primary = 'STWO_RV64_M8_GPU_NATIVE'
            self.assertEqual(gate.jobs_environment(runtime, {}), {})
            self.assertEqual(gate.jobs_environment(runtime, {primary: '0'}), {})
            self.assertEqual(gate.jobs_environment(runtime, {primary: '1'}), runtime['jobs_env'])
            # The obsolete acknowledgement cannot select native jobs or inject assets.
            self.assertEqual(gate.jobs_environment(runtime, {'STWO_RV64_M8_JOBS': '1'}), {})
            got = gate.jobs_environment(runtime, {primary: '1', 'STWO_RV64_M8_JOBS_PINNED_BYTES': '2'})
            self.assertEqual(got, libraries)
            with self.assertRaisesRegex(RuntimeError, 'requires pinned'):
                gate.jobs_environment({}, {primary: '1'})
            for missing in libraries:
                incomplete = {'jobs_env': {k: v for k, v in libraries.items() if k != missing},
                              'jobs_env_sha256': runtime['jobs_env_sha256']}
                with self.subTest(missing=missing), self.assertRaisesRegex(RuntimeError, 'requires pinned'):
                    gate.jobs_environment(incomplete, {primary: '1'})
            other = Path(tmp) / 'unrecorded.so'
            other.write_bytes(b'unrecorded')
            for selected in ('0', '1'):
                with self.assertRaisesRegex(RuntimeError, 'not a pinned asset'):
                    gate.jobs_environment(runtime, {primary: selected,
                                                    'STWO_RV64_M8_JOBS_LIBRARY': str(other)})
            Path(libraries['STWO_RV64_M8_JOBS_LIBRARY']).write_bytes(b'changed')
            with self.assertRaises(RuntimeError): gate.jobs_environment(runtime, {primary: '1'})
            unpinned = {'jobs_env': libraries}
            with self.assertRaises(RuntimeError): gate.jobs_environment(unpinned, {primary: '1'})

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
