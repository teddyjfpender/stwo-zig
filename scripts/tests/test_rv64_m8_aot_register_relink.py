"""Immutable scheduled-image replacement; host orchestration, no CUDA execution.

The independent physical A/B oracle remains bench_truth.cu/bench_projection.cu:
link the original artifact and the renamed scheduled test artifact explicitly.
Runtime environment values do not select a different production catalogue.
For the physical harness, compile the scheduled test object with
-D<original-symbol>=<original-symbol>_scheduled_test, then pass those two
symbols to the existing bench_case.py; the production and baseline artifacts
are never rewritten. Physical CUDA compilation/replay is a separate gate.
"""
from pathlib import Path
import json
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.rv64 import rv64_m8_aot_register_relink as R
from scripts.tests.test_rv64_cuda_aot_register_schedule import synthetic


class ImmutableImage(unittest.TestCase):
    def test_scheduled_shard_is_exact_existing_replace_lowering(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, _ = synthetic(4)
            symbol = 'rv64_truth_domain_0_shard_47'
            source = source.replace('t_shard_0', symbol)
            (root / 'case-0-domain.cu').write_text(source)
            parts = root / 'role-0'
            parts.mkdir()
            (parts / (symbol + '.cu')).write_text(source)
            entry = {'kind': 'truth-shard', 'symbol': symbol, 'launch_bounds': '128,2'}
            actual, report = R.lower(entry, root, root)
            expected, _ = R.Schedule.lower_module(source, source, '128,2')
            self.assertEqual(actual, expected)
            self.assertEqual(report['symbol'], symbol)
            self.assertNotIn('getenv(', actual)
            self.assertNotIn(symbol + '_t5(', actual)

    def test_physical_bench_header_preserves_explicit_artifact_symbols_and_geometry(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, _ = synthetic(4)
            scheduled, _ = R.Schedule.lower_module(source, source, '128,2')
            headers = []
            emitter = Path(__file__).resolve().parents[2] / 'tests/cuda/rv64/aot_register_schedule/bench_case.py'
            for name, text in (('original', source), ('scheduled', scheduled)):
                path = root / (name + '.cu')
                path.write_text(text)
                result = subprocess.run([sys.executable, str(emitter), str(path),
                                         't_shard_0', 't_shard_0_scheduled_test', 'immutable'],
                                        check=True, capture_output=True, text=True)
                self.assertIn('#define BENCH_BEFORE t_shard_0\n', result.stdout)
                self.assertIn('#define BENCH_AFTER t_shard_0_scheduled_test\n', result.stdout)
                self.assertEqual(path.read_text(), text)
                headers.append(result.stdout)
            self.assertEqual(headers[0], headers[1])

    def test_object_authority_requires_one_definition_and_retains_rdc_slices(self):
        link = ['unchanged.o', 'rv64_aot_0123456789abcdef-entry.o',
                'rv64_aot_0123456789abcdef-part-0.o']
        index = {'kernel': [link[1]]}
        self.assertEqual(R.admitted_objects(link, index, 'kernel'), link[1:])
        for values in ([], [link[0], link[1]]):
            with self.assertRaisesRegex(ValueError, 'expected one admitted object'):
                R.admitted_objects(link, {'kernel': values}, 'kernel')

    def test_real_relink_orchestration_preserves_baseline_and_immutable_catalogue(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            admitted = root / 'admitted.o'
            admitted.write_bytes(b'immutable baseline object')
            untouched = root / 'untouched.o'
            untouched.write_bytes(b'other admitted kernels')
            kernel = root / 'kernel.cu'
            kernel.write_text('extern "C" __global__ void kernel() {}\n')
            base = root / 'base.json'
            link = ['nvcc', '-shared', str(admitted), str(untouched), '-o', 'baseline.so']
            base.write_text(json.dumps({'link_command': link, 'library_sha256': 'baseline-pin'}))
            runtime = root / 'runtime.json'
            runtime.write_text(json.dumps({'assets': {'library': 'baseline.so'},
                                          'asset_sha256': {'library': 'baseline-pin'}}))
            plan = root / 'plan.json'
            plan.write_text(json.dumps([{'kind': 'bounds-only', 'symbol': 'kernel',
                                         'source': str(kernel), 'launch_bounds': '128'}]))
            baseline = {p: p.read_bytes() for p in (admitted, untouched, kernel, base, runtime, plan)}
            sources = []
            for option in ([], ['--replace']):
                out = root / ('explicit' if option else 'default')
                commands = []
                def run(command, **kwargs):
                    commands.append(command)
                    if '-o' in command:
                        Path(command[command.index('-o') + 1]).write_bytes(b'host fixture output')
                    return SimpleNamespace(returncode=0, stdout='', stderr='')
                argv = ['relink', '--source-root', str(root), '--base-link', str(base),
                        '--base-runtime', str(runtime), '--plan', str(plan), '--out', str(out), *option]
                image = SimpleNamespace(stwo_rv64_composition_role_on=1,
                                        stwo_rv64_truth_composition_role_on=1, kernel=1)
                with patch.object(sys, 'argv', argv), patch.object(R, 'symbol_index', return_value={'kernel': [str(admitted)]}), \
                     patch.object(R.subprocess, 'run', side_effect=run), patch.object(R.ctypes, 'CDLL', return_value=image), patch('builtins.print'):
                    R.main()
                report = json.loads((out / 'build.json').read_text())
                self.assertIsNone(report['dispatcher'])
                self.assertEqual(report['removed_objects'], [str(admitted)])
                self.assertEqual(report['modules'][0]['symbol'], 'kernel')
                self.assertEqual(report['link_command'][2:4], [str(out.resolve() / 'obj/kernel.o'), str(untouched)])
                self.assertNotIn(str(admitted), report['link_command'])
                self.assertFalse(any('t5_composition_dispatch' in str(c) for c in commands))
                sources.append((out / 'src/kernel.cu').read_bytes())
                for path, data in baseline.items():
                    self.assertEqual(path.read_bytes(), data, str(path))
            self.assertEqual(sources[0], sources[1])


if __name__ == '__main__':
    unittest.main()
