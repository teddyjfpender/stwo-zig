import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cuda_build_lib import aot_cache


class CubinCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'unit.cu'
        self.source.write_text('kernel source')
        self.plan = {'native_runtime_files': [{'path': 'support.h', 'sha256': '12' * 32}],
                     'source_closure_sha256': '34' * 32, 'tools': {'nvcc': {'sha256': '56' * 32},
                     'host_cxx': {'sha256': '78' * 32}}, 'build_identity_sha256': '90' * 32}
        self.command = ['nvcc', '-cubin', '-O3', str(self.source), '-o', str(self.root / 'out')]

    def key(self, sm=90):
        return aot_cache.identity(self.source, sm, self.plan, self.command)

    def test_unrelated_archive_selection_reuses_identical_compilation(self):
        key = self.key()
        self.plan['build_identity_sha256'] = 'ab' * 32
        self.plan['frontend'] = 'different'
        self.assertEqual(key, self.key())

    def test_source_tool_flags_headers_and_architecture_invalidate(self):
        key = self.key()
        self.assertNotEqual(key, self.key(sm=80))
        self.source.write_text('changed kernel source')
        self.assertNotEqual(key, self.key())
        self.source.write_text('kernel source')
        self.command[2] = '-O0'
        self.assertNotEqual(key, self.key())
        self.command[2] = '-O3'
        self.plan['tools']['nvcc']['sha256'] = 'cd' * 32
        self.assertNotEqual(key, self.key())
        self.plan['tools']['nvcc']['sha256'] = '56' * 32
        (self.root / 'included.cuh').write_text('header source')
        self.assertNotEqual(key, self.key())

    def test_corrupt_or_mismatched_cached_cubin_is_never_used(self):
        cache = self.root / 'cache'
        original = self.root / 'compiled.cubin'
        original.write_bytes(b'compiled device bytes')
        target = self.root / 'restored.cubin'
        key = self.key()
        aot_cache.publish(cache, key, original)
        self.assertTrue(aot_cache.restore(cache, key, target))
        self.assertEqual(original.read_bytes(), target.read_bytes())
        (cache / (key + '.cubin')).write_bytes(b'corrupted')
        self.assertFalse(aot_cache.restore(cache, key, target))
        aot_cache.publish(cache, key, original)
        stamp = cache / (key + '.json')
        r = json.loads(stamp.read_text()); r['identity'] = 'wrong'
        stamp.write_text(json.dumps(r))
        self.assertFalse(aot_cache.restore(cache, key, target))
        self.assertFalse(aot_cache.restore(cache, 'absent', target))



class PartialCompilerProgress(unittest.TestCase):
    def test_completed_cubin_survives_another_compiler_failure(self):
        from scripts.cuda_build_lib.builder import run_parallel
        from scripts.cuda_build_lib.errors import BuildError
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            good, bad = root / 'good.cubin', root / 'bad.cubin'
            commands = [([sys.executable, '-c', "import pathlib,sys; pathlib.Path(sys.argv[-1]).write_bytes(b'complete')", '-o', str(good)], good),
                        ([sys.executable, '-c', 'raise SystemExit(3)', '-o', str(bad)], bad)]
            with self.assertRaises(BuildError):
                run_parallel(commands, 2, on_complete=lambda path: aot_cache.publish(root/'cache', 'finished', path))
            restored = root / 'restored.cubin'
            self.assertTrue(aot_cache.restore(root/'cache', 'finished', restored))
            self.assertEqual(restored.read_bytes(), b'complete')
            self.assertFalse(bad.exists())

if __name__ == '__main__':
    unittest.main()
