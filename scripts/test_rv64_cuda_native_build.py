#!/usr/bin/env python3
"""Fast compiler-custody checks; no CUDA installation or rented GPU needed."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from rv64_cuda_native_library_build import compile_native, run_checked


class NativeBuildTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / 'input.cu'
        self.source.write_text('good source')
        self.header = self.root / 'header.cuh'
        self.header.write_text('header version1')
        self.obj = self.root / 'kernel.o'
        self.log = self.root / 'compile.log'
        self.compiler = self.root / 'fake-nvcc'
        self.compiler.write_text('#!' + sys.executable + '\n' + '''
import pathlib, sys
args = sys.argv[1:]
source = pathlib.Path(args[args.index('-c') + 1])
output = pathlib.Path(args[args.index('-o') + 1])
dep = pathlib.Path(args[args.index('-MF') + 1])
header = source.parent / 'header.cuh'
output.write_bytes(b'partial')
if source.read_text().startswith('FAIL'):
    raise SystemExit(7)
output.write_bytes(source.read_bytes() + header.read_bytes())
dep.write_text(str(output) + ': ' + str(source) + ' ' + str(header) + '\\n')
''')
        self.compiler.chmod(0o755)

    def compile(self):
        return compile_native(str(self.compiler), 'test-nvcc-v1', [], self.source,
                              self.obj, self.log, 5)

    def test_cache_binds_header_and_object_bytes(self):
        self.assertFalse(self.compile())
        self.assertTrue(self.compile())
        self.header.write_text('header version2')
        self.assertFalse(self.compile())
        self.assertIn(b'version2', self.obj.read_bytes())
        self.obj.write_bytes(b'tampered')
        self.assertFalse(self.compile())
        self.assertNotEqual(b'tampered', self.obj.read_bytes())
        self.assertTrue(self.compile())

    def test_failed_partial_compile_preserves_previous_cache(self):
        self.compile()
        files = [self.obj, self.obj.with_suffix('.d'), self.obj.with_suffix('.json')]
        before = [p.read_bytes() for p in files]
        self.source.write_text('FAIL after partial output')
        with self.assertRaises(subprocess.CalledProcessError):
            self.compile()
        self.assertEqual(before, [p.read_bytes() for p in files])
        self.assertFalse(list(self.root.glob('.*pending*')))
        self.assertFalse(list(self.root.glob('.*.d')))
        self.assertFalse(list(self.root.glob('.*.json')))

    def test_malformed_stamp_is_not_a_hit(self):
        self.compile()
        self.obj.with_suffix('.json').write_text('{partial')
        self.assertFalse(self.compile())
        self.assertIn('dependencies', json.loads(self.obj.with_suffix('.json').read_text()))

    def test_deadline_stops_optimizer_descendants(self):
        heartbeat = self.root / 'heartbeat'
        child = "import pathlib,sys,time; f=pathlib.Path(sys.argv[1]).open('ab',buffering=0)\nwhile True: f.write(b'x'); time.sleep(.01)"
        parent = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",sys.argv[1],sys.argv[2]]); time.sleep(60)'
        with self.log.open('w') as log:
            with self.assertRaises(subprocess.TimeoutExpired):
                run_checked([sys.executable, '-c', parent, child, str(heartbeat)], log, .5)
        self.assertTrue(heartbeat.is_file())
        size = heartbeat.stat().st_size
        time.sleep(.1)
        self.assertEqual(size, heartbeat.stat().st_size)


if __name__ == '__main__':
    unittest.main()
