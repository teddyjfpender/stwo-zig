"""Jovian precompile input limits against unmodified pinned op-geth."""
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from autoresearch.tests.test_keth_op_p256 import ORACLE, ROOT, compile_owned, implement_hints, RustProgram, run_rust_vm


@unittest.skipUnless(ORACLE.is_file(), 'build the pinned OP precompile oracle first')
class JovianPrecompileLimitsTests(unittest.TestCase):
    def test_exact_limit_and_first_oversized_input(self):
        source = ROOT / 'autoresearch/experiments/evm_keth/cairo/op_stack/precompile_admission.cairo'
        program = compile_owned(source, proof_mode=False)
        program.hints = implement_hints(program)
        rust = RustProgram.from_bytes(json.dumps(program.Schema().dump(program)).encode(), 'exceeds_limit')
        request = SimpleNamespace(config=SimpleNamespace(getoption=lambda name: {
            'layout': 'all_cairo_instance', 'no_coverage': True}.get(name, False)),
            node=SimpleNamespace(path=Path('/tmp/test_keth_op_precompile_limits.py')))
        run = run_rust_vm([program], [rust], [source], [('op_stack', 'precompile_admission')], request, None)
        cases = [(address, size + over, over) for address, size in
                 ((8, 81984), (12, 288960), (14, 278784), (15, 156672)) for over in (0, 1)]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / 'input.json').write_text(json.dumps([
                dict(address='0x' + address.to_bytes(20, 'big').hex(), input='0x' + '00'*size, gas=60000000)
                for address, size, _ in cases]))
            subprocess.run([str(ORACLE), '--input', str(path/'input.json'), '--output', str(path/'result.json')], check=True)
            expected = json.loads((path/'result.json').read_text())
        for (address, size, over), native in zip(cases, expected):
            with self.subTest(address=address, size=size):
                self.assertEqual(run('exceeds_limit', address=address * 2**152, input_length=size), over)
                self.assertEqual(bool(native['error']), bool(over))
                self.assertEqual(native['gas_left'], 60000000 - native['required_gas'])


if __name__ == '__main__':
    unittest.main()
