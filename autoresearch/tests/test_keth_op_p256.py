"""P-256 verification against the unmodified pinned Jovian precompile."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

import keth_types.patches
from cairo_addons.compiler import implement_hints
from cairo_addons.rust_bindings.vm import Program as RustProgram
from cairo_addons.testing.runner import run_rust_vm
from ethereum_types.bytes import Bytes
from autoresearch.experiments.evm_keth.op_compiler import compile_owned

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / 'block-data/keth-integration-20261029/op-precompile-oracle-1'
P = int('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff', 16)
N = int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551', 16)
B = int('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b', 16)
G = (int('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296', 16),
     int('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 16))


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x-3) * pow(2*y, -1, P) if a == b else (v-y) * pow(u-x, -1, P)) % P
    result_x = (slope*slope-x-u) % P
    return result_x, (slope*(x-result_x)-y) % P


def multiply(k):
    result, base = None, G
    while k:
        if k & 1:
            result = point_add(result, base)
        base = point_add(base, base)
        k >>= 1
    return result


def encode(fields):
    return b''.join(v.to_bytes(32, 'big') for v in fields)


def vectors():
    result = []
    for index, message in enumerate((0, 1, 2**256-1, N-1, N, N+1)):
        secret = (1, N-1, 17, 29, 1234567, 999)[index]
        nonce = int.from_bytes(hashlib.sha256(f'p256-fixture-{index}'.encode()).digest(), 'big') % (N-1) + 1
        r = multiply(nonce)[0] % N
        s = pow(nonce, -1, N) * (message + r*secret) % N
        public = multiply(secret)
        fields = [message, r, s, *public]
        result.extend([(f'valid-{index}', encode(fields), True),
                       (f'high-s-{index}', encode([message, r, N-s, *public]), True),
                       (f'wrong-hash-{index}', encode([message ^ 1, r, s, *public]), False)])
    # A valid signature with R.x >= n exercises reduction of the final x.
    for delta in range(1, 100):
        x = N + delta
        square = (x*x*x-3*x+B) % P
        y = pow(square, (P+1)//4, P)
        if y*y % P == square:
            result.append(('x-above-order', encode([0, delta, delta, x, y]), True))
            break
    fields = [1, 1, 1, *G]
    for name, index, value in [('r-zero', 1, 0), ('s-zero', 2, 0), ('r-order', 1, N),
                               ('s-order', 2, N), ('x-prime', 3, P), ('y-prime', 4, P),
                               ('off-curve', 4, G[1] ^ 1)]:
        modified = fields[:]
        modified[index] = value
        result.append((name, encode(modified), False))
    result += [('infinity', encode([N-1, 1, 1, *G]), False),
               ('empty', b'', False), ('short', bytes(159), False), ('long', bytes(161), False)]
    return result


@unittest.skipUnless(ORACLE.is_file(), 'build the pinned OP precompile oracle first')
class OpP256Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = ROOT / 'autoresearch/experiments/evm_keth/cairo/op_stack/p256.cairo'
        program = compile_owned(source, proof_mode=False)
        program.hints = implement_hints(program)
        rust = RustProgram.from_bytes(json.dumps(program.Schema().dump(program)).encode(), 'verify_signature')
        request = SimpleNamespace(config=SimpleNamespace(getoption=lambda name: {
            'layout': 'all_cairo_instance', 'no_coverage': True}.get(name, False)),
            node=SimpleNamespace(path=Path('/tmp/test_keth_op_p256.py')))
        cls.cairo = staticmethod(run_rust_vm([program], [rust], [source], [('op_stack', 'p256')], request, None))

    def test_valid_invalid_boundaries_high_s_and_x_above_order(self):
        cases = vectors()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            (path / 'input.json').write_text(json.dumps([
                dict(address='0x' + '00'*18 + '0100', input='0x'+raw.hex(), gas=100000)
                for _, raw, _ in cases]))
            subprocess.run([str(ORACLE), '--input', str(path/'input.json'), '--output', str(path/'output.json')], check=True)
            expected = json.loads((path/'output.json').read_text())
        self.assertEqual(len(expected), len(cases))
        for (name, raw, valid), native in zip(cases, expected):
            with self.subTest(name=name):
                self.assertEqual(native['error'], '')
                self.assertEqual(native['required_gas'], 3450)
                self.assertEqual(native['gas_left'], 96550)
                self.assertEqual(native['output'], '0x' + ('00'*31+'01' if valid else ''))
                self.assertEqual(self.cairo('verify_signature', data=Bytes(raw)), int(valid))


if __name__ == '__main__':
    unittest.main()
