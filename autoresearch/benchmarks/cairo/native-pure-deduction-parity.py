#!/usr/bin/env python3
"""Compile the emitted C G round and compare full-width edge/random inputs."""
import argparse
import ctypes
import hashlib
import itertools
import json
from pathlib import Path
import random
import re
import subprocess
import tempfile


def reference(words):
    mask = (1 << 32) - 1
    a, b, c, d, m0, m1 = words
    def rotr(x, shift):
        return ((x >> shift) | (x << (32 - shift))) & mask
    a = (a + b + m0) & mask
    d = rotr(d ^ a, 16)
    c = (c + d) & mask
    b = rotr(b ^ c, 12)
    a = (a + b + m1) & mask
    d = rotr(d ^ a, 8)
    c = (c + d) & mask
    b = rotr(b ^ c, 7)
    return [a, b, c, d]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zig', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    emitter = root / 'autoresearch/benchmarks/cairo/native-pure-deduction-emitter-v23.zig.txt'
    emitted = '\n'.join(re.findall(r'^\s*\\\\(.*)$', emitter.read_text(), re.MULTILINE))
    if 'witness_blake_g' not in emitted:
        raise ValueError('C helper preamble was not found')
    source = '#include <stdint.h>\n' + emitted + '\nvoid probe_g(const uint32_t *i, uint32_t *o) { witness_blake_g(i, o); }\n'
    edge = [0, 1, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff]
    rng = random.Random(0x5354574F)
    inputs = itertools.chain(itertools.product(edge, repeat=6),
                             ([rng.getrandbits(32) for _ in range(6)] for _ in range(10000)))
    with tempfile.TemporaryDirectory(prefix='cairo-native-g-') as directory:
        folder = Path(directory)
        unit, library = folder / 'probe.c', folder / 'probe.dylib'
        unit.write_text(source)
        subprocess.run([str(args.zig), 'cc', '-O3', '-shared', '-fPIC', str(unit), '-o', str(library)], check=True)
        compiled = ctypes.CDLL(str(library)).probe_g
        compiled.argtypes = [ctypes.POINTER(ctypes.c_uint32)] * 2
        compiled.restype = None
        count = 0
        for words in inputs:
            destination = (ctypes.c_uint32 * 4)()
            compiled((ctypes.c_uint32 * 6)(*words), destination)
            if list(destination) != reference(words):
                raise AssertionError(f'compiled G parity failed: {words}')
            count += 1
        receipt = {'schema': 'stwo-zig-cairo-native-g-parity-v1', 'status': 'qualified',
                   'cases': count, 'compiler': subprocess.check_output([str(args.zig), 'version'], text=True).strip(),
                   'emitter_sha256': hashlib.sha256(emitter.read_bytes()).hexdigest(),
                   'compiled_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                   'coverage': 'all six-word combinations of six full-width edges plus 10000 seeded random cases'}
        args.out.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt))


if __name__ == '__main__':
    main()
