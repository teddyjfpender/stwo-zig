#!/usr/bin/env python3
"""Independent schoolbook polynomial tower vs the compiled CUDA field header.

This checks host arithmetic, not device execution or a whole-protocol claim.
Only standard Python plus the C++ compiler is needed; no CUDA install.
"""
import argparse
import ctypes
import json
import random
import subprocess
import tempfile
from pathlib import Path

P = 2**31 - 1
ROOT = Path(__file__).resolve().parents[3]


def add(a, b):
    return tuple((x + y) % P for x, y in zip(a, b))


def cmul(a, b):
    return ((a[0]*b[0]-a[1]*b[1]) % P, (a[0]*b[1]+a[1]*b[0]) % P)


def qmul(a, b):
    # Schoolbook tower, deliberately not the CUDA Karatsuba expression.
    ac, bd = cmul(a[:2], b[:2]), cmul(a[2:], b[2:])
    return add(ac, cmul((2, 1), bd)) + add(cmul(a[:2], b[2:]), cmul(a[2:], b[:2]))


def omul(a, b):
    ac, bd = qmul(a[:4], b[:4]), qmul(a[4:], b[4:])
    return add(ac, qmul((0, 0, 1, 0), bd)) + add(qmul(a[:4], b[4:]), qmul(a[4:], b[:4]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cxx', default='g++')
    parser.add_argument('--cases', type=int, default=4096)
    args = parser.parse_args()
    rng = random.Random(0x5256363443554441)
    with tempfile.TemporaryDirectory(prefix='rv64-field-') as temp:
        library = Path(temp)/'field.so'
        subprocess.run([args.cxx, '-std=c++17', '-O2', '-shared', '-fPIC',
                        '-I'+str(ROOT/'tests/cuda/rv64/host_include'),
                        '-I'+str(ROOT/'src/backends/cuda/native'),
                        str(ROOT/'tests/cuda/rv64/numerical_bridge.cpp'), '-o', str(library)], check=True)
        lib = ctypes.CDLL(str(library))
        word8 = ctypes.c_uint32*8
        lib.rv64_test_mul.argtypes = [ctypes.POINTER(ctypes.c_uint32)]*3
        basis = [tuple(int(i == j) for i in range(8)) for j in range(8)]
        pairs = [(a, b) for a in basis for b in basis]
        edges = (0, 1, 2, P//2, P-2, P-1)
        pairs += [(tuple([a]*8), tuple([b]*8)) for a in edges for b in edges]
        pairs += [(tuple(rng.randrange(P) for _ in range(8)),
                   tuple(rng.randrange(P) for _ in range(8))) for _ in range(args.cases)]
        for a, b in pairs:
            out = word8()
            lib.rv64_test_mul(word8(*a), word8(*b), out)
            if tuple(out) != omul(a, b):
                raise AssertionError({'a': a, 'b': b, 'got': list(out), 'expected': omul(a, b)})
        print(json.dumps({'schema': 'rv64-cuda-independent-field-v1', 'cases': len(pairs),
                          'passed': True, 'device_execution': False}))


if __name__ == '__main__':
    main()
