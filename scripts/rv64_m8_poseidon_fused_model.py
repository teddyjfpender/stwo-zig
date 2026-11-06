#!/usr/bin/env python3
"""Bit-exact u32 model of poseidon2_m31_fused.cuh.

Every intermediate is computed modulo 2^32 exactly as the CUDA code does, and
the documented range preconditions are asserted at each fold. The model is
compared against the independent dense-matrix reference permutation.
"""
import random

import rv64_m7_poseidon2_ref as R

P = R.P
M32 = (1 << 32) - 1
MINUS_P = 0x80000001


def mad_lo(a, b, c):
    return (a * b + c) & M32


def fold32(x):
    assert 0 <= x <= (1 << 32) - 2, x
    r = mad_lo(x >> 31, MINUS_P, x)
    assert r <= P and r % P == x % P
    return r


def fold64(v):
    lo, hi = v & M32, v >> 32
    assert (lo & P) + (v >> 31) <= (1 << 32) - 2, v
    return fold32(mad_lo(lo >> 31, MINUS_P, mad_lo(hi, 2, lo)))


def weak(x):
    assert 0 <= x <= P, x
    return x


def wadd(a, b):
    return fold32(weak(a) + weak(b))


def wmul(a, b):
    v = weak(a) * weak(b)
    lo, hi = v & M32, v >> 32
    return fold32(mad_lo(lo >> 31, MINUS_P, mad_lo(hi, 2, lo)))


def add_rc(a, c):
    x = weak(a) + c
    assert x <= (1 << 32) - 2
    return (x & P) + (x >> 31)


def wfifth(a):
    q = wmul(a, a)
    return wmul(wmul(q, q), a)


def add_rot31(total, a, k):
    weak(total), weak(a)
    true = total + (((a << k) & P) | (a >> (31 - k)) if k else a)
    assert true <= 2 * P
    got = fold32(mad_lo(a >> (31 - k), MINUS_P, ((a << k) + total) & M32))
    assert got % P == true % P
    return got


def m4(z):
    assert all(0 <= x <= 2 * P for x in z)
    t = sum(z)
    return [fold64(t + z[j] + 2 * z[(j + 1) % 4]) for j in range(4)]


def external(s):
    col = [fold64((s[j] + s[4 + j]) + (s[8 + j] + s[12 + j]) + (s[16 + j] + s[20 + j]))
           for j in range(4)]
    out = []
    for b in range(6):
        out += m4([s[4 * b + j] + col[j] for j in range(4)])
    return out


def partial_linear(s):
    pair = [s[2 * i] + s[2 * i + 1] for i in range(12)]
    assert all(x <= M32 for x in pair)
    total = fold64(sum(pair))
    s0 = wadd(total, fold32(mad_lo(s[0], 0xFFFFFFFE, 0xFFFFFFFE)))
    return [s0] + [add_rot31(total, s[i], i - 1) for i in range(1, 24)]


def permute(state):
    s = external([weak(x) for x in state])
    for r in range(4):
        s = external([wfifth(add_rc(x, c)) for x, c in zip(s, R.INITIAL[24 * r:24 * r + 24])])
    for c in R.INTERNAL:
        s = [wfifth(add_rc(s[0], c))] + s[1:]
        s = partial_linear(s)
    for r in range(4):
        s = external([wfifth(add_rc(x, c)) for x, c in zip(s, R.FINAL[24 * r:24 * r + 24])])
    return s


def canon(s):
    return [0 if x == P else x for x in s]


def check(samples=64, seed=0x5EED24):
    rng = random.Random(seed)
    # Weak inputs include p itself (the non-canonical zero) to reach every
    # fold's upper boundary.
    states = [[0] * 24, [P - 1] * 24, [P] * 24, list(range(24))]
    states += [[rng.choice((0, 1, P - 1, P, rng.randrange(P + 1))) for _ in range(24)]
               for _ in range(samples)]
    for state in states:
        assert canon(permute(state)) == R.permute([x % P for x in state]), state
    for a in (0, 1, P - 1, P):
        for b in (0, 1, P - 1, P):
            assert wmul(a, b) % P == (a * b) % P
            assert wadd(a, b) % P == (a + b) % P
            for k in range(23):
                add_rot31(a, b, k)
    return len(states)


if __name__ == "__main__":
    print({"states_checked": check(), "status": "PASS"})
