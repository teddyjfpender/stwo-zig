#!/usr/bin/env python3
"""Cheap CPU formula/framing check. Does not compile or execute CUDA."""
import argparse
import hashlib
import json
import random
from pathlib import Path

import rv64_m7_poseidon2_ref as reference

ROOT = Path(__file__).resolve().parents[1]
P = reference.P


def add(a, b):
    value = a + b
    return value if value < P else value - P


def mul(a, b):
    product = a * b
    value = (product & P) + (product >> 31)
    return value if value < P else value - P


def rotate(a, k):
    return (((a << k) & P) | (a >> (31 - k))) if k else a


def external(state):
    state = state[:]
    for i in range(0, 24, 4):
        a, b, c, d = state[i:i + 4]
        ab, cd = add(a, b), add(c, d)
        all_values = add(ab, cd)
        all_b, all_d = add(all_values, b), add(all_values, d)
        state[i:i + 4] = [add(all_b, ab), add(all_b, add(c, c)),
                          add(all_d, cd), add(all_d, add(a, a))]
    for i in range(4):
        total = 0
        for j in range(i, 24, 4):
            total = add(total, state[j])
        for j in range(i, 24, 4):
            state[j] = add(state[j], total)
    return state


def fifth(a):
    square = mul(a, a)
    return mul(mul(square, square), a)


def permute(state):
    state = external(state)
    for offset in range(0, 96, 24):
        state = external([fifth(add(a, b)) for a, b in zip(state, reference.INITIAL[offset:offset + 24])])
    for constant in reference.INTERNAL:
        state[0] = fifth(add(state[0], constant))
        total = 0
        for value in state:
            total = add(total, value)
        double = add(state[0], state[0])
        state = [add(total, P - double if double else 0)] + [
            add(total, rotate(state[i], i - 1)) for i in range(1, 24)]
    for offset in range(0, 96, 24):
        state = external([fifth(add(a, b)) for a, b in zip(state, reference.FINAL[offset:offset + 24])])
    return state


def packed(domain, values):
    state = [0] * 24
    state[22:24] = [1, domain]
    full = len(values) - len(values) % 12
    for offset in range(0, full, 12):
        for i in range(12):
            state[i] = add(state[i], values[offset + i])
        state = permute(state)
    remainder = len(values) % 12
    for i in range(12):
        if i < remainder:
            state[i] = add(state[i], values[full + i])
        if i == remainder:
            state[i] = add(state[i], 1)
    return permute(state)[:9]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rng = random.Random(0x8_24_12)
    checked = 0
    for a in [0, 1, P - 1] + [rng.randrange(P) for _ in range(4096)]:
        b = rng.randrange(P)
        assert add(a, b) == (a + b) % P
        assert mul(a, b) == (a * b) % P
        for k in range(23):
            assert rotate(a, k) == a * (1 << k) % P
        checked += 25
    states = [[0] * 24, [P - 1] * 24, list(range(24))]
    states += [[rng.randrange(P) for _ in range(24)] for _ in range(5)]
    for state in states:
        assert permute(state) == reference.permute(state)
    widths = [0, 1, 11, 12, 13, 23, 24, 25, 47, 128, 479]
    for width in widths:
        values = [rng.randrange(P) for _ in range(width)]
        assert packed(1, values) == reference.sponge(1, values)
    children = [rng.randrange(P) for _ in range(18)]
    assert packed(2, children) == reference.sponge(2, children)
    sources = ["src/backends/cuda/native/rv64/poseidon2_m31.cuh",
               "src/backends/cuda/native/rv64/poseidon2_m31_register.cuh",
               "src/backends/cuda/native/common/m31.cuh",
               "tests/cuda/rv64/poseidon_commit_bench.cu",
               "tests/cuda/rv64/poseidon2_m31_smoke.cu",
               "scripts/rv64_m8_poseidon_static.py"]
    result = {"schema": "rv64-m8-p2-cpu-formula-check/v1", "status": "PASS",
              "evidence": "CPU formula model and source hashes only; CUDA uncompiled/unexecuted",
              "arithmetic_checks": checked, "permutation_cases": len(states),
              "packed_leaf_widths": widths, "parent_limbs": 18,
              "independent_reference": reference.check(),
              "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in sources},
              "cuda_qualified": False, "native_s2_qualified": False,
              "performance_gain": None}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "evidence", "arithmetic_checks", "permutation_cases")}))


if __name__ == "__main__":
    main()
