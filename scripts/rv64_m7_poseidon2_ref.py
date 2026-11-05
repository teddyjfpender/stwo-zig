#!/usr/bin/env python3
"""Independent dense-matrix reference; pinned P3 parameters, no GPU/proof claim."""
import hashlib
import json
from pathlib import Path
import random
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
P = 2147483647
SOURCE = (ROOT / "third_party/poseidon2_plonky3/reference_poseidon2.rs").read_text()


def external_constants(name):
    start = SOURCE.index("pub const " + name + ":")
    stop = SOURCE.index("\n];", start) + 3
    return [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", SOURCE[start:stop])]


INITIAL = external_constants("MERSENNE31_POSEIDON2_RC_24_EXTERNAL_INITIAL")
FINAL = external_constants("MERSENNE31_POSEIDON2_RC_24_EXTERNAL_FINAL")
start = SOURCE.index("pub const MERSENNE31_POSEIDON2_RC_24_INTERNAL:")
INTERNAL = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", SOURCE[start:SOURCE.index("]);", start) + 3])]
DIAGONAL = [P - 2] + [1 << i for i in range(23)]
M4 = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]
EXTERNAL = [[M4[r % 4][c % 4] * (2 if r // 4 == c // 4 else 1) for c in range(24)] for r in range(24)]


def external(state):
    return [sum(a * b for a, b in zip(row, state)) % P for row in EXTERNAL]


def permute(state):
    state = external(state)
    for offset in range(0, 96, 24):
        state = external([pow((v + c) % P, 5, P) for v, c in zip(state, INITIAL[offset:offset + 24])])
    for constant in INTERNAL:
        state[0] = pow((state[0] + constant) % P, 5, P)
        total = sum(state) % P
        state = [(total + d * v) % P for d, v in zip(DIAGONAL, state)]
    for offset in range(0, 96, 24):
        state = external([pow((v + c) % P, 5, P) for v, c in zip(state, FINAL[offset:offset + 24])])
    return state


def sponge(domain, values):
    state = [0] * 24
    state[22], state[23] = 1, domain
    at = 0
    for value in values:
        assert 0 <= value < P
        state[at] = (state[at] + value) % P
        at += 1
        if at == 12:
            state, at = permute(state), 0
    state[at] = (state[at] + 1) % P
    return permute(state)[:9]


def raw32(word):
    return [word & 65535, word >> 16]


def framing_vectors():
    leaf = sponge(1, list(range(479)))
    node = sponge(2, leaf + leaf)
    initial = sponge(3, raw32(8))
    mixed = sponge(3, initial + raw32(0xffffffff) + raw32(P))
    draw = sponge(6, mixed + [0, 0, 0, 0])
    return {"leaf_479": leaf, "node": node, "om31_initial": initial,
            "mixed_max_and_p": mixed, "draw_zero": draw[:8],
            "v2_om31_initial": sponge(3, raw32(8)+raw32(2)),
            "v2_draw_zero": sponge(6, sponge(3, raw32(8)+raw32(2))+raw32(0))[:8]}


def check():
    start = SOURCE.index("fn test_default_mersenne31_poseidon2_width_24")
    start = SOURCE.index("let expected:", start)
    expected = [int(x, 16) for x in re.findall(r"0x[0-9a-f]+", SOURCE[start:SOURCE.index("]);", start) + 3])]
    assert permute(list(range(24))) == expected
    rng = random.Random(0x51EED)
    inputs = [[0] * 24, [P - 1] * 24, [rng.randrange(P) for _ in range(24)]]
    vectors = (ROOT / "src/core/crypto/poseidon2_m31_w24_vectors.zig").read_text()
    numeric = [int(x) for x in re.findall(r"\b[0-9]+\b", vectors.split("{", 1)[1])]
    # Ignore the type's two array lengths before the initializer.
    numeric = numeric[2:]
    assert numeric == [n for state in inputs for n in state + permute(state)]
    domain = b"stwo/poseidon2/m31/p3-w24-rf8-rp22-x5-mds4-diag/v1"
    identity = hashlib.sha256(domain + b"".join(struct.pack("<I", n) for n in [24, 8, 22, 5] + DIAGONAL + INITIAL + FINAL + INTERNAL)).hexdigest()
    return {"official_kat": "PASS", "dense_vectors": len(inputs), "parameter_identity": identity, "framing_vectors": framing_vectors()}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
