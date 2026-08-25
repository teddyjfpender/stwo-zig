from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from cuda_build_lib.builder import validate_aot_manifest  # noqa: E402
from scripts.tests.cuda_native_aot_fixture import native_aot_root  # noqa: E402


NATIVE_AOT = native_aot_root()
P = 2_147_483_647
N_STATE = 16
N_REPS = 8
N_PARTIAL = 14
N_HALF = 4
N_CONSTRAINTS = 1_144
N_SOURCES = 1_296

Q = tuple[int, int, int, int]


def add(lhs: Q, rhs: Q) -> Q:
    return tuple((a + b) % P for a, b in zip(lhs, rhs))  # type: ignore[return-value]


def sub(lhs: Q, rhs: Q) -> Q:
    return tuple((a - b) % P for a, b in zip(lhs, rhs))  # type: ignore[return-value]


def cmul(lhs: tuple[int, int], rhs: tuple[int, int]) -> tuple[int, int]:
    return (
        (lhs[0] * rhs[0] - lhs[1] * rhs[1]) % P,
        (lhs[0] * rhs[1] + lhs[1] * rhs[0]) % P,
    )


def mul(lhs: Q, rhs: Q) -> Q:
    a0 = cmul(lhs[0:2], rhs[0:2])
    a1 = cmul(lhs[2:4], rhs[2:4])
    summed = cmul(
        ((lhs[0] + lhs[2]) % P, (lhs[1] + lhs[3]) % P),
        ((rhs[0] + rhs[2]) % P, (rhs[1] + rhs[3]) % P),
    )
    extension = ((2 * a1[0] - a1[1]) % P, (a1[0] + 2 * a1[1]) % P)
    return (
        (a0[0] + extension[0]) % P,
        (a0[1] + extension[1]) % P,
        (summed[0] - a0[0] - a1[0]) % P,
        (summed[1] - a0[1] - a1[1]) % P,
    )


def mul_base(value: Q, scalar: int) -> Q:
    return tuple((coordinate * scalar) % P for coordinate in value)  # type: ignore[return-value]


def base(value: int) -> Q:
    return (value % P, 0, 0, 0)


def pow5(value: Q) -> Q:
    square = mul(value, value)
    return mul(mul(square, square), value)


def m4(values: list[Q]) -> list[Q]:
    t0 = add(values[0], values[1])
    t02 = add(t0, t0)
    t1 = add(values[2], values[3])
    t12 = add(t1, t1)
    t2 = add(add(values[1], values[1]), t1)
    t3 = add(add(values[3], values[3]), t0)
    t4 = add(add(t12, t12), t3)
    t5 = add(add(t02, t02), t2)
    return [add(t3, t5), t5, add(t2, t4), t4]


def external_round(state: list[Q]) -> list[Q]:
    state = [add(value, base(1234)) for value in state]
    for group in range(4):
        state[group * 4 : group * 4 + 4] = m4(
            state[group * 4 : group * 4 + 4]
        )
    for lane in range(4):
        total = state[lane]
        for group in range(1, 4):
            total = add(total, state[group * 4 + lane])
        for group in range(4):
            index = group * 4 + lane
            state[index] = add(state[index], total)
    return [pow5(value) for value in state]


def internal_round(state: list[Q]) -> list[Q]:
    state[0] = add(state[0], base(1234))
    total = (0, 0, 0, 0)
    for value in state:
        total = add(total, value)
    state = [
        add(mul_base(value, 1 << (lane + 1)), total)
        for lane, value in enumerate(state)
    ]
    state[0] = pow5(state[0])
    return state


def source(column: int, row: int) -> int:
    return (column * 17 + row * 13 + 5) % P


def power(index: int) -> Q:
    return tuple(
        (index * 19 + coordinate * 23 + 7) % P
        for coordinate in range(4)
    )  # type: ignore[return-value]


def combine_lookup(state: list[Q], z: Q, alpha: Q) -> Q:
    result = sub((0, 0, 0, 0), z)
    alpha_power: Q = (1, 0, 0, 0)
    for value in state:
        result = add(result, mul(alpha_power, value))
        alpha_power = mul(alpha_power, alpha)
    return result


def bit_reverse(value: int, bits: int) -> int:
    result = 0
    for _ in range(bits):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


def previous_storage_row(row: int, evaluation_log: int) -> int:
    half = 1 << (evaluation_log - 1)
    natural = bit_reverse(row, evaluation_log)
    if natural < half:
        natural = half - 1 if natural == 0 else natural - 1
    else:
        offset = natural - half
        natural = half + (0 if offset + 1 == half else offset + 1)
    return bit_reverse(natural, evaluation_log)


def expected_row(row: int) -> Q:
    z: Q = (13, 17, 19, 23)
    alpha: Q = (29, 31, 37, 41)
    claimed: Q = (43, 47, 53, 59)
    constraints: list[Q] = []
    column = 0
    previous_column: Q = (0, 0, 0, 0)
    for rep in range(N_REPS):
        state = [base(source(column + lane, row)) for lane in range(N_STATE)]
        initial = state.copy()
        column += N_STATE
        for _ in range(N_HALF):
            state = external_round(state)
            for lane in range(N_STATE):
                stored = base(source(column, row))
                constraints.append(sub(state[lane], stored))
                state[lane] = stored
                column += 1
        for _ in range(N_PARTIAL):
            state = internal_round(state)
            stored = base(source(column, row))
            constraints.append(sub(state[0], stored))
            state[0] = stored
            column += 1
        for _ in range(N_HALF):
            state = external_round(state)
            for lane in range(N_STATE):
                stored = base(source(column, row))
                constraints.append(sub(state[lane], stored))
                state[lane] = stored
                column += 1

        d0 = combine_lookup(initial, z, alpha)
        d1 = combine_lookup(state, z, alpha)
        numerator = sub(d1, d0)
        denominator = mul(d0, d1)
        current = tuple(
            source(1264 + rep * 4 + coordinate, row)
            for coordinate in range(4)
        )
        difference = sub(current, previous_column)
        if rep + 1 == N_REPS:
            previous_row = previous_storage_row(row, 2)
            previous = tuple(
                source(1264 + rep * 4 + coordinate, previous_row)
                for coordinate in range(4)
            )
            difference = add(
                sub(sub(current, previous), previous_column),
                claimed,
            )
        constraints.append(sub(mul(difference, denominator), numerator))
        previous_column = current

    assert column == 1264
    assert len(constraints) == N_CONSTRAINTS
    combined: Q = (0, 0, 0, 0)
    for index, constraint in enumerate(constraints):
        combined = add(combined, mul(power(N_CONSTRAINTS - 1 - index), constraint))
    return mul_base(combined, [61, 67, 71, 73][row])


class CudaPoseidonAotTests(unittest.TestCase):
    def test_aot_matches_independent_exact_air(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(item for item in manifest if item["label"] == "poseidon")
        self.assertEqual("native_poseidon_constraint_v1", entry["abi_schema"])
        source_path = NATIVE_AOT / entry["file"]
        self.assertEqual(
            hashlib.sha256(source_path.read_bytes()).hexdigest(),
            entry["program_identity"],
        )
        validate_aot_manifest(NATIVE_AOT, manifest)
        harness = self._harness(source_path, str(entry["kernel_name"]))
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            source = root / "poseidon_aot_test.cpp"
            executable = root / "poseidon_aot_test"
            source.write_text(harness, encoding="utf-8")
            subprocess.run(
                [compiler, "-std=c++17", "-O2", str(source), "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
        actual = [int(value) for value in result.stdout.split()]
        expected = [
            coordinate
            for row in range(4)
            for coordinate in expected_row(row)
        ]
        self.assertEqual(expected, actual)

    @staticmethod
    def _harness(source: Path, kernel_name: str) -> str:
        return f"""
#include <iostream>
#include <vector>
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static Dim3 blockIdx{{0, 0, 0}}, blockDim{{64, 1, 1}}, threadIdx{{0, 0, 0}};
static unsigned __brev(unsigned value) {{
    value = ((value & 0x55555555u) << 1u) |
        ((value >> 1u) & 0x55555555u);
    value = ((value & 0x33333333u) << 2u) |
        ((value >> 2u) & 0x33333333u);
    value = ((value & 0x0f0f0f0fu) << 4u) |
        ((value >> 4u) & 0x0f0f0f0fu);
    value = ((value & 0x00ff00ffu) << 8u) |
        ((value >> 8u) & 0x00ff00ffu);
    return (value << 16u) | (value >> 16u);
}}
#include {json.dumps(str(source))}

int main() {{
    constexpr unsigned rows = 4;
    std::vector<unsigned> sources(1296u * rows);
    for (unsigned column = 0; column < 1296u; ++column) {{
        for (unsigned row = 0; row < rows; ++row) {{
            sources[column * rows + row] =
                (column * 17u + row * 13u + 5u) % kPrime;
        }}
    }}
    std::vector<unsigned> powers(4u * 1144u);
    for (unsigned index = 0; index < 1144u; ++index) {{
        for (unsigned coordinate = 0; coordinate < 4u; ++coordinate) {{
            powers[index * 4u + coordinate] =
                (index * 19u + coordinate * 23u + 7u) % kPrime;
        }}
    }}
    unsigned denominators[4] = {{61u, 67u, 71u, 73u}};
    unsigned lookup[8] = {{13u, 17u, 19u, 23u, 29u, 31u, 37u, 41u}};
    unsigned claimed[4] = {{43u, 47u, 53u, 59u}};
    unsigned coordinates[16] = {{}};
    for (unsigned row = 0; row < rows; ++row) {{
        threadIdx.x = row;
        {kernel_name}(
            sources.data(), sources.size(), rows,
            powers.data(), powers.size(),
            denominators, 4,
            lookup, 8,
            claimed, 4,
            coordinates, 16, rows,
            rows, 0, 1);
    }}
    for (unsigned row = 0; row < rows; ++row) {{
        for (unsigned coordinate = 0; coordinate < 4u; ++coordinate) {{
            std::cout << coordinates[coordinate * rows + row] << ' ';
        }}
    }}
}}
"""


if __name__ == "__main__":
    unittest.main()
