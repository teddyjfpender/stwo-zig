from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"


class CudaM31PermutationTraceTests(unittest.TestCase):
    def test_aot_program_matches_independent_scalar_trace(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(
            item for item in manifest if item["label"] == "m31_permutation_trace"
        )
        self.assertEqual(
            "native_m31_permutation_trace_v2",
            entry["abi_schema"],
        )
        source = NATIVE_AOT / entry["file"]
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            entry["program_identity"],
        )
        harness = self._harness(source, str(entry["kernel_name"]))
        # macOS may kill unsigned transient executables below the per-user
        # TMPDIR; /tmp is also the portable CI build-artifact boundary.
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            source_path = root / "m31_permutation_trace_test.cpp"
            executable = root / "m31_permutation_trace_test"
            source_path.write_text(harness, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-O2",
                    str(source_path),
                    "-o",
                    str(executable),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)

    @staticmethod
    def _harness(source: Path, kernel_name: str) -> str:
        return f"""
#include <cassert>
#include <cstdint>
#include <vector>
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static Dim3 blockIdx{{0, 0, 0}}, blockDim{{256, 1, 1}}, threadIdx{{0, 0, 0}};
#include {json.dumps(str(source))}

namespace expected {{
constexpr std::uint64_t kPrime = 2147483647ull;

unsigned from_u64(std::uint64_t value) {{
    std::uint64_t reduced = (value & kPrime) + (value >> 31u);
    reduced = (reduced & kPrime) + (reduced >> 31u);
    return reduced >= kPrime
        ? static_cast<unsigned>(reduced - kPrime)
        : static_cast<unsigned>(reduced);
}}

unsigned add(unsigned lhs, unsigned rhs) {{
    const std::uint64_t sum = static_cast<std::uint64_t>(lhs) + rhs;
    return static_cast<unsigned>(sum >= kPrime ? sum - kPrime : sum);
}}

unsigned mul(unsigned lhs, unsigned rhs) {{
    return from_u64(static_cast<std::uint64_t>(lhs) * rhs);
}}

unsigned pow5(unsigned value) {{
    const unsigned square = mul(value, value);
    return mul(mul(square, square), value);
}}

void m4(unsigned *x) {{
    const unsigned t0 = add(x[0], x[1]);
    const unsigned t02 = add(t0, t0);
    const unsigned t1 = add(x[2], x[3]);
    const unsigned t12 = add(t1, t1);
    const unsigned t2 = add(add(x[1], x[1]), t1);
    const unsigned t3 = add(add(x[3], x[3]), t0);
    const unsigned t4 = add(add(t12, t12), t3);
    const unsigned t5 = add(add(t02, t02), t2);
    x[0] = add(t3, t5);
    x[1] = t5;
    x[2] = add(t2, t4);
    x[3] = t4;
}}

void external_matrix(unsigned *state) {{
    for (unsigned group = 0; group < 4; ++group) m4(state + group * 4);
    for (unsigned lane = 0; lane < 4; ++lane) {{
        unsigned sum = state[lane];
        sum = add(sum, state[lane + 4]);
        sum = add(sum, state[lane + 8]);
        sum = add(sum, state[lane + 12]);
        for (unsigned group = 0; group < 4; ++group) {{
            const unsigned index = group * 4 + lane;
            state[index] = add(state[index], sum);
        }}
    }}
}}

void internal_matrix(unsigned *state) {{
    unsigned sum = state[0];
    for (unsigned lane = 1; lane < 16; ++lane) sum = add(sum, state[lane]);
    unsigned coefficient = 2;
    for (unsigned lane = 0; lane < 16; ++lane) {{
        state[lane] = add(mul(state[lane], coefficient), sum);
        coefficient = add(coefficient, coefficient);
    }}
}}

void row(
    unsigned *trace,
    std::uint64_t stride,
    unsigned row_index,
    unsigned reps,
    unsigned half_rounds,
    unsigned partial_rounds) {{
    std::uint64_t column = 0;
    for (unsigned rep = 0; rep < reps; ++rep) {{
        unsigned state[16];
        for (unsigned lane = 0; lane < 16; ++lane) {{
            state[lane] = from_u64(
                static_cast<std::uint64_t>(row_index) + lane + rep);
            trace[column++ * stride + row_index] = state[lane];
        }}
        for (unsigned round = 0; round < half_rounds; ++round) {{
            for (unsigned lane = 0; lane < 16; ++lane) {{
                state[lane] = add(
                    state[lane],
                    from_u64(1234));
            }}
            external_matrix(state);
            for (unsigned lane = 0; lane < 16; ++lane) {{
                state[lane] = pow5(state[lane]);
                trace[column++ * stride + row_index] = state[lane];
            }}
        }}
        for (unsigned round = 0; round < partial_rounds; ++round) {{
            state[0] = add(state[0], from_u64(1234));
            internal_matrix(state);
            state[0] = pow5(state[0]);
            trace[column++ * stride + row_index] = state[0];
        }}
        for (unsigned offset = 0; offset < half_rounds; ++offset) {{
            const unsigned round = offset + half_rounds;
            for (unsigned lane = 0; lane < 16; ++lane) {{
                state[lane] = add(
                    state[lane],
                    from_u64(1234));
            }}
            external_matrix(state);
            for (unsigned lane = 0; lane < 16; ++lane) {{
                state[lane] = pow5(state[lane]);
                trace[column++ * stride + row_index] = state[lane];
            }}
        }}
    }}
}}
}}  // namespace expected

void run_case(
    unsigned log_rows,
    unsigned reps,
    unsigned half_rounds,
    unsigned partial_rounds) {{
    const unsigned rows = 1u << log_rows;
    const std::uint64_t columns_per_rep =
        16ull * (1ull + 2ull * half_rounds) + partial_rounds;
    const std::uint64_t columns = reps * columns_per_rep;
    const std::uint64_t stride = rows + 3;
    std::vector<unsigned> actual(stride * columns, 0xa5a5a5a5u);
    std::vector<unsigned> oracle(stride * columns, 0xa5a5a5a5u);
    for (unsigned row = 0; row < rows; ++row) {{
        threadIdx.x = row;
        {kernel_name}(
            actual.data(), actual.size(), stride, rows, log_rows, reps,
            half_rounds, partial_rounds, 1, 1, 1234, 0, 0, 1234, 0);
        expected::row(
            oracle.data(), stride, row, reps, half_rounds, partial_rounds);
    }}
    assert(actual == oracle);
}}

int main() {{
    // Exact Native Poseidon geometry: all eight packed instances and rounds.
    run_case(3, 8, 4, 14);
    // Non-target shapes keep the generic recipe honest.
    run_case(3, 2, 2, 3);
    run_case(1, 1, 1, 1);
}}
"""


if __name__ == "__main__":
    unittest.main()
