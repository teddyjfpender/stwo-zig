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


class CudaIndexedRecurrenceTraceTests(unittest.TestCase):
    def test_aot_program_matches_independent_plonk_trace(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(
            item for item in manifest
            if item["label"] == "indexed_recurrence_trace"
        )
        self.assertEqual(
            "native_indexed_recurrence_trace_v1",
            entry["abi_schema"],
        )
        source = NATIVE_AOT / entry["file"]
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            entry["program_identity"],
        )
        harness = self._harness(source, str(entry["kernel_name"]))
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            source_path = root / "indexed_recurrence_trace_test.cpp"
            executable = root / "indexed_recurrence_trace_test"
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

void trace(
    unsigned log_rows,
    std::uint64_t preprocessed_stride,
    std::uint64_t main_stride,
    std::vector<unsigned> *preprocessed,
    std::vector<unsigned> *main) {{
    const unsigned rows = 1u << log_rows;
    std::vector<unsigned> fib(rows + 2);
    fib[0] = 1;
    fib[1] = 1;
    for (unsigned index = 2; index < fib.size(); ++index) {{
        fib[index] = add(fib[index - 1], fib[index - 2]);
    }}
    for (unsigned row = 0; row < rows; ++row) {{
        (*preprocessed)[row] = from_u64(row);
        (*preprocessed)[preprocessed_stride + row] = from_u64(row + 1);
        (*preprocessed)[2 * preprocessed_stride + row] = from_u64(row + 2);
        (*preprocessed)[3 * preprocessed_stride + row] = 1;
        (*main)[row] = row + 1 == rows ? 0 : 1;
        (*main)[main_stride + row] = fib[row];
        (*main)[2 * main_stride + row] = fib[row + 1];
        (*main)[3 * main_stride + row] = fib[row + 2];
    }}
}}
}}  // namespace expected

void run_case(unsigned log_rows) {{
    const unsigned rows = 1u << log_rows;
    const std::uint64_t preprocessed_stride = rows + 3;
    const std::uint64_t main_stride = rows + 5;
    std::vector<unsigned> actual_preprocessed(
        preprocessed_stride * 4,
        0xa5a5a5a5u);
    std::vector<unsigned> actual_main(main_stride * 4, 0xa5a5a5a5u);
    std::vector<unsigned> oracle_preprocessed(
        preprocessed_stride * 4,
        0xa5a5a5a5u);
    std::vector<unsigned> oracle_main(main_stride * 4, 0xa5a5a5a5u);
    for (unsigned row = 0; row < rows; ++row) {{
        threadIdx.x = row;
        {kernel_name}(
            actual_preprocessed.data(),
            actual_preprocessed.size(),
            preprocessed_stride,
            actual_main.data(),
            actual_main.size(),
            main_stride,
            rows,
            log_rows,
            0,
            1,
            1,
            1,
            1,
            1,
            0,
            1);
    }}
    expected::trace(
        log_rows,
        preprocessed_stride,
        main_stride,
        &oracle_preprocessed,
        &oracle_main);
    assert(actual_preprocessed == oracle_preprocessed);
    assert(actual_main == oracle_main);
}}

int main() {{
    run_case(5);
    run_case(2);
}}
"""


if __name__ == "__main__":
    unittest.main()
