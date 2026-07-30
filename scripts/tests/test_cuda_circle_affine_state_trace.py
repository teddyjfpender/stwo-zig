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


class CudaCircleAffineStateTraceTests(unittest.TestCase):
    def test_aot_program_matches_independent_state_machine_trace(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(
            item for item in manifest
            if item["label"] == "circle_affine_state_trace"
        )
        self.assertEqual(
            "native_circle_affine_state_trace_v1",
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
            source_path = root / "circle_affine_state_trace_test.cpp"
            executable = root / "circle_affine_state_trace_test"
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

unsigned reverse_bits(unsigned value, unsigned count) {{
    unsigned reversed = 0;
    for (unsigned bit = 0; bit < count; ++bit) {{
        reversed = (reversed << 1) | (value & 1u);
        value >>= 1;
    }}
    return reversed;
}}

unsigned coset_to_circle(unsigned index, unsigned rows) {{
    return (index & 1u) == 0u
        ? index / 2u
        : (2u * rows - index) / 2u;
}}

void run_case(unsigned log_rows) {{
    const unsigned rows = 1u << log_rows;
    const std::uint64_t preprocessed_stride = rows + 3;
    const std::uint64_t main_stride = rows + 5;
    std::vector<unsigned> actual_preprocessed(
        preprocessed_stride,
        0xa5a5a5a5u);
    std::vector<unsigned> actual_main(
        main_stride * 2,
        0xa5a5a5a5u);
    std::vector<unsigned> oracle_preprocessed(
        preprocessed_stride,
        0xa5a5a5a5u);
    std::vector<unsigned> oracle_main(
        main_stride * 2,
        0xa5a5a5a5u);

    for (unsigned storage_row = 0; storage_row < rows; ++storage_row) {{
        threadIdx.x = storage_row;
        {kernel_name}(
            actual_preprocessed.data(),
            actual_preprocessed.size(),
            preprocessed_stride,
            actual_main.data(),
            actual_main.size(),
            main_stride,
            rows,
            log_rows,
            17,
            23,
            0,
            1,
            1,
            0);
    }}
    for (unsigned storage_row = 0; storage_row < rows; ++storage_row) {{
        oracle_preprocessed[storage_row] = storage_row == 0 ? 1 : 0;
    }}
    for (unsigned logical_row = 0; logical_row < rows; ++logical_row) {{
        const unsigned circle = coset_to_circle(logical_row, rows);
        const unsigned storage_row = reverse_bits(circle, log_rows);
        oracle_main[storage_row] = stwo_m31_from_u64(17u + logical_row);
        oracle_main[main_stride + storage_row] = 23;
    }}
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
