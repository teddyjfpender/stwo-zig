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


class CudaPlonkLogupAotTests(unittest.TestCase):
    def test_aot_matches_exact_three_constraint_composition(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(item for item in manifest if item["label"] == "plonk_logup")
        self.assertEqual(
            "native_plonk_logup_constraint_v1",
            entry["abi_schema"],
        )
        source = NATIVE_AOT / entry["file"]
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            entry["program_identity"],
        )
        validate_aot_manifest(NATIVE_AOT, manifest)
        kernel_name = entry["kernel_name"]
        harness = f"""
#include <cassert>
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static Dim3 blockIdx{{0, 0, 0}}, blockDim{{128, 1, 1}}, threadIdx{{0, 0, 0}};
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
    constexpr unsigned trace_log_size = 1;
    constexpr unsigned inverse_rows = 1u << 30u;
    constexpr unsigned long long stride = rows;
    unsigned sources[16 * rows] = {{
        3, 5, 7, 9, 8, 10, 12, 14,
        13, 15, 17, 19, 18, 20, 22, 24,
        23, 25, 27, 29, 28, 30, 32, 34,
        33, 35, 37, 39, 38, 40, 42, 44,
        43, 45, 47, 49, 48, 50, 52, 54,
        53, 55, 57, 59, 58, 60, 62, 64,
        63, 65, 67, 69, 68, 70, 72, 74,
        73, 75, 77, 79, 78, 80, 82, 84
    }};
    unsigned powers[12] = {{
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12
    }};
    unsigned denominators[2] = {{61, 67}};
    unsigned lookup[8] = {{
        13, 17, 19, 23,
        29, 31, 37, 41
    }};
    unsigned claimed_sum[4] = {{43, 47, 53, 59}};
    unsigned coordinates[4 * rows] = {{}};
    for (unsigned row = 0; row < rows; ++row) {{
        threadIdx.x = row;
        {kernel_name}(
            sources, 16 * rows, stride,
            powers, 12,
            denominators, 2,
            lookup, 8,
            claimed_sum, 4,
            coordinates, 4 * rows, stride,
            rows, trace_log_size, inverse_rows);
    }}
    const unsigned expected[4][rows] = {{
        {{606176109, 1787302443, 1959867894, 1887363615}},
        {{1462550668, 1874025832, 1351282746, 649544424}},
        {{1293323832, 2115446679, 1386711407, 773983380}},
        {{1938565058, 1503624160, 1250970379, 1817175278}}
    }};
    for (unsigned coordinate = 0; coordinate < 4; ++coordinate) {{
        for (unsigned row = 0; row < rows; ++row) {{
            assert(coordinates[coordinate * stride + row] ==
                expected[coordinate][row]);
        }}
    }}
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness_path = root / "plonk_logup_aot_test.cpp"
            executable = root / "plonk_logup_aot_test"
            harness_path.write_text(harness, encoding="utf-8")
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-O2",
                    str(harness_path),
                    "-o",
                    str(executable),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
