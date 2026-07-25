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


NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"


class CudaXorLogupTraceAotTests(unittest.TestCase):
    def test_aot_matches_exact_cpu_trace_digests(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(
            item for item in manifest if item["label"] == "xor_logup_trace"
        )
        self.assertEqual("native_xor_logup_trace_v1", entry["abi_schema"])
        source = NATIVE_AOT / entry["file"]
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            entry["program_identity"],
        )
        validate_aot_manifest(NATIVE_AOT, manifest)
        kernel_name = entry["kernel_name"]
        harness = f"""
#include <cassert>
#include <cstdint>
#include <vector>
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

std::uint64_t run(unsigned log_size, unsigned log_step, unsigned long long offset) {{
    const unsigned rows = 1u << log_size;
    std::vector<unsigned> preprocessed(7u * rows);
    std::vector<unsigned> main_trace(4u * rows);
    std::vector<unsigned> relation_sources(7u * rows);
    for (unsigned row = 0; row < rows; ++row) {{
        blockIdx.x = row / 128u;
        threadIdx.x = row % 128u;
        {kernel_name}(
            preprocessed.data(), preprocessed.size(), rows,
            main_trace.data(), main_trace.size(), rows,
            relation_sources.data(), relation_sources.size(), rows,
            rows, log_size, log_step, offset);
    }}
    for (unsigned row = 0; row < rows; ++row) {{
        assert(relation_sources[row] == preprocessed[4u * rows + row]);
        assert(relation_sources[rows + row] == preprocessed[5u * rows + row]);
        assert(relation_sources[2u * rows + row] == preprocessed[6u * rows + row]);
        assert(relation_sources[3u * rows + row] == main_trace[3u * rows + row]);
        assert(relation_sources[4u * rows + row] == main_trace[row]);
        assert(relation_sources[5u * rows + row] == main_trace[rows + row]);
        assert(relation_sources[6u * rows + row] == main_trace[2u * rows + row]);
    }}
    std::uint64_t digest = 1469598103934665603ull;
    for (const auto *values : {{&preprocessed, &main_trace}}) {{
        for (unsigned value : *values) {{
            for (unsigned byte = 0; byte < 4; ++byte) {{
                digest ^= (value >> (8u * byte)) & 255u;
                digest *= 1099511628211ull;
            }}
        }}
    }}
    return digest;
}}

int main() {{
    assert(run(5, 0, 0) == 0xcf7da0d42b738762ull);
    assert(run(5, 1, 1) == 0xab89862a57b689e2ull);
    assert(run(5, 2, 3) == 0x1bd0ac4c0a50a72ull);
    assert(run(5, 5, 29) == 0x4d2b41ad5c9c15bdull);
    assert(run(8, 3, 0x100000005ull) == 0x0012f26abc8dc462ull);
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness_path = root / "xor_logup_trace_aot_test.cpp"
            executable = root / "xor_logup_trace_aot_test"
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
