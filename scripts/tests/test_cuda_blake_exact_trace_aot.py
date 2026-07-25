from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"
RUNTIME_BINDING = (
    ROOT / "src/backends/cuda/runtime/traces/blake_exact.zig"
)
CPU_PREPROCESSED_SHA256 = (
    "80ce951a14d3a4fd55cbafe281d3da5b1017d1da3acbdfdb91fab3d4e0f3cefe"
)
CPU_MAIN_SHA256 = (
    "314a97333fae566653f7e9623eef1dda309e0f4891f9117d5b63fb299321165e"
)


class CudaBlakeExactTraceAotTests(unittest.TestCase):
    def test_aot_program_matches_full_cpu_geometry_and_atomic_replay(
        self,
    ) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        entry = next(
            item for item in manifest if item["label"] == "blake_exact_trace"
        )
        self.assertEqual(
            "native_blake_exact_trace_v2",
            entry["abi_schema"],
        )
        source = NATIVE_AOT / entry["file"]
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            entry["program_identity"],
        )
        runtime_source = RUNTIME_BINDING.read_text(encoding="utf-8")
        identity = re.search(
            r"pub const program_identity = \[32\]u8\{([^}]*)\};",
            runtime_source,
            re.DOTALL,
        )
        self.assertIsNotNone(identity)
        assert identity is not None
        identity_bytes = bytes(
            int(value, 16)
            for value in re.findall(r"0x([0-9a-f]{2})", identity.group(1))
        )
        self.assertEqual(32, len(identity_bytes))
        self.assertEqual(
            entry["program_identity"],
            identity_bytes.hex(),
        )

        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            harness_path = root / "blake_exact_trace_test.cpp"
            executable = root / "blake_exact_trace_test"
            preprocessed = root / "preprocessed.bin"
            main = root / "main.bin"
            harness_path.write_text(
                self._harness(source, str(entry["kernel_name"])),
                encoding="utf-8",
            )
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-O2",
                    "-pthread",
                    str(harness_path),
                    "-o",
                    str(executable),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [str(executable), str(preprocessed), str(main)],
                check=True,
            )
            self.assertEqual(
                CPU_PREPROCESSED_SHA256,
                self._sha256(preprocessed),
            )
            self.assertEqual(CPU_MAIN_SHA256, self._sha256(main))

    def test_interaction_consumes_canonical_evaluations_without_mirror(
        self,
    ) -> None:
        exact_root = ROOT / "src/integrations/native_cuda/blake/exact"
        binding = (exact_root / "resident_bindings.zig").read_text(
            encoding="utf-8"
        )
        slots = (exact_root / "slots.zig").read_text(encoding="utf-8")
        trace = RUNTIME_BINDING.read_text(encoding="utf-8")
        self.assertIn("slots.preprocessed_evaluations", binding)
        self.assertIn("slots.main_evaluations", binding)
        self.assertNotIn("relation_sources", binding)
        self.assertNotIn("relation_sources", slots)
        self.assertNotIn("relation_slab", trace)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while payload := stream.read(1024 * 1024):
                digest.update(payload)
        return digest.hexdigest()

    @staticmethod
    def _harness(source: Path, kernel_name: str) -> str:
        return f"""
#include <cassert>
#include <cstdint>
#include <fstream>
#include <thread>
#include <vector>
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static thread_local Dim3 blockIdx{{0, 0, 0}};
static thread_local Dim3 blockDim{{128, 1, 1}};
static thread_local Dim3 threadIdx{{0, 0, 0}};
inline unsigned atomicAdd(unsigned *address, unsigned value) {{
    return __atomic_fetch_add(address, value, __ATOMIC_RELAXED);
}}
#include {json.dumps(str(source))}

void write_words(
    const char *path,
    const std::vector<unsigned> &words) {{
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    assert(output.good());
    output.write(
        reinterpret_cast<const char *>(words.data()),
        static_cast<std::streamsize>(words.size() * sizeof(unsigned)));
    assert(output.good());
}}

void launch_all(
    std::vector<unsigned> *preprocessed,
    std::vector<unsigned> *main) {{
    constexpr unsigned kWorkers = 8;
    constexpr unsigned kWorkRows = 1u << 16u;
    std::vector<std::thread> workers;
    workers.reserve(kWorkers);
    for (unsigned worker = 0; worker < kWorkers; ++worker) {{
        workers.emplace_back([&, worker]() {{
            for (unsigned row = worker; row < kWorkRows; row += kWorkers) {{
                blockIdx.x = row / 128u;
                threadIdx.x = row % 128u;
                {kernel_name}(
                    preprocessed->data(),
                    preprocessed->size(),
                    main->data(),
                    main->size(),
                    4u,
                    10u);
            }}
        }});
    }}
    for (auto &worker : workers) worker.join();
}}

std::uint64_t multiplicity_sum(const std::vector<unsigned> &main) {{
    std::uint64_t result = 0;
    const std::uint64_t first = main_xor_offset(0u, 4u);
    for (std::uint64_t index = first; index < main.size(); ++index)
        result += main[index];
    return result;
}}

int main(int argc, char **argv) {{
    assert(argc == 3);
    const std::size_t preprocessed_words =
        static_cast<std::size_t>(required_preprocessed_words());
    const std::size_t main_words =
        static_cast<std::size_t>(required_main_words(4u));
    std::vector<unsigned> preprocessed(preprocessed_words, 0u);
    std::vector<unsigned> main(main_words, 0u);
    launch_all(&preprocessed, &main);
    // 2^(4+3) + 2^(4+1) round rows, each with 128 lookups.
    assert(multiplicity_sum(main) == 20480u);
    write_words(argv[1], preprocessed);
    write_words(argv[2], main);

    // Replaying without pre-zeroing proves every shared write is an unsigned
    // unit increment: nonmultiplicity cells overwrite identically and every
    // exact multiplicity doubles under real host-thread contention.
    launch_all(&preprocessed, &main);
    assert(multiplicity_sum(main) == 40960u);
}}
"""


if __name__ == "__main__":
    unittest.main()
