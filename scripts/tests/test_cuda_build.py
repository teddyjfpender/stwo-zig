from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from cuda_build_lib.builder import (  # noqa: E402
    BuildConfig,
    BuildError,
    Toolchain,
    aot_compile_command,
    build_plan,
    load_native_closure,
    load_product_selection,
    load_source_closure,
    normalize_sms,
    write_aot_carriers,
)


SOURCE = ROOT / "src/backends/cuda/vendor/upstream"
MANIFEST = ROOT / "src/backends/cuda/source_manifest.json"
PRODUCT = ROOT / "src/backends/cuda/product_manifest.json"
NATIVE = ROOT / "src/backends/cuda/native"
NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"


class CudaBuildTests(unittest.TestCase):
    def config(self, output: Path) -> BuildConfig:
        return BuildConfig(
            source_root=SOURCE,
            source_manifest=MANIFEST,
            product_manifest=PRODUCT,
            native_root=NATIVE,
            native_aot_root=NATIVE_AOT,
            output_dir=output,
            toolchain=Toolchain(
                nvcc=Path("/opt/cuda/bin/nvcc"),
                host_cxx=Path("/usr/bin/c++"),
                archiver=Path("/usr/bin/ar"),
                cuda_home=Path("/opt/cuda"),
                cuda_library_dir=Path("/opt/cuda/lib64"),
                sms=(86, 90),
                jobs=3,
            ),
        )

    def test_imported_closure_and_aot_manifest_are_exact(self) -> None:
        closure = load_source_closure(SOURCE, MANIFEST)
        self.assertEqual(59, len(closure.ordinary_sources))
        self.assertEqual(340, len(closure.generated_sources))
        self.assertTrue(all("generated" not in path.parts for path in closure.ordinary_sources))
        self.assertTrue(all(path.is_file() for path in closure.generated_sources))

    def test_plan_is_explicit_and_does_not_probe_tools(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = build_plan(self.config(Path(temporary)), probe_tools=False)
        self.assertEqual("stwo-zig-cuda-native-build-v1", plan["schema"])
        self.assertEqual([86, 90], plan["target_sms"])
        self.assertEqual(59, plan["authority_ordinary_source_count"])
        self.assertEqual(340, plan["authority_aot_source_count"])
        self.assertEqual(37, plan["ordinary_source_count"])
        self.assertEqual(1, plan["aot_source_count"])
        self.assertEqual(2, plan["aot_cubin_count"])
        self.assertEqual(2, plan["native_runtime_source_count"])
        self.assertEqual(1, plan["native_host_source_count"])
        self.assertEqual(1, plan["native_cuda_source_count"])
        self.assertEqual(
            load_native_closure(NATIVE)["closure_sha256"],
            plan["native_runtime_closure_sha256"],
        )
        authority = load_source_closure(SOURCE, MANIFEST)
        product = load_product_selection(self.config(Path(temporary)), authority)
        self.assertEqual(
            product.aot_closure_sha256,
            plan["native_aot_closure_sha256"],
        )
        self.assertEqual("plan-only", plan["tools"]["nvcc"]["sha256"])
        self.assertIn("-dc", plan["fixed_flags"]["ordinary"])
        self.assertIn("-dc", plan["fixed_flags"]["native_cuda"])
        self.assertIn("-cubin", plan["fixed_flags"]["aot"])
        self.assertIn("-dlink", plan["fixed_flags"]["device_link"])
        self.assertNotIn("nvrtc", plan["fixed_flags"]["host"])

    def test_native_aot_source_bytes_change_the_build_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            native_aot = root / "aot"
            native_aot.mkdir()
            source = native_aot / "constraint_test_0000000000000005.cu"
            source.write_text("extern \"C\" __global__ void test() {}\n", encoding="utf-8")
            manifest = [{
                "kind": "constraint",
                "label": "test",
                "abi_schema": "ordinary_constraint_v1",
                "kernel_name": "test",
                "cache_key": "0000000000000005",
                "semantic_hash": "0000000000000006",
                "program_identity": "07" * 32,
                "file": source.name,
            }]
            (native_aot / "aot_manifest.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            original = self.config(root / "output")
            config = BuildConfig(
                source_root=original.source_root,
                source_manifest=original.source_manifest,
                product_manifest=original.product_manifest,
                native_root=original.native_root,
                native_aot_root=native_aot,
                output_dir=original.output_dir,
                toolchain=original.toolchain,
            )
            before = build_plan(config, probe_tools=False)
            source.write_text(
                "extern \"C\" __global__ void test() { asm(\"nop;\"); }\n",
                encoding="utf-8",
            )
            after = build_plan(config, probe_tools=False)
        self.assertNotEqual(
            before["native_aot_closure_sha256"],
            after["native_aot_closure_sha256"],
        )
        self.assertNotEqual(
            before["build_identity_sha256"],
            after["build_identity_sha256"],
        )

    def test_native_runtime_has_no_jit_or_cpu_fallback_surface(self) -> None:
        closure = load_native_closure(NATIVE)
        sources = "\n".join(
            path.read_text(encoding="utf-8")
            for path in closure["sources"]
        )
        self.assertIn("stwo_native_aot_function_launch", sources)
        self.assertNotIn("#include <nvrtc", sources.lower())
        self.assertNotIn("nvrtccompile", sources.lower())
        self.assertNotIn("fallback(", sources.lower())
        self.assertNotIn("getenv(", sources)
        self.assertNotIn("system(", sources)

    def test_architecture_parser_is_canonical_and_fail_closed(self) -> None:
        self.assertEqual((86, 89, 90), normalize_sms(["sm_90,86", "89"]))
        for invalid in ([], [""], ["native"], ["compute_90"], ["sm_9"]):
            with self.assertRaises(BuildError):
                normalize_sms(invalid)

    def test_aot_carrier_is_binary_search_and_exact_arch_only(self) -> None:
        entries = [
            {
                "cache_key": 5,
                "sm": 90,
                "offset": 0,
                "bytes": 4,
                "abi_schema": 1,
                "kernel_name": "test_kernel",
            }
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack.bin"
            pack.write_bytes(b"cbin")
            assembly, lookup = write_aot_carriers(entries, pack, root)
            assembly_source = assembly.read_text(encoding="utf-8")
            lookup_source = lookup.read_text(encoding="utf-8")
        self.assertIn('.incbin "', assembly_source)
        self.assertIn("stwo_aot_lookup", lookup_source)
        self.assertIn("entry.sm != sm", lookup_source)
        self.assertIn("entry.abi_schema != abi_schema", lookup_source)
        self.assertIn("std::strcmp(entry.kernel_name, kernel_name)", lookup_source)
        self.assertNotIn("nvrtc", lookup_source.lower())

    def test_empty_native_aot_pack_is_standard_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pack = root / "pack.bin"
            pack.write_bytes(b"")
            _, lookup = write_aot_carriers([], pack, root)
            source = lookup.read_text(encoding="utf-8")
        self.assertIn("constexpr std::size_t kEntryCount = 0;", source)
        self.assertIn("if (low == kEntryCount) return false;", source)
        self.assertNotIn("kEntries[] = {\n};", source)

    def test_sm90_poseidon_chain_preserves_upstream_ptxas_policy(self) -> None:
        toolchain = self.config(Path("/tmp/output")).toolchain
        poseidon = Path(
            "witness_poseidon_3_partial_rounds_chain_0123456789abcdef.cu"
        )
        ordinary = Path("composition_0123456789abcdef.cu")
        self.assertIn(
            "-Xptxas=-O0",
            aot_compile_command(toolchain, poseidon, Path("out.cubin"), 90),
        )
        self.assertNotIn(
            "-Xptxas=-O0",
            aot_compile_command(toolchain, poseidon, Path("out.cubin"), 86),
        )
        self.assertNotIn(
            "-Xptxas=-O0",
            aot_compile_command(toolchain, ordinary, Path("out.cubin"), 90),
        )

    def test_native_wide_fibonacci_aot_matches_scalar_recurrence(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        source = NATIVE_AOT / "constraint_wide_fibonacci_b0108a05e4de93ca.cu"
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(1, len(manifest))
        self.assertEqual("ordinary_constraint_v1", manifest[0]["abi_schema"])
        self.assertEqual(source.name, manifest[0]["file"])
        harness = f"""
#include <cassert>
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static Dim3 blockIdx{{0, 0, 0}}, blockDim{{128, 1, 1}}, threadIdx{{0, 0, 0}};
#include {json.dumps(str(source))}

int main() {{
    unsigned c0[2] = {{3, 3}};
    unsigned c1[2] = {{4, 4}};
    unsigned c2[2] = {{26, 26}};
    unsigned c3[2] = {{694, 694}};
    unsigned c4[2] = {{482315, 482315}};
    const unsigned *columns[] = {{c0, c1, c2, c3, c4}};
    unsigned offsets[3] = {{0, 0, 5}};
    unsigned base_params[1] = {{5}};
    unsigned ext_params[1] = {{0}};
    unsigned powers[12] = {{
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12
    }};
    unsigned denom[2] = {{2, 3}};
    unsigned out0[2] = {{0, 0}}, out1[2] = {{0, 0}};
    unsigned out2[2] = {{0, 0}}, out3[2] = {{0, 0}};
    for (unsigned row = 0; row < 2; ++row) {{
        threadIdx.x = row;
        stwo_jit_fused_4a5dad552ce2c7ae(
            columns, offsets, base_params, ext_params, powers, denom,
            out0, out1, out2, out3, 2, 0, 0);
    }}
    assert(out0[0] == 76 && out0[1] == 114);
    assert(out1[0] == 88 && out1[1] == 132);
    assert(out2[0] == 100 && out2[1] == 150);
    assert(out3[0] == 112 && out3[1] == 168);
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness_path = root / "wide_fibonacci_aot_test.cpp"
            executable = root / "wide_fibonacci_aot_test"
            harness_path.write_text(harness, encoding="utf-8")
            subprocess.run(
                [compiler, "-std=c++17", "-O2", str(harness_path), "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_native_wide_fibonacci_trace_matches_canonical_layout(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        source = NATIVE / "kernels/wide_fibonacci_trace.cu"
        harness = f"""
#include <cassert>
#define STWO_CUDA_HOST_TEST
#define __device__
#define __global__
#define __forceinline__ inline
#define __launch_bounds__(...)
struct Dim3 {{ unsigned x, y, z; }};
static Dim3 blockIdx{{0, 0, 0}}, blockDim{{8, 1, 1}}, threadIdx{{0, 0, 0}};
#include {json.dumps(str(source))}

int main() {{
    constexpr unsigned rows = 8;
    constexpr unsigned columns = 5;
    unsigned trace[rows * columns] = {{}};
    for (unsigned row = 0; row < rows; ++row) {{
        threadIdx.x = row;
        stwo_native_wide_fibonacci_trace_kernel(trace, rows, columns, 3);
    }}
    const unsigned logical_rows[rows] = {{0, 7, 4, 3, 2, 5, 6, 1}};
    for (unsigned row = 0; row < rows; ++row) {{
        unsigned previous = 1;
        unsigned current = logical_rows[row];
        assert(trace[row] == previous);
        assert(trace[rows + row] == current);
        for (unsigned column = 2; column < columns; ++column) {{
            const unsigned next = stwo_trace_m31_add(
                stwo_trace_m31_mul(previous, previous),
                stwo_trace_m31_mul(current, current));
            assert(trace[column * rows + row] == next);
            previous = current;
            current = next;
        }}
    }}
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness_path = root / "wide_fibonacci_trace_test.cpp"
            executable = root / "wide_fibonacci_trace_test"
            harness_path.write_text(harness, encoding="utf-8")
            subprocess.run(
                [compiler, "-std=c++17", "-O2", str(harness_path), "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_source_manifest_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            copied = root / "cuda"
            copied.mkdir()
            (copied / "one.cu").write_text("int x;\n", encoding="utf-8")
            manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
            local_manifest = root / "manifest.json"
            local_manifest.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(BuildError):
                load_source_closure(copied, local_manifest)


if __name__ == "__main__":
    unittest.main()
