from __future__ import annotations

import hashlib
import json
import re
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
    validate_aot_manifest,
    write_aot_carriers,
)
from cuda_device_smoke import compile_command  # noqa: E402


SOURCE = ROOT / "src/backends/cuda/vendor/upstream"
MANIFEST = ROOT / "src/backends/cuda/source_manifest.json"
PRODUCT = ROOT / "src/backends/cuda/product_manifest.json"
NATIVE = ROOT / "src/backends/cuda/native"
NATIVE_AOT = ROOT / "src/backends/cuda/aot/native"

EXPECTED_NATIVE_IMPLEMENTATION_SOURCES = {
    "host": {
        "aot_loader.cpp",
    },
    "runtime": {
        "runtime/context.cu",
    },
    "trace": {
        "kernels/wide_fibonacci_trace.cu",
    },
    "commitment": {
        "commitment/merkle.cu",
        "commitment/progressive.cu",
    },
    "constraint": {
        "constraints/powers.cu",
    },
    "transform": {
        "transform/b2n_retained.cu",
        "transform/composition_split.cu",
        "transform/lde.cu",
        "transform/n2b.cu",
    },
    "oods": {
        "oods/barycentric.cu",
        "oods/evaluate.cu",
    },
    "transcript": {
        "transcript/transcript.cu",
    },
    "quotient": {
        "quotient/combine.cu",
        "quotient/numerator.cu",
        "quotient/prepare.cu",
    },
    "fri": {
        "fri/final.cu",
        "fri/fold.cu",
    },
    "pow": {
        "pow/search.cu",
    },
    "decommit": {
        "decommit/fri.cu",
        "decommit/query_planning.cu",
        "decommit/sparse_parents.cu",
        "decommit/trace.cu",
    },
}


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
        native = load_native_closure(NATIVE)
        actual_sources = {
            path.relative_to(NATIVE.resolve()).as_posix()
            for path in native["sources"]
        }
        expected_sources = set().union(*EXPECTED_NATIVE_IMPLEMENTATION_SOURCES.values())
        self.assertEqual("stwo-zig-cuda-native-build-v1", plan["schema"])
        self.assertEqual([86, 90], plan["target_sms"])
        self.assertEqual(59, plan["authority_ordinary_source_count"])
        self.assertEqual(340, plan["authority_aot_source_count"])
        self.assertEqual(0, plan["ordinary_source_count"])
        self.assertEqual(1, plan["aot_source_count"])
        self.assertEqual(2, plan["aot_cubin_count"])
        self.assertEqual(expected_sources, actual_sources)
        self.assertEqual(len(native["sources"]), plan["native_runtime_source_count"])
        self.assertEqual(len(native["host_sources"]), plan["native_host_source_count"])
        self.assertEqual(len(native["cuda_sources"]), plan["native_cuda_source_count"])
        self.assertEqual(1, len(native["host_sources"]))
        self.assertEqual(
            len(expected_sources) - 1,
            len(native["cuda_sources"]),
        )
        self.assertEqual(
            native["closure_sha256"],
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
        self.assertIn("-c", plan["fixed_flags"]["native_cuda"])
        self.assertNotIn("-dc", plan["fixed_flags"]["native_cuda"])
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

    def test_fused_transforms_are_structural_exact_and_telemetry_bound(self) -> None:
        schedules = (
            NATIVE / "transform" / "transform_internal.cuh"
        ).read_text(encoding="utf-8")
        b2n = (NATIVE / "transform" / "b2n_retained.cu").read_text(
            encoding="utf-8"
        )
        n2b = (NATIVE / "transform" / "n2b.cu").read_text(encoding="utf-8")
        abi = (ROOT / "src/backends/cuda/abi/stages/transform.zig").read_text(
            encoding="utf-8"
        )
        self.assertIn("kFirstFusedLogN = 13", schedules)
        self.assertIn("kLastFusedLogN = 23", schedules)
        self.assertIn("schedules_are_exact()", schedules)
        self.assertIn("b2n_stage<false>", b2n)
        self.assertIn("n2b_stage<<<", n2b)
        self.assertIn("kFirstFusedLogN", b2n)
        self.assertIn("kFirstFusedLogN", n2b)
        self.assertNotIn("wide_fibonacci", (schedules + b2n + n2b).lower())
        self.assertEqual(4, abi.count("launches_out: *u32"))

    def test_device_header_definitions_have_internal_or_inline_linkage(self) -> None:
        violations: list[str] = []
        definition = re.compile(r"^__device__\s+")
        for path in sorted(NATIVE.rglob("*.cuh")):
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if not definition.match(line):
                    continue
                previous = lines[index - 1].strip() if index else ""
                if (
                    "static" not in line
                    and "inline" not in line
                    and "__forceinline__" not in line
                    and not previous.startswith("template ")
                ):
                    violations.append(
                        f"{path.relative_to(NATIVE)}:{index + 1}"
                    )
        self.assertEqual([], violations)

    def test_architecture_parser_is_canonical_and_fail_closed(self) -> None:
        self.assertEqual((86, 89, 90), normalize_sms(["sm_90,86", "89"]))
        for invalid in ([], [""], ["native"], ["compute_90"], ["sm_9"]):
            with self.assertRaises(BuildError):
                normalize_sms(invalid)

    def test_device_smoke_link_is_explicit_and_archive_bound(self) -> None:
        command = compile_command(
            Path("/usr/bin/c++"),
            Path("/repo/tests/cuda/native_test_smoke.cpp"),
            Path("/out/native_test_smoke"),
            Path("/out/libstwo_cuda_kernels.a"),
            Path("/usr/local/cuda"),
        )
        self.assertEqual("/usr/bin/c++", command[0])
        self.assertIn("/out/libstwo_cuda_kernels.a", command)
        self.assertIn("-L/usr/local/cuda/lib64", command)
        self.assertIn("-Wl,-rpath,/usr/local/cuda/lib64", command)
        self.assertIn("-lcudart", command)
        self.assertIn("-lcuda", command)
        self.assertEqual("/out/native_test_smoke", command[-1])

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
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(1, len(manifest))
        self.assertEqual("native_constraint_slab_v1", manifest[0]["abi_schema"])
        self.assertEqual(
            "sha256-source-and-contract-v1",
            manifest[0]["identity_scheme"],
        )
        source = NATIVE_AOT / manifest[0]["file"]
        self.assertEqual(source.name, manifest[0]["file"])
        self.assertEqual(
            hashlib.sha256(source.read_bytes()).hexdigest(),
            manifest[0]["program_identity"],
        )
        self.assertNotIn("const unsigned *const *", source.read_text(encoding="utf-8"))
        validate_aot_manifest(NATIVE_AOT, manifest)
        kernel_name = manifest[0]["kernel_name"]
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
    unsigned trace_slab[18] = {{
        3, 3, 0, 0,
        4, 4, 0, 0,
        26, 26, 0, 0,
        694, 694, 0, 0,
        482315, 482315
    }};
    unsigned powers[12] = {{
        1, 2, 3, 4,
        5, 6, 7, 8,
        9, 10, 11, 12
    }};
    unsigned denom[2] = {{2, 3}};
    unsigned coordinates[14] = {{}};
    for (unsigned row = 0; row < 2; ++row) {{
        threadIdx.x = row;
        {kernel_name}(
            trace_slab, 18, 4, 5, powers, 12, denom, 2,
            coordinates, 14, 4, 2, 0, 0);
    }}
    assert(coordinates[0] == 44 && coordinates[1] == 66);
    assert(coordinates[4] == 56 && coordinates[5] == 84);
    assert(coordinates[8] == 68 && coordinates[9] == 102);
    assert(coordinates[12] == 80 && coordinates[13] == 120);
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

    def test_native_aot_identity_rejects_source_or_contract_drift(self) -> None:
        manifest = json.loads(
            (NATIVE_AOT / "aot_manifest.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = NATIVE_AOT / manifest[0]["file"]
            shutil.copy2(source, root / source.name)
            validate_aot_manifest(root, manifest)

            (root / source.name).write_bytes(source.read_bytes() + b"\\n")
            with self.assertRaisesRegex(BuildError, "stale Native identities"):
                validate_aot_manifest(root, manifest)

            shutil.copy2(source, root / source.name)
            changed = json.loads(json.dumps(manifest))
            changed[0]["semantic_contract"] += ";changed"
            with self.assertRaisesRegex(BuildError, "stale Native identities"):
                validate_aot_manifest(root, changed)

    def test_constraint_power_expansion_matches_zig_vector(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        source = NATIVE / "constraints/powers.cu"
        harness = f"""
#include <cassert>
#define STWO_CUDA_HOST_TEST
#define __host__
#define __device__
#define __forceinline__ inline
#define __global__
#include {json.dumps(str(source))}

int main() {{
    using namespace stwo::cuda::constraints;
    const QM31 alpha{{{{2, 3}}, {{5, 7}}}};
    QM31 actual[9] = {{}};
    expand_powers(alpha, actual, 9);
    const QM31 expected[9] = {{
        {{{{1, 0}}, {{0, 0}}}},
        {{{{2, 3}}, {{5, 7}}}},
        {{{{2147483524u, 128}}, {{2147483625u, 58}}}},
        {{{{2147481849u, 2147483290u}}, {{2147481918u, 2147483476u}}}},
        {{{{2147479184u, 2147444175u}}, {{2147474211u, 2147463747u}}}},
        {{{{459282u, 2147152330u}}, {{294817u, 2147186938u}}}},
        {{{{8434437u, 5426608u}}, {{6095390u, 1849422u}}}},
        {{{{2131219849u, 157517203u}}, {{10828443u, 108159113u}}}},
        {{{{1767350271u, 796460768u}}, {{660723783u, 922542984u}}}},
    }};
    for (unsigned index = 0; index < 9; ++index) {{
        assert(actual[index].first.real == expected[index].first.real);
        assert(actual[index].first.imag == expected[index].first.imag);
        assert(actual[index].second.real == expected[index].second.real);
        assert(actual[index].second.imag == expected[index].second.imag);
    }}
}}
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            harness_path = root / "constraint_power_test.cpp"
            executable = root / "constraint_power_test"
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
    constexpr unsigned stride = 2 * rows;
    unsigned trace[stride * columns];
    for (unsigned &word : trace) word = 0xa5a5a5a5u;
    for (unsigned row = 0; row < rows; ++row) {{
        threadIdx.x = row;
        stwo_native_wide_fibonacci_trace_kernel(
            trace, stride, rows, columns, 3);
    }}
    const unsigned logical_rows[rows] = {{0, 7, 4, 3, 2, 5, 6, 1}};
    for (unsigned row = 0; row < rows; ++row) {{
        unsigned previous = 1;
        unsigned current = logical_rows[row];
        assert(trace[row] == previous);
        assert(trace[stride + row] == current);
        for (unsigned column = 2; column < columns; ++column) {{
            const unsigned next = stwo_trace_m31_add(
                stwo_trace_m31_mul(previous, previous),
                stwo_trace_m31_mul(current, current));
            assert(trace[column * stride + row] == next);
            previous = current;
            current = next;
        }}
    }}
    for (unsigned column = 0; column < columns; ++column) {{
        for (unsigned row = rows; row < stride; ++row) {{
            assert(trace[column * stride + row] == 0xa5a5a5a5u);
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
