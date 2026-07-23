from __future__ import annotations

import json
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
        self.assertEqual(0, plan["aot_source_count"])
        self.assertEqual(0, plan["aot_cubin_count"])
        self.assertEqual(1, plan["native_runtime_source_count"])
        self.assertEqual(
            load_native_closure(NATIVE)["closure_sha256"],
            plan["native_runtime_closure_sha256"],
        )
        self.assertEqual("plan-only", plan["tools"]["nvcc"]["sha256"])
        self.assertIn("-dc", plan["fixed_flags"]["ordinary"])
        self.assertIn("-cubin", plan["fixed_flags"]["aot"])
        self.assertIn("-dlink", plan["fixed_flags"]["device_link"])
        self.assertNotIn("nvrtc", plan["fixed_flags"]["host"])

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
