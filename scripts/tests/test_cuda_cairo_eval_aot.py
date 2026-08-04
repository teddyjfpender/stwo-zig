from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CAIRO_EVAL_AOT = (
    ROOT / "src/backends/cuda/aot/native/cairo_eval"
)
PARITY_FIXTURE = (
    ROOT / "tests/cuda/fixtures/cairo_eval_sn2_parity_fixture.h"
)
PARITY_SMOKE = ROOT / "tests/cuda/native_cairo_eval_sn2_parity_smoke.cpp"


class CudaCairoEvalAotTests(unittest.TestCase):
    def manifest(self) -> list[dict[str, object]]:
        return json.loads(
            (CAIRO_EVAL_AOT / "aot_manifest.json").read_text(
                encoding="utf-8"
            )
        )

    def test_exact_sn2_product_inventory_is_authenticated(self) -> None:
        manifest = self.manifest()
        self.assertEqual(271, len(manifest))
        self.assertEqual(
            279,
            sum(len(entry["occurrences"]) for entry in manifest),
        )
        self.assertTrue(
            all(
                entry["abi_schema"] == "cairo_eval_part_v1"
                and entry["module_globals"] == "none"
                and entry["codegen_version"] == 1
                for entry in manifest
            )
        )

    def test_checkout_retains_only_the_authenticated_manifest(self) -> None:
        self.assertEqual([], list(CAIRO_EVAL_AOT.glob("*.cu")))
        self.assertEqual(
            ["aot_manifest.json"],
            sorted(path.name for path in CAIRO_EVAL_AOT.iterdir()),
        )

    def test_sn2_parity_fixture_and_strict_aot_smoke_are_pinned(self) -> None:
        fixture_bytes = PARITY_FIXTURE.read_bytes()
        self.assertEqual(
            "583a9d20b8f540c71d8840f9025122dd"
            "1b022fa11b7ae3a374e161016c1cea20",
            hashlib.sha256(fixture_bytes).hexdigest(),
        )
        fixture_source = fixture_bytes.decode("utf-8")
        self.assertIn("constexpr std::uint32_t kFixtureRows = 4u;", fixture_source)
        self.assertIn("constexpr std::size_t kPlacementCount =", fixture_source)
        self.assertIn("constexpr std::size_t kComponentCount =", fixture_source)

        smoke = PARITY_SMOKE.read_text(encoding="utf-8")
        self.assertIn("fixture::kPlacementCount == 279", smoke)
        self.assertIn("fixture::kComponentCount == 58", smoke)
        self.assertIn("kExpectedAotLoads = 271", smoke)
        self.assertIn("stwo_native_aot_function_bind_with_globals", smoke)
        self.assertIn("STWO_NATIVE_AOT_MODULE_GLOBALS_NONE", smoke)
        self.assertIn("stats.aot_misses != 0", smoke)
        self.assertIn("runtime_compiles=0", smoke)
        self.assertIn("cpu_fallbacks=0", smoke)
        self.assertNotIn("nvrtc", smoke.lower())

    def test_sn2_parity_smoke_compiles_without_cuda_toolkit(self) -> None:
        compiler = shutil.which("c++")
        if compiler is None:
            self.skipTest("C++ compiler unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "cuda_runtime_api.h").write_text(
                "\n".join(
                    (
                        "#ifndef CUDA_RUNTIME_API_H",
                        "#define CUDA_RUNTIME_API_H",
                        "typedef int cudaError_t;",
                        'extern "C" const char *cudaGetErrorString(cudaError_t);',
                        "#endif",
                        "",
                    )
                ),
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-I",
                    str(root),
                    "-c",
                    str(PARITY_SMOKE),
                    "-o",
                    str(root / "parity-smoke.o"),
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)


if __name__ == "__main__":
    unittest.main()
