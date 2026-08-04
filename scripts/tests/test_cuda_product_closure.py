from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import cuda_product_closure as closure  # noqa: E402
from cuda_build_lib.builder import (  # noqa: E402
    BuildConfig,
    Toolchain,
    build_plan,
    compile_native_cuda,
    load_source_closure,
)


CUDA_ROOT = ROOT / "src/backends/cuda"
SOURCE = (
    CUDA_ROOT
    / "vendor/host_authority/crates/backend-cuda-kernels/cuda"
)
NATIVE = CUDA_ROOT / "native"


class CudaProductClosureTests(unittest.TestCase):
    def fixture(self, root: Path, *, define_active: bool) -> dict[str, Path]:
        paths = {
            "abi": root / "abi",
            "native": root / "native",
            "source": root / "source",
            "host_authority": root / "host_authority",
            "runtime_stages": root / "runtime" / "stages",
        }
        for path in paths.values():
            path.mkdir(parents=True)
        (paths["abi"] / "stages").mkdir()
        (paths["abi"] / "stages" / "proof.zig").write_text(
            'pub extern "c" fn stwo_active() callconv(.c) i32;\n',
            encoding="utf-8",
        )
        (paths["runtime_stages"] / "proof.zig").write_text(
            "const launch = abi.stwo_active;\n",
            encoding="utf-8",
        )
        (paths["host_authority"] / "raw.rs").write_text(
            "extern \"C\" {\n    pub fn stwo_active() -> i32;\n}\n",
            encoding="utf-8",
        )
        native_source = 'extern "C" int stwo_active() { return 0; }\n'
        if not define_active:
            native_source = 'extern "C" int stwo_other() { return 0; }\n'
        (paths["native"] / "proof.cu").write_text(native_source, encoding="utf-8")
        return paths

    def policy(self) -> dict[str, object]:
        return {
            "abi": {
                "rust_authority": "raw.rs",
                "generated_symbols": [],
                "zig_owned_symbols": [],
                "staged_stage_modules": [],
                "forbidden_symbol_fragments": ["_legacy_"],
            },
            "forbidden_product_tokens": ["cudaDeviceSynchronize("],
        }

    def ordinary(self) -> dict[str, object]:
        return {
            "product_sources": [],
            "resident_candidates": [],
        }

    def validate_fixture(
        self,
        paths: dict[str, Path],
    ) -> dict[str, int]:
        with mock.patch.multiple(
            closure,
            ABI=paths["abi"],
            NATIVE=paths["native"],
            SOURCE=paths["source"],
            HOST_AUTHORITY=paths["host_authority"],
            RUNTIME_STAGES=paths["runtime_stages"],
        ):
            return closure.validate_abi(self.policy(), self.ordinary())

    def test_zero_staged_modules_is_valid_when_every_symbol_is_implemented(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary), define_active=True)
            result = self.validate_fixture(paths)
        self.assertEqual(1, result["active_symbols"])
        self.assertEqual(0, result["staged_symbols"])
        self.assertEqual(1, result["wrapped_stage_symbols"])

    def test_zero_staged_modules_rejects_an_unimplemented_active_symbol(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = self.fixture(Path(temporary), define_active=False)
            with self.assertRaisesRegex(
                closure.ProductClosureError,
                "no selected implementation.*stwo_active",
            ):
                self.validate_fixture(paths)

    def test_current_unsafe_five_source_selection_is_rejected(self) -> None:
        product = closure.read_json(closure.PRODUCT_MANIFEST)
        self.assertIsInstance(product, dict)
        unsafe_sources = [
            closure.SOURCE / name
            for name in (
                "batch_inverse.cu",
                "cuda_mem_pool.cu",
                "prefix_sum.cu",
                "relation_graph.cu",
                "utils.cu",
            )
        ]
        with self.assertRaisesRegex(
            closure.ProductClosureError,
            "forbidden API/token policy.*cuda_mem_pool.cu",
        ):
            closure.validate_product_policy(product, unsafe_sources, [])

    def test_product_policy_scans_native_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "legacy.cu"
            source.write_text(
                'extern "C" int stwo_legacy_copy() { return 0; }\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                closure.ProductClosureError,
                "forbidden symbols.*stwo_legacy_copy",
            ):
                closure.validate_product_policy(self.policy(), [], [source])

    def test_relation_tus_use_independent_native_compile_commands(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            config = BuildConfig(
                source_root=SOURCE,
                source_manifest=CUDA_ROOT / "source_manifest.json",
                product_manifest=CUDA_ROOT / "product_manifest.json",
                native_root=NATIVE,
                native_aot_root=CUDA_ROOT / "aot/native",
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
            source_closure = load_source_closure(
                SOURCE,
                CUDA_ROOT / "source_manifest.json",
            )
            plan = build_plan(config, probe_tools=False)
            with mock.patch(
                "cuda_build_lib.builder.run_parallel"
            ) as run_parallel:
                compile_native_cuda(config, source_closure, plan, output)

        jobs, job_count = run_parallel.call_args.args
        self.assertEqual(3, job_count)
        relation_commands = {
            Path(command[-3]).relative_to(NATIVE).as_posix(): command
            for command, _destination in jobs
            if Path(command[-3]).is_relative_to(NATIVE / "relation")
        }
        self.assertEqual(
            {"relation/batch_inverse.cu", "relation/graph.cu"},
            set(relation_commands),
        )
        for command in relation_commands.values():
            self.assertEqual(str(config.toolchain.nvcc), command[0])
            self.assertIn("-c", command)
            self.assertNotIn("-dc", command)
            self.assertIn("--std=c++17", command)


if __name__ == "__main__":
    unittest.main()
