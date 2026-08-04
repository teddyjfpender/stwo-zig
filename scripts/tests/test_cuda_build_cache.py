"""End-to-end Zig cache coverage for the Native CUDA build command."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from dataclasses import replace
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from cuda_build_lib.builder import (  # noqa: E402
    BuildConfig,
    BuildError,
    Toolchain,
    build_plan,
)


CUDA_ROOT = ROOT / "src/backends/cuda"
NATIVE = CUDA_ROOT / "native"
NATIVE_AOT = CUDA_ROOT / "aot/native"


class CudaBuildCacheTests(unittest.TestCase):
    def test_generated_aot_set_must_match_its_pinned_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / "cuda/aot/native"
            shutil.copytree(NATIVE_AOT, generated)
            shutil.copytree(NATIVE, root / "cuda/native")
            config = replace(
                self._config(root / "output"),
                aot_set_roots=((".", generated),),
            )
            build_plan(config, probe_tools=False)

            manifest = generated / "aot_manifest.json"
            decoded = json.loads(manifest.read_text(encoding="utf-8"))
            decoded[0]["cache_key"] = "0000000000000001"
            manifest.write_text(json.dumps(decoded), encoding="utf-8")
            with self.assertRaisesRegex(
                BuildError,
                "generated CUDA AOT product-set manifest differs from its pin",
            ):
                build_plan(config, probe_tools=False)

    def test_native_cuda_source_and_header_changes_invalidate_the_plan(self) -> None:
        zig = shutil.which("zig")
        if zig is None:
            self.skipTest("Zig compiler unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._seed_project(project)
            cache = project / "cache"

            self._run_plan(zig, project, cache)
            initial = self._plan_outputs(cache)
            self.assertEqual(1, len(initial))

            self._run_plan(zig, project, cache)
            self.assertEqual(initial, self._plan_outputs(cache))

            header = project / "src/backends/cuda/native/commitment/blake2s_core.cuh"
            header.write_bytes(header.read_bytes() + b"\n// cache-invalidation-header\n")
            self._run_plan(zig, project, cache)
            after_header = self._plan_outputs(cache)
            self.assertEqual(2, len(after_header))
            self.assertTrue(initial < after_header)

            source = project / "src/backends/cuda/native/commitment/merkle.cu"
            source.write_bytes(source.read_bytes() + b"\n// cache-invalidation-source\n")
            self._run_plan(zig, project, cache)
            after_source = self._plan_outputs(cache)
            self.assertEqual(3, len(after_source))
            self.assertTrue(after_header < after_source)

    @staticmethod
    def _seed_project(project: Path) -> None:
        build_support = project / "build_support/backends"
        build_support.mkdir(parents=True)
        shutil.copy2(
            ROOT / "build_support/backends/cuda.zig",
            build_support / "cuda.zig",
        )
        (project / "build.zig").write_text(
            textwrap.dedent(
                """
                const std = @import("std");
                const cuda = @import("build_support/backends/cuda.zig");

                pub fn build(b: *std.Build) void {
                    const plan = cuda.addPlan(b, .{
                        .nvcc = "/cuda/bin/nvcc",
                        .host_cxx = "/usr/bin/c++",
                        .archiver = "/usr/bin/ar",
                        .cuda_home = "/cuda",
                        .library_dir = "/cuda/lib64",
                        .architectures = "sm_90",
                    });
                    b.step("plan", "Build the CUDA plan").dependOn(&plan.step);
                }
                """
            ).lstrip(),
            encoding="utf-8",
        )

        scripts = project / "scripts"
        scripts.mkdir()
        (scripts / "cuda_build.py").symlink_to(ROOT / "scripts/cuda_build.py")
        (scripts / "cuda_build_lib").symlink_to(
            ROOT / "scripts/cuda_build_lib",
            target_is_directory=True,
        )

        cuda_root = project / "src/backends/cuda"
        cuda_root.mkdir(parents=True)
        (cuda_root / "source_manifest.json").symlink_to(
            ROOT / "src/backends/cuda/source_manifest.json"
        )
        (cuda_root / "product_manifest.json").symlink_to(
            ROOT / "src/backends/cuda/product_manifest.json"
        )
        authority = (
            cuda_root
            / "vendor/host_authority/crates/backend-cuda-kernels"
        )
        authority.mkdir(parents=True)
        (authority / "cuda").symlink_to(
            ROOT
            / "src/backends/cuda/vendor/host_authority"
            / "crates/backend-cuda-kernels/cuda",
            target_is_directory=True,
        )
        shutil.copytree(
            ROOT / "src/backends/cuda/native",
            cuda_root / "native",
        )
        aot = cuda_root / "aot"
        aot.mkdir()
        (aot / "native").symlink_to(
            ROOT / "src/backends/cuda/aot/native",
            target_is_directory=True,
        )

    @staticmethod
    def _config(output: Path) -> BuildConfig:
        return BuildConfig(
            source_root=CUDA_ROOT / "vendor/host_authority/crates/backend-cuda-kernels/cuda",
            source_manifest=CUDA_ROOT / "source_manifest.json",
            product_manifest=CUDA_ROOT / "product_manifest.json",
            native_root=NATIVE,
            native_aot_root=NATIVE_AOT,
            output_dir=output,
            toolchain=Toolchain(
                nvcc=Path("/opt/cuda/bin/nvcc"),
                host_cxx=Path("/usr/bin/c++"),
                archiver=Path("/usr/bin/ar"),
                cuda_home=Path("/opt/cuda"),
                cuda_library_dir=Path("/opt/cuda/lib64"),
                sms=(90,),
                jobs=1,
            ),
        )

    @staticmethod
    def _run_plan(zig: str, project: Path, cache: Path) -> None:
        completed = subprocess.run(
            [zig, "build", "plan", "--cache-dir", str(cache)],
            cwd=project,
            text=True,
            capture_output=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(
                f"CUDA plan build failed:\n{completed.stdout}\n{completed.stderr}"
            )

    @staticmethod
    def _plan_outputs(cache: Path) -> set[Path]:
        return set(cache.glob("o/*/stwo-native-cuda-plan"))


if __name__ == "__main__":
    unittest.main()
