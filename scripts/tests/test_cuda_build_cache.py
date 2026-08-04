"""End-to-end Zig cache coverage for the Native CUDA build command."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class CudaBuildCacheTests(unittest.TestCase):
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
