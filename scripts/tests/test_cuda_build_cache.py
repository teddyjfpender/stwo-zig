"""End-to-end Zig cache coverage for the Native CUDA build command."""

from __future__ import annotations

import json
import hashlib
import os
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
from scripts.tests.cuda_native_aot_fixture import native_aot_root  # noqa: E402


CUDA_ROOT = ROOT / "src/backends/cuda"
NATIVE = CUDA_ROOT / "native"
NATIVE_AOT = native_aot_root()


class CudaBuildCacheTests(unittest.TestCase):
    def test_imported_manifest_and_cubin_are_outer_zig_cache_inputs(self) -> None:
        zig = shutil.which('zig')
        if zig is None:
            self.skipTest('Zig compiler unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            self._seed_project(project)
            cache = project / 'cache'
            bundle = project / 'imported'
            bundle.mkdir()
            metadata = next(e for e in json.loads((NATIVE_AOT/'aot_manifest.json').read_text())
                            if e['label'] == 'constant_qm31')
            header = bytearray(64)
            header[:6] = b'\x7fELF\x02\x01'
            header[18:20] = (190).to_bytes(2, 'little')
            artifact = bundle / 'unit.cubin'
            artifact.write_bytes(header)
            entry = {key: metadata[key] for key in ('cache_key', 'kernel_name', 'abi_schema', 'module_globals')}
            entry.update(sm=90, file='unit.cubin', flags=['-cubin', '-O3'],
                         source_sha256=hashlib.sha256((NATIVE_AOT/metadata['file']).read_bytes()).hexdigest(),
                         cubin_sha256=hashlib.sha256(header).hexdigest())
            manifest = {'schema': 'stwo-cuda-native-cubin-bundle-v1',
                        'producer': {'provider': 'nvidia_nvcc', **{key: 'ab'*32 for key in
                                     ('nvcc_sha256', 'toolkit_manifest_sha256', 'host_cxx_sha256', 'host_cc1plus_sha256')}},
                        'entries': [entry]}
            path = bundle / 'manifest.json'
            path.write_text(json.dumps(manifest))
            environment = dict(os.environ, STWO_CUDA_AOT_CUBIN_IMPORT_ROOT=str(bundle))
            self._run_plan(zig, project, cache, environment)
            self.assertEqual(len(self._plan_outputs(cache)), 1)
            manifest['producer']['nvcc_sha256'] = 'cd'*32
            path.write_text(json.dumps(manifest))
            self._run_plan(zig, project, cache, environment)
            self.assertEqual(len(self._plan_outputs(cache)), 2)
            # Alter only the cubin. A stale outer cache would silently succeed;
            # the correct build reruns the importer and rejects its digest.
            artifact.write_bytes(header + b'altered device code')
            with self.assertRaisesRegex(AssertionError, 'differs from its digest'):
                self._run_plan(zig, project, cache, environment)

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

            # Use an unreferenced header here so this test isolates Zig's build
            # cache key. Headers in an authenticated AOT source closure are
            # intentionally rejected as stale until their manifest is repinned;
            # that fail-closed behavior is covered by test_cuda_aot_identity.py.
            header = project / "src/backends/cuda/native/cache_invalidation_probe.cuh"
            header.write_bytes(b"// cache-invalidation-header\n")
            self._run_plan(zig, project, cache)
            after_header = self._plan_outputs(cache)
            self.assertEqual(2, len(after_header))
            self.assertTrue(initial < after_header)

            source = project / "src/backends/cuda/native/runtime/context.cu"
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
        shutil.copy2(
            ROOT / "build_support/backends/cuda_aot.zig",
            build_support / "cuda_aot.zig",
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

        contract = project / "src/frontends/cairo/witness/deduction_contract.zig"
        contract.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "src/frontends/cairo/witness/deduction_contract.zig", contract)

        cuda_root = project / "src/backends/cuda"
        cuda_root.mkdir(parents=True)
        (cuda_root / "active_source_manifest.json").symlink_to(
            ROOT / "src/backends/cuda/active_source_manifest.json"
        )
        (cuda_root / "product_manifest.json").symlink_to(
            ROOT / "src/backends/cuda/product_manifest.json"
        )
        authority = cuda_root / "authority"
        authority.mkdir(parents=True)
        (authority / "active").symlink_to(
            ROOT / "src/backends/cuda/authority/active",
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
        tools = project / "src/tools"
        tools.mkdir(parents=True)
        (tools / "cairo_cuda_witness_aot").symlink_to(
            ROOT / "src/tools/cairo_cuda_witness_aot",
            target_is_directory=True,
        )
        (tools / "cairo_witness_cpu_codegen").symlink_to(
            ROOT / "src/tools/cairo_witness_cpu_codegen",
            target_is_directory=True,
        )
        vectors = project / "vectors/cairo"
        vectors.mkdir(parents=True)
        (vectors / "sn_pie_2_witness_programs.bin").symlink_to(
            ROOT / "vectors/cairo/sn_pie_2_witness_programs.bin"
        )

    @staticmethod
    def _config(output: Path) -> BuildConfig:
        return BuildConfig(
            source_root=CUDA_ROOT / "authority/active",
            source_manifest=CUDA_ROOT / "active_source_manifest.json",
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
    def _run_plan(zig: str, project: Path, cache: Path, env=None) -> None:
        completed = subprocess.run(
            [zig, "build", "plan", "--cache-dir", str(cache)],
            cwd=project,
            env=env,
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
