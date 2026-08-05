"""One process-local cache product for tests that consume Native CUDA AOT."""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_TEMPORARY: tempfile.TemporaryDirectory | None = None


@lru_cache(maxsize=1)
def native_aot_root() -> Path:
    override = os.environ.get("STWO_CUDA_NATIVE_AOT_ROOT")
    if override:
        root = Path(override).resolve()
        if not (root / "aot_manifest.json").is_file():
            raise RuntimeError(f"Native CUDA AOT fixture is absent: {root}")
        return root

    zig = shutil.which("zig")
    if zig is None:
        raise unittest.SkipTest("Zig compiler unavailable")
    global _TEMPORARY
    _TEMPORARY = tempfile.TemporaryDirectory(prefix="stwo-native-cuda-aot-")
    atexit.register(_TEMPORARY.cleanup)
    temporary = Path(_TEMPORARY.name)
    executable = temporary / "cairo-cuda-witness-aot"
    compile_process = subprocess.run(
        [
            zig,
            "build-exe",
            "-OReleaseFast",
            "--dep",
            "cairo_witness_model",
            f"-Mroot={ROOT / 'src/tools/cairo_cuda_witness_aot/main.zig'}",
            f"-Mcairo_witness_model={ROOT / 'src/tools/cairo_witness_cpu_codegen/model.zig'}",
            f"-femit-bin={executable}",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if compile_process.returncode != 0:
        raise RuntimeError(
            "cannot compile Native CUDA AOT fixture:\n"
            + compile_process.stdout
            + compile_process.stderr
        )
    product = temporary / "cuda"
    generate_process = subprocess.run(
        [
            executable,
            ROOT / "vectors/cairo/sn_pie_2_witness_programs.bin",
            ROOT / "src/backends/cuda/aot/native",
            ROOT / "src/backends/cuda/authority/active",
            ROOT / "src/backends/cuda/native",
            product,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if generate_process.returncode != 0:
        raise RuntimeError(
            "cannot generate Native CUDA AOT fixture:\n"
            + generate_process.stdout
            + generate_process.stderr
        )
    root = product / "aot/native"
    if not (root / "aot_manifest.json").is_file():
        raise RuntimeError("Native CUDA AOT fixture did not publish its manifest")
    return root
