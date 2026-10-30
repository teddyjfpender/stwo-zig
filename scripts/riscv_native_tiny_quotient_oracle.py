#!/usr/bin/env python3
"""Run exact CUDA tiny-inverse arithmetic on the host against Zig oracle vectors.

This does not compile CUDA launch code or qualify a GPU execution path.
Generate vectors with STWO_NATIVE_TINY_ORACLE and the focused Zig test root.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--vectors", type=Path, required=True)
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--cxx", default="clang++")
    args = p.parse_args()
    out = args.out_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    vectors = args.vectors.resolve()
    size = vectors.stat().st_size
    if not size or size % 40:
        p.error("oracle file must contain complete ten-word records")
    # The pure arithmetic header uses CUDA function qualifiers but no runtime.
    # Explicitly substitute only those qualifiers for this host-only test.
    (out / "cuda_runtime_api.h").write_text(
        "#pragma once\n#define __host__\n#define __device__\n#define __forceinline__ inline\n")
    command = [args.cxx, "-std=c++17", "-O2", "-I" + str(out),
               "-I" + str(ROOT / "src/backends/cuda/native"),
               str(ROOT / "tests/cuda/native_quotient_tiny_host.cpp"),
               "-o", str(out / "oracle")]
    result = subprocess.run(command, capture_output=True, text=True)
    (out / "build.log").write_text(result.stdout + result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    run = subprocess.run([str(out / "oracle"), str(vectors)], capture_output=True, text=True)
    (out / "run.log").write_text(run.stdout + run.stderr)
    files = [ROOT / "src/backends/cuda/native/transform/quotient_tiny.cuh",
             ROOT / "src/backends/cuda/native/oods/field.cuh", vectors]
    receipt = {"schema": "stwo-native-tiny-deep-host-oracle-v1", "exit_code": run.returncode,
               "cases": size // 40, "gpu_qualified": False, "cuda_launch_code_compiled": False,
               "command": command, "files": [{"path": str(f), "sha256": hashlib.sha256(f.read_bytes()).hexdigest()} for f in files]}
    (out / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(run.stdout, end="")
    if run.stderr:
        print(run.stderr, end="")
    raise SystemExit(run.returncode)


if __name__ == "__main__":
    main()
