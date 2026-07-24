#!/usr/bin/env python3
"""Compile and execute the Native CUDA product smokes on a real GPU."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path


SCHEMA = "stwo-zig-cuda-device-smoke-v1"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def command_output(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
    )
    return (completed.stdout + completed.stderr).strip()


def compile_command(
    compiler: Path,
    source: Path,
    executable: Path,
    archive: Path,
    cuda_home: Path,
) -> list[str]:
    return [
        str(compiler),
        "-std=c++17",
        "-O2",
        f"-I{cuda_home / 'include'}",
        str(source),
        str(archive),
        f"-L{cuda_home / 'lib64'}",
        f"-Wl,-rpath,{cuda_home / 'lib64'}",
        "-lcudart",
        "-lcuda",
        "-ldl",
        "-lpthread",
        "-o",
        str(executable),
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--cuda-home", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--tests-dir",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "tests/cuda",
    )
    args = parser.parse_args()

    archive = args.archive.resolve()
    cuda_home = args.cuda_home.resolve()
    compiler = args.compiler.resolve()
    tests_dir = args.tests_dir.resolve()
    output = args.out_dir.resolve()
    sources = sorted(tests_dir.glob("native_*_smoke.cpp"))
    required = [
        archive,
        compiler,
        cuda_home / "include/cuda_runtime_api.h",
        cuda_home / "lib64/libcudart.so",
    ]
    if any(not path.is_file() for path in required):
        raise SystemExit("Native CUDA device-smoke input is absent")
    if not sources:
        raise SystemExit("Native CUDA device-smoke source set is empty")
    output.mkdir(parents=True, exist_ok=True)

    gpu = command_output(
        [
            "nvidia-smi",
            "--query-gpu=name,uuid,compute_cap,driver_version",
            "--format=csv,noheader",
        ]
    )
    if not gpu or "\n" in gpu:
        raise SystemExit("device smoke requires exactly one visible NVIDIA GPU")

    tests: list[dict[str, object]] = []
    for source in sources:
        executable = output / source.stem
        command = compile_command(
            compiler,
            source,
            executable,
            archive,
            cuda_home,
        )
        subprocess.run(command, check=True)
        result = subprocess.run(
            [str(executable)],
            check=True,
            capture_output=True,
            text=True,
        )
        tests.append(
            {
                "name": source.stem,
                "source_sha256": sha256_file(source),
                "executable_sha256": sha256_file(executable),
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        )

    receipt = {
        "schema": SCHEMA,
        "gpu": gpu,
        "cuda_visible_devices": os.environ.get("CUDA_VISIBLE_DEVICES"),
        "archive_sha256": sha256_file(archive),
        "compiler": str(compiler),
        "compiler_sha256": sha256_file(compiler),
        "compiler_version": command_output([str(compiler), "--version"]),
        "cuda_home": str(cuda_home),
        "tests": tests,
    }
    receipt_path = output / "cuda_device_smoke_receipt.json"
    receipt_path.write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        f"Native CUDA device smoke passed: {len(tests)} tests on {gpu}; "
        f"receipt {receipt_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
