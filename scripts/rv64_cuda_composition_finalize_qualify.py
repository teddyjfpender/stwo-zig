#!/usr/bin/env python3
"""Qualify native four/eight-coordinate composition interpolation and split."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["source-root", "fixtures", "build", "context-object"]:
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    root, build = args.source_root.resolve(), args.build.resolve()
    native = root / "src/backends/cuda/native"
    build.mkdir(parents=True, exist_ok=True)
    sources = [native / "transform/composition_split.cu", native / "rv64/composition_finalize.cu"]
    driver = root / "tests/cuda/rv64/composition_finalize_smoke.cu"
    fixtures = sorted(args.fixtures.resolve().glob("case-*.bin"))
    if len(fixtures) != 14:
        parser.error("expected all 14 native coordinate/depth/log fixtures")
    inputs = [*sources, driver, args.context_object.resolve(), Path(__file__).resolve(), *fixtures]
    inputs += sorted(native.rglob("*.cuh")) + sorted(native.rglob("*.h"))
    inputs += sorted((root / "tests/cuda/rv64").glob("*.cuh"))
    pinned = {str(path): sha(path) for path in inputs}
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-pthread", f"-I{native}", f"-I{root / 'tests/cuda/rv64'}"]
    executable = build / "smoke"
    started = time.monotonic()
    with (build / "compile.log").open("w") as log:
        objects = []
        for source in sources:
            obj = build / (source.stem + ".o")
            subprocess.run(["/usr/local/cuda/bin/nvcc", *flags, "-c", str(source), "-o", str(obj)], check=True, stdout=log, stderr=subprocess.STDOUT)
            objects.append(obj)
        subprocess.run(["/usr/local/cuda/bin/nvcc", *flags, str(driver), *map(str, objects), str(args.context_object.resolve()), "-o", str(executable)], check=True, stdout=log, stderr=subprocess.STDOUT)
    compile_seconds = time.monotonic() - started
    gates = {}
    for tool in ["normal", "memcheck", "racecheck", "initcheck", "synccheck"]:
        command = [str(executable), str(args.fixtures.resolve())]
        if tool != "normal":
            command = ["/usr/local/cuda/bin/compute-sanitizer", "--tool", tool, "--error-exitcode", "97", *command]
        path = build / (tool + ".log")
        with path.open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        if "PASS composition finalize cases=14 native_coefficients=true qm31_regression=true" not in path.read_text():
            raise RuntimeError("incomplete coefficient qualification")
        gates[tool] = {"result": "PASS", "log_sha256": sha(path)}
        print(json.dumps({"gate": tool, "result": "PASS"}), flush=True)
    for path, digest in pinned.items():
        if sha(Path(path)) != digest:
            raise RuntimeError("input changed during qualification: " + path)
    receipt = {"schema": "rv64-cuda-composition-finalize/v1", "scope": "Native coefficient parity and custody, not full AIR/execution acceptance", "cases": 14,
               "coordinates": [4, 8], "split_depths": [1, 2], "logs": [3, 5, 13, 17], "gates": gates,
               "compile_seconds": compile_seconds, "full_block_verified": False, "executable_sha256": sha(executable), "input_sha256": pinned}
    (build / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
