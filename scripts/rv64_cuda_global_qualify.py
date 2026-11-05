#!/usr/bin/env python3
"""Qualify native-authority global interaction kernels, not full block proofs."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--fixtures", type=Path, required=True)
    p.add_argument("--build", type=Path, required=True)
    p.add_argument("--context-object", type=Path, required=True)
    p.add_argument("--binding-object", type=Path, required=True)
    p.add_argument("--jobs", type=int, default=3)
    args = p.parse_args()
    if not 1 <= args.jobs <= 8:
        p.error("jobs must be in 1..8")
    root, fixtures, build = args.source_root.resolve(), args.fixtures.resolve(), args.build.resolve()
    build.mkdir(parents=True, exist_ok=True)
    count = int(re.search(r"global_case_count=(\d+)", (fixtures / "global_launches.h").read_text()).group(1))
    sources = [root / "src/backends/cuda/native/rv64/global.cu"] + [fixtures / f"case-{i}.cu" for i in range(count)]
    dependencies = [args.context_object.resolve(), args.binding_object.resolve()]
    driver = root / "tests/cuda/rv64/global_smoke.cu"
    inputs = sources + dependencies + [driver, Path(__file__).resolve(), fixtures / "global_launches.h"]
    inputs += [fixtures / f"case-{i}.bin" for i in range(count)]
    inputs += [root / "src/backends/cuda/native/rv64" / name for name in ["global.h", "binding.h", "binding.cu", "custody.cuh", "om31.cuh", "projection.cuh", "composition.cuh"]]
    pinned = {str(path): sha(path) for path in inputs}
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-pthread",
             f"-I{root / 'src/backends/cuda/native'}", f"-I{root / 'tests/cuda/rv64'}", f"-I{fixtures}"]
    nvcc = "/usr/local/cuda/bin/nvcc"
    def compile_one(item):
        out = build / f"{item.stem}.o"
        with (build / f"{item.stem}-compile.log").open("w") as log:
            subprocess.run([nvcc, *flags, "-Xptxas=-v", "-c", str(item), "-o", str(out)], check=True, stdout=log, stderr=subprocess.STDOUT)
        return out
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        objects = list(pool.map(compile_one, sources))
    executable = build / "global-smoke"
    with (build / "link.log").open("w") as log:
        subprocess.run([nvcc, *flags, str(driver), *map(str, objects + dependencies), "-o", str(executable)], check=True, stdout=log, stderr=subprocess.STDOUT)
    compile_seconds = time.monotonic() - started
    gates = {}
    for tool in ["normal", "memcheck", "racecheck", "initcheck", "synccheck"]:
        command = [str(executable), str(fixtures)]
        if tool != "normal":
            command = ["/usr/local/cuda/bin/compute-sanitizer", "--tool", tool, "--error-exitcode", "97", *command]
        path = build / f"{tool}.log"
        started = time.monotonic()
        with path.open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        if f"PASS global native projections/interactions cases={count} mutants=4" not in path.read_text():
            raise RuntimeError(f"incomplete {tool} gate")
        gates[tool] = {"result": "PASS", "seconds": time.monotonic() - started, "log_sha256": sha(path)}
    for path, digest in pinned.items():
        if sha(Path(path)) != digest:
            raise RuntimeError(f"input changed during qualification: {path}")
    receipt = {"schema": "rv64-cuda-native-global-interactions/v1", "honest_layouts": count, "mutants": 4,
               "scope": "Native CPU-shard RAM/KIO/Wire tuple projections and centered interaction witnesses; no execution acceptance",
               "full_block_verified": False, "compile_seconds": compile_seconds, "gates": gates,
               "input_sha256": pinned, "executable_sha256": sha(executable)}
    (build / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"layouts": count, "gates": gates, "full_block_verified": False}))


if __name__ == "__main__":
    main()
