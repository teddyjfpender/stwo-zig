#!/usr/bin/env python3
"""Qualify native closure and connected GKR traversal on the resident GPU."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ["source-root", "fixtures", "gkr-fixtures", "build", "objects"]:
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    root, build = args.source_root.resolve(), args.build.resolve()
    fixtures, gkr = args.fixtures.resolve(), args.gkr_fixtures.resolve()
    build.mkdir(parents=True, exist_ok=True)
    native = root / "src/backends/cuda/native"
    source = native / "rv64/closure.cu"
    drivers = [root / "tests/cuda/rv64" / name for name in ["closure_smoke.cu", "gkr_loop_smoke.cu"]]
    names = ["context.o", "gkr.o", "round.o", "tail.o", "rv64-batch.o", "rv64-gkr-binding-loop.o", "rv64-binding.o"]
    objects = [args.objects.resolve() / name for name in names]
    inputs = [source, *drivers, Path(__file__).resolve(), *objects]
    inputs += list(fixtures.glob("case-*.bin")) + list(gkr.glob("*.bin"))
    inputs += [native / "rv64" / name for name in ["closure.h", "custody.cuh", "om31.cuh", "gkr.h"]]
    inputs += [root / "tests/cuda/rv64" / name for name in ["context_owner.cuh", "fixture_words.cuh", "fixture_reader.h"]]
    pinned = {str(path): sha(path) for path in inputs}
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-pthread", f"-I{native}", f"-I{root / 'tests/cuda/rv64'}"]
    nvcc = "/usr/local/cuda/bin/nvcc"
    closure_object = build / "closure.o"
    started = time.monotonic()
    with (build / "compile.log").open("w") as log:
        subprocess.run([nvcc, *flags, "-Xptxas=-v", "-c", str(source), "-o", str(closure_object)], check=True, stdout=log, stderr=subprocess.STDOUT)
        for driver, dependencies in zip(drivers, [objects[:1], objects]):
            subprocess.run([nvcc, *flags, str(driver), str(closure_object), *map(str, dependencies), "-o", str(build / driver.stem)], check=True, stdout=log, stderr=subprocess.STDOUT)
    compile_seconds = time.monotonic() - started
    gates = {}
    for tool in ["normal", "memcheck", "racecheck", "initcheck", "synccheck"]:
        gates[tool] = {}
        for driver, data in zip(drivers, [fixtures, gkr]):
            command = [str(build / driver.stem), str(data)]
            if tool != "normal":
                command = ["/usr/local/cuda/bin/compute-sanitizer", "--tool", tool, "--error-exitcode", "97", *command]
            path = build / f"{driver.stem}-{tool}.log"
            started = time.monotonic()
            with path.open("w") as log:
                subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
            text = path.read_text()
            if driver.stem == "closure_smoke":
                assert "PASS native closure fixtures=15 framing_mutants=4" in text
            else:
                receipt = [json.loads(line) for line in text.splitlines() if line.startswith("{")][-1]
                assert receipt["cases"] == 9 and receipt["native_proof_and_artifact_parity"]
                assert receipt["binding_metadata_cases"] == 178 and not receipt["full_block_verified"]
            gates[tool][driver.stem] = {"result": "PASS", "seconds": time.monotonic() - started, "log_sha256": sha(path)}
    for path, digest in pinned.items():
        if sha(Path(path)) != digest:
            raise RuntimeError(f"input changed: {path}")
    receipt = {"schema": "rv64-cuda-native-closure/v1", "compile_seconds": compile_seconds, "gates": gates,
               "scope": "Local root sum/pole checks and independent manifest claim closure; connected numerical GKR traversal; no physical execution acceptance",
               "full_block_verified": False, "input_sha256": pinned,
               "executable_sha256": {d.stem: sha(build / d.stem) for d in drivers}}
    (build / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"gates": gates, "full_block_verified": False}))


if __name__ == "__main__":
    main()
