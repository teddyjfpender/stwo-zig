#!/usr/bin/env python3
"""Qualify resident lifted PCS commitments/openings with fresh native receivers."""
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
    for name in ["source-root", "fixtures", "build", "context-object", "merkle-object", "channel-object", "native-verifier"]:
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    root, fixtures, build = args.source_root.resolve(), args.fixtures.resolve(), args.build.resolve()
    build.mkdir(parents=True, exist_ok=True)
    native = root / "src/backends/cuda/native"
    sources = [native / "rv64/trace.cu", native / "commitment/progressive.cu"]
    driver = root / "tests/cuda/rv64/trace_smoke.cu"
    objects = [args.context_object.resolve(), args.merkle_object.resolve(), args.channel_object.resolve()]
    inputs = [*sources, driver, *objects, args.native_verifier.resolve(), Path(__file__).resolve()]
    inputs += [native / "rv64" / name for name in ["trace.h", "custody.cuh", "channel.h", "gkr.h"]]
    inputs += [native / "commitment" / name for name in ["mixed_layout.h", "blake2s_core.cuh", "blake2s_protocol.cuh", "resident_layout.cuh", "progressive_scalar.cuh"]]
    inputs += [fixtures / f"case-{i}.bin" for i in range(6)]
    pinned = {str(path): sha(path) for path in inputs}
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-pthread", f"-I{native}", f"-I{root / 'tests/cuda/rv64'}"]
    nvcc = "/usr/local/cuda/bin/nvcc"
    compiled = [build / f"{s.stem}.o" for s in sources]
    executable = build / "trace-smoke"
    started = time.monotonic()
    with (build / "compile.log").open("w") as log:
        for source, out in zip(sources, compiled):
            subprocess.run([nvcc, *flags, "-Xptxas=-v", "-c", str(source), "-o", str(out)], check=True, stdout=log, stderr=subprocess.STDOUT)
        subprocess.run([nvcc, *flags, str(driver), *map(str, compiled + objects), "-o", str(executable)], check=True, stdout=log, stderr=subprocess.STDOUT)
    compile_seconds = time.monotonic() - started
    gates = {}
    baseline = None
    for tool in ["normal", "memcheck", "racecheck", "initcheck", "synccheck"]:
        readback = build / f"readback-{tool}"
        readback.mkdir(exist_ok=True)
        command = [str(executable), str(fixtures), str(readback)]
        if tool != "normal":
            command = ["/usr/local/cuda/bin/compute-sanitizer", "--tool", tool, "--error-exitcode", "97", *command]
        path = build / f"{tool}.log"
        started = time.monotonic()
        with path.open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        assert "PASS native trace cases=6 mutants=3" in path.read_text()
        receiver_log = build / f"receiver-{tool}.log"
        with receiver_log.open("w") as log:
            subprocess.run([str(args.native_verifier), "verify", str(fixtures), str(readback)], check=True, stdout=log, stderr=subprocess.STDOUT)
        assert receiver_log.read_text().count("PASS fresh native trace receiver case=") == 6
        captures = {str(i): sha(readback / f"case-{i}.bin") for i in range(6)}
        if baseline is None:
            baseline = captures
        assert captures == baseline
        gates[tool] = {"result": "PASS", "seconds": time.monotonic() - started, "log_sha256": sha(path), "receiver_sha256": sha(receiver_log), "captures_sha256": captures}
    for path, digest in pinned.items():
        if sha(Path(path)) != digest:
            raise RuntimeError(f"input changed: {path}")
    receipt = {"schema": "rv64-cuda-native-trace-openings/v1", "compile_seconds": compile_seconds, "gates": gates,
               "scope": "Native prefixed lifted Merkle commitments, device root-to-query transcript and compact openings; no full Stark/Ethereum proof",
               "fresh_native_merkle_verification": True, "full_block_verified": False, "input_sha256": pinned, "executable_sha256": sha(executable)}
    (build / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"gates": gates, "full_block_verified": False}))


if __name__ == "__main__":
    main()
