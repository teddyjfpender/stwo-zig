#!/usr/bin/env python3
"""Qualify a complete resident native PCS proof, without claiming AIR execution."""
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
    for name in ["source-root", "fixture", "build", "objects", "native-verifier"]:
        p.add_argument("--" + name, required=True, type=Path)
    args = p.parse_args()
    root, build, old = args.source_root.resolve(), args.build.resolve(), args.objects.resolve()
    build.mkdir(parents=True, exist_ok=True)
    relative = ["context.o", "transform-lde.o", "transform-n2b.o", "deep-pipeline-qualified/deep.o", "deep-pipeline-qualified/samples.o",
                "fri-qualified-final/fri.o", "fri-qualified-final/channel.o", "rv64-pcs.o", "commitment-merkle.o", "trace-qualified-final/trace.o", "trace-qualified-final/progressive.o"]
    objects = [old / name for name in relative]
    driver = root / "tests/cuda/rv64/pcs_pipeline_smoke.cu"
    native = root / "src/backends/cuda/native"
    inputs = [driver, args.fixture.resolve(), args.native_verifier.resolve(), Path(__file__).resolve(), *objects]
    inputs += [native / "rv64" / name for name in ["deep.h", "samples.h", "fri.h", "trace.h", "channel.h", "pcs.h", "gkr.h"]]
    inputs += [root / "tests/cuda/rv64" / name for name in ["context_owner.cuh", "fixture_words.cuh"]]
    pinned = {str(path): sha(path) for path in inputs}
    flags = ["-O3", "-std=c++17", "-lineinfo", "-gencode", "arch=compute_120,code=sm_120", "-Xcompiler=-pthread", f"-I{native}", f"-I{root / 'tests/cuda/rv64'}"]
    executable = build / "pcs-pipeline-smoke"
    started = time.monotonic()
    with (build / "compile.log").open("w") as log:
        subprocess.run(["/usr/local/cuda/bin/nvcc", *flags, str(driver), *map(str, objects), "-o", str(executable)], check=True, stdout=log, stderr=subprocess.STDOUT)
    compile_seconds = time.monotonic() - started
    gates = {}
    baseline = None
    for tool in ["normal", "memcheck", "racecheck", "initcheck", "synccheck"]:
        readback = build / f"readback-{tool}.bin"
        command = [str(executable), str(args.fixture), str(readback)]
        if tool != "normal":
            command = ["/usr/local/cuda/bin/compute-sanitizer", "--tool", tool, "--error-exitcode", "97", *command]
        path = build / f"{tool}.log"
        started = time.monotonic()
        with path.open("w") as log:
            subprocess.run(command, check=True, stdout=log, stderr=subprocess.STDOUT)
        assert "hot_d2h=0 hot_h2d=0" in path.read_text()
        receiver = build / f"receiver-{tool}.log"
        with receiver.open("w") as log:
            subprocess.run([str(args.native_verifier), "verify", str(args.fixture), str(readback)], check=True, stdout=log, stderr=subprocess.STDOUT)
        text = receiver.read_text()
        assert "PASS complete GPU PCS proof native_verified=true native_proof_byte_parity=true" in text
        assert text.count("REJECT complete native PCS mutation=") == 6
        capture_hash = sha(readback)
        if baseline is None:
            baseline = capture_hash
        assert baseline == capture_hash
        gates[tool] = {"result": "PASS", "seconds": time.monotonic() - started, "capture_sha256": capture_hash, "log_sha256": sha(path), "receiver_sha256": sha(receiver)}
    for path, digest in pinned.items():
        if sha(Path(path)) != digest:
            raise RuntimeError(f"input changed: {path}")
    receipt = {"schema": "rv64-cuda-complete-native-pcs/v1", "compile_seconds": compile_seconds, "gates": gates,
               "scope": "Complete native OM31 PCS proof from compact coefficients; no AIR or execution acceptance",
               "construction": {"columns": 6, "point_height_groups": 3, "degree_log": 9, "evaluation_log": 11, "blowup_log": 2, "queries": 256, "pow_bits": 0, "fold_step": 4},
               "native_pcs_verified": True, "native_proof_byte_parity": True, "full_stark_verified": False, "full_block_verified": False,
               "input_sha256": pinned, "executable_sha256": sha(executable)}
    (build / "qualification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"gates": gates, "native_pcs_verified": True, "full_block_verified": False}))


if __name__ == "__main__":
    main()
