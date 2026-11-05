#!/usr/bin/env python3
"""CPU-only M7 binding/registry qualification on the pod, with source receipts.

No Ethereum performance claim is made by this gate. Run production dev-block
proofs and fresh receivers separately before promoting any reserved profile.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


SOURCES = [
    "src/integrations/circuit_cpu/om31/device_prove.zig",
    "src/integrations/riscv_cpu/mod.zig",
    "src/integrations/riscv_cpu/outer_gkr/binding.zig",
    "src/integrations/riscv_cpu/outer_gkr/hybrid_device.zig",
    "src/integrations/riscv_cpu/outer_gkr/hybrid_receiver.zig",
    "src/integrations/riscv_cpu/outer_gkr/hybrid_component.zig",
    "src/integrations/riscv_cpu/outer_gkr/hybrid_air.zig",
    "src/integrations/riscv_cpu/outer_gkr/hybrid_air_test.zig",
    "src/integrations/riscv_cpu/outer_gkr/hybrid_wire.zig",
    "src/integrations/riscv_cpu/outer_gkr/hybrid_wire_test.zig",
    "src/integrations/riscv_cpu/outer_gkr/child_verifier.zig",
    "src/integrations/riscv_cpu/outer_gkr/tuples.zig",
    "src/integrations/riscv_cpu/outer_gkr/binding_v2.zig",
    "src/integrations/riscv_cpu/outer_gkr/binding_v2_test.zig",
    "src/integrations/riscv_cpu/outer_gkr/circuit.zig",
    "src/integrations/riscv_cpu/outer_gkr/profile.zig",
    "src/integrations/riscv_cpu/outer_gkr/section.zig",
    "src/integrations/riscv_cpu/rv64_outer_gkr_test_root.zig",
    "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/binding.zig",
    "src/integrations/riscv_cpu/word16_execution/om31_security_candidate.zig",
    "src/integrations/riscv_cpu/word16_execution/om31_security_candidate_test.zig",
    "scripts/rv64_m5_negative_corpus.py",
    "src/backends/cuda/native/rv64/outer_gkr_projector.cuh",
    "src/backends/cuda/native/rv64/circuit_interaction.cu",
    "src/integrations/circuit_cpu/om31/fractions_qualification.zig",
]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", default="/workspace/m3/runs/m7-outer-gkr/binding-gate")
    p.add_argument("--lock", default="/workspace/m3/locks/build.1.lock")
    p.add_argument("--zig", default="/workspace/zig/zig")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    files = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in SOURCES}
    digest = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    commit = (root / ".m3-commit-full").read_text().strip()
    tree = (root / ".m3-tree").read_text().strip()
    env = os.environ.copy()
    env.update(ZIG_GLOBAL_CACHE_DIR="/workspace/m3/cache/zig-global", CUDA_VISIBLE_DEVICES="", STWO_RV64_GPU_PCS_HELPER="/bin/false")
    env.pop("STWO_ZIG_RV64_SETUP_CACHE", None)
    common = ["-Doptimize=ReleaseSafe", "-Dimplementation-commit=" + commit,
              "-Dimplementation-tree=" + tree, "-Dimplementation-dirty=true",
              "-Dimplementation-dirty-content-sha256=" + digest, "-j8", "--summary", "all"]
    receipt = {"schema": "rv64-m7-binding-gate/v1", "date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "source_commit": commit, "source_tree": tree, "implementation_dirty": True,
               "source_files_sha256": files, "source_snapshot_sha256": digest,
               "gpus": 0, "production_profile_promoted": False, "tests": []}
    steps = [(step, [args.zig, "build", step, *common]) for step in ("test-riscv64-outer-gkr", "test-riscv64-security-policy")]
    steps.append(("test-circuit-om31-cuda-fractions", [args.zig, "build", "--build-file", "src/integrations/circuit_cpu/build.zig",
                  "test-circuit-om31-cuda-fractions", "-Doptimize=ReleaseSafe", "-j8", "--summary", "all"]))
    for step, argv in steps:
        with open(args.lock, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            started = time.monotonic()
            load = os.getloadavg()[0]
            with open(out / (step + ".log"), "w") as log:
                result = subprocess.run(argv, cwd=root, env=env, stdout=log, stderr=subprocess.STDOUT)
            fcntl.flock(lock, fcntl.LOCK_UN)
        row = {"step": step, "argv": argv, "exit_code": result.returncode,
               "wall_s": time.monotonic() - started, "loadavg_1m": load, "log": str(out / (step + ".log"))}
        receipt["tests"].append(row)
        receipt["passed"] = all(r["exit_code"] == 0 for r in receipt["tests"])
        (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(row), flush=True)
        if result.returncode:
            print((out / (step + ".log")).read_text()[-12000:], flush=True)
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
