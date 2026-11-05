#!/usr/bin/env python3
"""Run the hybrid fixture, fresh CPU receiver and complete child circuit gate."""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes(root):
    files = sorted((root / "src").rglob("*.zig"))
    files = [path for path in files if not any(part in (".zig-cache", "zig-out") for part in path.parts)]
    files += [root / "vectors/circuit/official/circuit_air.air_programs_v1.bin"]
    return {str(path.relative_to(root)): sha(path) for path in files}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--library", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--gpu-lock", default="/workspace/m3/locks/gpu.lock")
    p.add_argument("--build-receipt", type=Path, required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True, exist_ok=True)
    proof = args.out / "proof.hom31"
    build = json.loads(args.build_receipt.read_text())
    if not build["passed"] or build["binary_sha256"] != sha(args.binary) or build["source_files_sha256"] != source_hashes(root):
        raise RuntimeError("Fixture build/source receipt mismatch")
    receipt = dict(schema="rv64-m7-hybrid-fixture/v1", date=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   ethereum_request=False, production_profile_promoted=False, outputs=180,
                   binary_sha256=sha(args.binary), library_sha256=sha(args.library),
                   build_receipt_sha256=sha(args.build_receipt), source_files_sha256=build["source_files_sha256"], tests=[])
    env = os.environ.copy()
    for name in tuple(env):
        if name.startswith("STWO_RV64_GPU"):
            env.pop(name)
    for mode in ("--prove", "--verify", "--check-child"):
        argv = [str(args.binary), mode, *([str(args.library)] if mode == "--prove" else []), str(proof)]
        lock = open(args.gpu_lock, "a") if mode == "--prove" else None
        try:
            if lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
            started = time.monotonic()
            with open(args.out / (mode[2:] + ".log"), "w") as log:
                run_env = env.copy()
                if not lock:
                    run_env["CUDA_VISIBLE_DEVICES"] = ""
                result = subprocess.run(argv, cwd=root, env=run_env, stdout=log, stderr=subprocess.STDOUT)
            receipt["tests"].append(dict(mode=mode, argv=argv, exit_code=result.returncode, wall_s=time.monotonic() - started,
                                         gpu_access=lock is not None))
        finally:
            if lock:
                fcntl.flock(lock, fcntl.LOCK_UN)
                lock.close()
        receipt["passed"] = all(test["exit_code"] == 0 for test in receipt["tests"])
        if proof.exists():
            receipt.update(fixture_proof_sha256=sha(proof), fixture_proof_bytes=proof.stat().st_size)
        (args.out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt["tests"][-1]), flush=True)
        if result.returncode:
            print((args.out / (mode[2:] + ".log")).read_text()[-12000:], flush=True)
            return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
