#!/usr/bin/env python3
"""Build the complete outer producer and fresh receiver with source receipts."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import time
import rv64_m7_hybrid_fixture_run as F


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--prefix", type=Path, required=True)
    p.add_argument("--lock", default="/workspace/m3/locks/build.1.lock")
    p.add_argument("--commit", required=True)
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = "/workspace/m3/cache/zig-global"
    receipt = dict(schema="rv64-m7-outer-production-build/v1", source_commit=args.commit, implementation_dirty=True, tests=[])
    with open(args.lock, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        receipt["source_files_sha256"] = F.source_hashes(root)
        for step in ("build-rv64-ethereum-gpu-combined", "build-rv64-ethereum-recursion-receiver"):
            argv = ["/workspace/zig/zig", "build", step, "-Doptimize=ReleaseFast", "-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v4+sha", "-j8", "--cache-dir", str(root / ".zig-cache"), "--prefix", str(args.prefix)]
            started = time.monotonic()
            with open(args.out / (step + ".log"), "w") as log:
                result = subprocess.run(argv, cwd=root / "src/integrations/riscv_cuda", env=env, stdout=log, stderr=subprocess.STDOUT)
            row = dict(step=step, argv=argv, exit_code=result.returncode, wall_s=time.monotonic() - started)
            receipt["tests"].append(row)
            receipt["sources_unchanged_during_build"] = receipt["source_files_sha256"] == F.source_hashes(root)
            receipt["passed"] = all(row["exit_code"] == 0 for row in receipt["tests"]) and receipt["sources_unchanged_during_build"]
            (args.out / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(json.dumps(row), flush=True)
            if not receipt["passed"]:
                print((args.out / (step + ".log")).read_text()[-12000:], flush=True)
                return 1
        base = args.prefix.parent
        driver = args.prefix / "bin/rv64-word16-ethereum-gpu-combined"
        receiver = args.prefix / "bin/rv64-word16-ethereum-recursion-receiver"
        library = base / "cuda/native/libstwo-rv64-native.so"
        receipt.update(driver_sha256=F.sha(driver), receiver_sha256=F.sha(receiver), library_sha256=F.sha(library))
        (args.out / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        (base / "build.json").write_text(json.dumps(dict(schema="rv64-m3-build/v1", stream="m7-outer-gkr", source_root=str(root), source_commit=args.commit,
                                                       driver_sha256=receipt["driver_sha256"], receiver_sha256=receipt["receiver_sha256"], library_sha256=receipt["library_sha256"],
                                                       source_receipt=str(args.out / "build-receipt.json")), indent=2) + "\n")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
