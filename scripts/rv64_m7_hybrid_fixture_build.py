#!/usr/bin/env python3
"""Build the exact focused hybrid fixture under the shared pod build lock."""
import argparse
import fcntl
import json
from pathlib import Path
import subprocess
import time
import rv64_m7_hybrid_fixture_run as F


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--prefix", type=Path, required=True)
    p.add_argument("--typed-pair", action="store_true")
    p.add_argument("--lock", default="/workspace/m3/locks/build.2.lock")
    args = p.parse_args()
    root = Path(__file__).resolve().parents[1]
    args.out.mkdir(parents=True, exist_ok=True)
    target = "rv64-outer-hybrid-typed-pair" if args.typed_pair else "rv64-outer-hybrid-fixtures"
    argv = ["/workspace/zig/zig", "build", "build-" + target, "-Doptimize=ReleaseSafe", "-j8", "--global-cache-dir", "/workspace/m3/cache/zig-global", "--prefix", str(args.prefix)]
    with open(args.lock, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        before = F.source_hashes(root)
        started = time.monotonic()
        with open(args.out / "build.log", "w") as log:
            result = subprocess.run(argv, cwd=root / "src/integrations/riscv_cuda", stdout=log, stderr=subprocess.STDOUT)
        unchanged = before == F.source_hashes(root)
        binary = args.prefix / "bin" / target
        receipt = dict(schema="rv64-m7-hybrid-fixture-build/v1", argv=argv, exit_code=result.returncode, wall_s=time.monotonic() - started,
                       passed=result.returncode == 0 and unchanged, sources_unchanged_during_build=unchanged,
                       source_files_sha256=before, binary_sha256=F.sha(binary) if binary.exists() else None)
        (args.out / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({key: value for key, value in receipt.items() if key != "source_files_sha256"}), flush=True)
        return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
