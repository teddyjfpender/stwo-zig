#!/usr/bin/env python3
"""Measure fresh small complete-proof processes using an already built runner.

The instruction and memory ladders share the runner's proof acceptance gate.
Diagnostic runs are separate from timing runs; neither promotes CSP changes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

from zig_serial_build import build_lock

ROOT = Path(__file__).resolve().parents[1]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--backend", choices=("cpu", "metal"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--sizes", nargs="+", type=int, default=[1, 4, 16, 64])
    parser.add_argument("--memory", action="store_true")
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--aot-bundle", type=Path)
    parser.add_argument("--aot-manifest-sha256")
    args = parser.parse_args()
    allowed = {1, 4, 16} if args.memory else {1, 4, 16, 64}
    if not set(args.sizes) <= allowed or args.samples < 1:
        parser.error("invalid ladder sizes or sample count")
    if args.backend == "metal" and (not args.aot_bundle or not args.aot_manifest_sha256):
        parser.error("Metal requires an authenticated AOT bundle and manifest digest")
    binary = args.binary.resolve(strict=True)
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ)
    diagnostics = [name for name in environment if name.startswith("STWO_") and
                   any(part in name for part in ("PROFILE", "TIMING", "HISTOGRAM", "DIAGNO", "CLOSURE"))]
    for name in diagnostics:
        environment.pop(name)
    source_patch = subprocess.check_output(["git", "diff", "HEAD", "--", "src", "scripts"], cwd=ROOT)
    (output / "source.patch").write_bytes(source_patch)
    records = []
    manifest = {
        "schema": "stwo.small-recursive-benchmark.v1",
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "binary": str(binary), "binary_sha256": digest(binary),
        "backend": args.backend, "memory_ladder": args.memory,
        "sizes": args.sizes, "samples": args.samples,
        "source_patch_sha256": digest(output / "source.patch"),
        "removed_diagnostics": diagnostics,
        "worker_environment": {k: v for k, v in environment.items() if k in ("STWO_ZIG_WORKERS", "STWO_ZIG_MERKLE_WORKERS")},
        "runs": records,
    }
    # Record new source files separately: git diff does not include them.
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard", "src", "scripts"], cwd=ROOT, text=True).splitlines()
    manifest["untracked_source_sha256"] = {p: digest(ROOT / p) for p in untracked}
    with build_lock():
        for size in args.sizes:
            for sample in range(args.samples):
                command = [str(binary), "--memory-addresses" if args.memory else "--native-steps",
                           str(size), "--native-backend", args.backend]
                if args.backend == "metal":
                    command += ["--aot-bundle", str(args.aot_bundle.resolve()),
                                "--aot-manifest-sha256", args.aot_manifest_sha256]
                path = output / f"{size}-{sample}.log"
                started = time.perf_counter()
                with path.open("xb") as log:
                    result = subprocess.run(["/usr/bin/time", "-l", *command], cwd=ROOT,
                                            env=environment, stdout=log, stderr=subprocess.STDOUT,
                                            timeout=180)
                seconds = time.perf_counter() - started
                text = path.read_text()
                verified = (result.returncode == 0 and "owners_destroyed=true" in text and
                            "SEGMENT_V2_OUTER_ARTIFACT_REJECTIONS truncated=true trailing=true" in text and
                            "producer_live_bytes_after_destroy=0" in text)
                record = {"argv": command, "exit_code": result.returncode, "verified": verified,
                          "request_seconds": seconds, "log": path.name, "log_sha256": digest(path)}
                for name in ("native_prove_ms", "native_verify_ms", "recursive_prepare_ms"):
                    match = re.search(rf"\b{name}=([0-9.]+)", text)
                    record[name] = float(match[1]) if match else None
                rss = re.search(r"(\d+)\s+maximum resident set size", text)
                record["max_rss_bytes"] = int(rss[1]) if rss else None
                records.append(record)
                (output / "results.json").write_text(json.dumps(manifest, indent=2) + "\n")
                print(f"{args.backend} size={size} sample={sample}: {seconds:.3f}s verified={verified}", flush=True)
                if not verified:
                    raise SystemExit(f"complete proof failed; retained {path}")
        if digest(binary) != manifest["binary_sha256"]:
            raise SystemExit("runner binary changed during measurement")


if __name__ == "__main__":
    main()
