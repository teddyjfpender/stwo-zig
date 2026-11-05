#!/usr/bin/env python3
"""Qualify a completed, matched producer/CUDA build on both M7 dev blocks.

Run on the pod, without an enclosing GPU lock. The resident harness owns that
lock for each job. Source/build identities and the optional codec library are
recorded before any request. Never compare timings across different assets.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import rv64_m3_pod as P


def digest(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stream", default="m7-integrate")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--control", type=Path, required=True)
    parser.add_argument("--mode", choices=("check", "off", "on"), required=True)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--arena", help="override the device arena for an explicit capacity gate, e.g. 22G")
    args = parser.parse_args()
    root, paths = P.src_root(args.stream), P.build_paths(args.stream)
    build = json.loads(paths["receipt"].read_text())
    for name in ("driver", "receiver", "library"):
        if digest(paths[name]) != build[name + "_sha256"]:
            raise SystemExit(f"incomplete or stale {name} build")
    if build.get("catalogue_gate", {}).get("status") != "pass":
        raise SystemExit("matched full CUDA image/catalogue gate required")
    if build["source_commit"] != P.source_commit(root):
        raise SystemExit("build/source marker mismatch")
    out = P.M3 / "runs" / args.stream / ("leaf-gate-" + args.tag)
    out.mkdir(exist_ok=False)
    provenance = {"schema": "rv64-m7-leaf-gate/v1", "build": build,
                  "build_receipt_sha256": digest(paths["receipt"]),
                  "mode": args.mode, "control": str(args.control),
                  "source_sha256": {str(p.relative_to(root)): digest(p) for p in sorted((root / "src").rglob("*"))
                                    if p.is_file() and p.suffix in (".zig", ".cu", ".cuh", ".h", ".cpp")},
                  "codec_library": {str(p): digest(p) for p in (Path("/lib/x86_64-linux-gnu/liblz4.so.1"),) if p.is_file()}}
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    command = [sys.executable, str(root / "scripts/rv64_m4_resident.py"), "daemon", "26235156", "24628607",
               "--stream", args.stream, "--build-stream", args.stream, "--repeat", str(args.repeat),
               "--tag", args.tag, "--store", "none", "--receive", "first",
               "--env", "STWO_RV64_LEAF_SEED_TAPE=" + {"check": "check", "off": "0", "on": "1"}[args.mode],
               "--env", "STWO_RV64_PACK_FOLD_CACHE=1", "--env", "STWO_RV64_COMPOSITION_ENQUEUE=0",
               "--env", "STWO_RV64_CPU_COMPACT_INGRESS=1"]
    if args.arena:
        command.extend(["--env", "STWO_RV64_DEVICE_ARENA=" + args.arena])
    if args.mode == "check":
        command.extend(["--env", "STWO_RV64_OUTER_PP_CLASS_CACHE=check",
                        "--env", "STWO_RV64_OUTER_PLAN_CLASS_CACHE=check"])
    provenance["command"] = command
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    with (out / "run.log").open("w") as log:
        subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    candidate = P.M3 / "runs" / args.stream / f"daemon-26235156-24628607-r{args.repeat}-{args.tag}" / "receipt.json"
    subprocess.run([sys.executable, str(root / "scripts/rv64_m7_pair.py"), str(args.control), str(candidate),
                    "--out", str(out / "parity.json")], check=True)
    result = json.loads(candidate.read_text())
    if {r["block"] for r in result["receivers"] if r.get("accepted")} != P.DEV_BLOCKS:
        raise SystemExit("fresh receiver acceptance required on both blocks")
    print(json.dumps({"gate": "pass", "directory": str(out), "candidate": str(candidate)}))


if __name__ == "__main__":
    main()
