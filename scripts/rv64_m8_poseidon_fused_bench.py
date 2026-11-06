#!/usr/bin/env python3
"""M8 Poseidon2-W24 kernel A/B: retained-tree GPU time vs Blake2s, with parity.

Runs prebuilt `bench-<variant>` / `smoke-<variant>` binaries (see the build
recipe in the receipt README). For every variant: the numerical KAT smoke,
all-retained-node parity against the independent CPU reference at 8 rows for
six widths, then CUDA-event medians on the nine M7 geometry classes. Large
roots must agree across variants. Holds the pod GPU lock only while running.
No FFT, transfer, FS, proof or Ethereum timing is implied.
"""
import argparse
import fcntl
import hashlib
import json
import os
import statistics
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rv64_m7_poseidon_commit_gate as G  # noqa: E402

CLASSES = [(47, 14), (128, 14), (479, 14), (47, 17), (128, 17), (304, 17), (479, 17),
           (128, 20), (479, 20)]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(argv, env):
    r = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=120)
    if r.returncode:
        raise RuntimeError(f"{argv[0]} exit {r.returncode}: {r.stderr[-400:]}")
    return r.stdout


def bench(binary, cols, log, reps, env, dump=False):
    out = run([str(binary), str(cols), str(log), str(reps)] + (["dump"] if dump else []), env)
    line = next(l for l in out.splitlines() if l.startswith("BENCH "))
    return json.loads(line[6:]), out


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bins", type=Path, required=True)
    p.add_argument("--variants", nargs="+", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--repeats", type=int, default=5)
    p.add_argument("--gpu", default="0")
    p.add_argument("--lock", default="/workspace/m3/locks/gpu.lock")
    a = p.parse_args()
    a.out.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CUDA_VISIBLE_DEVICES=a.gpu)
    receipt = dict(schema="rv64-m8-poseidon2-w24-kernel-ab/v1", label="M", status="RUNNING",
                   scope="retained Merkle tree hashing only; no FFT/transfer/FS/proof",
                   variants={}, binaries={}, parity={}, classes=[])
    for v in a.variants:
        receipt["binaries"][v] = {k: sha(a.bins / f"{k}-{v}") for k in ("bench", "smoke")}
    with open(a.lock, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for v in a.variants:
            smoke = run([str(a.bins / f"smoke-{v}")], env)
            assert "all independent numerical gates PASS" in smoke, smoke
            widths = []
            for cols in (1, 12, 13, 47, 128, 479):
                _, out = bench(a.bins / f"bench-{v}", cols, 3, 1, env, dump=True)
                got = list(map(int, next(l for l in out.splitlines()
                                         if l.startswith("TREE p2 ")).split()[4:]))
                if got != G.reference(cols, 8, "p2"):
                    raise RuntimeError(f"{v}: all-layer CPU parity failed width {cols}")
                widths.append(cols)
            receipt["parity"][v] = dict(smoke_kats="PASS", all_nodes_vs_cpu_rows8_widths=widths)
        for cols, log in CLASSES:
            row = dict(columns=cols, log_rows=log)
            roots = set()
            for v in a.variants:
                data, _ = bench(a.bins / f"bench-{v}", cols, log, a.repeats, env)
                roots.add(tuple(data["p2_root"]))
                row[v] = dict(p2_ms=statistics.median(data["p2_ms"]), p2_ms_all=data["p2_ms"],
                              blake_ms=statistics.median(data["blake_ms"]),
                              device=data["device"], p2_variant=data["p2_variant"])
            if len(roots) != 1:
                raise RuntimeError(f"large-tree root mismatch {cols}x2^{log}")
            row["p2_root"] = list(roots.pop())
            rows = 1 << log
            row["permutations"] = rows * ((cols // 12) + 1) + 2 * (rows - 1)
            receipt["classes"].append(row)
            print(json.dumps({k: (x["p2_ms"] if isinstance(x, dict) else x)
                              for k, x in row.items() if k != "p2_root"}), flush=True)
    receipt["status"] = "PASS"
    a.out.write_text(json.dumps(receipt, indent=1) + "\n")


if __name__ == "__main__":
    main()
