#!/usr/bin/env python3
"""Run the tensor-frontend benchmark matrix and compare against FlashProve.

usage: tensor_compare.py run   --bin <tensor-bench> --out <dir> [--suite toy,prims,mlp,layer]
       tensor_compare.py report --out <dir> [--baseline <flashprove results.json>]

Every benchmark is run through memguard (one at a time). Results are JSON lines
in <dir>/results.jsonl; the report is <dir>/COMPARISON.md.
"""
import argparse
import json
import os
import subprocess
import sys

MEMGUARD = os.path.expanduser("~/Coding/ge-ops/bin/memguard")

# FlashProve published (P) figures: docs/figures.tsv, paper Table 3, guide/performance.md
FP_PUBLISHED = {
    "machine": "1x H100 80 GB + 24 host CPUs, ~290 GB host RAM",
    "model": "Llama 4 Maverick (400.7B committed weights, 16.15B used per token), 1,024-token windows",
    "rate_tok_s_batch24": 111.23,
    "s_per_request_batch24": 9.206,
    "batch24_latency_s": (220.7, 225.9),
    "proof_bytes": 18.78e6,
    "verify_s_1thread": 21.14,
    "verify_s_24threads": 17.07,
    "commit_once_s": 2323.77,
    "client_download_bytes": 6.24e6,
    "bound_bits_with_pow": 126.21,
    "bound_bits_without_pow": 96.23,
    "zero_knowledge": True,
}

# Same statement as FlashProve's blocks/toy/product.h (a (.) b = c over 2^L), measured on this Mac.
FP_TOY_SAME_MACHINE = {  # L: (prove_s, verify_s, proof_bytes), deep staging, 1 core, hiding on
    16: (0.49, 0.022, 269e3),
    18: (2.05, 0.012, 251e3),
    20: (8.37, 0.014, 341e3),
}

TOY_CONFIGS = {
    # name: (queries, log_blowup, pow_bits)
    "proven128": (130, 3, 20),   # unique decoding, rate 1/8: 130 * 0.83 + 20 = 128 bits
    "conj128": (54, 2, 20),      # up-to-capacity conjecture, rate 1/4: 54 * 2 + 20 = 128 bits
}


def run_one(binary, args, gb, label):
    cmd = [MEMGUARD, "run", "--gb", str(gb), "--label", label, "--", binary] + [str(a) for a in args]
    p = subprocess.run(cmd, capture_output=True, text=True)
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            return json.loads(line)
    sys.stderr.write(p.stdout[-2000:] + p.stderr[-2000:])
    return {"error": p.returncode, "args": args}


def cmd_run(ns):
    os.makedirs(ns.out, exist_ok=True)
    suites = ns.suite.split(",")
    out = open(os.path.join(ns.out, "results.jsonl"), "a")

    def emit(tag, r):
        r["tag"] = tag
        out.write(json.dumps(r) + "\n")
        out.flush()
        print(tag, json.dumps(r)[:300])

    if "prims" in suites:
        emit("prims-1t", run_one(ns.bin, ["prims", 1], 4, "cmp-prims"))
    if "toy" in suites:
        for name, (q, lb, pw) in TOY_CONFIGS.items():
            for L in (16, 18, 20, 22):
                emit(f"toy-{name}-L{L}-1t", run_one(ns.bin, ["product", L, 1, q, lb, pw], 6, "cmp-toy"))
            emit(f"toy-{name}-L20-12t", run_one(ns.bin, ["product", 20, 12, q, lb, pw], 6, "cmp-toy"))
    if "mlp" in suites:
        for lt in (8, 9, 10):
            emit(f"mlp-t{lt}", run_one(ns.bin, ["mlp", lt, 12, 13, 12, 64, 2, 20], 12 if lt < 11 else 16, "cmp-mlp"))
    if "layer" in suites:
        for lt in (8, 9, 10):
            emit(f"layer-t{lt}", run_one(ns.bin, ["layer", lt, 12, 13, 5, 12], 12, "cmp-layer"))


def fmt_bytes(b):
    return f"{b/1e6:.2f} MB" if b >= 1e6 else f"{b/1e3:.0f} KB"


def cmd_report(ns):
    rows = [json.loads(l) for l in open(os.path.join(ns.out, "results.jsonl"))]
    by = {}
    for r in rows:
        by[r.get("tag")] = r  # last wins
    md = ["# Tensor frontend vs FlashProve: measured comparison", ""]
    base = None
    if ns.baseline and os.path.exists(ns.baseline):
        base = json.load(open(ns.baseline))
    if "prims-1t" in by:
        p = by["prims-1t"]
        md += ["## Primitives, one core, same machine (Apple M4 Max)", "",
               "| primitive | stwo-tensor (M31/QM31, Blake2s) | FlashProve (Goldilocks/cubic, BLAKE2b) |", "|---|---|---|",
               f"| base mul (arrays) | {p['m31_mul_per_s']:.2e}/s (SIMD {p['m31_mul_simd4_per_s']:.2e}/s) | 1.17e9/s |",
               f"| extension mul (arrays) | {p['qm31_mul_per_s']:.2e}/s | 2.26e8/s (5.5e8/s in register accumulation) |",
               f"| extension x base mul-add | {p['qm31_x_m31_muladd_per_s']:.2e}/s | 1.32e9/s |",
               f"| column leaf hash (2048 symbols) | {p['blake2s_leaf_2048x4B_MBps']:.0f} MB/s | 1,160 MB/s |",
               f"| RS encode 2^20 rate 1/2 (codeword symbols/s) | {p['rs_encode'][2]['codeword_symbols_per_s']:.2e} | 1.35e8 (2^16) / 8.7e7 (2^22) |",
               f"| sumcheck deg 2, all rounds, per entry | {p['sumcheck_deg2_2p20_ns_per_entry']:.1f} ns | ~5 ns first round (fold_round 2.2 + halve 2.8) |",
               ""]
    md += ["## Same statement, same machine: a (.) b = c over 2^L (FlashProve blocks/toy/product.h)", "",
           "FlashProve: deep staging (their best proof size), hiding on, 1 core. Ours: non-hiding unless noted.", "",
           "| L | config | ours prove | ours verify | ours proof | FlashProve prove | FlashProve verify | FlashProve proof | prove speedup |",
           "|---|---|---|---|---|---|---|---|---|"]
    for name in TOY_CONFIGS:
        for L in (16, 18, 20, 22):
            r = by.get(f"toy-{name}-L{L}-1t")
            if not r or "prove_s" not in r:
                continue
            fp = FP_TOY_SAME_MACHINE.get(L)
            fps = (f"{fp[0]:.2f} s", f"{fp[1]*1e3:.0f} ms", fmt_bytes(fp[2]), f"{fp[0]/r['prove_s']:.1f}x") if fp else ("-", "-", "-", "-")
            md.append(f"| {L} | {name} ({r['queries']}q, rate 1/{2**r['log_blowup']}, {r['pow_bits']} PoW) | {r['prove_s']:.3f} s | {r['verify_s']*1e3:.1f} ms | {fmt_bytes(r['proof_bytes'])} | {fps[0]} | {fps[1]} | {fps[2]} | {fps[3]} |")
    md.append("")
    mlp = [by[k] for k in sorted(by) if k.startswith("mlp-t") and "prove_s" in by[k]]
    if mlp:
        md += ["## SwiGLU MLP layer (D=4096, F=8192, 100.7M int8 weights), 12 threads", "",
               "| tokens | prove | verify | proof | proved MAC/s | prove us/token | committed bits/token | stage split (commit/GKR/op/batch/open) |",
               "|---|---|---|---|---|---|---|---|"]
        for r in mlp:
            s = r["stage_s"]
            md.append(f"| {int(r['tokens'])} | {r['prove_s']:.2f} s | {r['verify_s']*1e3:.0f} ms | {fmt_bytes(r['proof_bytes']['total'])} | {r['proved_macs_per_s']:.2e} | {r['prove_ns_per_token']/1e3:.0f} | {r['committed_bits_per_token']:.0f} | {s['witness_commit']:.2f}/{s['gkr']:.2f}/{s['op_sumchecks']:.2f}/{s['batch']:.2f}/{s['witness_open']+s['weight_open']:.2f} |")
        md.append("")
    open(os.path.join(ns.out, "COMPARISON.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--bin", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--suite", default="prims,toy,mlp")
    p = sub.add_parser("report")
    p.add_argument("--out", required=True)
    p.add_argument("--baseline")
    ns = ap.parse_args()
    {"run": cmd_run, "report": cmd_report}[ns.cmd](ns)


if __name__ == "__main__":
    main()
