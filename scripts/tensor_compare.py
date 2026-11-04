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
FP_TOY_SAME_MACHINE = {  # L: (prove_s, verify_s, proof_bytes), deep staging, 1 core, hiding on, 0 PoW bits
    16: (0.49, 0.022, 269e3),
    18: (2.05, 0.012, 251e3),
    20: (8.37, 0.014, 341e3),
}
# FlashProve toy at 20 PoW bits (matched to our pow 20), L=20, hiding on, 1 core
FP_TOY_W20 = {20: (8.63, 0.0125, 308e3)}
# FlashProve's own bound conventions (docs/figures.tsv, docs/limits.md):
#   all rounds added: 119.38 (with work) / 92.42 (without)
#   compiled single number (N/2^L): 126.21 / 96.23
FP_BOUNDS = {"all_rounds_with": 119.38, "all_rounds_without": 92.42, "compiled_with": 126.21, "compiled_without": 96.23}


def sec_fields(r):
    """Extract whole-bound bits from a bench row's security calculator output (any nesting)."""
    out = {}
    def walk(o, pre=""):
        if isinstance(o, dict):
            for k, v in o.items():
                walk(v, pre + k + ".")
        elif isinstance(o, (int, float)):
            out[pre[:-1]] = o
    walk(r.get("security") or {})
    def pick(*names):
        for n in names:
            for k, v in out.items():
                if k.endswith(n) and ("total" in k or "request" in k):
                    return v
        for n in names:
            for k, v in out.items():
                if k.endswith(n):
                    return v
        return None
    return {"sum_with": pick("sum_with_work"), "sum_without": pick("sum_without_work"),
            "rbr_compiled": pick("rbr_compiled"), "compiled": pick("compiled")}


def bits_cell(r):
    f = sec_fields(r)
    if f["sum_with"] is None:
        return "n/a (old build)"
    return f"{f['sum_with']:.1f} / {f['sum_without']:.1f}"

TOY_CONFIGS = {
    # name: (queries, log_blowup, pow_bits, extra pcs2 args)
    "proven128": (160, 2, 20, [2, 160, 2, 20, 2]),  # unique decoding, rate 1/4: 160 * 0.678 + 20 = 128.5 bits; pcs2 depth 2
    "conj128": (54, 2, 20, [2, 54]),                # up-to-capacity conjecture, rate 1/4: 54 * 2 + 20 = 128 bits; pcs2 depth 2
    # Johnson regime with OOD samples, 2 proximity rows, deep levels at rate 1/8 (security.md): ~113.5 / 96.8 bits all rounds
    "johnson": (122, 2, 20, [2, 76, 3, 20, 2, 2]),
    # Config.security = .bits128 (security.md section 10): degree-8 challenge field (OM31, the
    # -Dchallenge=om31 build's tensor-bench-om31) + Johnson/OOD PCS at 133 / 88 queries, 1 prox row,
    # work shift 1; the preset overrides the pcs2 arguments (security.md 10.1). >= 128 bits all rounds
    # added without PoW credit on toy, MLP and layer.
    "sec128": (122, 2, 20, [2, 76, 3, 20, 2, 2]),
}
CONFIG_ENV = {"johnson": {"TENSOR_OOD": "1", "TENSOR_DEEP": "76,3,20"}}
# configs that need another binary (suffix on --bin) and extra flags
CONFIG_BIN_SUFFIX = {"sec128": "-om31"}
CONFIG_FLAGS = {"sec128": ["--security", "bits128"]}


def bin_for(binary, name):
    return binary + CONFIG_BIN_SUFFIX.get(name, "")
os.environ["TENSOR_BATCH_MATMULS"] = "1"
os.environ.setdefault("TENSOR_PROVE_REPS", "3")


def run_one(binary, args, gb, label, env=None):
    cmd = [MEMGUARD, "run", "--gb", str(gb), "--label", label, "--", binary] + [str(a) for a in args]
    e = dict(os.environ)
    e.update(env or {})
    p = subprocess.run(cmd, capture_output=True, text=True, env=e)
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
        for name, (q, lb, pw, ex) in TOY_CONFIGS.items():
            for L in (16, 18, 20, 22):
                emit(f"toy-{name}-L{L}-1t", run_one(bin_for(ns.bin, name), ["product", L, 1, q, lb, pw] + ex + CONFIG_FLAGS.get(name, []), 6, "cmp-toy", CONFIG_ENV.get(name)))
            emit(f"toy-{name}-L20-12t", run_one(bin_for(ns.bin, name), ["product", 20, 12, q, lb, pw] + ex + CONFIG_FLAGS.get(name, []), 6, "cmp-toy", CONFIG_ENV.get(name)))
    if "zk" in suites:
        for L in (16, 18, 20, 22):
            emit(f"zktoy-hiding-L{L}-1t", run_one(ns.bin, ["product", L, 1, 56, 2, 20, "zk"], 6, "cmp-zk"))
        for lt in (8, 9, 10):
            os.environ["ZK_WEIGHT_LB"] = "3"
            emit(f"zkmlp-hiding-t{lt}", run_one(ns.bin, ["mlp", lt, 12, 13, 12, 64, 2, 20, "zk"], 14, "cmp-zk"))
    if "metal" in suites:
        for name in ("conj128", "johnson"):
            q, lb, pw, ex = TOY_CONFIGS[name]
            emit(f"metal-mlp-{name}-t10", run_one(ns.bin, ["mlp", 10, 12, 13, 12, q, lb, pw] + ex + ["--metal"], 10, "cmp-metal", CONFIG_ENV.get(name)))
            emit(f"metal-layer-{name}-t10", run_one(ns.bin, ["layer", 10, 11, 12, 4, 12, q, lb, pw, 2, 1, 0, 10, 1] + ex + ["--metal"], 12, "cmp-metal", CONFIG_ENV.get(name)))
            emit(f"metal-toy-{name}-L22", run_one(ns.bin, ["product", 22, 12, q, lb, pw] + ex + ["--metal"], 6, "cmp-metal", CONFIG_ENV.get(name)))
    if "mlp" in suites:
        for name, (q, lb, pw, ex) in TOY_CONFIGS.items():
            for lt in (8, 9, 10, 11):
                emit(f"mlp-{name}-t{lt}", run_one(bin_for(ns.bin, name), ["mlp", lt, 12, 13, 12, q, lb, pw] + ex + CONFIG_FLAGS.get(name, []), 10 if lt < 11 else 14, "cmp-mlp", CONFIG_ENV.get(name)))
    if "layer" in suites:
        for name, (q, lb, pw, ex) in TOY_CONFIGS.items():
            for lt in (9, 10):
                emit(f"layer-{name}-t{lt}", run_one(bin_for(ns.bin, name), ["layer", lt, 11, 12, 4, 12, q, lb, pw, 2, 1, 0, lt, 1] + ex + CONFIG_FLAGS.get(name, []), 12, "cmp-layer", CONFIG_ENV.get(name)))


def fmt_bytes(b):
    return f"{b/1e6:.2f} MB" if b >= 1e6 else f"{b/1e3:.0f} KB"


def fmt_proof(r):
    """Proof size as sent: the wire encoding (tensor-bench "encoded_bytes",
    wire.zig) when reported, else the struct-field sum marked with '*'."""
    enc = r.get("encoded_bytes")
    if enc and "proof" in enc:
        return fmt_bytes(enc["proof"])
    pb = r["proof_bytes"]
    return fmt_bytes(pb["total"] if isinstance(pb, dict) else pb) + "*"


def cmd_report(ns):
    rows = [json.loads(l) for l in open(os.path.join(ns.out, "results.jsonl"))]
    by = {}
    for r in rows:
        by[r.get("tag")] = r  # last wins
    md = ["# Tensor frontend vs FlashProve: measured comparison", "",
          "Proof sizes are wire-encoded bytes (design/tensor-frontend/wire.md, the files `tensor-verify` reads); "
          "'*' marks rows that only report the struct-field sum.", ""]
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
    md += ["## Same relation (a (.) b = c over 2^L), same machine, NON-hiding (ours) vs hiding (FlashProve)", "",
           "FlashProve: its sequential CPU reference (blocks/toy/product.h, not the CUDA cp_prove), deep staging, hiding on, 0 PoW, 1 core.",
           "Ours here is NON-hiding; the like-for-like hiding comparison is the next section. 'bits' = our soundness calculator's",
           "all-rounds-added bound with / without PoW (FlashProve's own all-rounds figure: 119.38 / 92.42).", "",
           "| L | config | bits (w/ / w/o PoW) | ours prove | ours verify | ours proof | FlashProve prove | FlashProve verify | FlashProve proof | prove ratio |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for name in TOY_CONFIGS:
        for L in (16, 18, 20, 22):
            r = by.get(f"toy-{name}-L{L}-1t")
            if not r or "prove_s" not in r:
                continue
            fp = FP_TOY_SAME_MACHINE.get(L)
            fps = (f"{fp[0]:.2f} s", f"{fp[1]*1e3:.0f} ms", fmt_bytes(fp[2]), f"{fp[0]/r['prove_s']:.1f}x") if fp else ("-", "-", "-", "-")
            md.append(f"| {L} | {name} ({r['queries']}q, rate 1/{2**r['log_blowup']}, {r['pow_bits']} PoW) | {bits_cell(r)} | {r['prove_s']:.3f} s | {r['verify_s']*1e3:.1f} ms | {fmt_proof(r)} | {fps[0]} | {fps[1]} | {fps[2]} | {fps[3]} |")
    md.append("")
    zt = [by[k] for k in sorted(by) if k.startswith("zktoy-") and "prove_s" in by[k]]
    if zt:
        md += ["## HEADLINE: hiding vs hiding, same relation and machine (FlashProve sequential CPU reference, 20-bit PoW where available)", "",
               "Both sides zero-knowledge. Our hiding-mode bits are the query term only (unique decoding) until the calculator covers hiding openings.", "",
               "| L | ours prove | ours verify | ours proof | FlashProve prove | FlashProve verify | FlashProve proof | prove ratio |", "|---|---|---|---|---|---|---|---|"]
        for r in sorted(zt, key=lambda r: r["log_n"]):
            fp = FP_TOY_W20.get(r["log_n"]) or FP_TOY_SAME_MACHINE.get(r["log_n"])
            fps = (f"{fp[0]:.2f} s", f"{fp[1]*1e3:.0f} ms", fmt_bytes(fp[2]), f"{fp[0]/r['prove_s']:.1f}x") if fp else ("-", "-", "-", "-")
            md.append(f"| {r['log_n']} | {r['prove_s']:.3f} s | {r['verify_s']*1e3:.1f} ms | {fmt_proof(r)} | {fps[0]} | {fps[1]} | {fps[2]} | {fps[3]} |")
        md.append("")
    zm = [by[k] for k in sorted(by) if k.startswith("zkmlp-") and "prove_s" in by[k]]
    if zm:
        md += ["## Zero-knowledge MLP layer (hiding weights + witness, public input/output), D=4096, F=8192, 12 threads", "",
               "| tokens | prove (+fwd) | verify | proof | weight commit (once) | peak RSS |", "|---|---|---|---|---|---|"]
        for r in sorted(zm, key=lambda r: r["log_t"]):
            md.append(f"| {2**r['log_t']} | {r['prove_s']:.2f} s (+{r['forward_s']:.2f}) | {r['verify_s']*1e3:.0f} ms | {fmt_proof(r)} | {r['commit_weights_s']:.2f} s | {r.get('peak_rss_bytes',0)/1e9:.1f} GB |")
        md.append("")
    mlp = [by[k] for k in sorted(by, key=lambda k: (k.split("-")[1], by[k].get("tokens", 0))) if k.startswith("mlp-") and "prove_s" in by[k]]
    if mlp:
        md += ["## SwiGLU MLP layer (D=4096, F=8192, 100.7M int8 weights), 12 threads", "",
               "| config | tokens | prove (+ integer forward) | verify | proof | proved MAC/s (fwd+prove) | prove us/token | committed bits/token | stage split (commit/GKR/op/batch/open) |",
               "|---|---|---|---|---|---|---|---|---|"]
        for r in mlp:
            s = r["stage_s"]
            cfgname = r["tag"].split("-")[1]
            md.append(f"| {cfgname} | {int(r['tokens'])} | {r['prove_s']:.2f} s (+{r['forward_s']:.2f}) | {r['verify_s']*1e3:.1f} ms | {fmt_proof(r)} | {r['macs']/(r['prove_s']+r['forward_s']):.2e} | {r['prove_ns_per_token']/1e3:.0f} | {r['committed_bits_per_token']:.0f} | {s['witness_commit']:.2f}/{s['gkr']:.2f}/{s['op_sumchecks']:.2f}/{s['batch']:.2f}/{s['witness_open']+s['weight_open']:.2f} |")
        md.append("")
    lay = [by[k] for k in sorted(by) if k.startswith("layer-") and "prove_s" in by[k]]
    if lay:
        md += ["## Llama-style decoder layer (GQA attention + RoPE + softmax + RMSNorm + SwiGLU), 12 threads", "",
               "| config | tokens | D | F | heads (q/kv) | weights | prove (+fwd) | verify | proof | prove ms/token |", "|---|---|---|---|---|---|---|---|---|---|"]
        for r in lay:
            md.append(f"| {r['tag'].split('-')[1]} | {2**r['log_t']} | {2**r['log_d']} | {2**r['log_f']} | {2**r['log_heads']}/{2**r['log_kv_heads']} | {r['weights']/1e6:.1f}M | {r['prove_s']:.2f} s (+{r['forward_s']:.2f}) | {r['verify_s']*1e3:.1f} ms | {fmt_proof(r)} | {r['prove_s']*1e3/2**r['log_t']:.2f} |")
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
