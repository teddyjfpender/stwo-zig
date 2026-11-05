#!/usr/bin/env python3
"""RV64 M7 compress proof-size model (stream profiles, M6 prep for M7). Standard library only.

Counts the bytes of one Circle-STARK proof as produced by core/vcs_lifted + core/fri_family:
  - trace trees: per UNIQUE query position, the opened column values (base M31, 4 B) for the
    circle->line conjugate pair, and the batched Merkle multiproof siblings (32 B) of that tree;
  - FRI line layers (CIRCLE_TO_LINE_FOLD_STEP = 1, then fold_step s per layer): per unique coset,
    the 2^s - 1 sibling OM31 values (32 B) and the layer tree's multiproof siblings;
  - last layer 2^log_last coefficients (32 B), commitments (32 B each, or 2^cap per tree with caps),
    OODS sampled values (cols x samples x 32 B), PoW nonce.
Multiproof sibling counts are EXACT for each sampled query set (Monte Carlo over the query
positions, same rule as vcs_lifted verifier: a sibling is sent iff it is not itself on a path).
Merkle caps of 2^c nodes stop paths c levels below the root.

The absolute scale is calibrated ONCE on the measured M5 default root (706,424 B [M],
vectors/reports/rv64-m5-20261104/summary.json): log trace 23, blowup 2, 108 queries, fold 4,
311 opened columns per query (diet census parent_side.today_columns [M]), 4 trees.

  python3 rv64_m7_compress_model.py table [--trials 64] [--json OUT]
"""
import argparse
import json
import random

HASH = 32
OM31 = 32
BASE = 4
MEASURED_ROOT_BYTES = 706_424


def multiproof_siblings(positions, depth, cap_log):
    """Siblings a batched decommitment sends for these leaf positions in a tree of `depth` levels,
    when paths stop at level `cap_log` from the root (cap of 2^cap_log nodes)."""
    layer = sorted(set(positions))
    sent = 0
    for _ in range(depth - cap_log):
        nxt = []
        i = 0
        while i < len(layer):
            a = layer[i]
            if i + 1 < len(layer) and layer[i + 1] == a ^ 1:
                i += 2
            else:
                sent += 1
                i += 1
            nxt.append(a >> 1)
        layer = sorted(set(nxt))
    return sent


def proof_bytes(trace_log, log_blowup, queries, fold_step, columns, trees=4, cap_log=0, log_last=0,
                samples=2, pow_bytes=8, trials=64, seed=7):
    rng = random.Random(seed)
    eval_log = trace_log + log_blowup
    total = 0.0
    parts = {"values": 0.0, "trace_paths": 0.0, "fri_values": 0.0, "fri_paths": 0.0, "fixed": 0.0}
    for _ in range(trials):
        # Query positions on the circle evaluation domain; the conjugate pair shares one line position.
        line = [rng.randrange(1 << (eval_log - 1)) for _ in range(queries)]
        uniq = sorted(set(line))
        b = 0
        # Trace trees: both conjugate points of each unique line position are opened (2 leaves).
        leaves = [2 * x for x in uniq] + [2 * x + 1 for x in uniq]
        b += len(uniq) * 2 * columns * BASE
        parts["values"] += len(uniq) * 2 * columns * BASE
        tp = trees * multiproof_siblings(leaves, eval_log, cap_log) * HASH
        b += tp
        parts["trace_paths"] += tp
        # FRI line layers: domain eval_log - 1, folded s at a time down to the last layer.
        dom = eval_log - 1
        pos = uniq
        ratio = trace_log - 1 - log_last  # line degree log ratio after the circle fold
        layers = 0
        while ratio > 0:
            step = min(fold_step, ratio)
            cosets = sorted(set(p >> step for p in pos))
            fv = len(cosets) * ((1 << step) - 1) * OM31
            fp = multiproof_siblings(cosets, dom - step, min(cap_log, dom - step)) * HASH
            b += fv + fp
            parts["fri_values"] += fv
            parts["fri_paths"] += fp
            pos = cosets
            dom -= step
            ratio -= step
            layers += 1
        commit = (1 << cap_log) * HASH
        b += (trees + layers) * commit
        b += (1 << log_last) * OM31
        b += columns * samples * OM31
        b += pow_bytes
        parts["fixed"] += (trees + layers) * commit + (1 << log_last) * OM31 + columns * samples * OM31 + pow_bytes
        total += b
    proof_bytes.last_parts = {k: v / trials for k, v in parts.items()}
    return total / trials, layers


def calibration(trials):
    raw, _ = proof_bytes(23, 1, 108, 4, 311, trials=trials)
    return MEASURED_ROOT_BYTES / raw, raw


ROWS = [
    # name, trace_log, log_blowup, queries, fold_step, columns, cap_log, log_last, pow, trees
    ("root r1 b2 q108 (M5 default, calibration)", 23, 1, 108, 4, 311, 0, 0, 20, 4),
    ("root m3 b4 q51", 23, 2, 51, 4, 311, 0, 0, 26, 4),
    ("C1 b8 q36 2^20, 311 cols", 20, 3, 36, 4, 311, 0, 0, 20, 4),
    ("C1 b8 q36 2^20, 311 cols, cap 16", 20, 3, 36, 4, 311, 4, 0, 20, 4),
    ("C1 b8 q36 2^20, 215 cols (outer GKR)", 20, 3, 36, 4, 215, 0, 0, 20, 4),
    ("C2 b16 q27 2^16 s3, 311 cols", 16, 4, 27, 3, 311, 0, 0, 20, 4),
    ("C2 b16 q27 2^16 s3, 311 cols, last 2^3", 16, 4, 27, 3, 311, 0, 3, 20, 4),
    ("C2 b16 q27 2^16 s3, 311 cols, cap 16", 16, 4, 27, 3, 311, 4, 0, 20, 4),
    ("C2 b16 q27 2^16 s4, 311 cols", 16, 4, 27, 4, 311, 0, 0, 20, 4),
    ("C2 b16 q27 2^17 s3, 311 cols", 17, 4, 27, 3, 311, 0, 0, 20, 4),
    ("C2 b16 q27 2^17 s3, 215 cols, last 2^3", 17, 4, 27, 3, 215, 0, 3, 20, 4),
    ("C2 b16 q27 2^18 s3, 311 cols", 18, 4, 27, 3, 311, 0, 0, 20, 4),
    ("C2 b16 q27 2^17 s3, 6189 cols (fused Blake k=1 rows)", 17, 4, 27, 3, 6189, 0, 0, 20, 4),
    ("C2 b16 q27 2^17 s3, 1072 cols (fused Blake k=10 rows)", 17, 4, 27, 3, 1072, 0, 0, 20, 4),
    ("C2 b16 q27 2^17 s3, 128 cols, 3 trees, last 2^3", 17, 4, 27, 3, 128, 0, 3, 20, 3),
    ("C2 b32 q22 p18 2^17 s3, 215 cols, last 2^3", 17, 5, 22, 3, 215, 0, 3, 18, 4),
    ("C2 b64 q18 p20 2^17 s3, 215 cols, last 2^3", 17, 6, 18, 3, 215, 0, 3, 20, 4),
    ("C2 b64 q18 p20 2^17 s3, 128 cols, 3 trees, last 2^3", 17, 6, 18, 3, 128, 0, 3, 20, 3),
    ("C2 b64 q18 p20 2^16 s3, 128 cols, 3 trees, last 2^3", 16, 6, 18, 3, 128, 0, 3, 20, 3),
    ("C2 b64 q18 p20 2^18 s3, 128 cols, 4 trees, last 2^3", 18, 6, 18, 3, 128, 0, 3, 20, 4),
    ("C2 b64 q18 p20 2^18 s3, 150 cols, 4 trees, last 2^3", 18, 6, 18, 3, 150, 0, 3, 20, 4),
    ("C2 b64 q18 p20 2^18 s3, 150 cols, 3 trees, last 2^3", 18, 6, 18, 3, 150, 0, 3, 20, 3),
    ("C2 b64 q18 p20 2^18 s3, 192 cols, 4 trees, last 2^3", 18, 6, 18, 3, 192, 0, 3, 20, 4),
    ("C2 b64 q18 p20 2^19 s3, 150 cols, 4 trees, last 2^3", 19, 6, 18, 3, 150, 0, 3, 20, 4),
]


def table(trials):
    k, raw_root = calibration(trials)
    out = {"schema": "rv64-m7-compress-model/v1", "label": "D (model calibrated on one measured root)",
           "calibration": {"measured_root_bytes": MEASURED_ROOT_BYTES, "model_raw_bytes": round(raw_root),
                           "scale": round(k, 4)},
           "rows": []}
    for name, n, b, q, s, cols, cap, last, pw, trees in ROWS:
        raw, layers = proof_bytes(n, b, q, s, cols, trees=trees, cap_log=cap, log_last=last, trials=trials)
        parts = {k: round(v * k_scale / 1000, 1) for k, v in proof_bytes.last_parts.items()} if (k_scale := k) else {}
        out["rows"].append({"name": name, "trace_log": n, "log_blowup": b, "queries": q, "fold_step": s,
                            "columns": cols, "trees": trees, "cap_log": cap, "log_last": last, "fri_layers": layers,
                            "pow_bits": pw, "conjectured_bits": b * q + pw, "calibrated_parts_kb": parts,
                            "lde_log": n + b, "model_bytes": round(raw), "calibrated_kb": round(raw * k / 1000, 1)})
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("table")
    t.add_argument("--trials", type=int, default=64)
    t.add_argument("--json")
    args = p.parse_args()
    value = table(args.trials)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(value, f, indent=1)
    print(f"calibration: model {value['calibration']['model_raw_bytes']} B vs measured {MEASURED_ROOT_BYTES} B "
          f"-> scale {value['calibration']['scale']}")
    for r in value["rows"]:
        pr = r["calibrated_parts_kb"]
        print(f"{r['calibrated_kb']:8.1f} KB  bits {r['conjectured_bits']}  layers {r['fri_layers']}  lde 2^{r['lde_log']}  "
              f"[vals {pr['values']} tp {pr['trace_paths']} fv {pr['fri_values']} fp {pr['fri_paths']}]  {r['name']}")


if __name__ == "__main__":
    main()
