#!/usr/bin/env python3
"""Project tensor-frontend proving cost to Llama 4 Maverick from measured coefficients.

usage: tensor_project.py --mlp <results.jsonl tag prefix mlp-t> --results <results.jsonl> [--layer-tag layer-t10]

Model (stated, not fitted to FlashProve):
  prove(request) = c_elem * W_tok * L_tok + c_weight * N_active_pass / batch + c_fixed
where
  W_tok   = committed witness elements per token (whole model), from the
            architecture and our integer model's committed tensors;
  c_elem  = measured prove seconds per committed witness element (marginal, from
            the MLP token sweep: slope of prove_s over witness elements);
  c_weight= measured weight-pass seconds per weight (fold + opening combine);
  N_active_pass = weights touched once per batch (all experts that receive a
            token; at batch 24 x 1024 tokens all 128 experts are hit, so the full
            400.7B committed table is passed once per batch).
All numbers printed with their inputs; hardware ratios are NOT applied.
"""
import argparse
import json

MAVERICK = dict(
    layers=48, d=5120, n_heads=40, n_kv=8, head_dim=128, ctx=1024,
    dense_ffn=16384, expert_ffn=8192, moe_every=2, n_experts=128, vocab=202048,
    committed_weights=400.7e9, active_weights=16.15e9,
)


def witness_per_token_layer(m, causal_half=True, moe=False):
    """Committed int8 tensors per token per layer in our integer model."""
    d, h, kv, hd = m["d"], m["n_heads"], m["n_kv"], m["head_dim"]
    ctx_eff = m["ctx"] / 2 if causal_half else m["ctx"]
    norm = 2 * (d + d)                 # two RMSNorms: normalized output + per-token scalars (~d each, generous)
    qkv = h * hd + 2 * kv * hd         # q, k, v projections
    rope = h * hd + kv * hd            # rotated q, k
    scores = h * ctx_eff               # requantized scores
    probs = h * ctx_eff                # exp lookup outputs / normalized probs
    attn_out = h * hd + d              # PV output, o-proj output
    resid = 2 * d
    ffn = m["expert_ffn"] if moe else m["dense_ffn"]
    mlp = 4 * ffn + d                  # gate, up, act, h, down out
    if moe:
        mlp += 4 * m["expert_ffn"] + d + 2  # shared expert + routed expert + router outputs
    return norm + qkv + rope + scores + probs + attn_out + resid + mlp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True)
    ap.add_argument("--batch", type=int, default=24)
    ns = ap.parse_args()
    rows = [json.loads(l) for l in open(ns.results)]
    mlp = sorted([r for r in rows if str(r.get("tag", "")).startswith("mlp-t") and "prove_s" in r], key=lambda r: r["tokens"])
    if len(mlp) < 2:
        raise SystemExit("need >= 2 MLP token points")
    # marginal cost per witness element: slope between smallest and largest token count
    a, b = mlp[0], mlp[-1]
    c_elem = (b["prove_s"] - a["prove_s"]) / (b["witness_elems"] - a["witness_elems"])
    c_weight = b["stage_s"]["weight_fold"] / b["weights"]
    m = MAVERICK
    per_layer = [witness_per_token_layer(m, moe=(i % m["moe_every"] == 1)) for i in range(m["layers"])]
    w_tok = sum(per_layer) + m["vocab"] / 1024  # lm-head logits (argmax via lookups), amortized estimate
    w_req = w_tok * m["ctx"]
    t_elem = c_elem * w_req
    t_weight = c_weight * m["committed_weights"] / ns.batch * 2  # fold + opening combine, per request share
    out = {
        "inputs": {"c_elem_s": c_elem, "c_weight_s": c_weight, "from": [a["tag"], b["tag"]], "batch": ns.batch},
        "witness_per_token": w_tok, "witness_per_request": w_req,
        "projected_s_per_request_this_machine": t_elem + t_weight,
        "split": {"witness": t_elem, "weights": t_weight},
        "flashprove_h100_s_per_request": 9.206,
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
