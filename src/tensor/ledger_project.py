#!/usr/bin/env python3
"""Witness ledger: per-class formulas, validation and the Maverick projection.

Usage (stdlib only; run with python3 -I):
  python3 -I ledger_project.py <ledger.jsonl> [<ledger.jsonl> ...]

Each input is the stdout of `TENSOR_LEDGER=1|noprove tensor-bench layer|model`
(design/tensor-frontend/ledger.md). For every run the script rebuilds the
bench's config, evaluates the closed-form element count of every ledger class
(FORMULAS below, read off transformer.zig / lm.zig / protocol.zig), and checks
it against the measured class (exact match expected, multiplicity columns
excepted: those are per request and data-independent in size but listed as
measured). It then evaluates the same formulas at the Maverick shape.

Symbols (all element counts are per request = one window of T tokens):
  T tokens, D model width, F dense FFN width, Fe expert width, Fs shared-
  expert width, H query heads, Hkv KV heads, dh = D / H, Dkv = Hkv dh,
  E experts, C slots per expert (2^log_capacity), Nr router columns (padded
  to the weight-table column count), V vocab, Ph head rows (2), P checked
  output positions (1), Q = width of the fused QKV output.
"""
import json
import math
import sys


def pow2ceil(x):
    return 1 << max(0, math.ceil(math.log2(x)))


def ilog2c(x):
    return max(0, math.ceil(math.log2(x)))


def wide_key_direct(n, bits):
    # transformer.Builder.wideKeyDirect: above 16 bits, one virtual key into
    # range(bits) (no limbs) when the table fits (<= 20 bits) and 2^n >= 4 2^bits
    return 16 < bits <= 20 and n >= bits + 2


def range_limbs(n, bits):
    # committed limb tensors per side of a rangeWide(n, ., bits): 0 (plain or
    # direct key) or 1 (lo and hi, one each)
    return 0 if bits <= 16 or wide_key_direct(n, bits) else 1


def slack_bits(T):
    return int(math.log2(T)) + 9


def slack_limbs(T, D):
    # attention division slacks: 2 rangeWide calls of lt + 9 bits over
    # n = lt + lh + ldh = log2(T D) bits; each commits lo + hi unless direct
    return 2 * range_limbs(int(math.log2(T)) + ilog2c(D), slack_bits(T))


def isqrt_limbs(T, D):
    # RMSNorm isqrt slacks: 2 rangeWide calls of gap_bits = log2(D) + 5 bits
    # (int8 activations) over n = log2(T) bits
    return 2 * range_limbs(int(math.log2(T)), int(math.log2(D)) + 5)


def direct_tables(T, D):
    # range tables a direct wide key adds (multiplicity column 2^bits, once per
    # request: one range(bits) table is shared by every layer)
    lt = int(math.log2(T))
    out = set()
    if wide_key_direct(lt + ilog2c(D), slack_bits(T)):
        out.add(slack_bits(T))
    return sum(1 << b for b in out)


# (scope, name) -> function(s, first_layer) giving elements per layer, for
# parts "dense" / "moe". Attention-block classes are shared by both parts.
def attn_block(s, first):
    T, D, H, Dkv = s["T"], s["D"], s["H"], s["Dkv"]
    sl = slack_limbs(T, D)
    il = isqrt_limbs(T, D)
    r = {}
    for rms in ("rms1", "rms2"):
        if not (rms == "rms1" and first):
            r[(rms, "xs")] = T * D
        r[(rms, "u")] = T * D
        r[(rms, "y")] = T * D
        for n in ("ss", "rt", "rt2", "inv", "inv_rt"):
            r[(rms, n)] = T
        if il:
            r[(rms, "isqrt.slack_lo")] = il * T
            r[(rms, "isqrt.slack_hi")] = il * T
    r[("attn.proj", "qkv")] = T * s["Q"]
    r[("rope", "q_rot")] = T * D
    r[("rope", "k_rot")] = T * Dkv
    for n in ("scores", "sel", "d", "e"):
        r[("attn", n)] = H * T * T
    for n in ("m", "den"):
        r[("attn", n)] = H * T
    for n in ("acc", "o", "od"):
        r[("attn", n)] = T * D
    r[("attn", "div.slack_lo")] = sl * T * D
    r[("attn", "div.slack_hi")] = sl * T * D
    r[("attn.proj", "wo")] = T * D
    return r


def dense_layer(s, first):
    T, D, F = s["T"], s["D"], s["F"]
    r = attn_block(s, first)
    for n in ("gate", "up", "silu", "glu"):
        r[("mlp", n)] = T * F
    r[("mlp", "down")] = T * D
    r[("residual", "residual")] = 2 * T * D  # h = x + attn, out = h + mlp
    return r


def moe_layer(s, first, shared=False):
    T, D, E, C, Fe = s["T"], s["D"], s["E"], s["C"], s["Fe"]
    r = attn_block(s, first)
    r[("moe.route", "logits")] = T * s["Nr"]
    r[("moe.route", "m")] = T
    for n in ("sel", "dr", "pre"):
        r[("moe.route", n)] = T * E
    r[("moe.route", "disp")] = E * C * T
    r[("moe.route", "occ")] = E * C
    r[("moe.expert", "xe.gather")] = E * C * D
    for n in ("gate", "up", "silu", "glu"):
        r[("moe.expert", n)] = E * C * Fe
    r[("moe.expert", "down")] = E * C * D
    r[("moe.expert", "combine")] = T * D
    r[("residual", "residual")] = 2 * T * D
    if shared:
        # NOT IMPLEMENTED in stwo-zig: Maverick's shared expert as a dense
        # SwiGLU of width Fs beside the routed expert, plus one add
        for n in ("gate", "up", "silu", "glu"):
            r[("moe.shared", n)] = T * s["Fs"]
        r[("moe.shared", "down")] = T * D
        r[("moe.shared", "add")] = T * D
    return r


def request_part(s, lm=True):
    T, D, V, Ph, P = s["T"], s["D"], s["V"], s["Ph"], s["P"]
    r = {}
    if not lm:
        r[("input", "x")] = T * D
        return r
    r[("embed", "onehot")] = T * V
    r[("embed", "gather")] = T * D
    r[("head", "slice")] = Ph * D
    for n in ("xs", "u", "y"):
        r[("rms.head", n)] = Ph * D
    for n in ("ss", "rt", "rt2", "inv", "inv_rt"):
        r[("rms.head", n)] = Ph
    r[("head", "logits")] = Ph * V
    r[("head.greedy", "dr")] = P * V
    r[("head.greedy", "m")] = P
    return r


def load(path):
    rows = [json.loads(l) for l in open(path) if l.startswith("{")]
    bench = [r for r in rows if "bench" in r][0]
    classes = [r for r in rows if r.get("ledger") == "class"]
    summary = [r for r in rows if r.get("ledger") == "summary"][0]
    return bench, classes, summary


def config_of(bench):
    T = 1 << bench["log_t"]
    D = 1 << bench["log_d"]
    H = 1 << bench["log_heads"]
    Hkv = 1 << bench["log_kv_heads"]
    dh = D // H
    s = dict(T=T, D=D, H=H, Hkv=Hkv, dh=dh, Dkv=Hkv * dh, F=1 << bench["log_f"], Ph=2, P=1)
    s["Q"] = pow2ceil(D + 2 * s["Dkv"])
    if bench["bench"] == "model":
        s["Fe"] = 1 << bench.get("log_f_expert", 0)
        s["E"] = 1 << bench["log_experts"]
        s["C"] = 1 << bench["log_capacity_used"]
        s["V"] = 1 << bench["log_vocab"]
        # router columns padded to the model's weight-table columns
        s["Nr"] = 1 << min(bench["log_d"], bench["log_f"], bench.get("log_f_expert", 99), 13)
    else:
        s["E"] = 1 << bench.get("log_experts", 0)
        s["C"] = 1 << bench.get("log_capacity", 0)
        s["V"] = 0
        s["Nr"] = 0
    return s


def predict(bench, s):
    """{(part, scope, name): elems} for the bench run's statement."""
    out = {}
    lm = bench["bench"] == "model"
    n_layers = bench.get("layers", bench.get("n_layers", 1))
    for l in range(n_layers):
        moe = lm and bench["log_experts"] > 0 and l % 2 == 1
        part = "moe" if moe else "dense"
        first = l == 0
        r = moe_layer(s, first) if moe else dense_layer(s, first)
        for k, v in r.items():
            out[(part,) + k] = out.get((part,) + k, 0) + v
    for k, v in request_part(s, lm).items():
        out[("request",) + k] = v
    return out


def validate(path):
    bench, classes, summary = load(path)
    s = config_of(bench)
    pred = predict(bench, s)
    meas = {(c["part"], c["scope"], c["name"]): c["elems"] for c in classes}
    bad = []
    for k, v in meas.items():
        if k[1] == "logup":
            continue
        if pred.get(k) != v:
            bad.append((k, v, pred.get(k)))
    for k, v in pred.items():
        # rms xs is data-dependent: not committed when the input already
        # fits the activation width (shift 0: range key on the input only)
        if k not in meas and v and k[2] != "xs":
            bad.append((k, None, v))
    mult = sum(v for k, v in meas.items() if k[1] == "logup")
    return bench, classes, summary, s, bad, mult


def fmt(n):
    return f"{n:,.0f}"


def maverick(ideal):
    """Maverick per request (1024 tokens, one checked output token)."""
    if ideal:
        # the model's own dims (not buildable: stwo-zig needs power-of-two dims)
        s = dict(T=1024, D=5120, H=40, Hkv=8, dh=128, F=16384, Fe=8192, Fs=8192, E=128, C=32, V=202048, Ph=2, P=1)
        s["Dkv"] = s["Hkv"] * s["dh"]
        s["Q"] = s["D"] + 2 * s["Dkv"]
        s["Nr"] = s["E"]
    else:
        # as stwo-zig would build it: power-of-two dims, router padded to the
        # 2^13-column weight table, fused QKV padded to a power of two
        s = dict(T=1024, D=8192, H=64, Hkv=8, dh=128, F=16384, Fe=8192, Fs=8192, E=128, C=32, V=1 << 18, Ph=2, P=1)
        s["Dkv"] = s["Hkv"] * s["dh"]
        s["Q"] = pow2ceil(s["D"] + 2 * s["Dkv"])
        s["Nr"] = 1 << 13
    dense = dense_layer(s, False)
    moe = moe_layer(s, False, shared=True)
    req = request_part(s, True)
    return s, dense, moe, req


def main(paths):
    runs = []
    for p in paths:
        bench, classes, summary, s, bad, mult = validate(p)
        runs.append((p, bench, classes, summary, s, bad, mult))
        print(f"== {p}: bench={bench['bench']} T={s['T']} D={s['D']} F={s['F']} H={s['H']} Hkv={s['Hkv']}"
              + (f" E={s['E']} C={s['C']} Fe={s['Fe']} V={s['V']} Nr={s['Nr']}" if bench["bench"] == "model" else ""))
        print(f"   committed {fmt(summary['committed_elems'])} elems, table {fmt(summary['table_elems'])} (padding {fmt(summary['padding_elems'])}),"
              f" multiplicity columns {fmt(mult)}; bits31 {fmt(summary['bits31'])}, used {fmt(summary['used_bits'])}"
              f" ({100 * summary['used_bits'] / max(summary['bits31'], 1):.1f}%)")
        print(f"   GKR leaves: direct {fmt(summary['gkr_leaves_direct'])}, virtual {fmt(summary['gkr_leaves_virtual'])}, tables {fmt(summary['gkr_leaves_tables'])}")
        print("   formula check: " + ("all classes match" if not bad else f"{len(bad)} MISMATCHES: {bad}"))
    for ideal in (True, False):
        s, dense, moe, req = maverick(ideal)
        nd = nm = 24
        tot_d = sum(dense.values())
        tot_m = sum(moe.values())
        tot_r = sum(req.values())
        # multiplicity columns: table sizes, ~8e4 measured, per request, plus
        # the range(lt + 9) table of the direct division-slack keys
        mult = 100_000 + direct_tables(s["T"], s["D"])
        n_w = nd * tot_d + nm * tot_m + tot_r + mult
        print(f"\n== Maverick ({'model dims, ideal' if ideal else 'power-of-two dims, as stwo-zig builds it'}): "
              f"T={s['T']} D={s['D']} H={s['H']} Hkv={s['Hkv']} F={s['F']} Fe={s['Fe']} Fs={s['Fs']} E={s['E']} C={s['C']} V={s['V']} Nr={s['Nr']} Q={s['Q']}")
        print(f"   n_w = 24 x dense({fmt(tot_d)}) + 24 x moe({fmt(tot_m)}) + request({fmt(tot_r)}) + mult({mult:.2e}) = {n_w:.3e} elements"
              f" = {n_w * 31 / 8 / 2**30:.1f} GiB at 31 bits")
        print(f"   per token per layer: dense {tot_d / s['T']:,.0f} elems ({31 * tot_d / s['T']:,.0f} bits), moe {tot_m / s['T']:,.0f} elems ({31 * tot_m / s['T']:,.0f} bits)")
        allc = {}
        for k, v in dense.items():
            allc[("dense",) + k] = nd * v
        for k, v in moe.items():
            allc[("moe",) + k] = nm * v
        for k, v in req.items():
            allc[("request",) + k] = v
        # group into op families for the ranking
        fam = {}
        for (part, scope, name), v in allc.items():
            f = family(part, scope, name)
            fam[f] = fam.get(f, 0) + v
        print("   ranking by share of committed bits (families):")
        for f, v in sorted(fam.items(), key=lambda x: -x[1]):
            print(f"     {f:44s} {v:12.4e} {100 * v / n_w:6.2f}%")
        for name, ns in (("ns/elem L9 dense", None),):
            pass
    print()
    for p, bench, classes, summary, s, bad, mult in runs:
        if "prove_s" in bench or "prove_s_per_request" in bench:
            ps = bench.get("prove_s", bench.get("prove_s_per_request"))
            nl = bench.get("layers", bench.get("n_layers", 1))
            print(f"timing {p}: prove {ps:.3f} s, {1e9 * ps / summary['committed_elems']:.1f} ns/committed elem,"
                  f" {1e9 * ps / s['T'] / nl:,.0f} ns/token/layer (all layers + request part), witness opening {summary['witness_opening_bytes']} B")


def family(part, scope, name):
    if scope == "attn" and name in ("scores", "sel", "d", "e"):
        return f"{part}: attention T^2 (scores/sel/d/e)"
    if scope == "attn":
        return f"{part}: attention T.D (acc/o/od/slack limbs, m/den)"
    if scope in ("rms1", "rms2", "rms.head"):
        return f"{part}: RMSNorm parts"
    if scope == "rope":
        return f"{part}: RoPE outputs"
    if scope == "attn.proj":
        return f"{part}: attention projections (qkv/wo out)"
    if scope == "mlp":
        return f"{part}: dense MLP (gate/up/silu/glu/down)"
    if scope == "moe.expert":
        return f"{part}: routed experts (E.C slot stacks)"
    if scope == "moe.shared":
        return f"{part}: shared expert (not implemented)"
    if scope == "moe.route":
        return f"{part}: MoE routing (logits/sel/dr/pre/disp/occ)"
    if scope == "residual":
        return f"{part}: residual stream"
    if scope == "embed":
        return f"request: embedding ({name})"
    if scope in ("head", "head.greedy"):
        return "request: LM head + greedy"
    return f"{part}: {scope}/{name}"


if __name__ == "__main__":
    main(sys.argv[1:])
