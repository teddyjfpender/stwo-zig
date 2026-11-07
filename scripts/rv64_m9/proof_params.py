#!/usr/bin/env python3
"""RV64 M9 stream m9-proof-params: PCS/FRI parameters per layer at equal security, and their GPU-s effect.

Design doc: design/riscv-proving-stack/rv64-m9-proof-params.md. Labels: [M] measured, [D] derived, [E] estimate.

Usage:
  python3 -I scripts/rv64_m9/proof_params.py [--json out.json] [--pow-rate GHS] [--n-trees N]

What it does (nothing here runs a GPU):
  1. Lists every layer's PCS/FRI parameters as the code defines them, and their conjectured / Johnson-regime bits.
  2. Fits, per recorded production leaf, a fixed + per-query row model per circuit component from the matched M6
     (native q108 b2) vs D2 (native q54 b4) node shapes of 24628607 and 26235156 [M rows, D fit].
  3. Prices every candidate parameter set at >= 128 conjectured bits on every layer:
       native  (log blowup, queries, PoW) -> native GPU-s (blowup share measured by nsys A/B) + leaf rows,
       leaf/fold outer proofs (log blowup, queries, PoW) -> their own commit GPU-s + parent fold rows,
       Merkle cap of the in-circuit child verifier (leaf: native proofs, fold: outer proofs),
       PoW grind GPU-s per proof (as-built kernel rate [M], engineered rate [E]).
  4. Writes per-layer factors that plan_model.py consumes as lever 'PARAMS'.
"""
import argparse, itertools, json, math, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PKG = 'vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package'
# Matched pairs: same block, same tree, native profile M6 (conjectured128_b2_q108_p20_fold4) vs D2 (d2_native_b4_q54_p20_fold4).
PAIRS = [('26235156', '26235156-combined-m6-v3', '26235156-combined-d2-coalesce-v1'),
         ('24628607', '24628607-combined-m6-v3', '24628607-combined-d2-only-head-v1')]

# --- circuit components (src/frontends/circuit/common/component_list.zig via scripts/rv64_m6_diet_receipt.py) ---
COMP = ['eq', 'qm31_ops', 'triple_xor', 'm_31_to_u_32', 'blake_g_gate']   # RECURSION_NODE_SHAPE raw=[...] order
W_MAIN = [4, 12, 20, 4, 52]
W_INTER = [8, 16, 48, 24, 104]
W_PP = [0, 0, 5, 3, 11]
LUT = [(16, 2, 8), (20, 16, 64), (8, 1, 8), (14, 1, 8), (18, 1, 8), (16, 1, 8)]   # constant lookup tables: (log, main, inter)
LUT_CELLS = sum((m + i) << lg for lg, m, i in LUT)
G_PER_COMPRESSION = 80   # Blake2s: 10 rounds x 8 G; one blake_g_gate row per G [code: circuit blake gadget]
TRIPLE_PER_BLAKE = 0.1   # triple_xor rows = blake_g rows / 10 on every recorded node [M]

# --- measured GPU-s splits (nsys CUPTI, NVTX-attributed; scripts/rv64_m9/nsys_proof_kind.py, receipts nsys-*.json) ---
# Native blowup A/B on the same blocks, b2 -> b4 (M6 -> D2), sum of a profiled warm pair [M]:
NATIVE_AB = {'26235156': (5.2916, 6.0560), '24628607': (7.6940, 8.7715)}
# Post-M8 fullstack 24628607 (codex/rv64-m8-gpu opt-combined ab8, pair): recursion GPU-s phases [M]
REC_M8 = dict(total=10.5699, witness=2.609 + 0.746,                        # MAIN-assignment + INTER-witness (raw-row bound)
              blowup=1.841 + 0.431 + 0.968 + 0.525 + 0.241 + 0.066,      # openings, deep, INTER lde+merkle, MAIN lde+merkle, FIXED, comp merkle
              comp_lde=1.769)                                             # composition-phase n2b (2N domain: may or may not scale)
NAT_M8 = dict(total=6.3348, blowup_phase_sum=1.322 + 0.344 + 0.532 + 0.294 + 0.299)   # openings, deep, MAIN, INTER, gap lde/merkle
# PoW: recursion pow phase 0.0272 GPU-s over 38 proofs at p20 (pair) [M] -> 0.716 ms per grind incl. launch + 2^18 grid overshoot
POW_MS_P20_AS_BUILT = 0.0272 / 38 * 1e3


def _git_show(path):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        return open(p).read()
    return subprocess.run(['git', '-C', ROOT, 'show', 'HEAD:' + path], capture_output=True, text=True, check=True).stdout


def node_shapes(run):
    out = {}
    for m in re.finditer(r'RECURSION_NODE_SHAPE node=(\d+) kind=(\w+) shape=\w+ raw=\[([\d,]+)\]', _git_show('%s/%s/producer.stderr' % (PKG, run))):
        out[int(m.group(1))] = (m.group(2), [int(x) for x in m.group(3).split(',')])
    return out


def padded(rows):
    return [1 << max(0, math.ceil(math.log2(max(1, r)))) for r in rows]


def cells(rows, pad=True):
    r = padded(rows) if pad else rows
    return sum(x * (a + b + c) for x, a, b, c in zip(r, W_MAIN, W_INTER, W_PP)) + LUT_CELLS


# --- security accounting (rv64-gkr-conjectured128-profile.md, rv64-m3-recursion-profile.md s"Soundness") ---
def conj_bits(lb, q, p):
    return lb * q + p                 # ethSTARK conjecture: each query <= rho = 2^-lb, PoW after the last FRI commit


def johnson_bits(lb, q, p):
    return lb * q / 2.0 + p           # robustness check: per-query sqrt(rho) (provable Johnson regime)


def min_queries(lb, p, target=128):
    return max(1, math.ceil((target - p) / lb))


# --- tree geometry of a child proof as seen by its in-circuit verifier ---
def tree_depths(trace_log, lb, fold_step=4, n_pcs=4, last_log=0):
    """Merkle depths of the child's PCS trees and FRI layer trees (FriConfig fold_step 4, last layer log 0)."""
    L = trace_log + lb
    pcs = [L] * n_pcs
    fri = []; d = L - 1; rem = trace_log - 1 - last_log
    fri.append(d)
    while rem > 0:
        s = min(fold_step, rem); rem -= s; d -= s
        if rem > 0 or last_log > 0:
            fri.append(d)
    return pcs + fri


def path_rows(depths, cap):
    """blake rows saved per query by a cap of 2^cap nodes per tree, and the one-off rows to hash each cap to its root."""
    save = sum(min(cap, d) for d in depths) * G_PER_COMPRESSION
    once = sum((1 << min(cap, d)) - 1 for d in depths) * G_PER_COMPRESSION
    return save, once


# --- leaf model: fixed + per-query rows per component, fitted on M6/D2 pairs ---
class Leaf:
    def __init__(self, block, node, y1, y2, n_trees, trace_log):
        self.block, self.node, self.y2, self.trace_log = block, node, y2, trace_log
        # depth term per query per +1 log blowup (every child tree one level deeper): blake_g and triple_xor only
        dt = [0, 0, n_trees * G_PER_COMPRESSION * TRIPLE_PER_BLAKE, 0, n_trees * G_PER_COMPRESSION]
        self.delta = dt
        # y1 = F + 108 r (b2), y2 = F + 54 (r + delta) (b4)  ->  r = (y1 - y2)/54 + delta, F = y1 - 108 r
        self.r = [(a - b) / 54.0 + d for a, b, d in zip(y1, y2, dt)]
        self.F = [a - 108 * r for a, r in zip(y1, self.r)]

    def rows(self, lb, q, cap=0):
        save, once = path_rows(tree_depths(self.trace_log, lb), cap) if cap else (0, 0)
        out = []
        for i in range(5):
            per_q = self.r[i] + (lb - 1) * self.delta[i]
            if i == 4:
                per_q -= save; extra = once
            elif i == 2:
                per_q -= save * TRIPLE_PER_BLAKE; extra = once * TRIPLE_PER_BLAKE
            else:
                extra = 0
            out.append(max(0.0, self.F[i] + extra + q * per_q))
        return out


def fit_leaves(n_trees=10):
    leaves, folds = [], []
    for block, m6, d2 in PAIRS:
        a, b = node_shapes(m6), node_shapes(d2)
        assert set(a) == set(b), (block, sorted(a), sorted(b))
        for n in sorted(a):
            ka, ya = a[n]; kb, yb = b[n]
            assert ka == kb
            if ka == 'leaf':
                trace_log = 22 if yb[0] > 50000 else 20   # segment leaves carry the large eq/receipt rows; truth leaves smaller [E]
                leaves.append(Leaf(block, n, ya, yb, n_trees, trace_log))
            else:
                folds.append((block, n, yb))
    return leaves, folds


# --- fold model: per-child rows proportional to the child's queries, 5.5% fixed (recsize fit) ---
FOLD_FIXED = 0.0546   # recsize m3-fold-census: vars(q) = 0.0546 + 0.008754 q relative to q108 [D]
FOLD_CHILD_TRACE_LOG = 23
CUR_FOLD_CAP = 3


def fold_rows(y_now, lb_child, q_child, cap, n_children=None):
    """Rows of a fold whose children are outer proofs at (lb_child, q_child) verified with Merkle cap `cap`.
    Calibrated on the recorded fold y_now (children at r1 b2 q108, cap 3)."""
    blake_now = y_now[4]
    if n_children is None:
        n_children = max(1, round(blake_now / 1.94e6))
    dep1 = tree_depths(FOLD_CHILD_TRACE_LOG, 1)
    s3, k3 = path_rows(dep1, CUR_FOLD_CAP)
    out = []
    for i in range(5):
        fixed = y_now[i] * FOLD_FIXED
        child = (y_now[i] - fixed) / n_children
        if i in (2, 4):
            scale = 1.0 if i == 4 else TRIPLE_PER_BLAKE
            a = (child - k3 * scale) / 108.0 + s3 * scale        # per query, full paths, at lb 1
            depn = tree_depths(FOLD_CHILD_TRACE_LOG, lb_child)
            s, k = path_rows(depn, cap)
            per_q = a + (lb_child - 1) * len(depn) * G_PER_COMPRESSION * scale - s * scale
            out.append(fixed + n_children * (q_child * per_q + k * scale))
        elif i == 0:
            out.append(y_now[i])
        else:
            out.append(fixed + child * q_child / 108.0 * n_children)
    return out


# --- GPU-s model per recursion node: witness ~ raw rows, the rest ~ padded rows, blowup share ~ 2^(lb-1) ---
def node_factor(y0, y1, lb_own, phi_r, w, pad=True):
    base = cells(y0, pad); new = cells(y1, pad)
    raw0 = cells(y0, False); raw1 = cells(y1, False)
    blow = 1 - phi_r + phi_r * 2.0 ** (lb_own - 1)
    return w * raw1 / raw0 + (1 - w) * new / base * blow


SCN = {  # (pess, central, opt)
    'phi_r': (0.55, 0.47, 0.385),        # blowup-proportional share of recursion node GPU-s at lb 1 [D, nsys phases; high = +composition 2N LDE]
    'w_rec': (0.30, 0.318, 0.33),        # raw-row-bound witness share of recursion GPU-s [M 0.318]
    # native blowup share at lb 2 (b4): M7-era A/B 0.123 per b2->b4 step -> 0.246 at b4 [M]; post-M8 phase sum / 1.41 = 0.31 [D]; 0.39 raw phase sum
    'phi_n': (0.39, 0.31, 0.25),
    'pow_kernel': ('as_built', 'check64', 'check64'),   # grind kernel: as built [M] or engineered check-every-64 [M dev-5090]
}


# Measured grind cost per proof [M dev-5090], m9_pow_bench (vectors/reports/rv64-m9-prep/m9-proof-params/pow-bench-dev5090.jsonl):
# mean ms per grind over 4 seeds. 'as_built' = search.cu today; 'check64' = engineered (best nonce read once per 64 candidates,
# same minimal nonce on 28/28 grinds). Above 28 bits: x4 per 2 bits [D].
POW_MS = {'as_built': {16: 0.3035, 18: 0.3371, 20: 0.7439, 22: 1.9237, 24: 4.6317, 26: 27.8883, 28: 144.2073},
          'check64': {16: 0.4692, 18: 0.4597, 20: 0.4754, 22: 0.5634, 24: 0.7552, 26: 2.6793, 28: 15.8809}}


def pow_gpu_s(p, kernel):
    t = POW_MS[kernel]
    if p in t:
        return t[p] * 1e-3
    if p > 28:
        return t[28] * 1e-3 * 2.0 ** (p - 28)
    lo = max(k for k in t if k < p); hi = min(k for k in t if k > p)
    return (t[lo] + (t[hi] - t[lo]) * (p - lo) / (hi - lo)) * 1e-3


def native_factor(lb, phi_n):
    return 1 - phi_n + phi_n * 2.0 ** (lb - 2)


# --- candidate parameter sets ---
POW_GRID = (20, 24, 26, 28, 32)
CURRENT = dict(native=(2, 54, 20), leaf=(1, 108, 20), fold=(1, 108, 20), leaf_cap=0, fold_cap=3)


SETS = {
    # recommended
    'A_caps5': dict(CURRENT, leaf_cap=5, fold_cap=5),                       # inside today's verifier guard (cap_log <= 5); no child proof changes
    'A_caps67': dict(CURRENT, leaf_cap=6, fold_cap=7),                      # model optimum; raise the guard to 7
    'B_caps67_pow24': dict(native=(2, 52, 24), leaf=(1, 104, 24), fold=(1, 104, 24), leaf_cap=6, fold_cap=7),   # + PoW 24 everywhere
    # rejected (for the record)
    'X_native_b8_q36_p20': dict(CURRENT, native=(3, 36, 20)),
    'X_native_b8_q32_p32': dict(CURRENT, native=(3, 32, 32)),
    'X_native_b4_q48_p32': dict(CURRENT, native=(2, 48, 32)),
    'X_native_b2_q108_p20_revert_d2': dict(CURRENT, native=(1, 108, 20)),
    'X_outer_b4_q51_p26_all': dict(CURRENT, leaf=(2, 51, 26), fold=(2, 51, 26)),
    'X_outer_b4_folds_only': dict(CURRENT, fold=(2, 51, 26)),
    'X_outer_b2_q96_p32': dict(CURRENT, leaf=(1, 96, 32), fold=(1, 96, 32)),
}


def native_candidates():
    out = []
    for lb in (1, 2, 3, 4):
        for p in POW_GRID:
            out.append((lb, min_queries(lb, p), p))
    return out


def outer_candidates():
    out = []
    for lb in (1, 2, 3):
        for p in POW_GRID:
            out.append((lb, min_queries(lb, p), p))
    return out


def evaluate(cfg, leaves, folds, sc, pad=True, mix=None):
    """Return per-layer GPU-s factors vs CURRENT for one scenario dict sc; pad=False models tight packing (fan-in)."""
    lbn, qn, pn = cfg['native']; lbl, ql, pl = cfg['leaf']; lbf, qf, pf = cfg['fold']
    # leaves: rows from the native params and the leaf cap; own commit at the leaf profile's blowup
    num = den = 0.0
    for lf in leaves:
        y0 = lf.rows(2, 54, 0); y1 = lf.rows(lbn, qn, cfg['leaf_cap'])
        g0 = cells(y0, pad)
        num += g0 * node_factor(y0, y1, lbl, sc['phi_r'], sc['w_rec'], pad); den += g0
    leaf_f = num / den
    # folds: level-1 folds verify leaf proofs, upper folds verify fold proofs. mix = share of fold GPU-s at level 1.
    mix = 0.75 if mix is None else mix
    num = den = 0.0
    for (_, _, y) in folds:
        g0 = cells(y, pad)
        y_l1 = fold_rows(y, lbl, ql, cfg['fold_cap']); y_up = fold_rows(y, lbf, qf, cfg['fold_cap'])
        f = mix * node_factor(y, y_l1, lbf, sc['phi_r'], sc['w_rec'], pad) + (1 - mix) * node_factor(y, y_up, lbf, sc['phi_r'], sc['w_rec'], pad)
        num += g0 * f; den += g0
    fold_f = num / den
    nat_f = native_factor(lbn, sc['phi_n']) / native_factor(2, sc['phi_n'])
    dpow_nat = pow_gpu_s(pn, sc['pow_kernel']) - pow_gpu_s(20, sc['pow_kernel'])
    dpow_leaf = pow_gpu_s(pl, sc['pow_kernel']) - pow_gpu_s(20, sc['pow_kernel'])
    dpow_fold = pow_gpu_s(pf, sc['pow_kernel']) - pow_gpu_s(20, sc['pow_kernel'])
    return dict(native=nat_f, leaf=leaf_f, fold=fold_f, dpow_native_proof=dpow_nat, dpow_leaf_proof=dpow_leaf, dpow_fold_proof=dpow_fold)


def gpu_s_at(block_shape, fac, base):
    """Kernel GPU-s of a request given a post-lever baseline split base=(N, Rl, Rf) and the node counts."""
    N, Rl, Rf = base
    nat_proofs = block_shape['seg'] + block_shape['truths']
    return (N * fac['native'] + nat_proofs * fac['dpow_native_proof'] + Rl * fac['leaf'] + block_shape['leaves'] * fac['dpow_leaf_proof']
            + Rf * fac['fold'] + block_shape['folds'] * fac['dpow_fold_proof'])


def root_bytes(q):
    # recsize roots: r1 q108 705,624 B; m3 q51 389,980 B -> 5,538 B/query + 107,5xx fixed [D, 2 points]
    b = (705624 - 389980) / (108 - 51)
    return 705624 - b * (108 - q)


def security_table():
    rows = []
    def add(layer, name, lb, q, p, fold=4, last=0, cap=None, src=''):
        rows.append(dict(layer=layer, profile=name, log_blowup=lb, blowup=1 << lb, queries=q, pow_bits=p, fold_step=fold, folding_arity=1 << fold,
                         log_last_layer_degree=last, merkle_cap_log_in_parent=cap, conjectured_bits=conj_bits(lb, q, p),
                         johnson_bits=johnson_bits(lb, q, p), source=src))
    add('native', 'd2_native_b4_q54_p20_fold4 (production)', 2, 54, 20, cap=0,
        src='src/integrations/riscv_cpu/word16_execution/om31_security_candidate.zig configFor')
    add('native', 'conjectured128_b2_q108_p20_fold4 (M6, default of the CPU route)', 1, 108, 20, cap=0, src='same')
    add('native', 'proven_beta2_q256_p0_fold4 (unique-decoding model)', 2, 256, 0, cap=0, src='same')
    add('leaf (outer proof of a leaf circuit)', 'm7/m6 k4-cap3 r1 b2 q108 p20 (production)', 1, 108, 20, cap=3,
        src='src/integrations/circuit_cpu/om31/protocol.zig Profile.config')
    add('fold (outer proof of a fold circuit)', 'm7/m6 k4-cap3 r1 b2 q108 p20 (production)', 1, 108, 20, cap=3, src='same')
    add('root (top fold, exported)', 'same as fold', 1, 108, 20, cap=None, src='same; no separate root STARK (d2-composed README)')
    add('outer alt', 'm3_b4_q51_p26_fold4 (shelved, 4-ary OOM)', 2, 51, 26, cap=0, src='protocol.zig')
    add('outer alt', 'm3_b8_q34_p26_fold4', 3, 34, 26, cap=0, src='protocol.zig')
    add('legacy rv64 suite', 'frontends/riscv/rv64/air/protocol.zig config()', 1, 70, 26, cap=None,
        src='frontends/riscv/rv64/air/protocol.zig (not the GPU route)')
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json'); ap.add_argument('--n-trees', type=int, default=10)
    a = ap.parse_args()
    leaves, folds = fit_leaves(a.n_trees)
    P = {n: {k: v[i] for k, v in SCN.items()} for i, n in enumerate(['pess', 'central', 'opt'])}
    res = dict(schema='rv64-m9-proof-params/v1', labels='M measured, D derived, E estimate', security=security_table())
    # fit quality: D2 rows reproduced exactly by construction; report fixed / per-query split
    fit = []
    for lf in leaves:
        y = lf.rows(2, 54)
        fit.append(dict(block=lf.block, node=lf.node, d2_rows=lf.y2, model_d2_rows=[round(x) for x in y],
                        fixed_share_at_d2=[round(f / max(1, t), 3) for f, t in zip(lf.F, y)],
                        per_query_rows_at_d2=[round(r + d) for r, d in zip(lf.r, lf.delta)]))
    res['leaf_fit'] = fit
    nat = sum(NATIVE_AB['24628607']); res['native_ab'] = {b: dict(m6=v[0], d2=v[1], ratio=v[1] / v[0]) for b, v in NATIVE_AB.items()}
    # 1) layer-by-layer sweeps around CURRENT (one layer changed at a time)
    sweeps = {}
    for layer, cands in (('native', native_candidates()), ('leaf', outer_candidates()), ('fold', outer_candidates())):
        rows = []
        for c in cands:
            cfg = dict(CURRENT); cfg[layer] = c
            r = dict(params=c, conjectured_bits=conj_bits(*c), johnson_bits=johnson_bits(*c))
            for pad in (True, False):
                for n, sc in P.items():
                    r[('padded' if pad else 'packed') + '_' + n] = evaluate(cfg, leaves, folds, sc, pad)
            rows.append(r)
        sweeps[layer] = rows
    for cap in range(0, 9):
        cfg = dict(CURRENT); cfg['leaf_cap'] = cap
        sweeps.setdefault('leaf_cap', []).append(dict(params=cap, **{('padded' if pad else 'packed') + '_' + n: evaluate(cfg, leaves, folds, sc, pad)
                                                                   for pad in (True, False) for n, sc in P.items()}))
    for cap in range(0, 10):
        cfg = dict(CURRENT); cfg['fold_cap'] = cap
        sweeps.setdefault('fold_cap', []).append(dict(params=cap, **{('padded' if pad else 'packed') + '_' + n: evaluate(cfg, leaves, folds, sc, pad)
                                                                   for pad in (True, False) for n, sc in P.items()}))
    res['sweeps'] = sweeps
    # 2) joint search at the p50 post-lever split (from plan_model #1-#9 central): minimise kernel GPU-s
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import plan_model as pm
    PP = {n: {k: v[i] for k, v in pm.SC.items()} for i, n in enumerate(['pess', 'central', 'opt'])}
    bk = pm.basket(); ipg = sum(r['mi'] for r in bk) / sum(r['gas'] / 1e6 for r in bk)
    mi = pm.GAS_PCT_EMBEDDED[50] * ipg; sh = pm.shape(mi)
    best9 = tuple(l for l in pm.LEVER_ORDER if l != 'GPU4')
    base = {}
    for n in PP:
        m = pm.model(mi, sh, PP[n], on=best9)
        # split recursion into leaves / folds with the fan-in leaf share (all #1-#9 sets include LEAVES)
        base[n] = (m['native_gpu_s'], m['recursion_gpu_s'] * pm.FANIN_LEAF_SHARE, m['recursion_gpu_s'] * (1 - pm.FANIN_LEAF_SHARE), m)
    search = {}
    for n, sc in P.items():
        N, Rl, Rf, m = base[n]
        shp = dict(seg=sh['seg'], truths=sh['truths'], leaves=m['leaves'], folds=m['nodes'] - m['leaves'])
        k0 = N + Rl + Rf
        best = []
        for nat_c in native_candidates():
            for leaf_c in outer_candidates():
                for fold_c in outer_candidates():
                    for lc in (0, 6):
                        for fc in (3, 7):
                            cfg = dict(native=nat_c, leaf=leaf_c, fold=fold_c, leaf_cap=lc, fold_cap=fc)
                            fac = evaluate(cfg, leaves, folds, sc, pad=False)   # #1-#9 includes k-leaf fan-in: packed leaves
                            k = gpu_s_at(shp, fac, (N, Rl, Rf))
                            best.append((k / k0, cfg, fac))
        best.sort(key=lambda x: x[0])
        cur = [b for b in best if b[1] == dict(CURRENT, leaf_cap=0, fold_cap=3)][0]
        search[n] = dict(p50_kernel_gpu_s_after_1_9=k0, current_factor=cur[0],
                         top=[dict(factor=f, cfg=c, fac=x) for f, c, x in best[:12]])
    res['search_p50_after_1_9'] = search
    # 3) named sets: factors for plan_model (lever PARAMS), packed (with k-leaf fan-in) and padded (exact pow2 rows)
    named = {}
    for name, cfg in SETS.items():
        row = dict(cfg=cfg, bits={k: dict(conjectured=conj_bits(*cfg[k]), johnson=johnson_bits(*cfg[k])) for k in ('native', 'leaf', 'fold')},
                   root_bytes=root_bytes(cfg['fold'][1]), root_bytes_now=root_bytes(108))
        for pad in (True, False):
            for n, sc in P.items():
                row[('padded' if pad else 'packed') + '_' + n] = evaluate(cfg, leaves, folds, sc, pad)
        for n, sc in P.items():
            N, Rl, Rf, m = base[n]
            shp = dict(seg=sh['seg'], truths=sh['truths'], leaves=m['leaves'], folds=m['nodes'] - m['leaves'])
            k = gpu_s_at(shp, row['packed_' + n], (N, Rl, Rf))
            row['p50_after_1_9_' + n] = dict(kernel_gpu_s=k, base=N + Rl + Rf, factor=k / (N + Rl + Rf))
        named[name] = row
    res['sets'] = named
    # 4) sensitivity of the recommended sets to the fit assumptions [D]: depth term (n_trees), fold fixed share, native trace log
    global FOLD_FIXED
    sens = {}
    keep = FOLD_FIXED
    for nt in (8, 10, 12):
        for ff in (0.03, keep, 0.10):
            for tl in (21, 22, 23):
                FOLD_FIXED = ff
                lv, fo = fit_leaves(nt)
                for lf in lv:
                    if lf.trace_log >= 21: lf.trace_log = tl
                for name in ('A_caps5', 'A_caps67', 'B_caps67_pow24'):
                    for pad in (True, False):
                        f = evaluate(SETS[name], lv, fo, P['central'], pad)
                        sens.setdefault(name + ('_padded' if pad else '_packed'), []).append((f['leaf'], f['fold'], nt, ff, tl))
    FOLD_FIXED = keep
    res['sensitivity'] = {k: dict(leaf_min=min(x[0] for x in v), leaf_max=max(x[0] for x in v), fold_min=min(x[1] for x in v), fold_max=max(x[1] for x in v))
                          for k, v in sens.items()}
    if a.json:
        os.makedirs(os.path.dirname(a.json), exist_ok=True)
        json.dump(res, open(a.json, 'w'), indent=1, sort_keys=True, default=str)
    # ---- print ----
    print('== security (conjectured = lb*q + pow; Johnson-regime robustness = lb*q/2 + pow)')
    for r in res['security']:
        print('  %-38s %-58s b%-3d q%-4d p%-3d fold%-3d cap %-4s conj %5.1f  johnson %5.1f' % (r['layer'], r['profile'], r['blowup'], r['queries'], r['pow_bits'],
              r['folding_arity'], r['merkle_cap_log_in_parent'], r['conjectured_bits'], r['johnson_bits']))
    print('\n== native blowup A/B b2->b4 [M]:', {b: round(v['ratio'], 3) for b, v in res['native_ab'].items()})
    print('== leaf fit: fixed share of rows at D2 (eq, qm31, triple, m31u32, blake) [D]')
    for f in fit[:6]:
        print('  ', f['block'], f['node'], f['fixed_share_at_d2'], 'per-query', f['per_query_rows_at_d2'])
    for layer in ('native', 'leaf', 'fold', 'leaf_cap', 'fold_cap'):
        print('\n== sweep %s (others at CURRENT): factors native / leaf / fold, packed central | padded central' % layer)
        for r in sweeps[layer]:
            c = r['packed_central']; d = r['padded_central']
            bits = ('conj %5.1f john %5.1f' % (r['conjectured_bits'], r['johnson_bits'])) if 'conjectured_bits' in r else ''
            print('  %-14s %s | nat %.3f leaf %.3f fold %.3f dpow %.4f/%.4f/%.4f s | padded leaf %.3f fold %.3f'
                  % (r['params'], bits, c['native'], c['leaf'], c['fold'], c['dpow_native_proof'], c['dpow_leaf_proof'], c['dpow_fold_proof'], d['leaf'], d['fold']))
    print('\n== named sets: packed factors native / leaf / fold (pess | central | opt), p50 after #1-#9 kernel GPU-s factor')
    for name, r in named.items():
        print('  %-32s ' % name + ' | '.join('%.3f/%.3f/%.3f' % (r['packed_' + n]['native'], r['packed_' + n]['leaf'], r['packed_' + n]['fold']) for n in P)
              + '   p50 x' + '/'.join('%.4f' % r['p50_after_1_9_' + n]['factor'] for n in P) + '  root %.0f kB' % (r['root_bytes'] / 1e3))
    print('\n== sensitivity (central, n_trees 8-12, fold fixed 3-10%, segment trace log 21-23): leaf / fold factor ranges')
    for k, v in res['sensitivity'].items():
        print('  %-28s leaf %.3f..%.3f  fold %.3f..%.3f' % (k, v['leaf_min'], v['leaf_max'], v['fold_min'], v['fold_max']))
    for n, s in search.items():
        print('\n== joint search %s: p50 kernel GPU-s after #1-#9 = %.2f; current params factor %.4f' % (n, s['p50_kernel_gpu_s_after_1_9'], s['current_factor']))
        for t in s['top'][:6]:
            print('   x%.4f  %s' % (t['factor'], t['cfg']))


if __name__ == '__main__':
    main()
