#!/usr/bin/env python3
"""RV64 M9 plan model: gas-weighted targets and the >60% cut budget on 2x RTX 5090.

Design doc: design/riscv-proving-stack/rv64-m9-plan.md. Labels: [M] measured, [D] derived, [E] estimate.

Usage:
  python3 -I scripts/rv64_m9/plan_model.py [--gas-sample gas_sample.json] [--json out.json]

Without --gas-sample the mainnet percentiles embedded below (computed from the 2,897-block sample) are used.
Every constant names its receipt. Nothing here runs a GPU.
"""
import argparse, json, math, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- mainnet gas sample (Sep 20 - Oct 20 2026, blocks 26.02M-26.24M, 60M limit) [M] ---
GAS_PCT_EMBEDDED = {5: 8.33, 10: 15.84, 25: 23.38, 50: 29.11, 75: 37.17, 90: 47.11, 95: 55.82, 99: 59.99}

# --- bench15-1 default arm, warm medians of 3, 2x5090 (codex/rv64-m8-gpu b289b021f,
#     vectors/reports/rv64-m8-20261106/bench15/SUMMARY.md) [M] ---
BENCH15 = {  # block: (Minstr, segs, warm_proving_s, capture_s, native_window_s, rec_after_native_s, kernel_gpu_s)
    26235156: (15.305679, 4, 9.55, 1.73, 2.84, 4.84, 6.56),
    24647140: (24.598260, 6, 11.46, 1.99, 3.83, 5.38, 8.47),
    24628607: (26.894777, 7, 11.77, 2.10, 3.81, 5.69, 8.43),
    25229957: (27.077168, 7, 12.51, 2.14, 4.05, 6.18, 9.12),
    24628608: (38.600821, 10, 17.03, 2.88, 6.87, 7.27, 11.72),
    24697070: (57.790096, 14, 25.14, 3.74, 11.19, 10.06, 18.39),
}

# --- 24628607 kernel census, opt-combined warm (vectors/reports/rv64-m8-20261106/opt-combined/README.md) [M] ---
# The ab8 'fullstack' total 8.478 includes T2 (chain_flow 1.141). T2 is default OFF (chain_run 0.996), so the
# default-consistent total is 8.478 - 0.145 = 8.333 [D] (bench15-1 measured 8.43 on the default image [M]).
K607 = 8.478 - (1.141 - 0.996)  # kernel GPU-s, CUPTI union, both GPUs, T2 off [D]
K607_FFT = 2.975       # all b2n/n2b/lde/fft kernels
K607_MERKLE = 1.430    # mixed_leaf_kernel 1.250 + child_layer_kernel 0.180
K607_CHAIN = 0.996     # recursion witness DAG: chain_run (T2 chain_flow 1.141 is off by default)
# native/recursion split [D]: M7 exact cells (engineering scope s1, 4-GPU doc s2.1) times M6 ns/cell
#   native 5.454 G x 0.72 ns = 3.93 GPU-s; recursion 21.7 G x 0.29 ns = 6.29 GPU-s; sum 10.22 vs 10.58 [M]
NATIVE_FRAC_607 = 3.93 / (3.93 + 6.29)
STAGE1_FRAC = 1.04 / (1.04 + 1.78)   # M8 gpu-native s5: Stage1 1.04 / Stage2 1.78 job GPU-s on 24628607 [M]
L607, F607 = 14, 5                    # leaves / folds on 24628607 at M7 default (14 leaves / 19 nodes) [M]
LEAF_K, FOLD_K = 0.47, 0.42           # relative GPU-s per leaf / per fold (levers.py, M6 recursion window by cells) [D]
# native truth share, M3 native fit 1.11 + 0.192*Minstr + 0.141*truths s (4-GPU doc s1.2, R2 0.994) [D]
M3_NAT = (1.11, 0.192, 0.141)

# --- capture with T1 (opt-T1-capture-parallel/README.md: 26235159 5.76 s; 24628607 2.07 s) [M] ---
CAP_A = 2.07 - (5.76 - 2.07) / (204.825818 - 26.894777) * 26.894777
CAP_B = (5.76 - 2.07) / (204.825818 - 26.894777)

# --- IO (rv64-m9-io-streaming.md s1.2, s5): H2D 0.614 link-s on the slower GPU, 24628607 warm [M];
#     after M8 removes geometry + fold statics, leaf statics stay per node [E]
IO_LINK_607_POST_M8 = 0.31  # s per GPU: 7.6 GB leaf statics/GPU at the in-request 24.6 GB/s [D, packed-ingress review]
IO_EXPOSED = 0.46           # share of H2D copy time exposed (packed-ingress review x0.46) [D]
DECODE_PER_LEAF = 0.004     # GPU-s per leaf node to decode packed statics on device (2.85-4.48 ms/node, ~4.0 at 0.83 GB) [M/E]

# --- k-leaf fan-in (codex/rv64-m9-fewer-leaves a056cee67, vectors/reports/rv64-m9-prep/m9-fewer-leaves/model.json,
#     option leafk_blake23_same = recommended): recursion-cell ratio and leaves after, per basket block [D/E] ---
FANIN_SAME = {  # block: (cell ratio, leaves, folds, depth) after fan-in
    26235156: (0.795, 7, 3, 2), 24647140: (0.858, 9, 3, 2), 24628607: (0.822, 9, 3, 2), 25229957: (0.822, 9, 3, 2),
    24628608: (0.853, 11, 4, 2), 24626900: (0.811, 12, 4, 2), 24697070: (0.754, 16, 5, 2), 24697073: (0.767, 14, 5, 2),
    26235168: (0.761, 24, 9, 3), 25229955: (0.762, 24, 9, 3), 24628590: (0.786, 28, 10, 3), 25229951: (0.774, 29, 10, 3),
    24628595: (0.760, 32, 11, 3), 24628611: (0.762, 32, 11, 3), 26235159: (0.757, 36, 12, 3)}
FANIN_LEAF_SHARE = 0.72     # leaf share of recursion cells after fan-in (26235168: 41.45 of 57.5 G) [D]

# --- Poseidon2 leaves (codex/rv64-m9-poseidon2-leaves 37e581cfc, m9-poseidon2-leaves/model.json projection_E.p50,
#     reviewed): recursion factor, native hashing GPU-s per Minstr, serial transcript GPU-s per Minstr ---
P2_AS_BUILT = (15.34 / 17.61, 4.12 / 103.3, 6.83 / 103.3)   # sponge node, x9.95 kernel, transcript x23.9 [M/D]
P2_2TO1_K06 = (8.91 / 17.61, 1.90 / 103.3, 6.83 / 103.3)    # 2-to-1 node + P2 kernels x0.6, transcript as built [E]
P2_ENGINEERED = (8.91 / 17.61, 1.90 / 103.3, 0.60 / 103.3)  # + parallel transcript at x3 Blake (protocol change) [E]

# --- GPU capture replay (codex/rv64-m9-gpu-replay 7d9850bab, m9-gpu-replay/first_pass_basket.json) [M]:
#     seeded serial first pass seconds, curve-service seconds and curve calls per basket block (2x5090 pod host) ---
FIRST_PASS = {  # block: (seeded_s, curve_s, curve_calls)
    26235156: (0.1241, 0.0, 0), 24647140: (0.1664, 0.0, 0), 24628607: (0.1693, 0.0, 0), 25229957: (0.1858, 0.0, 0),
    24628608: (0.2427, 0.0, 0), 24626900: (0.3312, 0.0, 0), 24697070: (0.5347, 0.16, 14109), 24697073: (0.939, 0.5212, 14070),
    26235168: (1.9483, 1.2612, 77790), 25229955: (1.1635, 0.4879, 38560), 24628590: (0.9693, 0.0, 0),
    25229951: (1.154, 0.2438, 19279), 24628595: (1.2548, 0.1445, 13152), 24628611: (1.7132, 0.5352, 14070),
    26235159: (2.6462, 1.5068, 60853)}

# --- M9 recursion-arch (codex/rv64-m9-recursion-arch, vectors/reports/rv64-m9-prep/m9-recursion-arch/{census.jsonl,model.json}):
#     padded recursion-cell factor vs the same tree at the production outer profile, per basket block [D on M]:
#     (factor with the log-24 composition tax [E], factor without it, folds, tree depth). Arity re-optimised. ---
REC_ARCH_JSON = os.path.join(ROOT, 'vectors/reports/rv64-m9-prep/m9-recursion-arch/model.json')
# lever x tree -> model.json tree key (post-M8 tree: env23 envelope; fan-in tree: blake23, qm31 may reach 2^24)
REC_ARCH_KEYS = {
    ('RECDIET', 'pm8'): 'post_m8/env23/diet', ('RECDIET', 'fan'): 'fanin/blake23/diet',
    ('RECBATCH', 'pm8'): 'post_m8/env23/batch2_diet/all', ('RECBATCH', 'fan'): 'fanin/blake23/batch2_diet/all',
    ('RECNB3', 'pm8'): 'post_m8/env23/diet+native_blake3', ('RECNB3', 'fan'): 'fanin/blake23/diet+native_blake3',
}


def rec_arch_table(path=REC_ARCH_JSON):
    """Read the per-block factors from model.json (no hand-copied table, so the plan cannot drift from the receipt)."""
    trees = json.load(open(path))['trees']
    out = {}
    for lk, key in REC_ARCH_KEYS.items():
        t = trees[key]
        out[lk] = dict(arity=t['arity'], key=key, job_fits_post_p1=t['max_job_post_p1_ok'],
                       blocks={int(b): (round(t['factor_taxed'][b], 3), round(t['factor'][b], 3), v['folds'], v['depth'])
                               for b, v in t['blocks'].items()})
    return out


REC_ARCH = rec_arch_table()


def _fp_fixed(v):  # first pass with the curve arithmetic fixed (Montgomery limbs): 1 us per curve call [E]
    return v[0] - v[1] + v[2] * 1e-6


def fit(xs, ys):
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx
    ss = sum((y - a - b * x) ** 2 for x, y in zip(xs, ys)); st = sum((y - my) ** 2 for y in ys)
    return a, b, 1 - ss / st


def basket():
    rd = json.load(open(os.path.join(ROOT, 'vectors/reports/rv64-cuda-real-segment-20261103/basket-input-readiness.json')))
    gas = {r['block']: r['gas_used'] for r in rd['blocks']}
    m3 = json.load(open(os.path.join(ROOT, 'vectors/reports/rv64-m3-20261104/summary.json')))
    rows = []
    for r in m3['rows']:
        rows.append(dict(block=r['block'], gas=gas[r['block']], mi=r['instructions'] / 1e6, seg=r['cpu_segments'],
                         truths=r['truth_proofs'], m3_s=r['request_s']))
    return sorted(rows, key=lambda r: r['gas'])


def folds(L, k=4):
    f = 0; lv = 0; n = L
    while n > 1:
        n = math.ceil(n / k); f += n; lv += 1
    return f, lv


def _fp_fit():
    _bm = {r['block']: r['mi'] for r in basket()}
    return fit([_bm[b] for b in FIRST_PASS], [_fp_fixed(v) for v in FIRST_PASS.values()])


KFIT = fit([v[0] for v in BENCH15.values()], [v[6] for v in BENCH15.values()])
WFIT = fit([v[0] for v in BENCH15.values()], [v[2] for v in BENCH15.values()])
FP_FIT = _fp_fit()  # services-fixed first pass s vs Minstr over the basket (synthetic p50/p95) [D]
N_PER_MI = K607 * NATIVE_FRAC_607 / 26.894777  # native kernel GPU-s per M instr [D]


def _bench15_truths():
    rd = json.load(open(os.path.join(ROOT, 'vectors/reports/rv64-m3-20261104/summary.json')))
    return {r['block']: r['truth_proofs'] for r in rd['rows']}


def shape(mi, truths=None, block=None):
    seg = math.ceil(mi * 1e6 / (1 << 22))
    if truths is None:  # basket fit truths ~ segments (M3 receipts) [D]
        truths = round(7.6 + 0.37 * seg)
    tl = max(2, math.ceil(0.7 * truths))  # coalesced truth leaves (24628607: 10 truths -> 7 leaves) [E]
    L = seg + tl
    F, lv = folds(L)
    return dict(block=block, seg=seg, truths=truths, truth_leaves=tl, leaves=L, folds=F, levels=lv)


# Recursion GPU-s fit on recursion NODES, not instructions [D]: R_obs = kernel - native(Minstr) on the 6 bench15-1 rows.
# M3 recursion time tracks leaves (6.49 + 1.196*leaves, R2 0.997 over 15 blocks, 4-GPU doc s1.2); on bench15-1
# nodes fit R2 0.953 vs Minstr 0.942. The Minstr fit over-charges recursion on big blocks (truths grow sub-linearly).
_T = _bench15_truths()
_NODES = [(lambda sh: sh['leaves'] + sh['folds'])(shape(v[0], _T[b])) for b, v in BENCH15.items()]
RFIT = fit(_NODES, [v[6] - N_PER_MI * v[0] for v in BENCH15.values()])


def truth_native_share(mi, truths):
    a, b, c = M3_NAT
    return c * truths / (a + b * mi + c * truths)


# Scenario parameters (pess, central, opt). Baseline = post-M8 GPU-native.
SC = {
    'k_m8': (1.0, 0.95, 0.90),        # kernel GPU-s after GPU-native vs bench15 (setup/replay moved to warm) [E]
    'busy': (0.60, 0.72, 0.80),       # GPU busy in the post-seal window after GPU-native [E]
    'busy_tail': (0.70, 0.80, 0.85),
    'head': (0.5, 0.4, 0.3),          # first segment ready [E, M8 s5]
    'fixed': (0.4, 0.3, 0.2),         # admission, warm setup, publish, readback [E; bench15 setup 0.11-0.21 + tail 0.03-0.07 M]
    # levers
    'p2': (P2_AS_BUILT, P2_2TO1_K06, P2_ENGINEERED),  # Poseidon2 (rec factor, native/Minstr, transcript/Minstr) [M/D/E]
    'fanin_d': (0.04, 0.0, -0.03),    # k-leaf cell ratio offset: pess ~ k2 policy (0.79-0.80), opt ~ any-family (0.72-0.75) [D]
    # streaming commit, reviewed (codex/rv64-m9-stream-commit 42ce18195): fused LDE->leaf loses x1.03-1.61 at log 22-24 [M];
    # aligned c32 chunks -0.11 GPU-s calibrated to T6 [D/E]; partial trees save memory, not time [M]; opt = recursion 2^26
    # chunk fix pays its -0.41 and fused tail at log <= 21 [E]
    'stream': (0.975, 0.955, 0.90),
    # witness rowpar, reviewed (codex/rv64-m9-witness-rowpar 4459242f1): leaf x0.513 / fold x0.760 measured on recorded nodes;
    # production whole assignment x0.70 (x0.60..0.80) [E]; opt = hybrid (tail on chain_run, not prototyped) x0.55 [E].
    # Class hits only: a new block runs the DAG (planner 0.4-1.0 s/node off the critical path) [E].
    'wit': (0.80, 0.70, 0.55),
    'io_cut': (0.10, 0.03, 0.02),     # packed ingress: residual link bytes 0.455 / 15.86 GB = 0.029 [D]; pess keeps fold/geometry copies [E]
    'd2d': (0.5, 0.7, 0.9),           # in-place coset/D2D: fraction of D2D copy time removed [E]
    'occ': (0.80, 0.85, 0.90),        # busy after graphs per class + 2 jobs/GPU (needs memory cuts) [E]
    # GPU capture, reviewed (codex/rv64-m9-gpu-replay 7d9850bab): full = replay + narrow capture + ledger on GPU + service fix;
    # the serial seeded first pass (per block [M], services fixed [E]) is the floor, times the pod-load spread [E]
    'cap_fp_spread': (1.15, 1.0, 0.90),
    # replay only (the prototype), net of the 48 B/step tape read-back: share of capture CPU removed [D/E]
    # (walk share 0.15/0.23/0.30 minus read-back 0.039/0.026/0.013; the stream's script had pess/opt swapped)
    'replay_net': (0.111, 0.204, 0.287),
    'four_gpu_eff': (0.85, 0.92, 0.96),
    'ngkr_nat': (0.90, 0.826, 0.80),  # native GKR v2-gkr: native cells x0.826, leaf x0.936 (levers.py, model.json) [D/E]
    'ngkr_rec': (0.96, 0.936, 0.92),
    # outer GKR, reviewed (codex/rv64-m9-outer-gkr a45530dc7): factor on recursion GPU-s, not cells (cells x0.56-0.63 [D]).
    # As built: post-M8 tree x1.07 central (LOO 1.04-1.17), pess = +v2 binding pass x1.28, opt x0.90 [D/E];
    # fan-in tree x1.13 (x1.10-1.25 LOO) [D/E]; engineered 0.25 ns/fact kernel with fused binding pass x0.78-0.84 [E]
    'ogkr_alone': (1.28, 1.07, 0.90),
    'ogkr_fanin': (1.35, 1.13, 0.95),
    'ogkr_eng': (0.90, 0.81, 0.78),
    'ogkr_p2': (1.28, 1.07, 0.90),    # on top of Poseidon2: no better basis than alone (the x0.57 cell basis is gone) [E]
    'd2_nat': (1.30, 1.40, 1.50),     # D2 (native b4) native cost factor; reverting divides by it (levers.py) [E]
    'd2_leaf': (0.60, 0.55, 0.50),    # D2 leaf cost factor; reverting divides by it (levers.py; M4.0 item 6: 0.60-0.73) [E]
    'miss_cpu_s': (1.2, 0.84, 0.5),   # host class build per leaf on a class miss: (13.2 plan + 2.72 pack) CPU-s / 19 nodes [D]
    'miss_par': (3, 4, 6),            # host threads building classes concurrently [E]
    # canonical leaf catalog R=4, HELD-OUT native tax (codex/rv64-m9-canon-leaf 64a2cb991 review s9) [D]:
    # CPU cells +61.2%, truth rows +2.5% -> x1.55 central; 26235168 +107% (pess); 24628607 +22.4% (opt)
    'canon_pad': (2.07, 1.55, 1.22),
    'fold_miss': (1.0, 0.97, 0.79),   # share of folds that are new classes on a new block: 204/210 exact leaves [D/E]
    'fold_miss_canon': (0.85, 0.79, 0.6),  # with canonical leaves, exact outer shape: 165/210 [D/E]
    # M9 recursion-arch: which REC_ARCH factor each scenario uses, and a multiplier for prover-side unknowns (Blake3
    # outer Merkle kernels at parity with Blake2s, 2^26 PoW grinding ~2-3 ms/node, ll4 last layer) [E]
    'rec_arch': (('taxed', 1.03), ('taxed', 1.0), ('untaxed', 1.0)),
}
D2D_PER_MI = 0.11 / 26.894777  # s/GPU per M instr (IO doc L5: <=0.11 s/GPU 607, <=0.75 s/GPU 159) [D]

# proposed landing order after GPU-native (doc s4): proof-neutral wave, profile wave, hash backbone, M10
# Recommended landing order after the stream results (doc s4). Off the order, evaluated alone and in the search:
#  P2 (reviewed: net loss once recursion is cut; transcript x23.9), D2REV (only pays after a large recursion cut, which
#  P2 no longer delivers), CANON (catalog R=4: held-out padding tax x1.55 native, fold classes still miss).
# r4 (wave-2 streams): outer GKR as built is a recursion GPU-s loss -> off the order; OGKR_ENG (gated on a standalone
# fused-kernel bench <= 0.3 ns/fact) takes its slot in the search. REPLAY = the replay prototype alone (no narrow-capture port).
LEVER_ORDER = ['IO', 'INPLACE', 'STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR_ENG', 'GPUCAP', 'GPU4']
EXTRA_LEVERS = ['P2', 'D2REV', 'CANON', 'OGKR', 'REPLAY', 'RECDIET', 'RECBATCH', 'RECNB3']
REC_LEVERS = ('RECDIET', 'RECBATCH', 'RECNB3')
LEVER_NAME = {
    'P2': 'Poseidon2-M31-W24 leaves (S2-S4)',
    'LEAVES': 'k-leaf fan-in: one leaf verifies 2-4 same-family natives (blake_g <= 2^23, <= 2.2 G cells)',
    'CANON': 'canonical leaf classes (L4)',
    'IO': 'packed class ingress + copy stream (L1a + L3)',
    'INPLACE': 'in-place coset / D2D (L5) + partial Merkle trees',
    'STREAM': 'FFT/LDE cuts: streaming commit fused LDE->leaf hash, leafless trees',
    'WITNESS': 'recursion witness without the task DAG',
    'OCC': 'occupancy: per-class graphs + 2 jobs/GPU (memory planner)',
    'GPUCAP': 'GPU capture replay (M10)',
    'GPU4': '4-GPU placement (M10)',
    'NGKR': 'native GKR v2-gkr in production (128-oracle cap)',
    'OGKR': 'outer GKR (DW-R1) in recursion nodes, as built (0.82 ns/fact)',
    'OGKR_ENG': 'outer GKR with an engineered 0.25 ns/fact kernel + fused v2 binding pass',
    'REPLAY': 'GPU capture replay only (narrow capture + ledger stay on CPU)',
    'D2REV': 'revert D2: native blowup b4 -> b2 once recursion is cheap',
    'RECDIET': 'outer-profile diet: q102/P26 + Blake3 outer commitments + whole-coset FRI leaves + last layer 2^4, fold arity re-optimised',
    'RECBATCH': 'RECDIET + sibling pairs proven as one outer proof (needs a streaming batch prover: 4.2 G-cell jobs)',
    'RECNB3': 'RECDIET + Blake3 native commitments (native proof-format change) [E]',
}


def model(mi, sh, p, on=(), gpus=2, production=False):
    """Post-M8 GPU-native request model with a set of levers switched on. Returns dict of GPU-s and wall."""
    N = N_PER_MI * mi * p['k_m8']
    L, F, lv, seg = sh['leaves'], sh['folds'], sh['levels'], sh['seg']
    R0 = max(0.0, RFIT[0] + RFIT[1] * (L + F)) * p['k_m8']
    wl = LEAF_K * L / (LEAF_K * L + FOLD_K * F)
    Rl, Rf = R0 * wl, R0 * (1 - wl)          # leaf / fold recursion GPU-s: D2 and native-GKR factors touch leaves only
    io = IO_LINK_607_POST_M8 * (L / L607) * IO_EXPOSED
    tx = 0.0  # serial transcript GPU-s (Poseidon2 channel) [M/E]
    d2d = D2D_PER_MI * mi
    cap = CAP_A + CAP_B * mi
    busy = p['busy']; G = gpus; eff = 1.0
    chain_frac = K607_CHAIN / (K607 * (1 - NATIVE_FRAC_607))  # share of recursion GPU-s in the witness DAG
    pcs_frac = (K607_FFT + K607_MERKLE) / K607                 # FFT + Merkle share of all kernel GPU-s
    if 'LEAVES' in on:  # k-leaf fan-in; natives unchanged, recursion cells x ratio [D, fewer-leaves receipt]
        blk = sh.get('block')
        if blk in FANIN_SAME:
            ratio, L2, F2, lv2 = FANIN_SAME[blk]
        else:  # synthetic p50/p95 shapes: small trees 0.82, >= 34 nodes 0.76 [D]
            ratio = 0.82 if L + F < 34 else 0.76; L2 = math.ceil(0.5 * L) + 1; F2, lv2 = folds(L2)
        ratio += p['fanin_d']
        R2 = (Rl + Rf) * ratio
        Rl, Rf = R2 * FANIN_LEAF_SHARE, R2 * (1 - FANIN_LEAF_SHARE)
        io *= L2 / L; L, F, lv = L2, F2, lv2
    rec = [l for l in REC_LEVERS if l in on]
    if rec:  # M9 recursion-arch: padded recursion-cell factor on the tree in effect [D on M], arity re-optimised
        tbl = REC_ARCH[(rec[-1], 'fan' if 'LEAVES' in on else 'pm8')]
        which, mult = p['rec_arch']
        blk = sh.get('block')
        ref = blk if blk in tbl['blocks'] else (26235168 if mi < 150 else 26235159)
        ft, fu, F3, lv3 = tbl['blocks'][ref]
        f = (ft if which == 'taxed' else fu) * mult
        R2 = (Rl + Rf) * f
        if rec[-1] == 'RECNB3':
            Rl, Rf = Rl * f, Rf * f
        else:  # outer-profile levers shrink fold verification only; leaves keep their native verification
            Rf = max(0.05 * Rf, R2 - Rl)
        if blk in tbl['blocks']:
            F, lv = F3, lv3
        else:
            F, lv = folds(L, tbl['arity'])
    nodes = L + F
    if 'CANON' in on:
        N *= p['canon_pad']
    if 'NGKR' in on:
        N *= p['ngkr_nat']; Rl *= p['ngkr_rec']
    if 'P2' in on:
        f2, n2, t2 = p['p2']
        Rl *= f2; Rf *= f2; N += n2 * mi; tx = t2 * mi
        chain_frac *= 0.5   # the Blake-G DAG is most of the chain; Poseidon rows are row-parallel [E]
    if 'OGKR' in on or 'OGKR_ENG' in on:
        if 'OGKR_ENG' in on:
            f = p['ogkr_eng']
        elif 'P2' in on:
            f = p['ogkr_p2']
        else:
            f = p['ogkr_fanin'] if 'LEAVES' in on else p['ogkr_alone']
        Rl *= f; Rf *= f
    if 'D2REV' in on:
        N /= p['d2_nat']; Rl /= p['d2_leaf']
    if 'STREAM' in on:
        cut = 1 - pcs_frac * (1 - p['stream'])
        N *= cut; Rl *= cut; Rf *= cut
    if 'WITNESS' in on:  # rowpar runs on class hits only; on a new block leaves all miss and fold_miss of folds [E]
        c = 1 - min(0.9, chain_frac) * (1 - p['wit'])
        if production:
            Rf *= 1 - (1 - c) * (1 - p['fold_miss'])
        else:
            Rl *= c; Rf *= c
    if 'IO' in on:
        io *= p['io_cut']; Rl += DECODE_PER_LEAF * L
    if 'INPLACE' in on:
        d2d *= 1 - p['d2d']
    if 'OCC' in on:
        busy = p['occ']  # k-leaf pair leaves are 12.4-13.4 GB post-P1: two fit per 32 GB GPU [E, fewer-leaves]
    if 'GPUCAP' in on:  # full GPU capture: serial seeded first pass (services fixed) is the floor [M/E]
        blk = sh.get('block')
        fp = _fp_fixed(FIRST_PASS[blk]) if blk in FIRST_PASS else FP_FIT[0] + FP_FIT[1] * mi
        cap = p['head'] + fp * p['cap_fp_spread'] + 0.2
    elif 'REPLAY' in on:
        cap = CAP_A + CAP_B * mi * (1 - p['replay_net'])
    if 'GPU4' in on:
        G = 4; eff = p['four_gpu_eff']
    if 'OCC' in on:
        tx *= 0.5  # one-thread serial channel: half hidden when 2 jobs share a GPU; fully exposed at 1 job/GPU [E]
    R = Rl + Rf + tx
    K2 = N + R
    tail_gpu = Rl / L + lv * (Rf / F if F else 0.0)   # last leaf + one fold per level
    tail = tail_gpu / p['busy_tail']
    s1 = N * STAGE1_FRAC
    # Stage 1 overlaps capture; the seal waits for both, and for the last segment's Stage 1 after capture ends
    pre_seal = max(p['head'] + s1 / (G * busy * eff), cap + s1 / max(1, seg) / busy)
    post = (K2 - s1 - tail_gpu) / (G * busy * eff) + io + d2d
    wall = p['fixed'] + pre_seal + post + tail
    miss = 0.0
    if production:  # every request is a new block: leaf classes miss, and most fold classes too (exact outer shape) [D/E]
        new = (0 if 'CANON' in on else L) + F * (p['fold_miss_canon'] if 'CANON' in on else p['fold_miss'])
        miss = new * p['miss_cpu_s'] / p['miss_par']
    wall += miss
    return dict(kernel_gpu_s=K2, native_gpu_s=N, recursion_gpu_s=R, leaves=L, nodes=nodes, capture_s=cap,
                pre_seal_s=pre_seal, post_seal_s=post, tail_s=tail, io_s=io, miss_s=miss, wall_s=wall)


def basket_weights(bk, gas_list):
    """Mainnet weight of each basket block: share of sampled blocks whose gas is nearest to it [D]."""
    w = {str(r['block']): 0 for r in bk}
    for g in gas_list:
        r = min(bk, key=lambda r: abs(r['gas'] - g)); w[str(r['block'])] += 1
    return {b: v / len(gas_list) for b, v in w.items()}


def bench15_extrapolated(mi):
    return WFIT[0] + WFIT[1] * mi


def run(gas_pct, out=None, gas_list=None):
    P = {n: {k: v[i] for k, v in SC.items()} for i, n in enumerate(['pess', 'central', 'opt'])}
    bk = basket()
    ipg = sum(r['mi'] for r in bk) / sum(r['gas'] / 1e6 for r in bk)  # instr per gas, basket gas-weighted [D]
    res = dict(labels='M measured, D derived, E estimate', fits={}, mainnet={}, basket={}, targets={}, levers={}, combos={})
    res['fits'] = dict(kernel_gpu_s=dict(a=KFIT[0], b_per_minstr=KFIT[1], r2=KFIT[2], label='D (bench15-1, n=6)'),
                       recursion_gpu_s_per_node=dict(a=RFIT[0], b_per_node=RFIT[1], r2=RFIT[2], label='D (bench15-1, n=6; used by the model)'),
                       warm_proving_s=dict(a=WFIT[0], b_per_minstr=WFIT[1], r2=WFIT[2], label='D (bench15-1, n=6)'),
                       instr_per_gas=ipg, native_gpu_s_per_minstr=N_PER_MI, capture_s=dict(a=CAP_A, b=CAP_B))
    over40 = [r for r in bk if r['gas'] > 40e6]
    res['basket'] = dict(blocks=len(bk), over40m_blocks=len(over40), over40m_block_share=len(over40) / len(bk),
                         over39m_block_share=sum(1 for r in bk if r['gas'] >= 39e6) / len(bk),
                         over40m_gas_share=sum(r['gas'] for r in over40) / sum(r['gas'] for r in bk),
                         mainnet_over40m_block_share=0.190, mainnet_over40m_gas_share=0.309, mainnet_over39m_block_share=0.208)
    cases = {'p50 (29.1M gas)': gas_pct[50], 'p95 (55.8M gas)': gas_pct[95]}
    blocks = {}
    for name, g in cases.items():
        mi = g * ipg; blocks[name] = (mi, shape(mi))
    for r in bk:
        blocks[str(r['block'])] = (r['mi'], shape(r['mi'], r['truths'], r['block']))
    # per-lever table on p50/p95, central (+ pess/opt)
    for name in list(cases) + ['26235168', '26235159', '24628607']:
        mi, sh = blocks[name]
        row = dict(minstr=mi, shape=sh, bench15_extrap_warm_s=bench15_extrapolated(mi),
                   baseline={n: model(mi, sh, P[n]) for n in P},
                   production_baseline={n: model(mi, sh, P[n], production=True) for n in P},
                   production_all_2gpu={n: model(mi, sh, P[n], on=tuple(l for l in LEVER_ORDER if l != 'GPU4'), production=True) for n in P},
                   production_all_2gpu_canon={n: model(mi, sh, P[n], on=tuple(l for l in LEVER_ORDER if l != 'GPU4') + ('CANON',), production=True) for n in P})
        single = {lv: {n: model(mi, sh, P[n], on=(lv,)) for n in P} for lv in EXTRA_LEVERS}; cum = {}; on = []
        for lv in LEVER_ORDER:
            single[lv] = {n: model(mi, sh, P[n], on=(lv,)) for n in P}
            on.append(lv)
            cum[lv] = {n: model(mi, sh, P[n], on=tuple(on)) for n in P}
        row['single'] = single; row['cumulative'] = cum
        res['levers'][name] = row
    # basket totals
    def total(on, n, gpus=2):
        return sum(model(blocks[str(r['block'])][0], blocks[str(r['block'])][1], P[n], on=on, gpus=gpus)['wall_s'] for r in bk)
    tot = {'baseline': {n: total((), n) for n in P}}
    on = []
    for lv in LEVER_ORDER:
        on.append(lv); tot[lv] = {n: total(tuple(on), n) for n in P}
    tot['bench15_extrap_warm_s'] = sum(bench15_extrapolated(r['mi']) for r in bk)
    tot['m3_s'] = sum(r['m3_s'] for r in bk)
    res['basket_totals'] = tot
    # M9 recursion-arch variants on top of the best 2-GPU order (#1-#9) and on 4 GPUs (#1-#10)
    all2 = tuple(l for l in LEVER_ORDER if l != 'GPU4')
    res['rec_arch'] = {}
    # RECBATCH jobs (a batch job holds both circuits: 4.21 G cells on the fan-in tree, > the 2.2 G post-P1 cap) cannot
    # share a 32 GB GPU, so OCC (two ~13 GB jobs per GPU) is off under it unless a streaming batch prover keeps a batch
    # job <= 13 GB (unprototyped). 'RECBATCH' below is that optimistic case; 'RECBATCH-OCC' is the memory-feasible one.
    for lv in ('none',) + REC_LEVERS + ('RECBATCH-OCC',):
        add = () if lv == 'none' else (('RECBATCH',) if lv == 'RECBATCH-OCC' else (lv,))
        drop = ('OCC',) if lv == 'RECBATCH-OCC' else ()
        on2 = tuple(l for l in all2 if l not in drop) + add
        on4 = tuple(l for l in LEVER_ORDER if l not in drop) + add
        row = {}
        for name in list(cases) + ['26235168', '26235159', '24628607']:
            mi, sh = blocks[name]
            row[name] = {n: dict(wall_2gpu=model(mi, sh, P[n], on=on2)['wall_s'], wall_4gpu=model(mi, sh, P[n], on=on4)['wall_s'],
                                 kernel_gpu_s=model(mi, sh, P[n], on=on2)['kernel_gpu_s'], recursion_gpu_s=model(mi, sh, P[n], on=on2)['recursion_gpu_s'],
                                 baseline=model(mi, sh, P[n])['wall_s']) for n in P}
        row['basket'] = {n: dict(wall_2gpu=total(on2, n), wall_4gpu=total(on4, n), baseline=tot['baseline'][n]) for n in P}
        res['rec_arch'][lv] = row
    # minimal 2-GPU lever sets reaching >=60% cut vs post-M8 baseline on p50, p95 and the basket (central)
    import itertools
    cand = [l for l in LEVER_ORDER if l not in ('GPU4', 'INPLACE', 'IO')] + ['P2', 'D2REV', 'OGKR', 'OGKR_ENG', 'REPLAY'] + list(REC_LEVERS)
    excl = ({'OGKR', 'OGKR_ENG'}, {'GPUCAP', 'REPLAY'}, {'RECDIET', 'RECBATCH'}, {'RECDIET', 'RECNB3'}, {'RECBATCH', 'RECNB3'},
            {'RECBATCH', 'OCC'})  # variants of one lever; a RECBATCH job (4.2 G cells) cannot share a GPU (OCC)
    base_on = ('IO', 'INPLACE')  # CANON excluded: as built it is a bench loss and keeps fold misses (canon-leaf review) [D/E]
    res['best_2gpu'] = {}
    for n in P:
        ok = []; best = (None, -1.0)
        for k in range(1, len(cand) + 1):
            for c in itertools.combinations(cand, k):
                if any(set(o) <= set(c) for o, _ in ok) or any(e <= set(c) for e in excl):
                    continue
                cuts = []
                for name in cases:
                    mi, sh = blocks[name]
                    b = model(mi, sh, P[n])['wall_s']; w = model(mi, sh, P[n], on=c + base_on)['wall_s']; cuts.append(1 - w / b)
                cuts.append(1 - total(c + base_on, n) / tot['baseline'][n])
                if min(cuts) > best[1]:
                    best = (c, min(cuts))
                if min(cuts) >= 0.60:
                    ok.append((c, cuts))
        res['best_2gpu'][n] = dict(levers=list(best[0]) + list(base_on), min_cut=best[1])
        res['combos'][n] = [dict(levers=list(c), cut_p50=x[0], cut_p95=x[1], cut_basket=x[2]) for c, x in ok[:10]]
    # mainnet-weighted view: model every sampled block (instr = gas x basket instr/gas) [E]
    if gas_list:
        def dist(on, n, gpus=2):
            w = sorted(model(g / 1e6 * ipg, shape(g / 1e6 * ipg), P[n], on=on, gpus=gpus)['wall_s'] for g in gas_list)
            k = len(w)
            return dict(mean=sum(w) / k, p50=w[k // 2], p90=w[int(0.9 * (k - 1))], p95=w[int(0.95 * (k - 1))], p99=w[int(0.99 * (k - 1))])
        all2 = tuple(l for l in LEVER_ORDER if l != 'GPU4')
        res['mainnet'] = dict(n=len(gas_list), baseline={n: dist((), n) for n in P}, m9_all_2gpu={n: dist(all2, n) for n in P},
                              m10_4gpu={n: dist(tuple(LEVER_ORDER), n) for n in P},
                              basket_weights=basket_weights(bk, gas_list),
                              basket_mainnet_percentile={str(r['block']): sum(1 for g in gas_list if g < r['gas']) / len(gas_list) for r in bk})
    if out:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        json.dump(res, open(out, 'w'), indent=1, sort_keys=True)
    return res, blocks, P


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gas-sample'); ap.add_argument('--json')
    a = ap.parse_args()
    pct = dict(GAS_PCT_EMBEDDED); g = None
    if a.gas_sample:
        rows = {r[0]: r for r in json.load(open(a.gas_sample))}  # 4 duplicate rows in the sample
        g = sorted(r[1] for r in rows.values()); n = len(g)
        pct = {p: g[min(n - 1, int(round(p / 100 * (n - 1))))] / 1e6 for p in GAS_PCT_EMBEDDED}
    res, blocks, P = run(pct, a.json, g)
    f = res['fits']
    print('recursion fit: %.3f + %.3f*nodes GPU-s (R2 %.3f)' % RFIT)
    print('fits: kernel GPU-s = %.2f + %.3f*Minstr (R2 %.3f); warm proving = %.2f + %.3f*Minstr (R2 %.3f); instr/gas %.3f; native %.3f GPU-s/Minstr'
          % (f['kernel_gpu_s']['a'], f['kernel_gpu_s']['b_per_minstr'], f['kernel_gpu_s']['r2'], f['warm_proving_s']['a'],
             f['warm_proving_s']['b_per_minstr'], f['warm_proving_s']['r2'], f['instr_per_gas'], f['native_gpu_s_per_minstr']))
    print('basket:', {k: round(v, 3) if isinstance(v, float) else v for k, v in res['basket'].items()})
    for name, row in res['levers'].items():
        print('\n== %s  Minstr %.1f  %s  bench15-extrap warm %.1f s' % (name, row['minstr'], row['shape'], row['bench15_extrap_warm_s']))
        b = row['baseline']
        pb = row['production_baseline']; pa = row['production_all_2gpu']
        print('  production (new block each request) baseline p/c/o %.2f / %.2f / %.2f (miss %.2f); all 2-GPU levers %.2f / %.2f / %.2f'
              % (pb['pess']['wall_s'], pb['central']['wall_s'], pb['opt']['wall_s'], pb['central']['miss_s'], pa['pess']['wall_s'], pa['central']['wall_s'], pa['opt']['wall_s']))
        print('  post-M8 baseline wall pess/central/opt %.2f / %.2f / %.2f  (central kernel %.2f GPU-s: native %.2f rec %.2f; cap %.2f pre-seal %.2f post %.2f tail %.2f io %.2f)'
              % (b['pess']['wall_s'], b['central']['wall_s'], b['opt']['wall_s'], b['central']['kernel_gpu_s'], b['central']['native_gpu_s'],
                 b['central']['recursion_gpu_s'], b['central']['capture_s'], b['central']['pre_seal_s'], b['central']['post_seal_s'],
                 b['central']['tail_s'], b['central']['io_s']))
        pc = row['production_all_2gpu_canon']
        print('  production all 2-GPU levers + CANON p/c/o %.2f / %.2f / %.2f' % (pc['pess']['wall_s'], pc['central']['wall_s'], pc['opt']['wall_s']))
        for lv in EXTRA_LEVERS:
            s = row['single'][lv]['central']
            print('  %-8s alone (not in order): GPU-s %+6.2f wall %+6.2f' % (lv, s['kernel_gpu_s'] - b['central']['kernel_gpu_s'], s['wall_s'] - b['central']['wall_s']))
        for lv in LEVER_ORDER:
            s = row['single'][lv]['central']; c = row['cumulative'][lv]
            print('  %-8s alone: GPU-s %6.2f (%+6.2f) wall %6.2f (%+6.2f) | cumulative wall p/c/o %6.2f %6.2f %6.2f  cut central %4.0f%%'
                  % (lv, s['kernel_gpu_s'], s['kernel_gpu_s'] - b['central']['kernel_gpu_s'], s['wall_s'], s['wall_s'] - b['central']['wall_s'],
                     c['pess']['wall_s'], c['central']['wall_s'], c['opt']['wall_s'], 100 * (1 - c['central']['wall_s'] / b['central']['wall_s'])))
    t = res['basket_totals']
    print('\n== 15-block totals (wall s): M3 %.0f; bench15-extrap %.0f; post-M8 baseline p/c/o %.0f %.0f %.0f' %
          (t['m3_s'], t['bench15_extrap_warm_s'], t['baseline']['pess'], t['baseline']['central'], t['baseline']['opt']))
    for lv in LEVER_ORDER:
        print('  +%-8s p/c/o %6.1f %6.1f %6.1f  cut central %4.0f%%' % (lv, t[lv]['pess'], t[lv]['central'], t[lv]['opt'],
                                                                 100 * (1 - t[lv]['central'] / t['baseline']['central'])))
    if res['mainnet']:
        m = res['mainnet']
        for k in ('baseline', 'm9_all_2gpu', 'm10_4gpu'):
            print('mainnet-weighted %-12s ' % k + ' | '.join('%s mean %.1f p50 %.1f p95 %.1f p99 %.1f' % (n, v['mean'], v['p50'], v['p95'], v['p99']) for n, v in m[k].items()))
        bw = m['basket_weights']
        for k, on in (('baseline', ()), ('m9_all_2gpu', tuple(l for l in LEVER_ORDER if l != 'GPU4')), ('m10_4gpu', tuple(LEVER_ORDER))):
            print('mainnet-weighted basket mean %-12s %s' % (k, ' '.join('%s %.1f' % (n, sum(bw[b] * model(*blocks[b], P[n], on=on)['wall_s'] for b in bw)) for n in P)))
        print('basket weights:', {b: round(v, 3) for b, v in bw.items()})
        print('basket mainnet percentiles:', {b: round(v, 2) for b, v in m['basket_mainnet_percentile'].items()})
    print('\n== M9 recursion-arch on top of #1-#9 (2 GPU) and #1-#10 (4 GPU): wall s (cut vs post-M8 baseline), central [pess..opt]')
    for lv, row in res['rec_arch'].items():
        parts = []
        for name in ('p50 (29.1M gas)', 'p95 (55.8M gas)', 'basket'):
            c = row[name]['central']; pe = row[name]['pess']; op = row[name]['opt']
            parts.append('%s %.2f (%.1f%%) [%.2f..%.2f] 4GPU %.2f (%.1f%%)' % (name.split(' ')[0], c['wall_2gpu'], 100 * (1 - c['wall_2gpu'] / c['baseline']),
                                                                       pe['wall_2gpu'], op['wall_2gpu'], c['wall_4gpu'], 100 * (1 - c['wall_4gpu'] / c['baseline'])))
        k = row['p50 (29.1M gas)']['central']
        print('  %-9s %s | p50 kernel %.2f GPU-s (recursion %.2f)' % (lv, ' | '.join(parts), k['kernel_gpu_s'], k['recursion_gpu_s']))
    for n, cs in res['combos'].items():
        b = res['best_2gpu'][n]
        print('\nbest 2-GPU set (%s): min cut over p50/p95/basket %.0f%% with %s' % (n, 100 * b['min_cut'], '+'.join(b['levers'])))
        print('minimal 2-GPU sets with >=60%% cut on p50, p95 and basket (%s):' % n)
        for c in cs:
            print('  %-45s p50 %.0f%% p95 %.0f%% basket %.0f%%' % ('+'.join(c['levers']), 100 * c['cut_p50'], 100 * c['cut_p95'], 100 * c['cut_basket']))


if __name__ == '__main__':
    main()
