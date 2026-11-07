#!/usr/bin/env python3
"""RV64 M9 segment shape: per-segment fixed vs proportional GPU-s, bigger CPU segments (2^23 / 2^24), mixed last
segments and truth batching, as a work-reduction lever for the M9 plan model.

Design doc: design/riscv-proving-stack/rv64-m9-segment-shape.md. Labels: [M] measured, [D] derived, [E] estimate.
Nothing here runs a GPU. Every constant names its receipt.

  python3 -I scripts/rv64_m9/segment_shape_model.py [--gas-sample gas_sample.json] [--json out.json]

Reuses (does not copy) the padding-aware recursion cell model of codex/rv64-m9-fewer-leaves
(scripts/rv64_m9_leaf_fanin_model.py: node rows are additive in children, padded cells, k-leaf grouping, 4-ary carry
tree) and the post-M8 request model of codex/rv64-m9-plan (scripts/rv64_m9/plan_model.py). `plan_model.model()` calls
`entry()` below for the SEG23 / SEG24 levers.
"""
import argparse, functools, json, math, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)
import rv64_m9_leaf_fanin_model as FM  # noqa: E402

# ---------------------------------------------------------------------------------------------------------------
# 1. Per-segment native GPU time on the M8 job path [M]: CUDA events per job, one job at a time on GPU1
#    (codex/rv64-m8-gpu vectors/reports/rv64-m8-20261106/native-finish-p3/{binding-stage1,composition,pcs}-parity-<b>.json).
#    Stage1 = FIXED + MAIN commit + local GKR + binding; then composition; then OODS + PCS. INTER commit/global
#    interaction are not in these spans. (block, ordinal, segment cells, stage1 ms, composition ms, pcs ms,
#    stage1 / gkr / pcs arena peak GB).
SEG_JOBS = [
    (24628607, 0, 372.43, 203.42, 59.34, 152.02, 16.04, 13.79, 12.93),
    (24628607, 1, 291.40, 166.80, 47.57, 132.29, 13.18, 11.30, 11.73),
    (24628607, 2, 294.82, 172.42, 50.09, 142.20, 13.35, 11.45, 11.90),
    (24628607, 3, 298.42, 172.70, 51.54, 147.30, 13.38, 11.45, 12.27),
    (24628607, 4, 291.73, 171.55, 49.21, 139.62, 13.25, 11.36, 11.74),
    (24628607, 5, 306.67, 177.35, 50.83, 140.45, 14.11, 12.16, 12.02),
    (24628607, 6, 196.75, 135.33, 29.54, 70.96, 9.85, 8.66, 5.43),   # short last segment (1.73 M instr, log 21)
    (26235156, 0, 347.04, 187.69, 54.47, 145.96, 14.94, 12.80, 12.63),
    (26235156, 1, 316.71, 194.77, 54.11, 146.82, 14.99, 12.97, 12.59),
    (26235156, 2, 306.18, 178.96, 52.10, 143.25, 13.95, 12.00, 12.02),
    (26235156, 3, 340.37, 249.28, 59.06, 137.41, 18.56, 16.47, 12.44),  # last segment (2.72 M instr, log 22)
]

# bench15-1 default arm, 6 proved blocks [M] (codex/rv64-m8-gpu vectors/reports/rv64-m8-20261106/bench15/summary.json):
# (Minstr, cpu segments, recursion nodes = Nsight launches / launches_per_node, kernel GPU-s, recursion after native s)
BENCH15 = {
    26235156: (15.305679, 4, 15, 6.5555, 4.8412), 24647140: (24.598260, 6, 19, 8.4670, 5.3820),
    24628607: (26.894777, 7, 19, 8.4290, 5.6920), 25229957: (27.077168, 7, 20, 9.1172, 6.1824),
    24628608: (38.600821, 10, 23, 11.7151, 7.2663), 24697070: (57.790096, 14, 36, 18.3928, 10.0637),
}
# p-truth-split warm walls (codex/rv64-m8-p-truth-split 1088a894d, vectors/reports/rv64-m8-20261106/p-truth-split/
# README.md) [M, single unqualified observations on a loaded pod]: (Minstr, segments, leaves, native s, recursion s)
TRUTH_SPLIT = {
    24626900: (49.12, 12, 20, 8.99, 7.88), 24697073: (60.39, 15, 27, 11.18, 10.57), 26235168: (113.38, 28, 45, 20.69, 17.20),
    25229955: (122.48, 30, 45, 21.71, 16.85), 25229951: (165.91, 40, 58, 29.75, 22.59), 24628590: (157.62, 38, 55, 30.05, 21.32),
    24628595: (172.80, 42, 64, 34.14, 24.51), 24628611: (187.66, 45, 67, 37.67, 25.47), 26235159: (204.83, 49, 73, 35.92, 26.43),
}
BENCH15_LEAVES = {26235156: 11, 24647140: 14, 24628607: 14, 25229957: 15, 24628608: 17, 24697070: 27}  # nodes - folds(4-ary) [D]

# ---------------------------------------------------------------------------------------------------------------
# 2. Segment geometry. A segment holds up to 2^k - 1 steps (rv64_ethereum_request.zig batch_steps < 2^k). The last
#    proof already uses a minimal cpu_log (rv64-segment-size-analysis.md s0) [M].
def cap_minstr(k):
    return ((1 << k) - 1) / 1e6


def segments(mi, k):
    n = max(1, math.ceil(mi / cap_minstr(k) - 1e-12))
    last = mi - (n - 1) * cap_minstr(k)
    return n, last


# CPU native verification rows inside a leaf (eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate) [M at log 22, FM.NATIVE].
# A larger trace adds one Merkle level per tree path and one FRI layer per doubling; the column-bound part (opened
# values, OODS constraint evaluation, GKR claims) does not grow. Per-log increment = the measured fold-child increment
# 22 -> 23 (FM.CHILD, same verifier code for one more layer/level) [D]; pess doubles it, opt 0. Columns: a 2^23 or 2^24
# segment uses the same component set and ladder instances as a full 2^22 one (segment-size-analysis s1.1: all ladders
# but LS at 2^24 fit), so the max-of-10 full CPU leaf rows are the base [E]; pess adds +5% rows for extra instances.
DELTA_LOG = [c - b for b, c in zip(FM.CHILD[22], FM.CHILD[23])]
VER_SCALE = {'pess': (2.0, 1.05), 'central': (1.0, 1.0), 'opt': (0.0, 1.0)}


def cpu_rows(log, sc='central'):
    if log <= 21:
        return list(FM.NATIVE['cpu_tail'])  # [M] 24628607 tail (log 21); smaller tails are cheaper -> conservative
    s, extra = VER_SCALE[sc]
    return [round(r * extra + s * (log - 22) * d) for r, d in zip(FM.NATIVE['cpu'], DELTA_LOG)]


def natives(mi, truths, k, sc='central'):
    n, last = segments(mi, k)
    last_log = max(18, math.ceil(math.log2(max(1.0, last * 1e6 + 1))))
    names = []
    for i in range(n):
        log = k if i < n - 1 else min(k, last_log)
        name = 'cpu%d_%s' % (log, sc)
        if name not in FM.NATIVE:
            FM.NATIVE[name] = cpu_rows(log, sc)
        names.append(name)
    return names + FM.truth_roster(truths), n, last


def tree(items, fanin=False, truth_only=False):
    if not fanin:
        groups = [(i, 1) for i in range(len(items))]
    else:
        n_cpu = sum(1 for i in items if i.startswith('cpu')) if truth_only else 0
        rest = FM.group_leaves(items[n_cpu:], 4, 'blake23', 0.03, 'class')
        groups = [(i, 1) for i in range(n_cpu)] + [(n_cpu + f, c) for f, c in rest]
    leaves = []
    for o, (f, c) in enumerate(groups):
        rows = [0] * 5
        for it in items[f:f + c]:
            rows = FM.add(rows, FM.NATIVE[it])
        leaves.append(FM.Node('leaf', o, 1, [], rows, c))
    nodes, root = FM.carry_tree(leaves, 4)
    d = FM.depths(nodes, root)
    L = sum(1 for x in nodes if x.kind == 'leaf')
    cells = sum(x.cells for x in nodes)
    return dict(leaves=L, folds=len(nodes) - L, levels=max(d) if d else 0, cells=cells,
                leaf_cells=sum(x.cells for x in nodes if x.kind == 'leaf'), max_node=max(x.cells for x in nodes))


@functools.lru_cache(maxsize=None)
def entry(mi, truths, k, fanin, sc='central', truth_only=False):
    """Recursion shape after the lever, relative to the 2^22 one-native-per-leaf baseline on the same block [D/E].
    Returns (cell ratio, leaves, folds, levels, cpu segments, leaf share of cells)."""
    base = tree(natives(mi, truths, 22, sc)[0])
    items, n, _ = natives(mi, truths, k, sc)
    t = tree(items, fanin, truth_only)
    return (t['cells'] / base['cells'], t['leaves'], t['folds'], t['levels'], n, t['leaf_cells'] / t['cells'])


# ---------------------------------------------------------------------------------------------------------------
# 3. Native GPU-s factor per doubling [D/E].
# Cells: exact source census on the two dev blocks (vectors/reports/rv64-m7-20261105/native-layout/model.json,
# total coefficient cells vs one_truth_per_family at 2^22): CPU23 compact37-extension x0.989 (24628607) / x0.967
# (26235156); CPU23 wide47 (the only CPU23 class that exists today) x1.050 / x1.017; CPU24 compact x1.075 / x0.979.
# Central 1.00: the compact37 extension (design only, CPU23-WIDENING.md) is the target, but its ladder head-instance
# padding is unmodelled, so central sits between it and wide47 [E]; pess = wide47 on 24628607, opt = compact on 26235156.
CELLS = {23: {'pess': 1.050, 'central': 1.000, 'opt': 0.967}, 24: {'pess': 1.150, 'central': 1.050, 'opt': 0.979}}
# FFT per-element growth: T4 CUDA-event bench, 256 MiB per call, RTX 5090 (codex/rv64-m8-gpu
# vectors/reports/rv64-m8-20261106/opt-T4-fft-passes/README.md) [M]: b2n 22->23 0.733->0.793 (+8.2%), 23->24
# 0.793->0.920 (+16%); n2b 0.719->0.760 (+5.7%), ->0.891 (+17%); LDE 23->24 0.682->0.748 (+9.7%). The 2-pass wide
# n2b/LDE stops at log 24 (n2b_smem.cuh kWideHighBits 11 + kWideLowBits 13; b2n STWO_B2N_WIDE_MAX_LOG 24), so the
# b4 LDE of a 2^23 segment (log 25) falls back to 3 passes: old/new 3-pass/2-pass = 1.06/0.70 = x1.5 [M ratio at log 20-22].
# Central assumes the wide kernel is extended to log 25/26 at the 23->24 twiddle trend (+10% LDE, +7% b2n/n2b per
# doubling); pess = the 3-pass fallback; opt = +4% (segment-size-analysis 1/22.5 per doubling).
FFT_GROWTH = {'pess': 0.5 * 1.07 + 0.5 * 1.50, 'central': 0.5 * 1.07 + 0.5 * 1.10, 'opt': 1.044}  # per doubling, LDE ~half [E]
# FFT share of native kernel GPU-s: all FFT/LDE kernels over the census total minus the recursion-only witness DAG
# (chain_run), 24628607 opt-combined (plan_model K607_FFT / (K607 - K607_CHAIN)) [D]; native is LDE-heavy.
NATIVE_FFT_SHARE = 2.975 / (8.333 - 0.996)
# Per-segment fixed native GPU time: intercept of segment job ms vs cells (section 1 fit, ~36 ms of ~370 ms) [D];
# GPU-native graphs remove most launch gaps, so central keeps half of it [E].
FIXED_SEG_S = {'pess': 0.0, 'central': 0.018, 'opt': 0.036}


def native_factor(k, mi, sc='central', n_per_mi=None):
    if k == 22:
        return 1.0
    d = k - 22
    f = CELLS[k][sc] * (1 + NATIVE_FFT_SHARE * (FFT_GROWTH[sc] ** d - 1))
    if n_per_mi:
        saved = (segments(mi, 22)[0] - segments(mi, k)[0]) * FIXED_SEG_S[sc]
        f -= saved / (n_per_mi * mi)
    return f


# ---------------------------------------------------------------------------------------------------------------
# 4. Memory on a 32 GB RTX 5090 (gpu_native.MemoryPlan, rv64-m8-gpu-native.md s3.7) [M/D].
MEM = dict(
    class_cache_gb=(2.5, 3.1), graphs_gb=0.25, reserve_gb=1.0, slab_gb=0.024,           # [M]/[default]/[E] s3.7
    main_per_seg22_gb=(4.15 + 3.23) / 7,   # main_resident 4.15 + 3.23 GB on 24628607 (7 segments) [M] -> per 2^22 seg [D]
    stage1_peak22_gb=(13.18, 18.56),       # SEG_JOBS stage1 arena peaks [M]
    pcs_peak22_gb=(11.73, 12.93),          # SEG_JOBS PCS arena peaks [M]
    # exact consumed-Eq GKR workspace / stage-1 lower bound incl. same-GPU MAIN, max CPU proof (native-layout model.json) [D]
    gkr_ws_gb={22: 10.20, 23: 15.34, 24: 31.38}, stage1_lower_gb={22: 16.01, 23: 26.64, 24: 42.69},
    leaf_peak_gb=(3.1, 18.2), fold_peak_gb=21.8,   # [M] s3.7; leaf classes do not change with segment size [D]
)


def memory_table(seg22_counts):
    out = {}
    for k in (22, 23, 24):
        s = 2 ** (k - 22)
        fixed = MEM['class_cache_gb'][1] + MEM['graphs_gb'] + MEM['reserve_gb'] + MEM['slab_gb']
        row = dict(stage1_job_peak_gb=[round(x * s, 1) for x in MEM['stage1_peak22_gb']] if k == 22 else
                   [round(MEM['stage1_peak22_gb'][0] * MEM['stage1_lower_gb'][k] / MEM['stage1_lower_gb'][22], 1),
                    round(MEM['stage1_peak22_gb'][1] * MEM['stage1_lower_gb'][k] / MEM['stage1_lower_gb'][22], 1)],
                   pcs_job_peak_gb=[round(x * s, 1) for x in MEM['pcs_peak22_gb']],
                   gkr_workspace_gb=MEM['gkr_ws_gb'][k], stage1_lower_bound_gb=MEM['stage1_lower_gb'][k],
                   label='22 [M]; 23/24 [D] scaled by the exact stage-1 lower bound, PCS by rows')
        for name, nseg in seg22_counts.items():
            main = MEM['main_per_seg22_gb'] * nseg / 2  # MAIN of the segments on one GPU; total independent of k [D]
            arena = 32.0 - fixed - main
            row['arena_free_gb_' + name] = round(arena, 1)
            row['stage1_fits_' + name] = arena >= row['stage1_job_peak_gb'][1]
            # post-P1: GKR chunk-bounded to <= 2 GB, streamed commit with one bank, partial trees [E]
            p1 = 2.0 + 1.0 * s * 1.2 + 1.1 * s  # GKR chunk + MAIN coeff (1.2 GB/2^22 seg) + one LDE bank/tree [E]
            row['stage1_post_p1_gb'] = round(p1, 1)
            row['stage1_fits_post_p1_' + name] = arena >= p1
        out[str(k)] = row
    return out


# ---------------------------------------------------------------------------------------------------------------
def fit(xs, ys):
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    a = my - b * mx
    ss = sum((y - a - b * x) ** 2 for x, y in zip(xs, ys)); st = sum((y - my) ** 2 for y in ys)
    return a, b, 1 - ss / st


def lstsq(X, Y):
    n = len(X[0]); M = [[sum(x[i] * x[j] for x in X) for j in range(n)] + [sum(x[i] * y for x, y in zip(X, Y))] for i in range(n)]
    for i in range(n):
        p = M[i][i]; M[i] = [v / p for v in M[i]]
        for r in range(n):
            if r != i:
                f = M[r][i]; M[r] = [a - f * b for a, b in zip(M[r], M[i])]
    coef = [M[i][n] for i in range(n)]
    my = sum(Y) / len(Y)
    ss = sum((y - sum(c * v for c, v in zip(coef, x))) ** 2 for x, y in zip(X, Y)); st = sum((y - my) ** 2 for y in Y)
    return coef, 1 - ss / st


def fits():
    out = {}
    a, b, r2 = fit([r[2] for r in SEG_JOBS], [r[3] + r[4] + r[5] for r in SEG_JOBS])
    out['segment_job_ms_vs_mcells'] = dict(a_ms=a, b_ms_per_mcell=b, r2=r2, n=len(SEG_JOBS),
                                           fixed_share_at_310m=a / (a + 310 * b), label='D (job-path CUDA events [M])')
    for i, name in ((3, 'stage1'), (4, 'composition'), (5, 'pcs')):
        a, b, r2 = fit([r[2] for r in SEG_JOBS], [r[i] for r in SEG_JOBS])
        out['segment_%s_ms' % name] = dict(a_ms=a, b_ms_per_mcell=b, r2=r2)
    rows = list(BENCH15.values())
    a, b, r2 = fit([r[0] for r in rows], [r[3] for r in rows])
    out['kernel_vs_minstr'] = dict(a=a, b=b, r2=r2, label='D (bench15-1 n=6) = plan_model KFIT')
    c, r2 = lstsq([(r[0], r[2]) for r in rows], [r[3] for r in rows])
    out['kernel_vs_minstr_nodes_no_intercept'] = dict(native_per_minstr=c[0], per_node=c[1], r2=r2, label='D (n=6)')
    c, r2 = lstsq([(1, r[0], r[2]) for r in rows], [r[3] for r in rows])
    out['kernel_vs_1_minstr_nodes'] = dict(a=c[0], native_per_minstr=c[1], per_node=c[2], r2=r2,
                                           label='D (n=6; Minstr and nodes collinear, coefficients unstable)')
    c, r2 = lstsq([(r[0], r[1]) for r in rows], [r[3] for r in rows])
    out['kernel_vs_minstr_segments_no_intercept'] = dict(per_minstr=c[0], per_segment=c[1], r2=r2,
                                                         label='D (n=6; segments ~ Minstr/4.19, collinear)')
    # 15 blocks: recursion-after-native wall vs nodes (6 qualified + 9 unqualified walls) [D]
    xs = [r[2] for r in BENCH15.values()] + [r[2] + math.ceil((r[2] - 1) / 3) for r in TRUTH_SPLIT.values()]
    ys = [r[4] for r in BENCH15.values()] + [r[4] for r in TRUTH_SPLIT.values()]
    a, b, r2 = fit(xs, ys)
    out['recursion_wall_vs_nodes_15'] = dict(a_s=a, b_s_per_node=b, r2=r2, label='D (bench15 6 [M] + p-truth-split 9 [M unqualified])')
    a, b, r2 = fit([r[0] for r in BENCH15.values()] + [r[0] for r in TRUTH_SPLIT.values()],
                   [BENCH15_NATIVE[k] for k in BENCH15] + [r[3] for r in TRUTH_SPLIT.values()])
    out['native_wall_vs_minstr_15'] = dict(a_s=a, b_s_per_minstr=b, r2=r2, label='D (same 15 walls)')
    return out


BENCH15_NATIVE = {26235156: 2.84, 24647140: 3.83, 24628607: 3.81, 25229957: 4.05, 24628608: 6.87, 24697070: 11.19}  # [M]


def per_segment_decomposition(P, rk):
    """GPU-s carried by one full 2^22 CPU segment in the post-M8 baseline [D]."""
    n_per_mi = P.N_PER_MI
    native = n_per_mi * cap_minstr(22)
    fx = fits()['segment_job_ms_vs_mcells']['fixed_share_at_310m']
    leaf = FM.cells(FM.NATIVE['cpu']) * rk
    # parent fold share: verifying one log-23 leaf as a fold child, padded like a 4-child fold, + higher levels (1/3) [D]
    fold_child = (FM.cells(FM.add(FM.add(FM.CHILD[23], FM.CHILD[23]), FM.add(FM.CHILD[23], FM.CHILD[23]))) / 4) * rk * (4 / 3)
    rec = leaf + fold_child
    tot = native + rec
    return dict(native_gpu_s=native, native_fixed_gpu_s=native * fx, leaf_gpu_s=leaf, fold_share_gpu_s=fold_child,
                recursion_gpu_s=rec, total_gpu_s=tot, fixed_share=(native * fx + rec) / tot,
                label='D: native = plan N_PER_MI x 4.194 Minstr; leaf/fold = padded cells x %.3f ns/cell (fan-in calibration)' % (rk * 1e9))


def near_empty_tail(gas_list, ipg, k, frac=0.10):
    n = 0; hit = 0
    for g in gas_list:
        mi = g / 1e6 * ipg
        s, last = segments(mi, k)
        n += 1
        if s > 1 and last < frac * cap_minstr(k):
            hit += 1
    return hit / n


def tail_cost(rk, n_per_mi):
    """GPU-s of a near-empty last segment vs absorbing it into the previous one as a 2^(k+1)-row proof [D/E]."""
    tail_native = n_per_mi * 0.2 + 0.018                       # ~0.2 M instr of native + fixed [D/E]
    tail_leaf = FM.cells(FM.NATIVE['cpu_tail']) * rk           # [D] conservative: log-21 tail leaf rows [M]
    fold_child = FM.unpadded(FM.CHILD[22]) * rk                # its verification in the parent fold [D]
    # absorbing: the previous segment doubles its CPU-component rows (padding) -> the CPU AIR share of a segment
    # CPU AIR share of a full segment's MAIN: compact37 columns of 338 M main cells / 2^22 rows = 80.5 cells/row
    # (native-layout model.json, 24628607 CPU proof 0) [D]; the other families are sized by use and do not double
    cpu_share = 37 / (337667360 / (1 << 22))
    absorb = n_per_mi * cap_minstr(22) * cpu_share             # [D/E] the doubled CPU plane, at the segment's GPU-s per cell
    return dict(tail_native=tail_native, tail_leaf=tail_leaf, tail_fold_child=fold_child,
                tail_total=tail_native + tail_leaf + fold_child, absorb_extra_native=absorb)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gas-sample'); ap.add_argument('--json')
    a = ap.parse_args()
    import plan_model as P
    gas = None
    pct = dict(P.GAS_PCT_EMBEDDED)
    if a.gas_sample:
        rows = {r[0]: r for r in json.load(open(a.gas_sample))}
        gas = sorted(r[1] for r in rows.values())
        nn = len(gas); pct = {p: gas[min(nn - 1, int(round(p / 100 * (nn - 1))))] / 1e6 for p in P.GAS_PCT_EMBEDDED}
    bk = P.basket()
    ipg = sum(r['mi'] for r in bk) / sum(r['gas'] / 1e6 for r in bk)
    cal = FM.calibrate()
    rk = cal['rk']
    res = dict(schema='rv64-m9-segment-shape/v1', labels='M measured, D derived, E estimate', fits=fits(),
               calibration=dict(rk_ns_per_cell=rk * 1e9, native_gpu_s_per_minstr=P.N_PER_MI),
               per_segment=per_segment_decomposition(P, rk))
    blocks = {}
    for name, g in (('p50', pct[50]), ('p95', pct[95])):
        mi = g * ipg; sh = P.shape(mi); blocks[name] = (mi, sh['truths'], None)
    for r in bk:
        blocks[str(r['block'])] = (r['mi'], r['truths'], r['block'])
    shapes = {}
    for name, (mi, truths, blk) in blocks.items():
        row = dict(minstr=mi, truths=truths)
        base = tree(natives(mi, truths, 22)[0])
        row['base_cells_g'] = base['cells'] / 1e9
        for k in (22, 23, 24):
            for fan in ('none', 'truth', 'all'):
                if k == 22 and fan == 'none':
                    continue
                for sc in ('pess', 'central', 'opt'):
                    e = entry(mi, truths, k, fan != 'none', sc, fan == 'truth')
                    row['k%d_%s_%s' % (k, fan, sc)] = dict(cell_ratio=e[0], leaves=e[1], folds=e[2], levels=e[3], cpu_segments=e[4],
                                                           native_factor=native_factor(k, mi, sc, P.N_PER_MI))
        row['k22_base'] = dict(leaves=base['leaves'], folds=base['folds'], levels=base['levels'], cpu_segments=segments(mi, 22)[0])
        shapes[name] = row
    res['shapes'] = shapes
    res['memory'] = memory_table({'24628607': 7, 'p50': segments(blocks['p50'][0], 22)[0], 'p95': segments(blocks['p95'][0], 22)[0]})
    res['tail'] = tail_cost(rk, P.N_PER_MI)
    if gas:
        res['near_empty_last_segment_share'] = {str(k): near_empty_tail(gas, ipg, k) for k in (22, 23, 24)}
    # cross-check: 2^22 + fan-in cell ratio vs the fewer-leaves receipt used by plan_model.FANIN_SAME [D]
    res['check_fanin_same'] = {b: dict(ours=round(shapes[str(b)]['k22_all_central']['cell_ratio'], 3), plan=v[0])
                               for b, v in P.FANIN_SAME.items() if str(b) in shapes}
    # request effect through the plan model (central/pess/opt)
    res['plan'] = plan_effect(P, pct, gas)
    if a.json:
        os.makedirs(os.path.dirname(a.json), exist_ok=True)
        json.dump(res, open(a.json, 'w'), indent=1, sort_keys=True)
    report(res)


# M9 plan rev 4 best 2-GPU sets (codex/rv64-m9-plan vectors/reports/rv64-m9-prep/m9-plan/model.json best_2gpu) [E]
REV4_BEST = {
    'pess': ('STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR_ENG', 'GPUCAP', 'IO', 'INPLACE'),
    'central': ('STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR_ENG', 'GPUCAP', 'IO', 'INPLACE'),
    'opt': ('STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR_ENG', 'GPUCAP', 'P2', 'D2REV', 'IO', 'INPLACE'),
}


def plan_effect(P, pct, gas):
    P.SEARCH_EXTRA = ['SEG23']
    res, blocks, PP = P.run(pct, None, gas)
    out = {}
    bk = P.basket()
    sets = {
        'baseline': lambda n: (),
        'SEG23': lambda n: ('SEG23',),
        'SEG24': lambda n: ('SEG24',),
        'LEAVES': lambda n: ('LEAVES',),
        'SEG23+LEAVES': lambda n: ('SEG23', 'LEAVES'),
        'rev4_best': lambda n: REV4_BEST[n],
        'rev4_best+SEG23': lambda n: REV4_BEST[n] + ('SEG23',),
        'rev4_best-LEAVES+SEG23': lambda n: tuple(l for l in REV4_BEST[n] if l != 'LEAVES') + ('SEG23',),
        'rev4_best+SEG24': lambda n: REV4_BEST[n] + ('SEG24',),
    }
    for label, fn in sets.items():
        out[label] = {}
        for n in PP:
            on = fn(n)
            row = {}
            for name in ('p50 (29.1M gas)', 'p95 (55.8M gas)'):
                mi, sh = blocks[name]
                b = P.model(mi, sh, PP[n]); m = P.model(mi, sh, PP[n], on=on)
                r4 = P.model(mi, sh, PP[n], on=REV4_BEST[n])
                pr = P.model(mi, sh, PP[n], on=on, production=True); pb = P.model(mi, sh, PP[n], production=True)
                row[name.split()[0]] = dict(wall_s=m['wall_s'], kernel_gpu_s=m['kernel_gpu_s'], native_gpu_s=m['native_gpu_s'],
                                            recursion_gpu_s=m['recursion_gpu_s'], base_wall_s=b['wall_s'],
                                            base_kernel_gpu_s=b['kernel_gpu_s'], cut=1 - m['wall_s'] / b['wall_s'],
                                            kernel_vs_rev4=m['kernel_gpu_s'] / r4['kernel_gpu_s'],
                                            production_wall_s=pr['wall_s'], production_cut=1 - pr['wall_s'] / pb['wall_s'],
                                            nodes=m['nodes'], leaves=m['leaves'])
            tb = sum(P.model(blocks[str(r['block'])][0], blocks[str(r['block'])][1], PP[n])['wall_s'] for r in bk)
            tw = sum(P.model(blocks[str(r['block'])][0], blocks[str(r['block'])][1], PP[n], on=on)['wall_s'] for r in bk)
            row['basket'] = dict(wall_s=tw, base_wall_s=tb, cut=1 - tw / tb)
            row['levers'] = list(on)
            out[label][n] = row
    out['search_best_2gpu'] = res.get('best_2gpu')
    out['search_combos_60'] = res.get('combos')
    if res.get('mainnet'):
        out['mainnet_note'] = 'plan_model mainnet view is unchanged (no SEG lever in its fixed m9_all_2gpu set)'
    return out


def report(res):
    f = res['fits']
    s = f['segment_job_ms_vs_mcells']
    print('per-segment native job ms = %.1f + %.3f*Mcells (R2 %.3f, n=%d): fixed share %.0f%% of a 310 M-cell segment [D]'
          % (s['a_ms'], s['b_ms_per_mcell'], s['r2'], s['n'], 100 * s['fixed_share_at_310m']))
    for k in ('stage1', 'composition', 'pcs'):
        x = f['segment_%s_ms' % k]; print('  %-11s %.1f + %.3f*Mcells (R2 %.3f)' % (k, x['a_ms'], x['b_ms_per_mcell'], x['r2']))
    x = f['kernel_vs_minstr']; print('kernel GPU-s = %.2f + %.3f*Minstr (R2 %.3f)' % (x['a'], x['b'], x['r2']))
    x = f['kernel_vs_minstr_nodes_no_intercept']; print('kernel GPU-s = %.3f*Minstr + %.3f*nodes (R2 %.3f)' % (x['native_per_minstr'], x['per_node'], x['r2']))
    x = f['kernel_vs_1_minstr_nodes']; print('kernel GPU-s = %.2f + %.3f*Minstr + %.3f*nodes (R2 %.3f; collinear)' % (x['a'], x['native_per_minstr'], x['per_node'], x['r2']))
    x = f['kernel_vs_minstr_segments_no_intercept']; print('kernel GPU-s = %.3f*Minstr + %.3f*segments (R2 %.3f; collinear)' % (x['per_minstr'], x['per_segment'], x['r2']))
    x = f['recursion_wall_vs_nodes_15']; print('recursion-after-native wall = %.2f + %.3f*nodes s (R2 %.3f, 15 blocks)' % (x['a_s'], x['b_s_per_node'], x['r2']))
    x = f['native_wall_vs_minstr_15']; print('native window wall = %.2f + %.3f*Minstr s (R2 %.3f, 15 blocks)' % (x['a_s'], x['b_s_per_minstr'], x['r2']))
    p = res['per_segment']
    print('one full 2^22 segment: native %.3f GPU-s (fixed %.3f) + leaf %.3f + fold share %.3f = %.3f GPU-s; fixed (not rows) share %.0f%% [D]'
          % (p['native_gpu_s'], p['native_fixed_gpu_s'], p['leaf_gpu_s'], p['fold_share_gpu_s'], p['total_gpu_s'], 100 * p['fixed_share']))
    print('\nshape (central): cell ratio vs 2^22 one-per-leaf | leaves/folds | native factor')
    for name, row in res['shapes'].items():
        if name not in ('p50', 'p95', '24628607', '26235168', '25229955', '26235159'):
            continue
        b = row['k22_base']
        line = '  %-9s %6.1f Mi seg22 %2d L%2d F%2d |' % (name, row['minstr'], b['cpu_segments'], b['leaves'], b['folds'])
        for key in ('k22_truth', 'k22_all', 'k23_none', 'k23_truth', 'k23_all', 'k24_none', 'k24_all'):
            e = row[key + '_central']
            line += ' %s x%.3f %d/%d n%.3f |' % (key, e['cell_ratio'], e['leaves'], e['folds'], e['native_factor'])
        print(line)
    print('\nfan-in cross-check (ours vs plan FANIN_SAME):', {b: (v['ours'], v['plan']) for b, v in res['check_fanin_same'].items()})
    print('\nmemory:')
    for k, row in res['memory'].items():
        print('  2^%s' % k, {kk: v for kk, v in row.items() if kk != 'label'})
    t = res['tail']
    print('\nnear-empty tail: native %.3f + leaf %.3f + fold child %.3f = %.3f GPU-s vs absorbing into a 2x previous proof +%.3f GPU-s'
          % (t['tail_native'], t['tail_leaf'], t['tail_fold_child'], t['tail_total'], t['absorb_extra_native']))
    if 'near_empty_last_segment_share' in res:
        print('  share of mainnet blocks with a last segment < 10%% full: %s' % {k: round(v, 3) for k, v in res['near_empty_last_segment_share'].items()})
    print('\nplan-model effect (wall s, cut vs post-M8 baseline):')
    for label, rows in res['plan'].items():
        if label.startswith('search_') or label == 'mainnet_note':
            continue
        for n, r in rows.items():
            print('  %-23s %-7s p50 %5.2f s (%3.0f%%; %5.2f GPU-s, x%.3f vs rev4; prod %3.0f%%) p95 %5.2f s (%3.0f%%; %5.2f GPU-s, x%.3f) basket %6.1f s (%3.0f%%)'
                  % (label, n, r['p50']['wall_s'], 100 * r['p50']['cut'], r['p50']['kernel_gpu_s'], r['p50']['kernel_vs_rev4'],
                     100 * r['p50']['production_cut'], r['p95']['wall_s'], 100 * r['p95']['cut'], r['p95']['kernel_gpu_s'],
                     r['p95']['kernel_vs_rev4'], r['basket']['wall_s'], 100 * r['basket']['cut']))
    for n, b in (res['plan']['search_best_2gpu'] or {}).items():
        print('  search best 2-GPU (%s) incl. SEG23: min cut %.0f%% %s' % (n, 100 * b['min_cut'], '+'.join(b['levers'])))
    for n, cs in (res['plan']['search_combos_60'] or {}).items():
        for c in cs:
            print('  >=60%% set (%s): %s p50 %.0f%% p95 %.0f%% basket %.0f%%' % (n, '+'.join(c['levers']), 100 * c['cut_p50'], 100 * c['cut_p95'], 100 * c['cut_basket']))


if __name__ == '__main__':
    main()
