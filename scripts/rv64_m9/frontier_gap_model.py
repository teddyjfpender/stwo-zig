#!/usr/bin/env python3
"""RV64 M9 frontier-gap model: work-reduction levers taken from ZisK / Airbender v3 / SP1, as a variant of plan_model.

Design doc: design/riscv-proving-stack/rv64-m9-frontier-gap.md. Labels: [M] measured, [D] derived, [E] estimate,
[code] read in a frontier source tree, [pub] published (ethproofs.org / vendor docs, fetched 2026-11-07).

It does NOT change plan_model.py. It loads it (sibling file, or `git show origin/codex/rv64-m9-plan:...` when the
plan branch is not merged yet), then adds five levers by scaling the plan model's own inputs (native GPU-s per
Minstr, the recursion fit, the leaf/fold split), so every other plan assumption is reused unchanged:

  STACK    stacked short columns: a native/truth proof opens ~equal-height columns, not 5,833 short ones per query
  BLAKE3R  7-round BLAKE3 compression for every recursion-facing tree and the channel (Blake2s is 10 rounds)
  GRIND26  query grinding 20 -> 26 bits on the native D2 and outer profiles (q54 -> q51, q108 -> q102)
  NGKRFULL native GKR for all INTER (not only the v2 strict classes)
  MLE      [speculative] Airbender-v3-style native IOP: base columns only at blowup 2 (GKR + WHIR); upper bound

Usage:
  python3 -I scripts/rv64_m9/frontier_gap_model.py [--gas-sample gas_sample.json] [--json out.json]
Nothing here runs a GPU.
"""
import argparse, contextlib, itertools, json, math, os, subprocess, sys, types

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLAN_PATH = os.path.join(ROOT, 'scripts', 'rv64_m9', 'plan_model.py')
PLAN_REF = 'origin/codex/rv64-m9-plan'


def load_plan_model():
    """plan_model as a module whose ROOT is this checkout (its data files are on codex/rv64-m7-integrate)."""
    if os.path.exists(PLAN_PATH):
        src = open(PLAN_PATH).read(); origin = PLAN_PATH
    else:
        src = subprocess.check_output(['git', '-C', ROOT, 'show', PLAN_REF + ':scripts/rv64_m9/plan_model.py'], text=True)
        origin = PLAN_REF + ':scripts/rv64_m9/plan_model.py'
    mod = types.ModuleType('plan_model')
    mod.__file__ = PLAN_PATH  # so plan_model.ROOT resolves to this checkout
    exec(compile(src, origin, 'exec'), mod.__dict__)
    mod.__origin__ = origin
    return mod


pm = load_plan_model()

# ---------------------------------------------------------------------------------------------------------------
# Evidence (all per 24628607 at the production D2 profile unless noted)
# ---------------------------------------------------------------------------------------------------------------
# [M] producer log of the accepted D2 request (m7-handoff/receipts/device-service/sparse-rc/
#     daemon-24628607-r2-sparse-d2-22g/producer.stderr, GPU_DEVICE_PEAK stage=trace_commit, mode=legacy):
#     CPU segment MAIN tree 3,111-3,606 columns holding 1.05-1.35 GB of coefficients; INTER 1,592-2,008 columns.
#     Equal-height width = coefficients / 2^22 rows: MAIN 3606 -> 80.5, INTER 2008 -> 46.1 [D], i.e. the average
#     committed column is 1/45 of the tallest one. Truth proofs: up to 7,409 columns over 30.3 M coefficients.
OPENED = dict(fixed=203, main=3606, inter=2008, comp=16)            # per query, CPU proof (poseidon2-leaves s5) [M]
EQ_HEIGHT = dict(main=1350669440 / 4 / 2 ** 22, inter=773049344 / 4 / 2 ** 22)  # [D] 80.5, 46.1
# [M/D] accepted all-Blake CPU-leaf census at b4 q54 p20 fold4 (rv64-m7-20261105/poseidon2, poseidon2-leaves s5):
#     554.8 M cells, 82.05 M non-hash; per query per tree Blake = ceil(w/16) + d compressions (d = 23).
LEAF_CELLS, LEAF_NONHASH = 554.8, 82.05
_rowhash = sum(math.ceil(w / 16) for w in OPENED.values())           # 366 compressions/query hash the opened row
_paths = 23 * len(OPENED)                                            # 92 compressions/query walk paths
LEAF_HASH_SHARE = (LEAF_CELLS - LEAF_NONHASH) / LEAF_CELLS           # 0.852 [D]
LEAF_ROW_SHARE = LEAF_HASH_SHARE * _rowhash / (_rowhash + _paths)    # 0.681 [D]: opened-row hashing share of a leaf
FOLD_ROW_SHARE = 0.80 * 19 / (19 + 21)                               # folds open 300-wide tall proofs: 0.38 [D]
# Frontier per-verified-proof references [code]:
#   ZisK Main (2^22, blowup 2, 247 GL columns opened): 36,201 Blake3 permutations per verified proof, "paths
#   dominate, typically 70-75%" (pil2-proofman setup/stark-recurser/docs-research/README.md, recursion-cell-memory-model.html)
#   Airbender v3 unrolled circuits: 40-58 committed BabyBear columns per row at 2^24 rows (circuit_defs/*/generated/layout.json)

SC = {  # (pess, central, opt)
    # STACK: opened-width factor after stacking short columns into equal-height ones. Ideal is (80.5+46.1+8+16)/5833 =
    # 0.026 [D] (composition is already full height); central keeps mid-height components unstacked and the truth proofs' widest tables partly [E].
    'stack_wf': (0.35, 0.15, 0.06),
    'stack_share': (0.55, 0.66, 0.68),   # opened-row share of leaf GPU-s (0.681 [D]; truth leaves and NGKR overlap [E])
    'stack_nat': (1.08, 1.03, 1.01),     # native: s fused butterfly layers to lift stacked LDEs + multi-point DEEP [E]
    # BLAKE3R: 7 of 10 rounds; G-gate share of a compression's committed cells (rest: message load, m31_to_u32,
    # feed-forward, tables) 0.6/0.8/0.9 [E]; native Merkle is HBM-bound (1.4-1.6 TB/s [M]) so no native gain.
    'b3_save': (0.3 * 0.6, 0.3 * 0.8, 0.3 * 0.9),
    'b3_hash_leaf': (0.80, 0.852, 0.852),
    'b3_hash_fold': (0.70, 0.80, 0.80),
    # GRIND26: per-query share of node cells (paths + rows + DEEP per query) [D/E]; grind rate Blake2s/s/GPU.
    # [review] The as-built device grind is far below the 25 G/s first assumed: codex/rv64-m8-gpu
    # vectors/reports/rv64-m8-20261106/runtime/pipeline-diagnostic-1.json [M, diagnostic, GPU 1 of the 2x5090 pod]
    # takes 3.149 s for 12 jobs at 28 bits vs 0.192 s at 25 bits, i.e. ~0.246 s per 28-bit grind: 2^28/0.246 s =
    # 1.1 G/s at the expected nonce (also the maximum-likelihood rate given the 25-bit row adds ~0 ms), and
    # P(rate >= 5 G/s) < 1% under a geometric nonce [D]. Central = as built 1.1 G/s, pess 0.8 G/s, opt 13.4 G/s =
    # an engineered kernel (rv64-gpu-2s-block-plan.md row 10: 2^26 in 5 ms) [E]. GRIND26 needs a faster kernel first.
    'grind_qshare': (0.90, 0.95, 0.97),
    'grind_rate': (0.8e9, 1.1e9, 13.4e9),
    # NGKRFULL: native beyond v2-strict NGKR (INTER 68.9 cells/instr; v2 strict halves INTER [D, 4-GPU s4.2]) [E]
    'ngkrf_nat': (1.0, 0.92, 0.86),
    'ngkrf_leaf': (1.0, 0.92, 0.85),     # INTER opened width; zero when STACK already compressed it [E]
    # [review] in-circuit GKR verifier (sumcheck per layer, OM31) as a share of today's leaf. ngkrf_leaf nets it when STACK
    # is off; with STACK on, the opened-width saving is gone but this cost stays (outer GKR as built was a net loss,
    # plan_model ogkr_alone x1.07) [E]
    'ngkrf_verify': (0.06, 0.04, 0.02),
    # MLE (speculative upper bound): native commit 50 BabyBear cols/cycle at LDE 2 vs our 193 cells/instr at LDE 4,
    # RV32 cycles x1.3-1.8 per RV64 instr, GKR prover compute replaces composition [E]
    'mle_nat': (0.75, 0.55, 0.40),
    'mle_leaf': (0.80, 0.55, 0.40),
}
NEW_LEVERS = ['STACK', 'BLAKE3R', 'GRIND26', 'NGKRFULL']
SPECULATIVE = ['MLE']
LEVER_NAME = {
    'STACK': 'stacked short columns: equal-height commitment layout, multi-point DEEP (STWO_RV64_M9_STACKED_COLUMNS)',
    'BLAKE3R': 'BLAKE3 (7-round) compression for recursion-facing trees + channel (STWO_RV64_M9_BLAKE3_RECURSION)',
    'GRIND26': 'query grinding 20 -> 26 bits: native q54 -> q51, outer q108 -> q102 (STWO_RV64_M9_GRIND26)',
    'NGKRFULL': 'native GKR for every INTER column, not only v2 strict classes (STWO_RV64_M9_NATIVE_GKR_FULL)',
    'MLE': '[speculative] Airbender-v3-style multilinear native (base columns at blowup 2, GKR + WHIR)',
}


def factors(on, p, sh):
    """(native factor, leaf factor, fold factor, extra kernel GPU-s) for the new levers [D/E]."""
    fN, fL, fF, extra = 1.0, 1.0, 1.0, 0.0
    if 'STACK' in on:
        fL *= 1 - p['stack_share'] * (1 - p['stack_wf'])
        fN *= p['stack_nat']
    if 'NGKRFULL' in on:
        fN *= p['ngkrf_nat']
        if 'STACK' not in on:
            fL *= p['ngkrf_leaf']
    if 'MLE' in on:
        fN *= p['mle_nat']; fL *= p['mle_leaf']
    if 'BLAKE3R' in on:
        hl = p['b3_hash_leaf']
        if 'STACK' in on:  # stacking removes most opened-row hashing: hash share of the remaining leaf [D]
            s = p['stack_share'] * (1 - p['stack_wf'])
            hl = max(0.0, (hl - s) / (1 - s))
        fL *= 1 - hl * p['b3_save']
        fF *= 1 - p['b3_hash_fold'] * p['b3_save']
    if 'NGKRFULL' in on and 'STACK' in on:
        fL += p['ngkrf_verify']
    if 'GRIND26' in on:
        q = p['grind_qshare']
        fL *= 1 - q * (1 - 51 / 54)   # leaves verify native D2 proofs: (128-26)/2 = 51
        fF *= 1 - q * (1 - 102 / 108)  # folds verify outer r1 proofs: (128-26)/1 = 102
        proofs = sh['seg'] + sh['truths'] + sh['leaves'] + sh['folds']
        extra += proofs * (2 ** 26 - 2 ** 20) / p['grind_rate']
    return fN, fL, fF, extra


def grind_tail_s(on, p, sh):
    """[review] Serial grind on the critical path: the last leaf and one fold per level grind one after another [D/E]."""
    if 'GRIND26' not in on:
        return 0.0
    return (1 + sh['levels']) * (2 ** 26 - 2 ** 20) / p['grind_rate']


@contextlib.contextmanager
def patched(fN, fL, fF, sh, leaves_on):
    """Scale plan_model inputs so model() sees native x fN, leaf recursion x fL, fold recursion x fF."""
    g = pm.__dict__
    keep = {k: g[k] for k in ('N_PER_MI', 'RFIT', 'LEAF_K', 'FOLD_K', 'FANIN_LEAF_SHARE')}
    try:
        g['N_PER_MI'] = keep['N_PER_MI'] * fN
        if leaves_on:  # the fan-in branch re-splits leaf/fold from FANIN_LEAF_SHARE
            s = keep['FANIN_LEAF_SHARE']; c = s * fL + (1 - s) * fF
            g['FANIN_LEAF_SHARE'] = s * fL / c
        else:
            L, F = sh['leaves'], sh['folds']
            wl = keep['LEAF_K'] * L / (keep['LEAF_K'] * L + keep['FOLD_K'] * F)
            c = wl * fL + (1 - wl) * fF
            g['LEAF_K'] = keep['LEAF_K'] * fL; g['FOLD_K'] = keep['FOLD_K'] * fF
        g['RFIT'] = (keep['RFIT'][0] * c, keep['RFIT'][1] * c, keep['RFIT'][2])
        yield
    finally:
        g.update(keep)


def model(mi, sh, p, on=(), gpus=2, production=False):
    plan_on = tuple(l for l in on if l not in NEW_LEVERS + SPECULATIVE)
    fN, fL, fF, extra = factors(on, p, sh)
    with patched(fN, fL, fF, sh, 'LEAVES' in plan_on):
        r = pm.model(mi, sh, p, on=plan_on, gpus=gpus, production=production)
    if extra:
        G = 4 if 'GPU4' in on else gpus
        busy = p['occ'] if 'OCC' in on else p['busy']
        eff = p['four_gpu_eff'] if 'GPU4' in on else 1.0
        tail = grind_tail_s(on, p, sh)  # serial part: not spread over G GPUs
        spread = (extra - tail) / (G * busy * eff)
        r = dict(r); r['kernel_gpu_s'] += extra; r['recursion_gpu_s'] += extra; r['grind_gpu_s'] = extra
        r['wall_s'] += spread + tail; r['post_seal_s'] += spread; r['tail_s'] += tail
    return r


def params():
    P = {n: {k: v[i] for k, v in pm.SC.items()} for i, n in enumerate(['pess', 'central', 'opt'])}
    for i, n in enumerate(['pess', 'central', 'opt']):
        P[n].update({k: v[i] for k, v in SC.items()})
    return P


def frontier_table(ipg):
    """Per-instruction / per-gas work comparison [D from M/code/pub]."""
    ours_cells = dict(fixed=9.6, main=100.5, inter=68.9, comp=23.7)  # cells/instr, 24628607 M6 protocol [M]
    lde_b4 = (ours_cells['main'] + ours_cells['inter'] + ours_cells['comp']) * 31 * 4
    zisk_step = 23527.0          # LDE bits/step excl. fixed, blowup 2 (committed-work-comparison-v1.json) [D]
    zisk_steps_per_gas = 242647058.8 / 59982888
    ab_cols = {'add_sub_lui_auipc_mop': 48, 'shift_binary': 58, 'jump_branch_slt': 55, 'load_store_word_only': 40,
               'load_store_subword_only': 46, 'mul_div_unsigned': 50}  # mem + witness widths [code]
    ab_mean = sum(ab_cols.values()) / len(ab_cols)
    return dict(
        ours_native_lde_bits_per_instr_D2=lde_b4, ours_native_lde_bits_per_gas_D2=lde_b4 * ipg,
        ours_native_lde_bits_per_instr_b2=lde_b4 / 2,
        zisk_native_lde_bits_per_step=zisk_step, zisk_native_lde_bits_per_gas=zisk_step * zisk_steps_per_gas,
        airbender_v3_committed_cols_per_cycle=ab_mean, airbender_v3_lde_bits_per_cycle=ab_mean * 31 * 2,
        ours_over_airbender_lde_bits_per_instr=lde_b4 / (ab_mean * 31 * 2),
        opened_width_ours_cpu_proof=sum(OPENED.values()), opened_width_zisk_main=247,
        # [review] composition is 16 columns at full height (16 x 2^23, rv64-m9-poseidon2-leaves.md s3): it cannot stack below 16
        opened_width_ours_equal_height=round(EQ_HEIGHT['main'] + EQ_HEIGHT['inter'] + 8 + OPENED['comp'], 1),
        leaf_row_share=LEAF_ROW_SHARE, leaf_hash_share=LEAF_HASH_SHARE, fold_row_share=FOLD_ROW_SHARE,
        per_query_compressions_ours=_rowhash + _paths, per_query_row_compressions_ours=_rowhash,
        zisk_main_verify_blake3_perms=36201, zisk_main_queries_jbr128_b2_p24=211,
        ours_leaf_queries_conj128_b4_p20=54,
        labels='D from M (our receipts), code (frontier trees), pub (ethproofs 2026-11-07)')


ETHPROOFS = {  # [pub] ethproofs.org/clusters, fetched 2026-11-07: average proving time on mainnet blocks, cost/proof
    'Airbender v3 1x5090': (1, 5.9, 0.0010), 'Zilkworm Airbender v3 2x5090': (2, 3.4, 0.0012),
    'Airbender v3 4x5090': (4, 2.4, 0.0016), 'ZisK 2x5090': (2, 6.0, 0.0021), 'ZisK 4x5090': (4, 7.3, 0.0064),
    'Succinct SP1 Twin Peaks 2x5090': (2, 28.8, 0.0093), 'Axiom OpenVM 16x5090': (16, 3.2, 0.0099),
}
SECURITY = {  # what each proof claims [code / pub]
    'ours (D2)': 'conjectured-128 (ethSTARK: log_b*q + pow); Johnson ~74-77 (rv64-m7-profiles.md s1)',
    'ZisK': '128-bit JBR (Johnson bound) query solver, 24 grinding bits (pil2-proofman hash_family.rs, security/pcs)',
    'Airbender v3': '100-bit pessimistic conjecture: q = ceil(1.2*floor((100-pow)/rate_bits)) (prover_config/example_configs.rs)',
    'SP1 Hypercube': '98-bit proven per soundcalc (L2BEAT), no proximity-gap conjecture (Succinct docs) [pub]',
}


def run(gas_pct, gas_list=None):
    P = params()
    res, blocks, _ = pm.run(gas_pct, None, gas_list)
    bk = pm.basket()
    best = tuple(res['best_2gpu']['central']['levers'])  # plan rev 4 best 2-GPU set (central)
    cases = ['p50 (29.1M gas)', 'p95 (55.8M gas)']
    def total(on, n):
        return sum(model(blocks[str(r['block'])][0], blocks[str(r['block'])][1], P[n], on=on)['wall_s'] for r in bk)
    out = dict(labels='M measured, D derived, E estimate', plan_model=pm.__origin__, plan_best_2gpu=list(best),
               frontier=frontier_table(res['fits']['instr_per_gas']), ethproofs=ETHPROOFS, security=SECURITY,
               lever_names=LEVER_NAME, params={k: list(v) for k, v in SC.items()}, single={}, on_best={}, search={})
    base = {n: {c: model(*blocks[c], P[n]) for c in cases} for n in P}
    base_tot = {n: total((), n) for n in P}
    out['baseline'] = {n: dict(p50=base[n][cases[0]]['wall_s'], p95=base[n][cases[1]]['wall_s'], basket=base_tot[n]) for n in P}
    for lv in NEW_LEVERS + SPECULATIVE + ['D2REV']:
        out['single'][lv] = {}
        for n in P:
            row = {}
            for c in cases:
                b = base[n][c]; s = model(*blocks[c], P[n], on=(lv,))
                row[c] = dict(d_gpu_s=s['kernel_gpu_s'] - b['kernel_gpu_s'], d_wall_s=s['wall_s'] - b['wall_s'],
                              d_native=s['native_gpu_s'] - b['native_gpu_s'], d_rec=s['recursion_gpu_s'] - b['recursion_gpu_s'])
            out['single'][lv][n] = row
    # on top of the plan's best 2-GPU set: every subset of the new levers (+ D2REV), and the 4-GPU view
    extra = NEW_LEVERS + ['D2REV']
    for n in P:
        rows = []
        for k in range(0, len(extra) + 1):
            for c in itertools.combinations(extra, k):
                on = best + c
                w = {cc: model(*blocks[cc], P[n], on=on) for cc in cases}
                tb = total(on, n)
                cuts = [1 - w[cases[0]]['wall_s'] / base[n][cases[0]]['wall_s'], 1 - w[cases[1]]['wall_s'] / base[n][cases[1]]['wall_s'],
                        1 - tb / base_tot[n]]
                rows.append(dict(add=list(c), p50_s=w[cases[0]]['wall_s'], p95_s=w[cases[1]]['wall_s'], basket_s=tb,
                                 p50_gpu_s=w[cases[0]]['kernel_gpu_s'], p50_native=w[cases[0]]['native_gpu_s'],
                                 p50_rec=w[cases[0]]['recursion_gpu_s'], p95_gpu_s=w[cases[1]]['kernel_gpu_s'],
                                 cut_p50=cuts[0], cut_p95=cuts[1], cut_basket=cuts[2], min_cut=min(cuts)))
        rows.sort(key=lambda r: -r['min_cut'])
        out['search'][n] = rows
        # 4 GPUs with the best 2-GPU set + the recommended new levers
        rec = best + ('STACK', 'BLAKE3R', 'GPU4')  # [review] GRIND26 dropped: a loss at the as-built grind rate
        w4 = {cc: model(*blocks[cc], P[n], on=rec, gpus=4) for cc in cases}
        tb4 = sum(model(blocks[str(r['block'])][0], blocks[str(r['block'])][1], P[n], on=rec, gpus=4)['wall_s'] for r in bk)
        out['on_best'][n] = dict(four_gpu=dict(levers=list(rec), p50_s=w4[cases[0]]['wall_s'], p95_s=w4[cases[1]]['wall_s'], basket_s=tb4,
                                               cut_p50=1 - w4[cases[0]]['wall_s'] / base[n][cases[0]]['wall_s'],
                                               cut_p95=1 - w4[cases[1]]['wall_s'] / base[n][cases[1]]['wall_s'],
                                               cut_basket=1 - tb4 / base_tot[n]),
                                 plan_best=next(r for r in rows if not r['add']))
        if gas_list:
            ipg = res['fits']['instr_per_gas']
            def dist(on, production=False):
                w = sorted(model(g / 1e6 * ipg, pm.shape(g / 1e6 * ipg), P[n], on=on, production=production)['wall_s'] for g in gas_list)
                k = len(w); return dict(mean=sum(w) / k, p50=w[k // 2], p95=w[int(0.95 * (k - 1))])
            out['on_best'][n]['mainnet_production'] = dict(
                baseline=dist((), True), plan_best=dist(best, True), plan_best_top=dist(best + tuple(rows[0]['add']), True))
            out['on_best'][n]['mainnet'] = dict(baseline=dist(()), plan_best=dist(best), plan_best_plus=dist(best + ('STACK', 'BLAKE3R')),
                                            plan_best_top=dist(best + tuple(rows[0]['add'])))
    # [review] production view: every mainnet request is a new block, so leaf classes and most fold classes miss and the
    # host class build (plan_model miss_s) is on the critical path. The search above is warm (class hits), like plan rev 4.
    out['production'] = {}
    for n in P:
        top_add = tuple(out['search'][n][0]['add'])
        pb = {c: model(*blocks[c], P[n], production=True)['wall_s'] for c in cases}
        row = dict(baseline=dict(p50_s=pb[cases[0]], p95_s=pb[cases[1]]))
        for name, on in (('plan_best', best), ('plan_best_top', best + top_add)):
            w = {c: model(*blocks[c], P[n], on=on, production=True) for c in cases}
            row[name] = dict(add=list(on[len(best):]), p50_s=w[cases[0]]['wall_s'], p95_s=w[cases[1]]['wall_s'],
                             p50_miss_s=w[cases[0]]['miss_s'], cut_p50=1 - w[cases[0]]['wall_s'] / pb[cases[0]],
                             cut_p95=1 - w[cases[1]]['wall_s'] / pb[cases[1]])
        out['production'][n] = row
    # [review] GRIND26 break-even grind rate (central, p50, on top of the top set without it): bisection on G/s
    n = 'central'; c50 = cases[0]; base_set = best + tuple(a for a in out['search'][n][0]['add'] if a != 'GRIND26')
    lo, hi = 0.1e9, 200e9
    for _ in range(60):
        mid = (lo * hi) ** 0.5; q = dict(P[n], grind_rate=mid)
        if model(*blocks[c50], q, on=base_set + ('GRIND26',))['wall_s'] < model(*blocks[c50], q, on=base_set)['wall_s']:
            hi = mid
        else:
            lo = mid
    out['grind26_break_even_rate'] = hi
    # what x0.67 asks for: the factor on all kernel GPU-s still needed after the best new set (central, p50)
    n = 'central'; top = out['search'][n][0]
    out['gap_to_60'] = dict(best_add=top['add'], min_cut=top['min_cut'], p50_gpu_s=top['p50_gpu_s'],
                            plan_p50_gpu_s=out['on_best'][n]['plan_best']['p50_gpu_s'],
                            factor_vs_plan_best=top['p50_gpu_s'] / out['on_best'][n]['plan_best']['p50_gpu_s'])
    return out


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--gas-sample'); ap.add_argument('--json')
    a = ap.parse_args()
    pct = dict(pm.GAS_PCT_EMBEDDED); g = None
    if a.gas_sample:
        rows = {r[0]: r for r in json.load(open(a.gas_sample))}
        g = sorted(r[1] for r in rows.values()); k = len(g)
        pct = {q: g[min(k - 1, int(round(q / 100 * (k - 1))))] / 1e6 for q in pm.GAS_PCT_EMBEDDED}
    out = run(pct, g)
    if a.json:
        os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
        json.dump(out, open(a.json, 'w'), indent=1, sort_keys=True)
    f = out['frontier']
    print('plan model:', out['plan_model'], '| plan best 2-GPU:', '+'.join(out['plan_best_2gpu']))
    print('frontier: ours native LDE bits/instr D2 %.0f (b2 %.0f), ZisK %.0f/step; Airbender v3 %.0f/cycle (x%.1f); opened width/query ours %d vs equal-height %.0f vs ZisK Main %d; leaf row-hash share %.3f'
          % (f['ours_native_lde_bits_per_instr_D2'], f['ours_native_lde_bits_per_instr_b2'], f['zisk_native_lde_bits_per_step'],
             f['airbender_v3_lde_bits_per_cycle'], f['ours_over_airbender_lde_bits_per_instr'], f['opened_width_ours_cpu_proof'],
             f['opened_width_ours_equal_height'], f['opened_width_zisk_main'], f['leaf_row_share']))
    for n, b in out['baseline'].items():
        print('post-M8 baseline %-7s p50 %.1f p95 %.1f basket %.0f' % (n, b['p50'], b['p95'], b['basket']))
    for lv, d in out['single'].items():
        c = d['central']
        print('%-8s alone (central): p50 dGPU-s %+5.2f (native %+5.2f rec %+5.2f) dwall %+5.2f | p95 dGPU-s %+5.2f dwall %+5.2f'
              % (lv, c['p50 (29.1M gas)']['d_gpu_s'], c['p50 (29.1M gas)']['d_native'], c['p50 (29.1M gas)']['d_rec'],
                 c['p50 (29.1M gas)']['d_wall_s'], c['p95 (55.8M gas)']['d_gpu_s'], c['p95 (55.8M gas)']['d_wall_s']))
    for n, rows in out['search'].items():
        print('\n[%s] plan best + new levers (top 8 by min cut):' % n)
        for r in rows[:8] + [r for r in rows if not r['add']]:
            print('  +%-36s p50 %5.2f s (%3.0f%%, %5.2f GPU-s: nat %5.2f rec %5.2f) p95 %5.2f (%3.0f%%) basket %5.1f (%3.0f%%)'
                  % ('+'.join(r['add']) or '(plan best)', r['p50_s'], 100 * r['cut_p50'], r['p50_gpu_s'], r['p50_native'], r['p50_rec'],
                     r['p95_s'], 100 * r['cut_p95'], r['basket_s'], 100 * r['cut_basket']))
        fg = out['on_best'][n]['four_gpu']
        print('  4 GPUs + STACK+BLAKE3R: p50 %.2f (%.0f%%) p95 %.2f (%.0f%%) basket %.1f (%.0f%%)'
              % (fg['p50_s'], 100 * fg['cut_p50'], fg['p95_s'], 100 * fg['cut_p95'], fg['basket_s'], 100 * fg['cut_basket']))
        if 'mainnet' in out['on_best'][n]:
            m = out['on_best'][n]['mainnet']
            print('  mainnet-weighted mean: baseline %.1f, plan best %.1f, + STACK+BLAKE3R %.1f s, + top set %.1f s (p95 %.1f)'
                  % (m['baseline']['mean'], m['plan_best']['mean'], m['plan_best_plus']['mean'], m['plan_best_top']['mean'], m['plan_best_top']['p95']))
    for n, row in out['production'].items():
        print('production (new block, class misses) %-7s baseline p50 %.2f p95 %.2f | plan best p50 %.2f (%.0f%%) | + top set p50 %.2f (%.0f%%, miss %.2f s) p95 %.2f (%.0f%%)'
              % (n, row['baseline']['p50_s'], row['baseline']['p95_s'], row['plan_best']['p50_s'], 100 * row['plan_best']['cut_p50'],
                 row['plan_best_top']['p50_s'], 100 * row['plan_best_top']['cut_p50'], row['plan_best_top']['p50_miss_s'],
                 row['plan_best_top']['p95_s'], 100 * row['plan_best_top']['cut_p95']))
        if 'mainnet_production' in out['on_best'][n]:
            m = out['on_best'][n]['mainnet_production']
            print('  mainnet-weighted mean, production: baseline %.1f, plan best %.1f, + top set %.1f s' % (m['baseline']['mean'], m['plan_best']['mean'], m['plan_best_top']['mean']))
    gp = out['gap_to_60']
    print('GRIND26 break-even device grind rate (central p50, on the top set): %.1f G Blake2s/s per GPU' % (out['grind26_break_even_rate'] / 1e9))
    print('\ncentral best: +%s min cut %.0f%%; p50 kernel %.2f GPU-s = x%.2f of the plan best %.2f' %
          ('+'.join(gp['best_add']), 100 * gp['min_cut'], gp['p50_gpu_s'], gp['factor_vs_plan_best'], gp['plan_p50_gpu_s']))


if __name__ == '__main__':
    main()
