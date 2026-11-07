#!/usr/bin/env python3
"""Stream m9-native-cells: plug the native work-reduction factors into the M9 plan model as new variants.

  python3 -I scripts/rv64_m9/native_cells_plan.py [--json out.json]

Imports scripts/rv64_m9/plan_model.py (verbatim copy of origin/codex/rv64-m9-plan, rev 4) and the lever table of
scripts/rv64_m9/native_cells.py (receipt vectors/reports/rv64-m9-prep/m9-native-cells/model.json). New variants:
  NCELLS   prover-side native cell cuts on top of NGKR (V2SHARE x PAD [x CORE_NARROW]); scales native GPU-s only,
           and only together with NGKR (it is defined on the v1 basis).
  ZBB      guest Zbb profile: instructions x0.937, native cells x0.955 [M basket]; capture and CPU segments scale
           with instructions, truth proofs do not.
  DISPATCH guest interpreter dispatch cut: instructions x0.92/0.85/0.79 [E]; native = CPU share x instr factor + truths.
Guest variants change the block shape (fewer CPU segments -> fewer CPU leaves). Basket blocks are re-shaped with the
plan's synthetic shape rule for both arms of a comparison (block id dropped), and the relative change is applied to
the plan's own per-block result, so no per-block receipt (fan-in, first pass) is extrapolated.
Labels: [M] measured, [D] derived, [E] estimate. Nothing here runs a GPU.
"""
import argparse, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import plan_model as PM  # noqa: E402
import native_cells as NC  # noqa: E402

BEST = ('STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR_ENG', 'GPUCAP', 'IO', 'INPLACE')  # plan rev 4 best 2-GPU set (central)
SCN = ('pess', 'central', 'opt')


def factors():
    res = NC.model(os.path.join(NC.REC, 'blocks.json'))
    nc = res['combined_prover_side_on_v1']['native_gpu_s_factor']
    g = res['guest']
    cpu = g['cpu_share_of_native_cells']
    z_i, z_n = g['zbb']['instr_factor'], g['zbb']['native_cells_factor']
    d = g['dispatch']['instr_factor']
    return dict(NCELLS={s: dict(instr=1.0, native=nc[s], needs='NGKR') for s in SCN},
                ZBB={s: dict(instr=z_i, native=z_n) for s in SCN},
                DISPATCH={s: dict(instr=d[s], native=cpu * d[s] + (1 - cpu)) for s in SCN}), res


def wall(mi, truths, block, p, on, extra, F, scn, production=False):
    """plan_model.model with the native-cells variants in `extra` applied."""
    fi, fn = 1.0, 1.0
    for v in extra:
        f = F[v][scn]
        if f.get('needs') and f['needs'] not in on:
            continue
        fi *= f['instr']; fn *= f['native']
    if truths is None:  # truth proofs follow gas, not instructions: keep the original block's truths
        truths = PM.shape(mi)['truths']
    keep = PM.N_PER_MI
    try:
        mi2 = mi * fi
        PM.N_PER_MI = keep * fn / fi          # native GPU-s = N_PER_MI * mi * fn
        sh = PM.shape(mi2, truths, block if fi == 1.0 else None)
        return PM.model(mi2, sh, p, on=on, production=production)
    finally:
        PM.N_PER_MI = keep


def run(out=None):
    F, res_nc = factors()
    P = {n: {k: v[i] for k, v in PM.SC.items()} for i, n in enumerate(SCN)}
    bk = PM.basket()
    ipg = sum(r['mi'] for r in bk) / sum(r['gas'] / 1e6 for r in bk)
    cases = {'p50': PM.GAS_PCT_EMBEDDED[50] * ipg, 'p95': PM.GAS_PCT_EMBEDDED[95] * ipg}
    sets = [
        ('best_rev4', BEST, ()),
        ('best_rev4+NCELLS', BEST, ('NCELLS',)),
        ('best_rev4+NCELLS+ZBB', BEST, ('NCELLS', 'ZBB')),
        ('best_rev4+NCELLS+ZBB+DISPATCH', BEST, ('NCELLS', 'ZBB', 'DISPATCH')),
        ('baseline+NCELLS(no NGKR: inert)', (), ('NCELLS',)),
        ('baseline+ZBB', (), ('ZBB',)),
        ('baseline+DISPATCH', (), ('DISPATCH',)),
    ]
    out_res = dict(labels='M measured, D derived, E estimate', factors=F, plan_model='scripts/rv64_m9/plan_model.py (rev 4, verbatim)',
                   best_rev4=list(BEST), results={})
    for scn in SCN:
        p = P[scn]
        base = {k: PM.model(mi, PM.shape(mi), p)['wall_s'] for k, mi in cases.items()}
        base_k = {k: PM.model(mi, PM.shape(mi), p)['kernel_gpu_s'] for k, mi in cases.items()}
        base_b = sum(PM.model(r['mi'], PM.shape(r['mi'], r['truths'], r['block']), p)['wall_s'] for r in bk)
        rows = {}
        for name, on, extra in sets:
            row = {}
            for k, mi in cases.items():
                w = wall(mi, None, None, p, on, extra, F, scn)
                row[k] = dict(wall_s=w['wall_s'], kernel_gpu_s=w['kernel_gpu_s'], native_gpu_s=w['native_gpu_s'],
                              cut=1 - w['wall_s'] / base[k], kernel_factor=w['kernel_gpu_s'] / base_k[k])
            tot = 0.0
            for r in bk:
                plan_w = PM.model(r['mi'], PM.shape(r['mi'], r['truths'], r['block']), p, on=on)['wall_s']
                fi = 1.0
                for v in extra:
                    f = F[v][scn]
                    if not (f.get('needs') and f['needs'] not in on):
                        fi *= f['instr']
                if fi == 1.0:
                    tot += wall(r['mi'], r['truths'], r['block'], p, on, extra, F, scn)['wall_s']
                else:  # relative change on synthetic shapes, applied to the plan's per-block wall
                    ref = wall(r['mi'], r['truths'], None, p, on, (), F, scn)['wall_s']
                    var = wall(r['mi'], r['truths'], None, p, on, extra, F, scn)['wall_s']
                    tot += plan_w * var / ref
            row['basket'] = dict(wall_s=tot, cut=1 - tot / base_b)
            row['min_cut'] = min(row['p50']['cut'], row['p95']['cut'], row['basket']['cut'])
            rows[name] = row
        out_res['results'][scn] = dict(baseline=dict(p50=base['p50'], p95=base['p95'], basket=base_b), sets=rows)
    if out:
        with open(out, 'w') as fh:
            json.dump(out_res, fh, indent=1)
    return out_res


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--json'); a = ap.parse_args()
    r = run(a.json)
    for v, f in r['factors'].items():
        print('%-8s ' % v + ' | '.join('%s instr x%.3f native x%.3f' % (s, f[s]['instr'], f[s]['native']) for s in SCN))
    for scn in SCN:
        R = r['results'][scn]; b = R['baseline']
        print('\n[%s] post-M8 baseline: p50 %.2f s, p95 %.2f s, basket %.0f s' % (scn, b['p50'], b['p95'], b['basket']))
        for name, row in R['sets'].items():
            print('  %-34s p50 %5.2f s (%+4.0f%%, kernel x%.3f) | p95 %5.2f s (%+4.0f%%) | basket %5.0f s (%+4.0f%%) | min cut %.0f%%' % (
                name, row['p50']['wall_s'], -100 * row['p50']['cut'], row['p50']['kernel_factor'], row['p95']['wall_s'], -100 * row['p95']['cut'],
                row['basket']['wall_s'], -100 * row['basket']['cut'], 100 * row['min_cut']))


if __name__ == '__main__':
    main()
