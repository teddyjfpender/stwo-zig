#!/usr/bin/env python3
"""M9 GPU capture replay: re-run the M9 plan model (rev 3) with the measured capture factor.

Labels: [M] measured, [D] derived, [E] estimate. Nothing here runs a GPU.

The plan models GPU capture as  cap = head + Minstr / cap_mips + 0.2  with cap_mips (120, 160, 250) [E].
That assumes every per-step capture cost leaves the CPU critical path except the serial fast first pass.
This script replaces it with three measured/derived variants:

  full_now   : replay + narrow capture + ledger on the GPU; first pass = the SEEDED first pass as measured
               per basket block (services as they are today). cap = head + t_seeded(block) + 0.2.
  full_fixed : as full_now, with first-pass service arithmetic fixed (Montgomery limbs, no per-call
               inverse / u768 %): curve/bulk/sponge/secp host time cut to an [E] floor.
  replay_only: only the compact-tape replay moves to the GPU (this prototype); narrow capture, ledger,
               boundary capture stay on CPU workers. cap = CAP_A + CAP_B * Minstr * (1 - walk_share).

Usage:
  python3 -I scripts/rv64_m9/gpu_replay_model.py --plan-root DIR --first-pass FP.json [--json OUT]
DIR holds scripts/rv64_m9/plan_model.py and the vectors it reads (origin/codex/rv64-m9-plan).
FP.json: {"blocks": {block: {"minstr", "seeded_s", "plain_s", "host_s", "curve_s", ...}}} from the receipts.
"""
import argparse, importlib.util, json, math, os, sys


def load_plan(root):
    spec = importlib.util.spec_from_file_location('plan_model', os.path.join(root, 'scripts/rv64_m9/plan_model.py'))
    pm = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pm)
    return pm


def fit(xs, ys):
    n = len(xs); mx = sum(xs) / n; my = sum(ys) / n
    b = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return my - b * mx, b


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--plan-root', required=True)
    ap.add_argument('--first-pass', required=True)
    ap.add_argument('--json')
    a = ap.parse_args()
    pm = load_plan(a.plan_root)
    fp = json.load(open(a.first_pass))['blocks']
    rows = sorted(fp.items(), key=lambda kv: kv[1]['minstr'])
    # [D] seeded first-pass seconds vs Minstr over the measured basket blocks (central); per-block values are used
    # for basket blocks, the fit for the synthetic p50/p95 blocks.
    a_s, b_s = fit([r['minstr'] for _, r in rows], [r['seeded_s'] for _, r in rows])
    # [D] the same with the service arithmetic fixed: ordinary steps at the seeded rate measured on service-light
    # blocks, plus a host floor of 1 us per curve call and the non-curve host time unchanged [E].
    def fixed_s(r):
        return r['seeded_s'] - r['curve_s'] + r['curve_calls'] * 1e-6
    a_f, b_f = fit([r['minstr'] for _, r in rows], [fixed_s(r) for _, r in rows])
    walk_share = (0.30, 0.23, 0.15)  # [D/E] share of per-step capture CPU that is the traced walk (see design doc s5)

    by_block = {str(k): v for k, v in fp.items()}
    variant = {'name': 'plan'}
    orig_model = pm.model
    orig_cap_b = pm.CAP_B

    def model(mi, sh, p, on=(), gpus=2, production=False):
        v = variant['name']
        if v == 'plan' or 'GPUCAP' not in on:
            return orig_model(mi, sh, p, on=on, gpus=gpus, production=production)
        k = {0.5: 0, 0.4: 1, 0.3: 2}[p['head']]  # pess / central / opt (head is (0.5, 0.4, 0.3) in SC)
        blk = str(sh.get('block')) if sh.get('block') else None
        if v == 'replay_only':
            pm.CAP_B = orig_cap_b * (1 - walk_share[k])
            try:
                return orig_model(mi, sh, p, on=tuple(x for x in on if x != 'GPUCAP'), gpus=gpus, production=production)
            finally:
                pm.CAP_B = orig_cap_b
        if v == 'full_now':
            t = by_block[blk]['seeded_s'] if blk in by_block else a_s + b_s * mi
            t *= (1.10, 1.0, 0.95)[k]  # pod-load spread of the seeded pass [M: 2 reps, +-3%] widened [E]
        else:
            t = fixed_s(by_block[blk]) if blk in by_block else a_f + b_f * mi
            t *= (1.15, 1.0, 0.90)[k]
        q = dict(p); q['cap_mips'] = mi / max(t, 1e-9)
        return orig_model(mi, sh, q, on=on, gpus=gpus, production=production)

    pm.model = model
    out = {'labels': 'M measured, D derived, E estimate', 'seeded_fit_s': {'a': a_s, 'b_per_minstr': b_s, 'mips_marginal': 1 / b_s},
           'fixed_fit_s': {'a': a_f, 'b_per_minstr': b_f, 'mips_marginal': 1 / b_f}, 'walk_share': walk_share, 'variants': {}}
    names = ['p50 (29.1M gas)', 'p95 (55.8M gas)', '26235168', '26235159', '24628607']
    for v in ('plan', 'full_now', 'full_fixed', 'replay_only'):
        variant['name'] = v
        res, blocks, P = pm.run(dict(pm.GAS_PCT_EMBEDDED))
        row = {}
        for name in names:
            L = res['levers'][name]
            base = L['baseline']['central']['wall_s']
            row[name] = {n: dict(before_gpucap=L['cumulative']['OGKR'][n]['wall_s'], after_gpucap=L['cumulative']['GPUCAP'][n]['wall_s'],
                                 capture_s=L['cumulative']['GPUCAP'][n]['capture_s'], pre_seal_s=L['cumulative']['GPUCAP'][n]['pre_seal_s'],
                                 cut_vs_baseline=1 - L['cumulative']['GPUCAP'][n]['wall_s'] / L['baseline'][n]['wall_s'])
                         for n in P}
            row[name]['baseline_central'] = base
        t = res['basket_totals']
        row['basket'] = {n: dict(before_gpucap=t['OGKR'][n], after_gpucap=t['GPUCAP'][n], cut_vs_baseline=1 - t['GPUCAP'][n] / t['baseline'][n]) for n in P}
        row['best_2gpu'] = res['best_2gpu']
        out['variants'][v] = row
    for v, row in out['variants'].items():
        print('== %s' % v)
        for name in names + ['basket']:
            c = row[name]['central']; pe = row[name]['pess']; op = row[name]['opt']
            extra = (' cap %.2f s pre-seal %.2f' % (c['capture_s'], c['pre_seal_s'])) if name != 'basket' else ''
            print('  %-16s after #1-#8 %6.2f -> +GPUCAP %6.2f (cut %3.0f%%; pess %3.0f%% opt %3.0f%%)%s' % (
                name, c['before_gpucap'], c['after_gpucap'], 100 * c['cut_vs_baseline'], 100 * pe['cut_vs_baseline'], 100 * op['cut_vs_baseline'], extra))
        b = row['best_2gpu']['central']
        print('  best 2-GPU set (central): min cut %.0f%% with %s' % (100 * b['min_cut'], '+'.join(b['levers'])))
    print('seeded first pass fit: %.3f + %.4f*Minstr s (%.0f MIPS marginal); services fixed: %.3f + %.4f*Minstr (%.0f MIPS)' % (a_s, b_s, 1 / b_s, a_f, b_f, 1 / b_f))
    if a.json:
        json.dump(out, open(a.json, 'w'), indent=1, sort_keys=True)


if __name__ == '__main__':
    main()
