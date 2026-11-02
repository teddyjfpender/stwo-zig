"""Per-phase core/wall profile of a GKR-route (or classic-route) prefix run.

usage: python3 -I gkr_phases.py RUN_DIR [LOG_WITH_OM_DOMAIN_LINES] [--json OUT]
Stage files physical-NNNN.stages.json map to report.workers (GKR) / cost (classic)
in order: CPU proofs then truth proofs.
"""
import json, sys, glob, os, collections, itertools, re

PH = ['witness', 'gkr', 'main_lde', 'main_hash', 'binding', 'inter_gen', 'inter_lde', 'inter_hash',
      'comp_eval', 'comp_interp', 'comp_commit', 'oods', 'deep_fri_commit', 'pow', 'fri_decommit',
      'trace_decommit', 'spill', 'other']


def usage(x):
    return (x.get('process_usage') or {}).get('lane_user_seconds', 0.0)


def leaves(x):
    if x.get('children'):
        for c in x['children']:
            yield from leaves(c)
    else:
        yield x


def classify(stages):
    """Returns phase -> [wall, core]. Streaming groups: first = MAIN, second = interaction."""
    out = collections.defaultdict(lambda: [0.0, 0.0])
    commit_group = 0
    for key, group in itertools.groupby(stages, key=lambda x: x['id']):
        group = list(group)
        if key == 'streaming_commit_prepare' or key == 'merkle_commit' and False:
            commit_group += 1
        for x in group:
            top = x['id']
            for leaf in leaves(x):
                w, u = leaf['seconds'], usage(leaf)
                if top == 'source_construction':
                    p = 'witness'
                elif top == 'main_commit' or top == 'interaction_commit':
                    side = 'main' if top == 'main_commit' else 'inter'
                    p = side + ('_lde' if leaf['id'] == 'streaming_transform' else '_hash')
                elif top == 'streaming_commit_prepare':
                    side = 'main' if commit_group == 1 else 'inter'
                    p = side + ('_lde' if leaf['id'] == 'streaming_transform' else '_hash')
                elif top == 'merkle_commit':
                    p = ('main' if commit_group <= 1 else 'inter') + '_hash'
                elif top.startswith('retained_main'):
                    p = 'spill'
                elif top == 'local_gkr_prove':
                    p = 'gkr'
                elif top == 'binding_finalize':
                    p = 'binding'
                elif top == 'interaction_generation':
                    p = 'inter_gen'
                elif top == 'composition_evaluation':
                    p = 'comp_eval'
                elif top == 'composition_interpolate_and_split':
                    p = 'comp_interp'
                elif top == 'composition_commit':
                    p = 'comp_commit'
                elif top.startswith('sampled_value') or top.startswith('oods'):
                    p = 'oods'
                elif top in ('fri_quotient_build_and_commit',) or top.startswith('fri_commit') or top.startswith('deep'):
                    p = 'deep_fri_commit'
                elif top == 'fri_decommit':
                    p = 'fri_decommit'
                elif top == 'proof_of_work':
                    p = 'pow'
                elif top == 'trace_decommit':
                    p = 'trace_decommit'
                else:
                    p = 'other'
                out[p][0] += w
                out[p][1] += u
    return out


def om_cells(log_path):
    """Committed MAIN/INTER M31 cells from OM_DOMAIN_STAGE / OM_TRUTH_DOMAIN_STAGE lines."""
    main = inter = 0
    if not log_path or not os.path.exists(log_path):
        return None
    for line in open(log_path, errors='replace'):
        m = re.match(r'OM_(TRUTH_)?DOMAIN_STAGE .*?log=(\d+) main=(\d+) inter=(\d+)', line)
        if m:
            n = 1 << int(m.group(2))
            main += int(m.group(3)) * n
            inter += int(m.group(4)) * n
    return main, inter


def run(d, log_path=None):
    rep = json.load(open(os.path.join(d, 'report.json')))
    files = sorted(glob.glob(os.path.join(d, 'physical-*.stages.json')))
    workers = rep.get('workers')
    total = collections.defaultdict(lambda: [0.0, 0.0])
    per = []
    for i, f in enumerate(files):
        ph = classify(json.load(open(f))['stages'])
        if workers:
            w = workers[i]
            # Older binaries do not record these stages: fall back to wall timings.
            if ph['witness'][0] == 0:
                ph['witness'][0] += w.get('source_ns', 0) / 1e9
            if ph['gkr'][0] == 0:
                ph['gkr'][0] += (w.get('inputs_ns', 0) + w.get('numerical_ns', 0)) / 1e9
            ph['spill'][0] += (w.get('spill_ns', 0) + w.get('restore_ns', 0)) / 1e9
        per.append((os.path.basename(f), ph))
        for k, v in ph.items():
            total[k][0] += v[0]
            total[k][1] += v[1]
    core_sum = sum(v[1] for v in total.values())
    res = {'dir': d, 'prove_s': rep['prove_ns'] / 1e9, 'steps': rep['total_steps'], 'cpu_proofs': rep['cpu_proofs'],
           'truth_proofs': rep['truth_proofs'], 'stage_core_s': core_sum,
           'phases': {k: {'wall_s': round(total[k][0], 3), 'core_s': round(total[k][1], 2)} for k in PH if k in total},
           'per_proof': [{'file': n, 'wall_s': round(sum(v[0] for v in ph.values()), 2), 'core_s': round(sum(v[1] for v in ph.values()), 2),
                          'top': sorted(((k, round(v[1], 2)) for k, v in ph.items()), key=lambda kv: -kv[1])[:4]} for n, ph in per]}
    cells = om_cells(log_path)
    if cells:
        res['committed_main_cells'] = cells[0]
        res['committed_inter_cells'] = cells[1]
    return res


if __name__ == '__main__':
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    out = None
    if '--json' in sys.argv:
        out = sys.argv[sys.argv.index('--json') + 1]
        args = [a for a in args if a != out]
    r = run(args[0], args[1] if len(args) > 1 else None)
    print(f"{r['dir']} prove={r['prove_s']:.2f}s steps={r['steps']} cpu={r['cpu_proofs']} truth={r['truth_proofs']} stage-core={r['stage_core_s']:.1f}s")
    for k, v in r['phases'].items():
        print(f"  {k:16} wall={v['wall_s']:8.2f}  core={v['core_s']:8.1f}  ({100 * v['core_s'] / max(r['stage_core_s'], 1e-9):4.1f}% of stage core)")
    for p in r['per_proof']:
        print('   ', p)
    if 'committed_main_cells' in r:
        print(f"  committed MAIN cells {r['committed_main_cells'] / 1e6:.0f}M  INTER {r['committed_inter_cells'] / 1e6:.0f}M")
    if out:
        json.dump(r, open(out, 'w'), indent=1)
