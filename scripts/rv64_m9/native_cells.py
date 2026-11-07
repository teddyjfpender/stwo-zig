#!/usr/bin/env python3
"""RV64 M9 stream m9-native-cells: native cells/columns budget and work-reduction levers.

Labels: [M] measured, [D] derived from measured values, [E] estimate.

  python3 -I scripts/rv64_m9/native_cells.py census --cells-dir DIR --out vectors/reports/rv64-m9-prep/m9-native-cells/blocks.json
      DIR holds `rv64-m9-native-cells <bundle.json> 18` outputs (one per basket block, file name ends in -<block>.json).
      The tool (src/integrations/riscv_cpu/build_m9_native_cells.zig) runs the production roster code on the
      declarations of produced native proofs; it is a declaration census, reconciled for 24628607 against the
      measured GPU_TRACE_OWNERSHIP tree=2 words (see README).
  python3 -I scripts/rv64_m9/native_cells.py model [--json out.json]
      Budget per component / instruction class, basket-weighted, and the lever table (native cells and GPU-s factors).

Design note: design/riscv-proving-stack/rv64-m9-native-cells.md.
"""
import argparse, glob, json, math, os, re, sys
from collections import OrderedDict, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REC = os.path.join(ROOT, 'vectors/reports/rv64-m9-prep/m9-native-cells')

BIND = 16                 # eq + prefix, two OM31 columns [M, binding.zig INTERACTION_COLUMNS]
KECCAK_ROWS_PER_PAIR = 27  # active rows per two permutations, production throughput_r27_v1 = Geometry.pair27 [M, rv64/air/delegations/keccak/layout.zig]

# --- native GPU-s by stage, 24628607 warm, opt-combined default kernels (ab8 fullstack, CUPTI union) [M] ---
# vectors/reports/rv64-m8-20261106/opt-combined/ab8-kernels.json on codex/rv64-m8-gpu, classified by kernel name:
#   rv64_{truth_domain,joined_domain,projection_case}* = native composition 0.571; *witness*/generate* 0.451;
#   inverse_contribute/scan_tile/cumulative/lift_add (classic LogUp) 0.399; oracles_*/batch_*/eq_expand/layer/
#   binding (local GKR + binding) 0.664, of which binding_eq_expand/derive_binding/project_binding 0.132; channel 0.103.
# The shared PCS kernels (FFT/LDE, Merkle, DEEP/samples, FRI = 4.82 GPU-s) are split between native and recursion:
# native PCS = native total - native-only kernels. Native total is the plan's [D] split: 3.93/(3.93+6.29) of
# 8.333 GPU-s = 3.204 (plan_model NATIVE_FRAC_607), so native PCS ~1.02 [D]. A committed-cell split instead gives
# 4.82 x 5.49 G x 4 / (5.49 G x 4 + 21.7 G x 2) = 1.62 [D]; the two bracket the PCS share (pess/opt below).
STAGE = OrderedDict(composition=0.571, witness=0.451, logup=0.399, gkr=0.532, binding=0.132, channel=0.103)
PCS_NATIVE = {'pess': 1.02, 'central': 1.32, 'opt': 1.62}  # pess = least PCS (cell cuts pay least) [D]
# v1 (native GKR) reshapes the stages: classic LogUp kernels go, GKR facts grow +10..30 % (CENSUS.md v1 GKR work) [D/E]
V1_GKR_GROWTH = 1.20
# recursion leaf dividend per removed native column [E]: native-gkr leaf model (q108, b2) 96,228 leaf cells per column
# (24628607-leaf-model.json cpu-0: 134.7 M / 1,400 columns), x0.55 for D2's b4/q54 leaf (plan_model d2_leaf), at the
# post-M8 recursion cost 5.56 GPU-s / 21.7 G cells (plan_model central on 24628607) [D].
LEAF_CELLS_PER_COL = 96228 * 0.55
REC_NS_PER_CELL = 5.56 / 21.7

CLASS = [  # (regex on component name, instruction class)
    (r'^core\.cpu$', 'cpu core row (every instruction)'),
    (r'^core\.(rom|boundary|selection)$', 'cpu control (ROM, boundary, selection)'),
    (r'^core\.alu', 'ALU / compare / branch FUNCTION'),
    (r'^core\.(binary|and_table)', 'bitwise (binary + and table)'),
    (r'^core\.(shift|shift_table)', 'shift (+ table)'),
    (r'^core\.jalr$', 'JALR'),
    (r'^core\.(multiplication|division)$', 'MUL / DIV'),
    (r'^core\.ls', 'LS32 (sub-dword load/store)'),
    (r'^dword\.', 'LS-D64 (aligned dword load/store)'),
    (r'^core\.(initial|terminal)$', 'memory image (initial/terminal)'),
    (r'^core\.range', 'range tables'),
    (r'^bulk\.', 'bulk memory + JUMPDEST services'),
    (r'^(bridge\.keccak|sponge\.)', 'keccak bridge + sponge'),
    (r'^truth\.keccak', 'keccak truth'),
    (r'^(bridge\.(add|double)|truth\.(add|double))', 'secp add/double (bridge + truth)'),
    (r'^(bridge\.sha256|truth\.sha256)', 'sha256 (bridge + truth)'),
    (r'^(bridge\.arith256|truth\.arith256)', 'arith256 (bridge + truth)'),
    (r'^bridge\.', 'curve bridges (bn254/bls12)'),
]
# prefix roster role -> component name (prefix4-active-rows-24628607.json uses role names)
PREFIX_NAME = {'ls_dword': 'dword.0', 'ls_dword_tail': 'dword.1', 'keccak_bridge': 'bridge.keccak', 'sponge_perm': 'sponge.perm',
               'sponge_call': 'sponge.call', 'add_bridge': 'bridge.add', 'double_bridge': 'bridge.double',
               'sha256_bridge': 'bridge.sha256', 'arith256_mod_bridge': 'bridge.arith256_mod'}


def prefix_name(role):
    if role.startswith('bulk_'):
        return 'bulk.' + role[5:]
    return PREFIX_NAME.get(role, 'core.' + role)


def klass(name):
    for rx, c in CLASS:
        if re.search(rx, name):
            return c
    return 'other'


# ----------------------------------------------------------------------------------------------- census
def census(cells_dir, out):
    m3 = json.load(open(os.path.join(ROOT, 'vectors/reports/rv64-m3-20261104/summary.json')))
    instr = {r['block']: r['instructions'] for r in m3['rows']}
    rd = json.load(open(os.path.join(ROOT, 'vectors/reports/rv64-cuda-real-segment-20261103/basket-input-readiness.json')))
    gas = {r['block']: r['gas_used'] for r in rd['blocks']}
    files = sorted(glob.glob(os.path.join(cells_dir, '*.json')))
    files = [f for f in files if not f.endswith('.census.json')]
    chosen = {}
    for f in files:
        b = int(re.search(r'-(\d{8})\.json$', f).group(1))
        tag = os.path.basename(f)
        if 'm8-census2' in tag:
            chosen[('current', b)] = f
        elif b not in chosen or 'scale' in tag:
            chosen[b] = f
    blocks = OrderedDict()
    for key in sorted(chosen, key=lambda k: (isinstance(k, tuple), k if not isinstance(k, tuple) else k[1])):
        f = chosen[key]
        d = json.load(open(f))
        b = key[1] if isinstance(key, tuple) else key
        comp = defaultdict(lambda: dict(rows=0, main=0, binding=0, classic=0, v2share=0, main_cols=0, cols_today=0, n=0))
        proofs = []
        for i, c in enumerate(d['cpus']):
            groups = defaultdict(int)
            for s in c['slots']:
                rows = 1 << s['log']
                e = comp[s['name']]
                e['rows'] += rows; e['main'] += rows * s['main_cols']; e['main_cols'] += s['main_cols']; e['n'] += 1
                e['binding'] += rows * (BIND if s['binding'] else 0)
                e['classic'] += rows * (s['today_cols'] - (BIND if s['binding'] else 0))
                e['cols_today'] += s['today_cols']
                if s['share_group'] is not None:
                    groups[s['log']] += 1
            proofs.append(dict(proof='cpu-%d' % i, kind='cpu', main=c['main_cells'], main_cols=c['main_cols'],
                               today=c['today'], logup3=c['logup3'], v1=c['v1'], v2share=c['v2share'],
                               binding_components=c['binding_components'], distinct_logs=c['distinct_binding_logs']))
        for i, t in enumerate(d['truths']):
            name = 'truth.' + t['family']
            e = comp[name]
            for p in t['parts']:
                rows = 1 << p['log']
                e['rows'] += rows if p['kind'] == t['family'] else 0
                e['main'] += rows * p['main_cols']; e['main_cols'] += p['main_cols']
                e['classic'] += rows * (p['local_cols'] + p['global_cols'])
            e['n'] += 1
            pad = None
            if t['family'] == 'keccak':
                big = [p for p in t['parts'] if p['kind'] == 'keccak'][0]
                act = ((t['calls'] + 1) // 2) * KECCAK_ROWS_PER_PAIR
                pad = dict(log=big['log'], active_rows=act, rows=1 << big['log'], main_cols=big['main_cols'])
            proofs.append(dict(proof='truth-%d' % i, kind=t['family'], calls=t['calls'], main=t['main_cells'], main_cols=t['main_cols'],
                               today=t['today'], logup3=t['logup3'], v1=t['v1'], v2share=t['v2share'], keccak_padding=pad))
        blocks[('current-' if isinstance(key, tuple) else '') + str(b)] = dict(
            block=b, gas=gas.get(b), instructions=instr.get(b), source=os.path.basename(f),
            proofs=proofs, components={k: dict(v) for k, v in sorted(comp.items())})
    res = dict(schema='rv64-m9-native-cells-blocks/v1',
               label='M (declaration census of produced native proofs; production roster code; 24628607 current reconciled with measured tree=2 words)',
               tool='rv64-m9-native-cells (src/integrations/riscv_cpu/build_m9_native_cells.zig)', rom_log=18,
               bundles='/workspace/m3/runs/integrate/<block>-2gpu-*/case/batch/trial-0/<block>/proof/bundle.json (M4 integrate, 2026-11-04); '
                       'current-24628607 = /workspace/m3/runs/m8-census2/daemon-24628607-r2-c2-24628607-00-baseline (M8 default, 2026-11-07)',
               blocks=blocks)
    with open(out, 'w') as fh:
        json.dump(res, fh, separators=(',', ':'))
    print('wrote', out, len(blocks), 'blocks')


# ----------------------------------------------------------------------------------------------- model
def tot(block, variant):
    m = sum(p['main'] for p in block['proofs'])
    i = sum(p[variant]['inter_cells'] for p in block['proofs'])
    c = sum(p['main_cols'] + p[variant]['inter_cols'] for p in block['proofs'])
    return m, i, c


def stage_gpu(scn, basis):
    """Native GPU-s by stage for 24628607 (today = M8 default) and the v1 (native GKR) basis [D]."""
    s = OrderedDict((k, v) for k, v in STAGE.items())
    s['pcs'] = PCS_NATIVE[scn]
    if basis == 'v1':
        s['logup'] = 0.0
        s['gkr'] *= V1_GKR_GROWTH
    return s


def native_factor(before, after, scn, basis):
    """Native GPU-s factor of a change from `before` to `after` cell dicts (main, inter, classic, binding) [D].
    Drivers: PCS and composition ~ committed cells; witness ~ MAIN; LogUp ~ classic INTER; binding kernels ~ binding cells;
    GKR traversal ~ facts (unchanged by column levers); channel fixed."""
    s = stage_gpu(scn, basis)
    tot0 = sum(s.values())
    r = lambda k: (after[k] / before[k]) if before[k] else 1.0
    cells0 = before['main'] + before['inter']; cells1 = after['main'] + after['inter']
    new = (s['pcs'] + s['composition']) * (cells1 / cells0) + s['witness'] * r('main') + s['logup'] * r('classic') \
        + s['binding'] * r('binding') + s['gkr'] + s['channel']
    return new / tot0


def model(blocks_path, out=None):
    B = json.load(open(blocks_path))['blocks']
    basket = OrderedDict((k, v) for k, v in B.items() if not k.startswith('current-'))
    cur = B.get('current-24628607')
    pre = json.load(open(os.path.join(REC, 'prefix4-active-rows-24628607.json')))
    res = OrderedDict(labels='M measured, D derived, E estimate', inputs=dict(blocks=os.path.relpath(blocks_path, ROOT)))

    # 1. reconciliation + headline totals ------------------------------------------------------------------------
    meas_tree2 = [142414080, 443547648, 193262336, 142366976, 147421696, 60162048, 102433792, 84017152, 65536,
                  141944320, 145746432, 239075328, 66060288, 499712]  # census2 producer.stderr GPU_TRACE_OWNERSHIP tree=2, native proofs [M]
    meas_pcs = [504340576, 1040449536, 632799008, 501201568, 332734816, 176603136, 512945568, 30490624, 115228672,
                500453664, 519525824, 579731456, 90357760, 715264]  # GPU_PCS_NATIVE coefficient_cells (all native trees incl. FIXED + composition) [M]
    if cur:
        decl = sorted(p['today']['inter_cells'] for p in cur['proofs'])
        m, i, c = tot(cur, 'today')
        res['reconciliation_24628607_current'] = dict(
            declared_inter_equals_measured_tree2=decl == sorted(meas_tree2), native_proofs=len(cur['proofs']),
            main=m, inter=i, main_plus_inter=m + i, measured_pcs_coefficient_cells=sum(meas_pcs),
            pcs_minus_main_inter=sum(meas_pcs) - m - i, label='M')

    # 2. per-block variant totals ------------------------------------------------------------------------------
    rows = []
    for k, b in list(basket.items()) + ([('current-24628607', cur)] if cur else []):
        r = dict(block=k, gas=b['gas'], minstr=b['instructions'] / 1e6 if b['instructions'] else None)
        for v in ('today', 'logup3', 'v1', 'v2share'):
            m, i, c = tot(b, v)
            r[v] = dict(main=m, inter=i, cells=m + i, cols=c)
        cpu = [p for p in b['proofs'] if p['kind'] == 'cpu']
        r['cpu_cells_today'] = sum(p['main'] + p['today']['inter_cells'] for p in cpu)
        r['truth_cells_today'] = r['today']['cells'] - r['cpu_cells_today']
        r['cpu_cells_per_instr_today'] = r['cpu_cells_today'] / b['instructions'] if b['instructions'] else None
        r['cells_per_instr_today'] = r['today']['cells'] / b['instructions'] if b['instructions'] else None
        r['cells_per_gas_today'] = r['today']['cells'] / b['gas'] if b['gas'] else None
        rows.append(r)
    res['blocks'] = rows

    # 3. budget per component and instruction class (basket sum, today and v1) ----------------------------------
    agg = defaultdict(lambda: defaultdict(float)); n_instr = sum(b['instructions'] for b in basket.values())
    for b in basket.values():
        for name, e in b['components'].items():
            a = agg[name]
            for f in ('rows', 'main', 'binding', 'classic'):
                a[f] += e[f]
            a['main_cols'] = max(a['main_cols'], e['main_cols'] / max(1, e['n']))
    tot_today = sum(a['main'] + a['binding'] + a['classic'] for a in agg.values())
    tot_v1 = sum(b_['v1']['cells'] for b_ in rows if not b_['block'].startswith('current'))
    comps = []
    for name, a in sorted(agg.items(), key=lambda x: -(x[1]['main'] + x[1]['binding'] + x[1]['classic'])):
        today = a['main'] + a['binding'] + a['classic']
        v1 = a['main'] + (a['binding'] if not name.startswith('truth.') else 0)
        comps.append(dict(component=name, klass=klass(name), main_cols=round(a['main_cols'], 1), main=a['main'], binding=a['binding'],
                          classic=a['classic'], today=today, today_share=today / tot_today,
                          cells_per_instr_today=today / n_instr, v1_main_plus_binding=v1, v1_cells_per_instr=v1 / n_instr))
    res['components_basket'] = comps
    classes = defaultdict(lambda: dict(today=0.0, main=0.0, binding=0.0, classic=0.0, v1=0.0))
    for c in comps:
        k = classes[c['klass']]
        for f in ('today', 'main', 'binding', 'classic'):
            k[f] += c[f]
        k['v1'] += c['v1_main_plus_binding']
    for b in basket.values():
        for p in b['proofs']:
            if p['kind'] == 'cpu':
                continue
            nm = klass('truth.' + p['kind'])
            classes[nm]['v1'] += p['v1']['inter_cells']
    # instruction-class shares from the exact prefix rows (24628607, 4 segments) [M]
    act = defaultdict(int); n_pre = 0
    for seg in pre['segments']:
        for role, log, nrows, arows in seg:
            if role == 'cpu':
                n_pre += arows
            if arows is not None:
                act[klass(prefix_name(role))] += arows
    cl = []
    for name, k in sorted(classes.items(), key=lambda x: -x[1]['today']):
        cl.append(dict(klass=name, today=k['today'], today_share=k['today'] / tot_today, today_cells_per_instr=k['today'] / n_instr,
                       v1=k['v1'], v1_cells_per_instr=k['v1'] / n_instr, main=k['main'], binding=k['binding'], classic=k['classic'],
                       prefix_active_rows_per_instr=(act.get(name, 0) / n_pre) if name in act else None))
    res['classes_basket'] = cl
    res['basket_totals'] = dict(instructions=n_instr, gas=sum(b['gas'] for b in basket.values()), today=tot_today, v1=tot_v1,
                                today_cells_per_instr=tot_today / n_instr, v1_cells_per_instr=tot_v1 / n_instr,
                                today_cells_per_gas=tot_today / sum(b['gas'] for b in basket.values()), label='M (declaration census) / D (v1)')

    # 4. padding [M on the prefix, D for the block] -------------------------------------------------------------
    widths = {c['component']: c['main_cols'] for c in comps}
    pad_waste = pad_total = 0.0
    pad_by = defaultdict(float)
    for seg in pre['segments']:
        for role, log, nrows, arows in seg:
            nm = prefix_name(role)
            w = widths.get(nm, 0) + BIND
            pad_total += nrows * w
            if arows is not None:
                pad_waste += (nrows - arows) * w; pad_by[nm] += (nrows - arows) * w
    kpad = [p['keccak_padding'] for b in basket.values() for p in b['proofs'] if p.get('keccak_padding')]
    k_waste = sum((p['rows'] - p['active_rows']) * (p['main_cols'] + BIND) for p in kpad)
    k_tot = sum(p['rows'] * (p['main_cols'] + BIND) for p in kpad)
    res['padding'] = dict(cpu_prefix_waste_share_of_cpu_v1=pad_waste / pad_total, cpu_prefix_top=sorted(pad_by.items(), key=lambda x: -x[1])[:8],
                          keccak_truth_waste_share_of_keccak_v1=k_waste / k_tot, keccak_truth_waste_cells_basket=k_waste,
                          label='M (exact active rows: prefix roster for CPU, ceil(calls/2)*29 for keccak)')

    # 5. levers -----------------------------------------------------------------------------------------------
    S = {}
    for nm in ('today', 'logup3', 'v1', 'v2share'):
        S[nm] = dict(main=sum(r_[nm]['main'] for r_ in rows if not r_['block'].startswith('current')),
                     inter=sum(r_[nm]['inter'] for r_ in rows if not r_['block'].startswith('current')),
                     cols=sum(r_[nm]['cols'] for r_ in rows if not r_['block'].startswith('current')))
    bind_today = sum(c['binding'] for c in comps); classic_today = sum(c['classic'] for c in comps)

    def cd(nm, binding=None, classic=None, main=None):
        d = dict(main=S[nm]['main'] if main is None else main, inter=S[nm]['inter'])
        d['binding'] = bind_today if binding is None else binding
        d['classic'] = (S[nm]['inter'] - d['binding']) if classic is None else classic
        return d
    today = cd('today', classic=classic_today)
    v1 = dict(main=S['v1']['main'], inter=S['v1']['inter'], binding=S['v1']['inter'], classic=0.0)
    v2 = dict(main=S['v2share']['main'], inter=S['v2share']['inter'], binding=S['v2share']['inter'], classic=0.0)
    l3 = dict(main=S['logup3']['main'], inter=S['logup3']['inter'], binding=bind_today, classic=S['logup3']['inter'] - bind_today)
    cpu_v1 = sum(c['v1_main_plus_binding'] for c in comps if not c['component'].startswith('truth.'))
    kmain = sum(c['main'] for c in comps if c['component'] == 'truth.keccak')
    core_main = sum(c['main'] for c in comps if c['component'] == 'core.cpu')

    def lever(name, label, before, after, basis, cols_removed=0, what='', soundness='', extra=None):
        f = {s: native_factor(before, after, s, basis) for s in ('pess', 'central', 'opt')}
        leaf = cols_removed * LEAF_CELLS_PER_COL * REC_NS_PER_CELL * 1e-9
        L = dict(lever=name, label=label, basis=basis, what=what, soundness=soundness,
                 cells_before=before['main'] + before['inter'], cells_after=after['main'] + after['inter'],
                 cells_factor=(after['main'] + after['inter']) / (before['main'] + before['inter']),
                 native_gpu_s_factor=f, leaf_columns_removed_basket=cols_removed,
                 leaf_recursion_gpu_s_saved_basket=leaf)
        if extra:
            L.update(extra)
        return L

    levers = []
    levers.append(lever('NGKR_V1', 'M/D', today, v1, 'today', S['today']['cols'] - S['v1']['cols'],
                        'native GKR v1: classic RAM/KIO/Wire + truth classic LogUp move into one stage-two GKR; one eq+prefix pair per component (plan lever NGKR)',
                        'changes the proof (new section, receiver, leaf); rv64-native-gkr.md sec 9 review; REQUIRED_BITS 151 gate'))
    levers.append(lever('LOGUP3', 'D', today, l3, 'today', S['today']['cols'] - S['logup3']['cols'],
                        'ALTERNATIVE to NGKR only: 3 fractions per classic LogUp column (degree-4 batch constraint, fits the b4 D2 composition)',
                        'same LogUp argument; constraint degree 3 -> 4; changes the proof'))
    levers.append(lever('V2SHARE', 'M (declaration census of the real Plan) / D (GPU-s)', v1, v2, 'v1', S['v1']['cols'] - S['v2share']['cols'],
                        'on top of v1: ONE eq + prefix pair per distinct row log of a proof; prefixes of same-log components combined with a fresh rho',
                        'needs the shared-row-point lemma (one batch per proof, lane-major); rho drawn after all instance claims; error +k/|OM31|; changes the proof'))
    # padding: recover half of the measured waste with a second tail height / exact keccak shard sizing [E on M]
    cpu_pad = res['padding']['cpu_prefix_waste_share_of_cpu_v1'] * cpu_v1
    for scn_rec, tag in ((0.5, 'central'),):
        cut = scn_rec * cpu_pad + scn_rec * k_waste
        after = dict(v2); after['main'] = v2['main'] - cut * 0.8; after['binding'] = v2['binding'] - cut * 0.2; after['inter'] = after['binding']
        levers.append(lever('PAD', 'M (waste) / E (recovery 50 %)', v2, after, 'v1', 0,
                            'tighter power-of-two packing: a second tail height for alu/ls_dword/bulk/sponge and exact keccak shard logs; recover ~half of the measured waste',
                            'prover-side shape only; roster/class change, no new argument',
                            extra=dict(waste_cells_basket=cpu_pad + k_waste)))
    # core narrowing: compact decode already cut 47 -> 37 [M]; a further -3 columns is a candidate, not verified [E]
    after = dict(v2); after['main'] = v2['main'] - core_main * 3 / 37; after['inter'] = v2['inter']
    levers.append(lever('CORE_NARROW', 'E', v2, after, 'v1', 3 * sum(1 for b in basket.values() for p in b['proofs'] if p['kind'] == 'cpu'),
                        'CPU row 37 -> 34 MAIN columns (candidate: derive the three enabled flags; not verified sound)',
                        'AIR change; needs the decode/enable authority re-derived; changes the proof'))
    res['levers'] = levers

    # 6. guest-side instruction cuts (guest-efficiency ledger) [M/E] -------------------------------------------
    res['guest'] = dict(
        zbb=dict(label='M (basket scored, zbb-prefix-24628607-v2.json)', instr_per_gas=(3.130023801238801, 2.934248313418029),
                 bits_per_gas=(33695.394597325794, 32187.44336049941), instr_factor=2.934248313418029 / 3.130023801238801,
                 native_cells_factor=32187.44336049941 / 33695.394597325794,
                 note='opt-in ethereum_services_v3_zbb profile: proven prefix + fresh verify; driver/class work left to make it default'),
        dispatch=dict(label='M (cost) / E (cut)', dispatch_instr_per_gas=(1.12, 1.36), instr_per_dispatched_op=28.1,
                      note='autoresearch/guest_efficiency/notes/client3-20261102.md: dispatch_cgoto 1.26-1.36 instr/gas, 28.1 instructions per EVM opcode; '
                           'PUSH1 16, POP 10, SWAP1 25, ADD 36 instructions each. Block-level gas/stack checks (evmone advanced-style basic-block '
                           'analysis) would take per-opcode overhead from ~28 to ~14-18 [E]: -0.35..-0.65 instr/gas = x0.80..0.89 instructions',
                      instr_factor=dict(pess=0.92, central=0.85, opt=0.79)),
        cpu_share_of_native_cells=sum(r_['cpu_cells_today'] for r_ in rows if not r_['block'].startswith('current')) /
        sum(r_['today']['cells'] for r_ in rows if not r_['block'].startswith('current')))

    # combined prover-side factor on top of v1 (V2SHARE x PAD x CORE_NARROW), per scenario [D/E]
    comb = {}
    for s in ('pess', 'central', 'opt'):
        f = 1.0
        for L in levers:
            if L['lever'] in ('V2SHARE', 'PAD') or (L['lever'] == 'CORE_NARROW' and s != 'pess'):
                f *= L['native_gpu_s_factor'][s]
        comb[s] = f
    res['combined_prover_side_on_v1'] = dict(native_gpu_s_factor=comb, levers='V2SHARE x PAD (+ CORE_NARROW central/opt)', label='D/E')
    if out:
        with open(out, 'w') as fh:
            json.dump(res, fh, indent=1)
    return res


def show(res):
    rc = res.get('reconciliation_24628607_current')
    if rc:
        print('24628607 current (M8 default): declared INTER == measured tree=2 words:', rc['declared_inter_equals_measured_tree2'],
              '| MAIN %.3f G INTER %.3f G | PCS coefficient cells %.3f G' % (rc['main'] / 1e9, rc['inter'] / 1e9, rc['measured_pcs_coefficient_cells'] / 1e9))
    t = res['basket_totals']
    print('\nbasket (15 blocks): %.0f M instr, %.1f M gas | today %.2f G cells = %.1f cells/instr, %.0f cells/gas | v1 %.2f G = %.1f cells/instr'
          % (t['instructions'] / 1e6, t['gas'] / 1e6, t['today'] / 1e9, t['today_cells_per_instr'], t['today_cells_per_gas'], t['v1'] / 1e9, t['v1_cells_per_instr']))
    print('\nper block: block Minstr | today cells/instr | cpu cells/instr | truth share | v1/today | v2share/v1 | cols today -> v2share')
    for r in res['blocks']:
        print('  %-17s %6.1f | %6.1f | %6.1f | %4.0f%% | %.3f | %.3f | %6d -> %6d' % (
            r['block'], r['minstr'] or 0, r['cells_per_instr_today'] or 0, r['cpu_cells_per_instr_today'] or 0,
            100 * r['truth_cells_today'] / r['today']['cells'], r['v1']['cells'] / r['today']['cells'],
            r['v2share']['cells'] / r['v1']['cells'], r['today']['cols'], r['v2share']['cols']))
    print('\ninstruction classes (basket): share of today | today cells/instr | v1 cells/instr | class rows per instruction (prefix)')
    for c in res['classes_basket']:
        pr = c['prefix_active_rows_per_instr']
        print('  %-42s %5.1f%% | %6.2f | %6.2f | %s' % (c['klass'], 100 * c['today_share'], c['today_cells_per_instr'], c['v1_cells_per_instr'],
                                                     '%.4f' % pr if pr is not None else '-'))
    print('\ntop components (basket): main cols | today cells/instr (main / binding / classic) | v1 cells/instr')
    for c in res['components_basket'][:16]:
        n = res['basket_totals']['instructions']
        print('  %-20s %6.1f | %6.2f (%5.2f / %5.2f / %5.2f) | %6.2f' % (c['component'], c['main_cols'], c['cells_per_instr_today'],
                                                                     c['main'] / n, c['binding'] / n, c['classic'] / n, c['v1_cells_per_instr']))
    p = res['padding']
    print('\npadding: CPU %.1f%% of CPU v1 cells (prefix); keccak truth %.1f%% of keccak v1 cells' % (100 * p['cpu_prefix_waste_share_of_cpu_v1'], 100 * p['keccak_truth_waste_share_of_keccak_v1']))
    print('\nlevers: cells factor | native GPU-s factor pess/central/opt | leaf columns removed, leaf GPU-s saved (basket)')
    for L in res['levers']:
        f = L['native_gpu_s_factor']
        print('  %-12s [%s] basis %-5s cells x%.3f | x%.3f / x%.3f / x%.3f | %7d cols, %.2f GPU-s' % (
            L['lever'], L['label'].split(' ')[0], L['basis'], L['cells_factor'], f['pess'], f['central'], f['opt'],
            L['leaf_columns_removed_basket'], L['leaf_recursion_gpu_s_saved_basket']))
    c = res['combined_prover_side_on_v1']['native_gpu_s_factor']
    print('  combined prover-side on v1: x%.3f / x%.3f / x%.3f' % (c['pess'], c['central'], c['opt']))
    g = res['guest']
    print('\nguest: zbb instr x%.3f, native cells x%.3f [M]; dispatch instr x%.2f/%.2f/%.2f [E]; CPU share of native cells %.2f'
          % (g['zbb']['instr_factor'], g['zbb']['native_cells_factor'], g['dispatch']['instr_factor']['pess'],
             g['dispatch']['instr_factor']['central'], g['dispatch']['instr_factor']['opt'], g['cpu_share_of_native_cells']))


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)
    a = sp.add_parser('census'); a.add_argument('--cells-dir', required=True); a.add_argument('--out', default=os.path.join(REC, 'blocks.json'))
    b = sp.add_parser('model'); b.add_argument('--blocks', default=os.path.join(REC, 'blocks.json')); b.add_argument('--json')
    args = ap.parse_args()
    if args.cmd == 'census':
        census(args.cells_dir, args.out)
    else:
        show(model(args.blocks, args.json))


if __name__ == '__main__':
    main()
