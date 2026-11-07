#!/usr/bin/env python3
"""Tests for scripts/rv64_m9/frontier_gap_model.py (python3 -I scripts/tests/test_rv64_m9_frontier_gap_model.py)."""
import math, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'rv64_m9'))
import frontier_gap_model as fg  # noqa: E402

pm = fg.pm
P = fg.params()
SHAPES = [(26.894777, pm.shape(26.894777, 10, 24628607)), (93.1, pm.shape(93.1)), (178.5, pm.shape(178.5))]
PLAN_SETS = [(), ('LEAVES',), ('IO', 'INPLACE', 'STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR_ENG', 'GPUCAP'), ('D2REV', 'NGKR')]


def close(a, b, tol=1e-9):
    return abs(a - b) <= tol * max(1.0, abs(a), abs(b))


def test_identity_without_new_levers():
    for mi, sh in SHAPES:
        for on in PLAN_SETS:
            for n in P:
                a = pm.model(mi, sh, P[n], on=on); b = fg.model(mi, sh, P[n], on=on)
                for k in ('wall_s', 'kernel_gpu_s', 'native_gpu_s', 'recursion_gpu_s'):
                    assert close(a[k], b[k]), (on, n, k, a[k], b[k])


def test_globals_restored():
    keep = (pm.N_PER_MI, pm.RFIT, pm.LEAF_K, pm.FOLD_K, pm.FANIN_LEAF_SHARE)
    for mi, sh in SHAPES:
        fg.model(mi, sh, P['central'], on=('STACK', 'BLAKE3R', 'GRIND26', 'LEAVES'))
    assert keep == (pm.N_PER_MI, pm.RFIT, pm.LEAF_K, pm.FOLD_K, pm.FANIN_LEAF_SHARE)


def test_split_scaling_is_exact():
    """native x fN, leaf x fL, fold x fF reach model() exactly, with and without fan-in."""
    for mi, sh in SHAPES:
        for leaves in (False, True):
            on = ('LEAVES',) if leaves else ()
            p = P['central']
            base = pm.model(mi, sh, p, on=on)
            with fg.patched(1.0, 0.5, 0.5, sh, leaves):
                half = pm.model(mi, sh, p, on=on)
            assert close(half['recursion_gpu_s'], 0.5 * base['recursion_gpu_s']), (leaves, half, base)
            assert close(half['native_gpu_s'], base['native_gpu_s'])
            with fg.patched(0.7, 1.0, 1.0, sh, leaves):
                nat = pm.model(mi, sh, p, on=on)
            assert close(nat['native_gpu_s'], 0.7 * base['native_gpu_s'])
            assert close(nat['recursion_gpu_s'], base['recursion_gpu_s'])
            # leaf-only factor: total recursion falls by leaf share x (1 - fL); fold-only by the rest
            with fg.patched(1.0, 0.0, 1.0, sh, leaves):
                fold_only = pm.model(mi, sh, p, on=on)
            with fg.patched(1.0, 1.0, 0.0, sh, leaves):
                leaf_only = pm.model(mi, sh, p, on=on)
            assert close(fold_only['recursion_gpu_s'] + leaf_only['recursion_gpu_s'], base['recursion_gpu_s'])


def test_evidence_arithmetic():
    f = fg.frontier_table(3.198)
    assert f['opened_width_ours_cpu_proof'] == 5833
    assert math.isclose(fg.LEAF_ROW_SHARE, 0.681, abs_tol=0.002)
    assert math.isclose(fg.LEAF_HASH_SHARE, 0.852, abs_tol=0.002)
    assert math.isclose(f['ours_native_lde_bits_per_instr_D2'], 193.1 * 31 * 4)
    assert 7.0 < f['ours_over_airbender_lde_bits_per_instr'] < 8.5
    assert math.isclose(f['opened_width_ours_equal_height'], 80.5 + 46.1 + 8 + 16, abs_tol=0.2)  # comp stays 16 wide


def test_levers_have_the_right_sign():
    mi, sh = SHAPES[1]
    for n in P:
        b = fg.model(mi, sh, P[n])
        for lv in ('STACK', 'BLAKE3R'):
            s = fg.model(mi, sh, P[n], on=(lv,))
            assert s['recursion_gpu_s'] < b['recursion_gpu_s'], (lv, n)
        g = fg.model(mi, sh, P[n], on=('GRIND26',))
        assert g['grind_gpu_s'] > 0
        st = fg.model(mi, sh, P[n], on=('STACK',))
        assert st['native_gpu_s'] >= b['native_gpu_s']  # stacking never makes native cheaper


def test_central_result_pinned():
    out = fg.run(dict(pm.GAS_PCT_EMBEDDED))
    top = out['search']['central'][0]
    assert set(top['add']) == {'STACK', 'BLAKE3R', 'NGKRFULL', 'D2REV'}, top['add']
    assert 0.55 < top['min_cut'] < 0.60, top['min_cut']  # [review] central does not reach 60% on 2 GPUs
    assert out['search']['pess'][0]['min_cut'] < 0.50  # pessimistic stays below 50% on 2 GPUs
    # production (new block per request): class-miss host build on the critical path lowers every cut
    for n in P:
        assert out['production'][n]['plan_best_top']['cut_p50'] < out['search'][n][0]['cut_p50'], n
    assert out['grind26_break_even_rate'] > P['central']['grind_rate']


def test_grind26_costs_at_as_built_rate():
    """[review] at the measured ~1.1 G/s device grind, 26-bit grinding is a net loss, and its serial tail is on the wall."""
    mi, sh = SHAPES[1]
    p = P['central']
    b = fg.model(mi, sh, p); g = fg.model(mi, sh, p, on=('GRIND26',))
    assert g['kernel_gpu_s'] > b['kernel_gpu_s'] and g['wall_s'] > b['wall_s']
    tail = fg.grind_tail_s(('GRIND26',), p, sh)
    assert close(tail, (1 + sh['levels']) * (2 ** 26 - 2 ** 20) / p['grind_rate'])
    free = fg.model(mi, sh, dict(p, grind_rate=1e30), on=('GRIND26',))  # same query cut, no grind
    assert close(g['tail_s'] - free['tail_s'], tail)
    fast = dict(p, grind_rate=200e9)  # with a near-free grind the query cut wins
    assert fg.model(mi, sh, fast, on=('GRIND26',))['kernel_gpu_s'] < b['kernel_gpu_s']


def test_ngkrfull_verifier_cost_with_stack():
    """[review] with STACK on, NGKRFULL's leaf saving is gone but its in-circuit GKR verifier cost stays."""
    for n in P:
        _, fl_s, _, _ = fg.factors(('STACK',), P[n], SHAPES[0][1])
        _, fl_sn, _, _ = fg.factors(('STACK', 'NGKRFULL'), P[n], SHAPES[0][1])
        assert close(fl_sn - fl_s, P[n]['ngkrf_verify'])


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for t in tests:
        t(); print('ok', t.__name__)
    print('%d/%d passed' % (len(tests), len(tests)))
