import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_m8_plan_sweep as sweep

G = sweep.GRANULE


def side(peak, staged, live=0, jobs=1):
    return {'jobs': jobs, 'peak_arena_words': peak, 'live_peak_words': live or peak, 'staged_words': staged,
            'peak_alloc': 3, 'peak_alloc_words': G, 'allocs': 5}


def worker_doc(rows, allocator='lifo', device=0):
    return {'schema': 'rv64-m8-jobs-class-plans/v2', 'device': device, 'arena_words': 1 << 20, 'allocator': allocator,
            'persistent': {'budget_words': 0, 'high_water_words': 0, 'evictions': 0, 'unbudgeted_regions': 1},
            'classes': [{'device': device, 'class_key': k, 'stat': s} for k, s in rows]}


def stat(bottom, top, declared=0, slab=G, pinned=G, persistent=0):
    return {'jobs': bottom['jobs'] + top['jobs'], 'declared_device_words': declared, 'declared_peak_words': declared,
            'slab_words': slab, 'peak_pinned_words': pinned, 'persistent_words': persistent, 'sides': [bottom, top]}


KA = 'aa' * 32
KB = 'bb' * 32


class SweepTests(unittest.TestCase):
    def write(self, root, name, doc):
        (root / name).write_text(json.dumps(doc))

    def test_collect_folds_workers_and_sides_and_reports_lifo_waste(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, 'worker-d0-1.json', worker_doc([(KA, stat(side(100 * G, 10 * G, 60 * G), side(110 * G, 10 * G, 70 * G), declared=300 * G))]))
            self.write(root, 'worker-d1-2.json', worker_doc([(KA, stat(side(105 * G, 12 * G), side(90 * G, 10 * G))), (KB, stat(side(20 * G, 2 * G), side(20 * G, 2 * G)))], device=1))
            s = sweep.collect(root, 'fixture', {KA: 'leaf'})
            a = next(c for c in s['classes'] if c['class_key'] == KA)
            self.assertEqual(a['label'], 'leaf')
            self.assertEqual(a['peak_arena_words'], 110 * G)
            self.assertEqual(a['staged_words'], 12 * G)
            self.assertEqual(a['jobs'], 4)
            self.assertEqual(sorted(a['devices']), [0, 1])
            self.assertEqual(a['live_peak_words'], 105 * G)
            self.assertEqual(a['declared_over_measured'], round(300 / 110, 4))
            b = next(c for c in s['classes'] if c['class_key'] == KB)
            self.assertTrue(b['label'].startswith('class-'))

    def test_collect_only_labeled_drops_host_model_workers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, 'gpu.json', worker_doc([(KA, stat(side(8 * G, G), side(8 * G, G)))], allocator='reuse'))
            self.write(root, 'fake.json', worker_doc([(KB, stat(side(4 * G, G), side(4 * G, G)))], allocator='lifo'))
            s = sweep.collect(root, 'tests', {KA: 'pcs'}, only_labeled=True)
            self.assertEqual([c['label'] for c in s['classes']], ['pcs'])
            self.assertEqual(s['allocator'], 'reuse')  # the fake worker's mode is not mixed in

    def test_collect_refuses_mixed_allocator_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, 'a.json', worker_doc([(KA, stat(side(G * 4, G), side(G * 4, G)))], allocator='lifo'))
            self.write(root, 'b.json', worker_doc([(KA, stat(side(G * 4, G), side(G * 4, G)))], allocator='reuse'))
            with self.assertRaises(ValueError):
                sweep.collect(root, 'x', {})

    def sweep_of(self, classes, allocator='lifo', label='s'):
        return {'schema': sweep.SWEEP_SCHEMA, 'label': label, 'allocator': allocator, 'classes': [
            {'label': n, 'class_key': k, 'peak_arena_words': p, 'staged_words': st, 'slab_words': G, 'pinned_words': G,
             'persistent_words': pw, 'declared_peak_words': 0, 'jobs': 1} for n, k, p, st, pw in classes]}

    def test_generate_sizes_the_arena_for_every_pair_and_passes_its_check(self):
        s = self.sweep_of([('leaf', KA, 1000 * G, 100 * G, 50 * G), ('fold', KB, 400 * G, 300 * G, 0)])
        p = sweep.generate([s], device_bytes=1 << 40, reserve_bytes=0, margin=0.0)
        self.assertEqual(sweep.check(p), [])
        self.assertEqual(p['gpu']['arena_words'], 1300 * G)  # leaf working beside fold's staged inputs
        self.assertEqual(p['gpu']['max_concurrent_jobs'], 2)
        self.assertEqual(p['gpu']['persistent_budget_words'], 50 * G)
        self.assertEqual(p['gpu']['pinned_slot_words'], G)  # every class pinned G words
        self.assertTrue(all(c['max_concurrent'] == 2 for c in p['classes']))

    def test_generate_caps_by_device_budget_and_serializes_what_cannot_overlap(self):
        s = self.sweep_of([('leaf', KA, 1000 * G, 100 * G, 0), ('fold', KB, 400 * G, 300 * G, 0)])
        p = sweep.generate([s], device_bytes=1200 * G * 4, reserve_bytes=0, margin=0.0)
        self.assertEqual(sweep.check(p), [])
        self.assertEqual(p['gpu']['arena_words'], 1200 * G)
        conc = {c['label']: c['max_concurrent'] for c in p['classes']}
        self.assertEqual(conc, {'leaf': 1, 'fold': 2})
        self.assertEqual(p['gpu']['max_concurrent_jobs'], 1)

    def test_generate_applies_margin_and_alignment_and_refuses_an_impossible_class(self):
        s = self.sweep_of([('leaf', KA, 1000 * G + 1, 10 * G, 0)])
        p = sweep.generate([s], device_bytes=1 << 40, reserve_bytes=0, margin=0.01)
        c = p['classes'][0]
        self.assertEqual(c['peak_words'] % G, 0)
        self.assertGreaterEqual(c['peak_words'], 1010 * G)
        with self.assertRaises(ValueError):
            sweep.generate([s], device_bytes=500 * G * 4, reserve_bytes=0)

    def test_generate_never_mixes_allocator_modes(self):
        a = self.sweep_of([('leaf', KA, 100 * G, 10 * G, 0)], allocator='lifo', label='l')
        b = self.sweep_of([('leaf', KA, 60 * G, 10 * G, 0)], allocator='reuse', label='r')
        with self.assertRaises(ValueError):
            sweep.generate([a, b])
        p = sweep.generate([a, b], allocator='reuse', device_bytes=1 << 40, reserve_bytes=0, margin=0.0)
        self.assertEqual(p['gpu']['allocator'], 'reuse')
        self.assertEqual(p['classes'][0]['peak_words'], 60 * G)
        self.assertEqual(p['inputs']['sweeps'], ['r'])

    def test_check_catches_stale_claims(self):
        s = self.sweep_of([('leaf', KA, 1000 * G, 100 * G, 0), ('fold', KB, 400 * G, 300 * G, 0)])
        p = sweep.generate([s], device_bytes=1 << 40, reserve_bytes=0, margin=0.0)
        p['gpu']['arena_words'] -= G
        self.assertTrue(any('max_concurrent' in x for x in sweep.check(p)))


if __name__ == '__main__':
    unittest.main()
