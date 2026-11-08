#!/usr/bin/env python3
"""M8 memory-plan sweep and per-class policy generator (spec §3.7, frontier-delta §4 item 3).

Measure: run each job-class harness (a binary or test that drives a real DeviceWorker) with
STWO_RV64_M8_JOBS_PLAN_DIR=<dir>; every Worker.destroy writes worker-*.json there (schema
rv64-m8-jobs-class-plans/v2: per class and per side the arena peak, live peak, staged, slab,
pinned, persistent words, declared footprint). `collect` folds those files into one sweep record.

Generate: `generate` turns sweep records into the committed policy (schema
rv64-m8-jobs-memory-policy/v1) that a worker consumes at start (STWO_RV64_M8_JOBS_PLAN):
  * class peak   = max measured arena peak over runs and sides, times (1 + margin), granule-aligned;
  * class staged = max measured staged inputs;
  * arena        = the smallest arena in which every class works beside every class's staged inputs
                   (Airbender two-sided static arena), capped by the device budget; classes that do
                   not fit beside the largest staged input in the capped arena get max_concurrent 1;
  * persistent budget = sum of the classes' persistent regions (all warm), capped;
  * allocator    = the mode the sweep measured (a policy never mixes lifo and reuse measurements).

`check` re-verifies a policy's pairwise claims (the Zig test plan_test.zig does the same through the
worker's real Arena). Memory layout only: nothing here can change proof bytes.

Subcommands:
  run      --spec spec.json --out DIR           run harnesses (pod), collect each into DIR/<label>/sweep.json
  collect  --dir PLANDIR --label L [--class KEY=NAME ...] [--harness TEXT] --out sweep.json
  generate --sweep a.json [b.json ...] --out policy.json [--device-bytes N] [--reserve-bytes N]
           [--margin F] [--allocator lifo|reuse] [--persistent-cap-words N] [--unplanned declared|refuse]
  check    --policy policy.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

GRANULE = 64
STATE_GRANULE = GRANULE
PLAN_SCHEMAS = ('rv64-m8-jobs-class-plans/v1', 'rv64-m8-jobs-class-plans/v2')
SWEEP_SCHEMA = 'rv64-m8-memory-plan-sweep/v1'
POLICY_SCHEMA = 'rv64-m8-jobs-memory-policy/v1'
# RTX 5090: 32 GiB. Reserve covers the CUDA context, the worker's pinned-free
# device state, cuBLAS-free kernels' static data and the frozen image's own
# resident tables; the real figure is a sweep input, never hard-wired below.
DEFAULT_DEVICE_BYTES = 32 * (1 << 30)
DEFAULT_RESERVE_BYTES = 2 * (1 << 30)


def align(words: int) -> int:
    return -(-int(words) // GRANULE) * GRANULE


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------- collect

def _side(stat: dict, i: int) -> dict:
    sides = stat.get('sides')
    if sides and len(sides) == 2:
        return sides[i]
    return {}


def fold_rows(files: list[tuple[str, dict]], labels: dict[str, str], default_label: str | None = None,
              only_labeled: bool = False) -> tuple[list[dict], str, dict]:
    """Merge worker plan rows into one row per class (max over workers/runs).

    only_labeled: keep only classes named in `labels` (a test binary also runs
    host-model workers whose rows are not job classes)."""
    classes: dict[str, dict] = {}
    allocators = set()
    persistent = {'budget_words': 0, 'high_water_words': 0, 'evictions': 0, 'unbudgeted_regions': 0}
    for _, doc in files:
        if doc.get('schema') not in PLAN_SCHEMAS:
            raise ValueError(f"unexpected plan schema {doc.get('schema')!r}")
        rows_in = [r for r in doc.get('classes', []) if not only_labeled or r['class_key'] in labels]
        if only_labeled and not rows_in:
            continue  # a worker that ran none of the swept classes (e.g. a host-model test)
        allocators.add(doc.get('allocator', 'lifo'))
        p = doc.get('persistent') or {}
        for k in persistent:
            persistent[k] = max(persistent[k], int(p.get(k, 0)))
        for row in rows_in:
            key = row['class_key']
            s = row['stat']
            c = classes.setdefault(key, {
                'label': labels.get(key, default_label or f'class-{key[:8]}'), 'class_key': key, 'jobs': 0, 'devices': [],
                'declared_device_words': 0, 'declared_staged_words': 0, 'declared_pinned_words': 0,
                'declared_peak_words': 0, 'slab_words': 0, 'pinned_words': 0, 'persistent_words': 0,
                'over_plan': 0, 'serialized': 0, 'planned_peak_words': 0,
                'sides': [{'jobs': 0, 'peak_arena_words': 0, 'live_peak_words': 0, 'staged_words': 0,
                           'peak_alloc': 0, 'peak_alloc_words': 0, 'allocs': 0} for _ in range(2)],
                'stage_ns': 0, 'enqueue_ns': 0, 'wait_ns': 0,
            })
            c['jobs'] += int(s.get('jobs', 0))
            if row.get('device') not in c['devices']:
                c['devices'].append(row.get('device'))
            for k in ('declared_device_words', 'declared_staged_words', 'declared_pinned_words',
                      'declared_peak_words', 'slab_words', 'persistent_words', 'planned_peak_words'):
                c[k] = max(c[k], int(s.get(k, 0)))
            c['pinned_words'] = max(c['pinned_words'], int(s.get('peak_pinned_words', 0)))
            for k in ('over_plan', 'serialized', 'stage_ns', 'enqueue_ns', 'wait_ns'):
                c[k] += int(s.get(k, 0))
            if 'sides' not in s:  # v1 rows: no per-side split, attribute to both
                for d in c['sides']:
                    d['peak_arena_words'] = max(d['peak_arena_words'], int(s.get('peak_arena_words', 0)))
                    d['staged_words'] = max(d['staged_words'], int(s.get('staged_words', 0)))
                continue
            for i in range(2):
                src, dst = _side(s, i), c['sides'][i]
                dst['jobs'] += int(src.get('jobs', 0))
                if int(src.get('peak_arena_words', 0)) >= dst['peak_arena_words']:
                    dst['peak_arena_words'] = int(src.get('peak_arena_words', 0))
                    dst['peak_alloc'] = int(src.get('peak_alloc', 0))
                    dst['peak_alloc_words'] = int(src.get('peak_alloc_words', 0))
                for k in ('live_peak_words', 'staged_words', 'allocs'):
                    dst[k] = max(dst[k], int(src.get(k, 0)))
    if len(allocators) > 1:
        raise ValueError(f'plan files mix allocator modes {sorted(allocators)}; sweep each mode separately')
    rows = []
    for c in classes.values():
        c['peak_arena_words'] = max(d['peak_arena_words'] for d in c['sides'])
        c['live_peak_words'] = max(d['live_peak_words'] for d in c['sides'])
        c['staged_words'] = max(d['staged_words'] for d in c['sides'])
        c['lifo_waste_words'] = c['peak_arena_words'] - c['live_peak_words'] if c['live_peak_words'] else 0
        c['declared_over_measured'] = (round(c['declared_peak_words'] / c['peak_arena_words'], 4)
                                       if c['peak_arena_words'] else None)
        rows.append(c)
    rows.sort(key=lambda r: (r['label'], r['class_key']))
    return rows, (allocators.pop() if allocators else 'lifo'), persistent


def collect(plan_dir: Path, label: str, labels: dict[str, str], harness: str = '', default_label: str | None = None,
            only_labeled: bool = False) -> dict:
    files = []
    for path in sorted(plan_dir.glob('*.json')):
        files.append((path.name, json.loads(path.read_text())))
    if not files:
        raise ValueError(f'no worker plan files in {plan_dir}')
    rows, allocator, persistent = fold_rows(files, labels, default_label, only_labeled)
    if not rows:
        raise ValueError(f'no swept class rows in {plan_dir}')
    return {
        'schema': SWEEP_SCHEMA, 'label': label, 'harness': harness, 'allocator': allocator,
        'label_kind': '[M]', 'persistent': persistent,
        'sources': [{'file': n, 'sha256': hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()}
                    for n, d in files],
        'classes': rows,
    }


# ---------------------------------------------------------------- generate

def pair_fits(arena: int, resident_peak: int, next_staged: int) -> bool:
    return resident_peak <= arena and next_staged <= arena - resident_peak


def generate(sweeps: list[dict], *, device_bytes: int = DEFAULT_DEVICE_BYTES,
             reserve_bytes: int = DEFAULT_RESERVE_BYTES, margin: float = 0.02,
             allocator: str | None = None, persistent_cap_words: int | None = None,
             unplanned: str = 'declared') -> dict:
    if not sweeps:
        raise ValueError('generate needs at least one sweep')
    modes = {s['allocator'] for s in sweeps}
    if allocator is None:
        if len(modes) != 1:
            raise ValueError(f'sweeps mix allocator modes {sorted(modes)}; pass --allocator')
        allocator = modes.pop()
    sweeps = [s for s in sweeps if s['allocator'] == allocator]
    if not sweeps:
        raise ValueError(f'no sweep measured allocator={allocator}')
    merged: dict[str, dict] = {}
    for s in sweeps:
        for c in s['classes']:
            m = merged.setdefault(c['class_key'], {'label': c['label'], 'class_key': c['class_key'], 'peak': 0,
                                                   'staged': 0, 'slab': 0, 'pinned': 0, 'persistent': 0,
                                                   'declared_peak': 0, 'jobs': 0, 'sweeps': []})
            m['peak'] = max(m['peak'], int(c['peak_arena_words']))
            m['staged'] = max(m['staged'], int(c['staged_words']))
            m['slab'] = max(m['slab'], int(c['slab_words']))
            m['pinned'] = max(m['pinned'], int(c['pinned_words']))
            m['persistent'] = max(m['persistent'], int(c['persistent_words']))
            m['declared_peak'] = max(m['declared_peak'], int(c.get('declared_peak_words', 0)))
            m['jobs'] += int(c['jobs'])
            m['sweeps'].append(s['label'])
    classes = []
    for m in merged.values():
        if m['peak'] == 0:
            raise ValueError(f"class {m['label']} has no measured peak")
        floor = m['staged'] + STATE_GRANULE + align(m['slab'])
        peak = max(align(math.ceil(m['peak'] * (1.0 + margin))), align(floor))
        classes.append({
            'label': m['label'], 'class_key': m['class_key'], 'peak_words': peak, 'staged_words': align(m['staged']),
            'slab_words': m['slab'], 'pinned_words': m['pinned'], 'persistent_words': m['persistent'],
            'max_concurrent': 2, 'measured_peak_words': m['peak'], 'declared_peak_words': m['declared_peak'],
            'jobs': m['jobs'], 'sweeps': sorted(set(m['sweeps'])),
        })
    classes.sort(key=lambda c: (c['label'], c['class_key']))
    persistent = sum(align(c['persistent_words']) for c in classes)
    if persistent_cap_words is not None:
        persistent = min(persistent, align(persistent_cap_words))
    budget = (int(device_bytes) - int(reserve_bytes)) // 4
    budget -= budget % GRANULE
    arena_budget = budget - persistent
    biggest_peak = max(c['peak_words'] for c in classes)
    if biggest_peak > arena_budget:
        big = max(classes, key=lambda c: c['peak_words'])
        raise ValueError(f"class {big['label']} peak {biggest_peak} words exceeds the arena budget {arena_budget}")
    max_staged = max(c['staged_words'] for c in classes)
    want = max(c['peak_words'] + max_staged for c in classes)  # every class beside the largest staged input
    arena = min(align(want), arena_budget)
    for c in classes:
        c['max_concurrent'] = 2 if all(pair_fits(arena, c['peak_words'], d['staged_words']) for d in classes) else 1
    concurrent = 2 if all(c['max_concurrent'] == 2 for c in classes) else 1
    # Measured pinned use already includes the slab's host mirror (Worker.pinnedAlloc).
    pinned_slot = align(max(c['pinned_words'] for c in classes) * (1.0 + margin))
    if persistent and any(align(c['persistent_words']) > persistent for c in classes):
        raise ValueError('a class persistent region exceeds the persistent budget')
    return {
        'schema': POLICY_SCHEMA,
        'generator': 'scripts/rv64/rv64_m8_plan_sweep.py generate',
        'label_kind': '[D] from [M] sweeps',
        'inputs': {'margin': margin, 'device_bytes': int(device_bytes), 'reserve_bytes': int(reserve_bytes),
                   'sweeps': [s['label'] for s in sweeps]},
        'gpu': {
            'arena_words': arena, 'persistent_budget_words': persistent, 'max_concurrent_jobs': concurrent,
            'max_outstanding': 3, 'allocator': allocator, 'device_budget_words': budget,
            'pinned_slot_words': pinned_slot,
        },
        'unplanned': unplanned,
        'classes': classes,
    }


def check(policy: dict) -> list[str]:
    """Pairwise claims of a policy; returns problems (empty = ok)."""
    problems = []
    if policy.get('schema') != POLICY_SCHEMA:
        problems.append(f"schema {policy.get('schema')!r}")
    g = policy['gpu']
    arena = int(g['arena_words'])
    if arena % GRANULE:
        problems.append('arena not granule aligned')
    cs = policy['classes']
    for c in cs:
        if c['peak_words'] % GRANULE or c['staged_words'] % GRANULE:
            problems.append(f"{c['label']}: unaligned")
        if c['peak_words'] > arena:
            problems.append(f"{c['label']}: peak exceeds arena")
        if c['peak_words'] < c['staged_words'] + STATE_GRANULE + align(c.get('slab_words', 0)):
            problems.append(f"{c['label']}: peak below its parts")
        if g.get('pinned_slot_words') and c.get('pinned_words', 0) > g['pinned_slot_words']:
            problems.append(f"{c['label']}: pinned use exceeds the pinned slot")
        fits_all = all(pair_fits(arena, c['peak_words'], d['staged_words']) for d in cs)
        if (c['max_concurrent'] == 2) != fits_all:
            problems.append(f"{c['label']}: max_concurrent {c['max_concurrent']} but fits_all={fits_all}")
    if (g['max_concurrent_jobs'] == 2) != all(c['max_concurrent'] == 2 for c in cs):
        problems.append('gpu.max_concurrent_jobs disagrees with the classes')
    return problems


# ---------------------------------------------------------------- run (pod)

def run_spec(spec: dict, out: Path) -> list[Path]:
    """spec = {"harnesses": [{"label", "argv", "env": {}, "cwd", "classes": {hex: name}, "default_label",
    "only_labeled", "timeout_s", "measure_with_policy"}]}. The policy env is dropped unless measure_with_policy
    (a validation run of a generated policy)."""
    written = []
    for h in spec['harnesses']:
        label = h['label']
        d = out / label
        plans = d / 'plans'
        if d.exists():
            raise ValueError(f'{d} exists: use a fresh --out (unique run dirs)')
        plans.mkdir(parents=True)
        env = dict(os.environ)
        env.update({k: str(v) for k, v in (h.get('env') or {}).items()})
        env['STWO_RV64_M8_JOBS_PLAN_DIR'] = str(plans)
        if not h.get('measure_with_policy'):
            env.pop('STWO_RV64_M8_JOBS_PLAN', None)  # measure with declared footprints
        t0 = time.time()
        with open(d / 'log.txt', 'wb') as log:
            rc = subprocess.run(h['argv'], cwd=h.get('cwd'), env=env, stdout=log, stderr=subprocess.STDOUT,
                                timeout=h.get('timeout_s', 1800)).returncode
        meta = {'label': label, 'argv': h['argv'], 'env': h.get('env') or {}, 'rc': rc,
                'wall_s': round(time.time() - t0, 3), 'log_sha256': sha256(d / 'log.txt')}
        (d / 'run.json').write_text(json.dumps(meta, indent=1))
        if rc != 0:
            raise RuntimeError(f'harness {label} exited {rc} (log {d / "log.txt"})')
        sweep = collect(plans, label, h.get('classes') or {}, harness=' '.join(h['argv']),
                        default_label=h.get('default_label'), only_labeled=bool(h.get('only_labeled')))
        sweep['run'] = meta
        (d / 'sweep.json').write_text(json.dumps(sweep, indent=1))
        written.append(d / 'sweep.json')
    return written


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--spec', type=Path, required=True)
    r.add_argument('--out', type=Path, required=True)
    c = sub.add_parser('collect')
    c.add_argument('--dir', type=Path, required=True)
    c.add_argument('--label', required=True)
    c.add_argument('--class', dest='classes', action='append', default=[], metavar='KEY=NAME')
    c.add_argument('--harness', default='')
    c.add_argument('--out', type=Path, required=True)
    g = sub.add_parser('generate')
    g.add_argument('--sweep', type=Path, action='append', required=True)
    g.add_argument('--out', type=Path, required=True)
    g.add_argument('--device-bytes', type=int, default=DEFAULT_DEVICE_BYTES)
    g.add_argument('--reserve-bytes', type=int, default=DEFAULT_RESERVE_BYTES)
    g.add_argument('--margin', type=float, default=0.02)
    g.add_argument('--allocator', choices=['lifo', 'reuse'])
    g.add_argument('--persistent-cap-words', type=int)
    g.add_argument('--unplanned', choices=['declared', 'refuse'], default='declared')
    k = sub.add_parser('check')
    k.add_argument('--policy', type=Path, required=True)
    a = p.parse_args(argv)
    if a.cmd == 'run':
        for path in run_spec(json.loads(a.spec.read_text()), a.out):
            print(path)
    elif a.cmd == 'collect':
        labels = dict(x.split('=', 1) for x in a.classes)
        a.out.write_text(json.dumps(collect(a.dir, a.label, labels, a.harness), indent=1))
    elif a.cmd == 'generate':
        policy = generate([json.loads(x.read_text()) for x in a.sweep], device_bytes=a.device_bytes,
                          reserve_bytes=a.reserve_bytes, margin=a.margin, allocator=a.allocator,
                          persistent_cap_words=a.persistent_cap_words, unplanned=a.unplanned)
        problems = check(policy)
        if problems:
            raise SystemExit('generated policy fails its own check: ' + '; '.join(problems))
        a.out.write_text(json.dumps(policy, indent=1) + '\n')
    else:
        problems = check(json.loads(a.policy.read_text()))
        for x in problems:
            print('PROBLEM', x)
        if problems:
            return 1
        print('OK')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
