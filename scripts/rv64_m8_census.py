#!/usr/bin/env python3
"""RV64 M8 census: one Nsight-profiled cold+warm service per block on the default path.

run      one `combined-serve` per block (cold + warm request), the canonical runner's
         service command (rv64_m7_integration_stack.command, preset `baseline` arm =
         default path) with `--nsys`; trace cuda,nvtx,osrt + CUDA graph node trace.
         Never wrap in flock gpu.lock: the harness takes the GPU lock per service.
analyze  warm-request window of one profiled service -> compact JSON: kernel GPU-s by
         family, top kernels with achieved DRAM bandwidth (bytes/launch from the
         kernel's buffer arguments are not in the trace, so bandwidth is reported only
         where a byte model exists), per-device busy union, idle gaps, CUDA API, OS
         runtime, memcpy/memset, NVTX GPU projection.

Labels: [M] measured from the trace, [D] derived. Profiled walls include profiler
overhead and are never headline numbers.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

M3 = Path('/workspace/m3')
DEV_BLOCKS = (26235156, 24628607)


def run(args):
    import rv64_m7_integration_stack as stack
    import rv64_m8_bench15 as bench
    assets = json.loads(args.assets.read_text())['assets']
    preset = json.loads(stack.DEFAULT_PRESET.read_text())
    root = HERE.parent
    stream = root.name
    rows = {r['block']: r for r in bench.basket()}
    environment = dict(stack.clean_environment(os.environ), TMPDIR=str(M3 / 'tmp'), RV64_NSYS_TRACE=args.trace)
    out = args.out
    out.mkdir(parents=True, exist_ok=True)
    for block in args.blocks:
        label = f'{args.tag}-{block}'
        manifest = {'source_root': str(root), 'assets': assets, 'block': block, 'preset': preset}
        argv, tag = stack.command(manifest, 'baseline', 0, stream, True, label)
        argv[argv.index('--repeat') + 1] = str(args.repeat)
        if block not in DEV_BLOCKS:
            argv.append('--bench-basket-block')
        argv += ['--quiet-mode', 'diagnostic', '--request-timeout', str(args.request_timeout)]
        for key, value in sorted(bench.block_environment(rows[block]).items()):
            argv += ['--env', f'{key}={value}']
        service = M3 / 'runs' / stream / f'daemon-{block}-r2-{tag}'
        record = {'block': block, 'run': str(service), 'argv': argv, 'trace': args.trace}
        with (out / f'{block}.log').open('w') as log:
            record['exit_code'] = subprocess.run(argv, cwd=root, env=environment, stdout=log, stderr=subprocess.STDOUT).returncode
        (out / f'{block}.json').write_text(json.dumps(record, indent=1) + '\n')
        if record['exit_code']:
            print(f'block {block} failed; see {out}/{block}.log', flush=True)
            if not args.keep_going:
                raise SystemExit(1)


# ----------------------------------------------------------------------------- analysis

FAMILIES = [  # first match wins; regex on the demangled kernel name (namespaces from src/backends/cuda/native)
    ('memcpy/memset', r'^\[(memcpy|memset)'),
    ('merkle/blake2s', r'blake2s::|merkle|poseidon|hash_leaves|hash_nodes|decommit'),
    ('pow grind', r'pow::'),
    ('quotients/oods/fri', r'deep_|sample_first|samples|fri_|quotient|oods'),
    ('circle fft/lde', r'transform::|n2b_|b2n_|lde|fft|twiddle|interpolat|composition_split'),
    ('gkr/sumcheck', r'rv64::layer<|batch_round|oracles_|close_layer|begin_layer|eq_expand|binding|gkr|projection_case|sumcheck'),
    ('logup/lookup', r'global_|scan_carries|scan_chunks|circuit_outer::cumulative|circuit_outer::generate|interaction|fraction|logup'),
    ('composition/constraints', r'truth_domain|stwo_rv64_composition_|joined_domain|lift_add|composition|constraint'),
    ('recursion assignment', r'circuit_fill::|assignment|om31|outer'),
    ('witness generation', r'witness|circuit_base::generate|bulk|analyze|capture|ingress'),
    ('transcript/channel', r'channel|draw|mix'),
]

SMS, REGS_PER_SM, WARPS_PER_SM, BLOCKS_PER_SM, SMEM_PER_SM = 170, 65536, 48, 32, 102400  # RTX 5090 (sm_120)


def occupancy(block, regs, smem):
    """[D] theoretical occupancy (resident warps / 48) from the launch shape; no counters on this pod."""
    warps = max(1, -(-block // 32))
    per_warp = -(-max(regs, 1) * 32 // 256) * 256
    limits = [BLOCKS_PER_SM, WARPS_PER_SM // warps, REGS_PER_SM // (per_warp * warps)]
    if smem:
        limits.append(SMEM_PER_SM // smem)
    blocks = max(0, min(limits))
    return blocks, round(blocks * warps / WARPS_PER_SM, 3)


def family(name):
    lower = name.lower()
    for fam, pattern in FAMILIES:
        if re.search(pattern, lower):
            return fam
    return 'other'


def union(intervals):
    total, gaps, last = 0, [], None
    for lo, hi in sorted(intervals):
        if last is None or lo > last:
            if last is not None:
                gaps.append((last, lo))
            total += hi - lo
            last = hi
        elif hi > last:
            total += hi - last
            last = hi
    return total, gaps


def gap_cause(db, names, dev, a, b):
    """[M] what surrounds one idle gap on device `dev`: the kernel that ended it / started after it, and the
    shortest host NVTX ranges (any thread) that cover the whole gap (= the host work the GPU waited on)."""
    def kernel(sql, t):
        row = db.execute(sql, (dev, t)).fetchone()
        return (names.get(row[0]) or '?')[:90] if row else None
    before = kernel('SELECT shortName FROM CUPTI_ACTIVITY_KIND_KERNEL WHERE deviceId = ? AND end <= ? ORDER BY end DESC LIMIT 1', a)
    after = kernel('SELECT shortName FROM CUPTI_ACTIVITY_KIND_KERNEL WHERE deviceId = ? AND start >= ? ORDER BY start LIMIT 1', b)
    covering = []
    try:
        for text, s0, e0 in db.execute('SELECT COALESCE(e.text, st.value), e.start, e.end FROM NVTX_EVENTS e LEFT JOIN StringIds st '
                                       'ON e.textId = st.id WHERE e.end IS NOT NULL AND e.start <= ? AND e.end >= ? '
                                       'ORDER BY e.end - e.start LIMIT 4', (a, b)):
            covering.append({'range': (text or '?')[:80], 'len_ms': round((e0 - s0) / 1e6, 1)})
    except sqlite3.OperationalError:
        pass
    return {'kernel_before': before, 'kernel_after': after, 'host_ranges_covering': covering}


def analyze(args):
    receipt = json.loads((args.run / 'receipt.json').read_text())
    request = receipt['requests'][args.request]
    db = sqlite3.connect(str(args.sqlite or args.run / 'nsys/timeline.sqlite'))
    epoch = db.execute('SELECT utcEpochNs FROM TARGET_INFO_SESSION_START_TIME').fetchone()[0]
    lo, hi = (t - epoch for t in request['utc_window_ns'])
    window = hi - lo
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    names = dict(db.execute('SELECT id, value FROM StringIds'))
    kernels = db.execute('SELECT deviceId, start, end, demangledName, shortName, gridX*gridY*gridZ, blockX*blockY*blockZ, '
                         'registersPerThread, staticSharedMemory+dynamicSharedMemory FROM CUPTI_ACTIVITY_KIND_KERNEL '
                         'WHERE end > ? AND start < ?', (lo, hi)).fetchall()
    per_device = {}
    fam = {}
    top = {}
    for dev, s, e, dn, sn, grid, block, regs, smem in kernels:
        s, e = max(s, lo), min(e, hi)
        per_device.setdefault(dev, []).append((s, e))
        name = names.get(sn) or names.get(dn) or '?'
        full = names.get(dn) or name
        f = family(full)
        fam.setdefault(f, [0, 0])
        fam[f][0] += e - s
        fam[f][1] += 1
        t = top.setdefault(name, {'family': f, 'ns': 0, 'launches': 0, 'grid': grid, 'block': block, 'regs': regs, 'smem': smem,
                                  'demangled': full[:200]})
        t['ns'] += e - s
        t['launches'] += 1
    copies = []
    if 'CUPTI_ACTIVITY_KIND_MEMCPY' in tables:
        kinds = {1: 'HtoD', 2: 'DtoH', 8: 'DtoD', 10: 'PtoP'}
        for dev, s, e, nbytes, kind in db.execute('SELECT deviceId, start, end, bytes, copyKind FROM CUPTI_ACTIVITY_KIND_MEMCPY WHERE end > ? AND start < ?', (lo, hi)):
            copies.append(('memcpy ' + kinds.get(kind, str(kind)), dev, max(s, lo), min(e, hi), nbytes))
    if 'CUPTI_ACTIVITY_KIND_MEMSET' in tables:
        for dev, s, e, nbytes in db.execute('SELECT deviceId, start, end, bytes FROM CUPTI_ACTIVITY_KIND_MEMSET WHERE end > ? AND start < ?', (lo, hi)):
            copies.append(('memset', dev, max(s, lo), min(e, hi), nbytes))
    copy_summary = {}
    for kind, dev, s, e, nbytes in copies:
        c = copy_summary.setdefault(kind, {'ns': 0, 'count': 0, 'bytes': 0})
        c['ns'] += e - s
        c['count'] += 1
        c['bytes'] += nbytes
        per_device.setdefault(dev, []).append((s, e))
    kernel_ns = sum(v[0] for v in fam.values())
    devices = {}
    for dev, intervals in sorted(per_device.items()):
        busy, gaps = union(intervals)
        kbusy, _ = union([(s, e) for d, s, e, *_ in kernels if d == dev and True])
        gaps = [(a, b) for a, b in gaps if b - a >= args.gap_ns]
        first = min(s for s, _ in intervals)
        last = max(e for _, e in intervals)
        devices[str(dev)] = {'busy_union_s': round(busy / 1e9, 4), 'busy_fraction_of_window': round(busy / window, 4),
                             'first_activity_s': round((first - lo) / 1e9, 4), 'last_activity_s': round((last - lo) / 1e9, 4),
                             'lead_idle_s': round((first - lo) / 1e9, 4), 'tail_idle_s': round((hi - last) / 1e9, 4),
                             'idle_gaps_ge_threshold': {'count': len(gaps), 'sum_s': round(sum(b - a for a, b in gaps) / 1e9, 4),
                                                        'largest': [dict({'at_s': round((a - lo) / 1e9, 3), 'len_ms': round((b - a) / 1e6, 2)},
                                                                         **gap_cause(db, names, dev, a, b))
                                                                    for a, b in sorted(gaps, key=lambda g: g[0] - g[1])[:12]]}}
    runtime = {}
    for name_id, n, total, mx in db.execute('SELECT nameId, COUNT(*), SUM(end-start), MAX(end-start) FROM CUPTI_ACTIVITY_KIND_RUNTIME '
                                            'WHERE end > ? AND start < ? GROUP BY nameId', (lo, hi)):
        runtime[names.get(name_id, str(name_id))] = {'count': n, 'sum_s': round(total / 1e9, 4), 'max_ms': round(mx / 1e6, 3)}
    osrt = {}
    if 'OSRT_API' in tables:
        for name_id, n, total, mx in db.execute('SELECT nameId, COUNT(*), SUM(end-start), MAX(end-start) FROM OSRT_API '
                                                'WHERE end > ? AND start < ? GROUP BY nameId', (lo, hi)):
            osrt[names.get(name_id, str(name_id))] = {'count': n, 'sum_s': round(total / 1e9, 4), 'max_ms': round(mx / 1e6, 3)}
    nvtx = {}
    if 'NVTX_EVENTS' in tables:
        for text, n, total, mx in db.execute('SELECT COALESCE(text, s.value), COUNT(*), SUM(e.end-e.start), MAX(e.end-e.start) FROM NVTX_EVENTS e '
                                             'LEFT JOIN StringIds s ON e.textId = s.id WHERE e.end > ? AND e.start < ? AND e.end IS NOT NULL '
                                             'GROUP BY 1', (lo, hi)):
            nvtx[text] = {'count': n, 'cpu_sum_s': round((total or 0) / 1e9, 4), 'cpu_max_ms': round((mx or 0) / 1e6, 3)}
    nvtx_gpu = {}
    if 'NVTX_EVENTS' in tables:
        # [M] GPU projection: each kernel/memcpy is attributed to the innermost NVTX push/pop range open on its
        # launching thread at launch time (same rule as nsys nvtx_gpu_proj_sum, restricted to this request window).
        ranges = {}
        for tid, s0, e0, text in db.execute('SELECT e.globalTid, e.start, e.end, COALESCE(e.text, st.value) FROM NVTX_EVENTS e '
                                            'LEFT JOIN StringIds st ON e.textId = st.id WHERE e.end IS NOT NULL AND e.end > ? AND e.start < ? '
                                            'AND e.eventType = 59', (lo - 60_000_000_000, hi)):
            ranges.setdefault(tid, []).append((s0, e0, text))
        for tid in ranges:
            ranges[tid].sort()
        import bisect
        starts = {tid: [r[0] for r in v] for tid, v in ranges.items()}
        ops = db.execute('SELECT r.globalTid, r.start, k.start, k.end FROM CUPTI_ACTIVITY_KIND_KERNEL k JOIN CUPTI_ACTIVITY_KIND_RUNTIME r '
                         'ON k.correlationId = r.correlationId WHERE k.end > ? AND k.start < ?', (lo, hi)).fetchall()
        for tid, launch, s0, e0 in ops:
            label = '(no range)'
            if tid in ranges:
                i = bisect.bisect_right(starts[tid], launch) - 1
                best = None
                while i >= 0:
                    rs, re_, text = ranges[tid][i]
                    if re_ >= launch:
                        best = text
                        break
                    i -= 1
                    if launch - rs > 120_000_000_000:
                        break
                if best:
                    label = best
            v = nvtx_gpu.setdefault(label, [0, 0])
            v[0] += min(e0, hi) - max(s0, lo)
            v[1] += 1
        nvtx_gpu = {k: {'kernel_gpu_s': round(v[0] / 1e9, 4), 'kernels': v[1]} for k, v in sorted(nvtx_gpu.items(), key=lambda x: -x[1][0])}
    families = {f: {'gpu_s': round(ns / 1e9, 4), 'pct': round(100 * ns / kernel_ns, 2) if kernel_ns else 0, 'launches': n}
                for f, (ns, n) in sorted(fam.items(), key=lambda x: -x[1][0])}
    top_list = sorted(top.items(), key=lambda x: -x[1]['ns'])[:args.top]
    result = {'schema': 'rv64-m8-census-warm/v1', 'run': str(args.run), 'block': request['block'], 'ordinal': request['ordinal'],
              'label': 'M (profiled; walls include Nsight overhead)', 'window_s': round(window / 1e9, 4),
              'request_wall_s': round(request['marker']['request_wall_ns'] / 1e9, 4), 'stages': request.get('stages'),
              'kernel_gpu_s': round(kernel_ns / 1e9, 4), 'kernel_launches': len(kernels), 'families': families,
              'top_kernels': [dict(name=n[:120], gpu_s=round(v['ns'] / 1e9, 4), pct=round(100 * v['ns'] / kernel_ns, 2),
                                   mean_us=round(v['ns'] / v['launches'] / 1e3, 2), **{k: v[k] for k in ('family', 'launches', 'grid', 'block', 'regs', 'smem')},
                                   theoretical_occupancy=occupancy(v['block'], v['regs'], v['smem'])[1],
                                   waves=round(v['grid'] / (SMS * max(1, occupancy(v['block'], v['regs'], v['smem'])[0])), 2),
                                   demangled=v['demangled'])
                              for n, v in top_list],
              'copies': {k: dict(v, gpu_s=round(v['ns'] / 1e9, 4), gb_per_s=round(v['bytes'] / v['ns'], 2) if v['ns'] else None) for k, v in copy_summary.items()},
              'devices': devices, 'cuda_api': dict(sorted(runtime.items(), key=lambda x: -x[1]['sum_s'])[:25]),
              'osrt': dict(sorted(osrt.items(), key=lambda x: -x[1]['sum_s'])[:20]), 'nvtx_cpu': nvtx, 'nvtx_gpu_projection': nvtx_gpu}
    args.out.write_text(json.dumps(result, indent=1) + '\n')
    print(json.dumps({k: result[k] for k in ('block', 'window_s', 'kernel_gpu_s', 'kernel_launches', 'families')}, indent=1))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='mode', required=True)
    r = sub.add_parser('run')
    r.add_argument('--assets', required=True, type=Path)
    r.add_argument('--blocks', required=True, type=int, nargs='+')
    r.add_argument('--tag', required=True)
    r.add_argument('--out', required=True, type=Path)
    r.add_argument('--trace', default='cuda,nvtx,osrt')
    r.add_argument('--request-timeout', type=float, default=600)
    r.add_argument('--keep-going', action='store_true')
    r.add_argument('--repeat', type=int, default=2)
    a = sub.add_parser('analyze')
    a.add_argument('--run', required=True, type=Path)
    a.add_argument('--sqlite', type=Path)
    a.add_argument('--request', type=int, default=1, help='request ordinal (1 = warm)')
    a.add_argument('--gap-ns', type=int, default=1_000_000)
    a.add_argument('--top', type=int, default=30)
    a.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    (run if args.mode == 'run' else analyze)(args)


if __name__ == '__main__':
    main()
