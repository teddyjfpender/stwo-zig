#!/usr/bin/env python3
"""RV64 M8 15-block benchmark: one command, the M3 basket, the final M8 path.

Seed of the post-M8 repeatable benchmark set (`bench --tier smoke|dev|basket`).
It drives the canonical interleaved runner's service command
(`rv64_m7_integration_stack.command`, the same one `rv64_gate.py` uses), so
every arm runs the frozen preset's `baseline` environment plus an arm overlay
of `STWO_RV64_M8_*` flags. Nothing here changes a proof byte.

Subcommands (run on the pod from /workspace/m3/src/<stream>, never wrapped in
`flock gpu.lock`: the harness takes the GPU lock per service itself):

  pin       freeze driver/receiver/CUDA image/addons into assets.json (sha256)
  check     inventory every input the basket needs (paths, sizes, sha256),
            report anything missing and how to regenerate it; no GPU
  estimate  wall-time estimate per arm [E]; no GPU
  run       the benchmark (or --smoke: one small block, short GPU use)
  report    rebuild bench15.json + bench15.md from the per-block receipts

Per block, in ascending M3 request time, stopping on the first failure
(owner rule: never loop the basket blind; scale one block at a time):

  1. headline services, interleaved over arms (A B C A B C ...), each a fresh
     `combined-serve` with a cold and a warm request, quiet gate enforced;
  2. byte parity: every request of every arm == the block's first proof
     (and == the frozen D2 golden on the two dev blocks);
  3. fresh CPU receivers on the retained reference proofs, after all timing;
  4. one Nsight-profiled service per arm (`--profile warm`) for kernel
     GPU-seconds (CUPTI union) and launches/syncs; never in headline medians;
  5. prune: proof payloads and Nsight files of every service are deleted
     once checked, so a block needs about one service of disk at a time.

Timing boundary (Ethproofs): `proving_s` is the service's request wall
(input bytes in, capture = witness generation, native, recursion, root
published); it excludes fetch and submit. `request_s` is the client latency
through the spool (adds queueing). Labels: [M] measured, [D] derived from
measured values, [E] estimate.
"""
import argparse
import fcntl
import gzip
import json
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import rv64_m7_integration_stack as stack  # noqa: E402

M3 = Path(os.environ.get('RV64_M3_ROOT', '/workspace/m3'))
GPU_LOCK = M3 / 'locks/gpu.lock'
M3_SUMMARY = ROOT / 'vectors/reports/rv64-m3-20261104/summary.json'
GOLDEN = ROOT / 'vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package'
RUNTIME = ROOT / 'design/riscv-proving-stack/m7-handoff/p0-runtime.json'
DEV_BLOCKS = (26235156, 24628607)
SMOKE_BLOCK = 26235156
DEVICES = 2
WORD_BYTES = 4  # M31 words
SCHEMA = 'rv64-m8-bench15/v1'

# M7 headline baselines; only these blocks were measured on the M7 default.
M7_BASELINE = {
    24628607: {'warm_proving_s': 12.9, 'label': 'M', 'note': 'M7 default warm, single profiled run',
               'source': 'design/riscv-proving-stack/rv64-m8-engineering-scope.md §1'},
    26235156: {'warm_proving_s': 10.5, 'label': 'M', 'note': 'M7 default warm',
               'source': 'design/riscv-proving-stack/rv64-m8-engineering-scope.md §1'},
    24697070: {'cold_proving_s': 69.871, 'label': 'M', 'note': 'M7 cold scale probe, one request',
               'source': 'vectors/reports/rv64-m7-20261105/callback-residency/README.md'},
}

# Arm overlays on the preset's baseline environment. {addon}/{outer_fs} are
# assets.json paths. PINNED_BYTES is the outer-fold gate value (c72b51646,
# outer-fold-review/gates.json: PASS on both dev blocks).
OUTER = {'STWO_RV64_M8_OUTER_JOBS': '1', 'STWO_RV64_M8_JOBS_LIBRARY': '{addon}',
         'STWO_RV64_M8_OUTER_FS_LIBRARY': '{outer_fs}', 'STWO_RV64_M8_JOBS_PINNED_BYTES': '2365587456'}
NATIVE = {'STWO_RV64_M8_NATIVE_JOBS': '1', 'STWO_RV64_M8_JOBS_LIBRARY': '{addon}'}
ARMS = {
    'default': {},
    'outer': OUTER,
    'native': NATIVE,
    'hybrid': dict(OUTER, **NATIVE),
    'jobs': {'STWO_RV64_M8_JOBS': '1', 'STWO_RV64_M8_JOBS_LIBRARY': '{addon}',
             'STWO_RV64_M8_OUTER_FS_LIBRARY': '{outer_fs}', 'STWO_RV64_M8_JOBS_PINNED_BYTES': '2365587456'},
    # The GPU-native request path (m8-gpu gate-10 env): fails closed at install today (GpuNativeNativeShapeHookMissing).
    'gpu-native': {'STWO_RV64_M8_JOBS': '1', 'STWO_RV64_M8_GPU_NATIVE': '1', 'STWO_RV64_M8_JOBS_LIBRARY': '{addon}'},
}
ASSET_NAMES = ('driver', 'receiver', 'library', 'sparse', 'observer', 'process_budget_guard', 'addon', 'outer_fs')
# M3 found blocks with >= 40 CPU segments OOM in resident composition unless the
# idle upper-PCS cache is released (proof-neutral; rv64-m3-20261104/SUMMARY.md).
LARGE_SEGMENTS = 40


# ----------------------------------------------------------------------------- basket

def basket(summary=None):
    """The 15 M3 blocks, ascending M3 request time, with their M3 [M] row."""
    data = summary if summary is not None else json.loads(M3_SUMMARY.read_text())
    rows = sorted(data['rows'], key=lambda r: r['request_s'])
    if len(rows) != 15 or data['totals']['request_s_sum_15'] != 1843.0:
        raise RuntimeError('M3 basket summary changed: expected 15 rows summing to 1843 s')
    return rows


def block_environment(row):
    return {'STWO_RV64_PCS_IDLE_CACHE_BYTES': '0'} if row['cpu_segments'] >= LARGE_SEGMENTS else {}


def arm_environment(name, assets):
    if name not in ARMS:
        raise ValueError(f'unknown arm {name!r}; choose from {", ".join(ARMS)}')
    return {key: value.format(**assets) for key, value in ARMS[name].items()}


# ----------------------------------------------------------------------------- parsing (pure)

FIELD = re.compile(r'(\w+)=(\{[^}]*\}|\S+)')
JOB_LINES = {  # kind -> (stderr tag, required field); the trailing space keeps NODE apart from NODE_HOST/NODE_MEM
    'outer_node': ('GPU_M8_OUTER_NODE ', 'ordinal'),
    'outer_fixed': ('GPU_M8_OUTER_FIXED ', 'ordinal'),
    'native_stage': ('GPU_M8_NATIVE_HYBRID ', 'stage'),  # event= lines (boot, replay, failures) are not jobs
}
REQUEST_MARK = 'GPU_RESIDENT_BLOCK '


def fields(body):
    out = {}
    for key, value in FIELD.findall(body):
        out[key] = int(value) if re.fullmatch(r'-?\d+', value) else (float(value) if re.fullmatch(r'-?\d+\.\d+', value) else value)
    return out


def split_requests(text):
    """Producer stderr lines per request: each request ends at its GPU_RESIDENT_BLOCK marker."""
    out, current = [], []
    for line in text.splitlines():
        current.append(line)
        if REQUEST_MARK in line:
            out.append(current)
            current = []
    return out


def spread(values):
    values = [v for v in values if isinstance(v, (int, float))]
    if not values:
        return None
    return {'n': len(values), 'sum': sum(values), 'max': max(values), 'median': statistics.median(values)}


def job_metrics(lines):
    """Per-job receipts the M8 job path prints (outer nodes, FIXED precommits, native stages)."""
    out = {}
    for kind, (tag, required) in JOB_LINES.items():
        rows = []
        for line in lines:
            at = line.find(tag)
            if at < 0:
                continue
            row = fields(line[at + len(tag):])
            if required not in row:
                continue
            if 'gpu_ms' in row and 'gpu_ns' not in row:
                row['gpu_ns'] = round(float(row['gpu_ms']) * 1e6)
            rows.append(row)
        if rows:
            peak = spread([r.get('arena_peak_words') for r in rows])
            out[kind] = {'count': len(rows), 'launches': spread([r.get('launches') for r in rows]),
                         'host_waits': spread([r.get('host_waits') for r in rows]),
                         'gpu_s': (lambda s: s and round(s['sum'] / 1e9, 4))(spread([r.get('gpu_ns') for r in rows])),
                         'peak_bytes': peak and peak['max'] * WORD_BYTES}
    return out


def request_metrics(request, combined, lines):
    """One served request: walls [M], critical-path stages [M], tail [D], job receipts [M]."""
    ns = lambda key: combined.get(key)
    s = lambda value: None if value is None else round(value / 1e9, 4)
    proving = request['marker']['request_wall_ns']
    parts = [ns('capture_ns'), ns('native_setup_ns'), ns('native_prove_ns'), ns('recursion_after_native_ns')]
    recursive = combined.get('recursive') or {}
    nodes = (recursive.get('leaf_proofs') or 0) + (recursive.get('fold_proofs') or 0)
    return {'ordinal': request['ordinal'], 'proving_s': s(proving), 'request_s': s(request['client_latency_ns']),
            'capture_s': s(parts[0]), 'setup_s': s(parts[1]), 'native_window_s': s(parts[2]),
            'recursion_after_native_s': s(parts[3]),
            'tail_s': s(proving - sum(parts)) if None not in parts else None,
            'nodes': nodes or None, 'root_proof_bytes': recursive.get('root_proof_bytes'),
            'jobs': job_metrics(lines)}


def profile_metrics(gpu_row, api_row, nodes, proving_s):
    """Profiled request: kernel GPU-s [M], busy [D], launches/syncs per node [D]."""
    out = {'profiled_proving_s': proving_s}
    if gpu_row:
        kernel = gpu_row['kernel_busy_gpu_seconds']
        out.update(kernel_gpu_s=round(kernel, 4), any_busy_gpu_s=round(gpu_row['any_busy_gpu_seconds'], 4),
                   gpu_busy=round(kernel / (DEVICES * proving_s), 4) if proving_s else None)
    if api_row:
        out.update(launches=api_row.get('cudaLaunchKernel'), stream_syncs=api_row.get('cudaStreamSynchronize'))
        if nodes:
            out.update(launches_per_node=round(out['launches'] / nodes, 1) if out['launches'] is not None else None,
                       syncs_per_node=round(out['stream_syncs'] / nodes, 2) if out['stream_syncs'] is not None else None)
    return out


def distribution(values):
    """p50/p90/max over blocks; p50/p90 are nearest-rank (ceil(q*n)-th smallest), so every value is a measured one."""
    values = sorted(v for v in values if isinstance(v, (int, float)))
    if not values:
        return None
    rank = lambda q: values[max(0, -(-int(q * 100) * len(values) // 100) - 1)]
    return {'n': len(values), 'p50': round(rank(0.5), 4), 'p90': round(rank(0.9), 4), 'max': round(values[-1], 4)}


def arm_failure_reason(text):
    """The most specific error line of a failed service log (fail-closed install, OOM, ...)."""
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    for pattern in (r'error: \w+', r'\b[A-Z][A-Za-z]+(Missing|Unavailable|Failed|NotLanded|Refused)\b', r'(?i)error|failed'):
        hits = [l for l in lines if re.search(pattern, l)]
        if hits:
            return hits[-1][-400:]
    return lines[-1][-400:] if lines else 'no output'


METRICS = ('proving_s', 'request_s', 'capture_s', 'setup_s', 'native_window_s', 'recursion_after_native_s', 'tail_s')


def median_row(rows):
    out = {'n': len(rows)}
    for key in METRICS:
        values = [r[key] for r in rows if r.get(key) is not None]
        out[key] = round(statistics.median(values), 4) if values else None
    return out


def aggregate_arm(services):
    """Headline medians (cold, warm), job/peak receipts, profiled GPU accounting for one arm of one block."""
    headline = [s for s in services if s['role'] == 'headline' and s.get('status') == 'ok']
    warm = [s['requests'][1] for s in headline]
    cold = [s['requests'][0] for s in headline]
    out = {'cold': median_row(cold), 'warm': median_row(warm)}
    peaks = [s.get('device_peak_bytes') for s in headline if s.get('device_peak_bytes')]
    out['device_peak_bytes_sampled'] = max(peaks) if peaks else None
    active = [s['nvml_kernel_active_percent'] for s in headline if s.get('nvml_kernel_active_percent') is not None]
    out['nvml_kernel_active_percent'] = round(statistics.median(active), 1) if active else None
    jobs = [r['jobs'] for r in warm if r.get('jobs')]
    if jobs:
        last = jobs[-1]
        out['jobs_warm'] = last
        peaks = [last[k]['peak_bytes'] for k in ('outer_node', 'native_stage') if k in last and last[k]['peak_bytes']]
        out['per_node_peak_bytes'] = max(peaks) if peaks else None
        node = last.get('outer_node')
        if node and node['launches']:
            out['job_launches_per_node'] = round(node['launches']['median'], 1)
        if node and node['host_waits']:
            out['job_syncs_per_node'] = round(node['host_waits']['median'], 2)
    profiled = [s for s in services if s['role'] == 'profile' and s.get('status') == 'ok' and s.get('profile')]
    if profiled:
        out['profile_warm'] = profiled[-1]['profile']
    return out


def aggregate(blocks, arms, rows):
    """Comparable JSON over all blocks: per block per arm + totals over blocks every arm completed."""
    m3 = {r['block']: r for r in rows}
    result = {'schema': SCHEMA, 'arms': arms, 'labels': {'M': 'measured', 'D': 'derived', 'E': 'estimate'},
              'timing_boundary': 'proving_s = service request wall (capture/witness generation through root publish; excludes fetch/submit) [M]; request_s = client latency through the spool [M]; tail_s = proving - capture - setup - native window - recursion after native [D]',
              'blocks': [], 'totals': {}}
    for row in rows:
        state = blocks.get(row['block'])
        entry = {'block': row['block'], 'instructions': row['instructions'], 'cpu_segments': row['cpu_segments'],
                 'm3_request_s': row['request_s'], 'm7': M7_BASELINE.get(row['block']),
                 'status': state['status'] if state else 'not_run', 'arms': {}}
        if state:
            entry['parity'] = state.get('parity')
            entry['receivers'] = state.get('receivers')
            if state.get('arm_failures'):
                entry['arm_failures'] = state['arm_failures']
            if state.get('error'):
                entry['error'] = state['error']
            for arm in arms:
                services = [s for s in state.get('services', []) if s['arm'] == arm]
                if services:
                    entry['arms'][arm] = aggregate_arm(services)
        result['blocks'].append(entry)
    for arm in arms:
        done = [b for b in result['blocks'] if b['status'] == 'done' and arm in b['arms'] and b['arms'][arm]['warm']['proving_s'] is not None]
        if not done:
            continue
        warm = sum(b['arms'][arm]['warm']['proving_s'] for b in done)
        cold = sum(b['arms'][arm]['cold']['proving_s'] for b in done)
        base = sum(m3[b['block']]['request_s'] for b in done)
        pick = lambda kind, key: [b['arms'][arm][kind][key] for b in done]
        result['totals'][arm] = {'blocks': len(done), 'warm_proving_s_sum': round(warm, 2), 'cold_proving_s_sum': round(cold, 2),
                                 'warm_request_s_sum': round(sum(v for v in pick('warm', 'request_s') if v), 2),
                                 'm3_request_s_sum_same_blocks': round(base, 2),
                                 'warm_over_m3': round(warm / base, 4), 'cold_over_m3': round(cold / base, 4),
                                 'warm_proving_s': distribution(pick('warm', 'proving_s')),
                                 'cold_proving_s': distribution(pick('cold', 'proving_s')),
                                 'warm_request_s': distribution(pick('warm', 'request_s')),
                                 'warm_over_m3_per_block': distribution([b['arms'][arm]['warm']['proving_s'] / m3[b['block']]['request_s'] for b in done])}
    failed = {arm: [b['block'] for b in result['blocks'] if arm in (b.get('arm_failures') or {})] for arm in arms}
    result['arm_failures'] = {arm: blocks for arm, blocks in failed.items() if blocks}
    return result


def fmt(value, digits=1):
    return '-' if value is None else f'{value:.{digits}f}'


def markdown(result):
    """Short tables: warm/cold proving per arm next to M3/M7, then the warm critical path per arm."""
    arms = result['arms']
    lines = ['# RV64 M8 15-block benchmark', '',
             'proving = service request wall incl. witness generation, excl. fetch/submit. Warm/cold = median over headline services [M].',
             'M3 = one request per block (`rv64-m3-20261104`) [M]; M7 = default warm where measured [M].', '',
             '| block | Minstr | seg | M3 s | M7 s | ' + ' | '.join(f'{a} warm / cold s' for a in arms) + ' | status |',
             '|---|---:|---:|---:|---:|' + '---:|' * len(arms) + '---|']
    for b in result['blocks']:
        m7 = b['m7'] or {}
        m7s = m7.get('warm_proving_s') or m7.get('cold_proving_s')
        cells = []
        for a in arms:
            arm = b['arms'].get(a)
            if a in (b.get('arm_failures') or {}):
                cells.append('FAIL')
            elif arm and arm['warm']['proving_s'] is not None:
                cells.append(f"{fmt(arm['warm']['proving_s'], 2)} / {fmt(arm['cold']['proving_s'], 2)}")
            else:
                cells.append('-')
        lines.append(f"| {b['block']} | {b['instructions'] / 1e6:.1f} | {b['cpu_segments']} | {fmt(b['m3_request_s'])} | "
                     f"{fmt(m7s)}{' (cold)' if m7 and not m7.get('warm_proving_s') else ''} | " + ' | '.join(cells) + f" | {b['status']} |")
    if result['totals']:
        lines += ['', '| arm | blocks | warm sum s | cold sum s | M3 sum s (same blocks) | warm / M3 [D] |', '|---|---:|---:|---:|---:|---:|']
        for a, t in result['totals'].items():
            lines.append(f"| {a} | {t['blocks']} | {t['warm_proving_s_sum']:.1f} | {t['cold_proving_s_sum']:.1f} | {t['m3_request_s_sum_same_blocks']:.1f} | {t['warm_over_m3']:.3f} |")
        lines += ['', '| arm | warm p50 / p90 / max s | cold p50 / p90 / max s | warm request p50 / p90 / max s |', '|---|---:|---:|---:|']
        q = lambda d: '-' if not d else f"{d['p50']:.2f} / {d['p90']:.2f} / {d['max']:.2f}"
        for a, t in result['totals'].items():
            lines.append(f"| {a} | {q(t.get('warm_proving_s'))} | {q(t.get('cold_proving_s'))} | {q(t.get('warm_request_s'))} |")
    for b in result['blocks']:
        for a, failure in (b.get('arm_failures') or {}).items():
            lines.append(f"\n- {b['block']} {a} FAILED ({failure.get('kind')}): `{failure.get('reason')}`")
    lines += ['', '## Warm critical path per arm', '',
              '| block | arm | warm request s | capture | setup | native window | recursion after native | tail [D] | kernel GPU-s | GPU busy [D] | device peak GB | per-node peak GB | launches/node | syncs/node |',
              '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for b in result['blocks']:
        for a in arms:
            arm = b['arms'].get(a)
            if not arm or arm['warm']['proving_s'] is None:
                continue
            w, p = arm['warm'], arm.get('profile_warm') or {}
            launches = arm.get('job_launches_per_node', p.get('launches_per_node'))
            syncs = arm.get('job_syncs_per_node', p.get('syncs_per_node'))
            peak = arm.get('per_node_peak_bytes')
            device = arm.get('device_peak_bytes_sampled')
            lines.append(f"| {b['block']} | {a} | {fmt(w['request_s'], 2)} | {fmt(w['capture_s'], 2)} | {fmt(w['setup_s'], 2)} | {fmt(w['native_window_s'], 2)} | "
                         f"{fmt(w['recursion_after_native_s'], 2)} | {fmt(w['tail_s'], 2)} | {fmt(p.get('kernel_gpu_s'), 2)} | "
                         f"{fmt(p.get('gpu_busy') and p['gpu_busy'] * 100, 0)}{'%' if p.get('gpu_busy') else ''} | "
                         f"{fmt(device and device / 1e9, 1)} | {fmt(peak and peak / 1e9, 1)} | {fmt(launches, 0)} | {fmt(syncs, 1)} |")
    lines += ['', 'launches/syncs per node: job receipts (`GPU_M8_OUTER_NODE launches/host_waits`) where the arm runs OuterNodeJobs [M], '
              'else Nsight `cudaLaunchKernel`/`cudaStreamSynchronize` in the profiled warm window / nodes [D]. '
              'device peak: NVML-sampled max used bytes over both GPUs in the headline services [M]. '
              'per-node peak: job arena peak words x 4 B [D]. GPU busy: CUPTI kernel union / (2 GPUs x profiled window) [D].', '']
    return '\n'.join(lines)


# ----------------------------------------------------------------------------- estimate (pure)

# Calibration [M]: rv64_gate.sh diagnostic walls at c72b51646-equivalent builds (cold, warm proving s),
# outer-fold-review rg2 and the M7 default; not matched interleaved timings.
CALIBRATION = {
    'default': {26235156: (24.0, 10.45), 24628607: (29.8, 12.8)},  # 24628607: m7-integrate p1 headline baseline services, quiet-accepted
    'outer': {26235156: (40.71, 16.65), 24628607: (50.02, 20.13)},
}
DELTA_FROM_DEFAULT = {'native': (2.5, 1.7), 'hybrid': None, 'jobs': None}  # native-hybrid README: warm native window +2.1/+1.3 s [M diagnostic]
SERVICE_OVERHEAD_S = 5.0 + 3.0 + 2 * 6.0  # boot + stop + two quiet admissions (5 one-second samples each) [M typical]
RECEIVER_OVER_M3 = 0.6  # fresh CPU receiver 30.1 s on 26235156 at c72b51646 vs 50.5 s at M3 [M]
NSYS_FACTOR = 1.5  # profiled service wall over unprofiled, plus export [E]


def linear(points, x):
    (x0, y0), (x1, y1) = sorted(points)
    k = (y1 - y0) / (x1 - x0)
    return y0 + k * (x - x0)


def estimate_walls(rows, arms, rounds, profile=True):
    """[E] per arm per block: (rounds x headline + profiled) services, plus receivers once per block."""
    m3 = {r['block']: r['request_s'] for r in rows}
    out = {'label': 'E', 'method': 'cold/warm per block linear in M3 request seconds through the two dev-block calibration points', 'arms': {}}
    for arm in arms:
        cal = CALIBRATION.get(arm)
        if cal is None:
            delta = DELTA_FROM_DEFAULT.get(arm) or (CALIBRATION['outer'][24628607][0] - CALIBRATION['default'][24628607][0],
                                                    CALIBRATION['outer'][24628607][1] - CALIBRATION['default'][24628607][1])
            cal = {b: (c + delta[0], w + delta[1]) for b, (c, w) in CALIBRATION['default'].items()}
        total, per_block = 0.0, {}
        for row in rows:
            x = m3[row['block']]
            cold = linear([(m3[b], c) for b, (c, _) in cal.items()], x)
            warm = linear([(m3[b], w) for b, (_, w) in cal.items()], x)
            service = SERVICE_OVERHEAD_S + cold + warm
            wall = rounds * service + (NSYS_FACTOR * service if profile else 0)
            per_block[row['block']] = {'cold_s': round(cold, 1), 'warm_s': round(warm, 1), 'service_s': round(service, 1),
                                       'arm_wall_s': round(wall, 1)}
            total += wall
        out['arms'][arm] = {'gpu_wall_s': round(total), 'gpu_wall_h': round(total / 3600, 2), 'blocks': per_block}
    receivers = sum(2 * RECEIVER_OVER_M3 * r['receiver_wall_s'] for r in rows)
    out['receivers_cpu_s'] = round(receivers)
    out['total_h'] = round((sum(a['gpu_wall_s'] for a in out['arms'].values()) + receivers) / 3600, 2)
    out['max_service_lock_hold_s'] = round(max(NSYS_FACTOR * b['service_s'] for a in out['arms'].values() for b in a['blocks'].values()))
    return out


# ----------------------------------------------------------------------------- pod side

def atomic(path, value):
    stack.write(path, value)


def load(path, default=None):
    path = Path(path)
    return json.loads(path.read_text()) if path.is_file() else default


def free_bytes(path):
    stat = os.statvfs(path)
    return stat.f_bavail * stat.f_frsize


def gpu_lock_free():
    """Non-blocking probe: True if no one holds gpu.lock right now (released at once)."""
    with GPU_LOCK.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(handle, fcntl.LOCK_UN)
        return True


def load_assets(path):
    manifest = json.loads(Path(path).read_text())
    if manifest.get('schema') != 'rv64-m8-bench-assets/v1':
        raise RuntimeError('assets.json schema mismatch')
    for name, value in manifest['assets'].items():
        if stack.sha(value) != manifest['asset_sha256'][name]:
            raise RuntimeError('pinned asset changed: ' + name)
    return manifest


def pin(args):
    runtime = json.loads(args.runtime.read_text())
    assets = dict(runtime['assets'])
    for name, value in assets.items():
        if stack.sha(value) != runtime['asset_sha256'][name]:
            raise RuntimeError('frozen runtime changed: ' + name)
    own = {'driver': args.driver, 'receiver': args.receiver, 'addon': args.addon, 'outer_fs': args.outer_fs}
    if args.copy_to:
        args.copy_to.mkdir(parents=True, exist_ok=False)
        for name, value in own.items():
            target = args.copy_to / Path(value).name
            shutil.copy2(value, target)
            own[name] = target
    assets.update({name: str(Path(value).resolve()) for name, value in own.items()})
    manifest = {'schema': 'rv64-m8-bench-assets/v1', 'source_commit': args.source_commit, 'runtime': str(args.runtime),
                'assets': assets, 'asset_sha256': {name: stack.sha(value) for name, value in assets.items()},
                'created_utc_ns': time.time_ns()}
    atomic(args.out, manifest)
    print(json.dumps({'assets': str(args.out), 'asset_sha256': manifest['asset_sha256']}, indent=1))


def check(args):
    """Inputs inventory: every file a basket request reads, with size and sha256, plus regeneration hints."""
    rows = basket()
    template = load(M3 / 'inputs/plan-template.json', {})
    jobs = {j['block']: j for j in template.get('jobs', [])}
    elf = M3 / 'inputs/guest.elf'
    missing, blocks = [], []

    def item(path, expect_sha=None):
        path = Path(path)
        entry = {'path': str(path), 'exists': path.exists()}
        if path.is_file():
            entry['bytes'] = path.stat().st_size
            if expect_sha:
                entry['sha256_ok'] = stack.sha(path) == expect_sha
        elif path.is_dir():
            entry['files'] = sum(1 for _ in path.rglob('*'))
        return entry

    for row in rows:
        block = row['block']
        request_path = M3 / f'inputs/requests/{block}.json'
        request = load(request_path, {})
        entry = {'block': block, 'segments': row['cpu_segments'], 'request': item(request_path)}
        entry['input'] = item(request.get('input', M3 / f'inputs/{block}.bin'), request.get('input_sha256'))
        entry['elf_sha256_ok'] = elf.is_file() and stack.sha(elf) == request.get('elf_sha256')
        entry['plan_template_job'] = block in jobs and jobs[block].get('segments') == row['cpu_segments']
        entry['block_env'] = block_environment(row)
        entry['witness'] = 'generated in-request by capture from the input bytes (no stored witness)'
        if block in DEV_BLOCKS:
            entry['golden'] = item(GOLDEN / f'{block}-combined-d2-coalesce-v1/trial-1/artifact-fingerprints.json')
        else:
            entry['golden'] = 'none frozen: parity = all arms/requests byte-identical to the block reference + fresh CPU receivers'
        entry['m3_parity_receipt'] = item(M3 / f'runs/integrate/{block}-2gpu-scale/receipt.json')
        problems = []
        if not entry['request']['exists'] or not entry['input'].get('sha256_ok'):
            problems.append('input/request: python3 scripts/rv64_m3_pod.py inputs (copies the read-only full15 originals)')
        if not entry['elf_sha256_ok']:
            problems.append('guest.elf: python3 scripts/rv64_m3_pod.py inputs')
        if not entry['plan_template_job']:
            problems.append('plan-template job: python3 scripts/rv64_m3_pod.py inputs')
        if isinstance(entry['golden'], dict) and not entry['golden']['exists']:
            problems.append('golden: git checkout vectors/reports/rv64-m7-20261105/d2-composed (frozen D2 package)')
        if not entry['m3_parity_receipt']['exists']:
            entry['m3_parity_note'] = 'informational only (M3 used another profile); the harness records parity_vs_m3 = unavailable'
        entry['problems'] = problems
        missing += [f'{block}: {p}' for p in problems]
        blocks.append(entry)
    shared = {'guest_elf': item(elf), 'plan_template': item(M3 / 'inputs/plan-template.json'),
              'catalogues': item(M3 / 'catalogues-v3'), 'preset': item(stack.DEFAULT_PRESET),
              'full15_originals': item(Path('/workspace/rv64-gpu-session/two-gpu-ready-fixed-full15'))}
    assets = {}
    if args.assets:
        manifest = json.loads(args.assets.read_text())
        for name, value in manifest['assets'].items():
            assets[name] = item(value, manifest['asset_sha256'][name])
            if not assets[name].get('sha256_ok'):
                missing.append(f'asset {name}: changed or missing ({value})')
    for name in ('guest_elf', 'plan_template', 'catalogues', 'preset'):
        if not shared[name]['exists']:
            missing.append(f'{name}: missing ({shared[name]["path"]})')
    result = {'schema': 'rv64-m8-bench15-check/v1', 'blocks': blocks, 'shared': shared, 'assets': assets,
              'disk_free_bytes': free_bytes(M3), 'gpu_lock_free_now': gpu_lock_free(), 'missing': missing,
              'status': 'READY' if not missing else 'MISSING'}
    if args.out:
        atomic(args.out, result)
    print(json.dumps(result, indent=1))
    return result


class Stop(RuntimeError):
    """A proof, parity or receiver failure: stop the benchmark (owner rule)."""


class Bench:
    def __init__(self, args):
        self.args = args
        self.out = args.out.resolve()
        self.assets = load_assets(args.assets)
        self.root = ROOT
        self.stream = ROOT.name
        if ROOT != M3 / 'src' / self.stream:
            raise SystemExit('run only from the synced pod source tree /workspace/m3/src/<stream>')
        self.preset = json.loads(stack.DEFAULT_PRESET.read_text())
        self.environment = dict(stack.clean_environment(os.environ), TMPDIR=str(M3 / 'tmp'))

    # -- one service ---------------------------------------------------------
    def service(self, block, row, arm, role, round_index, attempt):
        label = f'{self.out.name}-{block}-{arm}-{role[0]}{round_index}-a{attempt}'
        manifest = {'source_root': str(self.root), 'assets': self.assets['assets'], 'block': block, 'preset': self.preset}
        argv, tag = stack.command(manifest, 'baseline', 0, self.stream, role == 'profile', label)
        if block not in DEV_BLOCKS:
            argv.append('--bench-basket-block')
        if self.args.smoke:
            argv += ['--quiet-mode', 'diagnostic', '--request-timeout', str(self.args.request_timeout)]
        for key, value in sorted(dict(block_environment(row), **arm_environment(arm, self.assets['assets'])).items()):
            argv += ['--env', f'{key}={value}']
        run = M3 / 'runs' / self.stream / f'daemon-{block}-r2-{tag}'
        log = self.out / 'logs' / f'{label}.log'
        log.parent.mkdir(parents=True, exist_ok=True)
        entry = {'arm': arm, 'role': role, 'round': round_index, 'attempt': attempt, 'run': str(run), 'argv': argv,
                 'started_utc_ns': time.time_ns()}
        with log.open('w') as handle:
            code = subprocess.run(argv, cwd=self.root, env=self.environment, stdout=handle, stderr=subprocess.STDOUT).returncode
        entry.update(exit_code=code, finished_utc_ns=time.time_ns(), log=str(log))
        if code:
            text = log.read_text(errors='replace')
            entry['status'] = 'quiet_timeout' if 'quiet admission timed out' in text else 'failed'
            return entry
        receipt = json.loads((run / 'receipt.json').read_text())
        if len(receipt['requests']) != 2:
            entry['status'] = 'failed'
            entry['error'] = 'expected a cold and a warm request'
            return entry
        stderr = (run / 'producer.stderr').read_text(errors='replace')
        per_request = split_requests(stderr)
        entry['requests'] = []
        for index, request in enumerate(receipt['requests']):
            combined = load(Path(request['proof']) / 'combined-report.json', {})
            entry['requests'].append(request_metrics(request, combined, per_request[index] if index < len(per_request) else []))
        memory = receipt.get('physical_gpu_memory') or {}
        peaks = [v for v in (memory.get('peak_used_bytes') or {}).values() if v]
        entry['device_peak_bytes'] = max(peaks) if peaks else None
        active = [v['mean_percent'] for v in (memory.get('kernel_activity') or {}).values() if v.get('mean_percent') is not None]
        entry['nvml_kernel_active_percent'] = round(statistics.mean(active), 1) if active else None
        entry['quiet_accepted'] = [bool(q and q.get('accepted')) for q in receipt.get('quiet_before_requests', [])]
        entry['service_start_s'] = receipt.get('service_start_s')
        entry['status'] = 'ok'
        return entry

    # -- parity / receivers / profile ------------------------------------------
    def parity(self, block, entry, state):
        import rv64_gate as gate
        receipt = json.loads((Path(entry['run']) / 'receipt.json').read_text())
        golden = None
        if block in DEV_BLOCKS:
            golden = json.loads((GOLDEN / f'{block}-combined-d2-coalesce-v1/trial-1/artifact-fingerprints.json').read_text())
        for request in receipt['requests']:
            actual = stack.fingerprints(request)
            if state.get('reference') is None:
                state['reference'] = {'run': entry['run'], 'ordinal': request['ordinal'], 'fingerprints': actual}
            if actual != state['reference']['fingerprints']:
                atomic(self.out / f'parity-failure-{block}.json', {'run': entry['run'], 'ordinal': request['ordinal'],
                                                                   'expected': state['reference'], 'actual': actual})
                raise Stop(f'{block} {entry["arm"]}: proof bytes differ from the block reference')
            if golden is not None:
                try:
                    gate.frozen_parity(Path(request['proof']), golden)
                except RuntimeError as error:
                    raise Stop(f'{block} {entry["arm"]}: {error}')
        state['parity'] = {'requests_identical': state.get('parity', {}).get('requests_identical', 0) + len(receipt['requests']),
                           'frozen_d2_golden': golden is not None, 'reference_run': state['reference']['run']}

    def receive(self, block, run):
        log = self.out / 'logs' / f'{Path(run).name}-receiver.log'
        argv = [sys.executable, str(self.root / 'scripts/rv64_m4_resident.py'), 'receive', '--run', run,
                '--which', 'all', '--receiver-workers', str(self.args.receiver_workers)]
        with log.open('w') as handle:
            code = subprocess.run(argv, cwd=self.root, env=self.environment, stdout=handle, stderr=subprocess.STDOUT).returncode
        receipt = json.loads((Path(run) / 'receipt.json').read_text())
        verdicts = receipt.get('receivers') or []
        if code or len(verdicts) != 2 or not all(v.get('accepted') for v in verdicts):
            raise Stop(f'{block}: fresh CPU receiver rejected {run}')
        return [{'trial': v.get('trial'), 'accepted': True, 'wall_s': round(v['process']['wall_ns'] / 1e9, 1)} for v in verdicts]

    def gpu_seconds(self, entry, reference_run):
        run = Path(entry['run'])
        log = self.out / 'logs' / f'{run.name}-gpu-seconds.log'
        argv = [sys.executable, str(self.root / 'scripts/rv64_m7_gpu_seconds.py'), str(run), '--accepted-run', reference_run]
        with log.open('w') as handle:
            code = subprocess.run(argv, cwd=self.root, env=self.environment, stdout=handle, stderr=subprocess.STDOUT).returncode
        receipt = json.loads((run / 'receipt.json').read_text())
        api = ((receipt.get('cuda_api') or {}).get('per_request') or {}).get('requests') or []
        gpu = load(run / 'gpu-seconds.json', {}).get('requests', []) if code == 0 else []
        warm = entry['requests'][1]
        profile = profile_metrics(gpu[1] if len(gpu) > 1 else None, api[1] if len(api) > 1 else None,
                                  warm.get('nodes'), warm['proving_s'])
        if code:
            profile['gpu_seconds_error'] = log.read_text(errors='replace')[-600:]
        return profile

    def prune(self, run, keep_proofs=False):
        """Delete what this bench created and no longer needs: proof payloads, Nsight files; gzip the producer log."""
        run = Path(run)
        if not str(run).startswith(str(M3 / 'runs' / self.stream) + '/daemon-'):
            raise RuntimeError('refusing to prune outside this stream: ' + str(run))
        if not keep_proofs:
            for name in ('spool/out', 'nsys'):
                if (run / name).exists():
                    shutil.rmtree(run / name)
        stderr = run / 'producer.stderr'
        if not keep_proofs and stderr.is_file():
            with stderr.open('rb') as source, gzip.open(str(stderr) + '.gz', 'wb') as target:
                shutil.copyfileobj(source, target)
            stderr.unlink()

    # -- one block --------------------------------------------------------------
    def block(self, row):
        block = row['block']
        path = self.out / 'blocks' / f'{block}.json'
        state = load(path) or {'block': block, 'status': 'running', 'services': [], 'reference': None}
        if state['status'] == 'done':
            return state
        if state.get('reference') and not Path(state['reference']['run'], 'spool/out').is_dir():
            state = {'block': block, 'status': 'running', 'services': [], 'reference': None,
                     'restarted_after': 'reference proofs gone; block restarted'}
        state['status'] = 'running'
        save = lambda: atomic(path, state)
        done = {(s['arm'], s['role'], s['round']) for s in state['services']
                if s.get('status') == 'ok' and (s['role'] != 'profile' or 'profile' in s)}
        retained = {s['run'] for s in state['services'] if s.get('retained')}
        plan = [(arm, 'headline', r) for r in range(self.args.rounds) for arm in self.args.arms]
        failures = state.setdefault('arm_failures', {})
        for arm, role, round_index in plan:
            if (arm, role, round_index) in done or arm in failures:
                continue
            entry = self.attempt(block, row, arm, role, round_index, state, save)
            if entry['status'] != 'ok':  # only a tolerated arm gets here: record it, skip its other services on this block
                text = entry.get('error') or Path(entry['log']).read_text(errors='replace')
                failures[arm] = {'kind': 'parity' if entry['status'] == 'parity_failed' else 'service', 'run': entry['run'],
                                 'log': entry['log'], 'exit_code': entry.get('exit_code'),
                                 'reason': entry.get('error') or arm_failure_reason(text)}
                if Path(entry['run']).is_dir():
                    self.prune(entry['run'])
                save()
                continue
            first_of_arm = not any(s['run'] in retained and s['arm'] == arm for s in state['services'])
            keep = entry['run'] == state['reference']['run'] or (self.args.receivers == 'per-arm' and first_of_arm)
            entry['retained'] = keep
            if keep:
                retained.add(entry['run'])
            else:
                self.prune(entry['run'])
            save()
        if not state.get('receivers'):
            state['receivers'] = {run: self.receive(block, run) for run in sorted(retained)}
            save()
        if self.args.profile == 'warm':
            for arm in self.args.arms:
                if (arm, 'profile', 0) in done or arm in failures:
                    continue
                entry = self.attempt(block, row, arm, 'profile', 0, state, save)
                if entry['status'] != 'ok':
                    failures[arm] = {'kind': 'profile', 'run': entry['run'], 'log': entry['log'],
                                     'reason': entry.get('error') or arm_failure_reason(Path(entry['log']).read_text(errors='replace'))}
                    if Path(entry['run']).is_dir():
                        self.prune(entry['run'])
                    save()
                    continue
                entry['profile'] = self.gpu_seconds(entry, state['reference']['run'])
                self.prune(entry['run'])
                save()
        for run in sorted(retained):
            self.prune(run)
        state['status'] = 'done'
        save()
        return state

    def attempt(self, block, row, arm, role, round_index, state, save):
        need = self.args.min_free_gb * 2**30
        for attempt in range(1, self.args.quiet_retries + 2):
            if free_bytes(M3) < need:
                raise Stop(f'pod disk below {self.args.min_free_gb} GiB free before {block} {arm}; prune and resume')
            entry = self.service(block, row, arm, role, round_index, attempt + 10 * len(state['services']))
            state['services'].append(entry)
            save()
            if entry['status'] == 'ok':
                try:
                    self.parity(block, entry, state)
                except Stop as error:
                    if arm not in self.args.tolerate_arm_failure:
                        raise
                    entry['status'] = 'parity_failed'
                    entry['error'] = str(error)
                save()
                return entry
            if entry['status'] != 'quiet_timeout':
                if arm in self.args.tolerate_arm_failure:
                    return entry
                raise Stop(f'{block} {arm} {role}: service failed ({entry["log"]})')
        raise Stop(f'{block} {arm}: quiet gate refused {self.args.quiet_retries + 1} attempts (busy pod)')

    def run(self):
        rows = basket()
        if self.args.smoke:
            rows = [r for r in rows if r['block'] == SMOKE_BLOCK]
        elif self.args.blocks:
            wanted = set(self.args.blocks)
            rows = [r for r in rows if r['block'] in wanted]
        unknown = [a for a in self.args.tolerate_arm_failure if a not in self.args.arms]
        if unknown:
            raise SystemExit('--tolerate-arm-failure names arms not in --arms: ' + ','.join(unknown))
        if self.args.arms[0] in self.args.tolerate_arm_failure:
            raise SystemExit('the first arm sets the block reference proof and cannot be a tolerated-failure arm')
        if not self.args.wait_for_gpu and not gpu_lock_free():
            raise SystemExit('gpu.lock is held (a gate or another stream); not starting. Retry later or pass --wait-for-gpu')
        self.out.mkdir(parents=True, exist_ok=True)
        config = {'schema': SCHEMA, 'arms': self.args.arms, 'rounds': self.args.rounds, 'profile': self.args.profile,
                  'receivers': self.args.receivers, 'tolerate_arm_failure': self.args.tolerate_arm_failure, 'smoke': self.args.smoke, 'blocks': [r['block'] for r in rows],
                  'assets': self.assets, 'preset_sha256': stack.sha(stack.DEFAULT_PRESET), 'stream': self.stream,
                  'source_commit': self.args.source_commit}
        previous = load(self.out / 'config.json')
        if previous and {k: previous.get(k) for k in ('arms', 'rounds', 'profile', 'receivers', 'assets')} != \
                {k: config.get(k) for k in ('arms', 'rounds', 'profile', 'receivers', 'assets')}:
            raise SystemExit('resume refused: this output directory was started with another configuration')
        atomic(self.out / 'config.json', previous or config)
        try:
            for row in rows:
                state = self.block(row)
                print(json.dumps({'block': row['block'], 'status': state['status']}), flush=True)
        except Stop as error:
            failed = load(self.out / 'blocks' / f'{row["block"]}.json') or {'block': row['block'], 'services': []}
            failed.update(status='failed', error=str(error))
            atomic(self.out / 'blocks' / f'{row["block"]}.json', failed)
            print('BENCH STOP ' + str(error), flush=True)
            report_files(self.out, self.args.arms)
            raise SystemExit(1)
        report_files(self.out, self.args.arms)


def report_files(out, arms):
    rows = basket()
    blocks = {}
    for path in sorted((out / 'blocks').glob('*.json')):
        state = json.loads(path.read_text())
        blocks[state['block']] = state
    result = aggregate(blocks, arms, rows)
    config = load(out / 'config.json', {})
    result['config'] = {k: config.get(k) for k in ('rounds', 'profile', 'receivers', 'smoke', 'stream', 'source_commit')}
    result['asset_sha256'] = (config.get('assets') or {}).get('asset_sha256')
    atomic(out / 'bench15.json', result)
    (out / 'bench15.md').write_text(markdown(result))
    print(json.dumps({'json': str(out / 'bench15.json'), 'markdown': str(out / 'bench15.md'), 'totals': result['totals']}))
    return result


def arms_type(text):
    arms = [a for a in text.split(',') if a]
    for arm in arms:
        if arm not in ARMS:
            raise argparse.ArgumentTypeError(f'unknown arm {arm!r}; choose from {", ".join(ARMS)}')
    if len(set(arms)) != len(arms) or not arms:
        raise argparse.ArgumentTypeError('arms must be distinct and non-empty')
    return arms


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='mode', required=True)
    p = sub.add_parser('pin', help='freeze the benchmark assets')
    p.add_argument('--runtime', type=Path, default=RUNTIME, help='frozen CUDA runtime (library/sparse/observer/guard)')
    for name in ('driver', 'receiver', 'addon', 'outer_fs'):
        p.add_argument('--' + name.replace('_', '-'), required=True)
    p.add_argument('--source-commit', required=True)
    p.add_argument('--copy-to', type=Path, help='new directory to copy driver/receiver/addons into (so later builds cannot move them)')
    p.add_argument('--out', required=True, type=Path)
    c = sub.add_parser('check', help='inputs inventory (no GPU)')
    c.add_argument('--assets', type=Path)
    c.add_argument('--out', type=Path)
    e = sub.add_parser('estimate', help='wall-time estimate per arm [E] (no GPU)')
    e.add_argument('--arms', type=arms_type, default=list(ARMS))
    e.add_argument('--rounds', type=int, default=3)
    e.add_argument('--no-profile', action='store_true')
    r = sub.add_parser('run', help='the benchmark (resumable per block)')
    r.add_argument('--assets', required=True, type=Path)
    r.add_argument('--out', required=True, type=Path, help='bench directory; rerun the same command to resume')
    r.add_argument('--arms', type=arms_type, default=['default', 'outer'], help='comma list of ' + ','.join(ARMS))
    r.add_argument('--rounds', type=int, default=3, help='headline services per arm per block (interleaved)')
    r.add_argument('--blocks', type=int, nargs='+', help='subset of the basket (still ascending, still stop-on-failure)')
    r.add_argument('--profile', choices=('warm', 'none'), default='warm', help='one Nsight service per arm per block for GPU-s/launches/syncs')
    r.add_argument('--receivers', choices=('reference', 'per-arm'), default='reference',
                   help='fresh CPU receivers on the block reference service, or on the first service of every arm')
    r.add_argument('--receiver-workers', type=int, default=16)
    r.add_argument('--tolerate-arm-failure', type=lambda t: [a for a in t.split(',') if a], default=[],
                   help='arms whose service or parity failure is recorded per block (arm skipped there) instead of stopping the bench')
    r.add_argument('--quiet-retries', type=int, default=2)
    r.add_argument('--min-free-gb', type=float, default=3.0)
    r.add_argument('--wait-for-gpu', action='store_true', help='start even if gpu.lock is held now (the harness waits for it)')
    r.add_argument('--source-commit')
    r.add_argument('--smoke', action='store_true', help=f'one round on {SMOKE_BLOCK}, diagnostic quiet mode; walls unqualified')
    r.add_argument('--request-timeout', type=float, default=240)
    t = sub.add_parser('report', help='rebuild bench15.json/.md')
    t.add_argument('--out', required=True, type=Path)
    t.add_argument('--arms', type=arms_type)
    args = parser.parse_args()
    if args.mode == 'pin':
        pin(args)
    elif args.mode == 'check':
        check(args)
    elif args.mode == 'estimate':
        print(json.dumps(estimate_walls(basket(), args.arms, args.rounds, not args.no_profile), indent=1))
    elif args.mode == 'run':
        if args.smoke:
            args.rounds = 1
        Bench(args).run()
    else:
        report_files(args.out, args.arms or load(args.out / 'config.json', {}).get('arms') or ['default'])


if __name__ == '__main__':
    main()
