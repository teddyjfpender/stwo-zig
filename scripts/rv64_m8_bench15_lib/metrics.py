"""Parse request-scoped telemetry without making performance qualification claims."""
import gzip
from pathlib import Path
import re
import statistics

DEVICES = 2
WORD_BYTES = 4
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


def split_requests(text, setups=None):
    """Request lines after service readiness, excluding nested install proofs."""
    out, current = [], []
    setup = None
    for line in text.splitlines():
        if line.startswith('GPU_RESIDENT_SETUP '):
            _, phase, body = line.split(' ', 2)
            info = fields(body)
            if phase == 'reclaim' and setup is not None:
                setup['lines'].append(line)
                continue
            if type(info.get('block')) is not int or info['block'] < 0:
                raise ValueError('setup epoch has no valid block identity')
            if phase == 'begin' and setup is None:
                setup = {**info, 'lines': []}
                continue
            if (phase != 'end' or setup is None or setup['block'] != info['block']
                    or type(info.get('setup_ns')) is not int or info['setup_ns'] < 0
                    or info.get('status') not in ('accepted', 'failed')):
                raise ValueError('setup epoch is unbalanced or has invalid completion')
            if setups is not None:
                setups.append({**setup, **info})
            setup = None
            continue
        if setup is not None:
            setup['lines'].append(line)
            continue
        if line.startswith('GPU_RESIDENT_SERVICE ready '):
            # Native installation runs a legacy proof to construct classes;
            # it emits the same block marker. Only the final outer READY
            # boundary starts the measured service's request sequence.
            out, current = [], []
            continue
        current.append(line)
        if REQUEST_MARK in line:
            out.append(current)
            current = []
    if setup is not None:
        raise ValueError('setup epoch is missing its completion')
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


def request_metrics(request, combined, lines, native=None):
    """One served request: walls [M], critical-path stages [M], tail [D], job receipts [M]."""
    ns = lambda key: combined.get(key)
    s = lambda value: None if value is None else round(value / 1e9, 4)
    proving = request['marker']['request_wall_ns']
    parts = [ns('capture_ns'), ns('native_setup_ns'), ns('native_prove_ns'), ns('recursion_after_native_ns')]
    recursive = combined.get('recursive') or {}
    nodes = (recursive.get('leaf_proofs') or 0) + (recursive.get('fold_proofs') or 0)
    result = {'ordinal': request['ordinal'], 'proving_s': s(proving), 'request_s': s(request['client_latency_ns']),
            'capture_s': s(parts[0]), 'setup_s': s(parts[1]), 'native_window_s': s(parts[2]),
            'recursion_after_native_s': s(parts[3]),
            'tail_s': s(proving - sum(parts)) if None not in parts else None,
            'nodes': nodes or None, 'root_proof_bytes': recursive.get('root_proof_bytes'),
            'jobs': job_metrics(lines)}
    if native:
        marker = fields(lines[-1][len(REQUEST_MARK):]) if lines and lines[-1].startswith(REQUEST_MARK) else {}
        identity = tuple(native.get(k) for k in ('block', 'sequence', 'request_wall_ns'))
        if (any(type(v) is not int or v < 0 for v in identity)
                or identity != (request['block'], request['ordinal'], proving)
                or identity != tuple(marker.get(k) for k in ('block', 'iteration', 'request_wall_ns'))):
            raise ValueError('native request receipt and marker identity differ')
        setup = [native.get(k) for k in ('setup_ns', 'setup_plus_request_ns')]
        if (setup != [marker.get(k) for k in ('setup_ns', 'setup_plus_request_ns')]
                or (any(v is not None for v in setup) and
                    (any(type(v) is not int or v < 0 for v in setup) or setup[1] != setup[0] + proving))):
            raise ValueError('native setup accounting is incomplete or inconsistent')
        result.update(setup_miss_s=s(setup[0]), setup_plus_request_s=s(setup[1]))
        receipt = native['receipt']
        result['driver'] = {key: receipt.get(key) for key in (
            'host_waits', 'd2h', 'd2h_bytes', 'job_slab_d2h', 'job_slab_d2h_bytes',
            'host_callbacks', 'capture_release_callbacks', 'job_receipts_complete', 'transfer_scope')}
        result['driver'].update(
            device_span_s=[round(v / 1e6, 4) for v in receipt.get('device_gpu_us', [])[:DEVICES]],
            device_enqueue_s=[s(v) for v in receipt.get('device_enqueue_ns', [])[:DEVICES]],
            device_gate_s=[s(v) for v in receipt.get('device_gate_ns', [])[:DEVICES]],
            memory_serializations=receipt.get('device_memory_serializations', [])[:DEVICES],
            scope='Driver counters and CUDA-event spans; not a CUDA API census or a physical peak')
    return result


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


def producer_tail(run, limit=200_000):
    """Last bytes of a service's producer.stderr (plain or gzipped): the fail-closed reason lives there, not in the harness log."""
    run = Path(run)
    try:
        if (run / 'producer.stderr').is_file():
            data = (run / 'producer.stderr').read_bytes()
        elif (run / 'producer.stderr.gz').is_file():
            data = gzip.decompress((run / 'producer.stderr.gz').read_bytes())
        else:
            return ''
    except OSError:
        return ''
    return data[-limit:].decode(errors='replace')


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
    out['per_gpu_sampled_max_used_bytes'] = {d: max(values) for d in ('0', '1') if (values := [s['per_gpu_sampled_max_used_bytes'][d] for s in headline if d in s.get('per_gpu_sampled_max_used_bytes', {})])}
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
