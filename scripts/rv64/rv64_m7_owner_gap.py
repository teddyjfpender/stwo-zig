#!/usr/bin/env python3
"""Read-only warm D2 headline owner-gap partition, using actual interval unions."""
import bisect
from collections import defaultdict
import hashlib
import json
import sqlite3
import sys


def union(xs):
    out = []
    for a, b in sorted(xs):
        if b <= a:
            continue
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out


def inside(xs, a, b):
    first = bisect.bisect_right(xs, (a, 1 << 63)) - 1
    return [(max(lo, a), min(hi, b)) for lo, hi in xs[max(first, 0):]
            if lo < b and hi > a]


def subtract(xs, ys):
    out = []
    for a, b in xs:
        cursor = a
        for lo, hi in inside(ys, a, b):
            if cursor < lo:
                out.append((cursor, lo))
            cursor = max(cursor, hi)
        if cursor < b:
            out.append((cursor, b))
    return out


def duration(xs):
    return sum(b - a for a, b in xs)


path = sys.argv[1]
start, end = 45713537241, 51639866055
db = sqlite3.connect('file:' + path + '?mode=ro', uri=True)
strings = dict(db.execute('select id,value from StringIds'))
named = {'rv64/TC/FIXED', 'rv64/TC/MAIN', 'rv64/TC/INTER', 'rv64/composition',
         'rv64/recursion/MAIN-assignment', 'rv64/recursion/INTER-witness', 'rv64/owner/pcs'}
ranges = [(max(a, start), min(b, end), tid, text or strings.get(textid, ''))
          for a, b, tid, text, textid in db.execute('select start,end,globalTid,text,textId from NVTX_EVENTS where end>? and start<?', (start, end))
          if a < end and b > start]
owners = [r for r in ranges if r[3].startswith('rv64/owner/')]
top = [r for r in owners if not any(p != r and p[2] == r[2] and p[0] <= r[0] and p[1] >= r[1] for p in owners)]
runtime = db.execute('select start,end,globalTid,correlationId,nameId from CUPTI_ACTIVITY_KIND_RUNTIME where end>? and start<?', (start, end)).fetchall()
correlations = {correlation: tid for a, b, tid, correlation, name in runtime}
all_api, waits = defaultdict(list), defaultdict(list)
for a, b, tid, correlation, name in runtime:
    all_api[tid].append((max(a, start), min(b, end)))
    if strings[name].startswith(('cudaEventSynchronize', 'cudaStreamSynchronize', 'cudaDeviceSynchronize')):
        waits[tid].append((max(a, start), min(b, end)))
kernels, transfers, devices = defaultdict(list), defaultdict(list), defaultdict(set)
for table, target in [('CUPTI_ACTIVITY_KIND_KERNEL', kernels), ('CUPTI_ACTIVITY_KIND_MEMCPY', transfers), ('CUPTI_ACTIVITY_KIND_MEMSET', transfers)]:
    for a, b, device, correlation in db.execute('select start,end,deviceId,correlationId from ' + table + ' where end>? and start<?', (start, end)):
        target[device].append((max(a, start), min(b, end)))
        if correlation in correlations:
            devices[correlations[correlation]].add(device)
for mapping in (all_api, waits, kernels, transfers):
    for key in mapping:
        mapping[key] = union(mapping[key])
result = defaultdict(lambda: defaultdict(int))
unmarked_detail = defaultdict(lambda: defaultdict(int))
for a, b, tid, owner in top:
    assert len(devices[tid]) == 1, (tid, devices[tid])
    device = next(iter(devices[tid]))
    children = [r for r in ranges if r[2] == tid and r[3] in named and a <= r[0] and r[1] <= b and r != (a, b, tid, owner)]
    cuts = sorted({a, b} | {t for r in children for t in r[:2]})
    for lo, hi in zip(cuts, cuts[1:]):
        active = [r for r in children if r[0] <= lo and r[1] >= hi]
        label = min(active, key=lambda r: r[1] - r[0])[3] if active else ('rv64/owner/pcs' if owner == 'rv64/owner/pcs' else 'unmarked-owner')
        totals = result[label]
        previous_totals = dict(totals)
        totals['owner_ns'] += hi - lo
        remainder = [(lo, hi)]
        for key, spans in [('kernel_ns', kernels[device]), ('copy_or_set_only_ns', transfers[device]), ('blocking_api_no_gpu_ns', waits[tid]), ('other_runtime_no_gpu_ns', all_api[tid])]:
            left = subtract(remainder, spans)
            totals[key] += duration(remainder) - duration(left)
            remainder = left
        totals['untraced_host_no_gpu_ns'] += duration(remainder)
        assert sum(totals[k] for k in ('kernel_ns','copy_or_set_only_ns','blocking_api_no_gpu_ns','other_runtime_no_gpu_ns','untraced_host_no_gpu_ns')) == totals['owner_ns']
        if label == 'unmarked-owner':
            preceding = [r for r in children if r[1] <= lo]
            following = [r for r in children if r[0] >= hi]
            before = max(preceding, key=lambda r: r[1])[3] if preceding else 'start'
            after = min(following, key=lambda r: r[0])[3] if following else 'end'
            key = owner + ': after ' + before + ', before ' + after
            for name, value in totals.items():
                unmarked_detail[key][name] += value - previous_totals.get(name, 0)
output = {'schema': 'rv64-m7-owner-gap-partition/v1', 'sqlite_sha256': hashlib.file_digest(open(path, 'rb'), 'sha256').hexdigest(),
          'window_ns': [start, end], 'top_owner_ranges': len(top),
          'scope': 'Mutually exclusive same-physical-device intervals inside top-level owner host ranges. Untraced host includes driver calls, allocations, CPU work and scheduler descheduling; no CPU-only inference.',
          'stages_seconds': {k: {name: ns/1e9 for name, ns in v.items()} for k, v in result.items()},
          'unmarked_detail_seconds': {k: {name: ns/1e9 for name, ns in v.items()} for k, v in unmarked_detail.items()}}
print(json.dumps(output, indent=2))
