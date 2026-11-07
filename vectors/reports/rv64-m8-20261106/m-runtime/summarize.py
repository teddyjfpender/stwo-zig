#!/usr/bin/env python3
"""Compact summary of one canonical 3+3 experiment.json (warm request, stages, quiet, parity, receivers)."""
import json, statistics, sys
from pathlib import Path
exp = json.loads(Path(sys.argv[1]).read_text())
rows = []
out = {'experiment': sys.argv[1], 'status': exp.get('status'), 'warm_median_s': exp.get('warm_median_s'),
                 'fullstack_over_baseline': exp.get('measured_fullstack_over_baseline'), 'services': rows}
def stage(warm, name):
    st = warm.get('stages') or {}
    v = st.get(name)
    return v.get('seconds') if isinstance(v, dict) else v
for s in exp['services']:
    w = s.get('warm', {})
    receipt = json.loads((Path(s['run']) / 'receipt.json').read_text())
    cold = receipt['requests'][0]
    rows.append({'order': s['order_index'], 'arm': s['arm'], 'warm_request_s': w.get('marker', {}).get('request_wall_ns', 0) / 1e9,
                 'cold_request_s': cold.get('marker', {}).get('request_wall_ns', 0) / 1e9,
                 'warm_stages': w.get('stages'), 'quiet_accepted': (s.get('quiet') or {}).get('accepted'),
                 'payload_byte_parity': s.get('payload_byte_parity'),
                 'fresh_receivers': [r.get('accepted') for r in s.get('fresh_receivers', [])],
                 'service_start_s': receipt.get('service_start_s')})
arms = {}
for r in rows:
    arms.setdefault(r['arm'], []).append(r)
out['medians'] = {}
for arm, rs in arms.items():
    m = {'warm_request_s': statistics.median(r['warm_request_s'] for r in rs), 'cold_request_s': statistics.median(r['cold_request_s'] for r in rs)}
    keys = set().union(*[set((r['warm_stages'] or {}).keys()) for r in rs])
    for k in sorted(keys):
        vals = [r['warm_stages'][k] for r in rs if isinstance((r['warm_stages'] or {}).get(k), (int, float))]
        if len(vals) == len(rs):
            m['stage_' + k] = statistics.median(vals)
    out['medians'][arm] = m
out['reference'] = exp.get('payload_reference', {}).get('run')
out['fresh_receiver_scope'] = exp.get('fresh_receiver_scope', 'every request')
print(json.dumps(out, indent=1, default=str))
