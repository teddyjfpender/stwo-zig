#!/usr/bin/env python3
"""Validate matched joint-STARK test logs; retain every seed and scope."""
import argparse
import hashlib
import json
import re
import statistics
from pathlib import Path


def collect(paths):
    rows, files, seeds = [], [], set()
    expected = {(p, m, r, j) for p in ('diagnostic_q8_pow0', 'csp_q70_pow26')
                for m, r in ((0, True), (1, True), (1, False)) for j in (False, True)}
    for path in paths:
        raw = path.read_bytes()
        text = raw.decode()
        if 'All 15 tests passed.' not in text or re.search(r'FAIL|logged errors|leaked|error:|panic:', text):
            raise ValueError('Incomplete or failed test log')
        found, log_rows = set(), []
        for line in text.splitlines():
            if 'BLOCK_V6_JOINT ' not in line:
                continue
            fields = dict(re.findall(r'(\w+)=([^ ]+)', line.split('BLOCK_V6_JOINT ', 1)[1]))
            for key in ('mode', 'cycles', 'seed', 'prove_ns', 'verify_ns', 'stark_bytes', 'starks'):
                fields[key] = int(fields[key])
            for key in ('ram', 'joint', 'globals_open'):
                if fields[key] not in ('true', 'false'):
                    raise ValueError('Invalid boolean')
                fields[key] = fields[key] == 'true'
            identity = (fields['profile'], fields['mode'], fields['ram'], fields['joint'])
            if identity not in expected or identity in found:
                raise ValueError('Unexpected or duplicate arm')
            found.add(identity)
            if (not fields['globals_open'] or fields['starks'] != (1 if fields['joint'] else 2)
                    or any(fields[k] <= 0 for k in ('cycles', 'seed', 'prove_ns', 'verify_ns', 'stark_bytes'))):
                raise ValueError('Invalid scope or measurement')
            log_rows.append(fields)
        if found != expected or len({(r['cycles'], r['seed']) for r in log_rows}) != 1:
            raise ValueError('Missing arms or mismatched workload')
        seed = log_rows[0]['seed']
        if seed in seeds:
            raise ValueError('Duplicate transcript seed')
        seeds.add(seed)
        rows.extend(log_rows)
        files.append({'name': path.name, 'sha256': hashlib.sha256(raw).hexdigest()})
    if len({r['cycles'] for r in rows}) != 1:
        raise ValueError('Cannot summarize different workloads')
    summaries = []
    for profile, mode, ram in sorted({(r['profile'], r['mode'], r['ram']) for r in rows}):
        item = {'profile': profile, 'mode': mode, 'ram': ram, 'seeds': sorted(seeds)}
        for joint, name in ((False, 'separate'), (True, 'joint')):
            arm = [r for r in rows if (r['profile'], r['mode'], r['ram'], r['joint']) == (profile, mode, ram, joint)]
            item[name] = {k: {'median': statistics.median(r[k] for r in arm),
                             'min': min(r[k] for r in arm), 'max': max(r[k] for r in arm)}
                          for k in ('prove_ns', 'verify_ns', 'stark_bytes')}
        summaries.append(item)
    return {'schema': 'stwo-zig/joint-native-proof/v1', 'logs': files, 'rows': rows, 'summaries': summaries,
            'scope': 'Open native + projection + ordinary-memory relation proofs; no global or recursive closure',
            'timing': 'Proof phases exclude runner/witness/first-round setup, hostile probes and serialization; verification separately timed',
            'bytes': 'Postcard STARK bytes only; native/projection/memory claim transport is not included',
            'caution': 'Three transcript seeds are not a stable canonical PoW latency distribution; no Ethereum-block speedup claim'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', type=Path, nargs='+')
    args = parser.parse_args()
    print(json.dumps(collect(args.logs), indent=2))
