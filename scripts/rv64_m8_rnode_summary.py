#!/usr/bin/env python3
"""Summarise the r-node device encode / OODS check lines of one gate producer log.

usage: rv64_m8_rnode_summary.py <producer.stderr> [--label L]

Splits the log into requests at GPU_M8_OUTER_WINDOW open lines and reports, per
request: node count, device-encoded bytes identical (device == mirror == host
wire.encode), OODS values identical, encoder / OODS GPU ns (CUDA events) and the
host time still spent per node (GPU_M8_OUTER_NODE_HOST: prestage, init, finish,
decode, assemble, plus the check-mode mirror). Prints one JSON document.
"""
import json
import re
import sys

KV = re.compile(r'(\w+)=([^\s]+)')


def fields(line):
    return {k: v for k, v in KV.findall(line)}


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    path = argv[0]
    label = argv[argv.index('--label') + 1] if '--label' in argv else path
    requests = []
    cur = None
    for line in open(path, errors='replace'):
        if line.startswith('GPU_M8_OUTER_WINDOW open'):
            cur = {'encode': [], 'oods': [], 'host': [], 'node': []}
            requests.append(cur)
            continue
        if cur is None:
            continue
        if line.startswith('GPU_M8_OUTER_ENCODE ordinal='):
            cur['encode'].append(fields(line))
        elif line.startswith('GPU_M8_OUTER_OODS ordinal='):
            cur['oods'].append(fields(line))
        elif line.startswith('GPU_M8_OUTER_NODE_HOST'):
            cur['host'].append(fields(line))
        elif line.startswith('GPU_M8_OUTER_NODE ordinal='):
            cur['node'].append(fields(line))
    out = []
    for i, r in enumerate(requests):
        enc, oods, host, node = r['encode'], r['oods'], r['host'], r['node']
        s = lambda xs, k: sum(int(x.get(k, 0)) for x in xs)
        out.append({
            'request': i,
            'nodes': len(node),
            'encoded_nodes': len(enc),
            'encode_identical': sum(1 for e in enc if e.get('device_identical') == 'true' and e.get('mirror_identical') == 'true'),
            'encoded_bytes': s(enc, 'host_bytes'),
            'encode_gpu_ns_sum': s(enc, 'encode_gpu_ns'),
            'encode_gpu_ns_max': max([int(e.get('encode_gpu_ns', 0)) for e in enc] or [0]),
            'oods_nodes': len(oods),
            'oods_identical': sum(1 for o in oods if o.get('values_identical') == 'true' and o.get('verdict') == '0x0'),
            'oods_gpu_ns_sum': s(oods, 'oods_gpu_ns'),
            'node_gpu_ns_sum': s(node, 'gpu_ns'),
            'launches': [int(n.get('launches', 0)) for n in node],
            'outcomes': sorted({n.get('outcome', '?') for n in node}),
            'host_ns_sum': {k: s(host, k) for k in ('prestage_ns', 'init_ns', 'stage_ns', 'enqueue_ns', 'wait_ns', 'finish_ns', 'decode_ns', 'assemble_ns')},
            'mirror_ns_sum': s(enc, 'mirror_ns'),
        })
    print(json.dumps({'schema': 'rv64-m8-rnode-summary/v1', 'label': label, 'source': path, 'requests': out}, indent=1))


if __name__ == '__main__':
    main(sys.argv[1:])
