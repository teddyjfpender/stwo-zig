#!/usr/bin/env python3
"""Summarise gn-node receipts: piece-harness lines (GN_NODE_HARNESS / GN_NODE_NEGATIVE /
GN_NODE_HARNESS_SUMMARY) and in-service check lines (GN_NODE / GPU_M8_OUTER_NODE[_HOST]) into JSON.

usage: rv64_m8_gn_node_summary.py harness <log> | service <producer.stderr> [<frozen-parity proof.json>]
"""
import json, re, sys
from pathlib import Path

KV = re.compile(r'(\w+)=(\S+)')


def fields(line):
    out = {}
    for k, v in KV.findall(line):
        if v in ('true', 'false'):
            out[k] = v == 'true'
        else:
            try:
                out[k] = int(v, 0) if not v.startswith('0x') else int(v, 16)
            except ValueError:
                out[k] = v
    return out


def harness(path):
    nodes, negatives, summary = [], [], None
    for line in Path(path).read_text(errors='replace').splitlines():
        if line.startswith('GN_NODE_HARNESS_SUMMARY'):
            summary = fields(line)
        elif line.startswith('GN_NODE_HARNESS '):
            nodes.append(fields(line))
        elif line.startswith('GN_NODE_NEGATIVE'):
            negatives.append(fields(line))
    folds = [n for n in nodes if n.get('kind') == 'fold']
    leaves = [n for n in nodes if n.get('kind') == 'leaf']
    def stat(rows, key):
        v = [r[key] for r in rows if isinstance(r.get(key), int)]
        return {'n': len(v), 'min': min(v), 'max': max(v), 'sum': sum(v)} if v else None
    return {'schema': 'rv64-m8-gn-node-harness/v1', 'label': '[M]', 'summary': summary,
            'folds': {'n': len(folds), 'seeds_identical': sum(1 for n in folds if n.get('seeds_identical')),
                      'device_seeds_identical': sum(1 for n in folds if n.get('device_seeds_identical')),
                      'device_outputs_identical': sum(1 for n in folds if n.get('device_outputs_identical')),
                      'device_checkpoint_identical': sum(1 for n in folds if n.get('device_checkpoint_identical')),
                      'gpu_us': stat(folds, 'gpu_us'), 'host_enqueue_ns': stat(folds, 'host_enqueue_ns'),
                      'mirror_ns': stat(folds, 'mirror_ns'), 'warm_ns': stat(folds, 'warm_ns'), 'seeds': stat(folds, 'seeds')},
            'leaves': {'n': len(leaves), 'seeds_identical': sum(1 for n in leaves if n.get('seeds_identical')),
                       'device_seeds_identical': sum(1 for n in leaves if n.get('device_seeds_identical')),
                       'device_checkpoint_identical': sum(1 for n in leaves if n.get('device_checkpoint_identical')),
                       'gpu_us': stat(leaves, 'gpu_us'), 'host_enqueue_ns': stat(leaves, 'host_enqueue_ns'),
                       'proof_seeds': stat(leaves, 'proof_seeds'), 'tail_seeds': stat(leaves, 'tail_seeds')},
            'negatives': negatives, 'nodes': nodes}


def service(path, proof=None):
    gn, node, host = [], {}, {}
    for line in Path(path).read_text(errors='replace').splitlines():
        if line.startswith('GN_NODE ordinal='):
            gn.append(fields(line))
        elif line.startswith('GPU_M8_OUTER_NODE ordinal='):
            f = fields(line)
            node.setdefault(f['ordinal'], []).append(f)
        elif line.startswith('GPU_M8_OUTER_NODE_HOST'):
            f = fields(line)
            host.setdefault(f['ordinal'], []).append(f)
    out = {'schema': 'rv64-m8-gn-node-service/v1', 'label': '[M]', 'gn_nodes': len(gn),
           'outputs_identical': sum(1 for g in gn if g.get('outputs_identical')),
           'checkpoint_identical': sum(1 for g in gn if g.get('checkpoint_identical')),
           'accepted': sum(1 for g in gn if g.get('seed_tape') == 0 and g.get('child_binding') == 0),
           'seed_gpu_ns_sum': sum(g.get('seed_gpu_ns', 0) for g in gn),
           'seed_host_ns_sum': sum(g.get('seed_host_ns', 0) for g in gn),
           'outcomes': sorted({r.get('outcome') for rows in node.values() for r in rows}),
           'launches_per_node': sorted({r.get('launches') for rows in node.values() for r in rows}),
           'gn': gn}
    if proof:
        p = json.loads(Path(proof).read_text())
        out['frozen_parity'] = p.get('parity'); out['status'] = p.get('status')
    return out


if __name__ == '__main__':
    mode = sys.argv[1]
    result = harness(sys.argv[2]) if mode == 'harness' else service(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    print(json.dumps(result, indent=1))
