#!/usr/bin/env python3
"""Derive classic recursion cells from actual composed cold/warm proof logs."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

import rv64_m6_diet_receipt as D


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('package', type=Path)
    p.add_argument('--out', type=Path, required=True)
    args = p.parse_args()
    source = Path(__file__).resolve().parent.parent
    pinned = {
        'src/frontends/circuit/common/component_list.zig': 'd2f1e8facad581464f365958fb8e9fb9270fb28c09363b8361898df4136ceb2b',
        'scripts/rv64_m6_diet_receipt.py': 'ecbb608d8c20191f2765258109278eed9c93bfc7d62ec39e6fa729f04e2f1f6b',
    }
    for file, digest in pinned.items():
        if sha(source / file) != digest:
            raise RuntimeError('component-width authority changed: ' + file)
    out = {'schema': 'rv64-m7-composed-recursive-cells/v1', 'label': 'D',
           'author': 'OpenAI Codex',
           'scope': 'Derived actual padded recursion MAIN+INTER+gate-preprocessed cells, using measured per-proof row logs and pinned classic circuit component widths. Excludes native STARKs and LDE replication; counts the top fold once without double-counting its duplicate root export. Not a performance measurement.',
           'source_sha256': pinned, 'runs': []}
    for directory in sorted(args.package.iterdir()):
        log = directory / 'producer.stderr'
        if not log.is_file():
            continue
        text = log.read_text()
        logs = [tuple(int(x) for x in m.split(',')) for m in re.findall(r'^GPU_OUTER .*?logs=\{([^}]*)\}', text, re.M)]
        shapes = [(int(i), kind, tuple(int(x).bit_length() - 1 for x in rows.split(',')))
                  for i, kind, rows in re.findall(r'^RECURSION_NODE_SHAPE node=(\d+) kind=(\w+) .*?padded=\[([^\]]*)\]', text, re.M)]
        tree = json.loads((directory / 'trial-0/recursion-om31/tree.json').read_text())
        receipt = json.loads((directory / 'receipt.json').read_text())
        n = len(tree['nodes'])
        if len(logs) != 2*n or len(shapes) != n:
            raise RuntimeError('cold/warm node census incomplete: ' + directory.name)
        if {i for i, _, _ in shapes} != set(range(n)):
            raise RuntimeError('duplicate or missing source node id')
        markers = list(re.finditer(r'^GPU_RESIDENT_BLOCK block=(\d+) trial=(\d+) .*$', text, re.M))
        if len(markers) != 2 or len(receipt['requests']) != 2:
            raise RuntimeError('missing or duplicate request boundary')
        start = 0
        for trial, (marker, request) in enumerate(zip(markers, receipt['requests'])):
            if (int(marker[1]), int(marker[2])) != (request['block'], trial) or request['trial'] != trial:
                raise RuntimeError('foreign request scope')
            segment = text[start:marker.start()]
            if len(re.findall(r'^GPU_OUTER .*?logs=\{([^}]*)\}', segment, re.M)) != n:
                raise RuntimeError('request proof geometry count differs from actual tree')
            trial_tree = json.loads((directory / f'trial-{trial}/recursion-om31/tree.json').read_text())
            topology = lambda value: [(node['first_leaf'], node['leaf_count'], node['children']) for node in value['nodes']]
            if topology(trial_tree) != topology(tree):
                raise RuntimeError('cold/warm tree geometry changed')
            if sum(not node['children'] for node in trial_tree['nodes']) != request['leaves']:
                raise RuntimeError('tree native leaf count mismatch')
            start = marker.end()
        if re.search(r'^GPU_OUTER .*?logs=', text[start:], re.M):
            raise RuntimeError('unscoped proof geometry after final request')
        if Counter(logs[:n]) != Counter(logs[n:]):
            raise RuntimeError('warm committed geometries changed: ' + directory.name)
        unused = list(shapes)
        nodes = []
        for row_logs in logs[:n]:
            if len(row_logs) != len(D.COMPONENTS):
                raise RuntimeError('unexpected component roster')
            if row_logs[5:] != (16, 20, 8, 14, 18, 16) or any(log < 0 or log > 31 for log in row_logs):
                raise RuntimeError('classic component table schema changed')
            at = next((j for j, (_, _, pad) in enumerate(unused) if pad == row_logs[:5]), None)
            if at is None:
                raise RuntimeError('proof rows lack matching source shape')
            node, kind, _ = unused.pop(at)
            if bool(tree['nodes'][node]['children']) != (kind == 'fold'):
                raise RuntimeError('source node kind mismatch')
            nodes.append({'node': node, 'kind': kind, 'logs': row_logs, **D.cells(row_logs)})
        out['runs'].append({'configuration': directory.name, 'producer_stderr_sha256': sha(log),
                            'cold_warm_geometry_identical': True, 'nodes': len(nodes),
                            'cells': {key: sum(node[key] for node in nodes) for key in ['main', 'interaction', 'pp_gate_columns', 'total']},
                            'leaf_cells': sum(node['total'] for node in nodes if node['kind'] == 'leaf'),
                            'fold_cells': sum(node['total'] for node in nodes if node['kind'] == 'fold'),
                            'per_node': sorted(nodes, key=lambda node: node['node'])})
    args.out.write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps([{key: row[key] for key in ['configuration', 'nodes', 'cells']} for row in out['runs']], indent=2))


if __name__ == '__main__':
    main()
