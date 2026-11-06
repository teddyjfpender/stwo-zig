#!/usr/bin/env python3
"""Compact node x stage peak table from node_peaks_parser.py JSON (M8 memory).

Per recursion node (domain 1): node-attributed concurrent rounded peak, the
stage holding it, and the device-global rounded peak while the node ran
(node + shared + any co-resident reservation). Per stage: rounded peak and
starting baseline. Decimal GB. Allocator reservations, not GPU-completion
physical residency (observer host-joins at stage boundaries).

  rv64_m8_node_stage_table.py node-peaks.json [--request 1] --markdown OUT.md --json OUT.json
"""
import argparse
import json
from pathlib import Path


def gb(value):
    return round(value / 1e9, 3)


def build(summary, request_index):
    request = summary['requests'][request_index]
    columns = summary['stage_columns']
    rows = [dict(zip(columns, values)) for values in request['stage_rows']]
    nodes, native = {}, []
    for row in rows:
        (nodes.setdefault(row['ordinal'], []) if row['domain'] == 1 else native).append(row)
    table = []
    for ordinal in sorted(nodes):
        xs = nodes[ordinal]
        top = max(xs, key=lambda x: x['rounded_reservation_peak_bytes'])
        table.append({
            'ordinal': ordinal, 'device': top['device'],
            'node_peak_gb': gb(top['rounded_reservation_peak_bytes']), 'peak_stage': top['stage'],
            'global_peak_gb': gb(max(x['global_rounded_peak_bytes'] for x in xs)),
            'shared_baseline_max_gb': gb(max(x['shared_unattributed_baseline_bytes'] for x in xs)),
            'stages': {x['stage']: {'peak_gb': gb(x['rounded_reservation_peak_bytes']),
                                    'baseline_gb': gb(x['baseline_rounded_bytes']),
                                    'end_gb': gb(x['end_rounded_bytes'])} for x in xs if x['stage'] not in ('fixed_ingress', 'fixed_commit', 'fixed_adoption')},
        })
    native_top = sorted(native, key=lambda x: -x['rounded_reservation_peak_bytes'])[:8]
    return {
        'schema': 'rv64-m8-node-stage-table/v1', 'label': '[M] allocator reservations (observer), not physical residency',
        'request': request_index, 'completion': request['completion'], 'nodes': table,
        'native_top_stages': [{'ordinal': x['ordinal'], 'stage': x['stage'], 'device': x['device'],
                               'peak_gb': gb(x['rounded_reservation_peak_bytes']),
                               'global_peak_gb': gb(x['global_rounded_peak_bytes'])} for x in native_top],
    }


def markdown(t):
    stages = []
    for n in t['nodes']:
        for s in n['stages']:
            if s not in stages:
                stages.append(s)
    out = [f"Request {t['request']} ({t['completion']['block'] if t['completion'] else '?'}), {t['label']}. Decimal GB.", "",
           "| Node | GPU | Node peak | Peak stage | Device-global peak | Shared baseline max | " + " | ".join(stages) + " |",
           "|---:|---:|---:|---|---:|---:|" + "---:|" * len(stages)]
    for n in t['nodes']:
        cells = [f"{n['stages'][s]['peak_gb']:.2f}" if s in n['stages'] else '' for s in stages]
        out.append(f"| {n['ordinal']} | {n['device']} | {n['node_peak_gb']:.2f} | {n['peak_stage']} | {n['global_peak_gb']:.2f} | "
                   f"{n['shared_baseline_max_gb']:.2f} | " + " | ".join(cells) + " |")
    out += ["", "Largest native (domain 2) stages:", "", "| Ordinal | Stage | GPU | Stage peak | Device-global peak |", "|---:|---|---:|---:|---:|"]
    for x in t['native_top_stages']:
        out.append(f"| {x['ordinal']} | {x['stage']} | {x['device']} | {x['peak_gb']:.2f} | {x['global_peak_gb']:.2f} |")
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('summary', type=Path)
    p.add_argument('--request', type=int, default=1, help='0 = cold, 1 = warm')
    p.add_argument('--markdown', type=Path)
    p.add_argument('--json', type=Path)
    args = p.parse_args()
    table = build(json.loads(args.summary.read_text()), args.request)
    text = markdown(table)
    if args.markdown:
        args.markdown.write_text(text)
    if args.json:
        args.json.write_text(json.dumps(table, indent=1) + "\n")
    print(text)


if __name__ == '__main__':
    main()
