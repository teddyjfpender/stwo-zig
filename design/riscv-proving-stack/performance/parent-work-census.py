#!/usr/bin/env python3
"""Summarize opt-in BLOCK_V5_PARENT_GEOMETRY logs; no timing predictions."""
import argparse
import json
from pathlib import Path


def analyze(text):
    parents = []
    current = []
    for line in text.splitlines():
        if not line.startswith('BLOCK_V5_PARENT_GEOMETRY '):
            continue
        fields = dict(part.split('=', 1) for part in line.split()[1:])
        row = {k: (v if k == 'air' else int(v)) for k, v in fields.items()}
        if row['cohort'] == 0 and current:
            parents.append(current)
            current = []
        width = row['fixed'] + row['main'] + row['interaction']
        if row['committed_cells'] != row['padded_rows'] * width:
            raise ValueError('inconsistent committed-cell count')
        if row['rows'] > row['padded_rows']:
            raise ValueError('invalid padded row count')
        row['unpadded_cells'] = row['rows'] * width
        row['padding_cells'] = row['committed_cells'] - row['unpadded_cells']
        current.append(row)
    if current:
        parents.append(current)
    if not parents:
        raise ValueError('no parent geometry found')
    result = []
    for rows in parents:
        if [r['cohort'] for r in rows] != list(range(len(rows))):
            raise ValueError('incomplete or interleaved cohort sequence')
        total = sum(r['committed_cells'] for r in rows)
        grouped = {}
        for row in rows:
            group = grouped.setdefault(row['air'], {'air': row['air'], 'rows': 0, 'committed_cells': 0, 'padding_cells': 0})
            for key in ('rows', 'committed_cells', 'padding_cells'):
                group[key] += row[key]
        for group in grouped.values():
            group['share_of_air_cells'] = group['committed_cells'] / total
        result.append({'air_cells': total, 'padding_cells': sum(r['padding_cells'] for r in rows), 'cohorts': len(rows), 'cohort_geometry': rows, 'groups': sorted(grouped.values(), key=lambda r: -r['committed_cells'])})
    return {'scope': 'AIR fixed/main/interaction commitment cells only; excludes lookup-provider tables, composition, PCS expansion, scratch and all timing. Sequential single-lane logs required.', 'parents': result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.log.read_text()), indent=2))
