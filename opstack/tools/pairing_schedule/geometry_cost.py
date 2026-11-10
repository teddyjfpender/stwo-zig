#!/usr/bin/env python3
"""Source-derived geometry comparison, not a proof or a timing prediction."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
REPORTS = ROOT / 'vectors/reports'
INPUTS = [
    REPORTS / 'rv64-opstack-performance-20261109/guest/composite-pairing-literal-fold-v1.json',
    REPORTS / 'rv64-opstack-performance-20261109/guest/composite-pairing-source-v1.json',
    REPORTS / 'rv64-opstack-cpu-20261110/g2-exact-subgroup-physical-v1.json',
    REPORTS / 'opstack-cpu-20261110/mac6-source-cost-v1.json',
]


def role(name, active, fixed, main, inter, byte_lanes=0, ssa_lanes=0):
    if active <= 0:
        raise ValueError('model requires positive active counts')
    log = max(5, (active - 1).bit_length())
    return dict(name=name, active=active, log=log, padded=1 << log,
                fixed=fixed, main=main, inter=inter,
                byte_lanes=byte_lanes, ssa_lanes=ssa_lanes)


def costs(roles):
    columns = {kind: sum(r[kind] for r in roles) for kind in ('fixed', 'main', 'inter')}
    cells = {kind: sum(r[kind] * r['padded'] for r in roles) for kind in columns}
    dimensions = [r['log'] + lanes.bit_length() - 1 for r in roles
                  for lanes in (r['byte_lanes'], r['ssa_lanes']) if lanes]
    max_log = max(r['log'] for r in roles)
    return dict(roles=roles, native_cells=cells, total_native_cells=sum(cells.values()),
                committed_columns=columns, total_committed_columns=sum(columns.values()),
                max_component_log=max_log,
                padded_GKR_facts=sum(r['padded'] * (r['byte_lanes'] + r['ssa_lanes']) for r in roles),
                GKR_instances=len(dimensions), GKR_max_variables=max(dimensions),
                GKR_instance_layer_records=sum(dimensions),
                uniform_height_leaf_payload_model=sum(columns.values()) * (1 << max_log),
                row_padding=sum(r['padded'] - r['active'] for r in roles))


def report():
    fold, source, sg, capacities = [json.loads(p.read_text()) for p in INPUTS]
    counts = source['counts']
    subgroup_rows = counts['subgroup_arithmetic']
    if subgroup_rows != 4 * sg['active_rows'][1]:
        raise ValueError('source and physical subgroup row counts disagree')
    stages = fold['after']['MAC12_rows']
    non_sg = fold['after']['nonSG_rows']
    if stages != non_sg + subgroup_rows:
        raise ValueError('inconsistent normalized source census')
    common = [role('private_hints', counts['total_hints'], 3, 95, 32, 64, 1),
              role('frontier', source['shared_authority']['initial_fields'] + counts['assertions'],
                   35, 33, 16, 0, 1), role('BYTE', 256, 1, 1, 16, 1)]
    universal = costs([role('MAC12', stages, 40, 1106, 32, 512, 32)] + common)
    pinned = next(x for x in capacities['pairing'] if x['capacity'] == 12)
    if (universal['total_native_cells'], universal['total_committed_columns'],
            universal['padded_GKR_facts']) != (pinned['native_cells'], pinned['opening_width'],
                                             pinned['padded_local_facts']):
        raise ValueError('universal geometry diverges from qualified source model')
    split = costs([role('MAC12_nonSG', non_sg, 40, 1106, 32, 512, 32),
                   role('exact_SG', subgroup_rows, sg['widths']['fixed'][1],
                        sg['widths']['main'][1], sg['widths']['inter'][1], 512, 8)] + common)
    return dict(schema='op-pairing-independent-geometry-model/v1',
                qualification='Counterfactual cost only: split component is not implemented or admitted',
                source_receipts={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in INPUTS}, universal_MAC12=universal,
                independently_sized_SG=split,
                ratios_split_over_universal={
                    'native_cells': split['total_native_cells'] / universal['total_native_cells'],
                    'opening_column_count': split['total_committed_columns'] / universal['total_committed_columns'],
                    'GKR_facts': split['padded_GKR_facts'] / universal['padded_GKR_facts'],
                    'uniform_height_leaf_payload': split['uniform_height_leaf_payload_model'] /
                                                   universal['uniform_height_leaf_payload_model']},
                limits=[
                    'Columns are not mask/OODS samples or recursive gates; no root speed prediction',
                    'Leaf payload assumes all columns are hashed at the family maximum height; not measured traffic',
                    'Existing narrow subgroup coefficients/IDs must be remapped and requalified in the composite',
                    'Shared Q/z and canonical unit-SSA writer/reader authority must survive the split',
                    'No source instance, FRI domain or transcript may be changed under an old admitted identity',
                    'Universal MAC12 physical integration remains the current first gate',
                ])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    encoded = json.dumps(report(), indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    else:
        print(encoded, end='')


if __name__ == '__main__':
    main()
