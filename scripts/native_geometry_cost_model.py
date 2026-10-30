#!/usr/bin/env python3
"""Offline B8 geometry inventory; candidate cell arithmetic is not a proof/time claim.

The statement prefix is decoded using the canonical fixed-width geometry wire:
Family:u8, InfraKind:u32, all dimensions:u32 little endian. Other statement
fields are deliberately not decoded or authenticated by this diagnostic.
"""
from __future__ import annotations
import argparse
import collections
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / 'src/frontends/riscv/opcode_manifest.zig'
WIRE = ROOT / 'src/frontends/riscv/prover/guest_precompile/proof_artifact_wire.zig'
CLOCK = ROOT / 'src/frontends/riscv/runner/state_chain.zig'
WIDTHS = {'base_alu_reg': 35, 'base_alu_imm': 35, 'shifts_reg': 60, 'shifts_imm': 51,
          'lt_reg': 44, 'lt_imm': 37, 'branch_eq': 30, 'branch_lt': 37, 'lui': 18,
          'auipc': 29, 'jalr': 41, 'jal': 20, 'load_store': 50, 'mul': 39, 'mulh': 47,
          'div': 67, 'fence': 6}

def identity(path: Path) -> dict:
    data = path.read_bytes()
    return {'path': str(path.resolve()), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

def geometry(shape_hex: str) -> dict:
    families = re.search(r'pub const Family = enum\(u8\) \{(.*?)\n\};', FAMILY.read_text(), re.S)
    if not families:
        raise ValueError('canonical family enum was changed')
    names = re.findall(r'^\s*(\w+),', families.group(1), re.M)
    data = bytes.fromhex(shape_hex)
    cursor = 0
    def take(fmt):
        nonlocal cursor
        size = struct.calcsize(fmt)
        if cursor + size > len(data):
            raise ValueError('truncated statement geometry')
        result = struct.unpack_from(fmt, data, cursor)
        cursor += size
        return result
    count, = take('<I')
    if not 0 < count <= 256:
        raise ValueError('invalid component count')
    shards = []
    for index in range(count):
        family, log, rows, columns = take('<BIII')
        if family >= len(names) or not 1 <= log <= 24 or not 0 < rows <= 1 << log:
            raise ValueError('invalid native geometry')
        name = names[family]
        if columns != WIDTHS[name]:
            raise ValueError(f'unreviewed native width for {name}: {columns}')
        shards.append(dict(index=index, family=name, log=log, rows=rows, columns=columns))
    initial_pc, final_pc, cycles, infra_count = take('<IIII')
    if sum(x['rows'] for x in shards) != cycles or infra_count > 512:
        raise ValueError('native row census differs from cycles')
    infra = []
    for index in range(infra_count):
        kind, log, rows, columns = take('<IIII')
        if kind != 2 or columns != 10 or not 1 <= log <= 24 or not 0 < rows <= 1 << log:
            raise ValueError('unreviewed infrastructure geometry')
        infra.append(dict(index=index, kind='clock_update', log=log, rows=rows, columns=columns))
    public_initial, public_final, public_cycles = take('<III')
    if (public_initial, public_final, public_cycles) != (initial_pc, final_pc, cycles):
        raise ValueError('public geometry disagrees with statement')
    return dict(cycles=cycles, initial_pc=initial_pc, final_pc=final_pc, shards=shards, infrastructure=infra,
                decoded_prefix_bytes=cursor, full_statement_bytes=len(data), authenticates_statement=False)

def model(metadata_path: Path, census_path: Path) -> dict:
    metadata = json.loads(metadata_path.read_text())
    census = json.loads(census_path.read_text())
    if census['schema'] != 'stwo-b8-endpoint-root-source-full-cells-v1':
        raise ValueError('unsupported full source census')
    decoded = geometry(metadata['shape'])
    grouped = collections.defaultdict(list)
    for shard in decoded['shards']:
        grouped[shard['family']].append(shard)
    families = []
    for name, shards in grouped.items():
        rows = sum(x['rows'] for x in shards)
        padded = sum(1 << x['log'] for x in shards)
        width = shards[0]['columns']
        families.append(dict(family=name, shards=len(shards), width=width, rows=rows, padded_rows=padded,
                             main_cells=width*padded, padding_cells=width*(padded-rows),
                             row_percent=100*rows/decoded['cycles'], main_cells_per_real_instruction=width*padded/rows))
    families.sort(key=lambda x: x['main_cells'], reverse=True)
    infrastructure = []
    for item in decoded['infrastructure']:
        padded = 1 << item['log']
        infrastructure.append(dict(**item, padded_rows=padded, main_cells=10*padded,
                                   fixed_cells=2*padded, interaction_cells=16*padded,
                                   q1_direct_domain_rows=2*padded, q2_projection_domain_rows=4*padded))
    raw_native = sum(x['main_cells'] for x in families) + sum(x['main_cells'] for x in infrastructure)
    lsu = next(x for x in families if x['family'] == 'load_store')
    guard_cells = 2*lsu['padded_rows']
    if raw_native + guard_cells != census['native']['main']['cells'] or guard_cells != census['native_guard_main_cells']:
        raise ValueError('decoded geometry and independently supplied native census disagree')
    tree_raw = sum(x['raw_cells'] for x in census['trees'])
    tree_extended = sum(x['extended_cells'] for x in census['trees'])
    if (tree_raw, tree_extended) != (census['total_raw_cells'], census['total_extended_cells']):
        raise ValueError('full tree inventory totals disagree')
    old_clock_padded = sum(x['padded_rows'] for x in infrastructure)
    old_clock_rows = sum(x['rows'] for x in infrastructure)
    max_clock = 4*decoded['cycles'] - 1
    max_register_hops = 32*((max_clock-1)//((1 << 20)-1))
    register_padded_bound = 1 << max(1, (max_register_hops-1).bit_length()) if max_register_hops else 0
    old_clock_cells = old_clock_padded*(10+2+16)
    retained_register_cells_bound = register_padded_bound*(10+2+16)
    new_gap_main_cells = 3*lsu['padded_rows']
    # Conservative: add two independent pair accumulators per LSU shard and
    # a new separately scoped range16 provider; no credit for old RAM-gap
    # range20 queries/provider multiplicities that V3 would remove.
    new_gap_interaction_cells_upper = 8*lsu['padded_rows']
    new_range_provider_cells_upper = 11*(1 << 16)
    composition = census['trees'][-1]
    if any(x['maximum_raw_log'] > 20 for x in census['trees'][2:7] + census['trees'][8:-1]) or any(x['log'] > 20 for x in decoded['shards']):
        raise ValueError('non-clock provider exceeds the reviewed candidate composition log')
    candidate_composition_log = 20
    composition_cells_candidate = composition['columns']*(1 << candidate_composition_log)
    composition_cells_saved = max(0, composition['raw_cells']-composition_cells_candidate)
    candidate_raw_upper = (tree_raw-old_clock_cells+retained_register_cells_bound+new_gap_main_cells+
                           new_gap_interaction_cells_upper+new_range_provider_cells_upper-composition_cells_saved)
    return dict(schema='stwo-b8-native-geometry-cost-model-v1',
                boundary='offline exact cell inventory plus unqualified V3 arithmetic scenario; no runtime/proof qualification',
                inputs={'metadata': identity(metadata_path), 'full_census': identity(census_path)},
                geometry_sources=[identity(p) for p in [FAMILY, WIRE, CLOCK]],
                geometry=decoded, families=families, infrastructure=infrastructure,
                native=dict(raw_main_without_guards=raw_native, halt_guard_cells=guard_cells,
                            main_with_guards=raw_native+guard_cells, fixed=census['native']['fixed'],
                            interaction=census['native']['interaction'],
                            padding_main_cells=sum(x['padding_cells'] for x in families)+sum(10*(x['padded_rows']-x['rows']) for x in infrastructure)),
                all_trees=census['trees'], total_raw_cells=tree_raw, total_extended_cells=tree_extended,
                v3_scenario=dict(qualified=False, baseline_default_changed=False,
                    rationale='RAM gap hops dominate: register hops have a deterministic 32-register upper bound',
                    synthetic_rows=old_clock_rows, register_hop_upper_bound=max_register_hops,
                    ram_hop_lower_bound=max(0,old_clock_rows-max_register_hops),
                    old_clock_all_tree_cells=old_clock_cells, retained_register_all_tree_cells_upper=retained_register_cells_bound,
                    new_gap_main_cells=new_gap_main_cells, new_gap_interaction_cells_upper=new_gap_interaction_cells_upper,
                    new_separate_range16_provider_cells_upper=new_range_provider_cells_upper,
                    candidate_composition_raw_log=candidate_composition_log, composition_cells_saved=composition_cells_saved,
                    candidate_total_raw_cells_upper_under_assumptions=candidate_raw_upper,
                    modeled_raw_cell_reduction=tree_raw/candidate_raw_upper,
                    assumptions=['all non-clock existing raw logs <=20; new V3 components respect that bound',
                                 'current and predecessor access clocks independently authenticated below 2^27',
                                 'three new LSU cells low16/high11/slack11 and three actual range16 supplies',
                                 'retain source gap10 for stores and destination gap13 for loads; retain base register gap5',
                                 'new V3 typed authority, source roster, RAM endpoint closure and session dispatch required'],
                    measured_runtime_speedup=None))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--metadata', required=True, type=Path)
    parser.add_argument('--census', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = model(args.metadata, args.census)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    print(json.dumps({'output':str(args.output), 'total_raw_cells':result['total_raw_cells'],
                      'v3_modeled_raw_cell_reduction':result['v3_scenario']['modeled_raw_cell_reduction'],
                      'qualified':False}))
if __name__ == '__main__':
    main()
