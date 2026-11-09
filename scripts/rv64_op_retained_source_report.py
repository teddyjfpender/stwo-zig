#!/usr/bin/env python3
"""Witness-free OP retained-owner timeline. Does not execute or prove a guest.

Inputs are frozen source declarations/costs and a compiler-produced ABI-size
manifest. Reported payloads are not RSS/admission: prover/FFT scratch, child proof
artifacts, allocation capacities and some transient source construction coexist.
"""
import argparse
import hashlib
import json
from pathlib import Path


def load(path):
    return json.loads(Path(path).read_text())


def derive(plan, costs, seal, sizes, truths):
    metadata = plan['metadata']
    count = len(metadata['cpus'])
    if count == 0 or any(len(rows) != count for rows in
                         (metadata['requests'], metadata['spans'], costs['cpus'], seal['cpus'])):
        raise ValueError('CPU declarations, requests, spans, costs and seal records must have equal nonzero lengths')
    if sum(row['steps'] for row in costs['cpus']) != plan['steps']:
        raise ValueError('CPU cost steps do not cover the frozen execution')
    for ordinal, (cost, child) in enumerate(zip(costs['cpus'], seal['cpus'])):
        if cost['ordinal'] != ordinal or child['ordinal'] != ordinal:
            raise ValueError('CPU cost/seal records are reordered or duplicated')
        if metadata['requests'][ordinal]['cpu']['steps'] != cost['steps']:
            raise ValueError('CPU request/cost step counts differ')
        if child['main_coefficients'] != cost['main_coefficient_bytes'] or child['main_merkle_upper'] != cost['merkle_node_bytes']:
            raise ValueError('CPU seal/cost commitment geometry differs')
    known_origins = {
        'core': {'alu', 'alu_tail', 'and_table', 'binary', 'binary_tail', 'boundary', 'cpu',
                 'division', 'initial', 'jalr', 'ls', 'ls_tail', 'multiplication', 'range16',
                 'range8', 'rom', 'selection', 'shift', 'shift_table', 'shift_tail', 'terminal'},
        'bridge': {'keccak', 'add', 'double', 'sha256', 'arith256_mod', 'bn254_g1_add',
                   'bn254_g1_double', 'bn254_fp2_mul', 'bls12_381_fp2_mul', 'arith384_mont',
                   'bls12_381_g1_add', 'bls12_381_g1_double'},
        'bulk': {'cdesc', 'cmp', 'copy', 'desc', 'jdesc', 'jscan', 'jtab', 'set', 'ucopy'},
        'sponge': {'call', 'perm'}, 'dword': {0, 1},
    }
    for cost in costs['cpus']:
        for role in cost['roles']:
            origin = role['origin']
            if len(origin) != 1:
                raise ValueError('Role must have exactly one source origin')
            kind, name = next(iter(origin.items()))
            if not ((kind == 'tower' and name == {}) or
                    (kind in known_origins and not isinstance(name, (dict, list)) and name in known_origins[kind])):
                raise ValueError(f'Unreviewed retained source owner: {origin!r}')
            if not 0 <= role['log'] < 32 or not 0 <= role['active_rows'] <= (1 << role['log']) or len(role['widths']) != 3:
                raise ValueError('Role geometry is malformed')
    histogram = 8 * (65536 + 256)
    source_fixed_roles = {'alu', 'alu_tail', 'binary', 'binary_tail', 'shift', 'shift_tail',
                          'jalr', 'division', 'multiplication', 'ls', 'ls_tail', 'initial', 'terminal', 'selection'}
    metadata_roles = {'alu': 'alu', 'binary': 'binary', 'shift': 'shift',
                      'division': 'division', 'multiplication': 'multiplication',
                      'ls': 'ls32', 'initial': 'boundary', 'terminal': 'boundary'}
    curve_names = ['bn254_g1_add', 'bn254_g1_double', 'bn254_fp2_mul', 'bls12_381_fp2_mul',
                   'arith384_mont', 'bls12_381_g1_add', 'bls12_381_g1_double']
    result = []
    native_total = 0
    all_cpu_metadata = plan['steps'] * sizes['cpu_metadata']
    for declaration, compact, span, cost, child in zip(metadata['cpus'], metadata['requests'], metadata['spans'], costs['cpus'], seal['cpus']):
        roles = cost['roles']
        counters = {'tuple_metadata': 0, 'raw_fixed_masks': 0, 'histograms_and_saved_tables': 2 * histogram,
                    'service_and_bulk_copies_lower': 0, 'service_and_bulk_copies_upper': 0}
        retired = {'ordinary_capture_events': 0, 'temporary_family_facts': 0}
        aux = {'ls_raw_fixed_masks': 0, 'shift_semantic_histograms': 0}
        bulk = compact.get('bulk', {})
        all_bulk_calls = sum(bulk.get(k, 0) for k in ['calls', 'cmp_calls', 'jump_calls'])
        normal_bulk_words = sum(bulk.get(k, 0) for k in ['copy_words', 'set_words', 'ucopy_rows', 'cmp_words'])
        jump_rows, jump_calls = bulk.get('jump_rows', 0), bulk.get('jump_calls', 0)
        bulk_words_hi = normal_bulk_words + 9 * jump_rows
        bulk_words_lo = normal_bulk_words + 9 * jump_rows - 7 * jump_calls
        bridge_calls = dict(zip(['keccak', 'add', 'double'], compact['calls']))
        bridge_calls['sha256'] = compact.get('sha256_calls', 0)
        bridge_calls['arith256_mod'] = compact.get('arith256_mod_calls', 0)
        bridge_calls.update(zip(curve_names, compact.get('curve_calls', [0] * 7)))
        moved = 8 * ((1 << 20) + 65536 + 256)
        native = cost['steps'] * sizes['cpu_metadata'] + moved
        for role in roles:
            origin, rows, active = role['origin'], 1 << role['log'], role['active_rows']
            kind, name = next(iter(origin.items()))
            if kind == 'core':
                base = name.removesuffix('_tail')
                if base in ['alu', 'binary', 'shift']:
                    retired['temporary_family_facts'] += active * (sizes[base + '_native_fact'] + 4)
                elif name in ['division', 'multiplication']:
                    retired['temporary_family_facts'] += active * sizes[name + '_native_fact']
                elif name == 'jalr':
                    moved += active * sizes['jalr_fact']
                    native += active * sizes['jalr_fact']  # moved, not a new source allocation
                if base in metadata_roles:
                    count = active if base == 'multiplication' else rows
                    counters['tuple_metadata'] += count * sizes[metadata_roles[base] + '_metadata']
                if name in source_fixed_roles:
                    fixed = rows * role['widths'][0] * sizes['m31']
                    counters['raw_fixed_masks'] += fixed
                    if base == 'ls':
                        aux['ls_raw_fixed_masks'] += fixed
                if base == 'alu' or base == 'binary' or name == 'division':
                    counters['histograms_and_saved_tables'] += 8 * 65536
                if base == 'shift':
                    counters['histograms_and_saved_tables'] += 8 * ((1 << 20) + 65536)
                    aux['shift_semantic_histograms'] += 8 * (1 << 20)
                if base == 'ls':
                    counters['histograms_and_saved_tables'] += histogram + 8 * 131072
                    retired['ordinary_capture_events'] += active * sizes['ordinary_event']
                if name == 'and_table':
                    counters['histograms_and_saved_tables'] += rows * role['widths'][1] * 4 + rows * 4
                if name == 'shift_table':
                    counters['histograms_and_saved_tables'] += rows * role['widths'][1] * 4
            elif kind == 'dword':
                counters['tuple_metadata'] += rows * sizes['ls64_metadata']
                fixed = rows * role['widths'][0] * 4
                counters['raw_fixed_masks'] += fixed
                aux['ls_raw_fixed_masks'] += fixed
                counters['histograms_and_saved_tables'] += histogram
                retired['ordinary_capture_events'] += active * sizes['ordinary_event']
            else:
                counters['raw_fixed_masks'] += rows * role['widths'][0] * 4
                counters['histograms_and_saved_tables'] += histogram
                if kind == 'bridge':
                    payload = bridge_calls[name] * sizes['bridge_call']
                    counters['service_and_bulk_copies_lower'] += payload
                    counters['service_and_bulk_copies_upper'] += payload
                elif kind == 'tower':
                    payload = span['calls'] * sizes['tower_call']
                    counters['service_and_bulk_copies_lower'] += payload
                    counters['service_and_bulk_copies_upper'] += payload
                elif kind == 'bulk':
                    constant = all_bulk_calls * (sizes['bulk_call'] + 4) + active * 8
                    constant += active if name == 'jscan' else 8448 * 4 if name == 'jtab' else 0
                    counters['service_and_bulk_copies_lower'] += constant + bulk_words_lo * sizes['bulk_word']
                    counters['service_and_bulk_copies_upper'] += constant + bulk_words_hi * sizes['bulk_word']
                elif kind == 'sponge' and name == 'perm':
                    counters['histograms_and_saved_tables'] += 8 * 65536
        # The memory wrapper owns its merged histograms; with an LS tail it also
        # owns a merged selection histogram separate from either LS owner.
        if declaration['geometry'].get('ls_tail_log') is not None:
            counters['histograms_and_saved_tables'] += 8 * 131072
        # Omitted DIV still constructs the minimal inactive source in sources.zig.
        if declaration['geometry'].get('omit_empty_division', False):
            n = 1 << declaration['geometry']['division_log']
            counters['tuple_metadata'] += n * sizes['division_metadata']
            counters['raw_fixed_masks'] += 3 * n * 4
            counters['histograms_and_saved_tables'] += 8 * 65536
        sponge = compact.get('sponge', {})
        calls, perms = sponge.get('calls', 0), sponge.get('perms', 0)
        constant = calls * sizes['sponge_call'] + perms * (sizes['sponge_permutation'] + 4)
        # Packet.words<=17*permutations+1 per call, from RATE=136 and shift<=7.
        counters['service_and_bulk_copies_lower'] += constant
        counters['service_and_bulk_copies_upper'] += constant + (17 * perms + calls) * sizes['sponge_word']
        # Only the first/last CPU shard owns new copies of these public lists.
        public_copies = sum(role['active_rows'] * sizes['cell'] for role in roles
                            if role['origin'].get('core') in ['initial', 'terminal'])
        counters['tuple_metadata'] += public_copies
        native += retired['temporary_family_facts']
        native_total += native
        retained_lo = sum(counters[k] for k in ['tuple_metadata', 'raw_fixed_masks', 'histograms_and_saved_tables', 'service_and_bulk_copies_lower'])
        retained_hi = retained_lo - counters['service_and_bulk_copies_lower'] + counters['service_and_bulk_copies_upper']
        result.append({'ordinal': cost['ordinal'], 'source_owned_payload': counters,
                       'retired_capture_payload': retired, 'qualified_auxiliary_retirement': aux,
                       'new_source_retained_lower': retained_lo, 'new_source_retained_upper': retained_hi,
                       'cpu_metadata_active': cost['steps'] * sizes['cpu_metadata'], 'moved_capture_counts_and_jalr': moved,
                       'main_coefficients': cost['main_coefficient_bytes'], 'main_merkle_upper': cost['merkle_node_bytes'],
                       'interaction_payload': cost['interaction_bytes'], 'local_gkr_peak': child['source_checkpoint_plan']['peak_bytes']})
    if native_total != costs['native_capture_payload_bytes']:
        raise ValueError(f"Native capture payload mismatch: {native_total} != {costs['native_capture_payload_bytes']}")
    if sum(x['retired_capture_payload']['ordinary_capture_events'] for x in result) != costs['advice_capture_payload']['ordinary_events']:
        raise ValueError('Ordinary capture event payload mismatch')
    baseline = seal['measured_retained_capture_and_setup_baseline']
    live = baseline - all_cpu_metadata
    timeline = []
    for row in result:
        retired = sum(row['retired_capture_payload'].values())
        retained = row['new_source_retained_upper']
        constructed = live + row['cpu_metadata_active'] + retained - retired
        transient = row['main_coefficients'] + row['main_merkle_upper']
        child_peak = constructed + transient + row['local_gkr_peak']
        live = constructed - row['cpu_metadata_active'] - sum(row['qualified_auxiliary_retirement'].values())
        timeline.append({'ordinal': row['ordinal'], 'seal_payload_upper_excluding_unmodeled_scratch': child_peak,
                         'after_seal_park_payload_upper': live})
    truth_metadata = sum(row['retained_metadata_bound'] for row in truths)
    miller_metadata = sum(row['declaration']['calls'] * sizes['miller_advice_per_call'] + sizes['miller_advice_per_worker'] for row in costs['miller'])
    service_stage1 = []
    service_live = live
    for ordinal, row in enumerate(truths):
        # Local resource plan already covers its own retained metadata/PCS
        # payload; classic worker whole cap is a deliberately looser envelope.
        working = row['local_gkr']['whole_peak_bytes'] if row['local_gkr'] else 8 << 30
        service_stage1.append({'truth_ordinal': ordinal, 'family': row['declaration']['family'],
                               'whole_worker_payload_envelope_with_cpu_barrier': service_live + working,
                               'worker_bound_kind': 'reviewed-local-resource-plan' if row['local_gkr'] else 'explicit-whole-worker-cap'})
        service_live += row['retained_metadata_bound']
    service_stage1.append({'miller_workers': len(costs['miller']), 'retained_metadata_total': miller_metadata,
                           'last_miller_whole_worker_cap_envelope': service_live + miller_metadata + (8 << 30)})
    live += truth_metadata + miller_metadata
    stage2 = []
    for row in result:
        restore = live + row['cpu_metadata_active'] + row['main_coefficients'] + row['main_merkle_upper']
        # Both generated interaction evaluations and compact coefficients can
        # coexist during commit; one full extra tree is a conservative envelope.
        proving = restore + 2 * row['interaction_payload'] + row['main_merkle_upper']
        stage2.append({'ordinal': row['ordinal'], 'restore_payload_upper': restore,
                       'interaction_commit_payload_upper_excluding_pcs_scratch': proving})
        live -= row['new_source_retained_upper'] - sum(row['qualified_auxiliary_retirement'].values()) + row['moved_capture_counts_and_jalr']
    return {'schema': 'op-retained-source-lifetime-model/v1', 'heavy_execution_or_proof_rerun': False,
            'admission_or_rss_guarantee': False, 'compiled_sizes': sizes,
            'exact_reconstructed_native_capture_payload': native_total,
            'all_cpu_metadata_parked': all_cpu_metadata, 'cpus': result,
            'cpu_stage_one_timeline': timeline, 'cpu_stage_two_timeline': stage2,
            'truth_plans': truths, 'truth_retained_metadata_bound': truth_metadata,
            'classic_miller_retained_advice_bound': miller_metadata, 'service_stage_one_envelopes': service_stage1,
            'cpu_barrier_payload_upper': timeline[-1]['after_seal_park_payload_upper'],
            'maximum_seal_payload_upper': max(x['seal_payload_upper_excluding_unmodeled_scratch'] for x in timeline),
            'maximum_interaction_commit_payload_upper': max(x['interaction_commit_payload_upper_excluding_pcs_scratch'] for x in stage2),
            'not_yet_in_cpu_timeline': ['local child proof/artifact/header payloads not included in reviewed durable metadata figures', 'FFT/composition/PCS scratch and allocator headers', 'source-construction overlap with retired arrays', 'immutable FIXED lease mappings', 'schema2 immutable-key difference from measured schema1 setup baseline'],
            'bounds_notes': ['Bulk source copies every call/word list once per present kind, not merely matching facts.',
                             'Bulk JUMPDEST word interval uses ceil(codeWords/8); frozen aggregate counts omit exact codeWord lengths.',
                             'Sponge input-word interval uses packet words<=17*permutations+calls.',
                             'CPU ROM/range histograms and JALR facts move from capture and are not counted as new source allocations.',
                             'Generated provider metadata replaces freed capture family facts; LS metadata replaces consumed events.',
                             'Service advice remains captured for truth producers; copied CPU bridge advice is additional.',
                             'Only LS/D64 fixed masks and SHIFT semantic histograms use the qualified postseal auxiliary retirement.']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for key in ['plan', 'cost', 'seal', 'sizes', 'truths', 'output']:
        p.add_argument('--' + key, required=True)
    a = p.parse_args()
    report = derive(load(a.plan), load(a.cost), load(a.seal), load(a.sizes), load(a.truths))
    report['input_sha256'] = {
        key: hashlib.sha256(Path(getattr(a, key)).read_bytes()).hexdigest()
        for key in ['plan', 'cost', 'seal', 'sizes', 'truths']
    }
    Path(a.output).write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ['exact_reconstructed_native_capture_payload', 'cpu_barrier_payload_upper', 'maximum_seal_payload_upper', 'maximum_interaction_commit_payload_upper']}))


if __name__ == '__main__':
    main()
