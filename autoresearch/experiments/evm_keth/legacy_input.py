"""Narrow, witness-preserving schema bridge for the pinned Keth adapter.

9223254 -> 82f2125: three opcode names, eight builtin names, and inst_cache
becomes pc_count. This does not translate a proof or change an AIR constraint.
Every result still needs Zig proving and independent official verification.
"""
from __future__ import annotations

import json
from pathlib import Path
import array
import struct
import sys
import argparse

OPCODES = ('generic_opcode add_ap_opcode add_opcode add_opcode_small '
           'assert_eq_opcode assert_eq_opcode_double_deref assert_eq_opcode_imm '
           'call_opcode call_opcode_rel_imm jnz_opcode jnz_opcode_taken '
           'jump_opcode_rel_imm jump_opcode_rel jump_opcode_double_deref '
           'jump_opcode mul_opcode_small mul_opcode ret_opcode '
           'blake_compress_opcode qm_31_add_mul_opcode').split()
OPCODE_RENAMES = {'call_opcode': 'call_opcode_abs', 'jnz_opcode': 'jnz_opcode_non_taken',
                  'jump_opcode': 'jump_opcode_abs'}
BUILTINS = {'add_mod': 'add_mod_builtin', 'bitwise': 'bitwise_builtin',
            'output': 'output', 'mul_mod': 'mul_mod_builtin',
            'pedersen': 'pedersen_builtin', 'poseidon': 'poseidon_builtin',
            'range_check_bits_96': 'range_check96_builtin',
            'range_check_bits_128': 'range_check_builtin'}


def exact_keys(value: dict, expected) -> None:
    if set(value) != set(expected):
        raise ValueError(f'unsupported schema keys: {set(value) ^ set(expected)}')


def memory_value(memory: dict, address: int) -> int:
    ident = memory['address_to_id'][address]
    if ident == 0x3fffffff:
        raise ValueError(f'uninitialized public/instruction address {address}')
    if ident & 0x40000000:
        return sum(limb << (32 * i) for i, limb in enumerate(memory['f252_values'][ident & 0x3fffffff]))
    return memory['small_values'][ident]


def convert(data: dict, compiled: dict) -> tuple[dict, dict]:
    exact_keys(data, ('state_transitions', 'memory', 'inst_cache',
                     'public_memory_addresses', 'builtin_segments', 'public_segment_context'))
    transitions = data['state_transitions']
    exact_keys(transitions, ('initial_state', 'final_state', 'casm_states_by_opcode'))
    buckets = transitions['casm_states_by_opcode']
    exact_keys(buckets, OPCODES)
    exact_keys(data['builtin_segments'], BUILTINS)
    memory = data['memory']
    exact_keys(memory, ('config', 'address_to_id', 'f252_values', 'small_values'))
    if memory['config'] != {'small_max': (1 << 72) - 1, 'log_small_value_capacity': 24}:
        raise ValueError('unsupported memory configuration')
    public = set(data['public_memory_addresses'])
    program = [int(v, 0) if isinstance(v, str) else v for v in compiled['data']]
    for address, value in enumerate(program, 1):
        if address not in public or memory_value(memory, address) != value:
            raise ValueError(f'compiled program not bound at address {address}')
    cache = dict(data['inst_cache'])
    if len(cache) != len(data['inst_cache']):
        raise ValueError('duplicate instruction cache address')
    for address, value in cache.items():
        if memory_value(memory, address) != value:
            raise ValueError('instruction cache disagrees with memory')
    if any(s['pc'] not in cache for bucket in buckets.values() for s in bucket):
        raise ValueError('instruction cache does not cover execution')
    transitions['casm_states_by_opcode'] = {OPCODE_RENAMES.get(k, k): v for k, v in buckets.items()}
    data['builtin_segments'] = {BUILTINS[k]: v for k, v in data['builtin_segments'].items()}
    data['builtin_segments']['ec_op_builtin'] = None  # absent from the legacy schema
    data['pc_count'] = len(data.pop('inst_cache'))
    return data, {'schema': 'keth-legacy-input-conversion-v1',
                  'from_stwo_cairo': '92232543984e20e984c5a7194561ff1fffa76dae',
                  'to_stwo_cairo': '82f21252a68ec006d73e299f5bf1ce6d4db0ee78',
                  'compiled_program_cells_checked': len(program),
                  'instruction_cache_cells_checked': len(cache),
                  'execution_steps': sum(len(v) for v in buckets.values())}


def convert_file(source: Path, compiled: Path, target: Path) -> dict:
    data, receipt = convert(json.loads(source.read_text()), json.loads(compiled.read_text()))
    if target.suffix == '.cpi':
        with target.open('xb') as output:
            write_compact(output, data)
        receipt['transport'] = 'compact-v1'
    else:
        with target.open('x') as output:
            json.dump(data, output, separators=(',', ':'))
        receipt['transport'] = 'json'
    return receipt


def write_compact(output, data: dict) -> None:
    """Existing frozen CPI v1, matching tools/stwo-cairo-vm-adapter-rs/src/compact.rs."""
    def pack(fmt, *values):
        output.write(struct.pack('<' + fmt, *values))

    def words(values):
        chunk = array.array('I')
        for value in values:
            chunk.append(value)
            if len(chunk) == 16384:
                if sys.byteorder != 'little':
                    chunk.byteswap()
                output.write(chunk.tobytes())
                chunk = array.array('I')
        if sys.byteorder != 'little':
            chunk.byteswap()
        output.write(chunk.tobytes())

    output.write(b'STWZCPI\0')
    pack('II', 1, 0)
    transitions = data['state_transitions']
    for name in ('initial_state', 'final_state'):
        s = transitions[name]
        pack('III', s['pc'], s['ap'], s['fp'])
    pack('Q', data['pc_count'])
    present = data['public_segment_context']['present']
    if len(present) != 11 or any(type(v) is not bool for v in present):
        raise ValueError('invalid public segment context')
    pack('HHI', sum(int(v) << i for i, v in enumerate(present)), 0, 0)
    pack('II', len(OPCODES), 0)
    for name in OPCODES:
        group = transitions['casm_states_by_opcode'][OPCODE_RENAMES.get(name, name)]
        pack('Q', len(group))
        words(value for s in group for value in (s['pc'], s['ap'], s['fp']))
    memory = data['memory']
    output.write(memory['config']['small_max'].to_bytes(16, 'little'))
    pack('II', memory['config']['log_small_value_capacity'], 0)
    pack('QQQ', len(memory['address_to_id']), len(memory['f252_values']), len(memory['small_values']))
    words(memory['address_to_id'])
    words(limb for value in memory['f252_values'] for limb in value)
    for start in range(0, len(memory['small_values']), 4096):
        output.write(b''.join(v.to_bytes(16, 'little') for v in memory['small_values'][start:start+4096]))
    pack('Q', len(data['public_memory_addresses']))
    words(data['public_memory_addresses'])
    for name in (*BUILTINS.values(), 'ec_op_builtin'):
        segment = data['builtin_segments'][name]
        pack('B7xQQ', segment is not None, segment['begin_addr'] if segment else 0,
             segment['stop_ptr'] if segment else 0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--compiled', type=Path, required=True)
    parser.add_argument('--target', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists() or args.target.exists():
        parser.error('target and receipt must be fresh')
    receipt = convert_file(args.source, args.compiled, args.target)
    with args.receipt.open('x') as output:
        json.dump(receipt, output, indent=2)
        output.write('\n')
