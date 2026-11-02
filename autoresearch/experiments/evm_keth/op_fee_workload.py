#!/usr/bin/env python3
"""Prepare an OP sequencer-fee batch from complete reference checkpoints.

Expected outputs bind every raw transaction hash and every fee parameter/gas
input. Proving this kernel alone does not prove execution, derivation or the
membership of these parameters in an OP block's state.
"""
from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path
import subprocess

from eth_hash.auto import keccak

if __package__:
    from .bridge import PINS, digest, write_new
    from .check_fixture import header_hash
    from .op_encoding import op_transaction_bytes
else:
    from bridge import PINS, digest, write_new
    from check_fixture import header_hash
    from op_encoding import op_transaction_bytes

L1_BLOCK = '0x4200000000000000000000000000000000000015'


def load(path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == '.gz' else raw)


def output_values(value: dict, reference: dict) -> list[int]:
    result = [len(reference['rows']), value['base_fee'] % 2**128, value['base_fee'] // 2**128,
              value['blob_fee'] % 2**128, value['blob_fee'] // 2**128, value['base_scalar'],
              value['blob_scalar'], value['operator_scalar'], value['operator_constant'], value['jovian'], value['da_scalar']]
    for index, row in enumerate(reference['rows']):
        if row['l1_fee_overflow']:
            raise ValueError('L1 fee exceeds uint256; cannot fund a valid sequencer transaction')
        fee, raw_hash = int(row['l1_fee'], 16), bytes.fromhex(row['hash'][2:])
        result += [int.from_bytes(raw_hash[:16], 'little'), int.from_bytes(raw_hash[16:], 'little'),
                   row['bytes'], row['fastlz_size'], fee % 2**128, fee // 2**128,
                   int(row['operator_reserve'], 16), int(row['operator_fee'], 16),
                   row['estimated_da_size'], row['da_footprint'], value['gas_limits'][index], value['gas_used'][index]]
    return result


def prepare(native_path, checkpoints_path, result_path, oracle, out):
    native, checkpoints, reference = load(native_path), load(checkpoints_path), load(result_path)
    block, records = native['block'], checkpoints['checkpoints']
    transactions = block['transactions']
    if (not checkpoints['complete_reference_execution'] or not reference['offline_execution_checked']
            or header_hash(block) != block['hash'] or reference['block_hash'] != block['hash']
            or reference['computed_state_root'] != block['stateRoot']
            or reference['computed_receipt_root'] != block['receiptsRoot']
            or reference['geth_module']['Replace']['Version'] != PINS['op_reference']['op_geth_version']
            or len(records) != 2 * len(transactions)):
        raise ValueError('complete, root-correct reference checkpoints required')
    cumulative, selected, deposit_count = 0, [], 0
    for index, tx in enumerate(transactions):
        before, after = records[2 * index:2 * index + 2]
        raw = op_transaction_bytes(tx)
        expected_hash = '0x' + keccak(raw).hex()
        for row, phase in ((before, 'pre'), (after, 'post')):
            if row['phase'] != phase or row['transaction_index'] != index or row['transaction_hash'] != expected_hash:
                raise ValueError('checkpoint transaction identity/order mismatch')
        if index and records[2 * index - 1]['root'] != before['root']:
            raise ValueError('noncontiguous reference state checkpoints')
        receipt = after['receipt']
        cumulative += int(receipt['gasUsed'], 16)
        if (receipt['transactionHash'] != expected_hash or int(receipt['transactionIndex'], 16) != index
                or cumulative != int(receipt['cumulativeGasUsed'], 16)):
            raise ValueError('checkpoint receipt identity/gas mismatch')
        if int(tx['type'], 16) == 0x7e:
            if selected:
                raise ValueError('deposit after sequencer transaction is outside the qualified derivation order')
            deposit_count += 1
        else:
            selected.append((tx, before, after, raw))
    if not deposit_count or not selected or records[-1]['root'] != block['stateRoot'] or cumulative != int(block['gasUsed'], 16):
        raise ValueError('expected complete OP block with deposit prefix and sequencer transactions')
    fields = [f'0x{n:064x}' for n in (1, 3, 7, 8)]
    storage = selected[0][1]['state'][L1_BLOCK]['storage']
    for _, before, _, _ in selected:
        if any(before['state'][L1_BLOCK]['storage'][key] != storage[key] for key in fields):
            raise ValueError('L1 fee parameters changed after their lazy initialization')
    base, packed, blob, operator = [int(storage[key], 16) for key in fields]
    timestamp = int(block['timestamp'], 16)
    config = reference['chain_config']
    if timestamp < config['isthmusTime']:
        raise ValueError('this OP fee context requires at least Isthmus')
    jovian = int(config.get('jovianTime') is not None and timestamp >= config['jovianTime'])
    da_scalar = (operator >> 96) & 0xffff
    if jovian and da_scalar == 0:
        da_scalar = 400
    value = dict(transactions=['0x' + raw.hex() for _, _, _, raw in selected],
                 gas_limits=[int(tx['gas'], 16) for tx, _, _, _ in selected],
                 gas_used=[int(after['receipt']['gasUsed'], 16) for _, _, after, _ in selected],
                 base_fee=base, blob_fee=blob, base_scalar=(packed >> 96) & 0xffffffff,
                 blob_scalar=(packed >> 64) & 0xffffffff, operator_scalar=(operator >> 64) & 0xffffffff,
                 operator_constant=operator & (2**64 - 1), jovian=jovian, da_scalar=da_scalar)
    out.mkdir(parents=True, exist_ok=False)
    write_new(out / 'input.json', value)
    subprocess.run([str(oracle.resolve()), '--input', str(out / 'input.json'), '--output', str(out / 'reference.json')], check=True)
    fees = load(out / 'reference.json')
    dependency = fees['geth_module']['Replace']
    if dependency['Path'] != 'github.com/ethereum-optimism/op-geth' or dependency['Version'] != PINS['op_reference']['op_geth_version']:
        raise ValueError('fee oracle dependency pin mismatch')
    for row, (_, before, after, _) in zip(fees['rows'], selected):
        if (row['fastlz_size'] != before['fastlz_size'] or row['l1_fee'] != before['l1_fee']
                or row['operator_reserve'] != before['operator_fee_reserve'] or row['operator_fee'] != after['operator_fee']):
            raise ValueError('independent fee functions disagree with complete block execution')
    if len(fees['rows']) != len(selected):
        raise ValueError('fee oracle omitted transactions')
    footprint = sum(row['da_footprint'] for row in fees['rows'])
    if jovian and footprint != int(block['blobGasUsed'], 16):
        raise ValueError('Jovian DA footprint differs from block header')
    write_new(out / 'expected-output.json', output_values(value, fees))
    receipt = dict(schema='keth-op-fee-workload-v1', block_hash=block['hash'],
                   sequencer_transactions=len(selected), excluded_deposits=deposit_count,
                   da_footprint=footprint, native_input_sha256=digest(native_path),
                   checkpoints_sha256=digest(checkpoints_path), reference_result_sha256=digest(result_path),
                   oracle_sha256=digest(oracle), files={p.name: digest(p) for p in out.iterdir()},
                   op_block_execution_proved=False, op_derivation_proved=False,
                   public_block_statement_bound=False, scope='sequencer fee kernel with public parameters and transaction hashes')
    write_new(out / 'workload.json', receipt)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native-input', 'checkpoints', 'reference-result', 'oracle', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.native_input, args.checkpoints, args.reference_result, args.oracle, args.out), indent=2))
