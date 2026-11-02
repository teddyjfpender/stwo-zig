#!/usr/bin/env python3
"""Prepare checkpoint-bound OP execution kernels, outside Ethereum admission.

The view hash commits every supplied account/slot, including unchanged reads.
Its authentication to an MPT root is checked on the host, not proved in Cairo.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path

from eth_hash.auto import keccak

if __package__:
    from .bridge import PINS, digest, write_new
    from .check_fixture import header_hash
    from .op_encoding import op_transaction_bytes
    from .op_fee_workload import load
    from .state_proofs import EMPTY_CODE_HASH, EMPTY_ROOT
else:
    from bridge import PINS, digest, write_new
    from check_fixture import header_hash
    from op_encoding import op_transaction_bytes
    from op_fee_workload import load
    from state_proofs import EMPTY_CODE_HASH, EMPTY_ROOT

VIEW_DOMAIN = int('6f705f73746174655f766965775f7631', 16)
ENV_DOMAIN = int('6f705f656e7669726f6e6d656e745f7631', 16)


def limbs(raw: bytes) -> list[int]:
    if len(raw) != 32:
        raise ValueError('expected 32 bytes')
    return [int.from_bytes(raw[:16], 'little'), int.from_bytes(raw[16:], 'little')]


def view_hash(state: dict, accesses: list, *, version: int = 1, initial: bool = False) -> list[int]:
    if version not in (1, 2) or (initial and version == 1):
        raise ValueError('unsupported state-view format')
    values = [VIEW_DOMAIN + version - 1, len(accesses)]
    if version == 2:
        values.append(int(initial))
    for entry in accesses:
        address = entry['address']
        account = state[address]
        nonce, balance, code = (0, 0, EMPTY_CODE_HASH) if account is None else (
            int(account['nonce'], 16), int(account['balance'], 16), bytes.fromhex(account['codeHash'][2:]))
        values += [int.from_bytes(bytes.fromhex(address[2:]), 'little'), int(account is not None),
                   nonce, balance % 2**128, balance // 2**128, *limbs(code)]
        if initial:
            values += limbs(EMPTY_ROOT if account is None else bytes.fromhex(account['storageHash'][2:]))
        values.append(len(entry['storageKeys']))
        for key in entry['storageKeys']:
            value = int(account['storage'][key], 16) if account is not None else 0
            values += [*limbs(bytes.fromhex(key[2:])), value % 2**128, value // 2**128]
    return limbs(hashlib.blake2s(b''.join(v.to_bytes(32, 'little') for v in values)).digest())


def environment_hash(e: dict) -> list[int]:
    values = [ENV_DOMAIN, e['chain_id'], e['gas_limit'], int.from_bytes(bytes.fromhex(e['coinbase'][2:]), 'little'),
              e['number'], e['base_fee'], e['timestamp'] % 2**128, e['timestamp'] // 2**128,
              *limbs(bytes.fromhex(e['prev_randao'][2:])), 0,
              *limbs(bytes.fromhex(e['parent_beacon_block_root'][2:])), len(e['block_hashes'])]
    for value in e['block_hashes']:
        values += limbs(bytes.fromhex(value[2:]))
    return limbs(hashlib.blake2s(b''.join(v.to_bytes(32, 'little') for v in values)).digest())


def prepare(native_path: Path, checkpoints_path: Path, completion_path: Path, result_path: Path,
            accesses_path: Path, out: Path, index: int = 0):
    native, checkpoints, completion, reference = [load(p) for p in (
        native_path, checkpoints_path, completion_path, result_path)]
    if (completion['status'] != 'qualified' or completion['final_input_sha256'] != digest(native_path)
            or completion['checkpoints_sha256'] != digest(checkpoints_path)
            or completion['access_list_sha256'] != digest(accesses_path)
            or completion['attempts'][-1]['result_sha256'] != digest(result_path)
            or not checkpoints['complete_reference_execution'] or not reference['offline_execution_checked']
            or reference['geth_module']['Replace']['Version'] != PINS['op_reference']['op_geth_version']):
        raise ValueError('checkpoint/reference provenance mismatch')
    block, rows = native['block'], checkpoints['checkpoints']
    txs = block['transactions']
    if (native['chain_id'] != 10 or reference['block_hash'] != header_hash(block)
            or reference['computed_state_root'] != block['stateRoot']
            or reference['computed_receipt_root'] != block['receiptsRoot']
            or len(rows) != len(txs) * 2 or rows[-1]['root'] != block['stateRoot']
            or not 0 <= index < len(txs)):
        raise ValueError('expected complete root-correct OP Mainnet reference execution')
    for i, tx in enumerate(txs):
        expected = '0x' + keccak(op_transaction_bytes(tx)).hex()
        for row, phase in zip(rows[2*i:2*i+2], ('pre', 'post')):
            if row['phase'] != phase or row['transaction_index'] != i or row['transaction_hash'] != expected:
                raise ValueError('checkpoint transaction identity/order mismatch')
        if i and rows[2*i-1]['root'] != rows[2*i]['root']:
            raise ValueError('noncontiguous transaction checkpoints')
    tx = txs[index]
    config = reference['chain_config']
    if any(config.get(fork) is None or config[fork] > int(block['timestamp'], 16)
           for fork in ('regolithTime', 'pragueTime')):
        raise ValueError('the kernel requires post-Regolith/Prague OP rules')
    if int(tx['type'], 16) != 0x7e or not tx.get('to'):
        raise ValueError('this kernel currently admits only call deposits')
    accesses = sorted(load(accesses_path), key=lambda a: a['address'])
    for entry in accesses:
        entry['storageKeys'] = sorted(entry['storageKeys'])
    before, after = rows[2*index:2*index+2]
    if set(before['state']) != {a['address'] for a in accesses} or set(after['state']) != set(before['state']):
        raise ValueError('checkpoint access view differs')
    pre = copy.deepcopy(before['state'])
    codes = {'0x' + keccak(bytes.fromhex(c[2:])).hex(): c for c in native['witness']['codes']}
    codes['0x' + EMPTY_CODE_HASH.hex()] = '0x'
    for account in pre.values():
        if account is not None:
            account.pop('code', None)
            if account['codeHash'] not in codes:
                raise ValueError('missing authenticated contract code')
    value = dict(pre_state=pre, access_list=accesses, transaction='0x' + op_transaction_bytes(tx).hex(), codes=codes,
                 environment=dict(chain_id=10, number=int(block['number'], 16), gas_limit=int(block['gasLimit'], 16),
                                  base_fee=int(block['baseFeePerGas'], 16), timestamp=int(block['timestamp'], 16),
                                  coinbase=block['miner'], prev_randao=block['mixHash'],
                                  parent_beacon_block_root=block['parentBeaconBlockRoot'],
                                  block_hashes=[h['hash'] for h in reversed(native['witness']['headers'])]))
    receipt = after['receipt']
    expected = [10, value['environment']['number'], *limbs(keccak(bytes.fromhex(value['transaction'][2:]))),
                *limbs(bytes.fromhex(tx['sourceHash'][2:])), *view_hash(before['state'], accesses, version=2, initial=True),
                *view_hash(after['state'], accesses, version=2), int(receipt['gasUsed'], 16), int(receipt['status'], 16),
                int(receipt['depositNonce'], 16), *environment_hash(value['environment'])]
    out.mkdir(parents=True, exist_ok=False)
    write_new(out / 'input.json', value)
    write_new(out / 'expected-output.json', expected)
    result = dict(schema='keth-op-deposit-workload-v2', state_view_commitment_version=2,
                  transaction_index=index, transaction_hash=tx['hash'],
                  block_hash=block['hash'], before_root=before['root'], after_root=after['root'],
                  inputs_sha256={str(p): digest(p) for p in (native_path, checkpoints_path, completion_path, result_path, accesses_path)},
                  input_sha256=digest(out / 'input.json'), expected_output_sha256=digest(out / 'expected-output.json'),
                  accounts=len(accesses), storage_slots=sum(len(a['storageKeys']) for a in accesses),
                  native_execution_checked=True, cairo_execution_proved=False,
                  cairo_mpt_authentication_proved=False, derivation_proved=False,
                  pre_transaction_system_calls_proved=False)
    write_new(out / 'workload.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native', 'checkpoints', 'completion', 'reference-result', 'access-list', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--index', type=int, default=0)
    args = parser.parse_args()
    print(json.dumps(prepare(args.native, args.checkpoints, args.completion, args.reference_result,
                             args.access_list, args.out, args.index), indent=2))
