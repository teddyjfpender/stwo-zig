#!/usr/bin/env python3
"""Check Ethereum fixture identities independently of Keth's Cairo hints.

Run with Keth's pinned Python environment for eth-hash, rlp and eth-account.
This authenticates host inputs; it does not add a public Cairo block statement.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from eth_hash.auto import keccak
import rlp
from eth_account.typed_transactions import TypedTransaction
from eth_account._utils.legacy_transactions import Transaction

if __package__:
    from .bridge import digest, write_new
else:
    from bridge import digest, write_new

HEADER_FIELDS = ('parentHash sha3Uncles miner stateRoot transactionsRoot receiptsRoot '
                 'logsBloom difficulty number gasLimit gasUsed timestamp extraData mixHash '
                 'nonce baseFeePerGas withdrawalsRoot blobGasUsed excessBlobGas '
                 'parentBeaconBlockRoot requestsHash').split()
QUANTITIES = {'difficulty', 'number', 'gasLimit', 'gasUsed', 'timestamp',
              'baseFeePerGas', 'blobGasUsed', 'excessBlobGas'}


def header_hash(header: dict) -> str:
    values = []
    missing = False
    for field in HEADER_FIELDS:
        if field not in header or header[field] is None:
            missing = True
            continue
        if missing:
            raise ValueError('noncontiguous header fields')
        value = header[field]
        if field in QUANTITIES:
            number = int(value, 16)
            value = number.to_bytes((number.bit_length() + 7) // 8, 'big')
        else:
            value = bytes.fromhex(value.removeprefix('0x'))
        values.append(value)
    if len(values) < 15:
        raise ValueError('incomplete Ethereum header')
    return '0x' + keccak(rlp.encode(values)).hex()


def transaction_bytes(tx: dict) -> bytes:
    kind = int(tx.get('type', '0x0'), 16)
    common = ('nonce', 'gas', 'to', 'value', 'v', 'r', 's')
    extra = {0: ('gasPrice',), 1: ('chainId', 'gasPrice', 'accessList'),
             2: ('chainId', 'maxPriorityFeePerGas', 'maxFeePerGas', 'accessList'),
             3: ('chainId', 'maxPriorityFeePerGas', 'maxFeePerGas', 'accessList',
                 'maxFeePerBlobGas', 'blobVersionedHashes'),
             4: ('chainId', 'maxPriorityFeePerGas', 'maxFeePerGas', 'accessList', 'authorizationList')}
    if kind not in extra:
        raise ValueError(f'unsupported Ethereum transaction type {kind:#x}')
    value = {key: tx[key] for key in (*common, *extra[kind]) if key in tx and tx[key] is not None}
    value['to'] = bytes.fromhex((value.get('to') or '0x').removeprefix('0x'))
    value['data'] = tx['input']
    if kind:
        value['type'] = kind
        encoded = TypedTransaction.from_dict(value).encode()
    else:
        for key in ('nonce', 'gas', 'value', 'v', 'r', 's', 'gasPrice'):
            value[key] = int(value[key], 16)
        value['data'] = bytes.fromhex(value['data'].removeprefix('0x'))
        encoded = rlp.encode(Transaction.from_dict(value))
    return encoded


def transaction_hash(tx: dict) -> str:
    return '0x' + keccak(transaction_bytes(tx)).hex()


def check(fixture: Path, rpc_block: Path | None = None, rpc_parent: Path | None = None) -> dict:
    data = json.loads(fixture.read_text())
    if type(data['chainConfig']['chainId']) is not int or data['chainConfig']['chainId'] != 1 or len(data['blocks']) != 1:
        raise ValueError('expected one Ethereum mainnet block')
    block = data['blocks'][0]
    header = block['header']
    parent = data['witness']['ancestors'][0]
    for value in (header, parent):
        if header_hash(value) != value['hash']:
            raise ValueError('RLP/Keccak header hash mismatch')
    if header['parentHash'] != parent['hash'] or int(parent['number'], 16) + 1 != int(header['number'], 16):
        raise ValueError('fixture parent link mismatch')
    for tx in block['transaction']:
        if transaction_hash(tx) != tx['hash']:
            raise ValueError('signed transaction hash mismatch')
    result = {'schema': 'keth-ethereum-fixture-check-v1', 'fixture_sha256': digest(fixture),
              'header_hash': header['hash'], 'parent_hash': parent['hash'],
              'signed_transaction_hashes_checked': len(block['transaction']),
              'header_rlp_keccak_checked': True, 'parent_rlp_keccak_checked': True,
              'ethereum_block_statement_bound_in_proof': False}
    for path, expected, label in ((rpc_block, header, 'block'), (rpc_parent, parent, 'parent')):
        if path is None:
            continue
        observed = json.loads(path.read_text())['result']
        if header_hash(observed) != expected['hash'] or any(observed.get(k) != expected[k] for k in HEADER_FIELDS):
            raise ValueError(f'independent RPC {label} header mismatch')
        if label == 'block':
            transactions = observed['transactions']
            hashes = [t['hash'] if isinstance(t, dict) else t for t in transactions]
            if hashes != [t['hash'] for t in block['transaction']]:
                raise ValueError('independent RPC ordered transaction list mismatch')
        result['rpc_' + label + '_sha256'] = digest(path)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--rpc-block', type=Path)
    parser.add_argument('--rpc-parent', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.fixture, args.rpc_block, args.rpc_parent)
    write_new(args.out, result)
    print(json.dumps(result, indent=2))
