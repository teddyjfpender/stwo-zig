#!/usr/bin/env python3
"""Retain a block, parent and receipts from an explicitly selected JSON-RPC.

These are RPC observations, not consensus proofs or execution witnesses.
Number tags are resolved once; subsequent requests use the observed block hash.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import urllib.request

if __package__:
    from .bridge import digest, write_new
else:
    from bridge import digest, write_new


def rpc(endpoint: str, method: str, params: list):
    request = urllib.request.Request(endpoint,
        data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
        headers={'Content-Type': 'application/json', 'User-Agent': 'stwo-zig-keth-benchmark/1'})
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.load(response)
    if 'error' in value or value.get('result') is None:
        raise ValueError(f'{method}: {value.get("error", "missing result")}')
    return value


def collect(endpoint: str, chain_id: int, block_tag: str, out: Path, receipts: bool = False) -> dict:
    out.mkdir(parents=True, exist_ok=False)
    receipt = {'schema': 'keth-rpc-observation-v1', 'status': 'running',
               'endpoint': endpoint, 'requested_chain_id': chain_id, 'requested_block': block_tag,
               'started_at': datetime.now(timezone.utc).isoformat(),
               'scope': 'RPC observation; not an execution witness or consensus proof', 'files': {}}

    def retain(name: str, value: dict):
        write_new(out / name, value)
        receipt['files'][name] = digest(out / name)
        return value

    try:
        observed_chain = retain('chain.json', rpc(endpoint, 'eth_chainId', []))
        if int(observed_chain['result'], 16) != chain_id:
            raise ValueError('RPC chain ID mismatch')
        block_response = retain('block.json', rpc(endpoint, 'eth_getBlockByNumber', [block_tag, True]))
        block = block_response['result']
        if not isinstance(block['transactions'], list) or any(not isinstance(t, dict) for t in block['transactions']):
            raise ValueError('RPC did not return full transactions')
        parent_response = retain('parent.json', rpc(endpoint, 'eth_getBlockByHash', [block['parentHash'], False]))
        parent = parent_response['result']
        if parent['hash'] != block['parentHash'] or int(parent['number'], 16) + 1 != int(block['number'], 16):
            raise ValueError('RPC parent link mismatch')
        if receipts:
            response = retain('receipts.json', rpc(endpoint, 'eth_getBlockReceipts', [block['hash']]))
            values = response['result']
            if len(values) != len(block['transactions']):
                raise ValueError('receipt count mismatch')
            for index, (tx, value) in enumerate(zip(block['transactions'], values)):
                if value['transactionHash'] != tx['hash'] or value['blockHash'] != block['hash'] or int(value['transactionIndex'], 16) != index:
                    raise ValueError('receipt does not match ordered block transactions')
        types = Counter(int(t.get('type', '0x0'), 16) for t in block['transactions'])
        receipt.update(status='observed', block_number=int(block['number'], 16),
                       block_hash=block['hash'], gas_used=int(block['gasUsed'], 16),
                       transactions=len(block['transactions']),
                       transaction_types={hex(k): v for k, v in sorted(types.items())},
                       deposit_transactions=types[0x7e],
                       first_transaction_is_deposit=bool(block['transactions']) and int(block['transactions'][0].get('type', '0x0'), 16) == 0x7e,
                       cairo_proof_verified=False, op_stack_execution_proved=False)
    except Exception as error:
        receipt.update(status='failed', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        receipt['finished_at'] = datetime.now(timezone.utc).isoformat()
        write_new(out / 'observation.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    parser.add_argument('--chain-id', required=True, type=int)
    parser.add_argument('--block', default='finalized', help='JSON-RPC tag or hex block number')
    parser.add_argument('--receipts', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.chain_id < 1:
        parser.error('chain ID must be positive')
    print(json.dumps(collect(args.endpoint, args.chain_id, args.block, args.out, args.receipts), indent=2))


if __name__ == '__main__':
    main()
