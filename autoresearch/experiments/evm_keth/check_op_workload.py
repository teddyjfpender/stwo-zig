#!/usr/bin/env python3
"""Bind an official decoded span channel to retained historical OP block reads.

Run with Keth's pinned Python. Rebuilds header/transaction/receipt commitments;
does not authenticate consensus, execute transactions or prove derivation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import gzip
import json
from pathlib import Path

from eth_hash.auto import keccak

if __package__:
    from .bridge import digest, write_new
    from .check_fixture import HEADER_FIELDS, header_hash
    from .op_encoding import isthmus_l1_info, op_transaction_bytes, ordered_trie_root, quantity, receipt_bytes
else:
    from bridge import digest, write_new
    from check_fixture import HEADER_FIELDS, header_hash
    from op_encoding import isthmus_l1_info, op_transaction_bytes, ordered_trie_root, quantity, receipt_bytes


def load(path: Path):
    raw = path.read_bytes()
    return json.loads(gzip.decompress(raw) if path.suffix == '.gz' else raw)


def checked_header(value: dict) -> None:
    if header_hash(value) != value['hash']:
        raise ValueError('RLP/Keccak header hash mismatch')


def retained_path(directory: Path, name: str) -> Path:
    path = directory / name
    return path if path.is_file() else path.with_suffix(path.suffix + '.gz')


def check_block(block: dict, parent: dict, receipts: list, independent: dict) -> dict:
    for header in (block, parent, independent):
        checked_header(header)
    if any(block.get(k) != independent.get(k) for k in (*HEADER_FIELDS, 'hash')):
        raise ValueError('independent RPC header mismatch')
    if block['parentHash'] != parent['hash'] or quantity(block['number']) != quantity(parent['number']) + 1:
        raise ValueError('parent link mismatch')
    txs = block['transactions']
    hashes = [tx['hash'] for tx in txs]
    if hashes != [tx['hash'] if isinstance(tx, dict) else tx for tx in independent['transactions']]:
        raise ValueError('independent RPC transaction list mismatch')
    encoded = [op_transaction_bytes(tx) for tx in txs]
    if hashes != ['0x' + keccak(raw).hex() for raw in encoded]:
        raise ValueError('transaction encoding/hash mismatch')
    if ordered_trie_root(encoded) != block['transactionsRoot']:
        raise ValueError('transactions trie root mismatch')
    if len(receipts) != len(txs):
        raise ValueError('receipt count mismatch')
    cumulative = 0
    status = Counter()
    for index, (tx, receipt) in enumerate(zip(txs, receipts)):
        for item in (tx, receipt):
            if (item['blockHash'] != block['hash'] or quantity(item['blockNumber']) != quantity(block['number'])
                    or quantity(item['transactionIndex']) != index):
                raise ValueError('transaction/receipt metadata mismatch')
        if receipt['transactionHash'] != tx['hash'] or receipt['type'] != tx['type']:
            raise ValueError('receipt transaction mismatch')
        cumulative += quantity(receipt['gasUsed'])
        if cumulative != quantity(receipt['cumulativeGasUsed']):
            raise ValueError('receipt cumulative gas mismatch')
        status[quantity(receipt['status'])] += 1
    if cumulative != quantity(block['gasUsed']):
        raise ValueError('block gas mismatch')
    if ordered_trie_root([receipt_bytes(r) for r in receipts]) != block['receiptsRoot']:
        raise ValueError('receipts trie root mismatch')
    info = isthmus_l1_info(txs[0])
    deposits = [i for i, tx in enumerate(txs) if quantity(tx['type']) == 0x7e]
    # Deliberately narrow qualification: user deposits require authenticated L1
    # log derivation and cannot be silently ignored by this workload checker.
    if deposits != [0]:
        raise ValueError('expected exactly one L1-info deposit in this workload')
    return dict(number=quantity(block['number']), hash=block['hash'],
                timestamp=quantity(block['timestamp']), gas_used=cumulative,
                transactions=len(txs), sequencer_transactions=len(txs) - 1,
                transaction_types=dict(Counter(tx['type'] for tx in txs)),
                failed_transactions=status[0], l1_info=info,
                state_root=block['stateRoot'], parent_state_root=parent['stateRoot'],
                header_rlp_keccak_checked=True, transaction_root_checked=True,
                receipt_root_checked=True, deposit_source_hash_checked=True)


def check(channel_path: Path, block_directory: Path, config_path: Path,
          l1_directory: Path | None = None) -> dict:
    channel, config = load(channel_path), load(config_path)
    if (not channel['is_ready'] or channel['invalid_frames'] or channel['invalid_batches']
            or channel['batch_types'] != [1] * len(channel['batches'])):
        raise ValueError('expected valid, complete span channel')
    if config['l2_chain_id'] != 8453 or config['block_time'] != 2:
        raise ValueError('expected historical Base configuration')
    results, sources = [], {}
    for batch in channel['batches']:
        batch_results = []
        for element in batch['span_batch_elements']:
            timestamp = element['Timestamp']
            delta = timestamp - config['genesis']['l2_time']
            if delta < 0 or delta % config['block_time']:
                raise ValueError('timestamp outside configured block grid')
            number = config['genesis']['l2']['number'] + delta // config['block_time']
            directory = block_directory / str(number)
            paths = {name: retained_path(directory, name) for name in
                     ('chain.json', 'block.json', 'parent.json', 'receipts.json', 'independent-block.json')}
            if quantity(load(paths['chain.json'])['result']) != config['l2_chain_id']:
                raise ValueError('RPC chain ID mismatch')
            b, parent, receipts, other = [load(paths[name])['result'] for name in
                                        ('block.json', 'parent.json', 'receipts.json', 'independent-block.json')]
            result = check_block(b, parent, receipts, other)
            if result['number'] != number or result['timestamp'] != timestamp:
                raise ValueError('span block identity mismatch')
            if not config['isthmus_time'] <= timestamp < config['jovian_time']:
                raise ValueError('workload outside qualified historical fork interval')
            if results and (number != results[-1]['number'] + 1 or b['parentHash'] != results[-1]['hash']):
                raise ValueError('noncontiguous channel blocks')
            sequencer_hashes = ['0x' + keccak(bytes.fromhex(raw[2:])).hex() for raw in element['Transactions']]
            if sequencer_hashes != [tx['hash'] for tx in b['transactions'][1:]]:
                raise ValueError('decoded sequencer transaction order/content mismatch')
            info = result['l1_info']
            if info['number'] != element['EpochNum']:
                raise ValueError('span L1 origin number mismatch')
            if info['timestamp'] > timestamp:
                raise ValueError('L1 origin newer than L2 block')
            if results:
                previous = results[-1]['l1_info']
                if info['number'] == previous['number']:
                    if info['block_hash'] != previous['block_hash'] or info['sequence_number'] != previous['sequence_number'] + 1:
                        raise ValueError('L1 origin sequence mismatch')
                elif info['number'] <= previous['number'] or info['sequence_number'] != 0:
                    raise ValueError('invalid L1 origin transition')
            if l1_directory is not None:
                path = retained_path(l1_directory, f"{info['number']}.json")
                l1 = load(path)['result']
                checked_header(l1)
                if (l1['hash'] != info['block_hash'] or quantity(l1['number']) != info['number']
                        or quantity(l1['timestamp']) != info['timestamp'] or quantity(l1['baseFeePerGas']) != info['base_fee']):
                    raise ValueError('L1-info differs from observed L1 header')
                sources[str(path)] = digest(path)
            sources.update({str(p): digest(p) for p in paths.values()})
            results.append(result)
            batch_results.append(result)
        if batch['parent_check'] != [load(retained_path(block_directory / str(batch_results[0]['number']), 'block.json'))['result']['parentHash'][:42]]:
            raise ValueError('span parent check mismatch')
        if batch['l1_origin_check'] != [batch_results[-1]['l1_info']['block_hash'][:42]]:
            raise ValueError('span L1 origin hash check mismatch')
    if not results:
        raise ValueError('empty decoded channel')
    return dict(schema='keth-op-workload-check-v1', channel_id=channel['id'],
                channel_sha256=digest(channel_path), config_sha256=digest(config_path),
                l2_blocks=len(results), sequencer_transactions=sum(r['sequencer_transactions'] for r in results),
                deposits=len(results), total_gas_used=sum(r['gas_used'] for r in results),
                blocks=results, sources=sources, decoded_transactions_match_blocks=True,
                l1_origins_checked=l1_directory is not None,
                dynamic_batcher_authorization_verified=False, consensus_authenticated=False,
                op_stack_derivation_proved=False, l2_execution_proved=False,
                ethereum_settlement_compatible=False)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--channel', type=Path, required=True)
    parser.add_argument('--blocks', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--l1-headers', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.channel, args.blocks, args.config, args.l1_headers)
    write_new(args.out, result)
    print(json.dumps({k: v for k, v in result.items() if k not in ('blocks', 'sources')}, indent=2))
