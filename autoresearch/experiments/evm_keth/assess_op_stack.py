#!/usr/bin/env python3
"""Bind an OP workload assessment to retained RPC data and chain configuration.

This reports integration requirements, never an execution/derivation proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib

if __package__:
    from .bridge import PINS, digest, write_new
else:
    from bridge import PINS, digest, write_new


def assess(observation: Path, config_file: Path) -> dict:
    receipt = json.loads((observation / 'observation.json').read_text())
    if receipt['status'] != 'observed':
        raise ValueError('RPC collection did not complete')
    for name in ('chain.json', 'block.json', 'parent.json'):
        if digest(observation / name) != receipt['files'][name]:
            raise ValueError('RPC observation bytes changed')
    config = tomllib.loads(config_file.read_text())
    chain = int(json.loads((observation / 'chain.json').read_text())['result'], 16)
    if type(config['chain_id']) is not int or chain != config['chain_id'] or chain != receipt['requested_chain_id']:
        raise ValueError('chain configuration does not match RPC chain')
    block = json.loads((observation / 'block.json').read_text())['result']
    if block['hash'] != receipt['block_hash']:
        raise ValueError('block identity mismatch')
    timestamp = int(block['timestamp'], 16)
    active = {name.removesuffix('_time'): value for name, value in config.get('hardforks', {}).items()
              if name.endswith('_time') and type(value) is int and value <= timestamp}
    unsupported = sorted({int(tx.get('type', '0x0'), 16) for tx in block['transactions']} - {0, 1, 2, 3, 4})
    return {'schema': 'keth-op-stack-scope-assessment-v1',
            'observation_sha256': digest(observation / 'observation.json'),
            'chain_config_sha256': digest(config_file), 'chain_id': chain, 'chain_name': config['name'],
            'block_number': int(block['number'], 16), 'block_hash': block['hash'],
            'timestamp': timestamp, 'gas_used': int(block['gasUsed'], 16),
            'transactions': len(block['transactions']), 'block_time_seconds': config['block_time'],
            'active_configured_forks': active,
            'unsupported_keth_transaction_types': [hex(value) for value in unsupported],
            'keth_revision': PINS['keth']['revision'],
            'keth_chain_id_admitted': PINS['keth']['supported_chain_id'],
            'keth_execution_compatible': False, 'op_stack_execution_proved': False,
            'op_stack_derivation_proved': False,
            'requirements': [
                'Port deposit/post-execution transaction decoding and fork-specific state transitions into constrained Cairo execution.',
                'Implement and differentially test L1 data fees, operator fees, fee vault credits and fork-specific gas accounting.',
                'Match this chain configuration: timestamps, header fields, block rules, system calls, withdrawals and precompiles.',
                'Acquire execution state/code/trie witnesses and compare every executed block with an OP reference execution client.',
                'Publish and constrain chain/config identity, block hash and pre/post roots; bind the MessagePasser storage root and output root.',
                'Prove L1 data/receipt/blob processing and derivation, or verify a separate derivation proof bound to the identical execution inputs.',
                'Verify every segment plus its consistency proof; implement recursive compression and the intended settlement verifier if a single on-chain proof is required.',
                'Benchmark complete blocks and ranges at this chain block cadence, with repeated trials and retained exact-byte verifier receipts.',
            ],
            'performance_estimate': None,
            'performance_estimate_note': 'An Ethereum gas ratio does not determine OP execution, derivation or settlement proving cost.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observation', type=Path, required=True)
    parser.add_argument('--chain-config', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = assess(args.observation, args.chain_config)
    write_new(args.out, result)
    print(json.dumps(result, indent=2))
