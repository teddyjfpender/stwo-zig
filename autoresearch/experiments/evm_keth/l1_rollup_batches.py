#!/usr/bin/env python3
"""Locate configured rollup inbox submissions in a verified L1 workload.

An inbox match identifies an L1 submission. Payload authorization, blob data,
derivation and L2 execution require their own verification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import tomllib

if __package__:
    from .bridge import digest, write_new
    from .verify_bundle import check_manifest
else:
    from bridge import digest, write_new
    from verify_bundle import check_manifest


def characterize(fixture: Path, bundle: Path, configs: list[Path]) -> dict:
    manifest_path = bundle / 'bundle-results.json'
    manifest = json.loads(manifest_path.read_text())
    check_manifest(manifest)
    if digest(fixture) != manifest['workload']['fixture_sha256']:
        raise ValueError('fixture differs from verified workload')
    transactions = json.loads(fixture.read_text())['blocks'][0]['transaction']
    configured = {}
    for path in configs:
        config = tomllib.loads(path.read_text())
        configured[config['batch_inbox_addr'].lower()] = (config, path)
    submissions = []
    for index, tx in enumerate(transactions):
        address = (tx.get('to') or '').lower()
        if address not in configured:
            continue
        config, path = configured[address]
        segment = next(s for s in manifest['segments'] if s['role'] == 'body' and s['indices'][0] <= index < sum(s['indices']))
        submissions.append({'transaction_index': index, 'transaction_hash': tx['hash'],
            'transaction_type': tx['type'], 'inbox': address, 'chain_id': config['chain_id'],
            'chain_name': config['name'], 'chain_config_sha256': digest(path),
            'gas_limit': int(tx['gas'], 16), 'calldata_bytes': len(bytes.fromhex(tx['input'].removeprefix('0x'))),
            'blob_versioned_hashes': tx.get('blobVersionedHashes', []),
            'segment': segment['name'], 'segment_transaction_count': segment['indices'][1],
            'segment_cairo_transitions': segment['conversion']['execution_steps'],
            'segment_prove_ns': segment['trial']['timing']['prove_ns'],
            'segment_peak_rss_bytes': segment['trial']['process']['max_process_tree_rss_bytes'],
            'segment_proof_sha256': segment['trial']['proof_sha256'],
            'l1_execution_segment_verified': True, 'blob_data_verified': False,
            'batch_authorization_verified': False, 'l2_derivation_proved': False, 'l2_execution_proved': False})
    return {'schema': 'keth-l1-rollup-submissions-v1', 'fixture_sha256': digest(fixture),
            'manifest_sha256': digest(manifest_path), 'submissions': submissions,
            'scope': 'configured inbox matches within an independently verified L1 execution workload'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--chain-config', type=Path, action='append', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = characterize(args.fixture, args.bundle, args.chain_config)
    write_new(args.out, result)
    print(json.dumps(result, indent=2))
