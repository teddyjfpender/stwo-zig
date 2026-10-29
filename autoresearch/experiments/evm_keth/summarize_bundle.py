#!/usr/bin/env python3
"""Summarize a fully qualified serial block bundle; never extrapolate segments."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from verify_bundle import check_manifest


def summarize(bundle: Path) -> dict:
    manifest = json.loads((bundle / 'bundle-results.json').read_text())
    check_manifest(manifest)
    segments = manifest['segments']
    roles = {}
    for segment in segments:
        role = roles.setdefault(segment['role'], {'proof_count': 0, 'cairo_opcode_transitions': 0,
                                                'product_wall_ns': 0, 'prove_ns': 0,
                                                'official_verification_wall_ns': 0, 'peak_product_rss_bytes': 0})
        role['proof_count'] += 1
        role['cairo_opcode_transitions'] += segment['conversion']['execution_steps']
        trial = segment['trial']
        role['product_wall_ns'] += trial['process']['wall_ns']
        role['prove_ns'] += trial['timing']['prove_ns']
        role['official_verification_wall_ns'] += trial['official_verifier']['wall_ns']
        role['peak_product_rss_bytes'] = max(role['peak_product_rss_bytes'], trial['process']['max_process_tree_rss_bytes'])
    proof_bytes = sum(json.loads((bundle / s['name'] / 'proofs/trial-1.report.json').read_text())['proof']['bytes'] for s in segments)
    compressed = sum((bundle / s['name'] / 'proofs/trial-1.proof.json.bz2').stat().st_size for s in segments)
    return {'schema': 'keth-block-bundle-summary-v1', 'status': manifest['status'],
            'workload': manifest['workload'], 'complete_bundle_samples': 1,
            'proof_count': len(segments), 'workers': manifest['workers'],
            'host': segments[0]['benchmark']['host_details'],
            'witness_transport': Path(segments[0]['benchmark']['workload']['path']).suffix,
            'elapsed_wall_ns': manifest['elapsed_wall_ns'],
            'native_trace_wall_ns': sum(s['trace']['wall_ns'] for s in segments),
            'witness_conversion_wall_ns': sum(s['conversion']['wall_ns'] for s in segments),
            'product_wall_ns': sum(r['product_wall_ns'] for r in roles.values()),
            'prove_ns': sum(r['prove_ns'] for r in roles.values()),
            'official_verification_wall_ns': sum(r['official_verification_wall_ns'] for r in roles.values()),
            'cairo_opcode_transitions': sum(r['cairo_opcode_transitions'] for r in roles.values()),
            'peak_product_rss_bytes': max(r['peak_product_rss_bytes'] for r in roles.values()),
            'peak_trace_rss_bytes': max(s['trace']['max_process_tree_rss_bytes'] for s in segments),
            'proof_json_bytes': proof_bytes, 'compressed_proof_bytes': compressed,
            'roles': roles, 'claims': manifest['claims'],
            'notes': ['Compilation excluded; serial segments; fresh bundle cache retained across segments.',
                      'Product time includes loading, proving, Zig verification and publication.',
                      'RSS is Linux wait4 per-process/descendant peak, not simultaneous parent-child sum.',
                      'Consistency proof is not recursive aggregation; every child independently verifies.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.bundle), indent=2))
