#!/usr/bin/env python3
"""Summarize a fully qualified serial block bundle; never extrapolate segments."""
from __future__ import annotations

import argparse
import json
import re
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
                                                'official_verification_wall_ns': 0, 'peak_product_rss_bytes': 0,
                                                'peak_file_backing_bytes': 0, 'memory_modes': [], 'worker_counts': []})
        role['proof_count'] += 1
        role['cairo_opcode_transitions'] += segment['conversion']['execution_steps']
        trial = segment['trial']
        role['product_wall_ns'] += trial['process']['wall_ns']
        role['prove_ns'] += trial['timing']['prove_ns']
        role['official_verification_wall_ns'] += trial['official_verifier']['wall_ns']
        role['peak_product_rss_bytes'] = max(role['peak_product_rss_bytes'], trial['process']['max_process_tree_rss_bytes'])
        controls = segment['benchmark']['controlled_environment']
        mode = 'temporary-file-backed' if controls.get('STWO_CAIRO_FILE_BACKED_ALLOCATOR') == '1' else 'ordinary'
        if mode not in role['memory_modes']:
            role['memory_modes'].append(mode)
        workers = int(controls.get('STWO_ZIG_WORKERS', manifest['workers']))
        if workers not in role['worker_counts']:
            role['worker_counts'].append(workers)
        log = (bundle / segment['name'] / 'proofs/trial-1.product.log').read_text()
        backing = re.search(r'peak_backing_bytes=(\d+)', log)
        if backing:
            role['peak_file_backing_bytes'] = max(role['peak_file_backing_bytes'], int(backing.group(1)))
    proof_bytes = sum(json.loads((bundle / s['name'] / 'proofs/trial-1.report.json').read_text())['proof']['bytes'] for s in segments)
    compressed = sum((bundle / s['name'] / 'proofs/trial-1.proof.json.bz2').stat().st_size for s in segments)
    return {'schema': 'keth-block-bundle-summary-v1', 'status': manifest['status'],
            'workload': manifest['workload'], 'complete_bundle_samples': 1,
            'measurement_sessions': len(manifest.get('sessions', [None])),
            'uninterrupted_end_to_end_sample': not manifest.get('interrupted', False),
            'proof_count': len(segments), 'workers': manifest['workers'],
            'host': segments[0]['benchmark']['host_details'],
            'witness_transports': sorted({Path(s['benchmark']['workload']['path']).suffix for s in segments}),
            'elapsed_wall_ns': None if manifest.get('adopted_stage_measurements') else manifest['elapsed_wall_ns'],
            'recorded_driver_session_wall_ns': manifest['elapsed_wall_ns'],
            'standalone_stage_retries': manifest.get('adopted_stage_measurements', []),
            'native_trace_wall_ns': sum(s['trace']['wall_ns'] for s in segments),
            'witness_conversion_wall_ns': sum(s['conversion']['wall_ns'] for s in segments),
            'product_wall_ns': sum(r['product_wall_ns'] for r in roles.values()),
            'prove_ns': sum(r['prove_ns'] for r in roles.values()),
            'official_verification_wall_ns': sum(r['official_verification_wall_ns'] for r in roles.values()),
            'cairo_opcode_transitions': sum(r['cairo_opcode_transitions'] for r in roles.values()),
            'peak_product_rss_bytes': max(r['peak_product_rss_bytes'] for r in roles.values()),
            'peak_file_backing_bytes': max(r['peak_file_backing_bytes'] for r in roles.values()),
            'producer_binary_sha256s': sorted({s['benchmark']['product_sha256'] for s in segments}),
            'peak_trace_rss_bytes': max(s['trace']['max_process_tree_rss_bytes'] for s in segments),
            'proof_json_bytes': proof_bytes, 'compressed_proof_bytes': compressed,
            'roles': roles, 'claims': manifest['claims'],
            'notes': ['Compilation excluded; serial segments; fresh bundle cache retained across segments.',
                      'Elapsed time sums active measurement sessions; includes failed attempts and resume rechecks, excludes time between sessions.',
                      'Product time includes loading, proving, Zig verification and publication.',
                      'RSS is Linux wait4 per-process/descendant peak, not simultaneous parent-child sum.',
                      'File-backed mode uses temporary disk and reclaimable filesystem cache; RSS is not total physical footprint.',
                      'Consistency proof is not recursive aggregation; every child independently verifies.']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(summarize(args.bundle), indent=2))
