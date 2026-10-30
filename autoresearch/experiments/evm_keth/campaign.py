#!/usr/bin/env python3
"""Repeat complete serial Keth bundles, reverify all bytes, report dispersion."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics
import time

if __package__:
    from .bundle_benchmark import run, save
    from .bridge import claims, digest
    from .limits import default_address_space_gib
    from .summarize_bundle import summarize
    from .verify_bundle import verify
else:
    from bundle_benchmark import run, save
    from bridge import claims, digest
    from limits import default_address_space_gib
    from summarize_bundle import summarize
    from verify_bundle import verify


def campaign(args):
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    output = args.out / 'campaign.json'
    result = {'schema': 'keth-complete-bundle-campaign-v1', 'status': 'running',
              'requested_complete_trials': args.trials, 'trials': [], 'claims': claims(),
              'cache_policy': 'fresh preprocessed cache per bundle; inherited Metal disk archive; all trials recorded',
              'workload_fixture_sha256': digest(args.fixture), 'product_sha256': digest(args.product),
              'oracle_sha256': digest(args.oracle), 'workers': args.workers, 'chunk_size': args.chunk_size}
    started = time.monotonic_ns()
    save(output, result)
    try:
        for index in range(args.trials):
            directory = args.out / f'trial-{index+1}'
            trial = {'index': index+1, 'status': 'running', 'bundle': str(directory)}
            result['trials'].append(trial)
            save(output, result)
            trial_args = argparse.Namespace(**{'resume': False, 'rss_limit_bytes': 0, **vars(args), 'out': directory})
            run(trial_args)
            receipt = verify(directory, args.oracle)
            save(directory / 'reverification.json', receipt)
            summary = summarize(directory)
            save(directory / 'summary.json', summary)
            trial.update(status='qualified', manifest_sha256=receipt['manifest_sha256'],
                         proof_count=receipt['proof_count'], summary=summary)
            save(output, result)
        result['statistics'] = {}
        for metric in ('elapsed_wall_ns', 'prove_ns', 'native_trace_wall_ns', 'witness_conversion_wall_ns'):
            samples = [t['summary'][metric] for t in result['trials']]
            result['statistics'][metric] = {'samples': samples, 'median': statistics.median(samples),
                'minimum': min(samples), 'maximum': max(samples),
                'sample_stdev': statistics.stdev(samples) if len(samples) > 1 else None}
        result['status'] = 'qualified-complete-bundle-campaign'
    except Exception as error:
        result.update(status='failed', error_type=type(error).__name__, error=str(error))
        if result['trials'] and result['trials'][-1]['status'] == 'running':
            result['trials'][-1]['status'] = 'failed'
        raise
    finally:
        result['elapsed_wall_ns_including_reverification'] = time.monotonic_ns() - started
        save(output, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('keth-checkout', 'fixture', 'product', 'oracle', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--converter', type=Path)
    parser.add_argument('--rpc-snapshot', type=Path)
    parser.add_argument('--rpc-parent', type=Path)
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--chunk-size', type=int, default=4)
    parser.add_argument('--input-format', choices=('json', 'compact'), default='compact')
    parser.add_argument('--max-address-space-gib', type=int, default=default_address_space_gib())
    parser.add_argument('--keep-inputs', action='store_true')
    parser.add_argument('--rss-limit-bytes', type=int, default=0, help='optional Linux RSS guard')
    args = parser.parse_args()
    if not 1 <= args.trials <= 100 or min(args.workers, args.chunk_size) < 1 or min(args.max_address_space_gib, args.rss_limit_bytes) < 0:
        parser.error('invalid trial, worker, chunk or memory count')
    result = campaign(args)
    print(json.dumps({'status': result['status'], 'statistics': result['statistics']}, indent=2))
