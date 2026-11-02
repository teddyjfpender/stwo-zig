#!/usr/bin/env python3
"""Interrupt a real block bundle, reject changed retained bytes, then resume it.

Every segment is proved and independently verified. This qualification is an
interrupted run, never a fresh block latency or throughput sample.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest.mock import patch

if __package__:
    from . import bundle_benchmark as driver
    from .bridge import claims, digest
    from .summarize_bundle import summarize
    from .verify_bundle import verify
else:
    import bundle_benchmark as driver
    from bridge import claims, digest
    from summarize_bundle import summarize
    from verify_bundle import verify


def run(args):
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    bundle = args.out / 'bundle'
    trial = argparse.Namespace(**{**vars(args), 'out': bundle, 'resume': False,
                               'rss_limit_bytes': 0, 'keep_inputs': False, 'input_format': 'compact'})
    original = driver.run_benchmark

    def interrupted(stage, **kwargs):
        if stage.out.parent.name.startswith('body_'):
            raise RuntimeError('deliberate interruption after the init proof')
        return original(stage, **kwargs)

    result = dict(schema='keth-real-resume-qualification-v1', status='running', claims=claims(),
                  uninterrupted_end_to_end_sample=False)
    receipt = args.out / 'qualification.json'
    driver.save(receipt, result)
    try:
        with patch.object(driver, 'run_benchmark', side_effect=interrupted):
            try:
                driver.run(trial)
            except RuntimeError as error:
                if str(error) != 'deliberate interruption after the init proof':
                    raise
            else:
                raise ValueError('the deliberate interruption did not occur')
        failed = json.loads((bundle / 'bundle-results.json').read_text())
        if [s['status'] for s in failed['segments']] != ['qualified', 'failed']:
            raise ValueError('unexpected interrupted prefix')
        result['interrupted_manifest_sha256'] = digest(bundle / 'bundle-results.json')
        proof = bundle / 'init/proofs/trial-1.proof.json.bz2'
        original_bytes = proof.read_bytes()
        trial.resume = True
        try:
            proof.write_bytes(original_bytes + b'changed-retained-proof')
            try:
                driver.run(trial)
            except ValueError as error:
                if str(error) != 'retained proof hash mismatch':
                    raise
                result['changed_retained_bytes_rejected'] = True
            else:
                raise ValueError('changed retained proof was accepted')
        finally:
            proof.write_bytes(original_bytes)
        if digest(bundle / 'bundle-results.json') != result['interrupted_manifest_sha256']:
            raise ValueError('rejected resume modified the interrupted manifest')
        completed = driver.run(trial)
        if completed.get('resumed_segments') != 1 or not completed.get('interrupted'):
            raise ValueError('resume lost its interrupted measurement scope')
        result['reverification'] = verify(bundle, args.oracle)
        result['summary'] = summarize(bundle)
        result['status'] = 'qualified-real-interrupted-resume'
    except Exception as error:
        result.update(status='failed', error=str(error), error_type=type(error).__name__)
        raise
    finally:
        driver.save(receipt, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('keth-checkout', 'fixture', 'product', 'oracle', 'converter', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--rpc-snapshot', type=Path)
    parser.add_argument('--rpc-parent', type=Path)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--chunk-size', type=int, default=4)
    parser.add_argument('--max-address-space-gib', type=int, default=0)
    args = parser.parse_args()
    print(json.dumps({'status': run(args)['status']}))
