#!/usr/bin/env python3
"""ABBA comparison of disabled/enabled PCS graph reuse in one producer binary.

Each fresh process proves two identical admitted parents, counting cold cache
construction. All outputs are verified after producer exit against qualified pins.
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time

from parent_pair import sha, save, stats


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=3)
    args = parser.parse_args()
    if args.rounds < 3:
        parser.error('at least three ABBA rounds required')
    r = json.loads(args.receipt.read_bytes())
    admitted = r['cases'][0]['receipt']
    if not r['passed'] or not admitted['verified'] or admitted['native_inputs_used']:
        raise ValueError('independent admission required')
    expected = {f: bytes(admitted[k]).hex() for f, k in
                [('key.json', 'key_sha256'), ('claims.json', 'claims_sha256'), ('proof.bin', 'proof_sha256')]}
    original = r['producer']['argv']
    pos = original.index('--profile')
    if {f: sha(Path(original[pos + 2]) / f) for f in expected} != expected:
        raise ValueError('original artifact pin mismatch')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if not k.startswith('STWO_')}
    env['STWO_RISCV_RECURSIVE_PARENT_PROFILE'] = '1'
    binary = args.producer.resolve()
    save(out / 'provenance.json', {'producer_sha256': sha(binary), 'receipt_sha256': sha(args.receipt),
                                 'verifier_sha256': sha(Path(r['cases'][0]['argv'][0])),
                                 'driver_sha256': sha(Path(__file__)), 'expected_artifacts': expected,
                                 'scope': 'two requests per fresh process; cold cache cost included; local advisory'})
    samples = []
    for index, arm in enumerate(['off', 'on'] + ['off', 'on', 'on', 'off'] * args.rounds):
        directory = out / f'{index}-{arm}'
        directory.mkdir()
        requests = []
        for j in range(2):
            request = original[pos:].copy()
            request[2] = str(directory / f'parent-{j}')
            requests.append(request)
        manifest = directory / 'requests.json'
        save(manifest, {'version': 1, 'session_byte_budget': 67108864,
                        'retained_scratch_byte_limit': 268435456,
                        'pcs_plan_byte_budget': 268435456 if arm == 'on' else 0,
                        'requests': requests})
        argv = [str(binary), *original[1:pos], '--batch', str(manifest), sha(manifest)]
        started = time.monotonic_ns()
        with (directory / 'producer.log').open('x') as log:
            subprocess.run(['/usr/bin/time', '-l', *argv], env=env, stdout=log,
                           stderr=subprocess.STDOUT, check=True, timeout=180)
        seconds = (time.monotonic_ns() - started) / 1e9
        text = (directory / 'producer.log').read_text()
        report = next(json.loads(line) for line in text.splitlines()
                      if line.startswith('{"endpoint":"detached_parent_batch"'))
        if report['requests'] != 2 or report['plan_builds'] != 1:
            raise RuntimeError('workspace lifecycle mismatch')
        if arm == 'off' and (report['pcs_plan_hits'] != 0 or report['pcs_plan_retained_bytes'] != 0):
            raise RuntimeError('disabled cache retained state')
        for j in range(2):
            bundle = directory / f'parent-{j}'
            verify = r['cases'][0]['argv'].copy()
            verify[1] = str(bundle)
            result = subprocess.run(verify, env=env, capture_output=True, text=True, check=True, timeout=60)
            accepted = json.loads(result.stdout)
            if not accepted['verified'] or accepted['native_inputs_used']:
                raise RuntimeError('standalone verification failed')
            if {f: sha(bundle / f) for f in expected} != expected:
                raise RuntimeError('qualified artifact mismatch')
            (directory / f'verified-{j}.json').write_text(result.stdout)
        samples.append({'arm': arm, 'warmup': index < 2, 'process_seconds': seconds,
                        'pcs_plan_builds': report['pcs_plan_builds'], 'pcs_plan_hits': report['pcs_plan_hits'],
                        'pcs_plan_retained_bytes': report['pcs_plan_retained_bytes'], 'argv': argv,
                        'verified': True, 'producer_log_sha256': sha(directory / 'producer.log')})
        save(out / 'samples.json', samples)
        print(index, arm, round(seconds, 4), 'seconds; builds', report['pcs_plan_builds'],
              'hits', report['pcs_plan_hits'], 'both proofs verified identical', flush=True)
    measured = samples[2:]
    ratios = []
    for i in range(0, len(measured), 4):
        group = measured[i:i + 4]
        median = lambda arm: statistics.median(s['process_seconds'] for s in group if s['arm'] == arm)
        ratios.append(median('on') / median('off'))
    ratio = stats.hodges_lehmann(ratios)
    ci = stats.bootstrap_ci(ratios, seed=198)
    summary = {'median_seconds': {arm: statistics.median(s['process_seconds'] for s in measured if s['arm'] == arm)
                                  for arm in ('off', 'on')},
               'paired_ratios': ratios, 'on_over_off': ratio, 'ci95': ci,
               'speedup': 1 / ratio, 'improvement_supported': ci[1] < 1}
    save(out / 'summary.json', summary)
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
