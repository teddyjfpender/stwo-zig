#!/usr/bin/env python3
"""Local advisory ABBA replay of an independently admitted recursive parent.

Uses a retained parent gate receipt, rebuilds neither arm, and freshly verifies
both arms against the receipt's original key/claim/proof hashes. Build both arms
from their pinned source snapshots before invoking; do not compile while timing.
This endpoint is not a scored stwo-perf board and never writes a judged verdict.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'autoresearch/cli'))
from stwo_perf import stats


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2) + '\n')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=4)
    args = parser.parse_args()
    if args.rounds < 3:
        parser.error('at least three ABBA rounds are required')
    receipt = json.loads(args.receipt.read_text())
    template = receipt['producer']['argv']
    output_index = template.index('--profile') + 2
    original = Path(template[output_index])
    admitted = receipt['cases'][0]['receipt']
    if not receipt['passed'] or not admitted['verified'] or admitted['native_inputs_used']:
        raise RuntimeError('receipt must independently admit the original parent')
    expected = {name: bytes(admitted[field]).hex() for name, field in
                (('key.json', 'key_sha256'), ('claims.json', 'claims_sha256'), ('proof.bin', 'proof_sha256'))}
    if any(sha(original / name) != pin for name, pin in expected.items()):
        raise RuntimeError('original artifacts no longer match the admitted receipt')
    binaries = {'baseline': args.baseline.resolve(), 'candidate': args.candidate.resolve()}
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    env = {key: value for key, value in os.environ.items() if not key.startswith('STWO_')}
    env['STWO_RISCV_RECURSIVE_PARENT_PROFILE'] = '1'
    save(out / 'provenance.json', {
        'scope': 'local advisory complete-parent ABBA, not a judged board result',
        'receipt': str(args.receipt.resolve()), 'receipt_sha256': sha(args.receipt),
        'binary_sha256': {arm: sha(path) for arm, path in binaries.items()},
        'verifier_sha256': sha(Path(receipt['cases'][0]['argv'][0])),
        'expected_artifacts': expected, 'rounds': args.rounds,
        'environment': {'STWO_RISCV_RECURSIVE_PARENT_PROFILE': '1'},
    })
    samples = []
    for index, arm in enumerate(['baseline', 'candidate'] + ['baseline', 'candidate', 'candidate', 'baseline'] * args.rounds):
        argv = template.copy()
        argv[0] = str(binaries[arm])
        bundle = out / f'{index}-{arm}'
        argv[output_index] = str(bundle)
        log = out / f'{index}-{arm}.log'
        started = time.monotonic_ns()
        with log.open('w') as stream:
            subprocess.run(['/usr/bin/time', '-l', *argv], env=env, stdout=stream, stderr=subprocess.STDOUT, check=True, timeout=180)
        elapsed = (time.monotonic_ns() - started) / 1e9
        verify = receipt['cases'][0]['argv'].copy()
        verify[1] = str(bundle)
        result = subprocess.run(verify, env=env, capture_output=True, text=True, check=True, timeout=60)
        verified = json.loads(result.stdout)
        if not verified['verified'] or verified['native_inputs_used']:
            raise RuntimeError('independent verification failed')
        hashes = {name: sha(bundle / name) for name in expected}
        if hashes != expected:
            raise RuntimeError(f'{arm}: qualified artifact identity mismatch')
        (out / f'{index}-{arm}.verified.json').write_text(result.stdout)
        text = log.read_text()
        rss = re.search(r'(\d+)\s+maximum resident set size', text)
        phases = {name: sum(map(int, re.findall(name + r'=(\d+)', text))) / 1e9
                  for name in ('capture_ns', 'authority_ns', 'rows_ns', 'source_projection_ns', 'typed_ns')}
        samples.append({'arm': arm, 'warmup': index < 2, 'process_seconds': elapsed,
                        'maximum_rss_bytes': int(rss[1]) if rss else None,
                        'phases_seconds': phases, 'argv': argv, 'verify_argv': verify,
                        'artifacts': hashes, 'verified': True, 'log_sha256': sha(log)})
        save(out / 'samples.json', samples)
        print(index, arm, f'{elapsed:.4f}s; verified identical artifacts', flush=True)
    measured = samples[2:]
    ratios = []
    for offset in range(0, len(measured), 4):
        group = measured[offset:offset + 4]
        median = lambda arm: statistics.median(row['process_seconds'] for row in group if row['arm'] == arm)
        ratios.append(median('candidate') / median('baseline'))
    medians = {arm: statistics.median(row['process_seconds'] for row in measured if row['arm'] == arm) for arm in binaries}
    ratio = stats.hodges_lehmann(ratios)
    ci = stats.bootstrap_ci(ratios, seed=198)
    summary = {'median_seconds': medians, 'paired_round_ratios': ratios,
               'candidate_over_baseline': ratio, 'ratio_ci95': ci,
               'speedup': 1 / ratio, 'improvement_supported': ci[1] < 1,
               'samples_per_arm': args.rounds * 2}
    save(out / 'summary.json', summary)
    print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
