#!/usr/bin/env python3
"""Opt-in D2/coalescing gates only after the exact composed M6 asset gate passes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def sha(path):
    with Path(path).open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--provenance', required=True, type=Path)
    p.add_argument('--receiver', required=True, type=Path)
    p.add_argument('--mode', required=True, choices=['d2', 'coalesce', 'd2-coalesce'])
    p.add_argument('--tag', required=True)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    source = Path(__file__).resolve().parent.parent
    proven = json.loads(args.provenance.read_text())
    for block in [26235156, 24628607]:
        if not any(r.get('block') == block and r.get('exit') == 0 and r.get('all_m6_bytes') is True and r.get('fresh_cpu_accepted') is True for r in proven.get('runs', [])):
            raise RuntimeError('composed M6 bytes/fresh acceptance gate incomplete for ' + str(block))
    driver = Path('/workspace/m3/build/m7-combined-residency/zig-out/bin/rv64-word16-ethereum-gpu-combined')
    library = Path('/workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so')
    expected = {'driver': proven['driver_sha256'], 'library': proven['library_sha256'], 'receiver': sha(args.receiver)}
    preset = list(proven['preset'])
    if 'STWO_RV64_CPU_COMPACT_INGRESS=1' not in preset:
        raise RuntimeError('combined gate must exercise compact ingress')
    profile = 'd2_native_b4_q54_p20_fold4' if 'd2' in args.mode else 'conjectured128_b2_q108_p20_fold4'
    coalesce = 'coalesce' in args.mode
    args.out.mkdir(parents=True, exist_ok=True)
    result = {'schema': 'rv64-m7-combined-candidate-gate/v1', 'mode': args.mode, 'profile': profile, 'm6_provenance_sha256': sha(args.provenance), 'assets': expected, 'preset': preset, 'runs': []}
    env = {k: v for k, v in os.environ.items() if not k.startswith(('STWO_RV64_', 'STWO_ZIG_RV64_SETUP'))}
    for block in [26235156, 24628607]:
        if sha(driver) != expected['driver'] or sha(library) != expected['library'] or sha(args.receiver) != expected['receiver']:
            raise RuntimeError('frozen asset mutated')
        run = Path('/workspace/m3/runs/m7-fold-v3') / f'daemon-{block}-r2-{args.tag}'
        command = [sys.executable, str(source / 'scripts/rv64_m4_resident.py'), 'daemon', str(block), '--stream', 'm7-fold-v3', '--repeat', '2', '--store', 'none', '--receive', 'first', '--nsys', '--security-profile', profile, '--driver', str(driver), '--library', str(library), '--receiver', str(args.receiver), '--tag', args.tag]
        if coalesce:
            command += ['--coalesce-truth-families']
        for flag in preset:
            command += ['--env', flag]
        (args.out / f'{block}-command.json').write_text(json.dumps(command, indent=2) + '\n')
        with (args.out / f'{block}.log').open('w') as log:
            code = subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        row = {'block': block, 'run': str(run), 'exit': code}
        result['runs'].append(row)
        (args.out / 'gate.json').write_text(json.dumps(result, indent=2) + '\n')
        if code:
            raise RuntimeError('producer/receiver gate failed: ' + str(block))
        receipt = json.loads((run / 'receipt.json').read_text())
        expected_leaves = 11 if block == 26235156 else (14 if coalesce else 17)
        if not all(r['output_matches_pin'] and r['leaves'] == expected_leaves for r in receipt['requests']):
            raise RuntimeError('actual native leaf count/output gate failed')
        if not receipt['receivers'] or not all(r['accepted'] for r in receipt['receivers']):
            raise RuntimeError('fresh isolated receiver failed')
        row['actual_native_leaves'] = expected_leaves
        row['fresh_cpu_accepted'] = True
        with (args.out / f'{block}-gpu-seconds.log').open('w') as log:
            rc = subprocess.run([sys.executable, str(source / 'scripts/rv64_m7_gpu_seconds.py'), str(run), '--accepted-run', str(run)], stdout=log, stderr=subprocess.STDOUT).returncode
        row['gpu_accounting_complete'] = rc == 0
        (args.out / 'gate.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=1))


if __name__ == '__main__':
    main()
