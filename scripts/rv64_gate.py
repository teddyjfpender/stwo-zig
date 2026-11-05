#!/usr/bin/env python3
"""P0 commit gate: build, unit tests, prove, frozen parity, fresh CPU, corpus.

This is a correctness gate, not a performance experiment. Timing experiments
continue to use rv64_m7_integration_stack.py run (interleaved 3+3). The gate
uses that runner's baseline command and preset with a unique service tag.
The CUDA image is an explicit pinned build input, never an implicit stale
output of a host rebuild. A CUDA change must supply a newly built manifest.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import rv64_m7_integration_stack as stack

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / 'vectors/reports/rv64-m7-20261105/d2-composed/combined-d2-package'
RUNTIME = ROOT / 'design/riscv-proving-stack/m7-handoff/p0-runtime.json'
# A positive control plus byte, statement, cross-block, and coherent mutations.
# Coherent mutations rewrite bundle hashes and exercise semantic verification.
CASES = ('C00-control', 'S08-coherent-permute-native', 'S09-coherent-drop-native',
         'S10-coherent-dup-native', 'S11-coherent-permute-truth',
         'V02-cross-block-fold', 'V03-cross-block-leaf', 'V04-cross-block-root',
         'V05-cross-block-native', 'R04-root-proof-flip', 'R05-root-proof-truncate',
         'R06-leaf-proof-flip', 'R07-coherent-native-flip', 'R09-coherent-truth-flip',
         'X03-coherent-stage-one-flip', 'X04-coherent-cells-flip',
         'X06-coherent-terminal-value', 'T01-wrong-output', 'P01-wrong-native-profile')


def payload_name(name):
    # *.stages.json is process/timing telemetry (services/profiling.zig).
    # candidate-fixed-setup.json is a setup/cache report: its validation
    # counters differ between cold and warm requests (ethereum/gkr_main.zig).
    # Receiver-owned proof/binding artifacts below must still match exactly.
    return (name.endswith(('.bin', '.proof')) or
            name in ('bundle.json', 'candidate-source-bounds.json',
                     'recursion-om31/tree.json'))


def frozen_parity(proof, golden):
    expected = {name: row for name, row in golden.items() if payload_name(name)}
    if not expected or 'recursion-om31/root.proof' not in expected:
        raise RuntimeError('frozen default has no complete proof fingerprints')
    actual = {str(p.relative_to(proof)): {'sha256': stack.sha(p), 'bytes': p.stat().st_size}
              for p in proof.rglob('*') if p.is_file() and payload_name(str(p.relative_to(proof)))}
    if actual != expected:
        differences = sorted(k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k))
        raise RuntimeError('frozen default mismatch: ' + ', '.join(differences))
    return {'byte_identical': True, 'artifact_count': len(actual), 'fingerprints': actual}


def check_corpus(receipt):
    results = receipt.get('results', [])
    ids = [row['id'] for row in results]
    if len(ids) != len(CASES) or set(ids) != set(CASES):
        raise RuntimeError('negative corpus omitted or duplicated required cases')
    if receipt.get('unsupported') or not all(row.get('passed') is True for row in results):
        raise RuntimeError('negative corpus failed or skipped required cases')
    if receipt.get('crashes') or receipt.get('unexpected_accepts'):
        raise RuntimeError('negative corpus crashed or unexpectedly accepted')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stream', default='m7-integrate')
    p.add_argument('--out', required=True, type=Path, help='new unique receipt directory')
    p.add_argument('--runtime', default=RUNTIME, type=Path)
    p.add_argument('--block', type=int, choices=(26235156, 24628607), default=26235156)
    p.add_argument('--donor', type=Path, help='accepted opposite dev block; frozen D2 run by default')
    p.add_argument('--source-commit', required=True)
    args = p.parse_args()
    if ROOT != Path('/workspace/m3/src') / args.stream:
        p.error('run only in the synced pod source tree; no laptop builds')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = {'schema': 'rv64-commit-gate/v1', 'status': 'RUNNING',
               'source_commit': args.source_commit, 'source_sha256': stack.source_hashes(ROOT),
               'block': args.block, 'steps': [], 'timing_scope': 'correctness only; no speed claim'}
    env = stack.clean_environment(os.environ)
    env['ZIG_GLOBAL_CACHE_DIR'] = '/workspace/m3/cache/zig-global'
    env['TMPDIR'] = '/workspace/m3/tmp'

    def run(name, argv, cwd=ROOT, environment=None):
        step = {'name': name, 'argv': [str(a) for a in argv], 'started_ns': time.time_ns()}
        receipt['steps'].append(step)
        stack.write(out / 'gate.json', receipt)
        print('GATE ' + name, flush=True)
        with (out / (name + '.log')).open('w') as log:
            code = subprocess.run(step['argv'], cwd=cwd, env=environment or env,
                                  stdout=log, stderr=subprocess.STDOUT).returncode
        step.update(exit_code=code, finished_ns=time.time_ns())
        stack.write(out / 'gate.json', receipt)
        if code:
            raise RuntimeError(f'{name} failed ({code}); see {out / (name + ".log")}')

    try:
        runtime = json.loads(args.runtime.read_text())
        assets = dict(runtime['assets'])
        for name, path in assets.items():
            if stack.sha(path) != runtime['asset_sha256'][name]:
                raise RuntimeError('pinned runtime changed: ' + name)
        receipt['runtime'] = runtime
        lock = ['flock', '-w', '7200', '/workspace/m3/locks/build.1.lock']
        run('build', lock + [sys.executable, 'scripts/rv64_m3_pod.py', 'build',
                            '--stream', args.stream, '--only', 'zig'])
        run('unit-zig', lock + ['/workspace/zig/zig', 'build', 'test',
                               'test-rv64-recursion-ready', 'test-rv64-batch-plan',
                               'test-rv64-gkr-plan', 'test-rv64-pcs-geometry',
                               '-j2', '-Doptimize=ReleaseSafe', '-Dtarget=x86_64-linux-gnu',
                               '-Dcpu=x86_64_v4+sha', '--cache-dir', str(ROOT / '.zig-cache')],
            ROOT / 'src/integrations/riscv_cuda')
        run('unit-python', [sys.executable, '-m', 'unittest',
                            'scripts.tests.test_rv64_gate', 'scripts.tests.test_rv64_m7_composed_cells'])
        bins = Path('/workspace/m3/build') / args.stream / 'zig-out/bin'
        assets.update(driver=str(bins / 'rv64-word16-ethereum-gpu-combined'),
                      receiver=str(bins / 'rv64-word16-ethereum-recursion-receiver'))
        manifest = {'source_root': str(ROOT), 'assets': assets, 'block': args.block,
                    'preset': json.loads(stack.DEFAULT_PRESET.read_text())}
        receipt['preset'] = manifest['preset']
        receipt['preset_sha256'] = stack.sha(stack.DEFAULT_PRESET)
        receipt['asset_sha256'] = {name: stack.sha(path) for name, path in assets.items()}
        label = 'gate-' + out.name
        argv, tag = stack.command(manifest, 'baseline', 0, args.stream, False, label)
        # Keep quiet observations but do not call correctness walls matched timings.
        argv += ['--quiet-mode', 'diagnostic', '--request-timeout', '240']
        run('small-block-proof', argv)
        service = Path('/workspace/m3/runs') / args.stream / f'daemon-{args.block}-r2-{tag}'
        receipt['service'] = str(service)
        produced = json.loads((service / 'receipt.json').read_text())
        if len(produced['requests']) != 2:
            raise RuntimeError('expected cold and warm proofs')
        golden_path = GOLDEN / f'{args.block}-combined-d2-coalesce-v1/trial-1/artifact-fingerprints.json'
        golden = json.loads(golden_path.read_text())
        receipt['frozen_default_sha256'] = stack.sha(golden_path)
        receipt['parity'] = [frozen_parity(Path(row['proof']), golden) for row in produced['requests']]
        stack.write(out / 'gate.json', receipt)
        run('fresh-cpu-receiver', [sys.executable, 'scripts/rv64_m4_resident.py', 'receive',
                                    '--run', str(service), '--which', 'all'])
        verified = json.loads((service / 'receipt.json').read_text())
        if len(verified['receivers']) != 2 or not all(r.get('accepted') for r in verified['receivers']):
            raise RuntimeError('fresh CPU receivers did not accept both proofs')
        receipt['receivers'] = verified['receivers']
        donor_block = 24628607 if args.block == 26235156 else 26235156
        donor = args.donor or Path(f'/workspace/m3/runs/m7-fold-v3/daemon-{donor_block}-r2-combined-d2-coalesce-v1')
        corpus_env = dict(env, STWO_RV64_OUTER_PROFILE=manifest['preset']['common']['STWO_RV64_OUTER_PROFILE'],
                          STWO_RV64_NATIVE_VERSION='v1-flat')
        run('negative-corpus', [sys.executable, 'scripts/rv64_m5_negative_corpus.py', 'run',
                               '--run', str(service), '--donor', str(donor), '--format', 'm5-audit',
                               '--receiver', assets['receiver'], '--jobs', '1', '--cases', ','.join(CASES),
                               '--work', str(out / 'corpus-work'), '--out', str(out / 'corpus.json')],
            environment=corpus_env)
        check_corpus(json.loads((out / 'corpus.json').read_text()))
        if stack.source_hashes(ROOT) != receipt['source_sha256']:
            raise RuntimeError('source changed during gate; rebuild and rerun')
        if stack.sha(stack.DEFAULT_PRESET) != receipt['preset_sha256']:
            raise RuntimeError('preset changed during gate; rerun')
        receipt['status'] = 'PASS'
    except BaseException as error:
        receipt.update(status='FAIL', error=str(error))
        raise
    finally:
        stack.write(out / 'gate.json', receipt)
    print('GATE PASS ' + str(out), flush=True)


if __name__ == '__main__':
    main()
