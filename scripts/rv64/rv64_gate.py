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

if __package__ in (None, ""):  # run as a file: make `scripts.*` importable
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.rv64 import rv64_m7_integration_stack as stack
from scripts.rv64.rv64_validation import CASES, check_corpus, frozen_parity, payload_name, validate_assets, validate_receivers, validate_library_environment, jobs_environment, service_label, FROZEN_D2_PACKAGE as GOLDEN

ROOT = Path(__file__).resolve().parents[2]
# Canonical default runtime: the source-built opt-combined image (owner decision
# 2026-11-07). Pass --runtime conformance/rv64/presets/p0-runtime.json
# for the frozen a25 control.
RUNTIME = stack.DEFAULT_RUNTIME

def extra_environment(items):
    """--env KEY=VALUE for the proving service (e.g. STWO_RV64_M8_JOBS=1).

    Only STWO_* keys; each key once. The values are recorded in the receipt
    and appended after the preset's environment, so they override it.
    """
    result = {}
    for item in items:
        key, sep, value = item.partition('=')
        if not sep or not key.startswith('STWO_') or not key.replace('_', '').isalnum() or not key.isupper():
            raise ValueError(f'--env expects STWO_KEY=VALUE, got {item!r}')
        if key in result:
            raise ValueError(f'--env {key} given twice')
        result[key] = value
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stream', default='m7-integrate')
    p.add_argument('--out', required=True, type=Path, help='new unique receipt directory')
    p.add_argument('--runtime', default=RUNTIME, type=Path, help='pinned CUDA runtime JSON (default: default-runtime.json)')
    p.add_argument('--block', type=int, choices=(26235156, 24628607), default=26235156)
    p.add_argument('--donor', type=Path, help='accepted opposite dev block; frozen D2 run by default')
    p.add_argument('--source-commit', required=True)
    p.add_argument('--nsys', action='store_true', help='profile the same correctness requests; walls remain unqualified')
    p.add_argument('--nsys-root', type=Path, help='raw profile filesystem, forwarded to the resident harness')
    p.add_argument('--env', action='append', default=[], metavar='KEY=VALUE',
                   help='extra STWO_* service environment (repeatable), e.g. STWO_RV64_M8_JOBS=1')
    args = p.parse_args()
    try:
        extra_env = extra_environment(args.env)
    except ValueError as error:
        p.error(str(error))
    if ROOT != Path('/workspace/m3/src') / args.stream:
        p.error('run only in the synced pod source tree; no laptop builds')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = {'schema': 'rv64-commit-gate/v1', 'status': 'RUNNING',
               'source_commit': args.source_commit, 'source_sha256': stack.source_hashes(ROOT),
               'block': args.block, 'steps': [], 'timing_scope': 'correctness only; no speed claim',
               'extra_env': extra_env}
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
        validate_assets(assets, runtime['asset_sha256'])
        receipt['runtime'] = runtime
        jobs_env = jobs_environment(runtime, extra_env)
        receipt['jobs_env'] = jobs_env
        extra_env = {**jobs_env, **extra_env}
        lock = ['flock', '-w', '7200', '/workspace/m3/locks/build.1.lock']
        run('build', lock + [sys.executable, 'scripts/rv64/rv64_m3_pod.py', 'build',
                            '--stream', args.stream, '--only', 'zig'])
        run('unit-zig', lock + ['/workspace/zig/zig', 'build', 'test',
                               'test-rv64-recursion-ready', 'test-rv64-batch-plan',
                               'test-rv64-gkr-plan', 'test-rv64-pcs-geometry', 'test-rv64-jobs',
                               'test-rv64-jobs-outer', 'test-rv64-resources',
                               '-j2', '-Doptimize=ReleaseSafe', '-Dtarget=x86_64-linux-gnu',
                               '-Dcpu=x86_64_v4+sha', '--summary', 'all', '--cache-dir', str(ROOT / '.zig-cache')],
            ROOT / 'src/integrations/riscv_cuda')
        run('unit-python', [sys.executable, '-m', 'unittest',
                            'scripts.tests.test_rv64_gate', 'scripts.tests.test_rv64_m7_composed_cells',
                            'scripts.tests.test_rv64_quiet_checkpoint',
                            'scripts.tests.test_rv64_validation',
                            'scripts.tests.test_rv64_gpu_activity',
                            'scripts.tests.test_rv64_m8_bench15',
                            'scripts.tests.test_dev_test',
                            'scripts.tests.test_script_reachability',
                            'scripts.tests.test_ci', 'scripts.tests.test_ci_package_graph',
                            'scripts.tests.test_focused_ci_contract'])
        bins = Path('/workspace/m3/build') / args.stream / 'zig-out/bin'
        assets.update(driver=str(bins / 'rv64-word16-ethereum-gpu-combined'),
                      receiver=str(bins / 'rv64-word16-ethereum-recursion-receiver'))
        manifest = {'source_root': str(ROOT), 'assets': assets, 'block': args.block,
                    'preset': json.loads(stack.DEFAULT_PRESET.read_text())}
        effective_env = {**stack.arm_environment(manifest['preset'], 'baseline', assets), **extra_env}
        jobs_environment(runtime, effective_env)
        receipt['preset'] = manifest['preset']
        receipt['preset_sha256'] = stack.sha(stack.DEFAULT_PRESET)
        receipt['asset_sha256'] = {name: stack.sha(path) for name, path in assets.items()}
        label = service_label(out)
        argv, tag = stack.command(manifest, 'baseline', 0, args.stream, False, label)
        # Keep quiet observations but do not call correctness walls matched timings.
        argv += ['--quiet-mode', 'diagnostic', '--request-timeout', '240']
        if args.nsys:
            argv += ['--nsys']
        if args.nsys_root:
            if not args.nsys:
                raise RuntimeError('--nsys-root requires --nsys')
            argv += ['--nsys-root', str(args.nsys_root)]
        for key, value in sorted(extra_env.items()):
            argv += ['--env', f'{key}={value}']
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
        run('fresh-cpu-receiver', [sys.executable, 'scripts/rv64/rv64_m4_resident.py', 'receive',
                                    '--run', str(service), '--which', 'all'])
        verified = json.loads((service / 'receipt.json').read_text())
        receipt['receiver_acceptance'] = validate_receivers(
            verified.get('receivers'), [r['proof'] for r in verified['requests']],
            receipt['asset_sha256']['receiver'])
        receipt['receivers'] = verified['receivers']
        donor_block = 24628607 if args.block == 26235156 else 26235156
        donor = args.donor or Path(f'/workspace/m3/runs/m7-fold-v3/daemon-{donor_block}-r2-combined-d2-coalesce-v1')
        corpus_env = dict(env, STWO_RV64_OUTER_PROFILE=manifest['preset']['common']['STWO_RV64_OUTER_PROFILE'],
                          STWO_RV64_NATIVE_VERSION='v1-flat')
        run('negative-corpus', [sys.executable, 'scripts/rv64/rv64_m5_negative_corpus.py', 'run',
                               '--run', str(service), '--donor', str(donor), '--format', 'm5-audit',
                               '--receiver', assets['receiver'], '--jobs', '1', '--cases', ','.join(CASES),
                               '--work', str(out / 'corpus-work'), '--out', str(out / 'corpus.json')],
            environment=corpus_env)
        receipt['corpus_acceptance'] = check_corpus(json.loads((out / 'corpus.json').read_text()), receipt['asset_sha256']['receiver'])
        validate_assets(assets, receipt['asset_sha256'])
        jobs_environment(runtime, effective_env)
        if stack.source_hashes(ROOT) != receipt['source_sha256']:
            raise RuntimeError('source changed during gate; rebuild and rerun')
        if stack.sha(stack.DEFAULT_PRESET) != receipt['preset_sha256']:
            raise RuntimeError('preset changed during gate; rerun')
        receipt['status'] = receipt['corpus_acceptance']['status']
    except BaseException as error:
        receipt.update(status='FAIL', error=str(error))
        raise
    finally:
        stack.write(out / 'gate.json', receipt)
    print('GATE ' + receipt['status'] + ' ' + str(out), flush=True)
    # A resource-only rejection is preserved evidence, not a green semantic
    # gate. Exit 3 distinguishes incomplete coverage from an execution error.
    return 0 if receipt['status'] == 'PASS' else 3


if __name__ == '__main__':
    raise SystemExit(main())
