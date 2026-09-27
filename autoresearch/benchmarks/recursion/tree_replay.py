#!/usr/bin/env python3
"""Replay an admitted parent DAG with bounded concurrency and fresh verification.

Leaves are retained admitted inputs. This measures the parent subtree, not full
program production. Hold the repository build lock once around the experiment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'scripts'))
from recursive_proof_scheduler import Job, execute
from recursive_proof_worker_pool import ProducerPool
from zig_serial_build import build_lock


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipts', type=Path, required=True)
    parser.add_argument('--producer', type=Path, required=True)
    parser.add_argument('--producer-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--workers', type=int, default=2)
    parser.add_argument('--persistent-workers', action='store_true')
    parser.add_argument('--sample-rss', action='store_true', help='sample process RSS; adds monitoring overhead')
    parser.add_argument('--memory-budget-bytes', type=int, required=True)
    parser.add_argument('--job-memory-bytes', type=int, required=True)
    args = parser.parse_args()
    if sha(args.producer) != args.producer_sha256:
        raise ValueError('producer pin mismatch')
    output = args.output.resolve()
    if output.exists():
        raise ValueError('output must be new')
    receipts = {}
    pins = {str(args.producer.resolve()): args.producer_sha256}
    for path in sorted(args.receipts.glob('parent-*-accepted.json')):
        receipt = json.loads(path.read_bytes())
        if not receipt['passed'] or not receipt['producer']['exited_before_verification']:
            raise ValueError('receipt must independently admit producer artifacts')
        accepted = receipt['cases'][0]['receipt']
        if not accepted['verified'] or accepted['native_inputs_used']:
            raise ValueError('receipt lacks standalone acceptance')
        name = path.name.removesuffix('-accepted.json')
        receipts[name] = receipt
        pins[str(path.resolve())] = sha(path)
    if not receipts:
        raise ValueError('no admitted parents')
    originals = {str(Path(r['producer']['argv'][r['producer']['argv'].index('--profile') + 2]).resolve()): n
                 for n, r in receipts.items()}
    expected = {}
    jobs = []
    for name, receipt in receipts.items():
        argv = receipt['producer']['argv'].copy()
        pos = argv.index('--profile') + 2
        original = Path(argv[pos])
        expected[name] = {f: bytes(receipt['cases'][0]['receipt'][k]).hex()
                          for f, k in [('key.json', 'key_sha256'), ('claims.json', 'claims_sha256'), ('proof.bin', 'proof_sha256')]}
        for f, pin in expected[name].items():
            if sha(original / f) != pin:
                raise ValueError('admitted original changed')
            pins[str((original / f).resolve())] = pin
        dependencies = []
        for child_pos in (pos + 1, pos + 4):
            child = Path(argv[child_pos]).resolve()
            for f in ('key.json', 'claims.json', 'proof.bin'):
                pins[str(child / f)] = sha(child / f)
            if str(child) in originals:
                dependency = originals[str(child)]
                dependencies.append(dependency)
                argv[child_pos] = str(output / dependency)
        argv[0] = str(args.producer.resolve())
        argv[pos] = str(output / name)
        verify = receipt['cases'][0]['argv'].copy()
        verify[1] = str(output / name)
        for value in argv + verify:
            path = Path(value)
            if path.is_file():
                pins[str(path.resolve())] = sha(path)
        jobs.append(Job(name, tuple(dependencies), (tuple(argv), tuple(verify)),
                        args.job_memory_bytes, int(name.split('-')[1])))
    output.mkdir(parents=True)
    report = {'scope': 'parent DAG replay with retained leaves; not full-program proving',
              'input_sha256': pins, 'scheduler_sha256': sha(ROOT / 'scripts/recursive_proof_scheduler.py'),
              'driver_sha256': sha(__file__), 'expected_artifacts': expected}
    env = {k: v for k, v in os.environ.items() if not k.startswith('STWO_')}
    env['STWO_RISCV_RECURSIVE_PARENT_PROFILE'] = '1'

    def admit(job, logs):
        verified = json.loads(logs[-1].read_text())
        if not verified['verified'] or verified['native_inputs_used']:
            raise RuntimeError('standalone verification failed')
        if {f: sha(output / job.name / f) for f in expected[job.name]} != expected[job.name]:
            raise RuntimeError('qualified artifact identity changed')
        report['jobs'][job.name]['artifacts'] = expected[job.name]

    try:
        with build_lock(label='bounded-parent-dag-replay'):
            pool = None
            if args.persistent_workers:
                capacity = min(args.workers, len(jobs), args.memory_budget_bytes // args.job_memory_bytes)
                pool = ProducerPool(output / 'workers', capacity)
                report['worker_transport_sha256'] = sha(ROOT / 'scripts/recursive_proof_worker_pool.py')
            try:
                execute(jobs, output / 'logs', workers=args.workers, memory_bytes=args.memory_budget_bytes,
                        timeout=180, env=env, admit=admit, report=report, producer_pool=pool, sample_rss=args.sample_rss)
            finally:
                if pool is not None:
                    pool.close(failed=True)
    finally:
        report['inputs_unchanged'] = all(Path(p).is_file() and sha(p) == pin for p, pin in pins.items())
        if not report['inputs_unchanged']:
            report['passed'] = False
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    if not report['passed']:
        raise RuntimeError('DAG replay failed')
    print(json.dumps({'passed': True, 'nodes': len(jobs), 'wall_seconds': report['wall_ns'] / 1e9,
                      'maximum_active_jobs': report['maximum_active_jobs']}))


if __name__ == '__main__':
    main()
