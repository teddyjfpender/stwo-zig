#!/usr/bin/env python3
"""Trace and inspect the monolithic Keth witness; optionally prove and verify.

Inspection reports trace storage, not peak prover memory. It never qualifies
a proof. This direct route preserves the normal PIE replay admission limits.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys

if __package__:
    from .block_benchmark import fixture_metadata
    from .bridge import PINS, ROOT, authenticate, claims, digest
    from .bundle_benchmark import save
    from .limits import address_space_limit, default_address_space_gib
else:
    from block_benchmark import fixture_metadata
    from bridge import PINS, ROOT, authenticate, claims, digest
    from bundle_benchmark import save
    from limits import address_space_limit, default_address_space_gib
sys.path.insert(0, str(ROOT))
from scripts.benchmark_cairo import measure, run_benchmark


def run(args):
    args.out = args.out.resolve()
    keth = args.keth_checkout.resolve()
    source = authenticate(keth, PINS['keth'])
    workload = fixture_metadata(args.fixture)
    compiled = keth / 'build/main_compiled.json'
    args.out.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'keth-monolithic-witness-v1', 'status': 'running',
              'source': source, 'workload': workload, 'claims': claims(), 'stages': {},
              'workers': args.workers, 'compiled_program_sha256': digest(compiled),
              'converter_sha256': digest(args.converter)}
    manifest = args.out / 'main-results.json'
    save(manifest, result)
    env = dict(os.environ, PYTHONPATH=str(keth / 'cairo'), RAYON_NUM_THREADS=str(args.workers),
               STWO_ZIG_WORKERS=str(args.workers),
               STWO_CAIRO_PREPROCESSED_CACHE_DIR=str(args.out / 'cache'))

    def stage(name, command):
        result['phase'] = name
        save(manifest, result)
        usage = measure(command, args.out / (name + '.log'), env)
        result['stages'][name] = usage
        if usage['exit_code']:
            raise RuntimeError(f'{name}: process exited {usage["exit_code"]}')
        return usage

    try:
        with address_space_limit(args.max_address_space_gib) as policy:
            result['address_space_policy'] = policy
            number = workload['block_number']
            data = args.out / 'data/1' / str(number)
            data.mkdir(parents=True)
            shutil.copyfile(args.fixture, data / 'zkpi.json')
            stage('fixture-check', [str(keth / '.venv/bin/python'), str(Path(__file__).with_name('check_fixture.py')),
                  '--fixture', str(args.fixture.resolve()), '--out', str(args.out / 'fixture-check.json')])
            stage('trace', [str(keth / '.venv/bin/python'), '-c',
                'import os,sys;os.chdir(sys.argv[1]);os.execv(sys.argv[2],sys.argv[2:])', str(keth),
                str(keth / '.venv/bin/keth'), 'trace', '-b', str(number), '--chain-id', '1',
                '--data-dir', str(args.out / 'data'), '--proving-run-id', '1', '--step', 'main',
                '--compiled-program', str(compiled)])
            raw = data / '1' / f'prover_input_info_{number}'
            result['legacy_input_sha256'] = digest(raw)
            converted = args.out / 'main.cpi'
            stage('conversion', [str(args.converter.resolve()), '--source', str(raw),
                  '--compiled', str(compiled), '--target', str(converted), '--receipt', str(args.out / 'conversion.json')])
            result['conversion'] = json.loads((args.out / 'conversion.json').read_text())
            result['input_sha256'] = digest(converted)
            result['input_bytes'] = converted.stat().st_size
            stage('inspect', [str(args.product.resolve()), 'inspect', '--prover-input', str(converted)])
            result['inspection'] = json.loads((args.out / 'inspect.log').read_text())
            result['status'] = 'inspected-not-proved'
            if args.prove:
                summary = run_benchmark(argparse.Namespace(product=args.product.resolve(), oracle=args.oracle.resolve(),
                    program=None, program_type=None, prover_input=converted, arguments=None, params=None,
                    trials=1, out=args.out / 'proofs'), env=env)
                stage('inspect-public-output', [str(args.oracle.resolve()), 'inspect-blake2s-proof-public-output',
                    '--proof', str(args.out / 'proofs/trial-1.proof.json'), '--proof-format', 'json',
                    '--result', str(args.out / 'public-output.json')])
                prime = 2**251 + 17 * 2**192 + 1
                native = [int(v) % prime for v in raw.with_name(raw.name + '.run_output.txt').read_text().split()]
                public = [int(v, 16) for v in json.loads((args.out / 'public-output.json').read_text())]
                if public != native:
                    raise ValueError('verified monolithic output differs from native execution')
                result.update(status='qualified-monolithic-keth-workload', benchmark=summary, public_output=public)
            if authenticate(keth, PINS['keth']) != source or digest(compiled) != result['compiled_program_sha256'] or digest(args.converter) != result['converter_sha256'] or digest(args.fixture) != workload['fixture_sha256']:
                raise ValueError('source, program, converter or fixture changed during run')
    except Exception as error:
        result.update(status='failed', error=str(error), error_type=type(error).__name__)
        raise
    finally:
        save(manifest, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('keth-checkout', 'fixture', 'converter', 'product', 'oracle', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--max-address-space-gib', type=int, default=default_address_space_gib())
    parser.add_argument('--prove', action='store_true')
    args = parser.parse_args()
    if args.workers < 1 or args.max_address_space_gib < 0:
        parser.error('invalid worker or memory count')
    result = run(args)
    print(json.dumps({'status': result['status'], 'input_bytes': result['input_bytes'], 'trace_storage': result['inspection']['trace_storage']}))
