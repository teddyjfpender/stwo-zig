#!/usr/bin/env python3
"""Prove an owned OP Cairo kernel and bind all public results to its oracle.

This is deliberately separate from Ethereum block admission and qualification.
Full OP execution, derivation and settlement claims remain false.
"""
from __future__ import annotations

import argparse
import bz2
import json
import os
from pathlib import Path
import shutil
import sys
import time

if __package__:
    from .bridge import ROOT, PINS, authenticate, digest
    from .bundle_benchmark import save
else:
    from bridge import ROOT, PINS, authenticate, digest
    from bundle_benchmark import save
sys.path.insert(0, str(ROOT))
from scripts.benchmark_cairo import measure, run_benchmark


def run(args):
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    keth = args.keth_checkout.resolve()
    source = authenticate(keth, PINS['keth'])
    tools = {name: getattr(args, name).resolve() for name in ('product', 'oracle', 'converter')}
    inputs = {name: getattr(args, name).resolve() for name in ('source', 'input', 'expected_output')}
    expected = json.loads(inputs['expected_output'].read_text())
    if not isinstance(expected, list) or any(type(v) is not int or not 0 <= v < 2**251 + 17 * 2**192 + 1 for v in expected):
        raise ValueError('expected outputs must be canonical field integers')
    started = time.monotonic()
    result = dict(schema='keth-op-kernel-benchmark-v1', status='running', source=source,
                  scope='OP kernel with public parameters and transaction hashes; not complete block execution',
                  tool_sha256={k: digest(v) for k, v in tools.items()},
                  input_sha256={k: digest(v) for k, v in inputs.items()}, workers=args.workers,
                  stages={}, expected_output=expected, kernel_proof_verified=False,
                  op_block_execution_proved=False, op_derivation_proved=False, public_block_statement_bound=False)
    manifest = args.out / 'kernel-results.json'
    env = dict(os.environ, STWO_ZIG_WORKERS=str(args.workers), RAYON_NUM_THREADS=str(args.workers),
               STWO_CAIRO_PREPROCESSED_CACHE_DIR=str(args.out / 'cache'))
    result['cache_policy'] = 'fresh preprocessing directory across this trial set; inherited Metal disk archive'

    def stage(name, command):
        usage = measure(command, args.out / (name + '.log'), env)
        result['stages'][name] = usage
        save(manifest, result)
        if usage['exit_code']:
            raise RuntimeError(name + ' failed')

    try:
        compiled, trace, compact = [args.out / name for name in ('compiled.json', 'trace', 'input.cpi')]
        helper = Path(__file__).with_name('op_cairo.py')
        stage('compile', [str(keth / '.venv/bin/python'), str(helper), '--keth-checkout', str(keth),
                         'compile', '--source', str(inputs['source']), '--out', str(compiled)])
        result['compilation'] = json.loads(compiled.with_name(compiled.name + '.receipt.json').read_text())
        stage('trace', [str(keth / '.venv/bin/python'), str(helper), '--keth-checkout', str(keth),
                       'trace', '--compiled', str(compiled), '--input', str(inputs['input']), '--out', str(trace)])
        tracing = json.loads(trace.with_name(trace.name + '.receipt.json').read_text())
        if tracing['public_output'] != expected:
            raise ValueError('Cairo execution differs from the independent oracle')
        result['tracing'] = tracing
        stage('conversion', [str(tools['converter']), '--source', str(trace), '--compiled', str(compiled),
                             '--target', str(compact), '--receipt', str(args.out / 'conversion.json')])
        result['conversion'] = json.loads((args.out / 'conversion.json').read_text())
        result['compact_sha256'] = digest(compact)
        benchmark = run_benchmark(argparse.Namespace(product=tools['product'], oracle=tools['oracle'],
            program=None, program_type=None, prover_input=compact, arguments=None, params=None,
            trials=args.trials, out=args.out / 'proofs'), env=env)
        result['benchmark'] = benchmark
        result['proofs'] = []
        root = None
        for trial in benchmark['trials']:
            index = trial['index']
            proof = args.out / 'proofs' / f'trial-{index}.proof.json'
            for kind in ('output', 'statement'):
                destination = args.out / f'trial-{index}-public-{kind}.json'
                stage(f'inspect-{index}-{kind}', [str(tools['oracle']), f'inspect-blake2s-proof-public-{kind}',
                      '--proof', str(proof), '--proof-format', 'json', '--result', str(destination)])
            output = [int(v, 16) for v in json.loads((args.out / f'trial-{index}-public-output.json').read_text())]
            statement = json.loads((args.out / f'trial-{index}-public-statement.json').read_text())
            if (output != expected or statement['program_len'] != result['conversion']['compiled_program_cells_checked']
                    or statement['output_len'] != len(expected)):
                raise ValueError('verified proof does not publish the exact kernel statement')
            if root is not None and root != statement['program_root_blake2s']:
                raise ValueError('kernel program identity changed between trials')
            root = statement['program_root_blake2s']
            compressed = proof.with_suffix(proof.suffix + '.bz2')
            with proof.open('rb') as incoming, bz2.open(compressed, 'wb') as outgoing:
                shutil.copyfileobj(incoming, outgoing)
            result['proofs'].append(dict(index=index, proof_sha256=digest(proof),
                                         compressed_sha256=digest(compressed), public_statement=statement))
        if authenticate(keth, PINS['keth']) != source or any(digest(v) != result['tool_sha256'][k] for k, v in tools.items()):
            raise ValueError('Keth source or proving tools changed during the trial set')
        if any(digest(v) != result['input_sha256'][k] for k, v in inputs.items()):
            raise ValueError('kernel source/input changed during proving')
        overlay = Path(__file__).resolve().parent / 'cairo'
        if any(digest(overlay / name) != expected_hash for name, expected_hash in result['compilation']['source_files_sha256'].items()):
            raise ValueError('kernel dependency changed during proving')
        result.update(status='qualified-kernel', kernel_proof_verified=True, program_root_blake2s=root)
    except Exception as error:
        result.update(status='failed', error=str(error))
        raise
    finally:
        result['elapsed_seconds'] = time.monotonic() - started
        save(manifest, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('keth-checkout', 'source', 'input', 'expected-output', 'product', 'oracle', 'converter', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--trials', type=int, default=3)
    args = parser.parse_args()
    if args.workers < 1 or args.trials < 1:
        parser.error('positive worker and trial counts required')
    print(run(args)['status'])
