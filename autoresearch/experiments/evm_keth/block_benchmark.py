#!/usr/bin/env python3
"""Measure an unchanged Keth mainnet block workload through Stwo Zig.

Compilation is outside the measured interval. Failed stages remain in results;
only exact-byte official proof acceptance qualifies a proving trial.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import sys
import zipfile

from bridge import PINS, ROOT, authenticate, claims, digest
sys.path.insert(0, str(ROOT))
from scripts.benchmark_cairo import measure, run_benchmark


def publish(out: Path, result: dict) -> None:
    temporary = out / 'block-results.json.tmp'
    temporary.write_text(json.dumps(result, indent=2) + '\n')
    temporary.replace(out / 'block-results.json')


def fixture_metadata(path: Path) -> dict:
    data = json.loads(path.read_text())
    if type(data['chainConfig']['chainId']) is not int or data['chainConfig']['chainId'] != 1 or len(data['blocks']) != 1:
        raise ValueError('this workload admits one Ethereum mainnet block')
    block = data['blocks'][0]
    header = block['header']
    number = int(header['number'], 16)
    if number < PINS['keth']['minimum_block']:
        raise ValueError('the pinned Keth main program requires a Prague block')
    return {'block_number': number, 'block_hash': header['hash'],
            'parent_hash': header['parentHash'], 'post_state_root': header['stateRoot'],
            'pre_state_root': data['witness']['ancestors'][0]['stateRoot'],
            'gas_used': int(header['gasUsed'], 16),
            'transactions': len(block['transaction']), 'withdrawals': len(block['withdrawals']),
            'fixture_sha256': digest(path), 'fixture_bytes': path.stat().st_size}


def run(args: argparse.Namespace) -> dict:
    args.out = args.out.resolve()
    args.keth_checkout = args.keth_checkout.resolve()
    source = authenticate(args.keth_checkout, PINS['keth'])
    fixture = args.fixture.resolve()
    workload = fixture_metadata(fixture)
    compiled = args.keth_checkout / 'build' / f'{args.step}_compiled.json'
    if not compiled.is_file():
        raise ValueError(f'compile the Keth {args.step} program first')
    entry = args.keth_checkout / '.venv/bin/keth'
    if not entry.is_file():
        raise ValueError('install the pinned Keth environment first')
    args.out.mkdir(parents=True, exist_ok=False)
    result = {'schema': 'stwo-zig-keth-block-benchmark-v1', 'status': 'running',
              'scope': 'whole-keth-main-workload' if args.step == 'main' else 'keth-block-segment',
              'step': args.step, 'source': source, 'workload': workload,
              'compiled_program_sha256': digest(compiled), 'stages': [],
              'address_space_limit_gib': args.max_address_space_gib,
              'workers': args.workers, 'claims': claims()}
    if args.rpc_snapshot:
        rpc = json.loads(args.rpc_snapshot.read_text())['result']
        if (rpc['hash'] != workload['block_hash'] or rpc['stateRoot'] != workload['post_state_root']
                or len(rpc['transactions']) != workload['transactions']
                or int(rpc['gasUsed'], 16) != workload['gas_used']
                or int(rpc['number'], 16) != workload['block_number']
                or rpc['parentHash'] != workload['parent_hash']):
            raise ValueError('independent RPC snapshot does not match the witness')
        result['independent_rpc_snapshot_sha256'] = digest(args.rpc_snapshot)
    publish(args.out, result)
    env = dict(os.environ, STWO_ZIG_WORKERS=str(args.workers), RAYON_NUM_THREADS=str(args.workers),
               RUSTUP_TOOLCHAIN='nightly-2025-04-06')
    env['STWO_CAIRO_PREPROCESSED_CACHE_DIR'] = str(args.out / 'preprocessed-cache')
    if args.adapter:
        env['STWO_CAIRO_VM_ADAPTER'] = str(args.adapter.resolve())
    env['PYTHONPATH'] = str(args.keth_checkout / 'cairo') + os.pathsep + env.get('PYTHONPATH', '')
    old_limit = resource.getrlimit(resource.RLIMIT_AS)
    hard_limit = old_limit[1]
    if args.max_address_space_gib:
        resource.setrlimit(resource.RLIMIT_AS, (int(args.max_address_space_gib * (1 << 30)), hard_limit))

    def stage(name: str, command: list[str]) -> dict:
        receipt = {'name': name, 'command': command, 'status': 'running'}
        result['stages'].append(receipt)
        publish(args.out, result)
        receipt['process'] = measure(command, args.out / f'{name}.log', env)
        receipt['status'] = 'passed' if receipt['process']['exit_code'] == 0 else 'failed'
        publish(args.out, result)
        if receipt['status'] != 'passed':
            raise RuntimeError(f'{name} failed; see {args.out / (name + ".log")}')
        return receipt

    try:
        block = workload['block_number']
        data = args.out / 'data' / '1' / str(block)
        data.mkdir(parents=True)
        shutil.copyfile(fixture, data / 'zkpi.json')
        command = [str(entry), 'trace', '-b', str(block), '--chain-id', '1',
                   '--data-dir', str(args.out / 'data'), '--proving-run-id', '1',
                   '--step', args.step, '--compiled-program', str(compiled),
                   '--cairo-pie', '--trace-path', str(args.out / 'trace')]
        suffix = '' if args.step == 'main' else '_' + args.step
        if args.step == 'body':
            command += ['--start-index', str(args.start_index), '--len', str(args.chunk_size)]
            suffix += f'_{args.start_index}_{args.chunk_size}'
        elif args.step == 'mpt_diff':
            command += ['--branch-index', str(args.branch_index)]
            suffix += f'_{args.branch_index}'
        stage('keth-trace', command)
        pie = args.out / 'trace' / f'cairo_pie_{block}{suffix}.zip'
        if not pie.is_file():
            raise ValueError('Keth did not emit the requested PIE')
        result['pie'] = {'sha256': digest(pie), 'bytes': pie.stat().st_size}
        with zipfile.ZipFile(pie) as archive:
            result['keth_execution_resources'] = json.loads(archive.read('execution_resources.json'))
        output_file = pie.with_name(pie.stem + '.run_output.txt')
        field_prime = 2**251 + 17 * 2**192 + 1
        trace_output = [int(value.strip(), 0) % field_prime for value in output_file.read_text().splitlines() if value.strip()]
        result['trace_output'] = trace_output
        if args.step == 'main':
            reference_path = args.out / 'expected-main-output.json'
            reference_code = '''import json,sys
from pathlib import Path
from keth_types.patches import apply_patches
apply_patches()
from mpt.trie_diff import StateDiff
p=Path(sys.argv[1]);data=json.loads(p.read_text())
pre=bytes.fromhex(data['witness']['ancestors'][0]['stateRoot'][2:])
lo=int.from_bytes(pre[:16],'little');hi=int.from_bytes(pre[16:],'little')
a,b=StateDiff.from_json(p).compute_commitments()
Path(sys.argv[2]).write_text(json.dumps([lo,hi,a,b,a,b]))
'''
            stage('reference-output', [str(args.keth_checkout / '.venv/bin/python'), '-c', reference_code, str(fixture), str(reference_path)])
            result['expected_output'] = json.loads(reference_path.read_text())
            if trace_output != result['expected_output']:
                raise ValueError('Keth main output disagrees with independently computed witness diffs')
        result['source_after_trace'] = authenticate(args.keth_checkout, PINS['keth'])
        if digest(fixture) != workload['fixture_sha256'] or digest(compiled) != result['compiled_program_sha256']:
            raise ValueError('workload bytes changed during tracing')
        if args.trace_only:
            result['status'] = 'traced'
            return result
        if not args.adapter:
            raise ValueError('--adapter is required for the measured replay stage')
        compact = args.out / 'block.cpi'
        stage('official-vm-replay', [str(args.adapter.resolve()), 'run', '--program', str(pie),
                                   '--program-type', 'pie', '--input-format', 'compact',
                                   '--prover-input-out', str(compact)])
        result['compact_input'] = {'sha256': digest(compact), 'bytes': compact.stat().st_size}
        stage('zig-inspect', [str(args.product.resolve()), 'inspect', '--prover-input', str(compact)])
        result['phase'] = 'proving'
        publish(args.out, result)
        result['benchmark'] = run_benchmark(argparse.Namespace(
            product=args.product.resolve(), oracle=args.oracle.resolve(),
            program=pie, program_type='pie', prover_input=None, arguments=None, params=None,
            trials=args.trials, out=args.out / 'proofs'), env=env)
        for trial in range(1, args.trials + 1):
            output_path = args.out / f'trial-{trial}.public-output.json'
            stage(f'public-output-{trial}', [str(args.oracle.resolve()), 'inspect-blake2s-proof-public-output',
                  '--proof', str(args.out / 'proofs' / f'trial-{trial}.proof.json'),
                  '--proof-format', 'json', '--result', str(output_path)])
            public = [int(value, 16) for value in json.loads(output_path.read_text())]
            if public[:2] != [1, len(trace_output) + 2] or public[3:] != trace_output:
                raise ValueError('verified proof public output does not match the Keth execution')
        result['workload_outputs_match'] = True
        result['status'] = 'qualified-keth-workload'
        return result
    except Exception as error:
        result.update(status='failed', error=str(error), error_type=type(error).__name__)
        return result
    finally:
        if args.max_address_space_gib:
            resource.setrlimit(resource.RLIMIT_AS, old_limit)
        publish(args.out, result)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--keth-checkout', type=Path, required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--rpc-snapshot', type=Path)
    parser.add_argument('--step', choices=('main', 'init', 'body', 'teardown', 'mpt_diff'), default='main')
    parser.add_argument('--start-index', type=int, default=0)
    parser.add_argument('--chunk-size', type=int, default=1)
    parser.add_argument('--branch-index', type=int, default=0)
    parser.add_argument('--product', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--adapter', type=Path)
    parser.add_argument('--trials', type=int, default=3)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--max-address-space-gib', type=float, default=8)
    parser.add_argument('--trace-only', action='store_true')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.trials <= 100 or args.workers < 1 or args.chunk_size < 1 or args.start_index < 0 or not 0 <= args.branch_index <= 15:
        parser.error('invalid trial, worker, transaction or branch count')
    result = run(args)
    print(json.dumps({k: v for k, v in result.items() if k in ('status', 'scope', 'workload', 'error')}))
    if result['status'] == 'failed':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
