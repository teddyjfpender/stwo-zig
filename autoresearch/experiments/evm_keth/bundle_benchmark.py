#!/usr/bin/env python3
"""Serial Keth block proof bundle: all execution chunks, 16 trie branches, linker.

The linker checks commitment consistency; it is not a recursive proof verifier.
Qualification requires every child proof, its exact public output, a known
compiled program image, and the linker's exact concatenation of those outputs.
"""
from __future__ import annotations

import argparse
import bz2
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

if __package__:
    from .block_benchmark import fixture_metadata
    from .bridge import PINS, ROOT, authenticate, claims, digest
    from .limits import address_space_limit, default_address_space_gib
    from .verify_bundle import check_manifest, expected_specs, verify as verify_retained
    from .guarded_benchmark import run as guarded_benchmark
else:
    from block_benchmark import fixture_metadata
    from bridge import PINS, ROOT, authenticate, claims, digest
    from limits import address_space_limit, default_address_space_gib
    from verify_bundle import check_manifest, expected_specs, verify as verify_retained
    from guarded_benchmark import run as guarded_benchmark
sys.path.insert(0, str(ROOT))
from scripts.benchmark_cairo import measure, run_benchmark


def save(path: Path, value: dict) -> None:
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def run(args: argparse.Namespace) -> dict:
    if args.rss_limit_bytes < 0:
        raise ValueError('resident limit must be nonnegative')
    if args.rss_limit_bytes and not sys.platform.startswith('linux'):
        raise ValueError('the resident RSS guard requires Linux; use bounded_prove.py on Darwin')
    with address_space_limit(args.max_address_space_gib) as policy:
        return run_limited(args, policy)


def run_limited(args: argparse.Namespace, policy: dict) -> dict:
    started = time.monotonic_ns()
    args.out = args.out.resolve()
    keth = args.keth_checkout.resolve()
    source = authenticate(keth, PINS['keth'])
    workload = fixture_metadata(args.fixture)
    specs = expected_specs(workload['transactions'], args.chunk_size)
    converter = getattr(args, 'converter', None)
    conversion_tool = converter.resolve() if converter else Path(__file__).with_name('legacy_input.py')
    if converter and args.input_format != 'compact':
        raise ValueError('the native converter emits only compact-v1')
    conversion_identity = {'implementation': 'typed-rust-v1' if converter else 'python-v1',
                           'path': str(conversion_tool.resolve()), 'sha256': digest(conversion_tool)}
    hashes = json.loads((keth / 'build/program_hashes.json').read_text())
    compiled_digests = {role: digest(keth / 'build' / f'{role}_compiled.json') for role, _ in specs}
    for path in (keth / '.venv/bin/python', keth / '.venv/bin/keth', args.product, args.oracle):
        if not path.is_file():
            raise ValueError(f'not a regular file: {path}')
    args.out.mkdir(parents=True, exist_ok=args.resume)
    result = {'schema': 'stwo-zig-keth-block-bundle-v1', 'status': 'running',
              'source': source, 'workload': workload, 'body_chunk_size': args.chunk_size,
              'workers': args.workers, 'segments': [], 'claims': claims(),
              'address_space_limit_gib': args.max_address_space_gib,
              'resident_guard_bytes': args.rss_limit_bytes,
              'witness_transport': args.input_format,
              'scope': 'individually-verified-segment-bundle-with-consistency-proof',
              'cache_policy': 'fresh bundle cache; retained across serial segments',
              'compilation_included': False, 'address_space_policy': policy,
              'conversion_tool': conversion_identity}
    manifest = args.out / 'bundle-results.json'
    retained = []
    if args.resume:
        previous = json.loads(manifest.read_text())
        if previous['workload'] != workload or previous['source'] != source or previous['workers'] != args.workers or previous['body_chunk_size'] != args.chunk_size:
            raise ValueError('resume workload, source or worker configuration changed')
        recorded_specs = [(s['role'], s['indices']) for s in previous['segments']]
        if recorded_specs != specs[:len(recorded_specs)]:
            raise ValueError('resume segments are not a canonical prefix')
        for segment in previous['segments']:
            if segment['name'] != segment['role'] + ''.join('_' + str(i) for i in segment['indices']):
                raise ValueError('unexpected resume segment name')
        if previous.get('compiled_program_sha256', compiled_digests) != compiled_digests:
            raise ValueError('resume compiled programs changed')
        if previous['program_poseidon_hashes'] != hashes:
            raise ValueError('resume program hash registry changed')
        for segment in previous['segments']:
            if segment['status'] != 'qualified':
                break
            if digest(keth / 'build' / (segment['role'] + '_compiled.json')) != segment['compiled_program_sha256']:
                raise ValueError('resume compiled program changed')
            retained.append(segment)
        # Reverify every retained byte and public statement before adoption.
        verification = verify_retained(args.out, args.oracle, prefix=True)
        attempt_index = max(1, len(previous.get('sessions', [])))
        attempt = args.out / 'attempts' / f'session-{attempt_index}'
        while attempt.exists():
            attempt_index += 1
            attempt = args.out / 'attempts' / f'session-{attempt_index}'
        attempt.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(manifest, attempt / 'failed-manifest.json')
        save(attempt / 'retained-prefix-reverified.json', verification)
        for segment in previous['segments'][len(retained):]:
            directory = args.out / segment['name']
            if directory.exists():
                directory.rename(attempt / segment['name'])
        result['segments'] = list(retained)
        result['sessions'] = previous.get('sessions') or [
            {'status': previous['status'], 'elapsed_wall_ns': previous.get('elapsed_wall_ns')}]
        result['resumed_segments'] = len(retained)
        result['interrupted'] = True
        result['previous_conversion_tools'] = previous.get('previous_conversion_tools', []) + [previous.get('conversion_tool')]
        for name in ('fixture-check.json', 'fixture-check.log'):
            path = args.out / name
            if path.exists():
                path.rename(attempt / name)
        if 'adopted_stage_measurements' in previous:
            result['adopted_stage_measurements'] = previous['adopted_stage_measurements']
        result['previous_witness_transports'] = sorted({Path(s['benchmark']['workload']['path']).suffix for s in retained})
    save(manifest, result)
    env = dict(os.environ, STWO_ZIG_WORKERS=str(args.workers), RAYON_NUM_THREADS=str(args.workers),
               PYTHONPATH=str(keth / 'cairo'), STWO_CAIRO_PREPROCESSED_CACHE_DIR=str(args.out / 'cache'))
    number = workload['block_number']
    trace_dir = args.out / 'data' / '1' / str(number) / '1'
    trace_dir.mkdir(parents=True, exist_ok=args.resume)
    shutil.copyfile(args.fixture, trace_dir.parent / 'zkpi.json')
    result['program_poseidon_hashes'] = hashes
    result['compiled_program_sha256'] = compiled_digests
    result['program_hashes_file_sha256'] = digest(keth / 'build/program_hashes.json')
    expected_linker_output = []
    program_roots = {}
    scratch = tempfile.TemporaryDirectory(prefix='keth-block-witness-')
    result['intermediates'] = 'temporary directory outside the exported evidence tree'
    try:
        command = [str(keth / '.venv/bin/python'), str(Path(__file__).with_name('check_fixture.py')),
                   '--fixture', str(args.fixture.resolve()), '--out', str(args.out / 'fixture-check.json')]
        for flag, path in (('--rpc-block', getattr(args, 'rpc_snapshot', None)),
                           ('--rpc-parent', getattr(args, 'rpc_parent', None))):
            if path is not None:
                command += [flag, str(path.resolve())]
        result['fixture_check_process'] = measure(command, args.out / 'fixture-check.log', env)
        if result['fixture_check_process']['exit_code']:
            raise RuntimeError('independent fixture identity check failed')
        result['fixture_check'] = json.loads((args.out / 'fixture-check.json').read_text())
        save(manifest, result)
        for index, (role, indices) in enumerate(specs):
            name = role + ''.join('_' + str(i) for i in indices)
            if index < len(retained):
                segment = retained[index]
                public = segment['expected_public_output']
                program_roots[role] = segment['public_statement']['program_root_blake2s']
                if role != 'aggregator':
                    expected_linker_output += [len(public) + 2, hashes[f'{role}_compiled.json'], *public]
                continue
            directory = args.out / name
            directory.mkdir()
            intermediate = Path(scratch.name) / name
            intermediate.mkdir()
            native_dir = intermediate / 'native'
            compiled = keth / 'build' / f'{role}_compiled.json'
            segment = {'name': name, 'role': role, 'indices': indices, 'status': 'running',
                       'compiled_program_sha256': digest(compiled)}
            if segment['compiled_program_sha256'] != compiled_digests[role]:
                raise ValueError('compiled program changed during run')
            result['segments'].append(segment)
            save(manifest, result)
            command = [str(keth / '.venv/bin/keth'), 'trace', '-b', str(number), '--chain-id', '1',
                       '--data-dir', str(args.out / 'data'), '--proving-run-id', '1', '--step', role,
                       '--compiled-program', str(compiled), '--trace-path', str(native_dir)]
            if role == 'body':
                command += ['--start-index', str(indices[0]), '--len', str(indices[1])]
            elif role == 'mpt_diff':
                command += ['--branch-index', str(indices[0])]
            # Keth's aggregator discovers program_hashes.json relative to its cwd.
            command = [str(keth / '.venv/bin/python'), '-c',
                       'import os,sys;os.chdir(sys.argv[1]);os.execv(sys.argv[2],sys.argv[2:])',
                       str(keth)] + command
            segment['trace'] = measure(command, directory / 'trace.log', env)
            if segment['trace']['exit_code']:
                raise RuntimeError(f'{name}: native Keth trace failed')
            raw = native_dir / f'prover_input_info_{number}_{name}'
            segment['legacy_input_sha256'] = digest(raw)
            converted = intermediate / ('input.cpi' if args.input_format == 'compact' else 'input.json')
            conversion_receipt = directory / 'conversion.json'
            conversion_command = [str(conversion_tool)] if converter else [sys.executable, str(conversion_tool)]
            segment['conversion_process'] = measure(conversion_command + [
                '--source', str(raw), '--compiled', str(compiled), '--target', str(converted),
                '--receipt', str(conversion_receipt)], directory / 'conversion.log', env)
            if segment['conversion_process']['exit_code']:
                raise RuntimeError(f'{name}: witness conversion failed')
            segment['conversion'] = json.loads(conversion_receipt.read_text())
            segment['conversion']['wall_ns'] = segment['conversion_process']['wall_ns']
            segment['input_sha256'] = digest(converted)
            field_prime = 2**251 + 17 * 2**192 + 1
            expected = [int(v) % field_prime for v in raw.with_name(raw.name + '.run_output.txt').read_text().split()]
            shutil.copyfile(raw.with_name(raw.name + '.run_output.txt'), trace_dir / (raw.name + '.run_output.txt'))
            segment['expected_public_output'] = expected
            if args.rss_limit_bytes:
                summary = guarded_benchmark(argparse.Namespace(
                    product=args.product.resolve(), oracle=args.oracle.resolve(),
                    prover_input=converted, params=None, out=directory / 'proofs',
                    virtual_gib=args.max_address_space_gib, rss_limit_bytes=args.rss_limit_bytes,
                    sample_ms=2), env=env)
                segment['memory_guard'] = json.loads((directory / 'proofs/rss-guard.json').read_text())
                if segment['memory_guard']['samples'] == 0 or segment['memory_guard']['terminated']:
                    raise RuntimeError('resident guard did not qualify')
            else:
                summary = run_benchmark(argparse.Namespace(
                    product=args.product.resolve(), oracle=args.oracle.resolve(),
                    program=None, program_type=None, prover_input=converted,
                    arguments=None, params=None, trials=1, out=directory / 'proofs'), env=env)
            segment['benchmark'] = {k: v for k, v in summary.items() if k != 'trials'}
            trial = summary['trials'][0]
            segment['trial'] = {k: v for k, v in trial.items() if k not in ('stages', 'command')}
            proof = directory / 'proofs/trial-1.proof.json'
            for what in ('output', 'statement'):
                target = directory / f'public-{what}.json'
                command = [str(args.oracle.resolve()), f'inspect-blake2s-proof-public-{what}',
                           '--proof', str(proof), '--proof-format', 'json', '--result', str(target)]
                receipt = measure(command, directory / f'inspect-{what}.log', env)
                if receipt['exit_code']:
                    raise RuntimeError(f'{name}: official public {what} inspection failed')
            public = [int(v, 16) for v in json.loads((directory / 'public-output.json').read_text())]
            if public != expected:
                raise ValueError(f'{name}: proof outputs disagree with Keth')
            statement = json.loads((directory / 'public-statement.json').read_text())
            if statement['program_len'] != segment['conversion']['compiled_program_cells_checked'] or statement['output_len'] != len(expected):
                raise ValueError(f'{name}: public program/output length mismatch')
            segment['public_statement'] = statement
            root = statement['program_root_blake2s']
            if role in program_roots and program_roots[role] != root:
                raise ValueError(f'{name}: program identity changed within a role')
            program_roots[role] = root
            if role == 'aggregator':
                if public != expected_linker_output:
                    raise ValueError('consistency proof does not bind every verified child output')
            else:
                expected_linker_output += [len(public) + 2, hashes[f'{role}_compiled.json'], *public]
            segment['public_output_matches'] = True
            with proof.open('rb') as inp, bz2.open(str(proof) + '.bz2', 'wb') as out:
                shutil.copyfileobj(inp, out)
            segment['compressed_proof_sha256'] = digest(Path(str(proof) + '.bz2'))
            segment['status'] = 'qualified'
            proof.unlink()
            if args.keep_inputs:
                shutil.copyfile(raw, directory / 'legacy-input.json')
                shutil.copyfile(converted, directory / converted.name)
            shutil.rmtree(intermediate)
            save(manifest, result)
            print(json.dumps({'segment': name, 'status': 'qualified', **summary['summary']}), flush=True)
        result['source_after'] = authenticate(keth, PINS['keth'])
        if digest(args.fixture) != workload['fixture_sha256']:
            raise ValueError('fixture changed during run')
        if digest(conversion_tool) != conversion_identity['sha256']:
            raise ValueError('conversion implementation changed during run')
        if any(digest(keth / 'build' / f'{role}_compiled.json') != value for role, value in compiled_digests.items()) or digest(keth / 'build/program_hashes.json') != result['program_hashes_file_sha256']:
            raise ValueError('compiled programs changed during run')
        result['program_roots_blake2s'] = program_roots
        result['all_child_outputs_bound_to_consistency_proof'] = True
        result['status'] = 'qualified-segmented-keth-block-workload'
        check_manifest(result)
    except Exception as error:
        if 'converted' in locals() and converted.is_file():
            preserved = Path(tempfile.mkdtemp(prefix='keth-failed-input-')) / converted.name
            converted.replace(preserved)
            result['failed_input'] = {'path': str(preserved), 'sha256': digest(preserved), 'bytes': preserved.stat().st_size}
        if result['segments'] and result['segments'][-1]['status'] == 'running':
            result['segments'][-1]['status'] = 'failed'
        result.update(status='failed', error=str(error), error_type=type(error).__name__)
        raise
    finally:
        scratch.cleanup()
        result.setdefault('sessions', []).append({'status': result['status'], 'elapsed_wall_ns': time.monotonic_ns() - started})
        durations = [s['elapsed_wall_ns'] for s in result['sessions']]
        result['recorded_known_session_wall_ns'] = sum(value for value in durations if type(value) is int)
        result['elapsed_wall_ns'] = sum(durations) if all(type(value) is int for value in durations) else None
        save(manifest, result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('keth-checkout', 'fixture', 'product', 'oracle', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--rpc-snapshot', type=Path)
    parser.add_argument('--rpc-parent', type=Path)
    parser.add_argument('--converter', type=Path, help='qualified native compact converter; default: Python reference')
    parser.add_argument('--chunk-size', type=int, default=1)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--max-address-space-gib', type=int, default=default_address_space_gib())
    parser.add_argument('--input-format', choices=('json', 'compact'), default='compact')
    parser.add_argument('--keep-inputs', action='store_true')
    parser.add_argument('--resume', action='store_true', help='reverify a retained prefix and continue a failed run')
    parser.add_argument('--rss-limit-bytes', type=int, default=0)
    args = parser.parse_args()
    if args.chunk_size < 1 or args.workers < 1 or args.max_address_space_gib < 0:
        parser.error('counts must be positive; the address-space limit may be zero (disabled)')
    print(json.dumps({'status': run(args)['status']}))


if __name__ == '__main__':
    main()
