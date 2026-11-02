"""Qualify OP execution phases once each; publish a bundle only after verification.

Every attempt has new paths. Failed attempts remain visible; resumption reuses
only completed phases with identical dependencies. This is a correctness gate,
not a repeated-trial benchmark campaign.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from .bounded_process import run as bounded
from .bridge import ROOT, digest, write_new
import keth_types.patches
from .verify_op_block import verify


def qualify(args):
    args.out.mkdir(parents=True, exist_ok=True)
    native = json.loads(args.native_input.read_text())
    checkpoints = json.loads(args.checkpoints.read_text())
    count = len(native['block']['transactions'])
    if not checkpoints['complete_reference_execution'] or len(checkpoints['checkpoints']) != count * 2:
        raise ValueError('complete native reference checkpoints required')
    indices = args.indices if args.indices is not None else list(range(-1, count))
    if len(set(indices)) != len(indices) or any(i < -1 or i >= count for i in indices):
        raise ValueError('invalid or duplicate execution index')
    runtime = args.runtime_python_path / 'cairo_addons/rust_bindings.abi3.so'
    source_paths = dict(compiled=args.compiled,
        runtime=runtime, converter=args.converter, product=args.product, oracle=args.oracle,
        native=args.native_input, checkpoints=args.checkpoints)
    dependencies = {name: digest(path) for name, path in source_paths.items()}
    children = []
    for index in indices:
        name = 'system' if index == -1 else str(index)
        workload = args.workloads / (name + '.json')
        value = json.loads(workload.read_text())
        parts = []
        for phase in range(3):
            directory = args.out / f'{name}-phase-{phase}'
            directory.mkdir(exist_ok=True)
            completion = directory / 'qualified.json'
            expected = dict(dependencies=dependencies, workload_sha256=digest(workload), phase=phase)
            if completion.exists():
                result = json.loads(completion.read_text())
                if result['identity'] != expected or digest(args.out / result['proof']) != result['proof_sha256']:
                    raise ValueError('resumed phase identity differs')
            else:
                attempt = 1
                while (directory / f'attempt-{attempt}').exists():
                    attempt += 1
                attempt_dir = directory / f'attempt-{attempt}'
                attempt_dir.mkdir()
                source = attempt_dir / 'input.json'
                write_new(source, {**value, 'proof_phase': phase})
                trace = attempt_dir / 'trace.json'
                command = ['env', 'PYTHONPATH=' + str(args.runtime_python_path.resolve()) + ':' + str(ROOT),
                    str((args.keth_checkout / '.venv/bin/python').absolute()), '-m',
                    'autoresearch.experiments.evm_keth.op_cairo', '--keth-checkout', str(args.keth_checkout.resolve()),
                    'trace', '--compiled', str(args.compiled.resolve()), '--input', str(source.resolve()),
                    '--out', str(trace.resolve())]
                limit = int(args.max_footprint_gib * 2**30)
                measured = bounded(command, attempt_dir / 'trace.log', attempt_dir / 'trace.usage.json', limit)
                if not measured['completion_latency']:
                    raise RuntimeError(f'{name} phase {phase} trace failed; retained {attempt_dir}')
                cpi = attempt_dir / 'input.cpi'
                conversion = bounded([str(args.converter.resolve()), '--source', str(trace.resolve()),
                    '--compiled', str(args.compiled.resolve()), '--target', str(cpi.resolve()),
                    '--receipt', str((attempt_dir / 'conversion.json').resolve())],
                    attempt_dir / 'conversion.log', attempt_dir / 'conversion.usage.json', limit)
                if not conversion['completion_latency']:
                    raise RuntimeError(f'{name} phase {phase} conversion failed; retained {attempt_dir}')
                if args.discard_witness:
                    trace.unlink()
                proof_dir = attempt_dir / 'proof'
                subprocess.run([sys.executable, '-m', 'autoresearch.experiments.evm_keth.bounded_prove',
                    '--product', str(args.product.resolve()), '--oracle', str(args.oracle.resolve()),
                    '--prover-input', str(cpi.resolve()), '--out', str(proof_dir.resolve()),
                    '--workers', str(args.workers), '--max-footprint-gib',
                    str(args.max_prover_footprint_gib or args.max_footprint_gib)], check=True)
                measured = json.loads((proof_dir / 'results.json').read_text())
                if measured['status'] != 'qualified':
                    raise RuntimeError(f'{name} phase {phase} proof failed; retained {attempt_dir}')
                if dependencies != {key: digest(path) for key, path in source_paths.items()}:
                    raise ValueError('qualification dependency changed during the run')
                proof = proof_dir / 'trial-1.proof.json'
                result = dict(identity=expected, proof=str(proof.relative_to(args.out)), proof_sha256=digest(proof))
                write_new(completion, result)
                if args.discard_witness:
                    cpi.unlink()
            parts.append({key: result[key] for key in ('proof', 'proof_sha256')})
            print(f'QUALIFIED {name} phase {phase}', flush=True)
        children.append(dict(index=index, phases=parts))
    if indices != list(range(-1, count)):
        return dict(status='partial-execution-qualification', op_block_execution_proved=False, children=children)
    manifest = args.out / 'manifest.json'
    write_new(manifest, dict(block=native['block'], parent_header=native['witness']['headers'][0],
        receipts=[row['receipt'] for row in checkpoints['checkpoints'][1::2]], proofs=children,
        final_state_nodes=checkpoints['checkpoints'][-1]['proof_nodes']))
    result = verify(manifest, args.compiled, args.oracle, native['block']['hash'],
                    native['witness']['headers'][0]['stateRoot'])
    write_new(args.out / 'verified.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('native-input', 'checkpoints', 'workloads', 'compiled', 'runtime-python-path',
                 'keth-checkout', 'converter', 'product', 'oracle', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--indices', nargs='+', type=int)
    parser.add_argument('--max-footprint-gib', type=float, default=48)
    parser.add_argument('--max-prover-footprint-gib', type=float)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--discard-witness', action='store_true')
    args = parser.parse_args()
    if args.max_footprint_gib <= 0 or args.workers <= 0 or (args.max_prover_footprint_gib is not None and args.max_prover_footprint_gib <= 0):
        parser.error('positive memory limit and worker count required')
    print(json.dumps(qualify(args), indent=2))
