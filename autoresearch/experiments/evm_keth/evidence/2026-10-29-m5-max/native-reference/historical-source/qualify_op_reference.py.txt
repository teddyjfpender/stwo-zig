#!/usr/bin/env python3
"""Qualify the native reference runner on full inputs and rejected mutations.

Measures native execution only. No result is an OP Cairo proving measurement.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import statistics
import subprocess
import time

if __package__:
    from .bridge import PINS, digest, write_new
    from .check_fixture import header_hash
else:
    from bridge import PINS, digest, write_new
    from check_fixture import header_hash


def qualify(binary: Path, source: Path, out: Path, trials: int = 3) -> dict:
    binary, source = binary.resolve(), source.resolve()
    source_hash, binary_hash = digest(source), digest(binary)
    value = json.loads(source.read_text())
    out.mkdir(parents=True, exist_ok=False)
    result = dict(schema='keth-op-reference-qualification-v1', status='running',
                  input_sha256=source_hash, binary_sha256=binary_hash,
                  block_hash=value['block']['hash'], block_number=int(value['block']['number'], 16),
                  native_execution_only=True, cairo_execution_proved=False,
                  derivation_proved=False, trials=[], negative_checks=[])

    def invoke(input_path, name, expected):
        output_path = out / (name + '.json')
        started = time.monotonic()
        run = subprocess.run([str(binary), '--input', str(input_path), '--output', str(output_path)],
                             capture_output=True, text=True)
        (out / (name + '.log')).write_text(run.stdout + run.stderr)
        receipt = json.loads(output_path.read_text())
        entry = dict(name=name, elapsed_seconds=time.monotonic() - started,
                     returncode=run.returncode, input_sha256=digest(input_path),
                     result_sha256=digest(output_path), execution_seconds=receipt.get('execution_seconds'),
                     offline_execution_checked=receipt['offline_execution_checked'],
                     error=receipt.get('error'))
        (result['trials'] if expected else result['negative_checks']).append(entry)
        if ((run.returncode == 0) != expected or receipt['offline_execution_checked'] is not expected
                or any(receipt[k] is not False for k in ('cairo_execution_proved', 'derivation_proved', 'consensus_authenticated'))):
            raise ValueError(f'reference acceptance/rejection mismatch: {name}')
        if expected:
            dependency = receipt['geth_module']['Replace']
            if (dependency['Path'] != 'github.com/ethereum-optimism/op-geth'
                    or dependency['Version'] != PINS['op_reference']['op_geth_version']
                    or receipt['go_version'] != 'go' + PINS['op_reference']['go_version']):
                raise ValueError('reference toolchain/dependency pin mismatch')
            if (receipt['computed_state_root'] != value['block']['stateRoot']
                    or receipt['computed_receipt_root'] != value['block']['receiptsRoot']
                    or not receipt['requests_hash_checked']):
                raise ValueError('reference did not check complete execution roots')
        return entry

    try:
        for index in range(trials):
            invoke(source, f'trial-{index + 1}', True)
        for mutation in ('missing_state', 'missing_code', 'withdrawal_root', 'requests_hash'):
            altered = copy.deepcopy(value)
            if mutation == 'missing_state':
                altered['witness']['state'] = []
            elif mutation == 'missing_code':
                altered['witness']['codes'] = []
            else:
                key = 'withdrawalsRoot' if mutation == 'withdrawal_root' else 'requestsHash'
                altered['block'][key] = '0x' + '00' * 32
                # Keep the mutated header self-consistent so rejection reaches
                # the actual execution-derived root checks.
                altered['block']['hash'] = header_hash(altered['block'])
            path = out / (mutation + '-input.json')
            write_new(path, altered)
            invoke(path, mutation, False)
        if digest(source) != source_hash or digest(binary) != binary_hash:
            raise ValueError('input or reference binary changed during qualification')
        samples = [trial['execution_seconds'] for trial in result['trials']]
        result.update(status='qualified', native_execution_median_seconds=statistics.median(samples),
                      native_execution_min_seconds=min(samples), native_execution_max_seconds=max(samples))
    except Exception as error:
        result.update(status='failed', error=str(error))
        raise
    finally:
        write_new(out / 'qualification.json', result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--trials', type=int, default=3)
    args = parser.parse_args()
    if args.trials < 1:
        parser.error('positive trial count required')
    print(json.dumps(qualify(args.binary, args.input, args.out, args.trials), indent=2))
