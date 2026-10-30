"""Fixed-workload, stage-resolved memory experiment for an owned Keth runtime."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bounded_process import run
from .bridge import ROOT, digest, write_new


def profile(args):
    args.out.mkdir(parents=True, exist_ok=False)
    binary = args.runtime_python_path / 'cairo_addons/rust_bindings.abi3.so'
    identity = {key: digest(path) for key, path in dict(compiled=args.compiled, input=args.input, runtime=binary).items()}
    trace = args.out / 'trace.json'
    result = run(['env', 'PYTHONHASHSEED=0', 'KETH_WITNESS_MEMORY_PROFILE=1',
        'PYTHONPATH=' + str(args.runtime_python_path.resolve()) + ':' + str(ROOT),
        str((args.keth_checkout / '.venv/bin/python').absolute()), '-m',
        'autoresearch.experiments.evm_keth.op_cairo', '--keth-checkout', str(args.keth_checkout.resolve()),
        'trace', '--compiled', str(args.compiled.resolve()), '--input', str(args.input.resolve()),
        '--out', str(trace.resolve())], args.out / 'run.log', args.out / 'usage.json',
        int(args.max_footprint_gib * 2**30), args.out / 'samples.jsonl')
    stages, buffers = [], []
    for line in (args.out / 'run.log').read_text().splitlines():
        for prefix, target in (('KETH_MEMORY ', stages), ('KETH_BUFFER ', buffers)):
            if line.startswith(prefix):
                target.append(json.loads(line[len(prefix):]))
    samples = [json.loads(line) for line in (args.out / 'samples.jsonl').read_text().splitlines()]
    start = result['started_utc_ns']
    for index, stage in enumerate(stages):
        end = stages[index + 1]['time_ns'] if index + 1 < len(stages) else start + result['wall_ns']
        observations = [row[1] for row in samples if stage['time_ns'] <= start + row[0] < end]
        stage['maximum_observed_until_next_stage'] = max(observations, default=stage['footprint'])
    qualified = result['completion_latency']
    trace_receipt = json.loads(trace.with_name(trace.name + '.receipt.json').read_text()) if qualified else {}
    output = trace_receipt.get('public_output')
    record = dict(schema='keth-memory-profile-v1', identity=identity, measurement=result,
                  stages=stages, buffers=buffers, public_output=output,
                  trace_sha256=trace_receipt.get('trace_sha256'),
                  op_block_execution_proved=False)
    write_new(args.out / 'profile.json', record)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('compiled', 'input', 'runtime-python-path', 'keth-checkout', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--max-footprint-gib', type=float, default=48)
    print(json.dumps(profile(parser.parse_args()), indent=2))
