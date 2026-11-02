"""Accept a memory iteration only with fixed inputs and complete witness parity."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .bridge import digest, write_new


def compare(baseline: Path, candidate: Path, witness_comparison: Path):
    before, after, witness = [json.loads(path.read_text()) for path in (baseline, candidate, witness_comparison)]
    if (before['identity']['compiled'] != after['identity']['compiled']
            or before['identity']['input'] != after['identity']['input']
            or before['identity']['runtime'] == after['identity']['runtime']
            or before['public_output'] != after['public_output']
            or witness.get('schema') != 'keth-typed-witness-comparison-v1' or witness.get('equal') is not True
            or not before['measurement']['completion_latency'] or not after['measurement']['completion_latency']):
        raise ValueError('fixed-workload execution and complete witness parity required')
    required = {'adapter_start', 'memory_builder_ready', 'adapted_input_ready', 'serialization_start', 'serialization_end'}
    if any(not required <= {s['stage'] for s in v['stages']} for v in (before, after)):
        raise ValueError('incomplete stage instrumentation')
    initial, final = [v['measurement']['maximum_observed_footprint_bytes'] for v in (before, after)]
    return dict(schema='keth-memory-iteration-v1', compiled_sha256=before['identity']['compiled'],
        input_sha256=before['identity']['input'], baseline_runtime_sha256=before['identity']['runtime'],
        candidate_runtime_sha256=after['identity']['runtime'], baseline_footprint_bytes=initial,
        baseline_trace_sha256=before.get('trace_sha256'), candidate_trace_sha256=after.get('trace_sha256'),
        candidate_footprint_bytes=final, reduction_bytes=initial-final, reduction_percent=100*(initial-final)/initial,
        accepted=final < initial, witness_transport_equivalent=True,
        evidence_sha256={str(p): digest(p) for p in (baseline, candidate, witness_comparison)},
        buffer_diagnostics_are_capacity_bytes=True,
        measurement_scope='One process per fixed-workload run, Darwin physical footprint; trace generation and export only',
        full_prover_memory_reduction_qualified=False, op_block_execution_proved=False,
        baseline_stages=before['stages'], candidate_stages=after['stages'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('baseline', 'candidate', 'witness-comparison', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    result = compare(args.baseline, args.candidate, args.witness_comparison)
    write_new(args.out, result)
    print(json.dumps(result, indent=2))
