#!/usr/bin/env python3
"""M8 exact per-node/per-stage allocator peaks (diagnostic, not timing).

Runs ONE resident service (cold + warm) of the canonical default arm
(D2 + truth coalescing, auto arena, one proof per GPU) with
STWO_RV64_ALLOCATION_OBSERVER=1 and STWO_RV64_M8_MEM_TRACE, then:
  - tests/cuda/rv64/node_peaks_parser.py -> node-peaks.{json,md}
    (19-node x stage table; observer resets each stage's high-water at the
    boundary and logs node/stage/lane);
  - scripts/rv64_m8_memory_sweep.py replay -> sweep/policy.{json,md}.
The observer host-joins lanes at stage boundaries: walls are NOT latency.
The harness takes the GPU lock itself; never wrap this in gpu.lock.

  python3 scripts/rv64_m8_memory_measure.py --stream m8-memory --runtime RUNTIME.json \
      --out /workspace/m3/runs/m8-memory/peaks-<n> [--block 24628607] [--arena-sweep 22G]
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

import rv64_m7_integration_stack as stack

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--stream', required=True)
    p.add_argument('--runtime', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--block', type=int, default=24628607, choices=(24628607, 26235156))
    p.add_argument('--expected-nodes', type=int, default=19)
    p.add_argument('--arena-sweep', default='22G')
    p.add_argument('--request-timeout', default='600')
    p.add_argument('--no-trace', action='store_true', help='observer table only (isolation)')
    p.add_argument('--no-observer', action='store_true', help='neither observer nor trace (control)')
    args = p.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    trace_dir = out / 'trace'
    trace_dir.mkdir()
    runtime = json.loads(args.runtime.read_text())
    assets = dict(runtime['assets'])
    for name, path in assets.items():
        if stack.sha(path) != runtime['asset_sha256'][name]:
            raise SystemExit('pinned runtime changed: ' + name)
    bins = Path('/workspace/m3/build') / args.stream / 'zig-out/bin'
    assets.update(driver=str(bins / 'rv64-word16-ethereum-gpu-combined'),
                  receiver=str(bins / 'rv64-word16-ethereum-recursion-receiver'))
    manifest = {'source_root': str(ROOT), 'assets': assets, 'block': args.block,
                'preset': json.loads(stack.DEFAULT_PRESET.read_text())}
    label = 'peaks-' + out.name
    argv, tag = stack.command(manifest, 'baseline', 0, args.stream, False, label)
    if not args.no_observer:
        argv += ['--env', 'STWO_RV64_ALLOCATION_OBSERVER=1']
        if not args.no_trace:
            argv += ['--env', f'STWO_RV64_M8_MEM_TRACE={trace_dir}']
    argv += ['--quiet-mode', 'diagnostic', '--request-timeout', args.request_timeout]
    service = Path('/workspace/m3/runs') / args.stream / f'daemon-{args.block}-r2-{tag}'
    receipt = {'schema': 'rv64-m8-memory-measure/v1', 'label': '[M] allocator diagnostic; walls not latency',
               'block': args.block, 'service': str(service), 'argv': argv,
               'asset_sha256': {k: stack.sha(v) for k, v in assets.items()},
               'source_root': str(Path('/workspace/m3/src') / args.stream),
               'source_sha256_count': len(stack.source_hashes(Path('/workspace/m3/src') / args.stream))}
    stack.write(out / 'measure.json', receipt)
    env = stack.clean_environment(os.environ)
    env['TMPDIR'] = '/workspace/m3/tmp'
    with (out / 'service.log').open('w') as log:
        receipt['service_exit'] = subprocess.run(argv, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
    stack.write(out / 'measure.json', receipt)
    stderr = service / 'producer.stderr'
    receipt['parser_exit'] = subprocess.run(
        [sys.executable, str(ROOT / 'tests/cuda/rv64/node_peaks_parser.py'), str(stderr), '--block', str(args.block),
         '--expected-nodes', str(args.expected_nodes), '--raw-ref', str(stderr),
         '--json', str(out / 'node-peaks.json'), '--markdown', str(out / 'node-peaks.md')]).returncode
    traces = sorted(trace_dir.glob('arena-trace-*.tsv'))
    receipt['traces'] = [{'path': str(t), 'bytes': t.stat().st_size, 'sha256': stack.sha(t)} for t in traces]
    if traces:
        receipt['sweep_exit'] = subprocess.run(
            [sys.executable, str(ROOT / 'scripts/rv64_m8_memory_sweep.py'), 'replay', *map(str, traces),
             '--out', str(out / 'sweep'), '--arena', args.arena_sweep]).returncode
    stack.write(out / 'measure.json', receipt)
    print(json.dumps({k: receipt.get(k) for k in ('service_exit', 'parser_exit', 'sweep_exit')}))
    return 0 if receipt['service_exit'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
