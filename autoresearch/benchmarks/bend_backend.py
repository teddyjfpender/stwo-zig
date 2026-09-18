#!/usr/bin/env python3
"""Full verified backend-call latency; not full-proof throughput.

Build bend-backend-bench with -Dbend-executable=<same binary as --bend>.
The executable uses eight Bend threads and retains every internal Zig parity check.
"""
import argparse
import json
from pathlib import Path
import statistics
from bend_common import digest, measure, provenance


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bend', type=Path, required=True)
    p.add_argument('--benchmark', type=Path, required=True)
    p.add_argument('--oracle', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--logs', default='16,20,22,24')
    p.add_argument('--repeats', type=int, default=3)
    args = p.parse_args()
    if args.repeats < 1:
        p.error('repeats must be positive')
    report = provenance(args.bend, args.oracle)
    report.update(schema='stwo-bend-backend-evidence-v2', rows=[], all_equal=True,
                  threads=8, parity_enabled=True,
                  benchmark_sha256=digest(args.benchmark),
                  harness_sha256=digest(__file__),
                  scope='Timed backend operation includes request construction, child launch, IO, decoding, Zig parity, copies; domain/twiddle/input setup and external check excluded. Zig uses existing SIMD transforms and specialized 2x LDE. Single column, Bend measured first. No full proof.')
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    try:
        for op, name in enumerate(('fft', 'ifft', 'lde2x')):
            for target in map(int, args.logs.split(',')):
                log = target - 1 if op == 2 else target
                row = dict(operation=name, input_log=log, output_log=target, samples=[])
                for sample in range(args.repeats):
                    _, receipt = measure([args.benchmark.resolve(), op, log, 9100 + sample], timeout=180)
                    if receipt.get('equal') is not True:
                        raise ValueError('missing parity receipt')
                    row['samples'].append(receipt)
                b = statistics.median(s['bend_backend_ns'] for s in row['samples'])
                z = statistics.median(s['zig_operation_ns'] for s in row['samples'])
                row.update(bend_backend_median_ns=b, zig_operation_median_ns=z, bend_over_zig=b/z)
                report['rows'].append(row)
                save()
                print(f'{name} output log{target}: Bend backend {b/1e6:.3f} ms, Zig {z/1e6:.3f} ms, ratio {b/z:.2f}', flush=True)
    except Exception as exc:
        report.update(all_equal=False, error=str(exc))
        save()
        raise
    save()


if __name__ == '__main__':
    main()
