#!/usr/bin/env python3
"""Alternating paired CPU measurements of two built Bend algorithms."""
import argparse
import json
from pathlib import Path
import statistics
import tempfile
from bend_common import digest, fixture, measure, provenance


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('baseline', 'candidate', 'oracle', 'output'):
        p.add_argument('--' + arg, type=Path, required=True)
    args = p.parse_args()
    report = provenance(args.candidate, args.oracle)
    report.update(rows=[], all_equal=True, baseline_binary_sha256=digest(args.baseline),
                  harness_sha256=digest(__file__), paired_order='baseline/candidate, candidate/baseline, baseline/candidate')
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    try:
        with tempfile.TemporaryDirectory() as tmp:
            for op in ('fft', 'ifft', 'multiply', 'prefix'):
                for threads in (1, 8):
                    row = dict(operation=op, log_size=20, threads=threads, samples=[])
                    for sample in range(3):
                        req, expected, zig = fixture(args.oracle.resolve(), op, 20, 9200 + sample, Path(tmp))
                        pair = dict(zig=zig)
                        order = ('baseline', 'candidate') if sample % 2 == 0 else ('candidate', 'baseline')
                        for name in order:
                            actual, receipt = measure([getattr(args, name).resolve(), '--threads', threads, '--gpu', 'off'], req)
                            if actual != expected or receipt['lane'] != 'bend-cpu':
                                raise ValueError(f'{name} parity/lane mismatch for {op}')
                            pair[name] = receipt
                        row['samples'].append(pair)
                    for scope in ('compute_ns', 'wall_ns'):
                        b = statistics.median(s['baseline'][scope] for s in row['samples'])
                        c = statistics.median(s['candidate'][scope] for s in row['samples'])
                        row[scope + '_speedup'] = b/c
                    report['rows'].append(row)
                    save()
                    print(f'{op} t{threads}: compute speedup {row["compute_ns_speedup"]:.2f}x; process wall speedup {row["wall_ns_speedup"]:.2f}x', flush=True)
    except Exception as exc:
        report.update(all_equal=False, error=str(exc))
        save()
        raise
    save()


if __name__ == '__main__':
    main()
