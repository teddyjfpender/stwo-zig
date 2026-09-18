#!/usr/bin/env python3
"""Frozen Circle FFT matrix and parity gate. Mutate Bend, never this oracle."""
import argparse
import json
from pathlib import Path
import statistics
import tempfile
from bend_common import OPS, fixture, measure, provenance


def main(default_ops="fft,ifft"):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bend", type=Path, required=True)
    p.add_argument("--oracle", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--logs", default="16,18,20")
    p.add_argument("--threads", default="1,2,4,8")
    p.add_argument("--columns", default="1,16,64,128")
    p.add_argument("--batch-log", type=int, default=16)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--ops", default=default_ops)
    p.add_argument("--fixtures", type=int, default=0, help="additional seeded small fixtures per operation")
    args = p.parse_args()
    bend, oracle = args.bend.resolve(), args.oracle.resolve()
    report = provenance(bend, oracle)
    report.update({"rows": [], "fixture_count": 0, "all_equal": True,
                   "unavailable_lanes": {"zig_scalar": "not separately compiled", "metal": "not measured", "bend_metal": "not measured", "bend_cuda": "not measured"}})
    report["sources"][str(Path(__file__).resolve().relative_to(Path(__file__).resolve().parents[2]))] = __import__('bend_common').digest(__file__)
    ops = args.ops.split(',')
    if any(op not in OPS for op in ops) or args.repeats < 1:
        p.error("invalid operation or repeat count")
    def save():
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n')
    try:
        with tempfile.TemporaryDirectory(prefix="bend-bench-") as tmp:
            d = Path(tmp)
            for op in ops:
                for seed in range(args.fixtures):
                    log = 3 + seed % 8 if op.startswith('fri') else 1 + seed % 10
                    req, expected, _ = fixture(oracle, op, log, seed, d)
                    actual, telemetry = measure([bend, "--threads", "1", "--gpu", "off"], req)
                    if actual != expected:
                        raise ValueError(f"parity mismatch: {op} log={log} seed={seed}")
                    report["fixture_count"] += 1
                for log in map(int, args.logs.split(',')):
                    for columns in map(int, args.columns.split(',')):
                        if columns != 1 and log != args.batch_log:
                            continue
                        for threads in map(int, args.threads.split(',')):
                            row = {"operation": op, "log_size": log, "columns": columns, "threads": threads, "samples": [], "equal": True,
                                   "batch_mode": "sequential native child per column", "gpu_ns": None, "host_device_copy_bytes": 0}
                            for sample in range(args.repeats):
                                bs, zs = [], []
                                for col in range(columns):
                                    req, expected, zig = fixture(oracle, op, log, sample * 1000 + col + 9000, d)
                                    actual, native = measure([bend, "--threads", str(threads), "--gpu", "off"], req)
                                    if native["lane"] != "bend-cpu" or actual != expected:
                                        raise ValueError(f"parity/lane mismatch: {op} log={log} col={col}")
                                    bs.append(native)
                                    zs.append(zig)
                                def aggregate(samples):
                                    sums = {k: sum(s[k] for s in samples) for k in ("compute_ns", "wall_ns", "cpu_user_s", "cpu_system_s", "request_bytes", "response_bytes")}
                                    sums['peak_rss_bytes'] = max(s['peak_rss_bytes'] for s in samples)
                                    return sums
                                row['samples'].append({"bend": aggregate(bs), "zig": aggregate(zs)})
                            bns = statistics.median(s['bend']['compute_ns'] for s in row['samples'])
                            zns = statistics.median(s['zig']['compute_ns'] for s in row['samples'])
                            row.update({"bend_compute_median_ns": bns, "zig_compute_median_ns": zns, "bend_over_zig": bns/zns})
                            n = 1 << log
                            ops_count = columns * (3 * n * log // 2 + (n if op == 'ifft' else 0)) if op in ('fft', 'ifft') else columns * (n//2 if op == 'multiply' else n)
                            # FRI needs a richer op ledger; never invent its numerator.
                            row['effective_m31_ops_per_s'] = None if op.startswith('fri') else ops_count * 1e9/bns
                            report['rows'].append(row)
                            print(f"{op} log{log} x{columns} t{threads}: Bend {bns/1e6:.3f} ms, Zig {zns/1e6:.3f} ms, ratio {bns/zns:.2f}", flush=True)
                            save()
    except Exception as exc:
        report['all_equal'] = False
        report['error'] = str(exc)
        save()
        raise
    save()


if __name__ == "__main__":
    main()
