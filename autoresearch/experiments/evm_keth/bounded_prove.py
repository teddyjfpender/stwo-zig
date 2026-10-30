#!/usr/bin/env python3
"""Measure canonical proving with a Darwin product-footprint watchdog.

The watchdog records and terminates capacity attempts above an explicit limit.
It does not change proof parameters, hide failed attempts, or bound total host RAM.
"""
from __future__ import annotations

import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time

if __package__:
    from .bridge import ROOT
    from .disk_reserve import DiskReserve
else:
    from bridge import ROOT
    from disk_reserve import DiskReserve
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'scripts'))
# Keth's environment also exports a top-level `scripts` package. Load the
# owned driver by its exact path so that package cannot shadow this module.
_spec = importlib.util.spec_from_file_location('_stwo_benchmark_cairo', ROOT / 'scripts/benchmark_cairo.py')
benchmark_cairo = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(benchmark_cairo)


def physical_usage(pid: int) -> tuple[int, int]:
    # RUSAGE_INFO_V6 ABI: process_usage.zig and the macOS SDK sys/resource.h.
    # Full oversized buffer protects the v6 tail; fields are little-endian u64.
    buffer = ctypes.create_string_buffer(1024)
    libproc = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    libproc.proc_pid_rusage.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p)
    libproc.proc_pid_rusage.restype = ctypes.c_int
    if libproc.proc_pid_rusage(pid, 6, buffer) != 0:
        raise OSError(ctypes.get_errno(), 'proc_pid_rusage failed')
    current = struct.unpack_from('<Q', buffer, 16 + 7 * 8)[0]
    peak = struct.unpack_from('<Q', buffer, 16 + 28 * 8)[0]
    return current, peak


def run(args):
    if sys.platform != 'darwin':
        raise ValueError('this footprint watchdog requires Darwin')
    physical_usage(os.getpid())  # Refuse an unobservable capacity attempt.
    original = benchmark_cairo.measure
    limit = int(args.max_footprint_gib * (1 << 30))

    def measured(command, log, env=None):
        if Path(command[0]).resolve() != args.product.resolve():
            return original(command, log, env)
        started = time.monotonic_ns()
        maximum, samples, failures, reason = 0, 0, 0, None
        disk = DiskReserve(log.parent, int(getattr(args, 'min_free_disk_gib', 64) * 2**30))
        disk_reason = disk.check()
        if disk_reason:
            raise RuntimeError(disk_reason)
        with log.open('xb') as stream:
            process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, env=env)
            while True:
                done, status, usage = os.wait4(process.pid, os.WNOHANG)
                if done:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                try:
                    disk_reason = disk.check()
                    if disk_reason and reason is None:
                        reason = disk_reason
                        process.send_signal(signal.SIGKILL)
                    current, peak = physical_usage(process.pid)
                    maximum = max(maximum, current, peak)
                    samples += 1
                    failures = 0
                    if maximum > limit and reason is None:
                        reason = 'product physical footprint exceeded explicit limit'
                        process.send_signal(signal.SIGKILL)
                except OSError:
                    failures += 1
                    if failures >= 10 and reason is None:
                        reason = 'product footprint monitoring became unavailable'
                        process.send_signal(signal.SIGKILL)
                time.sleep(0.01)
        return {'exit_code': process.returncode, 'wall_ns': time.monotonic_ns() - started,
                'user_ns': round(usage.ru_utime * 1e9), 'system_ns': round(usage.ru_stime * 1e9),
                'max_process_tree_rss_bytes': usage.ru_maxrss,
                'rss_is_simultaneous_process_tree_sum': False,
                'footprint_watchdog': {'source': 'darwin_proc_pid_rusage_v6', 'limit_bytes': limit,
                    'maximum_observed_bytes': maximum, 'samples': samples, 'termination_reason': reason,
                    'scope': 'product process; not simultaneous process-tree or host memory'},
                'disk_reserve': disk.record()}

    benchmark_cairo.measure = measured
    try:
        return benchmark_cairo.run_benchmark(argparse.Namespace(product=args.product, oracle=args.oracle,
            prover_input=args.prover_input, program=None, program_type=None, arguments=None, params=None,
            trials=1, out=args.out), env=dict(os.environ, STWO_ZIG_WORKERS=str(args.workers),
            STWO_CAIRO_PREPROCESSED_CACHE_DIR=str(args.out.resolve() / 'cache')))
    finally:
        benchmark_cairo.measure = original


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'oracle', 'prover-input', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--max-footprint-gib', type=float, default=48)
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--min-free-disk-gib', type=float, default=64)
    args = parser.parse_args()
    if args.max_footprint_gib <= 0 or args.workers < 1:
        parser.error('footprint limit and worker count must be positive')
    run(args)
