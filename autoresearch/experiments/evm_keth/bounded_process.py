"""Run a trace/export command with a measured Darwin footprint limit."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from .bounded_prove import physical_usage
from .bridge import write_new


def run(command: list[str], log: Path, receipt: Path, limit: int, samples_path: Path | None = None):
    if sys.platform != 'darwin' or limit <= 0 or not command or receipt.exists():
        raise ValueError('require Darwin, a positive limit, command and new receipt')
    physical_usage(os.getpid())
    maximum, samples, failures, reason = 0, 0, 0, None
    started = time.monotonic_ns()
    started_utc = time.time_ns()
    with ExitStack() as stack:
        stream = stack.enter_context(log.open('xb'))
        timeline = stack.enter_context(samples_path.open('x')) if samples_path else None
        process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT)
        while True:
            done, status, usage = os.wait4(process.pid, os.WNOHANG)
            if done:
                process.returncode = os.waitstatus_to_exitcode(status)
                break
            try:
                current, peak = physical_usage(process.pid)
                maximum = max(maximum, current, peak)
                samples += 1
                if timeline:
                    timeline.write(json.dumps([time.monotonic_ns() - started, current, peak]) + '\n')
                failures = 0
                if maximum > limit and reason is None:
                    reason = 'process footprint exceeded explicit limit'
                    process.send_signal(signal.SIGKILL)
            except OSError:
                failures += 1
                if failures >= 10 and reason is None:
                    reason = 'process footprint monitoring became unavailable'
                    process.send_signal(signal.SIGKILL)
            time.sleep(0.01)
    result = dict(schema='keth-bounded-process-v1', command=command, exit_code=process.returncode,
                  wall_ns=time.monotonic_ns() - started, limit_bytes=limit,
                  started_utc_ns=started_utc, samples_path=str(samples_path) if samples_path else None,
                  maximum_observed_footprint_bytes=maximum, footprint_samples=samples,
                  footprint_source='darwin_proc_pid_rusage_v6', termination_reason=reason,
                  completion_latency=process.returncode == 0 and reason is None)
    write_new(receipt, result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--log', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--max-footprint-gib', type=float, default=48)
    parser.add_argument('--samples-path', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    result = run(command, args.log, args.receipt, int(args.max_footprint_gib * 2**30), args.samples_path)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['exit_code'] == 0 else 1)
