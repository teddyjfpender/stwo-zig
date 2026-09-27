"""Attach read-only macOS/Linux RSS sampling to one already running proof process.

This is supplementary telemetry, not OS physical footprint or an exact peak.
Process start identity is pinned to prevent following a reused PID. A missing
process or changed identity ends sampling without touching the prover.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time


def probe(pid):
    result = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart=', '-o', 'rss=',
                             '-o', 'time=', '-o', '%cpu=', '-o', 'comm='],
                            capture_output=True, text=True, check=False)
    if result.returncode == 1 and not result.stdout.strip():
        return None
    if result.returncode:
        raise RuntimeError(f'ps failed: {result.stderr.strip()}')
    parts = result.stdout.strip().split(maxsplit=8)
    if len(parts) != 9:
        raise ValueError('unexpected ps process record')
    return {'started': ' '.join(parts[:5]), 'rss_bytes': int(parts[5]) * 1024,
            'cpu_time': parts[6], 'cpu_percent': float(parts[7]), 'executable': parts[8]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--interval', type=float, default=5)
    args = parser.parse_args()
    if args.pid <= 0 or not 1 <= args.interval <= 60:
        parser.error('positive PID and interval in [1, 60] required')
    initial = probe(args.pid)
    if initial is None:
        raise RuntimeError('target process is not running')
    identity = initial['started'], initial['executable']
    directory = args.run_dir.resolve(strict=True)
    pattern = re.compile(r'BLOCK_STREAM proved_segments=(\d+)/(\d+).*?retained_nodes=(\d+) peak_bytes=(\d+) elapsed_ns=(\d+)')
    samples = 0
    peak = 0
    progress = None
    partial_line = ''
    start = time.monotonic_ns()
    with (directory / 'run.log').open() as log, (directory / 'rss-samples.jsonl').open('x') as output:
        output.write(json.dumps({'kind': 'metadata', 'pid': args.pid, 'process_identity': identity,
                                 'interval_seconds': args.interval, 'scope': 'sampled RSS; excludes time before attachment; not physical footprint'}) + '\n')
        output.flush()
        while True:
            try:
                current = probe(args.pid)
            except (RuntimeError, ValueError) as exc:
                output.write(json.dumps({'kind': 'observation_error', 'unix_ns': time.time_ns(), 'error': str(exc)}) + '\n')
                output.flush()
                time.sleep(args.interval)
                continue
            if current is None or (current['started'], current['executable']) != identity:
                reason = 'process_exited' if current is None else 'process_identity_changed'
                break
            # Read only new log bytes; never repeatedly load a growing block log.
            lines = (partial_line + log.read()).split('\n')
            partial_line = lines.pop()
            for line in lines:
                if match := pattern.search(line):
                    progress = {'verified_segments': int(match[1]), 'planned_segments': int(match[2]),
                                'retained_nodes': int(match[3]), 'tracked_peak_bytes': int(match[4]),
                                'pipeline_elapsed_ns': int(match[5])}
            peak = max(peak, current['rss_bytes'])
            samples += 1
            output.write(json.dumps({'kind': 'sample', 'unix_ns': time.time_ns(),
                                     'sampling_elapsed_ns': time.monotonic_ns() - start,
                                     **current, 'last_completed_progress': progress}) + '\n')
            output.flush()
            time.sleep(args.interval)
        summary = {'kind': 'summary', 'reason': reason, 'samples': samples,
                   'sampled_peak_rss_bytes': peak, 'last_completed_progress': progress,
                   'full_block_root_verified': False,
                   'qualification_authority': 'measurement.json and independently verified root, not this sampler'}
        output.write(json.dumps(summary) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
