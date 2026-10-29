#!/usr/bin/env python3
"""Measure one Cairo input with separate virtual-address and resident guards."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import signal
import sys
import threading

if __package__:
    from .bridge import ROOT
    from .limits import address_space_limit
else:
    from bridge import ROOT
    from limits import address_space_limit
sys.path.insert(0, str(ROOT))
from scripts.benchmark_cairo import run_benchmark


def run(args, env=None):
    if not sys.platform.startswith('linux') or not hasattr(os, 'pidfd_open'):
        raise ValueError('the resident RSS guard requires Linux /proc and pidfd support')
    if args.rss_limit_bytes < 1 or args.sample_ms <= 0:
        raise ValueError('resident limit and sample interval must be positive')
    with address_space_limit(args.virtual_gib) as policy:
        return run_limited(args, env, policy)


def run_limited(args, env, policy):
    product = args.product.resolve()
    out = args.out.resolve()
    stop = threading.Event()
    guard = {'schema': 'keth-prover-rss-guard-v2', 'rss_limit_bytes': args.rss_limit_bytes,
             'sample_interval_seconds': args.sample_ms / 1000,
             'virtual_address_limit_bytes': args.virtual_gib << 30,
             'address_space_policy': policy,
             'peak_sampled_rss_bytes': 0, 'samples': 0, 'terminated': False,
             'pid_namespace_mapping': 'NSpid innermost; process bound with pidfd'}

    def watch():
        target = None
        pidfd = None
        try:
            while not stop.is_set():
                if target is None:
                    for proc in Path('/proc').iterdir():
                        if not proc.name.isdigit():
                            continue
                        candidate = None
                        try:
                            command = (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')
                            if not command.startswith(str(product) + ' prove ') or str(out / 'trial-1.proof.json') not in command:
                                continue
                            fields = dict(line.split(':', 1) for line in (proc / 'status').read_text().splitlines() if ':' in line)
                            candidate = os.pidfd_open(int(fields['NSpid'].split()[-1]))
                            if (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace') != command:
                                os.close(candidate)
                                candidate = None
                                continue
                            pidfd, target = candidate, proc
                            candidate = None
                            break
                        except OSError:
                            if candidate is not None:
                                os.close(candidate)
                            continue
                if target is not None:
                    try:
                        fields = dict(line.split(':', 1) for line in (target / 'status').read_text().splitlines() if ':' in line)
                        rss = int(fields['VmRSS'].split()[0]) * 1024
                        guard['samples'] += 1
                        guard['peak_sampled_rss_bytes'] = max(guard['peak_sampled_rss_bytes'], rss)
                        if rss > args.rss_limit_bytes:
                            signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                            guard['terminated'] = True
                            break
                    except (OSError, KeyError):
                        break
                stop.wait(guard['sample_interval_seconds'])
        finally:
            if pidfd is not None:
                os.close(pidfd)

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    try:
        result = run_benchmark(argparse.Namespace(product=product, oracle=args.oracle.resolve(),
            program=None, program_type=None, prover_input=args.prover_input.resolve(),
            arguments=None, params=args.params, trials=1, out=out), env=dict(os.environ) if env is None else env)
        if guard['samples'] == 0 or guard['terminated']:
            raise RuntimeError('resident guard did not qualify')
        return result
    finally:
        stop.set()
        thread.join()
        target = out / 'rss-guard.json' if out.is_dir() else out.with_suffix('.rss-guard.json')
        target.write_text(json.dumps(guard, indent=2) + '\n')
        print(json.dumps(guard), flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('product', 'oracle', 'prover-input', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--params', type=Path)
    parser.add_argument('--virtual-gib', type=int, default=32)
    parser.add_argument('--rss-limit-bytes', type=int, default=8_000_000_000)
    parser.add_argument('--sample-ms', type=float, default=2)
    args = parser.parse_args()
    if args.virtual_gib < 0 or args.rss_limit_bytes < 1 or args.sample_ms <= 0:
        parser.error('resident limit and interval must be positive; virtual limit may be zero')
    run(args)
