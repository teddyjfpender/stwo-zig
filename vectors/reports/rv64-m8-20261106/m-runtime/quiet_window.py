#!/usr/bin/env python3
"""Wait (no GPU held) until the pod shows the canonical quiet gate's blockers absent:
no compiler/receiver process (same list as rv64_m4_resident.quiet_checkpoint) and no GPU
compute process, for --stable consecutive samples. Exit 0 when quiet, 1 on timeout."""
import argparse, os, subprocess, sys, time
from pathlib import Path
BLOCKERS = ("zig", "nvcc", "cc1", "cc1plus", "cicc", "ptxas", "clang", "clang++", "gcc", "g++")


def busy():
    found = []
    for d in Path('/proc').iterdir():
        if not d.name.isdigit():
            continue
        try:
            c = (d / 'cmdline').read_bytes().split(b'\0')
            exe = Path(os.fsdecode(c[0])).name if c[0] else ''
        except OSError:
            continue
        if exe in BLOCKERS or 'recursion-receiver' in exe:
            found.append(exe)
    gpu = subprocess.run(['nvidia-smi', '--query-compute-apps=pid', '--format=csv,noheader'], capture_output=True, text=True).stdout.split()
    return found + ['gpu:' + p for p in gpu]


p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--stable', type=int, default=30)
p.add_argument('--interval', type=float, default=2.0)
p.add_argument('--timeout', type=float, default=4 * 3600)
a = p.parse_args()
start, run = time.time(), 0
while time.time() - start < a.timeout:
    b = busy()
    run = 0 if b else run + 1
    if run >= a.stable:
        print(f'quiet after {time.time() - start:.0f}s'); sys.exit(0)
    time.sleep(a.interval)
print('timeout; last blockers', b); sys.exit(1)
