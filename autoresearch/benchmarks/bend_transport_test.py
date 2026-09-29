#!/usr/bin/env python3
"""Exercise persistent template framing, including fail-closed invalid reuse."""
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from bend_common import digest, fixture

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--bend', type=Path, required=True)
p.add_argument('--oracle', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
a = p.parse_args()
results = []
with tempfile.TemporaryDirectory() as tmp:
    d = Path(tmp)
    full, expected, _ = fixture(a.oracle.resolve(), 'fft', 4, 42, d)
    different, expected2, _ = fixture(a.oracle.resolve(), 'fft', 4, 43, d)
    bigger, _, _ = fixture(a.oracle.resolve(), 'fft', 5, 43, d)
    def frame(req, reuse=False, magic=0x33444e42):
        words = list(struct.unpack('<5I', req[:20]))
        words[0] = magic
        if reuse:
            words[2] |= 0x80000000
        end = 20 + (1 << words[3]) * 4 if reuse else len(req)
        return struct.pack('<5I', *words) + req[20:end]
    cases = [
        ('reuse_different_values', frame(full)+frame(different, True), expected+expected2, True),
        ('reuse_before_plan', frame(full, True), b'', False),
        ('reuse_wrong_size', frame(full)+frame(bigger, True), expected, False),
        ('legacy_magic_reuse', frame(full, True, 0x32444e42), b'', False),
        ('truncated_frame', frame(full)[:-1], b'', False),
    ]
    for name, request, want, success in cases:
        proc = subprocess.run([str(a.bend.resolve()), '--threads', '2', '--gpu', 'off'], input=request,
                              capture_output=True, timeout=30, env=dict(os.environ, STWO_BEND_PERSISTENT='1'))
        passed = (proc.returncode == 0) == success and proc.stdout == want
        results.append(dict(case=name, passed=passed, returncode=proc.returncode,
                            stderr=proc.stderr.decode(errors='replace')))
        if not passed:
            raise AssertionError(results[-1])
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_text(json.dumps(dict(binary_sha256=digest(a.bend), all_passed=True, cases=results), indent=2)+'\n')
print(f'{len(results)} transport cases passed')
