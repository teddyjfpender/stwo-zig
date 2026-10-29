#!/usr/bin/env python3
"""Build owned reference adapters against the clean, pinned Optimism module."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

if __package__:
    from .bridge import PINS, authenticate, digest, write_new
else:
    from bridge import PINS, authenticate, digest, write_new


def build(checkout: Path, out: Path, target: str, mise: str = 'mise') -> dict:
    checkout, out = checkout.resolve(), out.resolve()
    pin = PINS['op_reference']
    source = authenticate(checkout, pin)
    directory = Path(__file__).resolve().parent
    names = {'execution': ['op_reference/main.go', 'op_reference/execution.go', 'op_reference/checkpoints.go'],
             'path-probe': ['op_path_probe/main.go'], 'fee-oracle': ['op_fee_oracle/main.go'],
             'deposit-oracle': ['op_deposit_oracle/main.go']}[target]
    files = [directory / name for name in names]
    if out.exists() or out.with_suffix(out.suffix + '.build.json').exists():
        raise ValueError('build destination must be new')
    hashes = {name: digest(path) for name, path in zip(names, files)}
    out.parent.mkdir(parents=True, exist_ok=True)
    command = [mise, 'exec', 'go@' + pin['go_version'], '--', 'go', '-C', str(checkout),
               'build', '-trimpath', '-o', str(out), *map(str, files)]
    started = time.monotonic()
    # Explicit tool pin from outside the reference checkout: do not load or
    # automatically trust that repository's mise configuration.
    with tempfile.TemporaryDirectory(prefix='keth-op-build-') as temporary:
        subprocess.run(command, cwd=temporary, check=True, env=dict(os.environ, GOMAXPROCS='4'))
    if source != authenticate(checkout, pin) or hashes != {name: digest(path) for name, path in zip(names, files)}:
        raise ValueError('reference or adapter source changed during build')
    result = dict(schema='keth-op-reference-build-v1', target=target, source=source,
                  source_files_sha256=hashes, go_version=pin['go_version'],
                  go_mod_sha256=digest(checkout / 'go.mod'), go_sum_sha256=digest(checkout / 'go.sum'),
                  binary_sha256=digest(out), command=command, elapsed_seconds=time.monotonic() - started)
    write_new(out.with_suffix(out.suffix + '.build.json'), result)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-checkout', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--target', choices=('execution', 'path-probe', 'fee-oracle', 'deposit-oracle'), default='execution')
    parser.add_argument('--mise', default='mise')
    args = parser.parse_args()
    print(json.dumps(build(args.reference_checkout, args.out, args.target, args.mise), indent=2))
