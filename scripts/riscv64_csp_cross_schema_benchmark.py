#!/usr/bin/env python3
"""Sequential pinned CSP processes and fresh receivers; no prover implementation."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
try:
    from . import riscv64_csp_cross_schema as check
except ImportError:
    import riscv64_csp_cross_schema as check


def load(path): return json.loads(Path(path).read_text())
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path, value): Path(path).write_text(json.dumps(value, indent=2) + '\n')


def timed(command, directory, label):
    output, error, usage = (directory / f'{label}.{suffix}' for suffix in ('stdout.json', 'stderr', 'time'))
    invocation = ['/usr/bin/time', '-l', '-o', str(usage), *map(str, command)]
    started = time.time_ns()
    with output.open('xb') as out, error.open('xb') as err:
        result = subprocess.run(invocation, stdout=out, stderr=err,
                                env={**os.environ, 'STWO_ZIG_WORKERS': '8'}, check=False)
    elapsed = time.time_ns() - started
    if result.returncode:
        raise RuntimeError(f'{label} failed ({result.returncode}): {error}')
    text = usage.read_text()
    first = re.search(r'([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys', text)
    if first is None: raise ValueError('Unsupported time -l process measurement format')
    fields = {name: float(value) for name, value in zip(('real_seconds', 'user_seconds', 'system_seconds'), first.groups())}
    for key, pattern in [('maximum_rss_bytes', r'(\d+)\s+maximum resident set size'),
                         ('peak_memory_footprint_bytes', r'(\d+)\s+peak memory footprint'),
                         ('minor_page_faults', r'(\d+)\s+page reclaims'), ('major_page_faults', r'(\d+)\s+page faults')]:
        match = re.search(pattern, text)
        if match: fields[key] = int(match[1])
    fields['runner_elapsed_ns'] = elapsed
    return load(output), fields


def run(args):
    root, tools, assets = Path(args.output).resolve(), Path(args.tools).resolve(), Path(args.assets).resolve()
    if root.exists(): raise ValueError('Exclusive benchmark output directory already exists')
    sequence = args.sequence.split(',')
    allowed = ('legacy', 'single', 'ladder', 'single-present', 'ladder-present')
    if any(name not in allowed for name in sequence) or sequence[0] != 'legacy':
        raise ValueError('Sequence must start with legacy and contain known complete-proof classes')
    if any(name.endswith('-present') for name in sequence) and not args.control_word16_tool:
        raise ValueError('Present-DIV control classes require an explicitly pinned control tool')
    names = ('rv64-csp-full', 'rv64-full-verify', 'rv64-word16-csp', 'rv64-word16-sail')
    pins = {name: sha(tools / name) for name in names}
    if args.control_word16_tool:
        pins['rv64-word16-csp-present-control'] = sha(args.control_word16_tool)
    root.mkdir(parents=True)
    receipt = {'complete': False, 'scope': 'same complete software RV64IM ELF/input; actual process timings, not same AIR',
               'host_contention': args.host_contention, 'tools': pins, 'sequence': sequence, 'workers': 8,
               'process_scope': 'whole independent process; maximum RSS distinct from Darwin peak memory footprint', 'runs': []}
    save(root / 'receipt.json', receipt)
    with (root / 'host-before.txt').open('x') as host:
        subprocess.run(['ps', '-Ao', 'pid,pcpu,rss,comm'], stdout=host, check=True)
    old_config = old_statement = old_report = old_fresh = None
    for ordinal, name in enumerate(sequence):
        directory = root / f'{ordinal:02d}-{name}'
        directory.mkdir()
        artifact = directory / 'artifacts'
        config = load(assets / ('legacy-packed-example.json' if name == 'legacy' else f'word16-{name.removesuffix("-present")}.json'))
        if name == 'legacy': config['artifact_dir'] = str(artifact)
        save(directory / 'request.json', config)
        if name == 'legacy':
            producer, measurement = timed([tools / 'rv64-csp-full', directory / 'request.json'], directory, 'prove')
            fresh, fresh_measurement = timed([tools / 'rv64-full-verify', artifact / 'statement.json', artifact / 'claims.json', artifact / 'proof.bin', 'limbs24_v2'], directory, 'fresh')
            statement = load(artifact / 'statement.json')
            check.legacy.validate_expected_statement(statement, config)
            check.security(producer, fresh, 8, False)
            check.coverage(producer, config['expected_steps'])
            if old_statement is not None and old_statement != statement: raise ValueError('Legacy repetition changed public statement')
            old_config, old_statement, old_report, old_fresh = config, statement, producer, fresh
            semantic = {'semantic_statement_sha256': check.legacy.semantic_statement_digest(statement)}
        else:
            prover = Path(args.control_word16_tool) if name.endswith('-present') else tools / 'rv64-word16-csp'
            producer, measurement = timed([prover, '--prove', directory / 'request.json', artifact], directory, 'prove')
            fresh, fresh_measurement = timed([tools / 'rv64-word16-csp', '--verify', directory / 'request.json', artifact], directory, 'fresh')
            semantic = check.checked_pair(old_statement, load(artifact / 'statement.json'), artifact / 'cells.bin', old_config,
                                          config, old_report, producer, old_fresh, fresh)
        row = {'class': name, 'ordinal': ordinal, 'proof_sha256': sha(artifact / 'proof.bin'),
               'artifacts': {p.name: sha(p) for p in artifact.iterdir() if p.is_file()},
               'producer': producer, 'fresh_receiver': fresh, 'process': measurement,
               'fresh_process': fresh_measurement, **semantic}
        receipt['runs'].append(row)
        save(root / 'receipt.json', receipt)
        print(json.dumps({'class': name, 'ordinal': ordinal, 'process': measurement, **semantic}), flush=True)
    with (root / 'host-after.txt').open('x') as host:
        subprocess.run(['ps', '-Ao', 'pid,pcpu,rss,comm'], stdout=host, check=True)
    receipt['complete'] = True
    save(root / 'receipt.json', receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tools', required=True)
    parser.add_argument('--assets', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--sequence', default='legacy,single,single,legacy,single,ladder,ladder,single')
    parser.add_argument('--control-word16-tool', help='Frozen present-DIV tool for explicit single-present/ladder-present control classes')
    parser.add_argument('--host-contention', required=True, help='Observed host activity; do not claim isolation unless coordinated')
    run(parser.parse_args())

if __name__ == '__main__': main()
