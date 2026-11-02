#!/usr/bin/env python3
"""Fresh-process mutations of actual closed Word16 CSP/Sail proof artifacts.

The unchanged positive control must pass first. Each attack starts from a fresh
copy and must fail at the receiver; claims, public RAM and proof bytes are never
replaced by model-only assertions.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mutate_statement(directory, change):
    path = directory / 'statement.json'
    value = json.loads(path.read_text())
    change(value)
    path.write_text(json.dumps(value))


def mutate_cell(directory, address, field_offset, byte_mask=1, terminal=True):
    path = directory / 'cells.bin'
    raw = bytearray(path.read_bytes())
    count, terminal_count = struct.unpack_from('<II', raw, 8)
    if count != terminal_count:
        raise ValueError('Invalid positive sidecar')
    start = 16 + (23 * count if terminal else 0)
    for i in range(count):
        offset = start + 23 * i
        if struct.unpack_from('<Q', raw, offset)[0] == address:
            raw[offset + field_offset] ^= byte_mask
            path.write_bytes(raw)
            return
    raise ValueError(f'Attack address {address:#x} is not present')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--proof-directory', type=Path, required=True)
    parser.add_argument('--kind', choices=('csp', 'sail'), required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    statement = json.loads((args.proof_directory / 'statement.json').read_text())
    cells = (args.proof_directory / 'cells.bin').read_bytes()
    first_address = struct.unpack_from('<Q', cells, 16)[0]
    if args.kind == 'csp':
        output = config['guest']['symbols']['output_data']
    else:
        output = json.loads(Path(config['oracle']).read_text())['data_address']

    def run(directory):
        return subprocess.run([str(args.tool), '--verify', str(args.config), str(directory)], capture_output=True, timeout=120)

    positive = run(args.proof_directory)
    if positive.returncode or not json.loads(positive.stdout).get('physical_proof_verified'):
        raise ValueError(f'Unchanged positive control failed: {positive.stderr.decode()}')

    def cpu_field(name, transform):
        return lambda d: mutate_statement(d, lambda s: s['cpu'].__setitem__(name, transform(s['cpu'][name])))

    def balanced_claims(directory):
        def change(s):
            p = 2147483647
            for name, delta in [('cpu', 1), ('rom', -1)]:
                limb = s['claims'][name]['c0']['a']
                limb['v'] = (limb['v'] + delta) % p
        mutate_statement(directory, change)

    def corrupt_proof(directory):
        path = directory / 'proof.bin'
        raw = bytearray(path.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)

    def truncate_cells(directory):
        path = directory / 'cells.bin'
        path.write_bytes(path.read_bytes()[:-1])

    def final_registers(values):
        values[31] ^= 1
        return values

    attacks = [('false-final-pc', cpu_field('final_pc', lambda v: v + 4)),
               ('false-final-register', cpu_field('final_registers', final_registers)),
               ('incomplete-step-count', cpu_field('steps', lambda v: v - 1)),
               ('balanced-physical-claims', balanced_claims),
               ('foreign-initial-value', lambda d: mutate_cell(d, first_address, 8, terminal=False)),
               ('foreign-initial-rights', lambda d: mutate_cell(d, first_address, 22, terminal=False)),
               ('wrong-authenticated-output', lambda d: mutate_cell(d, output & ~7, 8 + (output & 7))),
               ('invalid-local-epoch', lambda d: mutate_statement(d, lambda s: s.__setitem__('epoch', 2))),
               ('truncated-public-cells', truncate_cells), ('corrupted-proof', corrupt_proof)]
    if 'ls_tail_log' in statement['geometry']:
        attacks.append(('invalid-LS-tail-capacity', lambda d: mutate_statement(d, lambda s: s['geometry'].__setitem__('ls_tail_log', 5))))
        if statement['geometry']['ls_tail_log'] is None:
            def absent_tail(directory):
                def change(s):
                    s['claims']['ls_tail']['ram']['c0']['a']['v'] = 1
                    limb = s['claims']['rom']['c0']['a']
                    limb['v'] = (limb['v'] - 1) % 2147483647
                mutate_statement(directory, change)
            attacks.append(('nonzero-absent-LS-tail-balanced-claim', absent_tail))
    expected_guard_errors = {}
    for family in ('alu', 'binary', 'shift'):
        tail = family + '_tail'
        if tail in statement['claims'] and statement['geometry'].get(tail + '_log') is None:
            name = 'nonzero-absent-' + family.upper() + '-tail-balanced-claim'
            def absent_pure_tail(directory, tail=tail):
                def change(s):
                    s['claims'][tail]['function']['c0']['a']['v'] = 1
                    limb = s['claims']['cpu']['c0']['a']
                    limb['v'] = (limb['v'] - 1) % 2147483647
                mutate_statement(directory, change)
            attacks.append((name, absent_pure_tail))
            expected_guard_errors[name] = 'error: NonzeroOmitted' + family.title() + 'TailClaim'
    if args.kind == 'csp':
        halt = config['guest']['symbols']['halt_flag']
        length = config['guest']['symbols']['output_len']
        attacks += [('false-halt', lambda d: mutate_cell(d, halt & ~7, 8 + (halt & 7))),
                    ('false-output-length', lambda d: mutate_cell(d, length & ~7, 8 + (length & 7)))]
    results = []
    with tempfile.TemporaryDirectory(prefix='rv64-word16-receiver-attacks-') as temporary:
        for name, mutate in attacks:
            target = Path(temporary) / name
            target.mkdir()
            for filename in ('statement.json', 'cells.bin', 'proof.bin'):
                shutil.copyfile(args.proof_directory / filename, target / filename)
            mutate(target)
            result = run(target)
            if result.returncode == 0:
                raise ValueError(f'Attack accepted: {name}')
            receiver_error = result.stderr.decode(errors='replace').splitlines()[0]
            if name in expected_guard_errors and receiver_error != expected_guard_errors[name]:
                raise ValueError(f'Wrong rejection authority for {name}: {receiver_error}')
            results.append({'attack': name, 'rejected': True, 'exit_code': result.returncode,
                            'receiver_error': receiver_error})
    report = {'schema': 'rv64-word16-actual-receiver-mutations-v1', 'kind': args.kind,
              'positive_fresh_receiver': True, 'steps': statement['cpu']['steps'],
              'tool_sha256': sha(args.tool), 'config_sha256': sha(args.config),
              'proof_sha256': sha(args.proof_directory / 'proof.bin'), 'attacks': results}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'positive_fresh_receiver': True, 'rejected_attacks': len(results)}))


if __name__ == '__main__':
    main()
