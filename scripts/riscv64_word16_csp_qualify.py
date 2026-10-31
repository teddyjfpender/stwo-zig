#!/usr/bin/env python3
"""Whole software CSP requests on the new joined Word16 proof, then fresh verify.

Independent Unicorn evidence pins the exact ELF, input, step count and output.
Only the existing ABI/symbol extraction helper is reused from the old runner;
no legacy proof tool, windowed proof or Ethereum contract is invoked.
"""
from __future__ import annotations
import argparse
import json
import subprocess
import time
from pathlib import Path

from riscv64_csp_full_proofs import ROOT, atomic_json, case_config, digest, selected_rows
from riscv64_csp_compare import ISA


def run(command, timeout, log):
    start = time.monotonic_ns()
    result = subprocess.run([str(arg) for arg in command], capture_output=True, timeout=timeout)
    log.with_suffix('.stdout').write_bytes(result.stdout)
    log.with_suffix('.stderr').write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{command[1]} failed: {result.stderr.decode(errors="replace")[-2000:]}')
    return json.loads(result.stdout), time.monotonic_ns() - start


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execution-report', type=Path, required=True)
    parser.add_argument('--guest-build', type=Path, required=True)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--target', action='append')
    parser.add_argument('--workers', type=int, default=8, choices=range(1, 65))
    parser.add_argument('--timeout', type=int, default=1800)
    parser.add_argument('--ls-ladder', action='store_true')
    args = parser.parse_args()
    if args.timeout <= 0:
        raise ValueError('timeout must be positive')
    execution = json.loads(args.execution_report.read_text())
    manifest_path = ROOT / 'vectors/riscv_csp/manifest-v2.json'
    manifest = json.loads(manifest_path.read_text())
    if execution.get('manifest_sha256') != digest(manifest_path):
        raise ValueError('CSP manifest differs from the independently checked execution report')
    rows = selected_rows(execution, targets=args.target)
    args.output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'rv64-word16-whole-CSP-qualification-v1', 'complete': False,
              'new_word16_joined_air': True, 'legacy_proofs_used': False,
              'execution_oracle': execution['oracle'],
              'execution_report_sha256': digest(args.execution_report),
              'manifest_sha256': digest(manifest_path), 'tool_sha256': digest(args.tool),
              'driver_sha256': digest(Path(__file__)), 'workers': args.workers, 'ls_ladder': args.ls_ladder,
              'timing_scope': 'functional complete processes; no controlled speedup comparison', 'cases': []}
    atomic_json(args.output / 'qualification.json', report)
    for row in rows:
        independent = row['oracle'][ISA[1]]
        if independent['instructions'] != row['rv64_instructions'] or independent['output'] != row['output']:
            raise ValueError('Native count/output differs from the independent execution oracle')
        old = case_config(row, manifest, args.guest_build, False, 48 * 1024 ** 3)
        guest = old['guest']
        guest['max_steps'] = old['expected_steps']
        config = {'guest': guest, 'elf_sha256': digest(Path(guest['elf'])),
                  'input_sha256': row['input_sha256'], 'expected_steps': old['expected_steps'],
                  'workers': args.workers, 'ls_ladder': args.ls_ladder}
        name = f"{row['target']}-{row['size']}-{int(row['negative'])}"
        config_path = args.output / (name + '.json')
        atomic_json(config_path, config)
        directory = args.output / name
        produced, producer_ns = run([args.tool, '--prove', config_path, directory], args.timeout, args.output / (name + '-produce.log'))
        verified, receiver_ns = run([args.tool, '--verify', config_path, directory], args.timeout, args.output / (name + '-verify.log'))
        if not produced.get('physical_proof_verified') or not verified.get('physical_proof_verified') or not produced.get('expected_output_bound_to_terminal_ram'):
            raise ValueError('Missing physical proof or CSP terminal authority')
        if produced['steps'] != row['rv64_instructions'] or verified['steps'] != row['rv64_instructions']:
            raise ValueError('Execution count differs from independent oracle')
        proof = directory / 'proof.bin'
        if produced['proof_bytes'] != proof.stat().st_size or verified['proof_bytes'] != proof.stat().st_size:
            raise ValueError('Reported proof length mismatch')
        report['cases'].append({'target': row['target'], 'size': row['size'], 'negative': row['negative'],
                               'instructions': row['rv64_instructions'], 'expected_output': row['output'],
                               'input_sha256': row['input_sha256'], 'elf_sha256': config['elf_sha256'],
                               'config_sha256': digest(config_path), 'proof_sha256': digest(proof),
                               'proof_bytes': proof.stat().st_size, 'fresh_receiver_verified': True,
                               'producer_process_ns': producer_ns, 'receiver_process_ns': receiver_ns,
                               'actual_geometry': produced['geometry'], 'source_cells': produced['source_cells']})
        atomic_json(args.output / 'qualification.json', report)
        print(f'{name}: {row["rv64_instructions"]} instructions; complete proof and fresh receiver PASS', flush=True)
    report['complete'] = True
    atomic_json(args.output / 'qualification.json', report)


if __name__ == '__main__':
    main()
