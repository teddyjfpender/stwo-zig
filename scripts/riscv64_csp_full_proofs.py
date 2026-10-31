#!/usr/bin/env python3
"""Capture and prove each selected complete software CSP execution in one STARK.

Requires the independently checked RV64 execution report and its exact ELF/input
artifacts. Fresh verification runs in a separate process. Profile-only results
never count as complete proof evidence. Cases run smallest instruction count first.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.riscv64_csp_compare import ISA, BINARIES, elf_info


def digest(path):
    hasher = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=path.parent,
                                         prefix=path.name + '.', suffix='.tmp',
                                         delete=False) as output:
            temporary = Path(output.name)
            json.dump(value, output, indent=2, allow_nan=False)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def selected_rows(execution, targets=None, sizes=None, negative='all'):
    if execution.get('complete') is not True or execution.get('oracle') != 'Unicorn 2.1.4':
        raise ValueError('Requires complete independently checked Unicorn 2.1.4 execution report')
    rows = []
    identities = set()
    for row in execution['rows']:
        if targets and row['target'] not in targets:
            continue
        if sizes and row['size'] not in sizes:
            continue
        if negative != 'all' and row['negative'] != (negative == 'true'):
            continue
        if row['target'] not in BINARIES or not 0 < row['rv64_instructions'] < (1 << 22):
            raise ValueError('Unsupported target or full-execution clock budget')
        key = row['target'], row['size'], row['negative'], row['input_sha256']
        if key in identities:
            raise ValueError('Duplicate selected execution case')
        identities.add(key)
        rows.append(row)
    if not rows:
        raise ValueError('No execution cases match the requested filters')
    return sorted(rows, key=lambda row: (row['rv64_instructions'], row['target'],
                                          row['size'], row['negative']))


def run_json(command, timeout, label):
    started = time.monotonic_ns()
    try:
        result = subprocess.run([str(value) for value in command], capture_output=True,
                                timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f'{label} exceeded {timeout}s timeout') from error
    if result.returncode:
        raise RuntimeError(f'{label} exited {result.returncode}: '
                           f'{result.stderr.decode(errors="replace")[-4000:]}')
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise ValueError(f'{label} must emit a JSON object')
    return parsed, time.monotonic_ns() - started


def case_config(row, manifest, work, profile_only, memory_limit_bytes):
    candidates = (manifest['negative_fixtures'] if row['negative'] else
                  manifest['targets'][row['target']]['cases'])
    matches = [case for case in candidates
               if case.get('target', row['target']) == row['target']
               and case['input_sha256'] == row['input_sha256']]
    if len(matches) != 1:
        raise ValueError('Execution case is not uniquely bound to the manifest')
    case = matches[0]
    elf = work / 'target' / ISA[1] / 'release' / BINARIES[row['target']]
    input_path = ROOT / case['input_path']
    if digest(elf) != row['elf_sha256'][ISA[1]]:
        raise ValueError('Guest ELF differs from independently checked execution report')
    if digest(input_path) != row['input_sha256']:
        raise ValueError('Guest input differs from independently checked execution report')
    _, symbols, _ = elf_info(elf)
    names = ('input_start', 'input_end', 'halt_flag', 'output_len', 'output_data',
             'output_end', 'stack_bottom', 'stack_top')
    artifacts = work / 'full-proof-artifacts' / f"{row['target']}-{row['size']}-{int(row['negative'])}"
    return {
        'artifact_dir': str(artifacts),
        'guest': {'elf': str(elf), 'input': str(input_path),
                  'expected_digest': row['output'],
                  'symbols': {name: symbols['__' + name] for name in names}},
        'expected_steps': row['rv64_instructions'],
        'memory_limit_bytes': memory_limit_bytes,
        'profile_only': profile_only,
    }


def validate_expected_statement(statement, config):
    """Reconstruct receiver authority from pinned ELF/input, without execution.

    Dynamic final registers and final clocks remain public proof claims. The
    expected initial image, immutable ROM and terminal CSP output are independent
    of the producer's journal or response JSON.
    """
    guest = config['guest']
    entry, elf_symbols, segments = elf_info(Path(guest['elf']))
    symbols = guest['symbols']
    if any(elf_symbols.get('__' + name) != value for name, value in symbols.items()):
        raise ValueError('Statement ABI symbols differ from independently parsed ELF')
    start, end = symbols['input_start'], symbols['input_end']
    halt, length, output = symbols['halt_flag'], symbols['output_len'], symbols['output_data']
    bottom, top = symbols['stack_bottom'], symbols['stack_top']
    if (end - start != 4096 or halt != end or length != halt + 4 or output != halt + 8
            or symbols['output_end'] != bottom or bottom - output < 32
            or not 256 <= top - bottom <= 1048576 or bottom & 15 or top & 15
            or not 0 < bottom - halt <= 1048576 or halt & 3):
        raise ValueError('Invalid independent CSP initial image layout')
    input_bytes = Path(guest['input']).read_bytes()
    if len(input_bytes) > 4096:
        raise ValueError('CSP input exceeds independently mapped region')
    # (start, exclusive end, file/host initialized bytes, permissions R/W/X).
    mappings = [(address, address + size, payload, flags)
                for address, size, payload, flags in segments]
    mappings += [(start, end, input_bytes, 4), (halt, bottom, b'', 6),
                 (bottom, top, b'', 6)]
    mappings.sort(key=lambda region: region[0])
    for i, (address, last, payload, flags) in enumerate(mappings):
        if (not 0 <= address < last <= 1 << 64 or len(payload) > last - address
                or flags & ~7 or (i and mappings[i - 1][1] > address)):
            raise ValueError('Invalid independently reconstructed memory mapping')
    addresses, words = [], []
    for address, last, payload, flags in mappings:
        if not flags & 1:
            continue
        if flags & 2 or address & 3 or (last - address) & 3:
            raise ValueError('Executable image is not canonical immutable RV64 words')
        if len(words) + (last - address) // 4 > 1 << 22:
            raise ValueError('Executable exceeds program ROM budget')
        for offset in range(0, last - address, 4):
            addresses.append(address + offset)
            words.append(int.from_bytes(payload[offset:offset + 4].ljust(4, b'\0'), 'little'))
    expected_program = {'base': addresses[0] if addresses else None,
                        'words': words, 'addresses': addresses}
    if statement['program'] != expected_program:
        raise ValueError('Statement program differs from complete expected executable ROM')
    initial_registers = [0] * 32
    initial_registers[2] = top
    if (statement['steps'] != config['expected_steps'] or statement['initial_pc'] != entry
            or statement['initial_registers'] != initial_registers):
        raise ValueError('Statement initial CPU state or instruction count differs from expectation')

    def initial_byte(address):
        for first, last, payload, flags in mappings:
            if first <= address < last:
                offset = address - first
                return payload[offset] if offset < len(payload) else 0, flags
        raise ValueError('Statement RAM cell extends beyond expected memory mappings')

    final_cells = {}
    previous = -1
    for cell in statement['cells']:
        address = cell['address']
        if (type(address) is not int or address & 7 or not previous < address <= (1 << 64) - 8
                or type(cell['final']) is not int or not 0 <= cell['final'] < 1 << 64):
            raise ValueError('Statement RAM cells are not canonical ordered u64 words')
        expected_bytes, permissions = zip(*(initial_byte(address + i) for i in range(8)))
        expected_initial = int.from_bytes(bytes(expected_bytes), 'little')
        readable = all(flags & 4 for flags in permissions)
        writable = all(flags & 2 for flags in permissions)
        if (cell['initial'] != expected_initial or cell['readable'] is not readable
                or cell['writable'] is not writable or not (readable or writable)
                or (not writable and cell['final'] != expected_initial)):
            raise ValueError('Statement RAM initial value or permissions differ from expected image')
        previous = address
        final_cells[address] = cell['final']

    def final_bytes(address, size):
        result = bytearray()
        for current in range(address, address + size):
            word = final_cells.get(current & ~7)
            if word is None:
                raise ValueError('Statement must authenticate all terminal CSP output cells')
            result.append((word >> (8 * (current & 7))) & 255)
        return bytes(result)

    if (int.from_bytes(final_bytes(halt, 4), 'little') != 1
            or int.from_bytes(final_bytes(length, 4), 'little') != 32
            or final_bytes(output, 32).hex() != guest['expected_digest']):
        raise ValueError('Statement final completion or output differs from expected CSP result')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execution-report', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--target', action='append', choices=tuple(BINARIES))
    parser.add_argument('--size', action='append', type=int)
    parser.add_argument('--negative', nargs='?', const='true', default='all',
                        choices=('all', 'true', 'false'))
    parser.add_argument('--profile-only', action='store_true')
    parser.add_argument('--profile-stages', action='store_true')
    parser.add_argument('--control-policy', choices=('bytes_v1', 'limbs24_v2'), default='bytes_v1')
    parser.add_argument('--prover', type=Path, default=ROOT / 'zig-out/bin/rv64-csp-full')
    parser.add_argument('--verifier', type=Path, default=ROOT / 'zig-out/bin/rv64-full-verify')
    parser.add_argument('--timeout', type=int, default=7200)
    parser.add_argument('--verify-timeout', type=int, default=1800)
    parser.add_argument('--memory-limit-bytes', type=int, default=48 * 1024 ** 3)
    args = parser.parse_args(argv)
    if args.timeout <= 0 or args.verify_timeout <= 0 or args.memory_limit_bytes <= 0:
        parser.error('timeouts and memory limit must be positive')
    args.work_dir = args.work_dir.resolve()
    args.execution_report = args.execution_report.resolve()
    execution = json.loads(args.execution_report.read_text())
    rows = selected_rows(execution, args.target, args.size, args.negative)
    manifest_path = ROOT / 'vectors/riscv_csp/manifest-v2.json'
    manifest = json.loads(manifest_path.read_text())
    executable = args.prover.resolve()
    verifier = args.verifier.resolve()
    report = {
        'schema': 'rv64-csp-full-single-shot-proofs-v1', 'complete': False,
        'whole_guest_proof': False, 'profile_only': args.profile_only,
        'profile_stages': args.profile_stages, 'control_policy': args.control_policy,
        'all_selected_profiled': False, 'selected_cases': len(rows),
        'execution_report_sha256': digest(args.execution_report),
        'manifest_sha256': digest(manifest_path), 'driver_sha256': digest(Path(__file__)),
        'binary_sha256': digest(executable),
        'verifier_binary_sha256': None if args.profile_only else digest(verifier),
        'host': platform.platform(), 'memory_limit_bytes': args.memory_limit_bytes,
        'timeout_seconds': args.timeout, 'verify_timeout_seconds': args.verify_timeout,
        'scope': 'One guest capture and one STARK per selected complete execution; '
                 'separate fresh-process receiver verification. Profile-only never establishes a proof.',
        'cases': [],
    }
    atomic_json(args.report, report)
    for row in rows:
        case_report = {key: row[key] for key in ('target', 'size', 'negative', 'input_sha256')}
        case_report.update({'expected_instructions': row['rv64_instructions'],
                            'elf_sha256': row['elf_sha256'][ISA[1]],
                            'expected_output': row['output'], 'status': 'running',
                            'whole_guest_proof': False})
        report['cases'].append(case_report)
        atomic_json(args.report, report)
        try:
            config = case_config(row, manifest, args.work_dir, args.profile_only,
                                 args.memory_limit_bytes)
            if args.control_policy != 'bytes_v1':
                config['control_policy'] = args.control_policy
            if args.profile_stages:
                config['profile_stages'] = True
            artifacts = Path(config['artifact_dir'])
            artifacts.mkdir(parents=True, exist_ok=True)
            config_path = artifacts / 'case-config.json'
            atomic_json(config_path, config)
            case_report['config_sha256'] = digest(config_path)
            def check_identities():
                expected_files = [(executable, report['binary_sha256']),
                                  (Path(config['guest']['elf']), row['elf_sha256'][ISA[1]]),
                                  (Path(config['guest']['input']), row['input_sha256'])]
                if not args.profile_only:
                    expected_files.append((verifier, report['verifier_binary_sha256']))
                for path, expected in expected_files:
                    if digest(path) != expected:
                        raise ValueError(f'Input or binary changed during benchmark: {path}')
            check_identities()
            print(f"{'Profile' if args.profile_only else 'Prove'} complete "
                  f"{row['target']}/{row['size']} negative={row['negative']} "
                  f"instructions={row['rv64_instructions']}", flush=True)
            measured, elapsed = run_json([executable, config_path], args.timeout, 'Full prover')
            if args.control_policy != 'bytes_v1' and measured.get('control_policy') != args.control_policy:
                raise ValueError('Prover did not bind the requested control policy')
            case_report['prover'] = measured
            case_report['prover_process_ns'] = elapsed
            check_identities()
            if args.profile_stages and not args.profile_only:
                stages = measured.get('stage_profile')
                if not isinstance(stages, dict) or not stages.get('stages'):
                    raise ValueError('Requested stage profile is missing')
            if measured.get('instructions') != row['rv64_instructions']:
                raise ValueError('Incomplete full execution capture')
            if args.profile_only:
                if measured.get('profile_only') is not True or measured.get('whole_guest_proof') is not False:
                    raise ValueError('Profile response must explicitly exclude proof completion')
                case_report['status'] = 'profiled'
            else:
                if measured.get('whole_guest_proof') is not True or measured.get('verified') is not True:
                    raise ValueError('Full prover did not establish complete verified execution')
                paths = [artifacts / name for name in ('statement.json', 'claims.json', 'proof.bin')]
                validate_expected_statement(json.loads(paths[0].read_text()), config)
                case_report['independent_statement_binding'] = True
                case_report['artifact_sha256'] = {path.name: digest(path) for path in paths}
                trusted_control = [] if args.control_policy == 'bytes_v1' else [args.control_policy]
                fresh, verify_elapsed = run_json([verifier, *paths, *trusted_control], args.verify_timeout, 'Fresh verifier')
                if args.control_policy != 'bytes_v1' and fresh.get('control_policy') != args.control_policy:
                    raise ValueError('Fresh verifier did not bind the requested control policy')
                if fresh.get('verified') is not True or fresh.get('whole_guest_proof') is not True:
                    raise ValueError('Fresh verifier did not accept a whole guest proof')
                check_identities()
                if any(digest(path) != case_report['artifact_sha256'][path.name] for path in paths):
                    raise ValueError('Proof artifacts changed during fresh verification')
                case_report['fresh_process'] = fresh
                case_report['verify_process_ns'] = verify_elapsed
                case_report['status'] = 'verified_full_execution'
                case_report['whole_guest_proof'] = True
        except Exception as error:
            case_report['status'] = 'failed'
            case_report['error'] = f'{type(error).__name__}: {error}'
            atomic_json(args.report, report)
            raise
        atomic_json(args.report, report)
    if args.profile_only:
        report['all_selected_profiled'] = all(case['status'] == 'profiled' for case in report['cases'])
    else:
        report['complete'] = all(case['status'] == 'verified_full_execution' for case in report['cases'])
        report['whole_guest_proof'] = report['complete']
    atomic_json(args.report, report)
    return report


if __name__ == '__main__':
    main()
