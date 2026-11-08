#!/usr/bin/env python3
"""Build and execute the same pinned software CSP workloads on RV32IM/RV64IM.

No proof is generated. RV32 public-value derivation includes witnesses and tree
construction; RV64 timing is execution only. Instruction counts are comparable,
these two frontend wall times are not. Requires Zig 0.15.2, the pinned Rust
nightly with rust-src, and optional Unicorn 2.1.4 for independent retirement counts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import struct
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.riscv_csp_benchmark_lib.contract import validate_manifest
from scripts.riscv_csp_benchmark_lib.public_output import reconstruct_public_output

TOOLCHAIN = 'nightly-2026-03-04'
ISA = ('riscv32im-unknown-none-elf', 'riscv64im-unknown-none-elf')
BINARIES = {'sha256': 'stark-v-bench-sha256', 'keccak': 'stark-v-bench-keccak',
            'poseidon2_m31': 'poseidon2_m31', 'ecdsa_secp256k1': 'ecdsa_secp256k1'}
FLAGS = '-C panic=abort -C opt-level=3 -C lto=fat -C embed-bitcode=yes -C codegen-units=1 -C link-arg=-Tlinker.ld'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, timeout=600,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


def elf_info(path):
    data = path.read_bytes()
    if len(data) < 52 or data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] != 1:
        raise ValueError('Expected little-endian ELF')
    wide = data[4] == 2
    if len(data) < (64 if wide else 52) or struct.unpack_from('<HHI', data, 16) != (2, 243, 1):
        raise ValueError('Expected a static RISC-V executable')
    entry = struct.unpack_from('<Q' if wide else '<I', data, 24)[0]
    if wide:
        phoff, shoff = struct.unpack_from('<QQ', data, 32)
        phsize, phcount, shsize, shcount = struct.unpack_from('<HHHH', data, 54)
    else:
        phoff, shoff = struct.unpack_from('<II', data, 28)
        phsize, phcount, shsize, shcount = struct.unpack_from('<HHHH', data, 42)
    if phsize < (56 if wide else 32) or shsize < (64 if wide else 40) or not phcount or not shcount:
        raise ValueError('Benchmark ELF requires program headers and a symbol table')
    if phoff + phcount * phsize > len(data) or shoff + shcount * shsize > len(data):
        raise ValueError('ELF header table is truncated')
    sections = [struct.unpack_from('<IIQQQQIIQQ' if wide else '<IIIIIIIIII',
                                   data, shoff + i * shsize) for i in range(shcount)]
    symbols = {}
    for section in sections:
        if section[1] != 2:
            continue
        if section[6] >= len(sections) or section[9] != (24 if wide else 16) or section[5] % section[9]:
            raise ValueError('Invalid ELF symbol table')
        strings = sections[section[6]]
        if section[4] + section[5] > len(data) or strings[4] + strings[5] > len(data):
            raise ValueError('ELF symbol/string table is truncated')
        names = data[strings[4]:strings[4] + strings[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            if wide:
                name, _, _, _, value, _ = struct.unpack_from('<IBBHQQ', data, offset)
            else:
                name, value, _, _, _, _ = struct.unpack_from('<IIIBBH', data, offset)
            end = names.index(b'\0', name)
            symbols[names[name:end].decode()] = value
    segments = []
    for index in range(phcount):
        offset = phoff + index * phsize
        if wide:
            kind, flags, file_offset, address, _, file_size, size, _ = struct.unpack_from('<IIQQQQQQ', data, offset)
        else:
            kind, file_offset, address, _, file_size, size, flags, _ = struct.unpack_from('<IIIIIIII', data, offset)
        if kind == 1 and size:
            if file_size > size or file_offset + file_size > len(data):
                raise ValueError('ELF segment is truncated')
            segments.append((address, size, data[file_offset:file_offset + file_size], flags))
    return entry, symbols, segments


def prepare(work, manifest):
    sources = work / 'sources'
    sources.mkdir(parents=True, exist_ok=True)
    paths, pins = {}, {}
    for target, metadata in manifest['targets'].items():
        destination = sources / target
        destination.mkdir(exist_ok=True)
        for pin in metadata['guest']['source_files']:
            relative = pin['path']
            if metadata['guest']['source_repository'] == 'csp_upstream':
                cached = work / 'upstream' / relative
                if not cached.exists() or digest(cached) != pin['sha256']:
                    url = f"https://raw.githubusercontent.com/privacy-ethereum/csp-benchmarks/{manifest['upstream']['commit']}/{relative}"
                    data = urllib.request.urlopen(url, timeout=30).read()
                    if hashlib.sha256(data).hexdigest() != pin['sha256']:
                        raise ValueError(f'Upstream source digest mismatch: {relative}')
                    cached.parent.mkdir(parents=True, exist_ok=True)
                    cached.write_bytes(data)
                source = cached
                suffix = Path(relative).relative_to(f'stark-v/guest/{target}')
            else:
                source = ROOT / relative
                suffix = Path(relative).relative_to(f'vectors/riscv_guests/{target}')
            if digest(source) != pin['sha256']:
                raise ValueError(f'Source digest mismatch: {relative}')
            pins[relative] = pin['sha256']
            if suffix.parts[0] == '.cargo' or suffix.name == 'rust-toolchain.toml':
                continue
            output = destination / suffix
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, output)
        if target in ('sha256', 'keccak'):
            source = destination / 'src/main.rs'
            text = source.read_text()
            if text.count('guest_bin::guest_main_raw!') != 1:
                raise ValueError('Pinned raw guest entry point changed')
            source.write_text(text.replace('guest_bin::guest_main_raw!', 'include!("runtime.rs");\n\nguest_main_raw!'))
            shutil.copy2(ROOT / 'src/frontends/riscv/rv64/fixtures/csp_runtime.rs', destination / 'src/runtime.rs')
            cargo = destination / 'Cargo.toml'
            cargo.write_text('\n'.join(line for line in cargo.read_text().splitlines()
                                       if not line.startswith(('guest-bin =', 'guest-lib ='))) + '\n')
            shutil.copy2(ROOT / 'vectors/riscv_guests/ecdsa_secp256k1/linker.ld', destination / 'linker.ld')
        paths[target] = destination
    env = os.environ.copy()
    env['CARGO_TARGET_DIR'] = str(work / 'target')
    env['RUSTFLAGS'] = FLAGS
    for isa in ISA:
        for target, directory in paths.items():
            print(f'Build {target} / {isa}', file=sys.stderr, flush=True)
            try:
                command(['cargo', f'+{TOOLCHAIN}', 'build', '--target', isa, '-Z',
                         'build-std=core,compiler_builtins', '--release', '--offline'], cwd=directory, env=env)
            except subprocess.CalledProcessError as error:
                raise RuntimeError(error.stderr.decode()[-4000:]) from error
    built = {target: {isa: work / 'target' / isa / 'release' / binary for isa in ISA}
             for target, binary in BINARIES.items()}
    prepared = {str(p.relative_to(sources)): digest(p) for p in sorted(sources.rglob('*')) if p.is_file()}
    return built, {'original_pins': pins, 'adapted_source_sha256': prepared, 'rustflags': FLAGS}


def oracle(path, input_bytes):
    import unicorn
    from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV32, UC_MODE_RISCV64, UC_HOOK_CODE, UC_HOOK_MEM_WRITE
    if unicorn.__version__ != '2.1.4':
        raise ValueError('Unicorn oracle must be 2.1.4')
    entry, symbols, segments = elf_info(path)
    uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64 if path.read_bytes()[4] == 2 else UC_MODE_RISCV32)
    pages = set()
    ranges = [(address, size) for address, size, _, _ in segments]
    ranges += [(symbols['__input_start'], symbols['__stack_top'] - symbols['__input_start'])]
    for address, size in ranges:
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page not in pages:
                uc.mem_map(page, 4096)
                pages.add(page)
    for address, _, data, _ in segments:
        if data:
            uc.mem_write(address, data)
    uc.mem_write(symbols['__input_start'], input_bytes)
    count = 0
    completed = False

    def retirement(engine, address, size, user):
        nonlocal count
        count += 1
        if count > 10000000:
            raise ValueError('Oracle retirement budget exhausted')

    def halt(engine, access, address, size, value, user):
        nonlocal completed
        if address != symbols['__halt_flag'] or size != 4 or value != 1:
            raise ValueError('Unexpected completion store')
        completed = True
        engine.emu_stop()

    uc.hook_add(UC_HOOK_CODE, retirement)
    uc.hook_add(UC_HOOK_MEM_WRITE, halt, begin=symbols['__halt_flag'], end=symbols['__halt_flag'] + 3)
    uc.emu_start(entry, 0)
    if not completed or int.from_bytes(uc.mem_read(symbols['__output_len'], 4), 'little') != 32:
        raise ValueError('Oracle did not complete with 32 output bytes')
    return {'instructions': count, 'output': bytes(uc.mem_read(symbols['__output_data'], 32)).hex()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=7, choices=range(1, 32))
    parser.add_argument('--oracle', action='store_true')
    args = parser.parse_args()
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((ROOT / 'vectors/riscv_csp/manifest-v2.json').read_text())
    validate_manifest(ROOT / 'vectors/riscv_csp/manifest-v2.json')
    binaries, source = prepare(work, manifest)
    command(['zig', 'build', 'riscv-trace-dump', '-Doptimize=ReleaseFast', '-Dcpu=native'], cwd=ROOT)
    cli = work / 'rv64-csp-runner'
    command(['zig', 'build-exe', 'src/frontends/riscv/rv64/csp_benchmark.zig', '-O',
             'ReleaseFast', f'-femit-bin={cli}'], cwd=ROOT)
    rows = []
    cases = [(target, case, False) for target, metadata in manifest['targets'].items() for case in metadata['cases']]
    cases += [(case['target'], {**case, 'input_size': 32}, True) for case in manifest['negative_fixtures']]
    report = {'schema': 'rv32-rv64-csp-execution-v1', 'complete': False, 'proof_supported': False,
              'host': {'platform': platform.platform(), 'machine': platform.machine()},
              'toolchain': command(['rustc', f'+{TOOLCHAIN}', '-vV']).stdout.decode(),
              'source': source, 'samples': args.samples, 'rows': rows,
              'timing_scope': {'rv32_wall_ns': 'process + RV32 execution, witnesses, committed tree derivation and public-value encoding',
                               'rv64_execution_ns': 'guest retirement + completion detection only; no retained trace, witness, tree or proof'},
              'oracle': 'Unicorn 2.1.4' if args.oracle else None,
              'manifest_sha256': digest(ROOT / 'vectors/riscv_csp/manifest-v2.json'),
              'implementation_source_sha256': {str(p.relative_to(ROOT)): digest(p) for p in sorted((ROOT / 'src/frontends/riscv/rv64').glob('*.zig'))},
              'runner_sha256': {'rv32': digest(ROOT / 'zig-out/bin/riscv-trace-dump'), 'rv64': digest(cli)}}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    for target, case, negative in cases:
        print(f'Execute {target}/{case["input_size"]}' + (' invalid signature' if negative else ''), file=sys.stderr, flush=True)
        input_path = ROOT / case['input_path']
        if digest(input_path) != case['input_sha256']:
            raise ValueError('Input digest mismatch')
        start = time.perf_counter_ns()
        raw = command([ROOT / 'zig-out/bin/riscv-trace-dump', '--public-values', binaries[target][ISA[0]],
                       '--input', input_path, '--max-steps', '10000000'], cwd=ROOT).stdout
        rv32_wall = time.perf_counter_ns() - start
        public = json.loads(raw)
        if reconstruct_public_output(public).hex() != case['expected_digest']:
            raise ValueError('RV32 output mismatch')
        _, symbols, _ = elf_info(binaries[target][ISA[1]])
        names = ('input_start', 'input_end', 'halt_flag', 'output_len', 'output_data', 'output_end', 'stack_bottom', 'stack_top')
        config = {'elf': str(binaries[target][ISA[1]]), 'input': str(input_path),
                  'expected_digest': case['expected_digest'], 'samples': args.samples,
                  'symbols': {name: symbols['__' + name] for name in names}}
        config_path = work / 'case.json'
        config_path.write_text(json.dumps(config))
        execution = json.loads(command([cli, config_path], cwd=ROOT).stdout)
        counts = {sample['instructions'] for sample in execution['samples']}
        if len(counts) != 1:
            raise ValueError('Nondeterministic instruction count')
        rv32_count = public['public_data']['clock']
        rv64_count = counts.pop()
        row = {'target': target, 'size': case['input_size'], 'negative': negative,
               'input_sha256': digest(input_path), 'output': case['expected_digest'],
               'rv32_instructions': rv32_count, 'rv64_instructions': rv64_count,
               'committed_rv32_instructions': case['expected_cycles'],
               'instruction_ratio_rv32_over_rv64': rv32_count / rv64_count,
               'rv32_wall_ns': rv32_wall, 'rv32_public_values_sha256': hashlib.sha256(raw).hexdigest(),
               'rv64_execution_ns_median': statistics.median(s['execution_ns'] for s in execution['samples']),
               'rv64': execution,
               'elf_sha256': {isa: digest(path) for isa, path in binaries[target].items()}}
        if args.oracle:
            row['oracle'] = {isa: oracle(path, input_path.read_bytes()) for isa, path in binaries[target].items()}
            for isa, expected_count in zip(ISA, (rv32_count, rv64_count)):
                observed = row['oracle'][isa]
                if observed['instructions'] != expected_count or observed['output'] != case['expected_digest']:
                    raise ValueError(f'Oracle disagrees on {target}/{isa}: {observed}, expected {expected_count}')
        rows.append(row)
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    report['complete'] = True
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'completed_cases': len(rows), 'report': str(args.report), 'proof_supported': False}))


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stderr.decode(errors='replace')[-4000:], file=sys.stderr)
        raise
