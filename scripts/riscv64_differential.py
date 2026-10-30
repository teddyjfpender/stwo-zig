#!/usr/bin/env python3
"""Deterministic RV64IM retirement comparisons against Unicorn 2.1.4.

Install the optional oracle in an isolated venv: pip install unicorn==2.1.4.
This is execution evidence, not Sail conformance or proof soundness evidence.
Temporary vectors and binaries are deleted automatically.
"""
import argparse
import hashlib
import json
import random
import subprocess
import tempfile
from pathlib import Path

import unicorn
from unicorn import Uc, UC_ARCH_RISCV, UC_MODE_RISCV64
from unicorn.riscv_const import UC_RISCV_REG_X0, UC_RISCV_REG_PC

ROOT = Path(__file__).resolve().parents[1]
if __package__:
    from .riscv64_cases import MASK, cases
else:
    from riscv64_cases import MASK, cases

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=64)
    parser.add_argument('--seed', type=int, default=0x52563634)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    if unicorn.__version__ != '2.1.4':
        raise SystemExit('Oracle must be unicorn==2.1.4')
    if not 1 <= args.samples <= 256:
        raise SystemExit('--samples must be between 1 and 256')
    rng = random.Random(args.seed)
    vectors = []
    for index, (word, a, b, is_memory) in enumerate(cases(rng, args.samples)):
        high = (1 << 32) if index % 2 else 0
        pc, data_address = high + 0x1800, high + 0x4000
        uc = Uc(UC_ARCH_RISCV, UC_MODE_RISCV64)
        uc.mem_map(pc & ~4095, 4096)
        uc.mem_map(data_address, 4096)
        uc.mem_write(pc, word.to_bytes(4, 'little'))
        data = rng.randbytes(16)
        uc.mem_write(data_address, data)
        registers = [0] + [rng.getrandbits(64) for _ in range(31)]
        registers[1] = data_address if is_memory else pc + 0x101 if a == 'jump' else a
        registers[2] = b
        for reg, value in enumerate(registers):
            uc.reg_write(UC_RISCV_REG_X0 + reg, value)
        uc.emu_start(pc, pc + 4, count=1)
        vectors.append(dict(
            instruction=word, pc=pc, registers=registers,
            expected_registers=[uc.reg_read(UC_RISCV_REG_X0 + reg) for reg in range(32)],
            expected_pc=uc.reg_read(UC_RISCV_REG_PC), memory_address=data_address,
            memory_before=list(data), memory_after=list(uc.mem_read(data_address, 16))))
    encoded = json.dumps(vectors, separators=(',', ':')).encode()
    with tempfile.TemporaryDirectory(prefix='stwo-rv64-differential-') as temporary:
        directory = Path(temporary)
        fixture = directory / 'vectors.json'
        fixture.write_bytes(encoded)
        binary = directory / 'rv64-diagnostic'
        subprocess.run(['zig', 'build-exe', 'src/frontends/riscv/rv64/diagnostic.zig',
                        '-O', 'ReleaseSafe', f'-femit-bin={binary}'], cwd=ROOT, check=True)
        result = subprocess.run([str(binary), 'vectors', str(fixture)],
                                check=True, text=True, capture_output=True)
        execution = json.loads(result.stdout)
        cached = json.loads(subprocess.check_output([str(binary), 'vectors-cached', str(fixture)], text=True))
        if cached['vectors'] != execution['vectors'] or cached['opcodes'] != execution['opcodes']:
            raise SystemExit('Cached and uncached coverage disagree')
        source = ROOT / 'src/frontends/riscv/rv64/fixtures/arithmetic.c'
        native = directory / 'native-arithmetic'
        guest = directory / 'rv64-arithmetic.elf'
        subprocess.run(['zig', 'cc', '-O2', str(source), '-o', str(native)],
                       cwd=ROOT, check=True)
        subprocess.run(['zig', 'cc', '-target', 'riscv64-freestanding',
                        '-mcpu=baseline_rv64+m-a-c-d-f', '-mabi=lp64', '-mcmodel=medium',
                        '-O2', '-nostdlib',
                        '-Wl,-e,_start', f'-Wl,-T,{source.with_suffix(".ld")}',
                        '-DRV64_GUEST', str(source), '-o', str(guest)],
                       cwd=ROOT, check=True)
        expected = int(subprocess.check_output([str(native)], text=True))
        smoke = json.loads(subprocess.check_output([str(binary), 'smoke', str(guest)], text=True))
        if smoke['stop'] != 'breakpoint' or smoke['a0'] != expected:
            raise SystemExit(f'Compiled RV64 guest disagrees with native program: {smoke}, expected {expected}')
        smoke['native_a0'] = expected
        smoke['source_sha256'] = hashlib.sha256(source.read_bytes()).hexdigest()
    report = dict(oracle='Unicorn', version=unicorn.__version__, seed=args.seed,
                  samples=args.samples, vector_sha256=hashlib.sha256(encoded).hexdigest(),
                  **execution, cached_execution=cached, sail_conformance=False, compiled_guest=smoke)
    if execution['opcodes'] != execution['expected_opcodes']:
        raise SystemExit(f'Incomplete execution opcode coverage: {execution}')
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
