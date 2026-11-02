#!/usr/bin/env python3
"""Build one continuous RV64IM oracle workload from the pinned Sail model.

All setup instructions and target cases retire in ONE architectural execution.
The retained RVFI file is independently checked during compact native capture;
the new Word16 proof then covers the entire execution, not tiny proof windows.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import itertools
import random
import socket
import struct
import subprocess
import time
from pathlib import Path

import riscv64_cases as cases
from riscv64_sail_qualify import REVISION, constant, decode, packet, receive

ROOT = Path(__file__).resolve().parents[1]
ENTRY = 0x80000000
DATA = 0x100004000


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def additional_cases():
    # Ordinary instructions supplied to the independent model. Their results
    # still come exclusively from Sail, not from a Python ISA implementation.
    for immediate in (-2048, -1, 7, 2047):
        yield ((immediate & 4095) << 20) | (1 << 15) | (3 << 7) | 0x67, 'jump_far', 0, False
    for f3, width in ((0, 1), (1, 2), (2, 4), (3, 8), (4, 1), (5, 2), (6, 4)):
        for offset in range(0, 8, width):
            yield cases.immediate(3, f3, offset), None, 0, True
    for f3, width in enumerate((1, 2, 4, 8)):
        for offset in range(0, 8, width):
            word = 0x23 | (f3 << 12) | (1 << 15) | (2 << 20) | (offset << 7)
            yield word, None, 0xFEDCBA9876543210, True


def elf(words):
    high = max(words) + 8
    text = bytearray(struct.pack('<I', 0x13) * ((high - ENTRY) // 4))
    for pc, word in words.items():
        struct.pack_into('<I', text, pc - ENTRY, word)
    out = bytearray(256) + text
    out[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH', out, 16, 2, 243, 1, ENTRY, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', out, 64, 1, 5, 256, ENTRY, ENTRY, len(text), len(text), 4)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=8, choices=range(1, 65))
    args = parser.parse_args()
    source = args.source.resolve()
    revision = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip()
    if revision != REVISION or subprocess.check_output(['git', '-C', source, 'status', '--porcelain']):
        raise ValueError('Expected the clean pinned Sail checkout')
    binary = source / 'build/c_emulator/sail_riscv_sim'
    info = subprocess.check_output([binary, '--build-info'], text=True)
    if REVISION[:7] not in info or 'Sail 0.20.2 ' not in info or 'dirty' in info:
        raise ValueError('Unpinned Sail executable')
    command = [str(binary)]
    overrides = [ROOT / 'conformance/rv64im-sail-override.json', ROOT / 'conformance/riscv/sail-rv32im-tagged-options.json']
    for path in overrides:
        command += ['--config-override', str(path)]
    if subprocess.check_output(command + ['--print-isa-string'], text=True).strip() != 'rv64im':
        raise ValueError('Sail ISA must be exactly rv64im')
    args.output.mkdir(parents=True, exist_ok=False)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    rng = random.Random(0x525636345341494c)
    words, registers = {}, [0] * 32
    memory = bytearray(16)
    pc, steps, targets = ENTRY, 0, 0
    started = time.monotonic_ns()
    with (args.output / 'sail.log').open('xb') as log, (args.output / 'retirements.rvfi').open('xb') as trace:
        with subprocess.Popen(command + ['--rvfi-dii', str(port)], stdout=log, stderr=log) as process:
            connection = None
            try:
                deadline = time.monotonic() + 20
                while connection is None and time.monotonic() < deadline:
                    try:
                        connection = socket.create_connection(('127.0.0.1', port), timeout=1)
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError('Sail exited before connection')
                        time.sleep(.01)
                if connection is None:
                    raise TimeoutError('Sail startup')
                connection.settimeout(30)
                workload = itertools.chain(cases.cases(rng, args.samples), additional_cases())
                for target, lhs, rhs, is_memory in workload:
                    data = rng.randbytes(16)
                    setup = constant(4, DATA) + constant(5, int.from_bytes(data[:8], 'little')) + [0x00523023]
                    setup += constant(5, int.from_bytes(data[8:], 'little')) + [0x00523423, 0x00000213, 0x00000293]
                    target_pc = pc + 4 * (len(setup) + 30)
                    lhs = DATA if is_memory else target_pc + 0x101 if lhs == 'jump' else target_pc + 0x2001 if lhs == 'jump_far' else lhs
                    stream = setup + constant(1, lhs) + constant(2, rhs) + [target]
                    connection.sendall(b''.join(packet(word) for word in stream))
                    raw = receive(connection, 88 * len(stream))
                    for index, word in enumerate(stream):
                        record_bytes = raw[88 * index:88 * (index + 1)]
                        row = decode(record_bytes)
                        if row['trap'] or row['halt'] or row['pc'] != pc or row['instruction'] != word:
                            raise ValueError(f'Nonretiring/discontinuous Sail execution at step {steps}: {row}')
                        if pc in words and words[pc] != word:
                            raise ValueError('Different instructions assigned to one immutable PC')
                        words[pc] = word
                        if row['rd']:
                            registers[row['rd']] = row['rd_value']
                        if row['write_mask']:
                            offset = row['address'] - DATA
                            for byte in range(8):
                                if row['write_mask'] >> byte & 1:
                                    if not 0 <= offset + byte < len(memory):
                                        raise ValueError('Oracle wrote outside admitted data image')
                                    memory[offset + byte] = row['write'] >> (8 * byte) & 255
                        pc = row['next_pc']
                        trace.write(record_bytes)
                        steps += 1
                    targets += 1
                    if targets % 2000 == 0:
                        print(f'{targets} continuous target cases, {steps} retired instructions', flush=True)
                connection.sendall(packet(0, 0))
                if not decode(receive(connection, 88))['halt']:
                    raise ValueError('Missing final Sail end-of-trace acknowledgement')
                connection.close()
                connection = None
                process.wait(timeout=20)
                if process.returncode:
                    raise RuntimeError('Sail process failed')
            finally:
                if connection is not None:
                    connection.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
    if not 0 < steps < 1 << 22:
        raise ValueError('Workload exceeds one local CPU clock epoch')
    (args.output / 'workload.elf').write_bytes(elf(words))
    oracle = {'schema': 1, 'steps': steps, 'initial_pc': ENTRY, 'final_pc': pc,
              'final_registers': registers, 'data_address': DATA, 'data_initial': [0] * 16,
              'data_final': list(memory), 'target_cases': targets, 'samples': args.samples,
              'sail_revision': REVISION, 'sail_build_info': info, 'sail_binary_sha256': sha(binary),
              'configuration_sha256': {str(path.relative_to(ROOT)): sha(path) for path in overrides},
              'elf_sha256': sha(args.output / 'workload.elf'), 'rvfi_sha256': sha(args.output / 'retirements.rvfi'),
              'oracle_generation_ns': time.monotonic_ns() - started,
              'scope': 'one continuous ordinary-instruction RV64IM execution; EBREAK/ECALL nonretiring excluded'}
    write_json(args.output / 'oracle.json', oracle)
    write_json(args.output / 'config.json', {'elf': str((args.output / 'workload.elf').resolve()),
               'elf_sha256': oracle['elf_sha256'], 'oracle': str((args.output / 'oracle.json').resolve()),
               'oracle_sha256': sha(args.output / 'oracle.json'),
               'rvfi': str((args.output / 'retirements.rvfi').resolve()), 'workers': 8})
    print(json.dumps({'target_cases': targets, 'steps': steps, 'oracle_sha256': sha(args.output / 'oracle.json')}))


if __name__ == '__main__':
    main()
