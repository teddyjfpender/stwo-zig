#!/usr/bin/env python3
"""Pinned RV64IM Sail retirement comparison through an unmodified RVFI-DII session.

One process and one TCP connection serve the batch. Register/memory setup uses
ordinary instructions. Evidence covers retirement effects, not a formal proof.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import random
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path
if __package__:
    from . import riscv64_cases as vectors
else:
    import riscv64_cases as vectors

ROOT = Path(__file__).resolve().parents[1]
REVISION = '8c7f2da58de0ba5e4457e4de07e0046f0439f35f'
MASK = (1 << 64) - 1

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def constant(register, value):
    # Fixed 15-instruction construction, including negative full-width values.
    out = [0x13 | register << 7 | ((value >> 56) & 255) << 20]
    for shift in range(48, -1, -8):
        out += [0x13 | register << 7 | 1 << 12 | register << 15 | 8 << 20,
                0x13 | register << 7 | 6 << 12 | register << 15 | ((value >> shift) & 255) << 20]
    return out

def receive(connection, count):
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise RuntimeError('Sail closed the RVFI session')
        data.extend(chunk)
    return bytes(data)

def packet(word, command=1):
    return struct.pack('<IHBB', word, 1, command, 0)

def decode(packet_bytes):
    values = struct.unpack('<11Q', packet_bytes)
    return {'pc': values[1], 'next_pc': values[2], 'instruction': values[3] & 0xffffffff,
            'rs1_value': values[4], 'rs2_value': values[5], 'rd_value': values[6],
            'address': values[7], 'read': values[8], 'write': values[9],
            'read_mask': packet_bytes[80], 'write_mask': packet_bytes[81],
            'rd': packet_bytes[84], 'trap': bool(packet_bytes[85]), 'halt': bool(packet_bytes[86])}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--samples', type=int, default=8, choices=range(1, 65))
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    source = args.source.resolve()
    actual = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip()
    if actual != REVISION or subprocess.check_output(['git', '-C', source, 'status', '--porcelain']):
        raise ValueError('Sail checkout is not the exact clean pin')
    binary = source / 'build/c_emulator/sail_riscv_sim'
    info = subprocess.check_output([binary, '--build-info'], text=True)
    if REVISION[:7] not in info or 'Sail 0.20.2 ' not in info or 'dirty' in info:
        raise ValueError(f'Unpinned Sail binary: {info}')
    overrides = [ROOT / 'conformance/rv64im-sail-override.json', ROOT / 'conformance/riscv/sail-rv32im-tagged-options.json']
    command = [str(binary)]
    for path in overrides:
        command += ['--config-override', str(path)]
    isa = subprocess.check_output(command + ['--print-isa-string'], text=True).strip()
    if isa != 'rv64im':
        raise ValueError(f'Incorrect Sail ISA: {isa}')
    with socket.socket() as port_socket:
        port_socket.bind(('127.0.0.1', 0))
        port = port_socket.getsockname()[1]
    results, count, setup_count = [], 0, 0
    rng = random.Random(0x525636345341494c)
    start = time.perf_counter_ns()
    with tempfile.TemporaryFile() as stderr, tempfile.TemporaryDirectory(prefix='stwo-rv64-sail-') as temporary:
        with subprocess.Popen(command + ['--rvfi-dii', str(port)], stdout=stderr, stderr=stderr) as process:
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
                connection.settimeout(20)
                for word, lhs, rhs, is_memory in vectors.cases(rng, args.samples):
                    address = 0x100004000
                    data = rng.randbytes(16)
                    prefix = constant(4, address) + constant(5, int.from_bytes(data[:8], 'little')) + [0x00523023]
                    prefix += constant(5, int.from_bytes(data[8:], 'little')) + [0x00523423, 0x00000213, 0x00000293]
                    pc = 0x80000000 + 4 * (len(prefix) + 30)
                    lhs = address if is_memory else pc + 0x101 if lhs == 'jump' else lhs
                    setup = prefix + constant(1, lhs) + constant(2, rhs)
                    stream = setup + [word]
                    connection.sendall(b''.join(packet(instruction) for instruction in stream) + packet(0, 0))
                    raw = receive(connection, 88 * (len(stream) + 1))
                    records = [decode(raw[i:i+88]) for i in range(0, len(raw), 88)]
                    if any(record['trap'] for record in records[:-1]) or not records[-1]['halt']:
                        raise ValueError(f'Sail trap at vector {count}: word={word:x}, records={records[-3:]}')
                    retired = records[-2]
                    if retired['instruction'] != word or retired['pc'] != pc:
                        raise ValueError('RVFI retirement identity mismatch')
                    initial = [0] * 32
                    initial[1], initial[2] = lhs, rhs
                    final = initial.copy()
                    if retired['rd']:
                        final[retired['rd']] = retired['rd_value']
                    after = bytearray(data)
                    if retired['write_mask']:
                        offset = retired['address'] - address
                        if not 0 <= offset < 16:
                            raise ValueError('Unexpected Sail store address')
                        for byte in range(8):
                            if retired['write_mask'] >> byte & 1:
                                after[offset + byte] = retired['write'] >> (8 * byte) & 255
                    results.append({'instruction': word, 'pc': pc, 'registers': initial, 'expected_registers': final,
                                    'expected_pc': retired['next_pc'], 'memory_address': address,
                                    'memory_before': list(data), 'memory_after': list(after)})
                    count += 1
                    setup_count += len(setup)
                    if count % 2000 == 0:
                        print(f'Sail compared {count} retirement cases', flush=True)
                connection.close()
                connection = None
                process.wait(timeout=20)
                if process.returncode:
                    raise RuntimeError('Sail session failed')
            finally:
                if connection:
                    connection.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
            elapsed = time.perf_counter_ns() - start
            fixture = Path(temporary) / 'vectors.json'
            encoded = json.dumps(results, separators=(',', ':')).encode()
            fixture.write_bytes(encoded)
            runner = Path(temporary) / 'runner'
            subprocess.run(['zig', 'build-exe', 'src/frontends/riscv/rv64/diagnostic.zig', '-O', 'ReleaseSafe', f'-femit-bin={runner}'], cwd=ROOT, check=True)
            zig_start = time.perf_counter_ns()
            uncached = json.loads(subprocess.check_output([runner, 'vectors', fixture]))
            cached = json.loads(subprocess.check_output([runner, 'vectors-cached', fixture]))
            zig_elapsed = time.perf_counter_ns() - zig_start
            report = {'schema': 'rv64im-pinned-sail-retirement-v1', 'equivalent': True, 'sail_revision': REVISION,
                      'compiler': '0.20.2', 'build_info': info, 'binary_sha256': digest(binary), 'isa': isa,
                      'configuration_sha256': {str(p.relative_to(ROOT)): digest(p) for p in overrides},
                      'samples': args.samples, 'vectors': count, 'setup_instructions': setup_count,
                      'sail_batch_wall_ns': elapsed, 'zig_two_modes_wall_ns': zig_elapsed,
                      'timing_scope': 'Sail startup + architectural setup + TCP framing + compared retirements; not proving throughput',
                      'vector_sha256': hashlib.sha256(encoded).hexdigest(), 'uncached': uncached, 'cached': cached,
                      'formal_proof': False, 'trap_state_qualification': False}
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(report, indent=2) + '\n')
            print(json.dumps({'equivalent': True, 'vectors': count, 'opcodes': uncached['opcodes']}))
if __name__ == '__main__':
    main()
