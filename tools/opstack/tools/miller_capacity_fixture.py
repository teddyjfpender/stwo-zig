#!/usr/bin/env python3
"""Pinned synthetic RV64/Miller-capacity fixture, not an OP/EVM workload.

The reference uses ordinary Python integers and multiplication in
Fp[i,u,w]/(i²+1,u³-9-i,w²-u), independently of the native sparse implementation.
The generated ELF uses the normal guest I/O ABI and carries its own symbols.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
PC = 0x1000
PACKET = 0x200000
TAG = 0x40001
ABI = dict(input_start=0x800000, input_end=0xC00000, halt_flag=0xC00000,
           output_len=0xC00004, output_data=0xC00008, output_end=0xC01000,
           stack_bottom=0xC01000, stack_top=0x1C01000,
           heap_start=0x1D00000, heap_end=0x1D01000)

def mul(a, b):
    """Full 12×12 polynomial product; no sparse multiplication formulas."""
    out = [0] * 12
    for j, x in enumerate(a):
        aw, z = divmod(j, 6)
        au, ai = divmod(z, 2)
        for k, y in enumerate(b):
            bw, z = divmod(k, 6)
            bu, bi = divmod(z, 2)
            w, u, i = aw + bw, au + bu, ai + bi
            v = x * y
            if w == 2:
                w, u = 0, u + 1
            if i == 2:
                i, v = 0, -v
            terms = [(v, i)]
            if u >= 3:
                u -= 3
                terms = [(9 * v, i), (v, i + 1)]
            for value, imag in terms:
                if imag == 2:
                    value, imag = -value, 0
                at = 6 * w + 2 * u + imag
                out[at] = (out[at] + value) % Q
    return out

def packet_bytes(values):
    return b"".join(x.to_bytes(32, "little") for x in values)

def reference(calls):
    packet = [1 + 2 * i for i in range(20)]
    initial = packet_bytes(packet)
    line = [0] * 12
    line[0:2] = [(packet[12] * packet[19]) % Q, (packet[13] * packet[19]) % Q]
    line[6:8] = [(packet[14] * packet[18]) % Q, (packet[15] * packet[18]) % Q]
    line[8:10] = packet[16:18]
    trace = hashlib.sha256()
    for _ in range(calls):
        trace.update(packet_bytes(packet))
        packet[:12] = mul(packet[:12], line)
        trace.update(packet_bytes(packet))
    return initial, packet_bytes(packet), trace.hexdigest()

def lui(rd, value):
    assert value & 0xFFF == 0 and 0 <= value < 1 << 31
    return value | (rd << 7) | 0x37

def addi(rd, rs, imm):
    assert -(1 << 11) <= imm < 1 << 11
    return ((imm & 0xFFF) << 20) | (rs << 15) | (rd << 7) | 0x13

def store(rs, base, imm, width):
    assert 0 <= imm < 1 << 11
    return ((imm >> 5) << 25) | (rs << 20) | (base << 15) | (width << 12) | ((imm & 31) << 7) | 0x23

def bne(a, b, offset):
    assert offset % 2 == 0 and -(1 << 12) <= offset < 1 << 12
    n = offset & 0x1FFF
    return ((n >> 12) << 31) | (((n >> 5) & 63) << 25) | (b << 20) | (a << 15) | (1 << 12) | (((n >> 1) & 15) << 8) | (((n >> 11) & 1) << 7) | 0x63

def program(calls):
    words = [lui(10, PACKET), lui(17, TAG & ~0xFFF), addi(17, 17, TAG & 0xFFF), addi(5, 0, calls),
             0x73, addi(5, 5, -1), bne(5, 0, -8),
             lui(6, ABI['halt_flag']), addi(7, 0, 43), store(7, 6, 4, 2), addi(7, 0, 1), store(7, 6, 0, 2)]
    for off in range(0, 48, 8):
        words += [(off << 20) | (10 << 15) | (3 << 12) | (28 << 7) | 0x03,
                  store(28, 6, 8 + off, 3)]
    terminal = PC + 4 * len(words)
    return struct.pack('<' + 'I' * (len(words) + 1), *words, 0x6F), terminal

def elf(code, packet):
    names = b'\0' + b''.join(('__' + name).encode() + b'\0' for name in ABI)
    symbols = bytearray(24)
    off = 1
    for name, value in ABI.items():
        symbols.extend(struct.pack('<IBBHQQ', off, 0x10, 0, 0xFFF1, value, 0))
        off += len(name) + 3
    shnames = b'\0.symtab\0.strtab\0.shstrtab\0'
    out = bytearray(0x2000 + len(packet))
    out[0x1000:0x1000 + len(code)] = code
    out[0x2000:0x2000 + len(packet)] = packet
    sections = []
    for data in (symbols, names, shnames):
        while len(out) % 8:
            out.append(0)
        sections.append((len(out), len(data)))
        out.extend(data)
    while len(out) % 8:
        out.append(0)
    shoff = len(out)
    out.extend(bytes(64))
    out.extend(struct.pack('<IIQQQQIIQQ', 1, 2, 0, 0, *sections[0], 2, 1, 8, 24))
    out.extend(struct.pack('<IIQQQQIIQQ', 9, 3, 0, 0, *sections[1], 0, 0, 1, 0))
    out.extend(struct.pack('<IIQQQQIIQQ', 17, 3, 0, 0, *sections[2], 0, 0, 1, 0))
    ident = b'\x7fELF\x02\x01\x01' + bytes(9)
    out[:64] = struct.pack('<16sHHIQQQIHHHHHH', ident, 2, 243, 1, PC, 64, shoff, 0, 64, 56, 3, 64, 4, 3)
    headers = [(5, 0x1000, PC, len(code)), (6, 0x2000, PACKET, 384), (4, 0x2180, PACKET + 384, 256)]
    for j, (flags, fileoff, address, size) in enumerate(headers):
        out[64 + 56*j:64 + 56*(j+1)] = struct.pack('<IIQQQQQQ', 1, flags, fileoff, address, address, size, size, 4096)
    return bytes(out)

def symbols_from_elf(data):
    shoff = struct.unpack_from('<Q', data, 40)[0]
    sym = struct.unpack_from('<IIQQQQIIQQ', data, shoff + 64)
    strings = struct.unpack_from('<IIQQQQIIQQ', data, shoff + 128)
    names = data[strings[4]:strings[4] + strings[5]]
    out = {}
    for pos in range(sym[4] + 24, sym[4] + sym[5], 24):
        name, _, _, _, value, _ = struct.unpack_from('<IBBHQQ', data, pos)
        label = names[name:names.index(0, name)].decode()
        out[label.removeprefix('__')] = value
    return out

def generate(directory, calls=1023):
    if not 1 <= calls <= 1023:
        raise ValueError('fixture supports 1..1023 calls')
    directory = Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    initial, final, trace_hash = reference(calls)
    code, terminal = program(calls)
    image = elf(code, initial)
    symbols = symbols_from_elf(image)
    assert symbols == ABI
    input_bytes = b'\0'
    paths = {name: directory / name for name in ['guest.elf', 'input.bin', 'config.json', 'reference.json']}
    paths['guest.elf'].write_bytes(image)
    paths['input.bin'].write_bytes(input_bytes)
    expected = final[:43].hex()
    steps = 4 + 3 * calls + 17  # expectation, checked against actual Machine capture
    config = dict(elf=str(paths['guest.elf']), input=str(paths['input.bin']),
                  elf_sha256=hashlib.sha256(image).hexdigest(), input_sha256=hashlib.sha256(input_bytes).hexdigest(),
                  expected_output=expected, symbols=symbols, output_directory=str(directory / 'native'),
                  terminal_pc=terminal, batch_steps=8191, max_steps=steps,
                  workers=16, execution_profile='ethereum_services_op_v1')
    registers = [0] * 32
    for reg, value in [(2, ABI['stack_top']), (6, ABI['halt_flag']), (7, 1), (10, PACKET), (17, TAG), (28, int.from_bytes(final[40:48], 'little'))]:
        registers[reg] = value
    report = dict(schema='op-synthetic-miller-full-span-fixture/v1', calls=calls,
                  scope='synthetic field-operation loop, no OP/EVM/pairing validity claim',
                  expected_steps=steps, expected_pc=terminal, expected_registers=registers,
                  initial_packet_sha256=hashlib.sha256(initial).hexdigest(), final_packet_hex=final.hex(),
                  ordered_before_after_packet_sha256=trace_hash, expected_output=expected,
                  elf_sha256=config['elf_sha256'], input_sha256=config['input_sha256'], symbols_from_elf=symbols,
                  independent_reference='full 12x12 polynomial multiplication; i^2=-1,u^3=9+i,w^2=u')
    paths['config.json'].write_text(json.dumps(config, indent=2) + '\n')
    paths['reference.json'].write_text(json.dumps(report, indent=2) + '\n')
    return paths['config.json']

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory')
    parser.add_argument('--calls', type=int, default=1023)
    args = parser.parse_args()
    print(generate(args.directory, args.calls))
