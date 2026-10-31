#!/usr/bin/env python3
"""Independent Unicorn execution of an RV64 Ethereum *services* guest.

`riscv64_ethereum_oracle.py` runs the software guest only: any ECALL stops it.
This oracle additionally implements the two explicit service ABIs natively in
Python, so a services guest can be compared against the Zig executor:

* Keccak service (`a7 = 0x00010001`): `a0` points at 25 little-endian u64
  words; the state is replaced by one Keccak-f[1600] permutation.
* secp256k1 word services (`a7 = 0x00020011` add, `0x00020012` double): `a0`
  points at 6 or 3 little-endian u256 coordinates (lhs XYZ [, rhs XYZ]); the
  lhs XYZ is overwritten by the RCB projective formulas of
  `src/frontends/riscv/rv64/ethereum_services/secp256k1.zig`, including its
  single conditional reduction of raw inputs.

Each service retires as one instruction, matching the executor. The report
never claims a proof; it is execution-only evidence. It also records a size and
alignment histogram of `memcpy`/`memset`/`memcmp` entries for cost analysis.
"""
import argparse
import collections
import hashlib
import json
import struct
from pathlib import Path

from scripts.riscv64_ethereum_oracle import checked_inputs, sha

KECCAK_TAG = 0x0001_0001
SECP_ADD_WORD_TAG = 0x0002_0011
SECP_DOUBLE_WORD_TAG = 0x0002_0012
FIELD_MODULUS = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
ROTATIONS = [
    [0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14],
]
MASK64 = (1 << 64) - 1


def rotl(value, shift):
    return ((value << shift) | (value >> (64 - shift))) & MASK64 if shift else value


def keccak_f1600(lanes):
    """Keccak-f[1600] on 25 lanes in the standard x + 5*y order."""
    a = list(lanes)
    for rc in ROUND_CONSTANTS:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rotl(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], ROTATIONS[x][y])
        a = [b[i] ^ ((~b[(i % 5 + 1) % 5 + 5 * (i // 5)]) & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def reduce_once(value):
    return value - FIELD_MODULUS if value >= FIELD_MODULUS else value


def secp_add(x1, y1, z1, x2, y2, z2):
    """RCB complete addition for secp256k1 (b = 7), same program as the executor."""
    p = FIELD_MODULUS
    xx, yy, zz = x1 * x2 % p, y1 * y2 % p, z1 * z2 % p
    xy = ((x1 + y1) * (x2 + y2) - xx - yy) % p
    yz = ((y1 + z1) * (y2 + z2) - yy - zz) % p
    xz = ((x1 + z1) * (x2 + z2) - xx - zz) % p
    bzz3 = zz * 21 % p
    ym, yp = (yy - bzz3) % p, (yy + bzz3) % p
    byz3 = yz * 21 % p
    xx3, bxx9 = xx * 3 % p, xx * 63 % p
    return ((xy * ym - byz3 * xz) % p, (yp * ym + bxx9 * xz) % p, (yz * yp + xx3 * xy) % p)


def secp_double(x, y, z):
    p = FIELD_MODULUS
    yy, zz = y * y % p, z * z % p
    xy2 = x * y * 2 % p
    bzz3, bzz9 = zz * 21 % p, zz * 63 % p
    ym, yp = (yy - bzz9) % p, (yy + bzz3) % p
    t = yy * zz * 168 % p
    return (xy2 * ym % p, (ym * yp + t) % p, yy * y % p * z % p * 8 % p)


def function_entries(raw):
    """Entry addresses of memcpy/memset/memcmp/memmove from the static symtab."""
    shoff = struct.unpack_from('<Q', raw, 40)[0]
    stride, count = struct.unpack_from('<HH', raw, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff + i * stride) for i in range(count)]
    found = {}
    for section in sections:
        if section[1] != 2:
            continue
        strings = sections[section[6]]
        names = raw[strings[4]:strings[4] + strings[5]]
        for i in range(section[5] // 24):
            name_offset, info, _, _, value, size = struct.unpack_from('<IBBHQQ', raw, section[4] + i * 24)
            if info & 0xF != 2 or size == 0:
                continue
            name = names[name_offset:names.index(b'\0', name_offset)].decode()
            short = name.rsplit('3mem6', 1)[-1] if '3mem6' in name else name
            if short in ('memcpy', 'memset', 'memcmp', 'memmove'):
                found[value] = short
    return found


def execute(config, timeout_seconds):
    import unicorn as U
    from unicorn import riscv_const as R
    if U.__version__ != "2.1.4":
        raise ValueError("oracle requires Unicorn2.1.4")
    entry, symbols, segments, payload, expected = checked_inputs(config)
    if config.get("execution_profile") != "ethereum_services_v2":
        raise ValueError("this oracle implements the ethereum_services_v2 word ABI only")
    maximum = config.get("max_steps", 1_000_000_000)
    engine = U.Uc(U.UC_ARCH_RISCV, U.UC_MODE_RISCV64)
    permissions = {}

    def region(address, size, flags):
        if size < 0 or size > 256 << 20:
            raise ValueError("oracle mapped region invalid")
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            permissions[page] = permissions.get(page, 0) | flags
    for address, size, data, flags in segments:
        region(address, size, (U.UC_PROT_READ if flags & 4 else 0) | (U.UC_PROT_WRITE if flags & 2 else 0) | (U.UC_PROT_EXEC if flags & 1 else 0))
    for begin, end, flags in (("input_start", "input_end", U.UC_PROT_READ), ("halt_flag", "output_end", U.UC_PROT_READ | U.UC_PROT_WRITE),
                              ("stack_bottom", "stack_top", U.UC_PROT_READ | U.UC_PROT_WRITE), ("heap_start", "heap_end", U.UC_PROT_READ | U.UC_PROT_WRITE)):
        region(symbols["__" + begin], symbols["__" + end] - symbols["__" + begin], flags)
    pages = sorted(permissions)
    i = 0
    while i < len(pages):
        j = i + 1
        while j < len(pages) and pages[j] == pages[j - 1] + 4096 and permissions[pages[j]] == permissions[pages[i]]:
            j += 1
        engine.mem_map(pages[i], 4096 * (j - i), permissions[pages[i]])
        i = j
    for address, _, data, _ in segments:
        if data:
            engine.mem_write(address, data)
    engine.mem_write(symbols["__input_start"], len(payload).to_bytes(4, "little") + payload)
    engine.reg_write(R.UC_RISCV_REG_SP, symbols["__stack_top"])
    raw = Path(config["elf"]).read_bytes()
    entries = function_entries(raw)
    state = {"instructions": 0, "keccak": 0, "add": 0, "double": 0, "halt_pc": None, "error": None, "ram_words": 0}
    sizes = {name: collections.Counter() for name in set(entries.values())}
    alignment = {name: collections.Counter() for name in set(entries.values())}

    def count(uc, address, size, _):
        state["instructions"] += 1
        if state["instructions"] > maximum:
            state["error"] = "instruction budget exceeded"
            uc.emu_stop()

    def on_entry(uc, address, size, _):
        name = entries[address]
        n = uc.reg_read(R.UC_RISCV_REG_A2)
        bucket = n if n < 64 else min(4096, 1 << (n.bit_length() - 1))
        sizes[name][bucket] += 1
        if name != 'memset':
            a0, a1 = uc.reg_read(R.UC_RISCV_REG_A0), uc.reg_read(R.UC_RISCV_REG_A1)
            alignment[name]['both8' if a0 & 7 == 0 and a1 & 7 == 0 else ('same' if (a0 ^ a1) & 7 == 0 else 'different')] += 1

    def service(uc, intno, _):
        # Unicorn has already advanced PC past the ECALL when this hook runs;
        # execution resumes at the instruction after the service retirement.
        pc = uc.reg_read(R.UC_RISCV_REG_PC)
        tag = uc.reg_read(R.UC_RISCV_REG_A7)
        pointer = uc.reg_read(R.UC_RISCV_REG_A0)
        try:
            if intno not in (8, 9, 11) or uc.mem_read(pc - 4, 4) != b"\x73\x00\x00\x00":
                raise ValueError("unexpected interrupt " + str(intno) + " at " + hex(pc))
            if tag == KECCAK_TAG:
                if pointer & 7:
                    raise ValueError("misaligned keccak packet")
                lanes = list(struct.unpack('<25Q', uc.mem_read(pointer, 200)))
                uc.mem_write(pointer, struct.pack('<25Q', *keccak_f1600(lanes)))
                state["keccak"] += 1
                state["ram_words"] += 25  # words touched, as the executor counts them
            elif tag in (SECP_ADD_WORD_TAG, SECP_DOUBLE_WORD_TAG):
                if pointer & 31:
                    raise ValueError("misaligned secp packet")
                coordinates = 6 if tag == SECP_ADD_WORD_TAG else 3
                data = bytes(uc.mem_read(pointer, 32 * coordinates))
                values = [reduce_once(int.from_bytes(data[32 * k:32 * k + 32], 'little')) for k in range(coordinates)]
                result = secp_add(*values) if coordinates == 6 else secp_double(*values)
                uc.mem_write(pointer, b''.join(v.to_bytes(32, 'little') for v in result))
                state["add" if coordinates == 6 else "double"] += 1
                state["ram_words"] += 4 * coordinates
            else:
                raise ValueError("unsupported service tag " + hex(tag))
        except Exception as error:  # noqa: BLE001 - reported, never swallowed
            state["error"] = str(error)
            uc.emu_stop()
            return
        uc.reg_write(R.UC_RISCV_REG_PC, pc)

    def halt(uc, access, address, size, value, _):
        if address == symbols["__halt_flag"] and size == 4 and value == 1:
            state["halt_pc"] = uc.reg_read(R.UC_RISCV_REG_PC)
            uc.emu_stop()
    engine.hook_add(U.UC_HOOK_CODE, count)
    for address in entries:
        engine.hook_add(U.UC_HOOK_CODE, on_entry, begin=address, end=address)
    engine.hook_add(U.UC_HOOK_INTR, service)
    engine.hook_add(U.UC_HOOK_MEM_WRITE, halt, begin=symbols["__halt_flag"], end=symbols["__halt_flag"] + 3)
    engine.emu_start(entry, 0, timeout=timeout_seconds * 1_000_000)
    halt_flag = int.from_bytes(engine.mem_read(symbols["__halt_flag"], 4), 'little')
    length = int.from_bytes(engine.mem_read(symbols["__output_len"], 4), 'little')
    output = bytes(engine.mem_read(symbols["__output_data"], min(length, 4096))) if 0 < length <= 4096 else b''
    completed = state["error"] is None and state["halt_pc"] is not None and halt_flag == 1
    histogram = {name: {"calls": sum(sizes[name].values()), "sizes": {str(k): v for k, v in sorted(sizes[name].items())},
                        "alignment": dict(alignment[name])} for name in sizes}
    return {"schema": "rv64-ethereum-services-unicorn-execution-v1", "oracle": "Unicorn2.1.4", "execution_only": True,
            "proof_verified": False, "completed": completed, "verified_output": completed and output == expected,
            "error": state["error"], "instructions": state["instructions"], "keccak_calls": state["keccak"],
            "secp_add_calls": state["add"], "secp_double_calls": state["double"], "service_ram_word_transitions": state["ram_words"],
            "output": output.hex(), "halt_store_pc": state["halt_pc"], "pc": None if state["halt_pc"] is None else state["halt_pc"] + 4,
            "final_registers": [engine.reg_read(getattr(R, "UC_RISCV_REG_X" + str(i))) for i in range(32)],
            "elf_sha256": config["elf_sha256"], "input_sha256": config["input_sha256"], "mem_function_histogram": histogram}


def compare(report, native):
    """Fields that must agree with the native executor's execution report."""
    for key in ("output", "pc", "instructions", "final_registers", "elf_sha256", "input_sha256", "keccak_calls", "secp_add_calls", "secp_double_calls", "service_ram_word_transitions"):
        if native.get(key) != report.get(key):
            raise ValueError("independent runner differs: " + key)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--compare", type=Path, help="native rv64-ethereum-execution report to compare")
    args = parser.parse_args()
    report = execute(json.loads(args.config.read_text()), args.timeout)
    if args.compare:
        raw = args.compare.read_bytes()
        compare(report, json.loads(raw))
        report["compared_runner_report_sha256"] = sha(raw)
        report["native_agreement"] = True
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ("completed", "verified_output", "instructions", "keccak_calls", "secp_add_calls", "secp_double_calls", "error")}))
    if not report["verified_output"]:
        raise SystemExit("services oracle did not verify completion")


if __name__ == "__main__":
    main()
