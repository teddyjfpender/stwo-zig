"""Independent Unicorn 2.1.4 check of the software OP guest and exact step count.

The software profile installs no service hook. The explicit services profile uses
the independent Python Keccak/RCB reference and rejects every other service tag. This is execution evidence.
"""

import hashlib
import struct
import time
from functools import lru_cache
from pathlib import Path

from scripts.riscv64_csp_compare import elf_info


@lru_cache(maxsize=16)
def montgomery_inverse(modulus):
    return pow(1 << 384, -1, modulus)


def mont384(packet):
    """Independent mathematical interpretation of the admitted Montgomery packet."""
    if len(packet) != 160:
        raise ValueError("Montgomery packet size")
    a, b, modulus = (int.from_bytes(packet[i : i + 48], "little") for i in (0, 48, 96))
    if modulus & 1 == 0:
        raise ValueError("Montgomery modulus must be odd")
    return (a * b * montgomery_inverse(modulus) % modulus).to_bytes(48, "little")


def arith256(packet):
    """Independent full-precision integers; no guest or producer arithmetic code."""
    if len(packet) != 160:
        raise ValueError("arith256 packet size")
    a, b, c, modulus = (
        int.from_bytes(packet[i : i + 32], "little") for i in range(0, 128, 32)
    )
    return ((a * b + c) % modulus if modulus else 0).to_bytes(32, "little")


def bn254_affine(packet, double):
    """Independent affine equations for the admitted partial G1 services."""
    p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
    if len(packet) != (64 if double else 128):
        raise ValueError("BN254 packet size")
    values = [
        int.from_bytes(packet[i : i + 32], "little") for i in range(0, len(packet), 32)
    ]
    if any(x >= p for x in values):
        raise ValueError("noncanonical BN254 input")
    x, y = values[:2]
    if double:
        if not y:
            raise ValueError("BN254 zero doubling denominator")
        u, v = x, y
        slope = 3 * x * x * pow(2 * y, -1, p) % p
    else:
        u, v = values[2:]
        if x == u:
            raise ValueError("BN254 zero addition denominator")
        slope = (v - y) * pow((u - x) % p, -1, p) % p
    result_x = (slope * slope - x - u) % p
    result_y = (slope * (x - result_x) - y) % p
    return result_x.to_bytes(32, "little") + result_y.to_bytes(32, "little")


def jumpdest_bitmap(code):
    """Independent byte walk: a PUSH immediate never creates a destination."""
    bitmap = bytearray(((len(code) + 63) // 64) * 8)
    pc = 0
    while pc < len(code):
        opcode = code[pc]
        if opcode == 0x5B:
            bitmap[pc // 8] |= 1 << (pc % 8)
        pc += opcode - 0x5F + 1 if 0x60 <= opcode <= 0x7F else 1
    return bytes(bitmap)


def execute(config, expected_steps, timeout=600):
    import unicorn as U
    from unicorn import riscv_const as R

    if U.__version__ != "2.1.4":
        raise ValueError("requires Unicorn 2.1.4")
    if config.get("execution_profile", "software") not in (
        "software",
        "ethereum_services_v3",
    ):
        raise ValueError("unsupported execution profile")
    if not 2 <= expected_steps <= config["max_steps"] <= 10_000_000_000:
        raise ValueError("invalid instruction budget")
    elf = Path(config["elf"])
    data = elf.read_bytes()
    payload = Path(config["input"]).read_bytes()
    if len(data) > 32 << 20 or not 0 < len(payload) < 16 << 20:
        raise ValueError("input bounds")
    for key, value in (("elf_sha256", data), ("input_sha256", payload)):
        if hashlib.sha256(value).hexdigest() != config[key]:
            raise ValueError("identity mismatch")
    if data[:6] != b"\x7fELF\2\1" or struct.unpack_from("<I", data, 48)[0] != 0:
        raise ValueError("requires RV64IM ELF")
    entry, symbols, segments = elf_info(elf)
    s = config["symbols"]
    if any(symbols.get("__" + name) != value for name, value in s.items()):
        raise ValueError("ELF symbols differ")
    fixed = {
        "input_start": 0x800000,
        "input_end": 0x1800000,
        "halt_flag": 0x1800000,
        "output_len": 0x1800004,
        "output_data": 0x1800008,
        "output_end": 0x1C00000,
        "stack_bottom": 0x1C00000,
        "stack_top": 0x2C00000,
        "heap_end": 0x10000000,
    }
    if (
        any(s.get(k) != v for k, v in fixed.items())
        or not s["stack_top"] <= s["heap_start"] < s["heap_end"]
        or s["heap_start"] % 16
    ):
        raise ValueError("invalid OP guest ABI")
    expected = bytes.fromhex(config["expected_output"])
    if len(expected) != 43 or expected[32] != 1 or expected[41:43] != b"OP":
        raise ValueError("expected output length")
    reserved = [
        (s[a], s[b])
        for a, b in (
            ("input_start", "input_end"),
            ("halt_flag", "output_end"),
            ("stack_bottom", "stack_top"),
            ("heap_start", "heap_end"),
        )
    ]
    if any(
        begin < addr + size and addr < end
        for addr, size, _, _ in segments
        for begin, end in reserved
    ):
        raise ValueError("ELF overlaps guest ABI")
    uc = U.Uc(U.UC_ARCH_RISCV, U.UC_MODE_RISCV64)
    pages = {}

    def region(addr, size, flags):
        if (
            not 0 <= addr < 1 << 64
            or not 0 < size <= 256 << 20
            or addr + size > 1 << 64
        ):
            raise ValueError("mapping bounds")
        for page in range(addr & ~4095, (addr + size + 4095) & ~4095, 4096):
            pages[page] = pages.get(page, 0) | flags
        if len(pages) > 65536:
            raise ValueError("mapping budget")

    for addr, size, _, flags in segments:
        region(
            addr,
            size,
            (U.UC_PROT_READ if flags & 4 else 0)
            | (U.UC_PROT_WRITE if flags & 2 else 0)
            | (U.UC_PROT_EXEC if flags & 1 else 0),
        )
    for i, (begin, end) in enumerate(reserved):
        region(begin, end - begin, U.UC_PROT_READ | (0 if i == 0 else U.UC_PROT_WRITE))
    ordered = sorted(pages)
    i = 0
    while i < len(ordered):
        j = i + 1
        while (
            j < len(ordered)
            and ordered[j] == ordered[j - 1] + 4096
            and pages[ordered[j]] == pages[ordered[i]]
        ):
            j += 1
        uc.mem_map(ordered[i], 4096 * (j - i), pages[ordered[i]])
        i = j
    for addr, _, value, _ in segments:
        if value:
            uc.mem_write(addr, value)
    uc.mem_write(s["input_start"], len(payload).to_bytes(4, "little") + payload)
    uc.reg_write(R.UC_RISCV_REG_SP, s["stack_top"])
    completed = False
    halt_pc = None

    def halt(uc, access, address, size, value, _):
        nonlocal completed, halt_pc
        if (address, size, value) != (s["halt_flag"], 4, 1):
            raise ValueError("invalid completion store")
        completed = True
        halt_pc = uc.reg_read(R.UC_RISCV_REG_PC)
        uc.emu_stop()

    uc.hook_add(U.UC_HOOK_MEM_WRITE, halt, begin=s["halt_flag"], end=s["halt_flag"] + 3)
    service_error = []
    sha_compressor = None
    service_counts = {
        "jumpdest_calls": 0,
        "jumpdest_bytes": 0,
        "curve_calls": [0] * 7,
        "sha256_calls": 0,
        "arith256_mod_calls": 0,
        "keccak_calls": 0,
        "secp_add_calls": 0,
        "secp_double_calls": 0,
        "sponge_calls": 0,
        "bulk_memcpy_calls": 0,
        "bulk_memcpy_unaligned_calls": 0,
        "bulk_memset_calls": 0,
        "bulk_memcmp_calls": 0,
        "bulk_memcpy_bytes": 0,
        "bulk_memcpy_unaligned_bytes": 0,
        "bulk_memset_bytes": 0,
        "bulk_memcmp_bytes": 0,
    }
    if config.get("execution_profile", "software") == "ethereum_services_v3":
        from scripts.riscv64_ethereum_services_oracle import (
            keccak_f1600,
            reduce_once,
            secp_add,
            secp_double,
        )

        def service(uc, intno, _):
            nonlocal sha_compressor
            pc = uc.reg_read(R.UC_RISCV_REG_PC)
            tag = uc.reg_read(R.UC_RISCV_REG_A7)
            pointer = uc.reg_read(R.UC_RISCV_REG_A0)
            try:
                if (
                    intno not in (8, 9, 11)
                    or bytes(uc.mem_read(pc - 4, 4)) != b"\x73\x00\x00\x00"
                ):
                    raise ValueError("unexpected service interrupt")
                if tag == 0x30010:
                    if pointer % 32:
                        raise ValueError("unaligned SHA compression packet")
                    if sha_compressor is None:
                        from opstack.sha_oracle import Compressor

                        sha_compressor = Compressor()
                    packet = bytes(uc.mem_read(pointer, 96))
                    state = struct.unpack("<8I", packet[:32])
                    result = sha_compressor.compress(state, packet[32:])
                    uc.mem_write(pointer, struct.pack("<8I", *result))
                    service_counts["sha256_calls"] += 1
                elif tag == 0x30040:
                    if pointer % 8:
                        raise ValueError("unaligned jumpdest packet")
                    code, length, bitmap = struct.unpack(
                        "<3Q", uc.mem_read(pointer, 24)
                    )
                    if (
                        code % 64
                        or bitmap % 8
                        or not 0 < length <= 1 << 20
                        or length % 8
                    ):
                        raise ValueError("jumpdest bounds")
                    spans = [
                        (pointer, pointer + 24),
                        (code, code + length),
                        (bitmap, bitmap + ((length + 63) // 64) * 8),
                    ]
                    for i, a in enumerate(spans):
                        if not 0 <= a[0] < a[1] <= 1 << 64:
                            raise ValueError("jumpdest address overflow")
                        for b in spans[i + 1 :]:
                            if a[0] < b[1] and b[0] < a[1]:
                                raise ValueError("jumpdest overlap")
                    uc.mem_write(
                        bitmap, jumpdest_bitmap(bytes(uc.mem_read(code, length)))
                    )
                    service_counts["jumpdest_calls"] += 1
                    service_counts["jumpdest_bytes"] += length
                elif tag in (0x30100, 0x30101):
                    if pointer % 32:
                        raise ValueError("unaligned BN254 packet")
                    packet = bytes(uc.mem_read(pointer, 64 if tag == 0x30101 else 128))
                    uc.mem_write(pointer, bn254_affine(packet, tag == 0x30101))
                    service_counts["curve_calls"][tag - 0x30100] += 1
                elif tag == 0x30121:
                    if pointer % 32:
                        raise ValueError("unaligned Montgomery packet")
                    packet = bytes(uc.mem_read(pointer, 160))
                    uc.mem_write(pointer, mont384(packet))
                    service_counts["curve_calls"][4] += 1
                elif tag == 0x30021:
                    if pointer % 32:
                        raise ValueError("unaligned arith256 packet")
                    packet = bytes(uc.mem_read(pointer, 160))
                    uc.mem_write(pointer + 128, arith256(packet))
                    service_counts["arith256_mod_calls"] += 1
                elif tag == 0x10001:
                    if pointer % 8:
                        raise ValueError("unaligned Keccak")
                    lanes = struct.unpack("<25Q", uc.mem_read(pointer, 200))
                    uc.mem_write(pointer, struct.pack("<25Q", *keccak_f1600(lanes)))
                    service_counts["keccak_calls"] += 1
                elif tag in (0x20011, 0x20012):
                    if pointer % 32:
                        raise ValueError("unaligned secp")
                    count = 6 if tag == 0x20011 else 3
                    data = bytes(uc.mem_read(pointer, count * 32))
                    values = [
                        reduce_once(
                            int.from_bytes(data[i * 32 : (i + 1) * 32], "little")
                        )
                        for i in range(count)
                    ]
                    result = secp_add(*values) if count == 6 else secp_double(*values)
                    uc.mem_write(
                        pointer, b"".join(x.to_bytes(32, "little") for x in result)
                    )
                    service_counts[
                        "secp_add_calls" if count == 6 else "secp_double_calls"
                    ] += 1
                elif tag in (0x30001, 0x30002, 0x30003):
                    words = 4 if tag == 0x30003 else 3
                    if pointer % 8:
                        raise ValueError("unaligned bulk packet")
                    dst, source, length = struct.unpack("<3Q", uc.mem_read(pointer, 24))
                    if dst % 8 or not 0 < length <= 1 << 20 or length % 8:
                        raise ValueError("bulk bounds")
                    spans = [(pointer, pointer + words * 8), (dst, dst + length)]
                    if tag == 0x30001:
                        spans.append((source & ~7, (source + length + 7) & ~7))
                    elif tag == 0x30003:
                        if source % 8:
                            raise ValueError("unaligned compare")
                        spans.append((source, source + length))
                    for i, a in enumerate(spans):
                        if not 0 <= a[0] < a[1] <= 1 << 64:
                            raise ValueError("bulk address overflow")
                        for b in spans[i + 1 :]:
                            if a[0] < b[1] and b[0] < a[1]:
                                raise ValueError("bulk word overlap")
                    if tag == 0x30001:
                        uc.mem_write(dst, bytes(uc.mem_read(source, length)))
                        prefix = (
                            "bulk_memcpy_unaligned" if source % 8 else "bulk_memcpy"
                        )
                        service_counts[prefix + "_calls"] += 1
                        service_counts[prefix + "_bytes"] += length
                    elif tag == 0x30002:
                        uc.mem_write(dst, bytes([source & 255]) * length)
                        service_counts["bulk_memset_calls"] += 1
                        service_counts["bulk_memset_bytes"] += length
                    else:
                        a = bytes(uc.mem_read(dst, length))
                        b = bytes(uc.mem_read(source, length))
                        result = (a > b) - (a < b)
                        examined = length
                        for i in range(0, length, 8):
                            if a[i : i + 8] != b[i : i + 8]:
                                examined = i + 8
                                break
                        uc.mem_write(
                            pointer + 24,
                            (result & ((1 << 64) - 1)).to_bytes(8, "little"),
                        )
                        service_counts["bulk_memcmp_calls"] += 1
                        service_counts["bulk_memcmp_bytes"] += examined
                elif tag == 0x30130:
                    if pointer % 8:
                        raise ValueError("unaligned sponge packet")
                    state_addr, msg, length, flags = struct.unpack(
                        "<4Q", uc.mem_read(pointer, 32)
                    )
                    if (
                        state_addr % 8
                        or length >= 1 << 20
                        or flags & ~3
                        or not flags & 1
                        and (not length or length % 136)
                    ):
                        raise ValueError("invalid sponge packet")
                    spans = [(pointer, pointer + 32), (state_addr, state_addr + 200)]
                    if length:
                        spans.append((msg & ~7, (msg + length + 7) & ~7))
                    for i, a in enumerate(spans):
                        for b in spans[i + 1 :]:
                            if a[0] < b[1] and b[0] < a[1]:
                                raise ValueError("sponge word overlap")
                    lanes = (
                        [0] * 25
                        if flags & 2
                        else list(struct.unpack("<25Q", uc.mem_read(state_addr, 200)))
                    )
                    message = bytes(uc.mem_read(msg, length)) if length else b""
                    for block in range(length // 136 + bool(flags & 1)):
                        chunk = bytearray(message[block * 136 : (block + 1) * 136])
                        tail = len(chunk)
                        chunk.extend(bytes(136 - tail))
                        if flags & 1 and block == length // 136:
                            chunk[tail] ^= 1
                            chunk[135] ^= 0x80
                        for i, value in enumerate(struct.unpack("<17Q", chunk)):
                            lanes[i] ^= value
                        lanes = keccak_f1600(lanes)
                    uc.mem_write(state_addr, struct.pack("<25Q", *lanes))
                    service_counts["sponge_calls"] += 1
                else:
                    raise ValueError(f"unsupported service tag {tag:#x}")
                uc.reg_write(R.UC_RISCV_REG_PC, pc)
            except (
                ValueError,
                struct.error,
                OSError,
                AttributeError,
                U.UcError,
            ) as error:
                service_error.append(str(error))
                uc.emu_stop()

        uc.hook_add(U.UC_HOOK_INTR, service)
    start = time.monotonic_ns()
    uc.emu_start(entry, 0, timeout=timeout * 1_000_000, count=expected_steps - 1)
    if service_error:
        raise ValueError(service_error[0])
    if completed or uc.query(U.UC_QUERY_TIMEOUT):
        raise ValueError("completed early or timed out")
    uc.emu_start(uc.reg_read(R.UC_RISCV_REG_PC), 0, timeout=1_000_000, count=1)
    length = int.from_bytes(uc.mem_read(s["output_len"], 4), "little")
    value = bytes(uc.mem_read(s["output_data"], 43))
    if service_error:
        raise ValueError(service_error[0])
    if not completed or length != 43 or value != expected:
        raise ValueError("output/count mismatch")
    return {
        "schema": "stwo.opstack.unicorn.v1",
        "oracle": "Unicorn2.1.4",
        "completed": True,
        "proof_verified": False,
        "services": service_counts,
        "sha256_oracle": sha_compressor.version
        if service_counts["sha256_calls"]
        else None,
        "exact_steps_verified": expected_steps,
        "elapsed_ns": time.monotonic_ns() - start,
        "elf_sha256": config["elf_sha256"],
        "input_sha256": config["input_sha256"],
        "output": value.hex(),
        "post_store_pc": halt_pc + 4,
        "final_registers": [
            uc.reg_read(getattr(R, f"UC_RISCV_REG_X{i}")) for i in range(32)
        ],
        "oracle_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
