#!/usr/bin/env python3
"""Independent Unicorn2.1.4 execution check of one pinned software ETH guest.

No host syscall/crypto implementation is installed. An optional expected step
count is checked using two native instruction budgets (N-1, then1), avoiding a
Python callback on every instruction. This is execution evidence, never a proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import time

from scripts.riscv64_csp_compare import elf_info


def sha(data):
    return hashlib.sha256(data).hexdigest()



def validate_layout(symbols, segments, input_size):
    s = {key.removeprefix("__"): value for key, value in symbols.items()}
    if (s["input_end"] - s["input_start"] != 4 << 20 or
            s["halt_flag"] != s["input_end"] or s["halt_flag"] & 3 or
            s["output_len"] != s["halt_flag"] + 4 or s["output_data"] != s["halt_flag"] + 8 or
            s["output_end"] != s["stack_bottom"] or
            not 43 <= s["output_end"] - s["output_data"] <= (4 << 20) - 8 or
            s["stack_top"] - s["stack_bottom"] != 16 << 20 or s["stack_bottom"] & 15 or
            s["stack_top"] & 15 or s["heap_start"] < s["stack_top"] or s["heap_start"] & 15 or
            not 0 < s["heap_end"] - s["heap_start"] <= 224 << 20 or
            not 0 < input_size <= (4 << 20) - 4):
        raise ValueError("oracle invalid Ethereum ABI layout")
    reserved = [(s["input_start"], s["input_end"]), (s["halt_flag"], s["output_end"]),
                (s["stack_bottom"], s["stack_top"]), (s["heap_start"], s["heap_end"])]
    for address, size, _, _ in segments:
        if any(address < end and begin < address + size for begin, end in reserved):
            raise ValueError("oracle ELF overlaps ABI region")


def checked_inputs(config):
    elf = Path(config["elf"])
    with elf.open("rb") as stream:
        data = stream.read((32 << 20) + 1)
    with Path(config["input"]).open("rb") as stream:
        payload = stream.read((4 << 20) - 3)
    if len(data) > 32 << 20 or len(payload) > (4 << 20) - 4:
        raise ValueError("oracle input resource limit")
    if sha(data) != config["elf_sha256"] or sha(payload) != config["input_sha256"]:
        raise ValueError("oracle input identity mismatch")
    if data[:6] != b"\x7fELF\2\1" or struct.unpack_from("<H", data, 18)[0] != 243 or struct.unpack_from("<I", data, 48)[0] != 0:
        raise ValueError("oracle requires ELF64 little-endian RV64 soft-float flags0")
    entry, symbols, segments = elf_info(elf)
    for name, expected in config["symbols"].items():
        if symbols.get("__" + name) != expected:
            raise ValueError("oracle ELF symbol differs: " + name)
    validate_layout(symbols, segments, len(payload))
    expected = bytes.fromhex(config["expected_output"])
    if len(expected) != 43 or expected[32] != 1:
        raise ValueError("oracle expected successful43-byte output required")
    return entry, symbols, segments, payload, expected


def execute(config, expected_steps=None, timeout_seconds=120):
    import unicorn as U
    from unicorn import riscv_const as R
    if U.__version__ != "2.1.4":
        raise ValueError("oracle requires Unicorn2.1.4")
    entry, symbols, segments, payload, expected = checked_inputs(config)
    maximum = config.get("max_steps", 1_000_000_000)
    if not 1 <= maximum <= 1_000_000_000 or not 1 <= timeout_seconds <= 600:
        raise ValueError("oracle execution budget invalid")
    if expected_steps is not None and not 2 <= expected_steps <= maximum:
        raise ValueError("oracle expected step count invalid")
    engine = U.Uc(U.UC_ARCH_RISCV, U.UC_MODE_RISCV64)
    permissions = {}
    image = []
    initial_registers = [0, 0, symbols["__stack_top"]] + [0] * 29

    def region(address, size, flags):
        if size < 0 or size > 256 << 20 or address < 0 or address + size > 1 << 64:
            raise ValueError("oracle mapped region invalid")
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            if page not in permissions and len(permissions) >= 65536:
                raise ValueError("oracle mapped page budget exceeded")
            permissions[page] = permissions.get(page, 0) | flags
    for address, size, data, flags in segments:
        permission = (U.UC_PROT_READ if flags & 4 else 0) | (U.UC_PROT_WRITE if flags & 2 else 0) | (U.UC_PROT_EXEC if flags & 1 else 0)
        region(address, size, permission)
        image.append({"address": address, "size": size, "flags": flags, "file_bytes": len(data), "sha256": sha(data)})
    for begin, end, flags in (("input_start", "input_end", U.UC_PROT_READ),
                              ("halt_flag", "output_end", U.UC_PROT_READ | U.UC_PROT_WRITE),
                              ("stack_bottom", "stack_top", U.UC_PROT_READ | U.UC_PROT_WRITE),
                              ("heap_start", "heap_end", U.UC_PROT_READ | U.UC_PROT_WRITE)):
        region(symbols["__" + begin], symbols["__" + end] - symbols["__" + begin], flags)
    # Coalesce only adjacent pages with identical permissions.
    pages = sorted(permissions)
    if len(pages) > 65536:
        raise ValueError("oracle mapped page budget exceeded")
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
    transport = len(payload).to_bytes(4, "little") + payload
    engine.mem_write(symbols["__input_start"], transport)
    # Match the documented initial architectural boundary, including SP.
    engine.reg_write(R.UC_RISCV_REG_SP, symbols["__stack_top"])
    completed = False
    halt_store_pc = None

    def halt(uc, access, address, size, value, _):
        nonlocal completed, halt_store_pc
        if address != symbols["__halt_flag"] or size != 4 or value != 1:
            raise ValueError("oracle invalid completion store")
        completed = True
        halt_store_pc = uc.reg_read(R.UC_RISCV_REG_PC)
        uc.emu_stop()
    engine.hook_add(U.UC_HOOK_MEM_WRITE, halt, begin=symbols["__halt_flag"], end=symbols["__halt_flag"] + 3)
    initial_image_identity = sha(json.dumps({"segments": image, "symbols": config["symbols"],
                                            "transport_sha256": sha(transport),
                                            "registers": initial_registers}, sort_keys=True).encode())
    started = time.monotonic_ns()
    if expected_steps is not None:
        engine.emu_start(entry, 0, timeout=timeout_seconds * 1_000_000, count=expected_steps - 1)
        if completed or engine.query(U.UC_QUERY_TIMEOUT):
            raise ValueError("oracle completion earlier than expected, or timed out")
        engine.emu_start(engine.reg_read(R.UC_RISCV_REG_PC), 0, timeout=1_000_000, count=1)
    else:
        engine.emu_start(entry, 0, timeout=timeout_seconds * 1_000_000, count=maximum)
    elapsed = time.monotonic_ns() - started
    output_length = int.from_bytes(engine.mem_read(symbols["__output_len"], 4), "little")
    output = bytes(engine.mem_read(symbols["__output_data"], min(output_length, 43)))
    flag = int.from_bytes(engine.mem_read(symbols["__halt_flag"], 4), "little")
    verified = completed and flag == 1 and output_length == 43 and output == expected
    if expected_steps is not None and not verified:
        raise ValueError("oracle did not complete on exactly expected instruction")
    return {"schema": "rv64-ethereum-unicorn-execution-v1", "oracle": "Unicorn2.1.4",
            "oracle_script_sha256": sha(Path(__file__).read_bytes()),
            "execution_only": True, "proof_verified": False, "completed": completed,
            "verified_output": verified, "exact_steps_verified": expected_steps if verified else None,
            "instruction_budget": maximum, "elapsed_ns": elapsed, "output": output.hex(),
            "output_sha256": sha(output), "halt_flag": flag, "halt_store_pc": halt_store_pc,
            # Unicorn memory hooks stop with the write committed but PC still at
            # the store. Normalize only the fixed-width store's fallthrough PC.
            "architectural_post_store_pc": halt_store_pc + 4 if completed else None,
            "observed_pc": engine.reg_read(R.UC_RISCV_REG_PC),
            "final_registers": [engine.reg_read(getattr(R, "UC_RISCV_REG_X" + str(i))) for i in range(32)],
            "elf_sha256": config["elf_sha256"], "canonical_input_sha256": sha(payload),
            "transport_sha256": sha(transport), "initial_registers": initial_registers,
            "initial_image_description_sha256": initial_image_identity,
            "initial_image": image, "abi_symbols": config["symbols"],
            "initial_memory_order": "zero mapped pages; overlay ELF file bytes; overlay u32le length+canonical input",
            "mapped_pages": len(pages), "ram_state_comparison": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--expected-steps", type=int)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--compare", type=Path, help="compare independent runner report after execution")
    args = parser.parse_args()
    report = execute(json.loads(args.config.read_text()), args.expected_steps, args.timeout)
    if args.compare:
        comparison_bytes = args.compare.read_bytes()
        comparison = json.loads(comparison_bytes)
        for key, expected in (("output", report["output"]), ("pc", report["architectural_post_store_pc"]),
                              ("instructions", report["exact_steps_verified"]),
                              ("final_registers", report["final_registers"]),
                              ("elf_sha256", report["elf_sha256"]),
                              ("input_sha256", report["canonical_input_sha256"])):
            if comparison[key] != expected:
                raise ValueError("independent runner differs: " + key)
        report["compared_runner_report_sha256"] = sha(comparison_bytes)
        report["final_registers_pc_output_count_match"] = True
    args.report.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.report.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n")
    temporary.replace(args.report)
    print(json.dumps({key: report[key] for key in ("completed", "verified_output", "exact_steps_verified", "elapsed_ns")}))
    if not report["verified_output"]:
        raise SystemExit("oracle bounded execution did not verify completion")


if __name__ == "__main__":
    main()
