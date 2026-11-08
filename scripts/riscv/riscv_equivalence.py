#!/usr/bin/env python3
"""Retirement-level differential checker for the RV32IM frontend.

The semantic authority is the pinned Sail model. In automatic mode this tool:

1. runs the Zig ELF runner and reads its canonical RVFI-shaped JSON;
2. verifies the Sail binary's pinned model tag and Sail compiler version;
3. injects the same instruction sequence through Sail RVFI-DII v1; and
4. compares every retired instruction's PC, word, integer write, next PC,
   and memory effect.

Formal simulator builds apply the checked-in, hash-pinned transport-only
patch that changes RVFI-DII's entry from 0x8000_0000 to the zkVM corpus base
0x0001_0000. The checker verifies that entry behaviorally and never translates
PCs or PC-derived architectural values.

Manual mode compares two pre-existing canonical JSON traces:

  python3 scripts/riscv_equivalence.py trace_a.json trace_b.json

Automatic Sail mode:

  python3 scripts/riscv_equivalence.py --run program.elf \
      --sail-bin /path/to/sail_riscv_sim \
      [--zig-bin zig-out/bin/riscv-trace-dump] [--max-steps N]

The release-corpus gate also runs the same ELF under the independently pinned
Spike executable. Spike is a secondary implementation cross-check; Sail
remains the normative ISA authority.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import socket
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any

try:
    from riscv_equivalence_lib import contract, rvfi, sail_identity
except ModuleNotFoundError:  # Imported as scripts.riscv_equivalence in tests.
    from scripts.riscv_equivalence_lib import contract, rvfi, sail_identity


ROOT = rvfi.ROOT

PINNED_SAIL_REVISION = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
PINNED_SPIKE_REVISION = "520a5f185083ac3c97b751501dfac02a6c1f5970"
PINNED_SAIL_COMPILER_VERSION = "0.20.2"
PINNED_SAIL_TAG = "2026-07-20-8c7f2da"
PINNED_SPIKE_BANNER = "Spike RISC-V ISA Simulator 1.1.1-dev"
PINNED_RVFI_TRANSPORT_PATCH_SHA256 = (
    "1309655496ea8c8aae3cade751b1ba695dd19b2048f6118d28371be693dbb734"
)

TRACE_SCHEMA = contract.TRACE_SCHEMA
PROFILE = contract.PROFILE
RVFI_DII_ENTRY = 0x0001_0000
RVFI_DII_V1_BYTES = rvfi.RVFI_DII_V1_BYTES
MAX_DIFFERENCES = contract.MAX_DIFFERENCES

DEFAULT_ZIG_BIN = ROOT / "zig-out" / "bin" / "riscv-trace-dump"
RVFI_TRANSPORT_PATCH = rvfi.RVFI_TRANSPORT_PATCH
SAIL_CONFIG_OVERRIDES = rvfi.SAIL_CONFIG_OVERRIDES

RETIREMENT_FIELDS = contract.RETIREMENT_FIELDS
MEMORY_FIELDS = contract.MEMORY_FIELDS
SPIKE_MEMORY_MAP = "0x1000:0x210000"

if RVFI_DII_ENTRY != rvfi.RVFI_DII_ENTRY:
    raise RuntimeError("RVFI entry carrier disagrees with the wire-contract package")

_SPIKE_COMMIT = re.compile(
    r"^core\s+0:\s+\d+\s+0x([0-9a-fA-F]+)\s+"
    r"\(0x([0-9a-fA-F]+)\)(.*)$"
)
_SPIKE_EFFECTS = re.compile(
    r"^\s*(?:x(\d+)\s+0x([0-9a-fA-F]+))?"
    r"(?:\s+mem\s+0x([0-9a-fA-F]+)"
    r"(?:\s+0x([0-9a-fA-F]+))?)?\s*$"
)


EquivalenceError = contract.EquivalenceError
SailDisagreement = contract.SailDisagreement
load_trace = contract.load_trace
validate_trace = contract.validate_trace
compare_traces = contract.compare_traces
verify_sail_binary = sail_identity.verify_sail_binary


def verify_spike_binary(spike_bin: Path) -> dict[str, str]:
    """Fail closed unless the executable identifies the pinned Spike release."""
    result = subprocess.run(
        [str(spike_bin), "--help"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    help_text = (result.stdout + result.stderr).strip()
    if not help_text.startswith(PINNED_SPIKE_BANNER):
        raise EquivalenceError(f"{spike_bin}: unexpected Spike identity")
    return {
        "repository_revision": PINNED_SPIKE_REVISION,
        "banner": PINNED_SPIKE_BANNER,
        "binary_sha256": _sha256_file(spike_bin),
    }


def run_zig_trace(
    elf_path: Path,
    zig_bin: Path,
    max_steps: int,
    input_path: Path | None,
) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temporary:
        output_path = Path(temporary.name)
    try:
        command = [
            str(zig_bin),
            "--elf",
            str(elf_path),
            "--output",
            str(output_path),
            "--max-steps",
            str(max_steps),
        ]
        if input_path is not None:
            command.extend(("--input", str(input_path)))
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True)
        return load_trace(output_path)
    finally:
        output_path.unlink(missing_ok=True)


# Scratch registers of the memory-seeding preamble. x1/x2 are the RISC-V
# ra/sp conventions, but under RVFI-DII nothing has run yet, so they are
# ordinary zero-initialized registers the preamble may borrow and must return
# to zero — Sail's reset state — before the compared stream begins.
_SEED_ADDRESS_REGISTER = 1
_SEED_VALUE_REGISTER = 2
# One JAL hop reaches at most ±1 MiB; the jump back to the entry chains hops
# when the preamble itself is longer than that.
_JAL_MAX_BACKWARD = 1 << 20


def _encode_load_immediate(register: int, value: int) -> list[int]:
    """LUI+ADDI pair leaving exactly `value` (mod 2^32) in `register`.

    The +0x800 carry fold: ADDI sign-extends its 12-bit immediate, so the LUI
    half must carry one when the low half is negative. Encoding is derived,
    not tabulated, and the pinned Sail itself checks it live — a wrong pair
    seeds the wrong word and the differential fails loudly.
    """
    low = value & 0xFFF
    signed_low = low - 0x1000 if low >= 0x800 else low
    high = ((value - signed_low) & 0xFFFF_FFFF) >> 12
    return [
        (high << 12) | (register << 7) | 0x37,
        (low << 20) | (register << 15) | (register << 7) | 0x13,
    ]


def _encode_jal_x0(offset: int) -> int:
    """JAL x0 with the RV32I bit-scattered immediate (imm[20|10:1|11|19:12])."""
    if offset % 2 or not -(1 << 20) <= offset < (1 << 20):
        raise EquivalenceError(f"JAL offset {offset} is not encodable")
    value = offset & 0x1F_FFFF
    return (
        (((value >> 20) & 1) << 31)
        | (((value >> 1) & 0x3FF) << 21)
        | (((value >> 11) & 1) << 20)
        | (((value >> 12) & 0xFF) << 12)
        | 0x6F
    )


def seed_preamble(
    initial_memory: list[tuple[int, int]],
    entry: int = RVFI_DII_ENTRY,
) -> list[int]:
    """Instruction words that materialize an initial memory image inside Sail.

    RVFI-DII injects instruction words, so Sail never loads the guest's ELF:
    its memory starts zeroed, and a load of runner-initialized memory (a
    public-input region, ELF data) would falsely diverge. The preamble builds
    that image with Sail's own stores, then restores x1/x2 to their reset
    zeros and jumps back so the compared stream starts at `entry` in the
    reset register state with only memory changed.

    The image must come from the guest's *definition* — its ELF and declared
    input — never from the trace's own read claims, which would make every
    load self-fulfilling and reduce Sail to an echo of the candidate.
    """
    words: list[int] = []
    seen: set[int] = set()
    for address, value in initial_memory:
        _u32(address, "initial memory address")
        _u32(value, "initial memory value")
        if address % 4:
            raise EquivalenceError(
                f"initial memory address 0x{address:08x} is not word-aligned"
            )
        if address in seen:
            raise EquivalenceError(
                f"initial memory address 0x{address:08x} is seeded twice"
            )
        seen.add(address)
        words.extend(_encode_load_immediate(_SEED_ADDRESS_REGISTER, address))
        words.extend(_encode_load_immediate(_SEED_VALUE_REGISTER, value))
        words.append(  # SW x2, 0(x1)
            (_SEED_VALUE_REGISTER << 20)
            | (_SEED_ADDRESS_REGISTER << 15)
            | (0b010 << 12)
            | 0x23
        )
    words.append((_SEED_ADDRESS_REGISTER << 7) | 0x13)  # ADDI x1, x0, 0
    words.append((_SEED_VALUE_REGISTER << 7) | 0x13)  # ADDI x2, x0, 0
    # Straight-line execution has carried the pc to entry + 4*len(words);
    # chain backward jumps to land *exactly* on the entry, because the first
    # compared retirement's pc is itself a compared field.
    pc = entry + 4 * len(words)
    while pc != entry:
        hop = min(pc - entry, _JAL_MAX_BACKWARD)
        words.append(_encode_jal_x0(-hop))
        pc -= hop
    return words


def run_sail_rvfi_dii(
    sail_bin: Path,
    zig_trace: dict[str, Any],
    timeout_seconds: float = 10.0,
    initial_memory: list[tuple[int, int]] | None = None,
) -> dict[str, Any]:
    """Execute Zig's retired words through the pinned Sail RVFI-DII transport."""
    validate_trace(zig_trace, "Zig")
    target_entry = zig_trace["initial_pc"]
    if target_entry != RVFI_DII_ENTRY:
        raise EquivalenceError(
            f"Zig ELF entry is 0x{target_entry:08x}, "
            f"formal RVFI corpus entry must be 0x{RVFI_DII_ENTRY:08x}"
        )
    preamble = seed_preamble(initial_memory) if initial_memory else []
    port = _reserve_tcp_port()
    command = [str(sail_bin), "--rv32"]
    for override in SAIL_CONFIG_OVERRIDES:
        command.extend(("--config-override", str(override)))
    command.extend(("--rvfi-dii", str(port)))
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    connection: socket.socket | None = None
    try:
        connection = _connect_rvfi(process, port, timeout_seconds)
        connection.settimeout(timeout_seconds)
        for index, word in enumerate(preamble):
            connection.sendall(struct.pack("<Q", (1 << 48) | word))
            packet = decode_rvfi_dii_v1(_recv_exact(connection, RVFI_DII_V1_BYTES))
            if index == 0 and packet["pc"] != RVFI_DII_ENTRY:
                raise EquivalenceError(
                    f"Sail RVFI transport entry is 0x{packet['pc']:08x}, expected "
                    f"0x{RVFI_DII_ENTRY:08x}; build the pinned Sail revision "
                    f"with {RVFI_TRANSPORT_PATCH.relative_to(ROOT)}"
                )
            # A preamble word that traps says the image or the encoders are
            # broken — a harness failure, never evidence about the candidate.
            if packet["trap"] or packet["halt"] or packet["intr"]:
                raise EquivalenceError(
                    f"memory-seeding preamble word {index} "
                    f"(0x{word:08x}) did not retire cleanly"
                )
        rows: list[dict[str, Any]] = []
        for order, zig_row in enumerate(zig_trace["retirements"]):
            instruction = zig_row["instruction"]
            connection.sendall(struct.pack("<Q", (1 << 48) | instruction))
            packet = _recv_exact(connection, RVFI_DII_V1_BYTES)
            row = decode_rvfi_dii_v1(packet)
            if row.pop("trap"):
                raise SailDisagreement(
                    f"Sail trapped at retirement {order} for 0x{instruction:08x}"
                )
            if row.pop("halt") or row.pop("intr"):
                raise SailDisagreement(
                    f"Sail emitted unexpected halt/interrupt at retirement {order}"
                )
            if order == 0 and row["pc"] != RVFI_DII_ENTRY:
                if preamble:
                    raise EquivalenceError(
                        f"memory-seeding preamble landed at 0x{row['pc']:08x}, "
                        f"not the entry 0x{RVFI_DII_ENTRY:08x}"
                    )
                raise EquivalenceError(
                    f"Sail RVFI transport entry is 0x{row['pc']:08x}, expected "
                    f"0x{RVFI_DII_ENTRY:08x}; build the pinned Sail revision "
                    f"with {RVFI_TRANSPORT_PATCH.relative_to(ROOT)}"
                )
            row["order"] = order
            rows.append(row)

        # EndOfTrace command. Sail replies with one marked halt packet.
        connection.sendall(struct.pack("<Q", 0))
        halt_packet = decode_rvfi_dii_v1(
            _recv_exact(connection, RVFI_DII_V1_BYTES)
        )
        if not halt_packet["halt"]:
            raise EquivalenceError("Sail RVFI-DII did not acknowledge EndOfTrace")
        connection.close()
        connection = None
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        if process.returncode != 0:
            raise EquivalenceError(
                f"Sail RVFI-DII exited {process.returncode}: "
                f"{stderr.decode(errors='replace').strip()}"
            )
        final_pc = rows[-1]["next_pc"] if rows else target_entry
        trace = {
            "schema": TRACE_SCHEMA,
            "profile": PROFILE,
            "initial_pc": target_entry,
            "retirements": rows,
            "final_pc": final_pc,
            "total_steps": len(rows),
        }
        validate_trace(trace, "Sail")
        return trace
    except BaseException:
        if connection is not None:
            connection.close()
        process.terminate()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        raise


def run_sail_word(
    sail_bin: Path,
    instruction: int,
    *,
    expect_trap: bool,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Observe one word and require the declared Sail trap disposition."""
    _u32(instruction, "instruction")
    port = _reserve_tcp_port()
    command = [str(sail_bin), "--rv32"]
    for override in SAIL_CONFIG_OVERRIDES:
        command.extend(("--config-override", str(override)))
    command.extend(("--rvfi-dii", str(port)))
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    connection: socket.socket | None = None
    try:
        connection = _connect_rvfi(process, port, timeout_seconds)
        connection.settimeout(timeout_seconds)
        connection.sendall(struct.pack("<Q", (1 << 48) | instruction))
        row = decode_rvfi_dii_v1(_recv_exact(connection, RVFI_DII_V1_BYTES))
        if row["pc"] != RVFI_DII_ENTRY:
            raise EquivalenceError(
                f"Sail RVFI transport entry is 0x{row['pc']:08x}, expected "
                f"0x{RVFI_DII_ENTRY:08x}; build the pinned Sail revision "
                f"with {RVFI_TRANSPORT_PATCH.relative_to(ROOT)}"
            )
        if row["trap"] != expect_trap:
            disposition = "trap" if expect_trap else "retire"
            raise SailDisagreement(
                f"Sail did not {disposition} 0x{instruction:08x} as expected"
            )
        if row["halt"] or row["intr"]:
            raise SailDisagreement(
                f"Sail emitted halt/interrupt for rejected word 0x{instruction:08x}"
            )

        connection.sendall(struct.pack("<Q", 0))
        halt_packet = decode_rvfi_dii_v1(
            _recv_exact(connection, RVFI_DII_V1_BYTES)
        )
        if not halt_packet["halt"]:
            raise EquivalenceError("Sail RVFI-DII did not acknowledge EndOfTrace")
        connection.close()
        connection = None
        _, stderr = process.communicate(timeout=timeout_seconds)
        if process.returncode != 0:
            raise EquivalenceError(
                f"Sail RVFI-DII exited {process.returncode}: "
                f"{stderr.decode(errors='replace').strip()}"
            )
        return row
    except BaseException:
        if connection is not None:
            connection.close()
        process.terminate()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
        raise


def run_sail_rejection(
    sail_bin: Path,
    instruction: int,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Require one injected word to trap at the formal transport entry."""
    return run_sail_word(
        sail_bin,
        instruction,
        expect_trap=True,
        timeout_seconds=timeout_seconds,
    )


def run_spike_commit_trace(
    spike_bin: Path,
    elf_path: Path,
    zig_trace: dict[str, Any],
    timeout_seconds: float = 60.0,
) -> list[dict[str, int | None]]:
    """Run an exact number of retirements and decode Spike's commit log."""
    validate_trace(zig_trace, "Zig")
    if zig_trace["initial_pc"] != RVFI_DII_ENTRY:
        raise EquivalenceError(
            f"Zig ELF entry is 0x{zig_trace['initial_pc']:08x}, "
            f"Spike corpus entry must be 0x{RVFI_DII_ENTRY:08x}"
        )
    command = _spike_command(
        spike_bin,
        elf_path,
        zig_trace["total_steps"],
        log_instructions=False,
    )
    result = subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    rows = decode_spike_commit_log(result.stdout + result.stderr)
    if len(rows) != zig_trace["total_steps"]:
        raise EquivalenceError(
            f"Spike retired {len(rows)} instructions, "
            f"Zig retired {zig_trace['total_steps']}"
        )
    return rows


def decode_spike_commit_log(log: str) -> list[dict[str, int | None]]:
    """Decode the stable scalar commit-log shape emitted by pinned Spike."""
    rows: list[dict[str, int | None]] = []
    for line_number, line in enumerate(log.splitlines(), start=1):
        match = _SPIKE_COMMIT.fullmatch(line)
        if match is None:
            continue
        effects = _SPIKE_EFFECTS.fullmatch(match.group(3))
        if effects is None:
            raise EquivalenceError(
                f"Spike commit log line {line_number} has unknown effects: {line!r}"
            )
        rd_text, rd_value_text, memory_address_text, memory_value_text = (
            effects.groups()
        )
        rows.append(
            {
                "pc": int(match.group(1), 16) & 0xFFFF_FFFF,
                "instruction": int(match.group(2), 16) & 0xFFFF_FFFF,
                "rd": int(rd_text) if rd_text is not None else 0,
                "rd_value": (
                    int(rd_value_text, 16) & 0xFFFF_FFFF
                    if rd_value_text is not None
                    else 0
                ),
                "memory_address": (
                    int(memory_address_text, 16) & 0xFFFF_FFFF
                    if memory_address_text is not None
                    else None
                ),
                # Loads log only their address; stores additionally log the
                # exact value written at the architectural access width.
                "memory_write_value": (
                    int(memory_value_text, 16) & 0xFFFF_FFFF
                    if memory_value_text is not None
                    else None
                ),
            }
        )
    return rows


def compare_spike_commit_trace(
    spike_rows: list[dict[str, int | None]],
    zig_trace: dict[str, Any],
) -> list[str]:
    """Compare every architectural field exposed by Spike's commit log."""
    validate_trace(zig_trace, "Zig")
    errors: list[str] = []
    zig_rows = zig_trace["retirements"]
    if len(spike_rows) != len(zig_rows):
        errors.append(
            f"retirement count: Spike={len(spike_rows)} Zig={len(zig_rows)}"
        )
    for order, (spike, zig) in enumerate(zip(spike_rows, zig_rows)):
        for field in ("pc", "instruction", "rd", "rd_value"):
            if spike[field] != zig[field]:
                errors.append(
                    f"retirement {order}.{field}: "
                    f"Spike=0x{int(spike[field] or 0):08x} "
                    f"Zig=0x{zig[field]:08x}"
                )
        memory = zig["memory"]
        has_memory = bool(memory["read_mask"] or memory["write_mask"])
        expected_address = memory["address"] if has_memory else None
        if spike["memory_address"] != expected_address:
            errors.append(
                f"retirement {order}.memory.address: "
                f"Spike={_optional_hex(spike['memory_address'])} "
                f"Zig={_optional_hex(expected_address)}"
            )
        expected_write = (
            memory["write_value"] if memory["write_mask"] != 0 else None
        )
        if spike["memory_write_value"] != expected_write:
            errors.append(
                f"retirement {order}.memory.write_value: "
                f"Spike={_optional_hex(spike['memory_write_value'])} "
                f"Zig={_optional_hex(expected_write)}"
            )
        if order + 1 < len(spike_rows):
            spike_next_pc = spike_rows[order + 1]["pc"]
            if spike_next_pc != zig["next_pc"]:
                errors.append(
                    f"retirement {order}.next_pc: "
                    f"Spike=0x{int(spike_next_pc or 0):08x} "
                    f"Zig=0x{zig['next_pc']:08x}"
                )
        if len(errors) >= MAX_DIFFERENCES:
            return errors
    return errors


def run_spike_disposition(
    spike_bin: Path,
    elf_path: Path,
    instruction: int,
    *,
    expect_trap: bool,
    timeout_seconds: float = 10.0,
) -> None:
    """Require Spike to trap or retire one profile-test instruction."""
    result = subprocess.run(
        _spike_command(spike_bin, elf_path, 1, log_instructions=True),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )
    log = result.stdout + result.stderr
    rows = decode_spike_commit_log(log)
    trap_at_entry = re.search(
        rf"exception\s+trap_[^\s,]+,\s+epc\s+0x{RVFI_DII_ENTRY:08x}\b",
        log,
    )
    if expect_trap:
        if trap_at_entry is None or rows:
            raise EquivalenceError(
                f"Spike did not trap 0x{instruction:08x} before retirement"
            )
        return
    if trap_at_entry is not None or len(rows) != 1:
        raise EquivalenceError(
            f"Spike did not retire profile-excluded word 0x{instruction:08x}"
        )
    if rows[0]["pc"] != RVFI_DII_ENTRY or rows[0]["instruction"] != instruction:
        raise EquivalenceError(
            f"Spike retired the wrong word for profile exclusion 0x{instruction:08x}"
        )


def _spike_command(
    spike_bin: Path,
    elf_path: Path,
    instructions: int,
    *,
    log_instructions: bool,
) -> list[str]:
    command = [
        str(spike_bin),
        "--isa=RV32IM",
        "--priv=M",
        "--disable-dtb",
        f"-m{SPIKE_MEMORY_MAP}",
        f"--pc=0x{RVFI_DII_ENTRY:x}",
        f"--instructions={instructions}",
    ]
    if log_instructions:
        command.append("-l")
    command.extend(("--log-commits", str(elf_path)))
    return command


decode_rvfi_dii_v1 = rvfi.decode_rvfi_dii_v1


def run_equivalence(
    elf_path: str | os.PathLike[str],
    sail_bin: str | os.PathLike[str],
    zig_bin: str | os.PathLike[str] = DEFAULT_ZIG_BIN,
    max_steps: int = 100_000,
    input_path: str | os.PathLike[str] | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Run Zig and Sail and return differential errors plus Sail provenance."""
    sail_path = Path(sail_bin).resolve()
    zig_path = Path(zig_bin).resolve()
    identity = verify_sail_binary(sail_path)
    zig_trace = run_zig_trace(
        Path(elf_path).resolve(),
        zig_path,
        max_steps,
        Path(input_path).resolve() if input_path is not None else None,
    )
    sail_trace = run_sail_rvfi_dii(sail_path, zig_trace)
    return compare_traces(sail_trace, zig_trace), identity


_reserve_tcp_port = rvfi.reserve_tcp_port
_connect_rvfi = rvfi.connect_rvfi
_recv_exact = rvfi.recv_exact
_u32 = contract.u32


def _optional_hex(value: int | None) -> str:
    return "none" if value is None else f"0x{value:08x}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("traces", nargs="*", help="two canonical trace JSON files")
    parser.add_argument("--run", type=Path, metavar="ELF", help="run Zig and pinned Sail")
    parser.add_argument("--sail-bin", type=Path, help="pinned sail_riscv_sim executable")
    parser.add_argument("--zig-bin", type=Path, default=DEFAULT_ZIG_BIN)
    parser.add_argument("--input", type=Path, help="guest input file for the Zig runner")
    parser.add_argument("--max-steps", type=int, default=100_000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.run is not None:
            if args.traces or args.sail_bin is None:
                raise EquivalenceError(
                    "--run requires --sail-bin and cannot be combined with trace paths"
                )
            if args.max_steps <= 0:
                raise EquivalenceError("--max-steps must be positive")
            errors, identity = run_equivalence(
                args.run,
                args.sail_bin,
                args.zig_bin,
                args.max_steps,
                args.input,
            )
            print(
                "Sail authority "
                f"{identity['repository_revision']} "
                f"(compiler {identity['compiler_version']}, "
                f"binary {identity['binary_sha256']})"
            )
        else:
            if len(args.traces) != 2 or args.sail_bin is not None or args.input is not None:
                raise EquivalenceError(
                    "manual mode requires exactly two trace paths"
                )
            authority = load_trace(args.traces[0])
            candidate = load_trace(args.traces[1])
            errors = compare_traces(authority, candidate, "trace-a", "trace-b")
    except (EquivalenceError, OSError, subprocess.SubprocessError) as error:
        print(f"riscv equivalence: {error}", file=os.sys.stderr)
        return 2

    if errors:
        print(f"DIVERGENCE ({len(errors)} difference(s)):")
        for error in errors:
            print(f"- {error}")
        return 1
    print("EQUIVALENT: every architectural retirement field matches.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
