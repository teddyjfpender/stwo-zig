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
import json
import os
import re
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent

PINNED_SAIL_REVISION = "8c7f2da58de0ba5e4457e4de07e0046f0439f35f"
PINNED_SPIKE_REVISION = "520a5f185083ac3c97b751501dfac02a6c1f5970"
PINNED_SAIL_COMPILER_VERSION = "0.20.2"
PINNED_SAIL_TAG = "2026-07-20-8c7f2da"
PINNED_SPIKE_BANNER = "Spike RISC-V ISA Simulator 1.1.1-dev"
PINNED_RVFI_TRANSPORT_PATCH_SHA256 = (
    "1309655496ea8c8aae3cade751b1ba695dd19b2048f6118d28371be693dbb734"
)

TRACE_SCHEMA = "stwo-riscv-retirement-trace-v1"
PROFILE = "rv32im-zkvm-v1"
RVFI_DII_ENTRY = 0x0001_0000
RVFI_DII_V1_BYTES = 88
MAX_DIFFERENCES = 64

DEFAULT_ZIG_BIN = ROOT / "zig-out" / "bin" / "riscv-trace-dump"
RVFI_TRANSPORT_PATCH = (
    ROOT / "conformance" / "riscv" / "sail-rvfi-zkvm-entry.patch"
)
SAIL_CONFIG_OVERRIDES = (
    ROOT / "conformance" / "riscv" / "sail-rv32im-override.json",
    ROOT / "conformance" / "riscv" / "sail-rv32im-tagged-options.json",
)

RETIREMENT_FIELDS = ("pc", "instruction", "rd", "rd_value", "next_pc")
MEMORY_FIELDS = ("address", "read_mask", "read_value", "write_mask", "write_value")
SPIKE_MEMORY_MAP = "0x1000:0x210000"

_SPIKE_COMMIT = re.compile(
    r"^core\s+0:\s+\d+\s+0x([0-9a-fA-F]+)\s+"
    r"\(0x([0-9a-fA-F]+)\)(.*)$"
)
_SPIKE_EFFECTS = re.compile(
    r"^\s*(?:x(\d+)\s+0x([0-9a-fA-F]+))?"
    r"(?:\s+mem\s+0x([0-9a-fA-F]+)"
    r"(?:\s+0x([0-9a-fA-F]+))?)?\s*$"
)


class EquivalenceError(ValueError):
    """A trace or external formal-model boundary is malformed."""


class SailDisagreement(EquivalenceError):
    """The pinned Sail model was consulted and contradicts the candidate.

    Raised only after the Sail session is answering, for outcomes that are
    Sail semantics rather than harness failures: a trap, halt, or interrupt
    where the candidate claims a successful retirement, or a declared trap
    disposition Sail refuses. Consumers that skip when Sail is *absent* must
    still fail loudly on this type; folding it into a generic error is how a
    real divergence gets misread as infrastructure noise.
    """


def load_trace(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Load and validate one canonical retirement trace."""
    with Path(path).open(encoding="utf-8") as handle:
        value = json.load(handle)
    validate_trace(value, str(path))
    return value


def validate_trace(trace: Any, label: str = "trace") -> None:
    if not isinstance(trace, dict):
        raise EquivalenceError(f"{label}: root must be an object")
    if trace.get("schema") != TRACE_SCHEMA:
        raise EquivalenceError(
            f"{label}: schema is {trace.get('schema')!r}, expected {TRACE_SCHEMA!r}"
        )
    if trace.get("profile") != PROFILE:
        raise EquivalenceError(
            f"{label}: profile is {trace.get('profile')!r}, expected {PROFILE!r}"
        )
    rows = trace.get("retirements")
    if not isinstance(rows, list):
        raise EquivalenceError(f"{label}: retirements must be an array")
    if trace.get("total_steps") != len(rows):
        raise EquivalenceError(f"{label}: total_steps does not match retirements")
    for order, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("order") != order:
            raise EquivalenceError(f"{label}: non-canonical retirement order at {order}")
        for field in RETIREMENT_FIELDS:
            _u32(row.get(field), f"{label}: retirement {order}.{field}")
        memory = row.get("memory")
        if not isinstance(memory, dict) or set(memory) != set(MEMORY_FIELDS):
            raise EquivalenceError(
                f"{label}: retirement {order}.memory has a non-canonical shape"
            )
        for field in MEMORY_FIELDS:
            value = _u32(memory.get(field), f"{label}: retirement {order}.memory.{field}")
            if field.endswith("_mask") and value > 0xF:
                raise EquivalenceError(
                    f"{label}: retirement {order}.memory.{field} exceeds RV32 width"
                )
    if "final_pc" in trace:
        _u32(trace["final_pc"], f"{label}: final_pc")
    if "final_regs" in trace:
        regs = trace["final_regs"]
        if not isinstance(regs, list) or len(regs) != 32:
            raise EquivalenceError(f"{label}: final_regs must contain 32 words")
        for index, value in enumerate(regs):
            _u32(value, f"{label}: final_regs[{index}]")
        if regs[0] != 0:
            raise EquivalenceError(f"{label}: final_regs[0] is not hard-wired zero")


def compare_traces(
    authoritative: dict[str, Any],
    candidate: dict[str, Any],
    authoritative_name: str = "Sail",
    candidate_name: str = "Zig",
) -> list[str]:
    """Return precise retirement differences between two canonical traces."""
    validate_trace(authoritative, authoritative_name)
    validate_trace(candidate, candidate_name)
    errors: list[str] = []
    authority_rows = authoritative["retirements"]
    candidate_rows = candidate["retirements"]
    if len(authority_rows) != len(candidate_rows):
        errors.append(
            f"retirement count: {authoritative_name}={len(authority_rows)} "
            f"{candidate_name}={len(candidate_rows)}"
        )

    for order, (expected, actual) in enumerate(zip(authority_rows, candidate_rows)):
        for field in RETIREMENT_FIELDS:
            if expected[field] != actual[field]:
                errors.append(
                    f"retirement {order}.{field}: "
                    f"{authoritative_name}=0x{expected[field]:08x} "
                    f"{candidate_name}=0x{actual[field]:08x}"
                )
                if len(errors) >= MAX_DIFFERENCES:
                    return errors
        for field in MEMORY_FIELDS:
            expected_value = expected["memory"][field]
            actual_value = actual["memory"][field]
            if expected_value != actual_value:
                errors.append(
                    f"retirement {order}.memory.{field}: "
                    f"{authoritative_name}=0x{expected_value:08x} "
                    f"{candidate_name}=0x{actual_value:08x}"
                )
                if len(errors) >= MAX_DIFFERENCES:
                    return errors

    if "final_pc" in authoritative and "final_pc" in candidate:
        if authoritative["final_pc"] != candidate["final_pc"]:
            errors.append(
                f"final_pc: {authoritative_name}=0x{authoritative['final_pc']:08x} "
                f"{candidate_name}=0x{candidate['final_pc']:08x}"
            )
    if "final_regs" in authoritative and "final_regs" in candidate:
        for index, (expected, actual) in enumerate(
            zip(authoritative["final_regs"], candidate["final_regs"])
        ):
            if expected != actual:
                errors.append(
                    f"final_regs[{index}]: {authoritative_name}=0x{expected:08x} "
                    f"{candidate_name}=0x{actual:08x}"
                )
                if len(errors) >= MAX_DIFFERENCES:
                    return errors
    return errors


def verify_sail_binary(sail_bin: Path) -> dict[str, str]:
    """Fail closed unless the executable identifies the pinned model/toolchain."""
    patch_sha256 = _sha256_file(RVFI_TRANSPORT_PATCH)
    if patch_sha256 != PINNED_RVFI_TRANSPORT_PATCH_SHA256:
        raise EquivalenceError(
            f"{RVFI_TRANSPORT_PATCH}: SHA-256 is {patch_sha256}, "
            f"expected {PINNED_RVFI_TRANSPORT_PATCH_SHA256}"
        )
    result = subprocess.run(
        [str(sail_bin), "--build-info"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    build_info = result.stdout + result.stderr
    expected = (
        f"Sail RISC-V git: {PINNED_SAIL_TAG}",
        f"Sail: Sail {PINNED_SAIL_COMPILER_VERSION} ",
    )
    missing = [line for line in expected if line not in build_info]
    if missing:
        raise EquivalenceError(
            f"{sail_bin}: build identity does not contain {missing!r}"
        )
    return {
        "repository_revision": PINNED_SAIL_REVISION,
        "model_tag": PINNED_SAIL_TAG,
        "compiler_version": PINNED_SAIL_COMPILER_VERSION,
        "binary_sha256": _sha256_file(sail_bin),
        "transport_patch_sha256": patch_sha256,
    }


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


def run_sail_rvfi_dii(
    sail_bin: Path,
    zig_trace: dict[str, Any],
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Execute Zig's retired words through the pinned Sail RVFI-DII transport."""
    validate_trace(zig_trace, "Zig")
    target_entry = zig_trace["initial_pc"]
    if target_entry != RVFI_DII_ENTRY:
        raise EquivalenceError(
            f"Zig ELF entry is 0x{target_entry:08x}, "
            f"formal RVFI corpus entry must be 0x{RVFI_DII_ENTRY:08x}"
        )
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


def decode_rvfi_dii_v1(packet: bytes) -> dict[str, Any]:
    """Decode the official 704-bit RVFI-DII v1 little-endian packet."""
    if len(packet) != RVFI_DII_V1_BYTES:
        raise EquivalenceError(
            f"RVFI-DII packet has {len(packet)} bytes, expected {RVFI_DII_V1_BYTES}"
        )
    words = struct.unpack("<11Q", packet)
    return {
        "order": words[0],
        "pc": words[1] & 0xFFFF_FFFF,
        "next_pc": words[2] & 0xFFFF_FFFF,
        "instruction": words[3] & 0xFFFF_FFFF,
        "rd_value": words[6] & 0xFFFF_FFFF,
        "memory": {
            "address": words[7] & 0xFFFF_FFFF,
            "read_value": words[8] & 0xFFFF_FFFF,
            "write_value": words[9] & 0xFFFF_FFFF,
            "read_mask": packet[80] & 0xF,
            "write_mask": packet[81] & 0xF,
        },
        "rd": packet[84] & 0x1F,
        "trap": packet[85] != 0,
        "halt": packet[86] != 0,
        "intr": packet[87] != 0,
    }


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


def _reserve_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _connect_rvfi(
    process: subprocess.Popen[bytes],
    port: int,
    timeout_seconds: float,
) -> socket.socket:
    deadline = time.monotonic() + timeout_seconds
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _, stderr = process.communicate()
            raise EquivalenceError(
                f"Sail exited before RVFI connection: "
                f"{stderr.decode(errors='replace').strip()}"
            )
        try:
            return socket.create_connection(("127.0.0.1", port), timeout=0.1)
        except OSError as error:
            last_error = error
            time.sleep(0.01)
    raise EquivalenceError(f"timed out connecting to Sail RVFI-DII: {last_error}")


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise EquivalenceError(
                f"Sail RVFI-DII closed after {len(result)} of {size} bytes"
            )
        result.extend(chunk)
    return bytes(result)


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF_FFFF:
        raise EquivalenceError(f"{label} must be a u32, found {value!r}")
    return value


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
