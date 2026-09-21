#!/usr/bin/env python3
"""Capture and strictly replay exact Revm-42 analyze_legacy observations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any


REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts import ethereum_block_proof_process as child_process  # noqa: E402
from scripts import ethereum_block_proof_protocol as protocol  # noqa: E402
from scripts import ethereum_block_proof_store as store  # noqa: E402
import ethereum_block_function_value_evidence as function_value  # noqa: E402


SCHEMA = "stwo.riscv.analyze-legacy-semantic-observation.v1"
STATUS = "captured-diagnostic-only"
CLAIM_BOUNDARY = "exact-revm42-execution-observation-not-air-or-proof"
PROFILE = "rv32im-zkvm-ethereum-v1"
CLOCK_FRAME = "leaf_local"
REVM_SOURCE_SHA256 = "cf26e05a027549b772a04ff4f2ad7bcd03eaaa5dbd42d53f03830050504671d4"
CARGO_LOCK_SHA256 = "17b841e66b7017edd621877bcbbd76ad50242d648e6dd49667d6e05dc3c46ce9"
REVM_REVISION = "45f05bd88fd09e32ea43cf5e94190759ea6ace7c"
FUNCTION_START = 0x000BD490
FUNCTION_END = 0x000BD9E8
FUNCTION_ROWS = 6_846_967
CALL_COUNT = 115
LEGACY_BYTES = 1_328_485
TOTAL_CODE_BYTES = 1_328_577
FALLBACK_INDICES = {4, 30, 70, 110, 119}
MAX_SECONDS = 60
MAX_OUTPUT_BYTES = store.MAX_JSON_BYTES
MAX_STDERR_BYTES = 64 * 1024
U32_MAX = (1 << 32) - 1
U64_MAX = (1 << 64) - 1
SHA = re.compile(r"[0-9a-f]{64}\Z")
NM_LINE = re.compile(r"^([0-9a-f]{8}) ([tT]) (.+)$")

TOP_KEYS = {
    "aggregate", "calls", "claim_boundary", "clock_frame", "content_sha256",
    "elf", "execution_journal", "execution_profile", "first_global_cycle",
    "first_segment_index", "function_authority", "function_value_evidence",
    "input", "nm_map", "observer_executable", "observer_semantics_source",
    "observer_source", "observer_witness_source", "pc_observation", "production", "promotion",
    "retired_instructions", "revm_cargo_lock", "revm_source", "sampled_cycles",
    "schema", "segment_count", "status", "witness_code_inventory",
    "witness_codes",
}
CALL_KEYS = {
    "bitmap_bytes", "bytes_struct_pointer", "call_index", "entry_clock",
    "entry_segment_index", "eof_immediate_padding", "jumpdest_count", "length",
    "length_clock", "observation_segment_index", "opcode_positions", "pointer_clock",
    "push_count", "push_overflow", "scan_iterations", "source_bytes_sha256",
    "source_pointer", "total_padding", "witness_code_index",
}
IDENTITY_KEYS = {"bytes", "path", "sha256"}


class AnalyzeLegacyEvidenceError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AnalyzeLegacyEvidenceError(message)


def _integer(
    value: Any,
    where: str,
    *,
    minimum: int = 0,
    maximum: int = U64_MAX,
) -> int:
    _require(type(value) is int and minimum <= value <= maximum, f"{where} differs")
    return value


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA.fullmatch(value) is not None, f"{where} differs")
    return value


def _identity(path: Path, where: str) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), where)
    canonical = path.resolve(strict=True)
    return {
        "bytes": len(raw),
        "path": str(canonical),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_identity(value: Any, where: str) -> bytes:
    _require(
        type(value) is dict
        and set(value) == IDENTITY_KEYS
        and type(value["path"]) is str
        and Path(value["path"]).is_absolute(),
        f"{where} identity shape differs",
    )
    _integer(value["bytes"], f"{where}.bytes")
    _sha(value["sha256"], f"{where}.sha256")
    path = Path(value["path"])
    raw = store.read_regular(path, where)
    _require(
        value == {
            "bytes": len(raw),
            "path": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
        },
        f"{where} identity differs",
    )
    return raw


def _u32(raw: bytes, offset: int, where: str) -> int:
    _require(0 <= offset <= len(raw) - 4, f"{where} offset differs")
    return int.from_bytes(raw[offset:offset + 4], "little")


def _decode_witness_codes(transport: bytes) -> list[dict[str, Any]]:
    _require(len(transport) >= 6, "stateless input is truncated")
    canonical_length = _u32(transport, 0, "transport")
    _require(
        canonical_length == len(transport) - 4 and transport[4:6] == b"\x14\x01",
        "stateless input framing differs",
    )
    body = transport[6:]
    _require(len(body) >= 20, "stateless input body is truncated")
    payload_offset = _u32(body, 0, "payload")
    witness_offset = _u32(body, 4, "witness")
    public_keys_offset = _u32(body, 16, "public keys")
    _require(
        payload_offset == 20
        and payload_offset <= witness_offset <= public_keys_offset <= len(body),
        "stateless input container offsets differ",
    )
    witness = body[witness_offset:public_keys_offset]
    _require(len(witness) >= 12, "witness is truncated")
    state_offset = _u32(witness, 0, "witness state")
    codes_offset = _u32(witness, 4, "witness codes")
    headers_offset = _u32(witness, 8, "witness headers")
    _require(
        state_offset == 12 and state_offset <= codes_offset <= headers_offset <= len(witness),
        "witness container offsets differ",
    )
    encoded = witness[codes_offset:headers_offset]
    if not encoded:
        return []
    first = _u32(encoded, 0, "code list")
    _require(first > 0 and first % 4 == 0 and first <= len(encoded),
             "code list first offset differs")
    count = first // 4
    offsets = [_u32(encoded, index * 4, f"code {index}") for index in range(count)]
    codes: list[dict[str, Any]] = []
    for index, start in enumerate(offsets):
        end = offsets[index + 1] if index + 1 < count else len(encoded)
        _require(first <= start <= end <= len(encoded), f"code {index} bounds differ")
        raw = encoded[start:end]
        classification = (
            "empty-bytecode-new-raw" if not raw else
            "eip7702-delegation-new-raw" if raw.startswith(b"\xef\x01") else
            "legacy-analyze-legacy"
        )
        codes.append({
            "bytes": raw,
            "classification": classification,
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    return codes


def _analyze(code: bytes) -> dict[str, Any]:
    position = 0
    previous = 0
    last = 0
    positions: list[int] = []
    push_count = 0
    jumpdest_count = 0
    while position < len(code):
        positions.append(position)
        previous, last = last, code[position]
        if last == 0x5B:
            jumpdest_count += 1
            position += 1
        else:
            push_offset = (last - 0x60) & 0xFF
            if push_offset < 32:
                push_count += 1
                position += push_offset + 2
            else:
                position += 1
    push_overflow = position - len(code)
    special = lambda opcode: ((opcode - 0xE6) & 0xFF) < 3
    eof_padding = int(special(previous)) if last == 0 else 1 + int(special(last))
    return {
        "bitmap_bytes": (len(code) + 7) // 8,
        "eof_immediate_padding": eof_padding,
        "jumpdest_count": jumpdest_count,
        "opcode_positions": positions,
        "push_count": push_count,
        "push_overflow": push_overflow,
        "scan_iterations": len(positions),
        "total_padding": push_overflow + eof_padding,
    }


def _validate_nm(raw: bytes) -> None:
    try:
        lines = raw.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise AnalyzeLegacyEvidenceError("nm map is not UTF-8") from error
    found = False
    for line in lines:
        match = NM_LINE.fullmatch(line)
        if match is None:
            continue
        address = int(match.group(1), 16)
        if not found:
            if address == FUNCTION_START and match.group(3) == (
                "revm_bytecode::legacy::analysis::analyze_legacy"
            ):
                found = True
            continue
        if address == FUNCTION_START:
            continue
        _require(address == FUNCTION_END, "analyze_legacy nm interval differs")
        return
    raise AnalyzeLegacyEvidenceError("analyze_legacy nm symbol is absent")


def _validate_pc_observation(raw: bytes, value: dict[str, Any]) -> None:
    observation = store.decode_strict(raw)
    expected_keys = {
        "basic_edges", "clock_frame", "content_sha256", "distinct_basic_edge_count",
        "distinct_pc_count", "elf_sha256", "execution_profile", "first_global_cycle",
        "first_segment_index", "input_sha256", "opcode_transitions", "per_pc",
        "production", "retired_instructions", "sampled_cycles", "schema",
        "segment_count", "source_sha256", "status", "transition_count",
        "transition_scope",
    }
    _require(
        type(observation) is dict
        and set(observation) == expected_keys
        and raw == protocol.canonical_bytes(observation)
        and observation["content_sha256"] == protocol.content_sha256(observation),
        "PC observation seal differs",
    )
    _require(
        observation["schema"] == "stwo.riscv.retirement-pc-hotspot-observation.v1"
        and observation["production"] is False
        and observation["clock_frame"] == CLOCK_FRAME
        and observation["execution_profile"] == PROFILE,
        "PC observation authority differs",
    )
    rows = 0
    total = 0
    previous_pc = -1
    for index, row in enumerate(observation["per_pc"]):
        _require(
            type(row) is dict and set(row) == {"count", "opcode_family", "pc"}
            and type(row["opcode_family"]) is str,
            f"PC observation row {index} differs",
        )
        pc = _integer(row["pc"], f"PC row {index}.pc", maximum=U32_MAX)
        count = _integer(row["count"], f"PC row {index}.count", minimum=1)
        _require(pc > previous_pc, "PC observation order differs")
        previous_pc = pc
        total += count
        if FUNCTION_START <= pc < FUNCTION_END:
            rows += count
    _require(
        rows == FUNCTION_ROWS
        and total == observation["retired_instructions"] == value["retired_instructions"]
        and observation["sampled_cycles"] == value["sampled_cycles"]
        and observation["segment_count"] == value["segment_count"]
        and observation["elf_sha256"] == value["elf"]["sha256"]
        and observation["input_sha256"] == value["input"]["sha256"]
        and observation["source_sha256"] == value["execution_journal"]["sha256"],
        "PC observation closure differs",
    )


def _promotion() -> dict[str, Any]:
    return {
        "air_claim": None,
        "end_to_end_wall_ns": None,
        "fresh_verification": None,
        "performance_claim_eligible": False,
        "production_promotion_eligible": False,
        "proof_correctness": None,
        "savings_claim": None,
        "scope": "exact-analyze-legacy-call-semantics-only",
    }


def _function_authority() -> dict[str, Any]:
    return {
        "entry_instruction_word": 0xFC010113,
        "entry_pc": FUNCTION_START,
        "length_imm": 8,
        "length_instruction_word": 0x0085A903,
        "length_pc": 0x000BD4C4,
        "length_rd": 18,
        "length_rs1": 11,
        "revm_bytecode_version": "42.0.0",
        "revm_git_revision": REVM_REVISION,
        "source_pointer_imm": 4,
        "source_pointer_instruction_word": 0x0044AA83,
        "source_pointer_pc": 0x000BD5C4,
        "source_pointer_rd": 21,
        "source_pointer_rs1": 9,
        "symbol": "revm_bytecode::legacy::analysis::analyze_legacy",
        "symbol_end_exclusive": FUNCTION_END,
        "symbol_rows": FUNCTION_ROWS,
    }


def validate(value: Any) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == TOP_KEYS,
             "analyze_legacy observation keys differ")
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["claim_boundary"] == CLAIM_BOUNDARY
        and value["execution_profile"] == PROFILE
        and value["clock_frame"] == CLOCK_FRAME
        and value["production"] is False
        and value["promotion"] == _promotion()
        and value["function_authority"] == _function_authority(),
        "analyze_legacy observation authority differs",
    )
    _sha(value["content_sha256"], "observation content seal")
    _require(value["content_sha256"] == protocol.content_sha256(value),
             "analyze_legacy content seal differs")
    identities: dict[str, bytes] = {}
    for field in (
        "elf", "execution_journal", "function_value_evidence", "input", "nm_map",
        "observer_executable", "observer_semantics_source", "observer_source",
        "observer_witness_source", "pc_observation", "revm_cargo_lock", "revm_source",
    ):
        identities[field] = _validate_identity(value[field], field.replace("_", " "))
    _require(
        value["revm_source"]["sha256"] == REVM_SOURCE_SHA256
        and value["revm_cargo_lock"]["sha256"] == CARGO_LOCK_SHA256,
        "Revm source custody differs",
    )
    _validate_nm(identities["nm_map"])
    _validate_pc_observation(identities["pc_observation"], value)
    source_function_value = function_value.load(Path(value["function_value_evidence"]["path"]))
    observed_lengths = source_function_value["observation"]
    _require(
        observed_lengths["entry_count"] == observed_lengths["value_count"] == CALL_COUNT
        and observed_lengths["pending_entry_count"] == 0
        and observed_lengths["value_sum"] == LEGACY_BYTES
        and observed_lengths["elf_sha256"] == value["elf"]["sha256"]
        and observed_lengths["input_sha256"] == value["input"]["sha256"]
        and observed_lengths["source_sha256"] == value["execution_journal"]["sha256"],
        "function-value cross-binding differs",
    )

    codes = _decode_witness_codes(identities["input"])
    _require(len(codes) == 120 and sum(len(code["bytes"]) for code in codes) == TOTAL_CODE_BYTES,
             "witness code inventory differs")
    legacy_indices = {
        index for index, code in enumerate(codes)
        if code["classification"] == "legacy-analyze-legacy"
    }
    fallback_indices = set(range(len(codes))) - legacy_indices
    _require(
        len(legacy_indices) == CALL_COUNT
        and sum(len(codes[index]["bytes"]) for index in legacy_indices) == LEGACY_BYTES
        and fallback_indices == FALLBACK_INDICES
        and all(
            len(codes[index]["bytes"]) == 23
            and codes[index]["classification"] == "eip7702-delegation-new-raw"
            for index in (4, 30, 70, 110)
        )
        and codes[119]["classification"] == "empty-bytecode-new-raw",
        "witness legacy/fallback routing differs",
    )
    wire_codes = value["witness_codes"]
    _require(type(wire_codes) is list and len(wire_codes) == len(codes),
             "witness code wires differ")
    for index, (wire, code) in enumerate(zip(wire_codes, codes, strict=True)):
        _require(
            type(wire) is dict
            and set(wire) == {
                "analyze_legacy_observed", "classification", "index", "length", "sha256",
            }
            and wire == {
                "analyze_legacy_observed": index in legacy_indices,
                "classification": code["classification"],
                "index": index,
                "length": len(code["bytes"]),
                "sha256": code["sha256"],
            },
            f"witness code {index} differs",
        )
    inventory = value["witness_code_inventory"]
    _require(inventory == {
        "accessed_legacy_code_count": CALL_COUNT,
        "code_count": 120,
        "eip7702_delegation_code_count": 4,
        "empty_code_count": 1,
        "legacy_bytes": LEGACY_BYTES,
        "legacy_code_count": CALL_COUNT,
        "routing_policy": "legacy=>analyze_legacy;empty-or-0xef01=>Bytecode::new_raw",
        "total_bytes": TOTAL_CODE_BYTES,
        "unobserved_fallback_code_count": 5,
    }, "witness code inventory closure differs")

    calls = value["calls"]
    _require(type(calls) is list and len(calls) == CALL_COUNT,
             "analyze_legacy calls differ")
    observed_indices: set[int] = set()
    source_chain = hashlib.sha256(b"stwo.riscv.analyze-legacy-source-bytes-chain.v1\x00")
    aggregate = {
        "bitmap_bytes_sum": 0,
        "call_count": CALL_COUNT,
        "eof_immediate_padding_sum": 0,
        "jumpdest_count_sum": 0,
        "length_sum": 0,
        "opcode_positions_sum": 0,
        "push_count_sum": 0,
        "push_overflow_sum": 0,
        "scan_iterations_sum": 0,
        "source_bytes_chain_sha256": None,
        "total_padding_sum": 0,
    }
    call_lengths: list[int] = []
    for ordinal, call in enumerate(calls):
        _require(type(call) is dict and set(call) == CALL_KEYS,
                 f"call {ordinal} keys differ")
        _require(call["call_index"] == ordinal,
                 f"call {ordinal} ordinal differs")
        code_index = _integer(
            call["witness_code_index"], f"call {ordinal} code index", maximum=119,
        )
        _require(code_index in legacy_indices and code_index not in observed_indices,
                 f"call {ordinal} witness authority differs")
        observed_indices.add(code_index)
        code = codes[code_index]["bytes"]
        analysis = _analyze(code)
        for field, expected in analysis.items():
            _require(call[field] == expected, f"call {ordinal} {field} differs")
        _require(
            call["length"] == len(code)
            and call["source_bytes_sha256"] == codes[code_index]["sha256"],
            f"call {ordinal} source bytes differ",
        )
        for field in (
            "bytes_struct_pointer", "entry_clock", "entry_segment_index", "length_clock",
            "observation_segment_index", "pointer_clock", "source_pointer",
        ):
            _integer(call[field], f"call {ordinal} {field}", maximum=U32_MAX)
        _require(call["source_pointer"] + call["length"] <= 1 << 32,
                 f"call {ordinal} source range overflows")
        call_lengths.append(call["length"])
        source_chain.update(bytes.fromhex(call["source_bytes_sha256"]))
        aggregate["bitmap_bytes_sum"] += call["bitmap_bytes"]
        aggregate["eof_immediate_padding_sum"] += call["eof_immediate_padding"]
        aggregate["jumpdest_count_sum"] += call["jumpdest_count"]
        aggregate["length_sum"] += call["length"]
        aggregate["opcode_positions_sum"] += sum(call["opcode_positions"])
        aggregate["push_count_sum"] += call["push_count"]
        aggregate["push_overflow_sum"] += call["push_overflow"]
        aggregate["scan_iterations_sum"] += call["scan_iterations"]
        aggregate["total_padding_sum"] += call["total_padding"]
    aggregate["source_bytes_chain_sha256"] = source_chain.hexdigest()
    _require(observed_indices == legacy_indices and value["aggregate"] == aggregate,
             "analyze_legacy aggregate closure differs")
    length_histogram: dict[int, int] = {}
    for length in call_lengths:
        length_histogram[length] = length_histogram.get(length, 0) + 1
    _require(
        sorted(length_histogram.items()) == [
            (row["value"], row["count"]) for row in observed_lengths["histogram"]
        ],
        "analyze_legacy length histogram cross-binding differs",
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(path.absolute(), "analyze_legacy evidence", maximum=MAX_OUTPUT_BYTES)
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "analyze_legacy evidence is not canonical JSON")
    return validate(value)


def _expected_argv(executable: Path, inputs: dict[str, Path], segment_count: int) -> list[str]:
    return [
        str(executable.resolve(strict=True)),
        "--cargo-lock", str(inputs["cargo_lock"].resolve(strict=True)),
        "--elf", str(inputs["elf"].resolve(strict=True)),
        "--execution-journal", str(inputs["execution_journal"].resolve(strict=True)),
        "--function-value-evidence", str(inputs["function_value_evidence"].resolve(strict=True)),
        "--input", str(inputs["input"].resolve(strict=True)),
        "--nm-map", str(inputs["nm_map"].resolve(strict=True)),
        "--observer-semantics-source", str(inputs["observer_semantics_source"].resolve(strict=True)),
        "--observer-source", str(inputs["observer_source"].resolve(strict=True)),
        "--observer-witness-source", str(inputs["observer_witness_source"].resolve(strict=True)),
        "--pc-observation", str(inputs["pc_observation"].resolve(strict=True)),
        "--revm-source", str(inputs["revm_source"].resolve(strict=True)),
        "--segment-count", str(segment_count),
    ]


def capture(
    *,
    executable: Path,
    inputs: dict[str, Path],
    segment_count: int,
    output: Path,
    stderr_output: Path,
    staging: Path,
    timeout_seconds: int = MAX_SECONDS,
) -> dict[str, Any]:
    _integer(timeout_seconds, "timeout", minimum=1, maximum=MAX_SECONDS)
    _integer(segment_count, "segment count", minimum=1, maximum=64)
    _require(executable.name == "riscv-analyze-legacy-semantic-observer",
             "observer executable name differs")
    _require(not os.path.lexists(output) and not os.path.lexists(stderr_output),
             "analyze_legacy output already exists")
    store.require_directory(output.parent.absolute(), "observer output parent")
    store.require_directory(staging.absolute(), "observer staging", create=True)
    argv = _expected_argv(executable, inputs, segment_count)
    _require(len(argv) == 25 and all("proof" not in part.lower() for part in argv),
             "observer argv could launch a proof path")
    stdout = tempfile.TemporaryFile(prefix="analyze-legacy.stdout.", dir=staging)
    stderr = tempfile.TemporaryFile(prefix="analyze-legacy.stderr.", dir=staging)
    try:
        child = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        deadline = time.monotonic() + timeout_seconds
        outcome = None
        while outcome is None and time.monotonic() < deadline:
            outcome = child_process._wait4_nohang(child)
            if outcome is None:
                if os.fstat(stdout.fileno()).st_size > MAX_OUTPUT_BYTES or os.fstat(
                    stderr.fileno()
                ).st_size > MAX_STDERR_BYTES:
                    break
                time.sleep(0.01)
        if outcome is None:
            child_process._terminate_group(child)
            raise AnalyzeLegacyEvidenceError("analyze_legacy observer exceeded its bound")
        return_code, _ = outcome
        _require(
            child_process.drain_process_group(child, "analyze_legacy observer")
            and return_code == 0,
            "analyze_legacy observer did not complete cleanly",
        )
        stdout.seek(0)
        stderr.seek(0)
        raw = stdout.read(MAX_OUTPUT_BYTES + 1)
        stderr_raw = stderr.read(MAX_STDERR_BYTES + 1)
    finally:
        stdout.close()
        stderr.close()
    _require(len(raw) <= MAX_OUTPUT_BYTES and stderr_raw == b"",
             "analyze_legacy observer output differs")
    value = store.decode_strict(raw)
    _require(type(value) is dict and raw == protocol.canonical_bytes(value),
             "observer stdout is not canonical JSON")
    validate(value)
    store.publish_new_or_identical(output.absolute(), raw, staging_directory=staging.absolute())
    store.publish_new_or_identical(
        stderr_output.absolute(), stderr_raw, staging_directory=staging.absolute(),
    )
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    replay = commands.add_parser("replay")
    replay.add_argument("--evidence", type=Path, required=True)
    capture_parser = commands.add_parser("capture")
    capture_parser.add_argument("--executable", type=Path, required=True)
    for name in (
        "cargo-lock", "elf", "execution-journal", "function-value-evidence", "input",
        "nm-map", "observer-semantics-source", "observer-source", "observer-witness-source",
        "pc-observation",
        "revm-source",
    ):
        capture_parser.add_argument(f"--{name}", type=Path, required=True)
    capture_parser.add_argument("--segment-count", type=int, required=True)
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--stderr-output", type=Path, required=True)
    capture_parser.add_argument("--staging", type=Path, required=True)
    capture_parser.add_argument("--timeout-seconds", type=int, default=MAX_SECONDS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "replay":
            value = load(args.evidence)
        else:
            inputs = {
                name.replace("_path", ""): getattr(args, name)
                for name in (
                    "cargo_lock", "elf", "execution_journal", "function_value_evidence",
                    "input", "nm_map", "observer_semantics_source", "observer_source",
                    "observer_witness_source", "pc_observation", "revm_source",
                )
            }
            value = capture(
                executable=args.executable,
                inputs=inputs,
                segment_count=args.segment_count,
                output=args.output,
                stderr_output=args.stderr_output,
                staging=args.staging,
                timeout_seconds=args.timeout_seconds,
            )
        print(json.dumps({
            "call_count": value["aggregate"]["call_count"],
            "content_sha256": value["content_sha256"],
            "production": value["production"],
            "schema": value["schema"],
            "status": value["status"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (AnalyzeLegacyEvidenceError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
