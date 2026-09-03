"""Strict admission for retained compact Ethereum capture/replay diagnostics.

The two Zig receipts are execution diagnostics, never proof evidence.  This
module mirrors their frozen canonical codecs, reopens every named authority,
and cross-binds the real execution/source/profile/compact-tape/replay chain.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
from typing import Any

from scripts import ethereum_block_proof_materialization as materialization
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store


EVIDENCE_KIND = "stwo-compact-ethereum-capture-replay-diagnostic-v1"
MANIFEST_SCHEMA = "stwo.ethereum.block-compact-replay-materialization.v1"
REPLAY_SCHEMA = "stwo.ethereum.block-compact-parallel-replay-receipt.v1"
PROFILE_SCHEMA = "stwo.ethereum.guest-pc-function-profile.v1"
MANIFEST_STATUS = "captured-diagnostic-only"
REPLAY_STATUS = "replayed-diagnostic-only"
PROFILE_STATUS = "execution-profiled-diagnostic-only"
EXECUTION_PROFILE = "rv32im-zkvm-ethereum-v1"
ARTIFACT_MAGIC = b"STWEMT01"
MAX_ARTIFACT_BYTES = 256 << 20
MAX_LEAF_CYCLES = 1 << 24
MAX_MANIFEST_BYTES = 64 << 20
MAX_RECEIPT_BYTES = 16 << 20
MAX_WORKERS = 32

ARTIFACT_CHECKSUM_DOMAIN = b"stwo.riscv.ethereum-minimal-artifact.v1\x00"
ARTIFACT_CHAIN_DOMAIN = b"stwo-zig/riscv/ethereum-minimal-artifact-chain/v1\x00"
BOUNDARY_ENTRY_DOMAIN = b"stwo.riscv.minimal-boundary.entry.v1\x00"
BOUNDARY_EXIT_DOMAIN = b"stwo.riscv.minimal-boundary.exit.v1\x00"
CPU_DOMAIN = b"stwo-zig/riscv/segment-boundary-cpu/v1\x00"
LEAF_DOMAIN = b"stwo.riscv.ethereum-minimal-leaf.v1\x00"
REPLAY_CHAIN_DOMAIN = b"stwo-zig/riscv/ethereum-compact-replay-chain/v1\x00"
WITNESS_DOMAIN = b"stwo-zig/riscv/ethereum-compact-replay-witness/v1\x00"

IDENTITY_KEYS = ("bytes", "path", "sha256")
MANIFEST_KEYS = (
    "content_sha256", "artifact_chain_sha256", "artifact_format_version",
    "artifact_magic", "artifacts", "clock_frame", "elf", "execution_journal",
    "execution_profile", "execution_profile_abi_version",
    "execution_profile_receipt", "execution_profile_semantic_sha256",
    "expected_output", "input", "materialization_result",
    "materializer_executable_sha256", "program_sha256", "segment_count",
    "segment_step_budget", "session_sha256", "source_request", "stage_timings",
    "status", "total_artifact_bytes", "total_core_cycles", "total_cycles",
    "total_keccak_calls", "total_recovery_calls", "schema",
)
MANIFEST_ARTIFACT_KEYS = (
    "artifact", "capture_wall_ns", "completion", "core_cycle_count",
    "cycle_count", "encode_wall_ns", "entry_boundary_sha256", "entry_cpu_sha256",
    "entry_memory_sha256", "exit_boundary_sha256", "exit_cpu_sha256",
    "exit_memory_sha256", "global_first_cycle", "keccak_calls",
    "leaf_seal_sha256", "publish_wall_ns", "recovery_calls", "segment_index",
)
STAGE_TIMING_KEYS = (
    "capture_wall_ns", "encode_wall_ns", "observer_wall_ns",
    "pc_attribution_wall_ns", "post_execution_authority_wall_ns",
    "publish_wall_ns", "stream_observed_wall_ns",
    "pre_manifest_materialization_wall_ns",
)
REPLAY_KEYS = (
    "content_sha256", "artifact_chain_sha256", "artifacts_manifest", "clock_frame",
    "elf", "execution_journal", "execution_profile", "execution_profile_abi_version",
    "execution_profile_receipt", "execution_profile_semantic_sha256",
    "expected_output", "input", "leaf_authorities", "manifest_content_sha256",
    "materialization_result", "process_scope", "program_sha256",
    "replay_chain_sha256", "replay_executable", "replay_receipt", "replay_timing",
    "requested_workers", "schema", "segment_count", "segment_step_budget",
    "session_sha256", "source_request", "status", "timing_scope",
)
REPLAY_RECEIPT_KEYS = (
    "admitted_workers", "core_cycles", "keccak_calls", "leaf_count",
    "recovery_calls", "total_cycles",
)
REPLAY_TIMING_KEYS = ("wall_ns", "user_ns", "system_ns")
LEAF_AUTHORITY_KEYS = (
    "core_trace_rows", "core_trace_sha256", "entry_cpu_sha256", "exit_cpu_sha256",
    "keccak_call_count", "keccak_calls_sha256", "keccak_execution_rows",
    "keccak_rows_sha256", "recovery_call_count", "recovery_calls_sha256",
    "recovery_execution_rows", "recovery_rows_sha256", "segment_index",
    "state_chain_access_count", "state_chain_memory_clock_updates",
    "state_chain_register_clock_updates", "state_chain_sha256",
    "touched_memory_sha256", "touched_memory_words", "witness_sha256",
)
PROFILE_KEYS = (
    "content_sha256", "attributed_core_rows", "attributed_external_calls",
    "core_rows", "elf", "execution_journal", "external_calls",
    "external_execution_rows", "external_family_counts", "function_count",
    "function_top_coverage_core_rows", "function_top_coverage_external_calls",
    "functions_truncated", "materialization_result", "nonzero_pc_count",
    "out_of_text_core_rows", "out_of_text_external_calls", "pc_stride",
    "pc_top_coverage_core_rows", "pc_top_coverage_external_calls", "pcs_truncated",
    "schema", "source_request", "status", "text_end", "text_start",
    "top_functions", "top_pcs", "unattributed_core_rows",
    "unattributed_external_calls",
)
FUNCTION_KEYS = (
    "address", "core_rows", "external_calls", "name", "size",
    "total_retirements",
)
PC_KEYS = (
    "core_rows", "external_calls", "function", "function_offset", "pc",
    "total_retirements",
)


def _require(condition: bool, message: str) -> None:
    protocol.require(condition, message)


def _ordered(value: Any, keys: tuple[str, ...], where: str) -> dict[str, Any]:
    _require(type(value) is dict and tuple(value) == keys, f"{where} keys/order differ")
    return value


def _uint(value: Any, bits: int, where: str, *, positive: bool = False) -> int:
    maximum = (1 << bits) - 1
    _require(type(value) is int and 0 <= value <= maximum, f"{where} differs")
    if positive:
        _require(value > 0, f"{where} must be positive")
    return value


def _sha(value: Any, where: str) -> str:
    return protocol._sha(value, where)


def _read_zig_json(path: Path, where: str, maximum: int) -> tuple[bytes, dict[str, Any]]:
    raw = store.read_regular(path, where, maximum=maximum)
    _require(raw.endswith(b"\n") and not raw.endswith(b"\n\n"),
             f"{where} newline framing differs")
    value = store.decode_strict(raw)
    _require(type(value) is dict, f"{where} must be an object")
    try:
        canonical = json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
        ).encode("utf-8") + b"\n"
    except (TypeError, ValueError) as error:
        raise protocol.ProofProtocolError(f"{where} is not canonical JSON") from error
    _require(raw == canonical, f"{where} is not canonical declaration-order JSON")
    prefix = b'{"content_sha256":"'
    _require(raw.startswith(prefix), f"{where} content seal position differs")
    end = len(prefix) + 64
    _require(raw[end:end + 2] == b'",', f"{where} content seal framing differs")
    expected = _sha(value.get("content_sha256"), f"{where}.content_sha256")
    _require(raw[len(prefix):end].decode("ascii") == expected,
             f"{where} content seal differs")
    unsigned = b"{" + raw[end + 2:]
    _require(hashlib.sha256(unsigned).hexdigest() == expected,
             f"{where} content seal differs")
    return raw, value


def _identity(value: Any, where: str, *, allow_empty: bool = False) -> tuple[dict[str, Any], Path]:
    value = _ordered(value, IDENTITY_KEYS, where)
    size = _uint(value["bytes"], 64, f"{where}.bytes")
    _require(allow_empty or size > 0, f"{where}.bytes differs")
    digest = _sha(value["sha256"], f"{where}.sha256")
    _require(type(value["path"]) is str and value["path"], f"{where}.path differs")
    path = Path(value["path"])
    _require(path.is_absolute(), f"{where}.path must be absolute")
    store.validate_file_identity(path, {"bytes": size, "sha256": digest}, where)
    return value, path


def _file_identity(path: Path, where: str) -> dict[str, Any]:
    _require(path.is_absolute(), f"{where} path must be absolute")
    return {"path": str(path), **store.file_identity(path, where)}


def _completion(value: Any, where: str) -> dict[str, Any] | None:
    if value is None:
        return None
    value = _ordered(value, ("kind", "address", "value", "clock", "exit_code"), where)
    kind = _uint(value["kind"], 8, f"{where}.kind", positive=True)
    _require(kind <= 8, f"{where}.kind differs")
    address = _uint(value["address"], 32, f"{where}.address")
    clock = _uint(value["clock"], 32, f"{where}.clock")
    _uint(value["value"], 32, f"{where}.value")
    if value["exit_code"] is not None:
        _uint(value["exit_code"], 32, f"{where}.exit_code")
    if kind == 2:
        _require(clock == 0 and address % 4 == 0, f"{where} self-loop differs")
    return value


class _Cursor:
    def __init__(self, value: bytes) -> None:
        self.value = value
        self.at = 0

    def take(self, count: int) -> bytes:
        _require(count >= 0 and self.at + count <= len(self.value),
                 "compact artifact is truncated")
        result = self.value[self.at:self.at + count]
        self.at += count
        return result

    def integer(self, count: int) -> int:
        return int.from_bytes(self.take(count), "little")


def _boundary_digest(domain: bytes, words: list[tuple[int, int, int]], side: int) -> str:
    digest = hashlib.sha256(domain + struct.pack("<I", len(words)))
    for word in words:
        digest.update(struct.pack("<II", word[0], word[side]))
    return digest.hexdigest()


def _parse_compact_artifact(
    path: Path, identity: dict[str, Any], record: dict[str, Any], manifest: dict[str, Any],
) -> None:
    raw = store.read_regular(path, f"compact artifact {record['segment_index']}",
                             maximum=MAX_ARTIFACT_BYTES)
    _require(len(raw) == identity["bytes"] and hashlib.sha256(raw).hexdigest()
             == identity["sha256"], "compact artifact identity differs")
    _require(len(raw) >= 48, "compact artifact is truncated")
    body, checksum = raw[:-32], raw[-32:]
    _require(hashlib.sha256(ARTIFACT_CHECKSUM_DOMAIN + body).digest() == checksum,
             "compact artifact checksum differs")
    cursor = _Cursor(body)
    _require(cursor.take(8) == ARTIFACT_MAGIC, "compact artifact magic differs")
    format_version = cursor.integer(2)
    schema_version = cursor.integer(2)
    _require((format_version, schema_version, cursor.integer(4)) == (1, 1, 0),
             "compact artifact header differs")
    payload_start = cursor.at
    source = [cursor.take(32).hex() for _ in range(5)]
    entry_boundary = cursor.take(32).hex()
    exit_boundary = cursor.take(32).hex()
    _require(all(int(digest, 16) != 0 for digest in source)
             and int(entry_boundary, 16) != 0 and int(exit_boundary, 16) != 0,
             "compact artifact source identity is zero")
    segment_index = cursor.integer(4)
    global_first_cycle = cursor.integer(8)
    cycle_count = cursor.integer(4)
    core_cycle_count = cursor.integer(4)
    entry_cpu_bytes = cursor.take(132)
    exit_cpu_bytes = cursor.take(132)
    _require(int.from_bytes(entry_cpu_bytes[4:8], "little") == 0
             and int.from_bytes(exit_cpu_bytes[4:8], "little") == 0,
             "compact artifact zero register differs")
    entry_cpu = hashlib.sha256(CPU_DOMAIN + entry_cpu_bytes).hexdigest()
    exit_cpu = hashlib.sha256(CPU_DOMAIN + exit_cpu_bytes).hexdigest()
    tag = cursor.integer(1)
    if tag == 0:
        completion = None
    else:
        _require(tag == 1, "compact artifact completion tag differs")
        completion = {
            "kind": cursor.integer(1), "address": cursor.integer(4),
            "value": cursor.integer(4), "clock": cursor.integer(4),
        }
        exit_tag = cursor.integer(1)
        _require(exit_tag in (0, 1), "compact artifact exit code tag differs")
        completion["exit_code"] = cursor.integer(4) if exit_tag else None
        _completion(completion, "compact artifact completion")
    _require(0 < cycle_count <= MAX_LEAF_CYCLES and core_cycle_count <= cycle_count,
             "compact artifact cycle geometry differs")
    ordinary_count = cursor.integer(4)
    _require(ordinary_count <= core_cycle_count, "compact artifact word count differs")
    cursor.take(ordinary_count * 4)
    keccak_count = cursor.integer(4)
    _require(keccak_count <= cycle_count, "compact artifact Keccak count differs")
    keccak_clocks = []
    for _ in range(keccak_count):
        clock = cursor.integer(4)
        pc = cursor.integer(4)
        state_pointer = cursor.integer(4)
        pointer_register = cursor.integer(1)
        cursor.take(4 + 50 * 4 * 3)
        _require(pointer_register <= 31 and pc % 4 == 0
                 and state_pointer % 4 == 0 and 0 < clock <= cycle_count,
                 "compact artifact Keccak record differs")
        keccak_clocks.append(clock)
    recovery_count = cursor.integer(4)
    _require(recovery_count <= cycle_count, "compact artifact recovery count differs")
    recovery_clocks = []
    for _ in range(recovery_count):
        clock = cursor.integer(4)
        pc = cursor.integer(4)
        io_pointer = cursor.integer(4)
        pointer_register = cursor.integer(1)
        cursor.take(4 + 32 * 3)
        recovery_id = cursor.integer(4)
        cursor.take(64)
        status = cursor.integer(4)
        cursor.take(25 * 4 + 17 * 4 * 2)
        _require(pointer_register <= 31 and pc % 4 == 0 and io_pointer % 4 == 0
                 and recovery_id in (0, 1) and status == 1
                 and 0 < clock <= cycle_count,
                 "compact artifact recovery record differs")
        recovery_clocks.append(clock)
    _require(keccak_count + recovery_count == cycle_count - core_cycle_count,
             "compact artifact external count differs")
    _require(keccak_clocks == sorted(set(keccak_clocks))
             and recovery_clocks == sorted(set(recovery_clocks))
             and len(set(keccak_clocks + recovery_clocks))
             == len(keccak_clocks) + len(recovery_clocks),
             "compact artifact external clock order differs")
    leaf_seal_at = cursor.at
    retained_leaf_seal = cursor.take(32).hex()
    expected_leaf_seal = hashlib.sha256(
        LEAF_DOMAIN + struct.pack("<HHH", format_version, schema_version, 3)
        + body[payload_start:leaf_seal_at]
    ).hexdigest()
    _require(retained_leaf_seal == expected_leaf_seal,
             "compact artifact leaf seal differs")
    boundary_count = cursor.integer(4)
    _require(boundary_count <= MAX_LEAF_CYCLES, "compact artifact boundary count differs")
    words = []
    for _ in range(boundary_count):
        words.append((cursor.integer(4), cursor.integer(4), cursor.integer(4)))
    _require(cursor.at == len(body), "compact artifact has trailing bytes")
    _require(all(address % 4 == 0 for address, _, _ in words)
             and [word[0] for word in words] == sorted(set(word[0] for word in words)),
             "compact artifact boundary order differs")
    _require(entry_boundary == _boundary_digest(BOUNDARY_ENTRY_DOMAIN, words, 1)
             and exit_boundary == _boundary_digest(BOUNDARY_EXIT_DOMAIN, words, 2),
             "compact artifact boundary identity differs")
    expected = {
        "segment_index": segment_index, "global_first_cycle": global_first_cycle,
        "cycle_count": cycle_count, "core_cycle_count": core_cycle_count,
        "keccak_calls": keccak_count, "recovery_calls": recovery_count,
        "entry_boundary_sha256": entry_boundary, "exit_boundary_sha256": exit_boundary,
        "entry_cpu_sha256": entry_cpu, "exit_cpu_sha256": exit_cpu,
        "entry_memory_sha256": source[3], "exit_memory_sha256": source[4],
        "leaf_seal_sha256": retained_leaf_seal, "completion": completion,
    }
    for field, value in expected.items():
        _require(record[field] == value, f"compact artifact {field} differs")
    _require(source[0] == manifest["program_sha256"]
             and source[1] == manifest["input"]["sha256"]
             and source[2] == manifest["session_sha256"],
             "compact artifact source identity differs")


def _validate_stage_timings(value: Any) -> dict[str, Any]:
    value = _ordered(value, STAGE_TIMING_KEYS, "compact stage timings")
    for field in STAGE_TIMING_KEYS:
        _uint(value[field], 64, f"compact stage timings.{field}")
    classified = (value["capture_wall_ns"] + value["encode_wall_ns"]
                  + value["publish_wall_ns"] + value["pc_attribution_wall_ns"])
    _require(value["stream_observed_wall_ns"] > 0
             and value["pre_manifest_materialization_wall_ns"] > 0
             and value["observer_wall_ns"] >= classified
             and value["stream_observed_wall_ns"] >= value["observer_wall_ns"]
             and value["pre_manifest_materialization_wall_ns"] >=
             value["stream_observed_wall_ns"]
             + value["post_execution_authority_wall_ns"],
             "compact stage timing closure differs")
    return value


def _validate_manifest(path: Path) -> dict[str, Any]:
    _, value = _read_zig_json(path, "compact materialization manifest", MAX_MANIFEST_BYTES)
    value = _ordered(value, MANIFEST_KEYS, "compact materialization manifest")
    _require(value["schema"] == MANIFEST_SCHEMA and value["status"] == MANIFEST_STATUS
             and value["artifact_magic"] == ARTIFACT_MAGIC.decode()
             and value["artifact_format_version"] == 1
             and value["clock_frame"] == "leaf_local"
             and value["execution_profile"] == EXECUTION_PROFILE,
             "compact materialization authority differs")
    _uint(value["execution_profile_abi_version"], 16,
          "compact execution profile ABI", positive=True)
    segment_count = _uint(value["segment_count"], 32, "compact segment count", positive=True)
    _require(segment_count >= 2, "compact segment count differs")
    step_budget = _uint(value["segment_step_budget"], 64,
                        "compact segment step budget", positive=True)
    _require(step_budget <= MAX_LEAF_CYCLES, "compact segment step budget differs")
    for field in (
        "artifact_chain_sha256", "execution_profile_semantic_sha256",
        "materializer_executable_sha256", "program_sha256", "session_sha256",
    ):
        _sha(value[field], f"compact manifest.{field}")
    for field in (
        "elf", "execution_journal", "execution_profile_receipt", "expected_output",
        "input", "materialization_result", "source_request",
    ):
        _identity(value[field], f"compact manifest.{field}", allow_empty=field == "input")
    _validate_stage_timings(value["stage_timings"])
    artifacts = value["artifacts"]
    _require(type(artifacts) is list and len(artifacts) == segment_count,
             "compact artifact count differs")
    totals = {key: 0 for key in (
        "bytes", "core", "cycles", "keccak", "recovery", "capture", "encode", "publish",
    )}
    expected_global = 1
    previous = None
    chain = hashlib.sha256(ARTIFACT_CHAIN_DOMAIN + struct.pack("<I", segment_count))
    for index, record in enumerate(artifacts):
        record = _ordered(record, MANIFEST_ARTIFACT_KEYS, f"compact artifact {index}")
        _require(record["segment_index"] == index, "compact artifact order differs")
        _uint(record["global_first_cycle"], 64, "compact global cycle", positive=True)
        cycle_count = _uint(record["cycle_count"], 32, "compact cycle count", positive=True)
        core_count = _uint(record["core_cycle_count"], 32, "compact core cycle count")
        keccak = _uint(record["keccak_calls"], 32, "compact Keccak count")
        recovery = _uint(record["recovery_calls"], 32, "compact recovery count")
        _require(record["global_first_cycle"] == expected_global
                 and core_count <= cycle_count
                 and core_count + keccak + recovery == cycle_count,
                 "compact artifact geometry differs")
        expected_global += cycle_count
        completion = _completion(record["completion"], f"compact artifact {index}.completion")
        _require((completion is not None) == (index + 1 == segment_count),
                 "compact terminal completion differs")
        for field in (
            "entry_boundary_sha256", "entry_cpu_sha256", "entry_memory_sha256",
            "exit_boundary_sha256", "exit_cpu_sha256", "exit_memory_sha256",
            "leaf_seal_sha256",
        ):
            _sha(record[field], f"compact artifact {index}.{field}")
        identity, artifact_path = _identity(record["artifact"],
                                             f"compact artifact {index}")
        _parse_compact_artifact(artifact_path, identity, record, value)
        if previous is not None:
            _require(previous["exit_memory_sha256"] == record["entry_memory_sha256"]
                     and previous["exit_cpu_sha256"] == record["entry_cpu_sha256"],
                     "compact artifact continuation differs")
        previous = record
        for field in ("capture_wall_ns", "encode_wall_ns", "publish_wall_ns"):
            _uint(record[field], 64, f"compact artifact {index}.{field}")
        totals["bytes"] += identity["bytes"]
        totals["core"] += core_count
        totals["cycles"] += cycle_count
        totals["keccak"] += keccak
        totals["recovery"] += recovery
        totals["capture"] += record["capture_wall_ns"]
        totals["encode"] += record["encode_wall_ns"]
        totals["publish"] += record["publish_wall_ns"]
        chain.update(struct.pack("<IQ", index, identity["bytes"]))
        chain.update(bytes.fromhex(identity["sha256"]))
        chain.update(bytes.fromhex(record["leaf_seal_sha256"]))
    expected_totals = {
        "total_artifact_bytes": totals["bytes"], "total_core_cycles": totals["core"],
        "total_cycles": totals["cycles"], "total_keccak_calls": totals["keccak"],
        "total_recovery_calls": totals["recovery"],
    }
    for field, expected in expected_totals.items():
        _require(_uint(value[field], 64, f"compact manifest.{field}") == expected,
                 f"compact manifest.{field} differs")
    _require(value["stage_timings"]["capture_wall_ns"] == totals["capture"]
             and value["stage_timings"]["encode_wall_ns"] == totals["encode"]
             and value["stage_timings"]["publish_wall_ns"] == totals["publish"],
             "compact manifest timing totals differ")
    _require(chain.hexdigest() == value["artifact_chain_sha256"],
             "compact artifact chain differs")
    return value


def _validate_profile(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    _, value = _read_zig_json(path, "Ethereum execution PC profile", MAX_RECEIPT_BYTES)
    value = _ordered(value, PROFILE_KEYS, "Ethereum execution PC profile")
    _require(value["schema"] == PROFILE_SCHEMA and value["status"] == PROFILE_STATUS
             and value["pc_stride"] == 4,
             "Ethereum execution PC profile authority differs")
    for field in ("elf", "execution_journal", "materialization_result", "source_request"):
        identity, _ = _identity(value[field], f"execution profile.{field}")
        _require(identity == manifest[field], f"execution profile {field} differs")
    numeric = (
        "attributed_core_rows", "attributed_external_calls", "core_rows",
        "external_calls", "external_execution_rows", "function_count",
        "function_top_coverage_core_rows", "function_top_coverage_external_calls",
        "nonzero_pc_count", "out_of_text_core_rows", "out_of_text_external_calls",
        "pc_top_coverage_core_rows", "pc_top_coverage_external_calls", "text_end",
        "text_start", "unattributed_core_rows", "unattributed_external_calls",
    )
    for field in numeric:
        _uint(value[field], 64, f"execution profile.{field}")
    _require(value["text_start"] < value["text_end"] and value["function_count"] > 0,
             "execution profile text authority differs")
    _require(value["attributed_core_rows"] + value["unattributed_core_rows"]
             + value["out_of_text_core_rows"] == value["core_rows"]
             and value["attributed_external_calls"] + value["unattributed_external_calls"]
             + value["out_of_text_external_calls"] == value["external_calls"],
             "execution profile classified totals differ")
    families = value["external_family_counts"]
    _require(type(families) is list and len(families) == 2,
             "execution profile external families differ")
    expected_names = ("keccakf", "secp256k1_recover")
    calls = rows = 0
    for index, family in enumerate(families):
        family = _ordered(family, ("calls", "execution_rows", "family"),
                          f"execution profile family {index}")
        _require(family["family"] == expected_names[index],
                 "execution profile family order differs")
        calls += _uint(family["calls"], 64, "execution profile family calls")
        rows += _uint(family["execution_rows"], 64,
                      "execution profile family rows")
    _require(calls == value["external_calls"]
             and rows == value["external_execution_rows"]
             and value["core_rows"] == manifest["total_core_cycles"]
             and families[0]["calls"] == manifest["total_keccak_calls"]
             and families[1]["calls"] == manifest["total_recovery_calls"],
             "execution profile and compact geometry differ")
    functions = value["top_functions"]
    pcs = value["top_pcs"]
    _require(type(functions) is list and 0 < len(functions) <= 512
             and type(pcs) is list and len(pcs) <= 2048,
             "execution profile top-list geometry differs")
    _require(type(value["functions_truncated"]) is bool
             and value["functions_truncated"]
             == (value["function_count"] > len(functions))
             and type(value["pcs_truncated"]) is bool
             and value["pcs_truncated"] == (value["nonzero_pc_count"] > len(pcs)),
             "execution profile truncation flags differ")
    previous = None
    function_core = function_external = 0
    for index, function in enumerate(functions):
        function = _ordered(function, FUNCTION_KEYS, f"execution profile function {index}")
        address = _uint(function["address"], 32, "execution profile function address")
        core = _uint(function["core_rows"], 64, "execution profile function core rows")
        external = _uint(function["external_calls"], 64,
                         "execution profile function external calls")
        _uint(function["size"], 32, "execution profile function size")
        total = _uint(function["total_retirements"], 64,
                      "execution profile function total")
        _require(type(function["name"]) is str and function["name"]
                 and total == core + external,
                 "execution profile function differs")
        order = (-total, -core, address, function["name"].encode("utf-8"))
        _require(previous is None or previous <= order,
                 "execution profile function order differs")
        previous = order
        function_core += core
        function_external += external
    previous = None
    pc_core = pc_external = 0
    for index, pc in enumerate(pcs):
        pc = _ordered(pc, PC_KEYS, f"execution profile PC {index}")
        core = _uint(pc["core_rows"], 64, "execution profile PC core rows")
        external = _uint(pc["external_calls"], 64,
                         "execution profile PC external calls")
        address = _uint(pc["pc"], 32, "execution profile PC address")
        total = _uint(pc["total_retirements"], 64, "execution profile PC total")
        _require((pc["function"] is None
                  or type(pc["function"]) is str and pc["function"])
                 and (pc["function_offset"] is None
                      or type(pc["function_offset"]) is int
                      and 0 <= pc["function_offset"] <= (1 << 32) - 1)
                 and (pc["function"] is None) == (pc["function_offset"] is None)
                 and address % 4 == 0
                 and value["text_start"] <= address < value["text_end"]
                 and total == core + external,
                 "execution profile PC differs")
        order = (-total, -core, address)
        _require(previous is None or previous <= order,
                 "execution profile PC order differs")
        previous = order
        pc_core += core
        pc_external += external
    _require(function_core == value["function_top_coverage_core_rows"]
             and function_external
             == value["function_top_coverage_external_calls"]
             and pc_core == value["pc_top_coverage_core_rows"]
             and pc_external == value["pc_top_coverage_external_calls"],
             "execution profile top-list coverage differs")
    return value


def _leaf_witness(leaf: dict[str, Any]) -> str:
    digest = hashlib.sha256(WITNESS_DOMAIN)
    for field, bits in (("segment_index", 32), ("core_trace_rows", 32)):
        digest.update(leaf[field].to_bytes(bits // 8, "little"))
    for field in ("core_trace_sha256", "entry_cpu_sha256", "exit_cpu_sha256"):
        digest.update(bytes.fromhex(leaf[field]))
    for count, authority, rows, row_authority in (
        ("keccak_call_count", "keccak_calls_sha256", "keccak_execution_rows",
         "keccak_rows_sha256"),
        ("recovery_call_count", "recovery_calls_sha256", "recovery_execution_rows",
         "recovery_rows_sha256"),
    ):
        digest.update(leaf[count].to_bytes(4, "little"))
        digest.update(bytes.fromhex(leaf[authority]))
        digest.update(leaf[rows].to_bytes(4, "little"))
        digest.update(bytes.fromhex(leaf[row_authority]))
    for field in (
        "state_chain_access_count", "state_chain_memory_clock_updates",
        "state_chain_register_clock_updates",
    ):
        digest.update(leaf[field].to_bytes(4, "little"))
    digest.update(bytes.fromhex(leaf["state_chain_sha256"]))
    digest.update(leaf["touched_memory_words"].to_bytes(4, "little"))
    digest.update(bytes.fromhex(leaf["touched_memory_sha256"]))
    return digest.hexdigest()


def _validate_replay(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    _, value = _read_zig_json(path, "compact parallel replay receipt", MAX_RECEIPT_BYTES)
    value = _ordered(value, REPLAY_KEYS, "compact parallel replay receipt")
    _require(value["schema"] == REPLAY_SCHEMA and value["status"] == REPLAY_STATUS
             and value["process_scope"] == "single-cli-process"
             and value["timing_scope"] == "parallel-replay-call-self-rusage"
             and value["clock_frame"] == "leaf_local"
             and value["execution_profile"] == EXECUTION_PROFILE,
             "compact parallel replay authority differs")
    for field in (
        "artifact_chain_sha256", "execution_profile_semantic_sha256",
        "manifest_content_sha256", "program_sha256", "replay_chain_sha256",
        "session_sha256",
    ):
        _sha(value[field], f"compact replay.{field}")
    for field in (
        "artifacts_manifest", "elf", "execution_journal", "execution_profile_receipt",
        "expected_output", "input", "materialization_result", "replay_executable",
        "source_request",
    ):
        _identity(value[field], f"compact replay.{field}", allow_empty=field == "input")
    shared = (
        "artifact_chain_sha256", "clock_frame", "elf", "execution_journal",
        "execution_profile", "execution_profile_abi_version", "execution_profile_receipt",
        "execution_profile_semantic_sha256", "expected_output", "input",
        "materialization_result", "program_sha256", "segment_count",
        "segment_step_budget", "session_sha256", "source_request",
    )
    for field in shared:
        _require(value[field] == manifest[field], f"compact replay {field} differs")
    _require(value["manifest_content_sha256"] == manifest["content_sha256"],
             "compact replay manifest content seal differs")
    manifest_path = Path(value["artifacts_manifest"]["path"])
    _require(value["artifacts_manifest"] == _file_identity(
        manifest_path, "compact replay artifacts manifest"),
        "compact replay artifacts manifest identity differs")
    _require(value["replay_executable"]["sha256"]
             == manifest["materializer_executable_sha256"],
             "materializer/replay executable identity differs")
    requested = _uint(value["requested_workers"], 16, "requested replay workers", positive=True)
    _require(requested <= MAX_WORKERS, "requested replay workers differ")
    replay = _ordered(value["replay_receipt"], REPLAY_RECEIPT_KEYS, "replay totals")
    for field, bits in (
        ("admitted_workers", 16), ("core_cycles", 64), ("keccak_calls", 64),
        ("leaf_count", 32), ("recovery_calls", 64), ("total_cycles", 64),
    ):
        _uint(replay[field], bits, f"replay totals.{field}",
              positive=field in {"admitted_workers", "leaf_count", "total_cycles"})
    _require(replay["admitted_workers"] == min(requested, manifest["segment_count"])
             and replay["leaf_count"] == manifest["segment_count"],
             "replay worker/leaf admission differs")
    timing = _ordered(value["replay_timing"], REPLAY_TIMING_KEYS, "replay timing")
    for field in REPLAY_TIMING_KEYS:
        _uint(timing[field], 64, f"replay timing.{field}", positive=field == "wall_ns")
    leaves = value["leaf_authorities"]
    _require(type(leaves) is list and len(leaves) == manifest["segment_count"],
             "replay leaf authority count differs")
    totals = {"core": 0, "keccak": 0, "recovery": 0}
    chain = hashlib.sha256(REPLAY_CHAIN_DOMAIN + struct.pack("<I", len(leaves)))
    for index, leaf in enumerate(leaves):
        leaf = _ordered(leaf, LEAF_AUTHORITY_KEYS, f"replay leaf {index}")
        for field in LEAF_AUTHORITY_KEYS:
            if field.endswith("_sha256"):
                _sha(leaf[field], f"replay leaf {index}.{field}")
            else:
                _uint(leaf[field], 32, f"replay leaf {index}.{field}")
        _require(leaf["segment_index"] == index
                 and leaf["keccak_execution_rows"] == leaf["keccak_call_count"]
                 and leaf["recovery_execution_rows"] == leaf["recovery_call_count"]
                 and leaf["witness_sha256"] == _leaf_witness(leaf),
                 "replay leaf authority differs")
        source = manifest["artifacts"][index]
        _require(leaf["core_trace_rows"] == source["core_cycle_count"]
                 and leaf["entry_cpu_sha256"] == source["entry_cpu_sha256"]
                 and leaf["exit_cpu_sha256"] == source["exit_cpu_sha256"]
                 and leaf["keccak_call_count"] == source["keccak_calls"]
                 and leaf["recovery_call_count"] == source["recovery_calls"],
                 "replay leaf and compact artifact differ")
        totals["core"] += leaf["core_trace_rows"]
        totals["keccak"] += leaf["keccak_call_count"]
        totals["recovery"] += leaf["recovery_call_count"]
        chain.update(struct.pack("<I", index))
        chain.update(bytes.fromhex(leaf["witness_sha256"]))
    _require(chain.hexdigest() == value["replay_chain_sha256"],
             "compact replay chain differs")
    _require(replay["core_cycles"] == totals["core"]
             and replay["keccak_calls"] == totals["keccak"]
             and replay["recovery_calls"] == totals["recovery"]
             and replay["total_cycles"] == sum(totals.values())
             and replay["core_cycles"] == manifest["total_core_cycles"]
             and replay["total_cycles"] == manifest["total_cycles"],
             "compact replay totals differ")
    return value


def validate(path: Path) -> dict[str, Any]:
    """Validate and normalize one complete capture/profile/replay diagnostic."""
    _require(path.is_absolute(), "compact replay receipt path must be absolute")
    _, raw_replay = _read_zig_json(path, "compact parallel replay receipt", MAX_RECEIPT_BYTES)
    manifest_path = Path(raw_replay.get("artifacts_manifest", {}).get("path", ""))
    _require(manifest_path.is_absolute(), "compact manifest path must be absolute")
    manifest = _validate_manifest(manifest_path)
    replay = _validate_replay(path, manifest)
    profile_path = Path(manifest["execution_profile_receipt"]["path"])
    profile = _validate_profile(profile_path, manifest)
    materialized = materialization.validate(Path(manifest["materialization_result"]["path"]))
    source = materialized["source_request"]
    source_manifest = materialized["manifest"]
    for field in ("execution_journal", "expected_output", "input", "source_request"):
        expected = ({key: materialized["source_request_identity"][key]
                     for key in IDENTITY_KEYS} if field == "source_request"
                    else source_manifest[field])
        _require(manifest[field] == expected, f"compact/source {field} differs")
    _require(manifest["elf"] == source["elf"]
             and manifest["execution_profile"] == source["execution_profile"]
             and manifest["execution_profile_abi_version"] == source["profile_abi_version"]
             and manifest["execution_profile_semantic_sha256"]
             == source["profile_semantic_digest"]
             and manifest["segment_count"] == source["segment_count"]
             and manifest["segment_step_budget"] == source["segment_step_budget"]
             and manifest["total_cycles"] == source_manifest["total_cycles"],
             "compact/source execution authority differs")
    _require(profile["core_rows"] == replay["replay_receipt"]["core_cycles"]
             and profile["external_calls"] == replay["replay_receipt"]["keccak_calls"]
             + replay["replay_receipt"]["recovery_calls"],
             "execution profile/replay totals differ")
    return {
        "kind": EVIDENCE_KIND,
        "receipt": _file_identity(path, "compact parallel replay receipt"),
        "materialization_manifest": _file_identity(
            manifest_path, "compact materialization manifest",
        ),
        "execution_profile_receipt": _file_identity(
            profile_path, "Ethereum execution PC profile",
        ),
        "replay_executable": replay["replay_executable"],
        "projection": {
            "artifact_chain_sha256": manifest["artifact_chain_sha256"],
            "execution_profile": manifest["execution_profile"],
            "execution_profile_abi_version": manifest["execution_profile_abi_version"],
            "execution_profile_semantic_sha256": manifest[
                "execution_profile_semantic_sha256"
            ],
            "input": {key: manifest["input"][key] for key in ("bytes", "sha256")},
            "expected_output": {
                key: manifest["expected_output"][key] for key in ("bytes", "sha256")
            },
            "segment_count": manifest["segment_count"],
            "segment_step_budget": manifest["segment_step_budget"],
            "total_cycles": replay["replay_receipt"]["total_cycles"],
            "total_core_cycles": replay["replay_receipt"]["core_cycles"],
            "total_keccak_calls": replay["replay_receipt"]["keccak_calls"],
            "total_recovery_calls": replay["replay_receipt"]["recovery_calls"],
            "requested_workers": replay["requested_workers"],
            "admitted_workers": replay["replay_receipt"]["admitted_workers"],
            "replay_chain_sha256": replay["replay_chain_sha256"],
            "capture_stage_timings": manifest["stage_timings"],
            "capture_timing_scope": "pre-manifest-materialization-diagnostic",
            "replay_timing": replay["replay_timing"],
            "timing_scope": replay["timing_scope"],
            "matrix_timing_admissible": False,
            "proof_complete": False,
        },
    }
