#!/usr/bin/env python3
"""Capture and replay bounded RISC-V retirement PC-hotspot evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
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
import ethereum_block_pc_hotspot_contract as hotspot_contract  # noqa: E402


SCHEMA = "stwo.ethereum.riscv-pc-hotspot-evidence.v1"
OBSERVATION_SCHEMA = "stwo.riscv.retirement-pc-hotspot-observation.v1"
STATUS = "captured-execution-diagnostic-only"
OBSERVATION_STATUS = "captured-diagnostic-only"
CLAIM_BOUNDARY = "execution-retirement-observation-not-a-proof"
TRANSITION_SCOPE = (
    "within-segment-adjacent-observed-core-rows-"
    "external-retirements-omitted"
)
MAX_PRODUCER_SECONDS = 60
MAX_OBSERVATION_BYTES = store.MAX_JSON_BYTES
MAX_STDERR_BYTES = 64 * 1024
POLL_SECONDS = 0.01
DEFAULT_TOP_BASIC_EDGE_LIMIT = 64
MAX_TOP_BASIC_EDGE_LIMIT = 1024
FORBIDDEN_COMMAND_TOKENS = frozenset({
    "aggregate",
    "aggregation",
    "ethereum-block-leaf-producer",
    "ethereum-parent-producer",
    "ethereum-parent-prove",
    "ethereum-parent-prover",
    "h8",
    "prove",
    "prover",
    "proof",
    "recursive-prove",
    "verify",
    "verifier",
})
OBSERVATION_KEYS = {
    "schema",
    "status",
    "production",
    "execution_profile",
    "clock_frame",
    "elf_sha256",
    "input_sha256",
    "source_sha256",
    "first_segment_index",
    "segment_count",
    "first_global_cycle",
    "sampled_cycles",
    "retired_instructions",
    "transition_scope",
    "transition_count",
    "distinct_pc_count",
    "distinct_basic_edge_count",
    "per_pc",
    "opcode_transitions",
    "basic_edges",
    "content_sha256",
}


PcHotspotEvidenceError = hotspot_contract.PcHotspotContractError


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PcHotspotEvidenceError(message)


def _integer(
    value: Any,
    where: str,
    *,
    minimum: int = 0,
    maximum: int = (1 << 64) - 1,
) -> int:
    _require(
        type(value) is int and minimum <= value <= maximum,
        f"{where} differs",
    )
    return value


def _identity(
    path: Path,
    where: str,
    *,
    allow_empty: bool = False,
) -> dict[str, Any]:
    path = path.absolute()
    raw = store.read_regular(path, where)
    _require(allow_empty or raw, f"{where} is empty")
    return {
        "path": str(path),
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_identity(
    value: Any,
    where: str,
    *,
    allow_empty: bool = False,
) -> dict[str, Any]:
    _require(
        type(value) is dict and set(value) == {"path", "bytes", "sha256"},
        f"{where} keys differ",
    )
    path = Path(value["path"])
    _require(path.is_absolute(), f"{where} path differs")
    _require(
        value == _identity(path, where, allow_empty=allow_empty),
        f"{where} identity differs",
    )
    return value


def _require_safe_argv(argv: Any, timeout_seconds: Any) -> list[str]:
    _integer(
        timeout_seconds,
        "PC hotspot timeout",
        minimum=1,
        maximum=MAX_PRODUCER_SECONDS,
    )
    _require(
        type(argv) is list
        and 1 <= len(argv) <= 16
        and all(type(item) is str and item for item in argv),
        "PC hotspot argv differs",
    )
    for token in argv[1:]:
        normalized = token.lower()
        _require(
            normalized not in FORBIDDEN_COMMAND_TOKENS
            and not normalized.startswith("--proof")
            and not normalized.startswith("--prove")
            and not normalized.startswith("--verify")
            and not normalized.startswith("--aggregate")
            and "leaf-producer" not in normalized
            and "parent-produc" not in normalized
            and "recursive-prov" not in normalized,
            "full-proof command is forbidden in PC hotspot evidence",
        )
    return argv


_sample_authority = hotspot_contract.sample_authority
_top_edges = hotspot_contract.top_edges
_validate_observation = hotspot_contract.validate_observation
_decode_observation = hotspot_contract.decode_observation


def _run(
    argv: list[str],
    staging: Path,
    timeout_seconds: int,
) -> tuple[bytes, bytes, dict[str, Any]]:
    _require_safe_argv(argv, timeout_seconds)
    stdout = tempfile.TemporaryFile(prefix="pc-hotspot.stdout.", dir=staging)
    stderr = tempfile.TemporaryFile(prefix="pc-hotspot.stderr.", dir=staging)
    started = time.monotonic_ns()
    try:
        child = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
    except OSError as error:
        stdout.close()
        stderr.close()
        raise PcHotspotEvidenceError(
            "PC hotspot observer failed to launch"
        ) from error
    deadline = time.monotonic() + timeout_seconds
    outcome = None
    failure = None
    while outcome is None:
        outcome = child_process._wait4_nohang(child)
        if outcome is not None:
            break
        if os.fstat(stdout.fileno()).st_size > MAX_OBSERVATION_BYTES:
            failure = "PC hotspot stdout exceeded its bound"
            break
        if os.fstat(stderr.fileno()).st_size > MAX_STDERR_BYTES:
            failure = "PC hotspot stderr exceeded its bound"
            break
        if time.monotonic() >= deadline:
            failure = "PC hotspot observer timed out"
            break
        time.sleep(POLL_SECONDS)
    if failure is not None:
        child_process._terminate_group(child)
        stdout.close()
        stderr.close()
        raise PcHotspotEvidenceError(failure)
    _require(outcome is not None, "PC hotspot process wait differs")
    return_code, usage = outcome
    clean_group = child_process.drain_process_group(child, "PC hotspot observer")
    ended = time.monotonic_ns()
    stdout.seek(0)
    stderr.seek(0)
    stdout_raw = stdout.read(MAX_OBSERVATION_BYTES + 1)
    stderr_raw = stderr.read(MAX_STDERR_BYTES + 1)
    stdout.close()
    stderr.close()
    _require(
        clean_group
        and return_code == 0
        and len(stdout_raw) <= MAX_OBSERVATION_BYTES
        and len(stderr_raw) <= MAX_STDERR_BYTES,
        "PC hotspot observer did not complete cleanly",
    )
    maximum_rss = round(usage.ru_maxrss)
    maximum_rss_bytes = maximum_rss if sys.platform == "darwin" else maximum_rss * 1024
    return stdout_raw, stderr_raw, {
        "exit_code": return_code,
        "timeout_seconds": timeout_seconds,
        "timing": {
            "wall_ns": ended - started,
            "user_ns": max(0, round(usage.ru_utime * 1_000_000_000)),
            "system_ns": max(0, round(usage.ru_stime * 1_000_000_000)),
        },
        "maximum_resident_set_bytes": maximum_rss_bytes,
        "maximum_resident_set_source": (
            "darwin-wait4-ru_maxrss-bytes"
            if sys.platform == "darwin"
            else "wait4-ru_maxrss-kib-normalized-to-bytes"
        ),
        "process_group_drained": True,
    }


def _expected_argv(
    *,
    executable: dict[str, Any],
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    source: dict[str, Any],
    sample: dict[str, Any],
) -> list[str]:
    return [
        executable["path"],
        "--elf",
        elf["path"],
        "--input",
        input_identity["path"],
        "--execution-journal",
        source["path"],
        "--first-segment-index",
        str(sample["first_segment_index"]),
        "--segment-count",
        str(sample["segment_count"]),
    ]


def _canonical_totals(
    observation: dict[str, Any],
    top_edges: list[dict[str, Any]],
) -> dict[str, Any]:
    transition_sum = sum(row["count"] for row in observation["opcode_transitions"])
    edge_sum = sum(row["count"] for row in observation["basic_edges"])
    return {
        "retired_instructions": observation["retired_instructions"],
        "per_pc_count_sum": sum(row["count"] for row in observation["per_pc"]),
        "transition_count": observation["transition_count"],
        "opcode_transition_count_sum": transition_sum,
        "basic_edge_count_sum": edge_sum,
        "distinct_pc_count": observation["distinct_pc_count"],
        "distinct_basic_edge_count": observation["distinct_basic_edge_count"],
        "reported_top_basic_edge_count": len(top_edges),
    }


def _same_json(left: Any, right: Any) -> bool:
    return protocol.canonical_bytes(left) == protocol.canonical_bytes(right)


def capture(
    *,
    executable_path: Path,
    observer_source_path: Path,
    elf_path: Path,
    input_path: Path,
    execution_journal_path: Path,
    first_segment_index: int,
    segment_count: int,
    top_basic_edge_limit: int,
    timeout_seconds: int,
    output_path: Path,
    staging_directory: Path,
) -> dict[str, Any]:
    executable = _identity(executable_path, "PC hotspot observer executable")
    observer_source = _identity(observer_source_path, "PC hotspot observer source")
    elf = _identity(elf_path, "PC hotspot ELF")
    input_identity = _identity(input_path, "PC hotspot input", allow_empty=True)
    source = _identity(execution_journal_path, "PC hotspot execution journal")
    _require(
        os.access(executable["path"], os.X_OK),
        "PC hotspot observer is not executable",
    )
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    store.require_directory(output_path.parent, "PC hotspot evidence parent")
    store.require_directory(staging_directory, "PC hotspot staging", create=True)
    sample = _sample_authority(
        journal_path=Path(source["path"]),
        elf=elf,
        input_identity=input_identity,
        first_segment_index=first_segment_index,
        segment_count=segment_count,
    )
    argv = _expected_argv(
        executable=executable,
        elf=elf,
        input_identity=input_identity,
        source=source,
        sample=sample,
    )
    _require_safe_argv(argv, timeout_seconds)
    stdout_raw, stderr_raw, process = _run(argv, staging_directory, timeout_seconds)
    _require(stderr_raw == b"", "PC hotspot observer stderr is not empty")
    observation = _decode_observation(
        stdout_raw,
        sample=sample,
        elf=elf,
        input_identity=input_identity,
        source=source,
    )
    top_edges = _top_edges(observation["basic_edges"], top_basic_edge_limit)
    stdout_path = output_path.with_name(f"{output_path.stem}.stdout.json")
    stderr_path = output_path.with_name(f"{output_path.stem}.stderr")
    store.publish_new_or_identical(
        stdout_path, stdout_raw, staging_directory=staging_directory,
    )
    store.publish_new_or_identical(
        stderr_path, stderr_raw, staging_directory=staging_directory,
    )
    value = protocol.seal({
        "schema": SCHEMA,
        "status": STATUS,
        "claim_boundary": CLAIM_BOUNDARY,
        "production": False,
        "no_extrapolation": True,
        "observer_executable": executable,
        "observer_source": observer_source,
        "elf": elf,
        "input": input_identity,
        "execution_journal": source,
        "argv": argv,
        "sample": sample,
        "observation_content_sha256": observation["content_sha256"],
        "per_pc": observation["per_pc"],
        "opcode_transitions": observation["opcode_transitions"],
        "top_basic_edge_limit": top_basic_edge_limit,
        "top_basic_edges": top_edges,
        "canonical_totals": _canonical_totals(observation, top_edges),
        "transport": {
            "stdout": _identity(stdout_path, "PC hotspot stdout"),
            "stderr": _identity(stderr_path, "PC hotspot stderr", allow_empty=True),
        },
        "process": process,
        "promotion": {
            "scope": "sampled-retirement-observer-process-only",
            "diagnostic_eligible": True,
            "proof_correctness": None,
            "fresh_verification": None,
            "full_corpus_estimate": None,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        },
    })
    store.publish_new_or_identical(
        output_path,
        protocol.canonical_bytes(value),
        staging_directory=staging_directory,
    )
    return value


def _validate_process(value: Any) -> dict[str, Any]:
    _require(
        type(value) is dict
        and set(value) == {
            "exit_code",
            "timeout_seconds",
            "timing",
            "maximum_resident_set_bytes",
            "maximum_resident_set_source",
            "process_group_drained",
        }
        and value["exit_code"] == 0
        and value["process_group_drained"] is True,
        "PC hotspot process receipt differs",
    )
    _integer(
        value["timeout_seconds"],
        "PC hotspot timeout",
        minimum=1,
        maximum=MAX_PRODUCER_SECONDS,
    )
    _integer(
        value["maximum_resident_set_bytes"],
        "PC hotspot maximum RSS",
        minimum=1,
    )
    _require(
        value["maximum_resident_set_source"]
        in {
            "darwin-wait4-ru_maxrss-bytes",
            "wait4-ru_maxrss-kib-normalized-to-bytes",
        },
        "PC hotspot maximum RSS source differs",
    )
    timing = value["timing"]
    _require(
        type(timing) is dict and set(timing) == {"wall_ns", "user_ns", "system_ns"},
        "PC hotspot timing keys differ",
    )
    for field in ("wall_ns", "user_ns", "system_ns"):
        _integer(timing[field], f"PC hotspot {field}")
    _require(
        0 < timing["wall_ns"] <= (MAX_PRODUCER_SECONDS + 1) * 1_000_000_000,
        "PC hotspot wall timing differs",
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "status",
        "claim_boundary",
        "production",
        "no_extrapolation",
        "observer_executable",
        "observer_source",
        "elf",
        "input",
        "execution_journal",
        "argv",
        "sample",
        "observation_content_sha256",
        "per_pc",
        "opcode_transitions",
        "top_basic_edge_limit",
        "top_basic_edges",
        "canonical_totals",
        "transport",
        "process",
        "promotion",
        "content_sha256",
    }
    _require(type(value) is dict and set(value) == expected_keys,
             "PC hotspot evidence keys differ")
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["claim_boundary"] == CLAIM_BOUNDARY
        and value["production"] is False
        and value["no_extrapolation"] is True
        and value["content_sha256"] == protocol.content_sha256(value),
        "PC hotspot evidence authority differs",
    )
    executable = _validate_identity(
        value["observer_executable"], "PC hotspot observer executable",
    )
    _require(os.access(executable["path"], os.X_OK),
             "PC hotspot observer is not executable")
    _validate_identity(value["observer_source"], "PC hotspot observer source")
    elf = _validate_identity(value["elf"], "PC hotspot ELF")
    input_identity = _validate_identity(value["input"], "PC hotspot input", allow_empty=True)
    source = _validate_identity(value["execution_journal"],
                                "PC hotspot execution journal")
    sample = _sample_authority(
        journal_path=Path(source["path"]),
        elf=elf,
        input_identity=input_identity,
        first_segment_index=value["sample"].get("first_segment_index")
        if type(value["sample"]) is dict else -1,
        segment_count=value["sample"].get("segment_count")
        if type(value["sample"]) is dict else -1,
    )
    _require(_same_json(value["sample"], sample),
             "PC hotspot sample authority differs")
    expected_argv = _expected_argv(
        executable=executable,
        elf=elf,
        input_identity=input_identity,
        source=source,
        sample=sample,
    )
    _require(value["argv"] == expected_argv, "PC hotspot argv differs")
    _require_safe_argv(value["argv"], value["process"].get("timeout_seconds")
                       if type(value["process"]) is dict else None)
    transport = value["transport"]
    _require(
        type(transport) is dict and set(transport) == {"stdout", "stderr"},
        "PC hotspot transport differs",
    )
    stdout_identity = _validate_identity(transport["stdout"], "PC hotspot stdout")
    stderr_identity = _validate_identity(
        transport["stderr"], "PC hotspot stderr", allow_empty=True,
    )
    stdout_raw = store.read_regular(
        Path(stdout_identity["path"]),
        "PC hotspot stdout",
        maximum=MAX_OBSERVATION_BYTES,
    )
    stderr_raw = store.read_regular(
        Path(stderr_identity["path"]),
        "PC hotspot stderr",
        maximum=MAX_STDERR_BYTES,
    )
    _require(stderr_raw == b"", "PC hotspot observer stderr is not empty")
    observation = _decode_observation(
        stdout_raw,
        sample=sample,
        elf=elf,
        input_identity=input_identity,
        source=source,
    )
    top_edges = _top_edges(observation["basic_edges"], value["top_basic_edge_limit"])
    _require(
        value["observation_content_sha256"] == observation["content_sha256"]
        and _same_json(value["per_pc"], observation["per_pc"])
        and _same_json(value["opcode_transitions"], observation["opcode_transitions"])
        and _same_json(value["top_basic_edges"], top_edges)
        and _same_json(
            value["canonical_totals"], _canonical_totals(observation, top_edges),
        ),
        "PC hotspot evidence projection differs",
    )
    _validate_process(value["process"])
    _require(
        _same_json(value["promotion"], {
            "scope": "sampled-retirement-observer-process-only",
            "diagnostic_eligible": True,
            "proof_correctness": None,
            "fresh_verification": None,
            "full_corpus_estimate": None,
            "estimated_end_to_end_wall_ns": None,
            "production_promotion_eligible": False,
        }),
        "PC hotspot promotion boundary differs",
    )
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "PC hotspot evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        "PC hotspot evidence is not canonical JSON",
    )
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture or replay bounded PC-hotspot execution evidence",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    capture_parser = subparsers.add_parser("capture")
    capture_parser.add_argument("--executable", type=Path, required=True)
    capture_parser.add_argument("--observer-source", type=Path, required=True)
    capture_parser.add_argument("--elf", type=Path, required=True)
    capture_parser.add_argument("--input", type=Path, required=True)
    capture_parser.add_argument("--execution-journal", type=Path, required=True)
    capture_parser.add_argument("--first-segment-index", type=int, required=True)
    capture_parser.add_argument("--segment-count", type=int, required=True)
    capture_parser.add_argument(
        "--top-basic-edge-limit", type=int, default=DEFAULT_TOP_BASIC_EDGE_LIMIT,
    )
    capture_parser.add_argument(
        "--timeout-seconds", type=int, default=MAX_PRODUCER_SECONDS,
    )
    capture_parser.add_argument("--output", type=Path, required=True)
    capture_parser.add_argument("--staging", type=Path, required=True)
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "capture":
            value = capture(
                executable_path=arguments.executable,
                observer_source_path=arguments.observer_source,
                elf_path=arguments.elf,
                input_path=arguments.input,
                execution_journal_path=arguments.execution_journal,
                first_segment_index=arguments.first_segment_index,
                segment_count=arguments.segment_count,
                top_basic_edge_limit=arguments.top_basic_edge_limit,
                timeout_seconds=arguments.timeout_seconds,
                output_path=arguments.output,
                staging_directory=arguments.staging,
            )
        else:
            value = load(arguments.evidence)
        print(json.dumps({
            "schema": value["schema"],
            "status": value["status"],
            "content_sha256": value["content_sha256"],
            "production": value["production"],
            "no_extrapolation": value["no_extrapolation"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (PcHotspotEvidenceError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
