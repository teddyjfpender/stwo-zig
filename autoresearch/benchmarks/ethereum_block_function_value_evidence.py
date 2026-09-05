#!/usr/bin/env python3
"""Capture, seal, and replay bounded function-load value observations."""

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
import ethereum_block_function_value_contract as contract  # noqa: E402


SCHEMA = "stwo.riscv.function-load-value-observation-evidence.v1"
STATUS = "captured-diagnostic-only-nonpromotable"
CLAIM_BOUNDARY = contract.CLAIM_BOUNDARY
MAX_PRODUCER_SECONDS = 60
MAX_SAMPLE_SEGMENTS = contract.MAX_SAMPLE_SEGMENTS
MAX_OBSERVATION_BYTES = store.MAX_JSON_BYTES
MAX_STDERR_BYTES = 64 * 1024
POLL_SECONDS = 0.01
U32_MAX = contract.U32_MAX
FunctionValueEvidenceError = contract.FunctionValueContractError
_require = contract.require
_integer = contract.integer
_sample_authority = contract.sample_authority
_decode_observation = contract.decode_observation
validate_observation = contract.validate_observation


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
        "bytes": len(raw),
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _validate_identity(
    value: Any,
    where: str,
    *,
    allow_empty: bool = False,
) -> dict[str, Any]:
    _require(
        type(value) is dict
        and set(value) == {"bytes", "path", "sha256"}
        and type(value["path"]) is str
        and Path(value["path"]).is_absolute(),
        f"{where} keys differ",
    )
    _integer(value["bytes"], f"{where}.bytes", minimum=0 if allow_empty else 1)
    contract.sha256(value["sha256"], f"{where}.sha256")
    _require(
        value == _identity(Path(value["path"]), where, allow_empty=allow_empty),
        f"{where} identity differs",
    )
    return value


def _expected_argv(
    *,
    executable: dict[str, Any],
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    journal: dict[str, Any],
    observation: dict[str, Any],
) -> list[str]:
    return [
        executable["path"],
        "--elf",
        elf["path"],
        "--input",
        input_identity["path"],
        "--execution-journal",
        journal["path"],
        "--segment-count",
        str(observation["segment_count"]),
        "--entry-pc",
        str(observation["entry_pc"]),
        "--entry-instruction-word",
        str(observation["entry_instruction_word"]),
        "--value-pc",
        str(observation["value_pc"]),
        "--value-instruction-word",
        str(observation["value_instruction_word"]),
    ]


def _run(
    argv: list[str],
    staging: Path,
    timeout_seconds: int,
) -> tuple[bytes, bytes, dict[str, Any]]:
    _integer(
        timeout_seconds,
        "function-value timeout",
        minimum=1,
        maximum=MAX_PRODUCER_SECONDS,
    )
    _require(
        type(argv) is list
        and len(argv) == 17
        and all(type(item) is str and item for item in argv),
        "function-value producer argv differs",
    )
    stdout = tempfile.TemporaryFile(prefix="function-value.stdout.", dir=staging)
    stderr = tempfile.TemporaryFile(prefix="function-value.stderr.", dir=staging)
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
        raise FunctionValueEvidenceError(
            "function-value observer failed to launch"
        ) from error
    deadline = time.monotonic() + timeout_seconds
    outcome = None
    failure = None
    while outcome is None:
        outcome = child_process._wait4_nohang(child)
        if outcome is not None:
            break
        if os.fstat(stdout.fileno()).st_size > MAX_OBSERVATION_BYTES:
            failure = "function-value stdout exceeded its bound"
            break
        if os.fstat(stderr.fileno()).st_size > MAX_STDERR_BYTES:
            failure = "function-value stderr exceeded its bound"
            break
        if time.monotonic() >= deadline:
            failure = "function-value observer timed out"
            break
        time.sleep(POLL_SECONDS)
    if failure is not None:
        child_process._terminate_group(child)
        stdout.close()
        stderr.close()
        raise FunctionValueEvidenceError(failure)
    _require(outcome is not None, "function-value process wait differs")
    return_code, usage = outcome
    clean_group = child_process.drain_process_group(child, "function-value observer")
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
        "function-value observer did not complete cleanly",
    )
    maximum_rss = round(usage.ru_maxrss)
    maximum_rss_bytes = maximum_rss if sys.platform == "darwin" else maximum_rss * 1024
    return stdout_raw, stderr_raw, {
        "exit_code": return_code,
        "maximum_resident_set_bytes": maximum_rss_bytes,
        "maximum_resident_set_source": (
            "darwin-wait4-ru_maxrss-bytes"
            if sys.platform == "darwin"
            else "wait4-ru_maxrss-kib-normalized-to-bytes"
        ),
        "process_group_drained": True,
        "timeout_seconds": timeout_seconds,
        "timing": {
            "system_ns": max(0, round(usage.ru_stime * 1_000_000_000)),
            "user_ns": max(0, round(usage.ru_utime * 1_000_000_000)),
            "wall_ns": ended - started,
        },
    }


def _promotion() -> dict[str, Any]:
    return {
        "air_claim": None,
        "end_to_end_wall_ns": None,
        "fresh_verification": None,
        "performance_claim_eligible": False,
        "production_promotion_eligible": False,
        "proof_correctness": None,
        "scope": "sampled-function-load-value-observation-only",
    }


def _totals(observation: dict[str, Any]) -> dict[str, Any]:
    return {
        "distinct_value_count": len(observation["histogram"]),
        "entry_count": observation["entry_count"],
        "histogram_count_sum": sum(row["count"] for row in observation["histogram"]),
        "histogram_weighted_sum": sum(
            row["count"] * row["value"] for row in observation["histogram"]
        ),
        "maximum_value": observation["histogram"][-1]["value"],
        "minimum_value": observation["histogram"][0]["value"],
        "pending_entry_count": observation["pending_entry_count"],
        "value_count": observation["value_count"],
    }


def _same_json(left: Any, right: Any) -> bool:
    return protocol.canonical_bytes(left) == protocol.canonical_bytes(right)


def _build_evidence(
    *,
    mode: str,
    executable: dict[str, Any],
    observer_source: dict[str, Any],
    elf: dict[str, Any],
    input_identity: dict[str, Any],
    journal: dict[str, Any],
    raw_observation: dict[str, Any],
    stderr: dict[str, Any] | None,
    sample: dict[str, Any],
    observation: dict[str, Any],
    process: dict[str, Any] | None,
) -> dict[str, Any]:
    return protocol.seal({
        "argv": _expected_argv(
            executable=executable,
            elf=elf,
            input_identity=input_identity,
            journal=journal,
            observation=observation,
        ),
        "canonical_totals": _totals(observation),
        "claim_boundary": CLAIM_BOUNDARY,
        "elf": elf,
        "execution_journal": journal,
        "input": input_identity,
        "mode": mode,
        "no_extrapolation": True,
        "observation": observation,
        "observer_executable": executable,
        "observer_source": observer_source,
        "process": process,
        "production": False,
        "promotion": _promotion(),
        "raw_observation": raw_observation,
        "sample": sample,
        "schema": SCHEMA,
        "status": STATUS,
        "stderr": stderr,
    })


def admit(
    *,
    executable_path: Path,
    observer_source_path: Path,
    elf_path: Path,
    input_path: Path,
    execution_journal_path: Path,
    observation_path: Path,
    output_path: Path,
    staging_directory: Path,
) -> dict[str, Any]:
    executable = _identity(executable_path, "function-value observer executable")
    observer_source = _identity(observer_source_path, "function-value observer source")
    elf = _identity(elf_path, "function-value ELF")
    input_identity = _identity(input_path, "function-value input", allow_empty=True)
    journal = _identity(execution_journal_path, "function-value execution journal")
    raw_observation = _identity(observation_path, "function-value raw observation")
    _require(os.access(executable["path"], os.X_OK),
             "function-value observer is not executable")
    raw = store.read_regular(
        observation_path.absolute(),
        "function-value raw observation",
        maximum=MAX_OBSERVATION_BYTES,
    )
    predecoded = store.decode_strict(raw)
    _require(type(predecoded) is dict,
             "function-value observation is not an object")
    segment_count = predecoded.get("segment_count")
    _integer(
        segment_count,
        "function-value segment count",
        minimum=1,
        maximum=MAX_SAMPLE_SEGMENTS,
    )
    sample = _sample_authority(
        journal_path=execution_journal_path.absolute(),
        elf=elf,
        input_identity=input_identity,
        segment_count=segment_count,
    )
    observation = _decode_observation(
        raw,
        elf=elf,
        input_identity=input_identity,
        journal=journal,
        sample=sample,
    )
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    store.require_directory(output_path.parent, "function-value evidence parent")
    store.require_directory(staging_directory, "function-value staging", create=True)
    value = _build_evidence(
        mode="retained-observation-admission",
        executable=executable,
        observer_source=observer_source,
        elf=elf,
        input_identity=input_identity,
        journal=journal,
        raw_observation=raw_observation,
        stderr=None,
        sample=sample,
        observation=observation,
        process=None,
    )
    store.publish_new_or_identical(
        output_path,
        protocol.canonical_bytes(value),
        staging_directory=staging_directory,
    )
    return value


def capture(
    *,
    executable_path: Path,
    observer_source_path: Path,
    elf_path: Path,
    input_path: Path,
    execution_journal_path: Path,
    segment_count: int,
    entry_pc: int,
    entry_instruction_word: int,
    value_pc: int,
    value_instruction_word: int,
    timeout_seconds: int,
    output_path: Path,
    staging_directory: Path,
) -> dict[str, Any]:
    executable = _identity(executable_path, "function-value observer executable")
    observer_source = _identity(observer_source_path, "function-value observer source")
    elf = _identity(elf_path, "function-value ELF")
    input_identity = _identity(input_path, "function-value input", allow_empty=True)
    journal = _identity(execution_journal_path, "function-value execution journal")
    _require(os.access(executable["path"], os.X_OK),
             "function-value observer is not executable")
    for value, where in (
        (entry_pc, "entry PC"),
        (entry_instruction_word, "entry instruction word"),
        (value_pc, "value PC"),
        (value_instruction_word, "value instruction word"),
    ):
        _integer(value, f"function-value {where}", maximum=U32_MAX)
    _require(entry_pc != value_pc, "function-value PCs must differ")
    sample = _sample_authority(
        journal_path=execution_journal_path.absolute(),
        elf=elf,
        input_identity=input_identity,
        segment_count=segment_count,
    )
    expected = {
        "segment_count": segment_count,
        "entry_pc": entry_pc,
        "entry_instruction_word": entry_instruction_word,
        "value_pc": value_pc,
        "value_instruction_word": value_instruction_word,
    }
    argv = _expected_argv(
        executable=executable,
        elf=elf,
        input_identity=input_identity,
        journal=journal,
        observation=expected,
    )
    output_path = output_path.absolute()
    staging_directory = staging_directory.absolute()
    store.require_directory(output_path.parent, "function-value evidence parent")
    store.require_directory(staging_directory, "function-value staging", create=True)
    raw, stderr_raw, process = _run(argv, staging_directory, timeout_seconds)
    _require(stderr_raw == b"", "function-value observer stderr is not empty")
    observation = _decode_observation(
        raw,
        elf=elf,
        input_identity=input_identity,
        journal=journal,
        sample=sample,
    )
    for field, expected_value in expected.items():
        _require(observation[field] == expected_value,
                 f"function-value observed {field} differs")
    observation_path = output_path.with_name(f"{output_path.stem}.observation.json")
    stderr_path = output_path.with_name(f"{output_path.stem}.stderr")
    store.publish_new_or_identical(
        observation_path, raw, staging_directory=staging_directory,
    )
    store.publish_new_or_identical(
        stderr_path, stderr_raw, staging_directory=staging_directory,
    )
    value = _build_evidence(
        mode="adapter-process-group-capture",
        executable=executable,
        observer_source=observer_source,
        elf=elf,
        input_identity=input_identity,
        journal=journal,
        raw_observation=_identity(
            observation_path, "function-value raw observation",
        ),
        stderr=_identity(stderr_path, "function-value stderr", allow_empty=True),
        sample=sample,
        observation=observation,
        process=process,
    )
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
            "maximum_resident_set_bytes",
            "maximum_resident_set_source",
            "process_group_drained",
            "timeout_seconds",
            "timing",
        }
        and value["exit_code"] == 0
        and value["process_group_drained"] is True,
        "function-value process receipt differs",
    )
    _integer(
        value["timeout_seconds"],
        "function-value timeout",
        minimum=1,
        maximum=MAX_PRODUCER_SECONDS,
    )
    _integer(
        value["maximum_resident_set_bytes"],
        "function-value maximum RSS",
        minimum=1,
    )
    _require(
        value["maximum_resident_set_source"] in {
            "darwin-wait4-ru_maxrss-bytes",
            "wait4-ru_maxrss-kib-normalized-to-bytes",
        },
        "function-value maximum RSS source differs",
    )
    timing = value["timing"]
    _require(
        type(timing) is dict
        and set(timing) == {"system_ns", "user_ns", "wall_ns"},
        "function-value timing keys differ",
    )
    for field in ("system_ns", "user_ns", "wall_ns"):
        _integer(timing[field], f"function-value {field}")
    _require(
        0 < timing["wall_ns"]
        <= (value["timeout_seconds"] + 1) * 1_000_000_000,
        "function-value wall timing differs",
    )
    return value


def validate(value: Any) -> dict[str, Any]:
    expected_keys = {
        "argv",
        "canonical_totals",
        "claim_boundary",
        "content_sha256",
        "elf",
        "execution_journal",
        "input",
        "mode",
        "no_extrapolation",
        "observation",
        "observer_executable",
        "observer_source",
        "process",
        "production",
        "promotion",
        "raw_observation",
        "sample",
        "schema",
        "status",
        "stderr",
    }
    _require(type(value) is dict and set(value) == expected_keys,
             "function-value evidence keys differ")
    _require(
        value["schema"] == SCHEMA
        and value["status"] == STATUS
        and value["claim_boundary"] == CLAIM_BOUNDARY
        and value["production"] is False
        and value["no_extrapolation"] is True
        and value["content_sha256"] == protocol.content_sha256(value),
        "function-value evidence authority differs",
    )
    executable = _validate_identity(
        value["observer_executable"], "function-value observer executable",
    )
    _require(os.access(executable["path"], os.X_OK),
             "function-value observer is not executable")
    _validate_identity(value["observer_source"], "function-value observer source")
    elf = _validate_identity(value["elf"], "function-value ELF")
    input_identity = _validate_identity(
        value["input"], "function-value input", allow_empty=True,
    )
    journal = _validate_identity(
        value["execution_journal"], "function-value execution journal",
    )
    raw_identity = _validate_identity(
        value["raw_observation"], "function-value raw observation",
    )
    raw = store.read_regular(
        Path(raw_identity["path"]),
        "function-value raw observation",
        maximum=MAX_OBSERVATION_BYTES,
    )
    segment_count = value["sample"].get("segment_count") \
        if type(value["sample"]) is dict else None
    sample = _sample_authority(
        journal_path=Path(journal["path"]),
        elf=elf,
        input_identity=input_identity,
        segment_count=segment_count,
    )
    _require(_same_json(value["sample"], sample),
             "function-value sample authority differs")
    observation = _decode_observation(
        raw,
        elf=elf,
        input_identity=input_identity,
        journal=journal,
        sample=sample,
    )
    _require(_same_json(value["observation"], observation),
             "function-value observation projection differs")
    expected_argv = _expected_argv(
        executable=executable,
        elf=elf,
        input_identity=input_identity,
        journal=journal,
        observation=observation,
    )
    _require(value["argv"] == expected_argv,
             "function-value argv differs")
    _require(_same_json(value["canonical_totals"], _totals(observation)),
             "function-value canonical totals differ")
    if value["mode"] == "adapter-process-group-capture":
        _validate_process(value["process"])
        _validate_identity(value["stderr"], "function-value stderr", allow_empty=True)
        _require(
            store.read_regular(
                Path(value["stderr"]["path"]),
                "function-value stderr",
                maximum=MAX_STDERR_BYTES,
            ) == b"",
            "function-value observer stderr is not empty",
        )
    elif value["mode"] == "retained-observation-admission":
        _require(value["process"] is None and value["stderr"] is None,
                 "function-value retained admission process differs")
    else:
        raise FunctionValueEvidenceError("function-value capture mode differs")
    _require(_same_json(value["promotion"], _promotion()),
             "function-value promotion boundary differs")
    return value


def load(path: Path) -> dict[str, Any]:
    raw = store.read_regular(
        path.absolute(), "function-value evidence", maximum=store.MAX_JSON_BYTES,
    )
    value = store.decode_strict(raw)
    _require(
        type(value) is dict and raw == protocol.canonical_bytes(value),
        "function-value evidence is not canonical JSON",
    )
    return validate(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Capture, admit, or replay function-load value evidence",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--executable", type=Path, required=True)
    common.add_argument("--observer-source", type=Path, required=True)
    common.add_argument("--elf", type=Path, required=True)
    common.add_argument("--input", type=Path, required=True)
    common.add_argument("--execution-journal", type=Path, required=True)
    common.add_argument("--output", type=Path, required=True)
    common.add_argument("--staging", type=Path, required=True)
    admit_parser = subparsers.add_parser("admit", parents=[common])
    admit_parser.add_argument("--observation", type=Path, required=True)
    capture_parser = subparsers.add_parser("capture", parents=[common])
    capture_parser.add_argument("--segment-count", type=int, required=True)
    capture_parser.add_argument("--entry-pc", type=lambda item: int(item, 0), required=True)
    capture_parser.add_argument(
        "--entry-instruction-word", type=lambda item: int(item, 0), required=True,
    )
    capture_parser.add_argument("--value-pc", type=lambda item: int(item, 0), required=True)
    capture_parser.add_argument(
        "--value-instruction-word", type=lambda item: int(item, 0), required=True,
    )
    capture_parser.add_argument(
        "--timeout-seconds", type=int, default=MAX_PRODUCER_SECONDS,
    )
    replay_parser = subparsers.add_parser("replay")
    replay_parser.add_argument("--evidence", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "admit":
            value = admit(
                executable_path=arguments.executable,
                observer_source_path=arguments.observer_source,
                elf_path=arguments.elf,
                input_path=arguments.input,
                execution_journal_path=arguments.execution_journal,
                observation_path=arguments.observation,
                output_path=arguments.output,
                staging_directory=arguments.staging,
            )
        elif arguments.command == "capture":
            value = capture(
                executable_path=arguments.executable,
                observer_source_path=arguments.observer_source,
                elf_path=arguments.elf,
                input_path=arguments.input,
                execution_journal_path=arguments.execution_journal,
                segment_count=arguments.segment_count,
                entry_pc=arguments.entry_pc,
                entry_instruction_word=arguments.entry_instruction_word,
                value_pc=arguments.value_pc,
                value_instruction_word=arguments.value_instruction_word,
                timeout_seconds=arguments.timeout_seconds,
                output_path=arguments.output,
                staging_directory=arguments.staging,
            )
        else:
            value = load(arguments.evidence)
        print(json.dumps({
            "content_sha256": value["content_sha256"],
            "mode": value["mode"],
            "production": value["production"],
            "schema": value["schema"],
            "status": value["status"],
        }, sort_keys=True, separators=(",", ":")))
        return 0
    except (FunctionValueEvidenceError, protocol.ProofProtocolError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
