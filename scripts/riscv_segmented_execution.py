#!/usr/bin/env python3
"""Durable controller for the RISC-V segmented execution NDJSON stream.

The Zig tool deliberately keeps no on-disk session checkpoint.  Recovery
replays deterministic execution from the ELF, byte-compares the fsynced journal
prefix, and appends only new records.  This makes a crash cost one execution
replay, not the already-published segment proofs that will consume this journal.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
from typing import Any

HEADER_SCHEMA = "stwo.riscv.segmented-execution-header.v1"
SEGMENT_SCHEMA = "stwo.riscv.segmented-execution-segment.v1"
SUMMARY_SCHEMA = "stwo.riscv.segmented-execution-summary.v1"
PLAN_SCHEMA = "stwo.riscv.segmented-execution-capture-plan.v1"
RECEIPT_SCHEMA = "stwo.riscv.segmented-execution-capture-receipt.v1"
CLAIM_BOUNDARY = "execution-only-not-a-proof"
MIN_SEGMENT_STEPS = 1 << 16
MAX_SEGMENT_STEPS = 1 << 24
MAX_RECORD_BYTES = 64 * 1024
MAX_JOURNAL_BYTES = 64 * 1024 * 1024
HEX64 = frozenset("0123456789abcdef")
FAMILIES = (
    "auipc",
    "base_alu_imm",
    "base_alu_reg",
    "branch_eq",
    "branch_lt",
    "div",
    "jal",
    "jalr",
    "load_store",
    "lt_imm",
    "lt_reg",
    "lui",
    "mul",
    "mulh",
    "shifts_imm",
    "shifts_reg",
    "fence",
)


class ContractError(RuntimeError):
    pass


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_identity(path: Path) -> dict[str, Any]:
    _require_regular(path)
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": _sha(data)}


def _require_regular(path: Path) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError as exc:
        raise ContractError(f"missing path: {path}") from exc
    if not stat.S_ISREG(mode) or path.is_symlink():
        raise ContractError(f"path must be a regular non-symlink: {path}")


def _require_directory(path: Path) -> None:
    mode = path.lstat().st_mode
    if not stat.S_ISDIR(mode) or path.is_symlink():
        raise ContractError(f"bundle must be a directory, not a symlink: {path}")


def _keys(value: Any, expected: tuple[str, ...], label: str) -> dict[str, Any]:
    if type(value) is not dict or tuple(value) != expected:
        raise ContractError(f"{label} keys/order mismatch")
    return value


def _integer(value: Any, label: str, minimum: int = 0, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{label} must be an integer in [{minimum},{maximum}]")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ContractError(f"{label} must be boolean")
    return value


def _hex64(value: Any, label: str) -> str:
    if type(value) is not str or len(value) != 64 or any(ch not in HEX64 for ch in value):
        raise ContractError(f"{label} must be canonical lowercase SHA-256")
    return value


def _optional_hex(value: Any, label: str) -> str | None:
    return None if value is None else _hex64(value, label)


def _family_rows(value: Any, label: str) -> dict[str, int]:
    if type(value) is not list or len(value) != len(FAMILIES):
        raise ContractError(f"{label} must contain every typed opcode family")
    result: dict[str, int] = {}
    for index, record in enumerate(value):
        record = _keys(record, ("family", "rows"), f"{label}[{index}]")
        if record["family"] != FAMILIES[index]:
            raise ContractError(f"{label} family order mismatch")
        result[record["family"]] = _integer(record["rows"], f"{label}.rows")
    return result


def _boundary(value: Any, label: str) -> dict[str, Any]:
    value = _keys(
        value,
        (
            "pc",
            "cpu_sha256",
            "rw_memory_sha256",
            "rw_memory_retained_words",
            "rw_memory_nonzero_words",
            "access_clocks_sha256",
            "memory_access_clock_entries",
        ),
        label,
    )
    _integer(value["pc"], f"{label}.pc", maximum=(1 << 32) - 1)
    _hex64(value["cpu_sha256"], f"{label}.cpu_sha256")
    _hex64(value["rw_memory_sha256"], f"{label}.rw_memory_sha256")
    retained = _integer(value["rw_memory_retained_words"], f"{label}.retained")
    nonzero = _integer(value["rw_memory_nonzero_words"], f"{label}.nonzero")
    if nonzero > retained:
        raise ContractError(f"{label} nonzero memory exceeds retained words")
    _hex64(value["access_clocks_sha256"], f"{label}.access_clocks_sha256")
    _integer(value["memory_access_clock_entries"], f"{label}.clock_entries")
    return value


def _parse_line(line: bytes, index: int) -> dict[str, Any]:
    if not line.endswith(b"\n") or len(line) > MAX_RECORD_BYTES:
        raise ContractError(f"record {index} has invalid transport framing")
    try:
        record = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"record {index} is not canonical JSON") from exc
    record = _keys(record, ("payload", "content_sha256"), f"record {index}")
    digest = _hex64(record["content_sha256"], f"record {index}.content_sha256")
    if _sha(_canonical(record["payload"])) != digest:
        raise ContractError(f"record {index} content digest mismatch")
    if _canonical(record) + b"\n" != line:
        raise ContractError(f"record {index} is not canonical one-line JSON")
    return record


def validate_records(
    lines: list[bytes],
    plan: dict[str, Any] | None = None,
    *,
    require_complete: bool,
) -> dict[str, Any] | None:
    if not lines:
        if require_complete:
            raise ContractError("execution journal is empty")
        return None
    records = [_parse_line(line, index) for index, line in enumerate(lines)]
    header = _keys(
        records[0]["payload"],
        (
            "schema",
            "profile",
            "claim_boundary",
            "elf_bytes",
            "elf_sha256",
            "input_bytes",
            "input_sha256",
            "segment_step_budget",
            "strict_completion",
            "trace_retention",
        ),
        "header",
    )
    if header["schema"] != HEADER_SCHEMA or header["profile"] != "rv32im-zkvm-v1":
        raise ContractError("unsupported segmented execution header")
    if header["claim_boundary"] != CLAIM_BOUNDARY or header["trace_retention"] != "segment-owned":
        raise ContractError("execution claim boundary/retention mismatch")
    _boolean(header["strict_completion"], "header.strict_completion")
    budget = _integer(
        header["segment_step_budget"],
        "header.segment_step_budget",
        MIN_SEGMENT_STEPS,
        MAX_SEGMENT_STEPS,
    )
    _hex64(header["elf_sha256"], "header.elf_sha256")
    _hex64(header["input_sha256"], "header.input_sha256")
    if plan is not None:
        if header["elf_bytes"] != plan["elf"]["bytes"] or header["elf_sha256"] != plan["elf"]["sha256"]:
            raise ContractError("header ELF identity differs from capture plan")
        if header["input_bytes"] != plan["input"]["bytes"] or header["input_sha256"] != plan["input"]["sha256"]:
            raise ContractError("header input identity differs from capture plan")
        if budget != plan["segment_step_budget"] or not header["strict_completion"]:
            raise ContractError("header execution policy differs from capture plan")

    previous_digest = records[0]["content_sha256"]
    expected_cycle = 1
    expected_cpu: str | None = None
    expected_memory: str | None = None
    expected_clocks: str | None = None
    totals = {family: 0 for family in FAMILIES}
    total_cycles = total_core = total_external = total_unclassified = 0
    segment_count = 0
    last_segment: dict[str, Any] | None = None
    summary: dict[str, Any] | None = None

    for record_index, record in enumerate(records[1:], 1):
        payload = record["payload"]
        schema = payload.get("schema") if type(payload) is dict else None
        if schema == SUMMARY_SCHEMA:
            if record_index != len(records) - 1:
                raise ContractError("summary must be the final journal record")
            summary = payload
            break
        payload = _keys(
            payload,
            (
                "schema",
                "previous_record_sha256",
                "segment_index",
                "global_first_cycle",
                "cycle_count",
                "is_first",
                "is_last",
                "entry",
                "exit",
                "core_trace_rows",
                "external_trace_rows",
                "unclassified_core_rows",
                "opcode_family_rows",
                "completion_reason",
                "completion_address",
                "completion_value",
                "completion_clock",
                "exit_code",
                "output_bytes",
                "output_sha256",
                "continuation_sha256",
            ),
            f"segment {segment_count}",
        )
        if payload["schema"] != SEGMENT_SCHEMA or payload["previous_record_sha256"] != previous_digest:
            raise ContractError("segment schema/hash chain mismatch")
        if _integer(payload["segment_index"], "segment_index", maximum=(1 << 32) - 1) != segment_count:
            raise ContractError("segment index is not contiguous")
        if _integer(payload["global_first_cycle"], "global_first_cycle") != expected_cycle:
            raise ContractError("segment cycle range is not contiguous")
        cycles = _integer(payload["cycle_count"], "cycle_count", 1, budget)
        is_first = _boolean(payload["is_first"], "is_first")
        is_last = _boolean(payload["is_last"], "is_last")
        if is_first != (segment_count == 0):
            raise ContractError("segment first-role mismatch")
        entry = _boundary(payload["entry"], "entry")
        exit_state = _boundary(payload["exit"], "exit")
        if expected_cpu is not None and (
            entry["cpu_sha256"] != expected_cpu
            or entry["rw_memory_sha256"] != expected_memory
            or entry["access_clocks_sha256"] != expected_clocks
        ):
            raise ContractError("adjacent segment boundary mismatch")
        core = _integer(payload["core_trace_rows"], "core_trace_rows")
        external = _integer(payload["external_trace_rows"], "external_trace_rows")
        unclassified = _integer(payload["unclassified_core_rows"], "unclassified_core_rows")
        family_rows = _family_rows(payload["opcode_family_rows"], "opcode_family_rows")
        if core + external != cycles or sum(family_rows.values()) + unclassified != core:
            raise ContractError("segment row inventory does not close")
        for family, count in family_rows.items():
            totals[family] += count
        total_cycles += cycles
        total_core += core
        total_external += external
        total_unclassified += unclassified
        completion = payload["completion_reason"]
        if completion is not None and type(completion) is not str:
            raise ContractError("completion_reason must be a string or null")
        output_bytes = payload["output_bytes"]
        if output_bytes is not None:
            _integer(output_bytes, "output_bytes")
        output_sha = _optional_hex(payload["output_sha256"], "output_sha256")
        continuation = _optional_hex(payload["continuation_sha256"], "continuation_sha256")
        if is_last:
            if completion is None or continuation is not None or (output_bytes is None) != (output_sha is None):
                raise ContractError("completed segment publication is malformed")
        elif completion is not None or continuation is None or output_bytes is not None or output_sha is not None:
            raise ContractError("yielded segment publication is malformed")
        _integer(payload["completion_address"], "completion_address", maximum=(1 << 32) - 1)
        _integer(payload["completion_value"], "completion_value", maximum=(1 << 32) - 1)
        _integer(payload["completion_clock"], "completion_clock", maximum=(1 << 32) - 1)
        if payload["exit_code"] is not None:
            _integer(payload["exit_code"], "exit_code", maximum=(1 << 32) - 1)
        expected_cycle += cycles
        expected_cpu = exit_state["cpu_sha256"]
        expected_memory = exit_state["rw_memory_sha256"]
        expected_clocks = exit_state["access_clocks_sha256"]
        previous_digest = record["content_sha256"]
        segment_count += 1
        last_segment = payload

    if summary is None:
        if require_complete:
            raise ContractError("execution journal has no final summary")
        return None
    if last_segment is None or not last_segment["is_last"]:
        raise ContractError("summary does not follow a completed segment")
    summary = _keys(
        summary,
        (
            "schema",
            "previous_record_sha256",
            "claim_boundary",
            "completed",
            "segment_count",
            "total_cycles",
            "total_core_trace_rows",
            "total_external_trace_rows",
            "total_unclassified_core_rows",
            "opcode_family_rows",
            "completion_reason",
            "exit_code",
            "output_bytes",
            "output_sha256",
            "final_cpu_sha256",
            "final_rw_memory_sha256",
            "final_access_clocks_sha256",
            "segment_statement_v2_global_cycle_limit",
            "segment_statement_v2_admissible",
        ),
        "summary",
    )
    if summary["previous_record_sha256"] != previous_digest or summary["claim_boundary"] != CLAIM_BOUNDARY:
        raise ContractError("summary chain/claim boundary mismatch")
    if not _boolean(summary["completed"], "summary.completed"):
        raise ContractError("summary is not complete")
    exact = (
        summary["segment_count"] == segment_count
        and summary["total_cycles"] == total_cycles
        and summary["total_core_trace_rows"] == total_core
        and summary["total_external_trace_rows"] == total_external
        and summary["total_unclassified_core_rows"] == total_unclassified
        and _family_rows(summary["opcode_family_rows"], "summary.opcode_family_rows") == totals
        and summary["completion_reason"] == last_segment["completion_reason"]
        and summary["exit_code"] == last_segment["exit_code"]
        and summary["output_bytes"] == last_segment["output_bytes"]
        and summary["output_sha256"] == last_segment["output_sha256"]
        and summary["final_cpu_sha256"] == last_segment["exit"]["cpu_sha256"]
        and summary["final_rw_memory_sha256"] == last_segment["exit"]["rw_memory_sha256"]
        and summary["final_access_clocks_sha256"] == last_segment["exit"]["access_clocks_sha256"]
    )
    if not exact:
        raise ContractError("summary does not exactly reduce the segment journal")
    v2_limit = _integer(summary["segment_statement_v2_global_cycle_limit"], "v2 limit", 1)
    if _boolean(summary["segment_statement_v2_admissible"], "v2 admissible") != (total_cycles <= v2_limit):
        raise ContractError("summary V2 claim boundary is inconsistent")
    return summary


def _git_authority(repository: Path) -> dict[str, Any]:
    def run(*args: str) -> bytes:
        return subprocess.check_output(("git", "-C", str(repository), *args))

    head = run("rev-parse", "HEAD").decode("ascii").strip()
    tree = run("rev-parse", "HEAD^{tree}").decode("ascii").strip()
    status = run("status", "--porcelain=v1", "-z", "--untracked-files=all")
    return {"head": head, "tree": tree, "status_sha256": _sha(status), "clean": not status}


def make_plan(
    repository: Path,
    tool: Path,
    elf: Path,
    input_path: Path | None,
    segment_steps: int,
) -> dict[str, Any]:
    if not MIN_SEGMENT_STEPS <= segment_steps <= MAX_SEGMENT_STEPS:
        raise ContractError(
            f"segment steps must be in [{MIN_SEGMENT_STEPS},{MAX_SEGMENT_STEPS}]; "
            "tiny segments create pathological journals"
        )
    empty_sha = _sha(b"")
    input_identity = (
        _file_identity(input_path)
        if input_path is not None
        else {"path": None, "bytes": 0, "sha256": empty_sha}
    )
    command = [str(tool), "--elf", str(elf), "--segment-steps", str(segment_steps)]
    if input_path is not None:
        command.extend(("--input", str(input_path)))
    return {
        "schema": PLAN_SCHEMA,
        "repository": str(repository),
        "source": _git_authority(repository),
        "controller": _file_identity(Path(__file__).resolve()),
        "tool": _file_identity(tool),
        "elf": _file_identity(elf),
        "input": input_identity,
        "segment_step_budget": segment_steps,
        "strict_completion": True,
        "command": command,
    }


def _write_new_or_identical(path: Path, content: bytes) -> None:
    if path.exists() or path.is_symlink():
        _require_regular(path)
        if path.read_bytes() != content:
            raise ContractError(f"existing file differs from canonical bytes: {path}")
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_journal(path: Path) -> list[bytes]:
    if not path.exists() and not path.is_symlink():
        return []
    _require_regular(path)
    data = path.read_bytes()
    if len(data) > MAX_JOURNAL_BYTES:
        raise ContractError("execution journal exceeds bounded size")
    if data and not data.endswith(b"\n"):
        end = data.rfind(b"\n") + 1
        fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.ftruncate(fd, end)
            os.fsync(fd)
        finally:
            os.close(fd)
        data = data[:end]
    return data.splitlines(keepends=True)


def _append_line(path: Path, line: bytes) -> None:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ContractError("journal append target is not regular")
        view = memoryview(line)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _receipt(plan: dict[str, Any], journal_path: Path, summary: dict[str, Any]) -> dict[str, Any]:
    journal = journal_path.read_bytes()
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "complete",
        "claim_boundary": CLAIM_BOUNDARY,
        "plan_sha256": _sha(_canonical(plan)),
        "journal_bytes": len(journal),
        "journal_sha256": _sha(journal),
        "segment_count": summary["segment_count"],
        "total_cycles": summary["total_cycles"],
        "total_core_trace_rows": summary["total_core_trace_rows"],
        "total_external_trace_rows": summary["total_external_trace_rows"],
        "segment_statement_v2_admissible": summary["segment_statement_v2_admissible"],
        "final_cpu_sha256": summary["final_cpu_sha256"],
        "final_rw_memory_sha256": summary["final_rw_memory_sha256"],
        "output_sha256": summary["output_sha256"],
    }


def _lock_bundle(bundle: Path) -> int:
    path = bundle / ".capture.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ContractError("capture lock is not regular")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise ContractError("another capture owns this bundle") from exc
    return fd


def capture_bundle(
    *,
    repository: Path,
    bundle: Path,
    tool: Path,
    elf: Path,
    input_path: Path | None,
    segment_steps: int,
    max_new_segments: int | None = None,
    require_clean: bool = False,
) -> dict[str, Any] | None:
    repository = repository.resolve(strict=True)
    tool = tool.resolve(strict=True)
    elf = elf.resolve(strict=True)
    input_path = input_path.resolve(strict=True) if input_path is not None else None
    bundle = bundle.resolve(strict=False)
    plan = make_plan(repository, tool, elf, input_path, segment_steps)
    if require_clean and not plan["source"]["clean"]:
        raise ContractError("clean source is required")
    if bundle.exists() or bundle.is_symlink():
        _require_directory(bundle)
    else:
        bundle.mkdir(mode=0o700)
    lock_fd = _lock_bundle(bundle)
    try:
        plan_path = bundle / "plan.json"
        plan_bytes = _canonical(plan) + b"\n"
        _write_new_or_identical(plan_path, plan_bytes)
        stored_plan = json.loads(plan_path.read_bytes())
        if stored_plan != plan:
            raise ContractError("capture plan identity changed across resume")
        journal_path = bundle / "execution.ndjson"
        lines = _read_journal(journal_path)
        summary = validate_records(lines, plan, require_complete=False) if lines else None
        if summary is not None:
            receipt = _receipt(plan, journal_path, summary)
            _write_new_or_identical(bundle / "receipt.json", _canonical(receipt) + b"\n")
            return receipt

        invocation = len(tuple(bundle.glob("invocation-*.stderr")))
        stderr_path = bundle / f"invocation-{invocation:06d}.stderr"
        stderr_file = open(stderr_path, "xb")
        process = subprocess.Popen(
            plan["command"],
            stdout=subprocess.PIPE,
            stderr=stderr_file,
            start_new_session=True,
        )
        assert process.stdout is not None
        seen = 0
        new_segments = 0
        stopped = False
        try:
            for raw in process.stdout:
                if len(raw) > MAX_RECORD_BYTES:
                    raise ContractError("tool emitted an oversized record")
                if seen < len(lines):
                    if raw != lines[seen]:
                        raise ContractError(f"replayed record {seen} differs from durable prefix")
                    seen += 1
                    continue
                candidate = lines + [raw]
                validate_records(candidate, plan, require_complete=False)
                _append_line(journal_path, raw)
                lines.append(raw)
                seen += 1
                payload = json.loads(raw)["payload"]
                if payload["schema"] == SEGMENT_SCHEMA:
                    new_segments += 1
                    if max_new_segments is not None and new_segments >= max_new_segments and not payload["is_last"]:
                        stopped = True
                        _terminate_group(process)
                        break
            if not stopped:
                return_code = process.wait()
                if return_code != 0:
                    raise ContractError(f"segmented execution tool exited {return_code}")
        finally:
            if process.poll() is None:
                _terminate_group(process)
            process.stdout.close()
            stderr_file.close()
        if stderr_path.stat().st_size != 0:
            raise ContractError(f"segmented execution emitted stderr: {stderr_path}")
        if stopped:
            validate_records(lines, plan, require_complete=False)
            return None
        summary = validate_records(lines, plan, require_complete=True)
        assert summary is not None
        receipt = _receipt(plan, journal_path, summary)
        _write_new_or_identical(bundle / "receipt.json", _canonical(receipt) + b"\n")
        return receipt
    finally:
        os.close(lock_fd)


def validate_bundle(bundle: Path) -> dict[str, Any]:
    bundle = bundle.resolve(strict=True)
    _require_directory(bundle)
    plan_path = bundle / "plan.json"
    receipt_path = bundle / "receipt.json"
    journal_path = bundle / "execution.ndjson"
    for path in (plan_path, receipt_path, journal_path):
        _require_regular(path)
    plan_raw = plan_path.read_bytes()
    receipt_raw = receipt_path.read_bytes()
    if not plan_raw.endswith(b"\n") or not receipt_raw.endswith(b"\n"):
        raise ContractError("plan/receipt must have exactly one terminal LF")
    plan = json.loads(plan_raw)
    if _canonical(plan) + b"\n" != plan_raw or plan.get("schema") != PLAN_SCHEMA:
        raise ContractError("capture plan is not canonical")
    lines = _read_journal(journal_path)
    summary = validate_records(lines, plan, require_complete=True)
    assert summary is not None
    expected = _receipt(plan, journal_path, summary)
    actual = json.loads(receipt_raw)
    if actual != expected or _canonical(actual) + b"\n" != receipt_raw:
        raise ContractError("capture receipt does not recompute")
    return actual


def _path(value: str) -> Path:
    return Path(value)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--repository", type=_path, default=Path.cwd())
    capture.add_argument("--bundle", type=_path, required=True)
    capture.add_argument("--tool", type=_path, required=True)
    capture.add_argument("--elf", type=_path, required=True)
    capture.add_argument("--input", type=_path)
    capture.add_argument("--segment-steps", type=int, required=True)
    capture.add_argument("--max-new-segments", type=int)
    capture.add_argument("--require-clean", action="store_true")
    validate = sub.add_parser("validate")
    validate.add_argument("bundle", type=_path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "validate":
            result = validate_bundle(args.bundle)
        else:
            if args.max_new_segments is not None and args.max_new_segments <= 0:
                raise ContractError("max-new-segments must be positive")
            result = capture_bundle(
                repository=args.repository,
                bundle=args.bundle,
                tool=args.tool,
                elf=args.elf,
                input_path=args.input,
                segment_steps=args.segment_steps,
                max_new_segments=args.max_new_segments,
                require_clean=args.require_clean,
            )
            if result is None:
                print(_canonical({"status": "partial", "bundle": str(args.bundle)}).decode())
                return 75
        print(_canonical(result).decode())
        return 0
    except (ContractError, OSError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
