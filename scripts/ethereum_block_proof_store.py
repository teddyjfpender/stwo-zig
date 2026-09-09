"""No-follow, create-only storage for resumable Ethereum block proofs."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_protocol as protocol


JOURNAL_HEADER_SCHEMA = "stwo.ethereum.block-proof-task-journal-header.v1"
JOURNAL_RECORD_SCHEMA = "stwo.ethereum.block-proof-task-journal-record.v1"
JOURNAL_NAME = "publication.ndjson"
MAX_JSON_BYTES = 16 * 1024 * 1024


def _reject_constant(value: str) -> None:
    raise protocol.ProofProtocolError(f"non-finite JSON number is forbidden: {value}")


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        protocol.require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def decode_strict(raw: bytes) -> Any:
    protocol.require(0 < len(raw) <= MAX_JSON_BYTES, "JSON evidence size differs")
    try:
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise protocol.ProofProtocolError("JSON evidence is not canonical UTF-8 JSON") from error


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise protocol.ProofProtocolError("cannot fsync proof evidence directory") from error


def require_directory(path: Path, where: str, *, create: bool = False) -> None:
    if create and not os.path.lexists(path):
        try:
            path.mkdir(mode=0o700)
            _fsync_directory(path.parent)
        except OSError as error:
            raise protocol.ProofProtocolError(f"cannot create {where}") from error
    try:
        metadata = path.lstat()
    except OSError as error:
        raise protocol.ProofProtocolError(f"cannot inspect {where}") from error
    protocol.require(not stat.S_ISLNK(metadata.st_mode) and stat.S_ISDIR(metadata.st_mode),
                     f"{where} is not a non-symlink directory")


def require_allowed_entries(path: Path, allowed: set[str], where: str) -> None:
    require_directory(path, where)
    try:
        actual = {entry.name for entry in path.iterdir()}
    except OSError as error:
        raise protocol.ProofProtocolError(f"cannot inventory {where}") from error
    protocol.require(actual <= allowed, f"{where} contains unexpected entries")


def _open_regular(path: Path, flags: int, where: str) -> int:
    try:
        before = path.lstat()
    except OSError as error:
        raise protocol.ProofProtocolError(f"cannot inspect {where}") from error
    protocol.require(not stat.S_ISLNK(before.st_mode) and stat.S_ISREG(before.st_mode),
                     f"{where} is not a non-symlink regular file")
    guarded = flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, guarded)
    except OSError as error:
        raise protocol.ProofProtocolError(f"cannot open {where} without following links") from error
    try:
        after = os.fstat(descriptor)
        protocol.require(stat.S_ISREG(after.st_mode)
                         and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino),
                         f"{where} changed during admission")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(path: Path, where: str, *, maximum: int | None = None) -> bytes:
    descriptor = _open_regular(path, os.O_RDONLY, where)
    try:
        with os.fdopen(descriptor, "rb") as source:
            raw = source.read() if maximum is None else source.read(maximum + 1)
    except OSError as error:
        raise protocol.ProofProtocolError(f"cannot read {where}") from error
    if maximum is not None:
        protocol.require(len(raw) <= maximum, f"{where} exceeds its byte bound")
    return raw


def read_canonical_json(path: Path, where: str) -> dict[str, Any]:
    raw = read_regular(path, where, maximum=MAX_JSON_BYTES)
    value = decode_strict(raw)
    protocol.require(type(value) is dict and raw == protocol.canonical_bytes(value),
                     f"{where} is not canonical JSON")
    return value


def file_identity(path: Path, where: str) -> dict[str, Any]:
    descriptor = _open_regular(path, os.O_RDONLY, where)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
    except OSError as error:
        raise protocol.ProofProtocolError(f"cannot hash {where}") from error
    protocol.require(size > 0, f"{where} is empty")
    return {"bytes": size, "sha256": digest.hexdigest()}


def validate_file_identity(path: Path, expected: dict[str, Any], where: str) -> None:
    protocol.require(file_identity(path, where) == expected, f"{where} identity differs")


def publish_new_or_identical(
    path: Path, payload: bytes, *, staging_directory: Path,
) -> dict[str, Any]:
    """Hard-link a fully fsynced staging file; never replace an existing path."""
    require_directory(path.parent, "proof evidence parent")
    require_directory(staging_directory, "proof staging directory")
    if os.path.lexists(path):
        protocol.require(read_regular(path, f"existing {path.name}") == payload,
                         f"existing proof evidence differs: {path.name}")
        return {"bytes": len(payload), "sha256": protocol.sha256_bytes(payload)}
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=staging_directory,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            protocol.require(read_regular(path, f"concurrent {path.name}") == payload,
                             f"concurrent proof evidence differs: {path.name}")
        _fsync_directory(path.parent)
    except OSError as error:
        raise protocol.ProofProtocolError(f"cannot publish proof evidence: {path.name}") from error
    finally:
        temporary.unlink(missing_ok=True)
    return {"bytes": len(payload), "sha256": protocol.sha256_bytes(payload)}


def _read_journal(path: Path) -> list[dict[str, Any]]:
    raw = read_regular(path, "proof task journal", maximum=MAX_JSON_BYTES)
    protocol.require(raw.endswith(b"\n"), "proof task journal has a partial tail")
    records = []
    for line in raw.splitlines(keepends=True):
        value = decode_strict(line)
        protocol.require(type(value) is dict and line == protocol.canonical_bytes(value),
                         "proof task journal record is not canonical")
        protocol.require(value.get("content_sha256") == protocol.content_sha256(value),
                         "proof task journal record digest differs")
        records.append(value)
    return records


class TaskJournal:
    """One durable intent/prepared/committed transaction for one proof task."""

    def __init__(
        self, task_directory: Path, plan_sha256: str, request: dict[str, Any],
        staging_directory: Path,
    ) -> None:
        require_directory(task_directory, "proof task directory", create=True)
        self.task_directory = task_directory
        self.path = task_directory / JOURNAL_NAME
        self.request = request
        self.staging_directory = staging_directory
        header = protocol.seal({
            "schema": JOURNAL_HEADER_SCHEMA,
            "task_id": request["task_id"],
            "plan_sha256": plan_sha256,
            "request_sha256": request["content_sha256"],
        })
        if not os.path.lexists(self.path):
            require_allowed_entries(task_directory, set(), "new proof task directory")
            publish_new_or_identical(
                self.path, protocol.canonical_bytes(header),
                staging_directory=staging_directory,
            )
        self.records = _read_journal(self.path)
        self._validate_header(header)
        descriptor = _open_regular(self.path, os.O_WRONLY | os.O_APPEND,
                                   "proof task journal")
        self.output = os.fdopen(descriptor, "wb", buffering=0)
        self.closed = False
        self.state()

    def _validate_header(self, expected: dict[str, Any]) -> None:
        protocol.require(self.records and self.records[0] == expected,
                         "proof task journal header differs")

    def state(self) -> dict[str, Any]:
        tail = self.records[1:]
        protocol.require(len(tail) <= 3, "proof task journal has trailing records")
        expected_phases = ["intent", "prepared", "committed"][:len(tail)]
        protocol.require([record.get("phase") for record in tail] == expected_phases,
                         "proof task journal phase order differs")
        prepared: dict[str, Any] | None = None
        for index, record in enumerate(tail):
            record = protocol.exact(record, {
                "schema", "task_id", "request_sha256", "phase", "task_record",
                "task_record_sha256", "content_sha256",
            }, f"proof task journal record {index}")
            protocol.require(record["schema"] == JOURNAL_RECORD_SCHEMA
                             and record["task_id"] == self.request["task_id"]
                             and record["request_sha256"] == self.request["content_sha256"],
                             "proof task journal identity differs")
            if record["phase"] == "intent":
                protocol.require(record["task_record"] is None
                                 and record["task_record_sha256"] is None,
                                 "proof task intent carries evidence")
            elif record["phase"] == "prepared":
                prepared = record["task_record"]
                protocol.require(type(prepared) is dict
                                 and prepared.get("content_sha256")
                                 == protocol.content_sha256(prepared)
                                 and record["task_record_sha256"]
                                 == prepared["content_sha256"],
                                 "prepared proof task evidence differs")
            else:
                protocol.require(prepared is not None and record["task_record"] is None
                                 and record["task_record_sha256"]
                                 == prepared["content_sha256"],
                                 "committed proof task evidence differs")
        phase = "empty" if not tail else tail[-1]["phase"]
        return {"phase": phase, "task_record": prepared}

    def _append(
        self, phase: str, task_record: dict[str, Any] | None,
        task_record_sha256: str | None,
    ) -> None:
        record = protocol.seal({
            "schema": JOURNAL_RECORD_SCHEMA,
            "task_id": self.request["task_id"],
            "request_sha256": self.request["content_sha256"],
            "phase": phase,
            "task_record": task_record,
            "task_record_sha256": task_record_sha256,
        })
        try:
            self.output.write(protocol.canonical_bytes(record))
            os.fsync(self.output.fileno())
        except OSError as error:
            raise protocol.ProofProtocolError("cannot append proof task journal") from error
        self.records.append(record)

    def begin(self) -> None:
        protocol.require(self.state()["phase"] == "empty", "proof task already started")
        self._append("intent", None, None)

    def prepare(self, task_record: dict[str, Any]) -> None:
        protocol.require(self.state()["phase"] == "intent", "proof task lacks intent")
        self._append("prepared", task_record, task_record["content_sha256"])

    def commit(self) -> None:
        state = self.state()
        protocol.require(state["phase"] == "prepared", "proof task is not prepared")
        self._append("committed", None, state["task_record"]["content_sha256"])

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
        finally:
            self.closed = True

    def __enter__(self) -> TaskJournal:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
