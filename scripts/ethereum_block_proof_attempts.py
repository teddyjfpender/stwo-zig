"""Append-only multi-attempt custody for proof-bearing block-proof tasks."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store


HEADER_SCHEMA = "stwo.ethereum.block-proof-attempt-journal-header.v1"
RECORD_SCHEMA = "stwo.ethereum.block-proof-attempt-journal-record.v1"
ATTEMPT_CUSTODY_SCHEMA = "stwo.ethereum.block-proof-attempt-custody.v1"
JOURNAL_NAME = "publication.ndjson"
ATTEMPTS_DIRECTORY = "attempts"
MAX_ATTEMPTS = 4096
ATTEMPT_OUTPUTS = {"proof.bin", "verify-receipt.json"}


def attempt_relative(index: int) -> str:
    return f"{ATTEMPTS_DIRECTORY}/attempt-{index:06d}"


def _inventory(directory: Path, *, absent_ok: bool) -> list[dict[str, Any]]:
    if not os.path.lexists(directory):
        protocol.require(absent_ok, "proof attempt directory is absent")
        return []
    store.require_directory(directory, "proof attempt directory")
    store.require_allowed_entries(directory, ATTEMPT_OUTPUTS, "proof attempt directory")
    result = []
    for entry in sorted(directory.iterdir(), key=lambda path: path.name):
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise protocol.ProofProtocolError("cannot inventory proof attempt") from error
        protocol.require(not stat.S_ISLNK(metadata.st_mode)
                         and stat.S_ISREG(metadata.st_mode),
                         "proof attempt entry is not a non-symlink regular file")
        result.append({"path": entry.name, **store.file_identity(
            entry, f"proof attempt {entry.name}",
        )})
    return result


def _custody(
    index: int, classification: str, started_unix_ns: int, directory: Path,
    *, absent_ok: bool,
) -> dict[str, Any]:
    ended_unix_ns = time.time_ns()
    reliable = ended_unix_ns >= started_unix_ns
    inventory = _inventory(directory, absent_ok=absent_ok)
    return {
        "schema": ATTEMPT_CUSTODY_SCHEMA,
        "attempt_index": index,
        "attempt_path": attempt_relative(index),
        "classification": classification,
        "started_unix_ns": started_unix_ns,
        "ended_unix_ns": ended_unix_ns,
        "observed_wall_ns": ended_unix_ns - started_unix_ns if reliable else None,
        "clock_reliable": reliable,
        "inventory": inventory,
        "inventory_sha256": protocol.sha256_bytes(protocol.canonical_bytes(inventory)),
    }


def validate_attempt_custody(
    value: Any, expected_index: int, expected_classification: str,
) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "attempt_index", "attempt_path", "classification",
        "started_unix_ns", "ended_unix_ns", "observed_wall_ns", "clock_reliable",
        "inventory", "inventory_sha256",
    }, "proof attempt custody")
    protocol.require(value["schema"] == ATTEMPT_CUSTODY_SCHEMA
                     and value["attempt_index"] == expected_index
                     and value["attempt_path"] == attempt_relative(expected_index)
                     and value["classification"] == expected_classification,
                     "proof attempt custody identity differs")
    for field in ("started_unix_ns", "ended_unix_ns"):
        protocol.require(type(value[field]) is int and value[field] > 0,
                         f"proof attempt custody {field} differs")
    protocol.require(type(value["clock_reliable"]) is bool,
                     "proof attempt custody clock status differs")
    if value["clock_reliable"]:
        protocol.require(value["ended_unix_ns"] >= value["started_unix_ns"]
                         and value["observed_wall_ns"]
                         == value["ended_unix_ns"] - value["started_unix_ns"],
                         "proof attempt custody wall time differs")
    else:
        protocol.require(value["observed_wall_ns"] is None,
                         "unreliable proof attempt carries wall time")
    protocol.require(type(value["inventory"]) is list
                     and value["inventory_sha256"]
                     == protocol.sha256_bytes(protocol.canonical_bytes(value["inventory"])),
                     "proof attempt custody inventory digest differs")
    names = []
    for position, item in enumerate(value["inventory"]):
        protocol._identity(item, f"proof attempt inventory {position}", path=True)
        names.append(item["path"])
    protocol.require(names == sorted(set(names)) and set(names) <= ATTEMPT_OUTPUTS,
                     "proof attempt custody inventory differs")
    return value


class ProofTaskJournal:
    """One canonical success selected from append-only numbered attempts."""

    def __init__(
        self, task_directory: Path, plan_sha256: str, request: dict[str, Any],
        staging_directory: Path,
    ) -> None:
        store.require_directory(task_directory, "proof task directory", create=True)
        self.task_directory = task_directory
        self.attempts_directory = task_directory / ATTEMPTS_DIRECTORY
        store.require_directory(
            self.attempts_directory, "proof attempts directory", create=True,
        )
        self.path = task_directory / JOURNAL_NAME
        self.request = request
        self.staging_directory = staging_directory
        header = protocol.seal({
            "schema": HEADER_SCHEMA,
            "task_id": request["task_id"],
            "plan_sha256": plan_sha256,
            "request_sha256": request["content_sha256"],
        })
        if not os.path.lexists(self.path):
            store.require_allowed_entries(
                task_directory, {ATTEMPTS_DIRECTORY}, "new proof task directory",
            )
            store.publish_new_or_identical(
                self.path, protocol.canonical_bytes(header),
                staging_directory=staging_directory,
            )
        self.records = store._read_journal(self.path)
        protocol.require(self.records and self.records[0] == header,
                         "proof attempt journal header differs")
        descriptor = store._open_regular(
            self.path, os.O_WRONLY | os.O_APPEND, "proof attempt journal",
        )
        self.output = os.fdopen(descriptor, "wb", buffering=0)
        self.closed = False
        self.state()

    def state(self) -> dict[str, Any]:
        expected_index = 0
        pending = None
        prepared = None
        committed = None
        history = []
        for position, record in enumerate(self.records[1:]):
            record = protocol.exact(record, {
                "schema", "task_id", "request_sha256", "phase", "attempt_index",
                "started_unix_ns", "attempt_custody", "task_record", "task_record_sha256",
                "content_sha256",
            }, f"proof attempt journal record {position}")
            protocol.require(record["schema"] == RECORD_SCHEMA
                             and record["task_id"] == self.request["task_id"]
                             and record["request_sha256"]
                             == self.request["content_sha256"],
                             "proof attempt journal identity differs")
            phase = record["phase"]
            index = record["attempt_index"]
            if phase == "intent":
                protocol.require(pending is None and prepared is None
                                 and committed is None and index == expected_index
                                 and type(record["started_unix_ns"]) is int
                                 and record["started_unix_ns"] > 0
                                 and record["attempt_custody"] is None
                                 and record["task_record"] is None
                                 and record["task_record_sha256"] is None,
                                 "proof attempt intent differs")
                pending = {
                    "attempt_index": index,
                    "started_unix_ns": record["started_unix_ns"],
                }
            elif phase in ("failed_after_launch", "indeterminate_after_launch"):
                protocol.require(pending is not None and index == expected_index
                                 and record["started_unix_ns"]
                                 == pending["started_unix_ns"]
                                 and record["task_record"] is None
                                 and record["task_record_sha256"] is None,
                                 "indeterminate proof attempt differs")
                validate_attempt_custody(
                    record["attempt_custody"], index, phase,
                )
                history.append(record["attempt_custody"])
                pending = None
                expected_index += 1
            elif phase == "prepared":
                protocol.require(pending is not None and index == expected_index
                                 and record["started_unix_ns"]
                                 == pending["started_unix_ns"]
                                 and type(record["task_record"]) is dict
                                 and record["task_record"].get("content_sha256")
                                 == protocol.content_sha256(record["task_record"])
                                 and record["task_record_sha256"]
                                 == record["task_record"]["content_sha256"],
                                 "prepared proof attempt differs")
                validate_attempt_custody(record["attempt_custody"], index, "verified")
                prepared = record
                pending = None
            elif phase == "committed":
                protocol.require(prepared is not None and committed is None
                                 and index == expected_index
                                 and record["started_unix_ns"]
                                 == prepared["started_unix_ns"]
                                 and record["attempt_custody"] is None
                                 and record["task_record"] is None
                                 and record["task_record_sha256"]
                                 == prepared["task_record_sha256"],
                                 "committed proof attempt differs")
                committed = prepared["task_record"]
            else:
                raise protocol.ProofProtocolError("proof attempt journal phase differs")
        protocol.require(expected_index < MAX_ATTEMPTS, "proof attempt limit exceeded")
        return {
            "pending": pending,
            "prepared": prepared["task_record"] if prepared is not None else None,
            "committed": committed,
            "history": history,
            "next_attempt_index": expected_index,
        }

    def _append(
        self, phase: str, attempt_index: int, started_unix_ns: int,
        attempt_custody: dict[str, Any] | None,
        task_record: dict[str, Any] | None, task_record_sha256: str | None,
    ) -> None:
        record = protocol.seal({
            "schema": RECORD_SCHEMA,
            "task_id": self.request["task_id"],
            "request_sha256": self.request["content_sha256"],
            "phase": phase,
            "attempt_index": attempt_index,
            "started_unix_ns": started_unix_ns,
            "attempt_custody": attempt_custody,
            "task_record": task_record,
            "task_record_sha256": task_record_sha256,
        })
        try:
            self.output.write(protocol.canonical_bytes(record))
            os.fsync(self.output.fileno())
        except OSError as error:
            raise protocol.ProofProtocolError("cannot append proof attempt journal") from error
        self.records.append(record)

    def seal_pending_indeterminate(self) -> dict[str, Any]:
        return self._seal_pending("indeterminate_after_launch")

    def seal_pending_failed(self) -> dict[str, Any]:
        return self._seal_pending("failed_after_launch")

    def _seal_pending(self, classification: str) -> dict[str, Any]:
        protocol.require(
            classification in ("failed_after_launch", "indeterminate_after_launch"),
            "proof attempt terminal classification differs",
        )
        state = self.state()
        pending = state["pending"]
        protocol.require(pending is not None, "proof attempt has no pending intent")
        started = pending["started_unix_ns"]
        index = pending["attempt_index"]
        custody = _custody(
            index, classification, started,
            self.task_directory / attempt_relative(index), absent_ok=True,
        )
        self._append(
            classification, index, started, custody, None, None,
        )
        return custody

    def begin(self) -> tuple[int, Path]:
        state = self.state()
        protocol.require(state["pending"] is None and state["prepared"] is None
                         and state["committed"] is None,
                         "proof task cannot begin another attempt")
        index = state["next_attempt_index"]
        started = time.time_ns()
        self._append("intent", index, started, None, None, None)
        directory = self.task_directory / attempt_relative(index)
        protocol.require(not os.path.lexists(directory),
                         "new proof attempt directory already exists")
        store.require_directory(directory, "new proof attempt directory", create=True)
        return index, directory

    def prepare(
        self, task_record: dict[str, Any], attempt_index: int,
    ) -> dict[str, Any]:
        state = self.state()
        protocol.require(state["pending"] is not None
                         and state["pending"]["attempt_index"] == attempt_index,
                         "proof attempt lacks matching intent")
        started = state["pending"]["started_unix_ns"]
        custody = _custody(
            attempt_index, "verified", started,
            self.task_directory / attempt_relative(attempt_index), absent_ok=False,
        )
        self._append(
            "prepared", attempt_index, started, custody, task_record,
            task_record["content_sha256"],
        )
        return custody

    def commit(self) -> None:
        state = self.state()
        protocol.require(state["prepared"] is not None and state["committed"] is None,
                         "proof attempt is not prepared")
        prepared = self.records[-1]
        self._append(
            "committed", prepared["attempt_index"], prepared["started_unix_ns"],
            None, None,
            prepared["task_record_sha256"],
        )

    def validate_indeterminate_inventories(self) -> None:
        for custody in self.state()["history"]:
            directory = self.task_directory / custody["attempt_path"]
            current = _inventory(directory, absent_ok=True)
            protocol.require(current == custody["inventory"],
                             "indeterminate proof attempt changed after sealing")

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
        finally:
            self.closed = True

    def __enter__(self) -> ProofTaskJournal:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
