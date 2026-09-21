"""Append-only multi-attempt journal for one recursive-pipeline stage."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_attempts as proof_attempts
from scripts import ethereum_block_proof_store as durable
from scripts import recursive_pipeline_protocol as protocol


HEADER_SCHEMA = "stwo.recursive-pipeline-stage-journal-header.v1"
RECORD_SCHEMA = "stwo.recursive-pipeline-stage-journal-record.v1"
JOURNAL_NAME = "attempts.ndjson"
ATTEMPT_FILES = {
    "output.bin", "stage-result.json", "profile.json", "stdout.log", "stderr.log",
}
ORDERED_PHASES = (
    "intent", "running", "outputs_published", "validated", "committed",
)
TERMINAL_FAILURES = ("failed", "indeterminate")


class StageAttemptJournal:
    """Durable stage attempts; selection is owned by append-only run refs."""

    def __init__(
        self, stage_root: Path, manifest_sha256: str, node_id: str,
        staging_directory: Path,
    ) -> None:
        durable.require_directory(stage_root, "pipeline stage directory", create=True)
        self.stage_root = stage_root
        self.attempts_root = stage_root / proof_attempts.ATTEMPTS_DIRECTORY
        durable.require_directory(
            self.attempts_root, "pipeline stage attempts", create=True,
        )
        self.path = stage_root / JOURNAL_NAME
        self.manifest_sha256 = protocol.digest(
            manifest_sha256, "stage journal manifest identity",
        )
        self.node_id = node_id
        self.staging_directory = staging_directory
        header = protocol.seal({
            "schema": HEADER_SCHEMA,
            "manifest_sha256": manifest_sha256,
            "node_id": node_id,
        })
        if not os.path.lexists(self.path):
            durable.require_allowed_entries(
                stage_root, {proof_attempts.ATTEMPTS_DIRECTORY},
                "new pipeline stage directory",
            )
            durable.publish_new_or_identical(
                self.path, protocol.canonical_bytes(header),
                staging_directory=staging_directory,
            )
        self.records = durable._read_journal(self.path)
        protocol.require(self.records and self.records[0] == header,
                         "pipeline stage journal header differs")
        descriptor = durable._open_regular(
            self.path, os.O_WRONLY | os.O_APPEND, "pipeline stage journal",
        )
        self.output = os.fdopen(descriptor, "wb", buffering=0)
        self.closed = False
        self.state()

    def state(self) -> dict[str, Any]:
        attempts: list[dict[str, Any]] = []
        current: dict[str, Any] | None = None
        for position, record in enumerate(self.records[1:]):
            validate_record(record, self.manifest_sha256, self.node_id, position)
            index = record["attempt_index"]
            if current is None or current["terminal"]:
                protocol.require(record["phase"] == "intent"
                                 and index == len(attempts),
                                 "pipeline attempt order differs")
                current = {
                    "attempt_index": index,
                    "records": [],
                    "phase": None,
                    "terminal": False,
                    "semantic_key_sha256": record["semantic_key_sha256"],
                    "execution_key_sha256": record["execution_key_sha256"],
                }
                attempts.append(current)
            protocol.require(index == current["attempt_index"]
                             and record["semantic_key_sha256"]
                             == current["semantic_key_sha256"]
                             and record["execution_key_sha256"]
                             == current["execution_key_sha256"],
                             "pipeline attempt identity drifted")
            phase = record["phase"]
            prior = current["phase"]
            if phase in TERMINAL_FAILURES:
                protocol.require(prior in ORDERED_PHASES[:-1]
                                 and not current["terminal"],
                                 "pipeline attempt terminal phase differs")
                current["terminal"] = True
            else:
                expected = ORDERED_PHASES[0] if prior is None else (
                    ORDERED_PHASES[ORDERED_PHASES.index(prior) + 1]
                    if prior not in TERMINAL_FAILURES and prior != "committed"
                    else None
                )
                protocol.require(phase == expected,
                                 "pipeline attempt phase order differs")
                if phase == "committed":
                    current["terminal"] = True
            current["records"].append(record)
            current["phase"] = phase
            current["record"] = record
        protocol.require(len(attempts) < proof_attempts.MAX_ATTEMPTS,
                         "pipeline stage attempt limit exceeded")
        active = attempts[-1] if attempts and not attempts[-1]["terminal"] else None
        committed = [attempt for attempt in attempts
                     if attempt["phase"] == "committed"]
        return {
            "attempts": attempts,
            "active": active,
            "committed": committed,
            "next_attempt_index": len(attempts),
        }

    @classmethod
    def read_state(
        cls, stage_root: Path, manifest_sha256: str, node_id: str,
    ) -> dict[str, Any]:
        durable.require_directory(stage_root, "pipeline stage directory")
        records = durable._read_journal(stage_root / JOURNAL_NAME)
        header = protocol.seal({
            "schema": HEADER_SCHEMA,
            "manifest_sha256": manifest_sha256,
            "node_id": node_id,
        })
        protocol.require(records and records[0] == header,
                         "pipeline stage journal header differs")
        view = object.__new__(cls)
        view.records = records
        view.manifest_sha256 = manifest_sha256
        view.node_id = node_id
        return view.state()

    def attempt_directory(self, index: int) -> Path:
        return self.stage_root / proof_attempts.attempt_relative(index)

    def begin(self, semantic_sha256: str, execution_sha256: str) -> tuple[int, Path]:
        state = self.state()
        protocol.require(state["active"] is None,
                         "pipeline stage has an active attempt")
        index = state["next_attempt_index"]
        started = time.time_ns()
        self._append(
            index, "intent", started, None, semantic_sha256, execution_sha256,
            output_artifact=None, stage_result=None, profile_receipt=None,
            validation_receipt=None, failure=None,
        )
        directory = self.attempt_directory(index)
        protocol.require(not os.path.lexists(directory),
                         "pipeline attempt directory already exists")
        durable.require_directory(directory, "pipeline attempt directory", create=True)
        return index, directory

    def mark_running(self, index: int) -> None:
        self._advance(index, "running")

    def outputs_published(
        self, index: int, *, output_artifact: dict[str, Any],
        stage_result: dict[str, Any], profile_receipt: dict[str, Any],
    ) -> None:
        self._advance(
            index, "outputs_published", output_artifact=output_artifact,
            stage_result=stage_result, profile_receipt=profile_receipt,
        )

    def validated(self, index: int, validation_receipt: dict[str, Any]) -> None:
        self._advance(index, "validated", validation_receipt=validation_receipt)

    def commit(self, index: int) -> None:
        self._advance(index, "committed")

    def fail(self, index: int, failure: str, *, indeterminate: bool = False) -> None:
        protocol.require(type(failure) is str and failure,
                         "pipeline failure classification differs")
        state = self.state()
        active = state["active"]
        protocol.require(active is not None and active["attempt_index"] == index,
                         "pipeline stage has no matching active attempt")
        prior = active["record"]
        self._append(
            index, "indeterminate" if indeterminate else "failed",
            prior["started_unix_ns"], time.time_ns(),
            prior["semantic_key_sha256"], prior["execution_key_sha256"],
            output_artifact=prior["output_artifact"],
            stage_result=prior["stage_result"],
            profile_receipt=prior["profile_receipt"],
            validation_receipt=prior["validation_receipt"],
            failure=failure,
        )

    def _advance(self, index: int, phase: str, **updates: Any) -> None:
        state = self.state()
        active = state["active"]
        protocol.require(active is not None and active["attempt_index"] == index,
                         "pipeline stage has no matching active attempt")
        prior = active["record"]
        values = {
            "output_artifact": prior["output_artifact"],
            "stage_result": prior["stage_result"],
            "profile_receipt": prior["profile_receipt"],
            "validation_receipt": prior["validation_receipt"],
            "failure": None,
        }
        values.update(updates)
        self._append(
            index, phase, prior["started_unix_ns"],
            time.time_ns() if phase == "committed" else None,
            prior["semantic_key_sha256"], prior["execution_key_sha256"],
            **values,
        )

    def _append(
        self, attempt_index: int, phase: str, started_unix_ns: int,
        ended_unix_ns: int | None, semantic_key_sha256: str,
        execution_key_sha256: str, *, output_artifact: dict[str, Any] | None,
        stage_result: dict[str, Any] | None,
        profile_receipt: dict[str, Any] | None,
        validation_receipt: dict[str, Any] | None,
        failure: str | None,
    ) -> None:
        record = protocol.seal({
            "schema": RECORD_SCHEMA,
            "manifest_sha256": self.manifest_sha256,
            "node_id": self.node_id,
            "attempt_index": attempt_index,
            "phase": phase,
            "started_unix_ns": started_unix_ns,
            "ended_unix_ns": ended_unix_ns,
            "semantic_key_sha256": semantic_key_sha256,
            "execution_key_sha256": execution_key_sha256,
            "output_artifact": output_artifact,
            "stage_result": stage_result,
            "profile_receipt": profile_receipt,
            "validation_receipt": validation_receipt,
            "failure": failure,
        })
        validate_record(record, self.manifest_sha256, self.node_id, len(self.records) - 1)
        try:
            self.output.write(protocol.canonical_bytes(record))
            os.fsync(self.output.fileno())
        except OSError as error:
            raise protocol.PipelineError("cannot append pipeline stage journal") from error
        self.records.append(record)

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
        finally:
            self.closed = True

    def __enter__(self) -> "StageAttemptJournal":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def validate_record(
    value: Any, manifest_sha256: str, node_id: str, position: int,
) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "manifest_sha256", "node_id", "attempt_index", "phase",
        "started_unix_ns", "ended_unix_ns", "semantic_key_sha256",
        "execution_key_sha256", "output_artifact", "stage_result",
        "profile_receipt", "validation_receipt", "failure", "content_sha256",
    }, f"pipeline stage record {position}")
    protocol.require(value["schema"] == RECORD_SCHEMA
                     and value["manifest_sha256"] == manifest_sha256
                     and value["node_id"] == node_id,
                     "pipeline stage record authority differs")
    protocol.require(type(value["attempt_index"]) is int
                     and value["attempt_index"] >= 0,
                     "pipeline attempt index differs")
    protocol.require(value["phase"] in ORDERED_PHASES + TERMINAL_FAILURES,
                     "pipeline attempt phase differs")
    protocol.require(type(value["started_unix_ns"]) is int
                     and value["started_unix_ns"] > 0,
                     "pipeline attempt start differs")
    protocol.digest(value["semantic_key_sha256"], "attempt semantic key")
    protocol.digest(value["execution_key_sha256"], "attempt execution key")
    for field in ("output_artifact", "stage_result", "profile_receipt",
                  "validation_receipt"):
        if value[field] is not None:
            protocol.validate_blob_ref(value[field], f"attempt {field}")
    outputs = (value["output_artifact"], value["stage_result"],
               value["profile_receipt"])
    if value["phase"] in ("intent", "running"):
        protocol.require(outputs == (None, None, None)
                         and value["validation_receipt"] is None,
                         "pre-publication attempt carries artifacts")
    elif value["phase"] == "outputs_published":
        protocol.require(all(item is not None for item in outputs)
                         and value["validation_receipt"] is None,
                         "published attempt artifacts differ")
    elif value["phase"] in ("validated", "committed"):
        protocol.require(all(item is not None for item in outputs)
                         and value["validation_receipt"] is not None,
                         "validated attempt artifacts differ")
    if value["phase"] in ("committed",) + TERMINAL_FAILURES:
        protocol.require(type(value["ended_unix_ns"]) is int
                         and value["ended_unix_ns"] >= value["started_unix_ns"],
                         "pipeline attempt end differs")
    else:
        protocol.require(value["ended_unix_ns"] is None,
                         "nonterminal pipeline attempt has an end time")
    if value["phase"] in TERMINAL_FAILURES:
        protocol.require(type(value["failure"]) is str and value["failure"],
                         "pipeline attempt failure differs")
    else:
        protocol.require(value["failure"] is None,
                         "successful pipeline phase carries failure")
    return protocol.validate_seal(value, f"pipeline stage record {position}")
