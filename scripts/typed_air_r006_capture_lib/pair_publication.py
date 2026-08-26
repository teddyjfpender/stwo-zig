"""Crash-resumable attempt publication transactions for paired R-006 capture."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

from .codec import content_digest, exact_object
from .model import CaptureError
from . import pair_durability as durability
from . import pair_recovery as recovery


PUBLICATION_HEADER_SCHEMA = "stwo.typed-air.r006-attempt-publication-header.v1"
PUBLICATION_RECORD_SCHEMA = "stwo.typed-air.r006-attempt-publication-record.v1"
PUBLICATION_JOURNAL_NAME = "attempt-publications.ndjson"

_HEADER_FIELDS = {
    "schema",
    "session_id",
    "plan_sha256",
    "planned_attempts",
    "content_sha256",
}
_RECORD_FIELDS = {
    "schema",
    "global_ordinal",
    "lane",
    "lane_ordinal",
    "attempt_id",
    "phase",
    "attempt_record",
    "attempt_record_sha256",
    "content_sha256",
}


def _schedule_identity(schedule: dict[str, Any]) -> dict[str, Any]:
    return {
        "global_ordinal": schedule["global_ordinal"],
        "lane": schedule["lane"],
        "lane_ordinal": schedule["lane_ordinal"],
        "attempt_id": schedule["attempt_id"],
    }


def _record(
    schedule: dict[str, Any],
    phase: str,
    *,
    attempt_record: dict[str, Any] | None,
    attempt_record_sha256: str | None,
) -> dict[str, Any]:
    result = {
        "schema": PUBLICATION_RECORD_SCHEMA,
        **_schedule_identity(schedule),
        "phase": phase,
        "attempt_record": attempt_record,
        "attempt_record_sha256": attempt_record_sha256,
    }
    result["content_sha256"] = content_digest(result)
    return result


def validate_publication_records(
    records: list[dict[str, Any]],
    *,
    plan: dict[str, Any],
    lane_records: Mapping[str, list[dict[str, Any]]] | None,
    require_complete: bool,
) -> dict[str, Any]:
    if not records:
        raise CaptureError("paired attempt-publication journal is empty")
    header = exact_object(records[0], _HEADER_FIELDS, "attempt-publication header")
    planned = len(plan["interleaving"])
    if (
        header["schema"] != PUBLICATION_HEADER_SCHEMA
        or header["session_id"] != plan["session_id"]
        or header["plan_sha256"] != plan["content_sha256"]
        or header["planned_attempts"] != planned
    ):
        raise CaptureError("paired attempt-publication header changed")
    cursor = 1
    committed = 0
    prepared_records: list[dict[str, Any]] = []
    authorizations: list[dict[str, Any]] = []
    current_power_source = plan["host_preflight"]["host"]["power_source"]
    pending: dict[str, Any] | None = None
    for schedule in plan["interleaving"]:
        if cursor == len(records):
            break
        while True:
            intent = exact_object(
                records[cursor], _RECORD_FIELDS, "attempt-publication record"
            )
            if (
                intent["schema"] != PUBLICATION_RECORD_SCHEMA
                or intent["phase"] != "intent"
                or any(
                    intent[name] != expected
                    for name, expected in _schedule_identity(schedule).items()
                )
                or intent["attempt_record"] is not None
                or intent["attempt_record_sha256"] is not None
            ):
                raise CaptureError("paired attempt-publication intent is out of sequence")
            pending = {
                "phase": "intent",
                "schedule": schedule,
                "record": None,
                "intent_sha256": intent["content_sha256"],
            }
            cursor += 1
            if cursor == len(records):
                break
            next_record = exact_object(
                records[cursor], _RECORD_FIELDS, "attempt-publication record"
            )
            if next_record["phase"] != "retry_authorized":
                break
            authorization = recovery.validate_authorization(
                next_record["attempt_record"],
                schedule=schedule,
                durable_prefix=committed,
                retry_index=len(authorizations) + 1,
                prior_intent_sha256=intent["content_sha256"],
                from_power_source=current_power_source,
            )
            if (
                next_record["schema"] != PUBLICATION_RECORD_SCHEMA
                or any(
                    next_record[name] != expected
                    for name, expected in _schedule_identity(schedule).items()
                )
                or next_record["attempt_record_sha256"]
                != authorization["content_sha256"]
            ):
                raise CaptureError("attempt retry publication changed")
            authorizations.append(authorization)
            current_power_source = authorization["to_power_source"]
            pending = None
            cursor += 1
            if cursor == len(records):
                break
        if pending is None or cursor == len(records):
            break
        prepared = next_record
        attempt_record = prepared["attempt_record"]
        if (
            prepared["schema"] != PUBLICATION_RECORD_SCHEMA
            or prepared["phase"] != "prepared"
            or any(
                prepared[name] != expected
                for name, expected in _schedule_identity(schedule).items()
            )
            or type(attempt_record) is not dict
            or attempt_record.get("content_sha256") != content_digest(attempt_record)
            or prepared["attempt_record_sha256"] != attempt_record["content_sha256"]
        ):
            raise CaptureError("paired prepared attempt publication changed")
        pending = {"phase": "prepared", "schedule": schedule, "record": attempt_record}
        cursor += 1
        if cursor == len(records):
            break
        commit = exact_object(
            records[cursor], _RECORD_FIELDS, "attempt-publication record"
        )
        if (
            commit["schema"] != PUBLICATION_RECORD_SCHEMA
            or commit["phase"] != "committed"
            or any(
                commit[name] != expected
                for name, expected in _schedule_identity(schedule).items()
            )
            or commit["attempt_record"] is not None
            or commit["attempt_record_sha256"] != attempt_record["content_sha256"]
        ):
            raise CaptureError("paired attempt-publication commit changed")
        prepared_records.append(attempt_record)
        pending = None
        committed += 1
        cursor += 1
    if cursor != len(records):
        raise CaptureError("paired attempt-publication journal has trailing records")
    if lane_records is not None:
        completed = durability.completed_interleaving(plan, lane_records)
        lane_count = len(completed)
        pending_prepared = pending is not None and pending["phase"] == "prepared"
        if lane_count not in {committed, committed + pending_prepared}:
            raise CaptureError("lane evidence disagrees with attempt-publication state")
        for schedule, attempt_record in zip(
            plan["interleaving"], prepared_records, strict=False
        ):
            if lane_records[schedule["lane"]][schedule["lane_ordinal"]] != attempt_record:
                raise CaptureError("committed publication differs from its lane record")
        if lane_count == committed + 1:
            assert pending is not None and pending["phase"] == "prepared"
            schedule = pending["schedule"]
            if lane_records[schedule["lane"]][schedule["lane_ordinal"]] != pending["record"]:
                raise CaptureError("prepared publication differs from its lane record")
    if require_complete and (committed != planned or pending is not None):
        raise CaptureError("paired attempt-publication journal is not complete")
    return {
        "header": header,
        "committed_attempts": committed,
        "pending": pending,
        "authorizations": authorizations,
        "current_power_source": current_power_source,
        "recovery_disclosure": recovery.disclosure(authorizations),
        "records": len(records),
    }


class AttemptPublicationJournal:
    def __init__(self, root: Path, plan: dict[str, Any]) -> None:
        self.path = root / PUBLICATION_JOURNAL_NAME
        self.plan = plan
        self.closed = False
        if not os.path.lexists(self.path):
            self.output = durability._create_journal(
                self.path, "attempt-publication journal"
            )
            self.records: list[dict[str, Any]] = []
            durability._append(
                self.output,
                self.records,
                {
                    "schema": PUBLICATION_HEADER_SCHEMA,
                    "session_id": plan["session_id"],
                    "plan_sha256": plan["content_sha256"],
                    "planned_attempts": len(plan["interleaving"]),
                },
            )
        else:
            self.output, self.records = durability._open_journal_append(
                self.path, "attempt-publication journal"
            )
        self.summary(lane_records=None, require_complete=False)

    def summary(
        self,
        *,
        lane_records: Mapping[str, list[dict[str, Any]]] | None,
        require_complete: bool,
    ) -> dict[str, Any]:
        return validate_publication_records(
            self.records,
            plan=self.plan,
            lane_records=lane_records,
            require_complete=require_complete,
        )

    def begin(
        self,
        schedule: dict[str, Any],
        lane_root: Path,
        attempt: dict[str, Any],
    ) -> None:
        summary = self.summary(lane_records=None, require_complete=False)
        pending = summary["pending"]
        if pending is not None:
            if pending["phase"] != "intent" or pending["schedule"] != schedule:
                raise CaptureError("attempt publication is already prepared")
            raise CaptureError(
                "catastrophic interruption left an unresolved attempt intent; "
                "the child may already have executed, so start a fresh paired bundle"
            )
        durability._append(
            self.output,
            self.records,
            _record(
                schedule,
                "intent",
                attempt_record=None,
                attempt_record_sha256=None,
            ),
        )
        paths = (
            attempt["report_path"],
            attempt["stderr_path"],
            attempt["proof_path"],
            attempt["verify_stdout_path"],
            attempt["verify_stderr_path"],
        )
        if any(os.path.lexists(lane_root / relative) for relative in paths):
            raise CaptureError(
                "catastrophic interruption left an unprepared attempt publication; "
                "start a fresh paired bundle"
            )

    def authorize_pending_retry(
        self,
        schedule: dict[str, Any],
        lane_root: Path,
        attempt: dict[str, Any],
        *,
        observed_power_source: str,
        authorized_at_utc: str,
        controller_commit: str,
    ) -> dict[str, Any]:
        summary = self.summary(lane_records=None, require_complete=False)
        pending = summary["pending"]
        if (
            pending is None
            or pending["phase"] != "intent"
            or pending["schedule"] != schedule
        ):
            raise CaptureError("attempt retry authorization lacks its pending intent")
        paths = (
            attempt["report_path"],
            attempt["stderr_path"],
            attempt["proof_path"],
            attempt["verify_stdout_path"],
            attempt["verify_stderr_path"],
        )
        retained = [relative for relative in paths if os.path.lexists(lane_root / relative)]
        if retained:
            raise CaptureError(
                "interrupted attempt retained output and cannot be retried safely"
            )
        authorization = recovery.build_authorization(
            schedule,
            durable_prefix=summary["committed_attempts"],
            retry_index=len(summary["authorizations"]) + 1,
            prior_intent_sha256=pending["intent_sha256"],
            from_power_source=summary["current_power_source"],
            to_power_source=observed_power_source,
            authorized_at_utc=authorized_at_utc,
            controller_commit=controller_commit,
        )
        durability._append(
            self.output,
            self.records,
            _record(
                schedule,
                "retry_authorized",
                attempt_record=authorization,
                attempt_record_sha256=authorization["content_sha256"],
            ),
        )
        return authorization

    def prepare(self, schedule: dict[str, Any], record: dict[str, Any]) -> None:
        summary = self.summary(lane_records=None, require_complete=False)
        pending = summary["pending"]
        if (
            pending is None
            or pending["phase"] != "intent"
            or pending["schedule"] != schedule
        ):
            raise CaptureError("attempt publication lacks its durable intent")
        sealed = dict(record)
        sealed["content_sha256"] = content_digest(sealed)
        durability._append(
            self.output,
            self.records,
            _record(
                schedule,
                "prepared",
                attempt_record=sealed,
                attempt_record_sha256=sealed["content_sha256"],
            ),
        )

    def commit(self, schedule: dict[str, Any]) -> None:
        summary = self.summary(lane_records=None, require_complete=False)
        pending = summary["pending"]
        if (
            pending is None
            or pending["phase"] != "prepared"
            or pending["schedule"] != schedule
        ):
            raise CaptureError("attempt publication is not prepared for commit")
        durability._append(
            self.output,
            self.records,
            _record(
                schedule,
                "committed",
                attempt_record=None,
                attempt_record_sha256=pending["record"]["content_sha256"],
            ),
        )

    def close(self) -> dict[str, Any]:
        if self.closed:
            raise CaptureError("attempt-publication journal closed twice")
        self.output.flush()
        os.fsync(self.output.fileno())
        self.output.close()
        self.closed = True
        identity = durability._identity(
            self.path, PUBLICATION_JOURNAL_NAME, len(self.records)
        )
        summary = self.summary(lane_records=None, require_complete=False)
        if summary["authorizations"]:
            identity["recovery_disclosure"] = summary["recovery_disclosure"]
        return identity

    def abandon(self) -> None:
        if self.closed:
            return
        try:
            self.output.flush()
            os.fsync(self.output.fileno())
            self.output.close()
        finally:
            self.closed = True


def read_publication_journal(
    path: Path,
    *,
    plan: dict[str, Any],
    lane_records: Mapping[str, list[dict[str, Any]]],
    require_complete: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    records = durability.read_journal_regular(path, "attempt-publication journal")
    summary = validate_publication_records(
        records,
        plan=plan,
        lane_records=lane_records,
        require_complete=require_complete,
    )
    identity = durability.journal_identity(records, PUBLICATION_JOURNAL_NAME)
    if summary["authorizations"]:
        identity["recovery_disclosure"] = summary["recovery_disclosure"]
    return summary, identity
