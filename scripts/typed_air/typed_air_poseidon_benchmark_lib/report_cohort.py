"""Replay validation for schedules, samples, and summaries in H-010 reports."""

from __future__ import annotations

import json
import re
from typing import Any

from .cohort import integer_summary, launch_order
from .contract import (
    ARMS,
    DEFAULT_LOGS,
    MEASURED_ROUNDS,
    STRESS_LOG,
    WARMUP_ROUNDS,
    validate_sample,
)


COHORT_KEYS = frozenset(
    {
        "log_size",
        "rows",
        "warmup_rounds",
        "measured_rounds",
        "schedule",
        "warmups",
        "samples",
        "summaries",
        "failure",
        "valid",
    }
)
FAILURE_KEYS = frozenset(
    {
        "code",
        "message",
        "phase",
        "log_size",
        "round",
        "phase_round",
        "launch_ordinal",
        "arm",
    }
)
RECORD_KEYS = frozenset(
    {"round", "phase_round", "launch_ordinal", "child_exit", "sample"}
)
FAILURE_CODE_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")


class CohortReportError(ValueError):
    """A reported cohort cannot be replayed from its embedded records."""


def validate_failure(value: Any) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != FAILURE_KEYS:
        raise CohortReportError("failure record key set is invalid")
    for key in ("code", "message", "phase"):
        if type(value[key]) is not str or not value[key]:
            raise CohortReportError(f"failure {key} must be non-empty text")
    if len(value["code"]) > 64 or FAILURE_CODE_RE.fullmatch(value["code"]) is None:
        raise CohortReportError("failure code must be lowercase kebab-case")
    for key in ("log_size", "round", "phase_round", "launch_ordinal"):
        if value[key] is not None and (type(value[key]) is not int or value[key] < 0):
            raise CohortReportError(f"failure {key} must be null or non-negative")
    if value["arm"] is not None and value["arm"] not in ARMS:
        raise CohortReportError("failure arm is unknown")
    return value


def _validate_schedule(schedule: Any, *, round_count: int) -> None:
    if type(schedule) is not list or len(schedule) != round_count:
        raise CohortReportError("cohort schedule does not match its replay prefix")
    for round_index, entry in enumerate(schedule):
        if type(entry) is not dict or set(entry) != {
            "round",
            "phase",
            "phase_round",
            "arms",
        }:
            raise CohortReportError("schedule entry key set is invalid")
        phase = "warmup" if round_index < WARMUP_ROUNDS else "measured"
        phase_round = round_index if phase == "warmup" else round_index - WARMUP_ROUNDS
        expected = {
            "round": round_index,
            "phase": phase,
            "phase_round": phase_round,
            "arms": list(launch_order(round_index)),
        }
        if entry != expected:
            raise CohortReportError(f"schedule round {round_index} is not canonical")


def _phase_positions(phase: str) -> list[tuple[int, int, str]]:
    rounds = (
        range(WARMUP_ROUNDS)
        if phase == "warmup"
        else range(WARMUP_ROUNDS, WARMUP_ROUNDS + MEASURED_ROUNDS)
    )
    return [
        (round_index, launch_ordinal, arm)
        for round_index in rounds
        for launch_ordinal, arm in enumerate(launch_order(round_index))
    ]


def _positions_before(
    stop_round: int, stop_ordinal: int
) -> tuple[list[tuple[int, int, str]], list[tuple[int, int, str]]]:
    warmups: list[tuple[int, int, str]] = []
    measured: list[tuple[int, int, str]] = []
    for round_index in range(WARMUP_ROUNDS + MEASURED_ROUNDS):
        for launch_ordinal, arm in enumerate(launch_order(round_index)):
            if (round_index, launch_ordinal) == (stop_round, stop_ordinal):
                return warmups, measured
            destination = warmups if round_index < WARMUP_ROUNDS else measured
            destination.append((round_index, launch_ordinal, arm))
    raise CohortReportError("failure coordinate is outside the canonical schedule")


def _validate_records(
    records: Any,
    *,
    log_size: int,
    phase: str,
    positions: list[tuple[int, int, str]],
) -> dict[str, list[dict[str, object]]]:
    if type(records) is not list or len(records) != len(positions):
        raise CohortReportError(f"{phase} records do not match the replay prefix")
    by_arm: dict[str, list[dict[str, object]]] = {arm: [] for arm in ARMS}
    for record, (round_index, launch_ordinal, arm) in zip(records, positions):
        phase_round = (
            round_index
            if phase == "warmup"
            else round_index - WARMUP_ROUNDS
        )
        if type(record) is not dict or frozenset(record) != RECORD_KEYS:
            raise CohortReportError("sample record key set is invalid")
        for key, expected in (
            ("round", round_index),
            ("phase_round", phase_round),
            ("launch_ordinal", launch_ordinal),
            ("child_exit", 0),
        ):
            if type(record[key]) is not type(expected) or record[key] != expected:
                raise CohortReportError(f"sample record {key} disagrees with schedule")
        sample = record["sample"]
        if type(sample) is not dict:
            raise CohortReportError("embedded sample must be an object")
        try:
            encoded = (
                json.dumps(sample, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
            validate_sample(encoded, expected_arm=arm, expected_log=log_size)
        except (TypeError, UnicodeError, ValueError) as error:
            raise CohortReportError(f"embedded sample failed replay: {error}") from error
        by_arm[arm].append(sample)
    return by_arm


def _validate_invalid_cohort(cohort: dict[str, Any], *, log_size: int) -> None:
    failure = validate_failure(cohort["failure"])
    if failure["log_size"] != log_size:
        raise CohortReportError("cohort and failure log sizes disagree")
    if type(cohort["summaries"]) is not dict or cohort["summaries"]:
        raise CohortReportError("invalid cohort summaries must be empty")

    phase = failure["phase"]
    if phase == "cohort-validation":
        for key in ("round", "phase_round", "launch_ordinal", "arm"):
            if failure[key] is not None:
                raise CohortReportError("cohort-validation failure has launch coordinates")
        _validate_schedule(
            cohort["schedule"], round_count=WARMUP_ROUNDS + MEASURED_ROUNDS
        )
        _validate_records(
            cohort["warmups"],
            log_size=log_size,
            phase="warmup",
            positions=_phase_positions("warmup"),
        )
        _validate_records(
            cohort["samples"],
            log_size=log_size,
            phase="measured",
            positions=_phase_positions("measured"),
        )
        return

    if phase not in {"warmup", "measured"}:
        raise CohortReportError("invalid cohort failure phase is unsupported")
    round_index = failure["round"]
    phase_round = failure["phase_round"]
    launch_ordinal = failure["launch_ordinal"]
    if type(round_index) is not int or type(launch_ordinal) is not int:
        raise CohortReportError("launch failure coordinates must be integers")
    total_rounds = WARMUP_ROUNDS + MEASURED_ROUNDS
    if round_index >= total_rounds or launch_ordinal >= len(ARMS):
        raise CohortReportError("launch failure coordinate is out of range")
    expected_phase = "warmup" if round_index < WARMUP_ROUNDS else "measured"
    expected_phase_round = (
        round_index if expected_phase == "warmup" else round_index - WARMUP_ROUNDS
    )
    expected_arm = launch_order(round_index)[launch_ordinal]
    if (
        phase != expected_phase
        or type(phase_round) is not int
        or phase_round != expected_phase_round
        or failure["arm"] != expected_arm
    ):
        raise CohortReportError("launch failure coordinates disagree with schedule")
    _validate_schedule(cohort["schedule"], round_count=round_index + 1)
    warmup_positions, measured_positions = _positions_before(
        round_index, launch_ordinal
    )
    _validate_records(
        cohort["warmups"],
        log_size=log_size,
        phase="warmup",
        positions=warmup_positions,
    )
    _validate_records(
        cohort["samples"],
        log_size=log_size,
        phase="measured",
        positions=measured_positions,
    )


def validate_cohort_document(cohort: Any) -> int:
    if type(cohort) is not dict or frozenset(cohort) != COHORT_KEYS:
        raise CohortReportError("cohort key set is invalid")
    log_size = cohort["log_size"]
    if type(log_size) is not int or log_size not in (*DEFAULT_LOGS, STRESS_LOG):
        raise CohortReportError("cohort has unsupported log size")
    exact = {
        "rows": 1 << log_size,
        "warmup_rounds": WARMUP_ROUNDS,
        "measured_rounds": MEASURED_ROUNDS,
    }
    for key, expected in exact.items():
        if type(cohort[key]) is not type(expected) or cohort[key] != expected:
            raise CohortReportError(f"cohort {key} is invalid")
    if type(cohort["valid"]) is not bool:
        raise CohortReportError("cohort validity must be boolean")
    if not cohort["valid"]:
        _validate_invalid_cohort(cohort, log_size=log_size)
        return log_size
    if cohort["failure"] is not None:
        raise CohortReportError("valid cohort carries a failure")
    _validate_schedule(
        cohort["schedule"], round_count=WARMUP_ROUNDS + MEASURED_ROUNDS
    )
    _validate_records(
        cohort["warmups"],
        log_size=log_size,
        phase="warmup",
        positions=_phase_positions("warmup"),
    )
    measured = _validate_records(
        cohort["samples"],
        log_size=log_size,
        phase="measured",
        positions=_phase_positions("measured"),
    )
    summaries = cohort["summaries"]
    if type(summaries) is not dict or set(summaries) != set(ARMS):
        raise CohortReportError("cohort summary arm set is incomplete")
    for arm in ARMS:
        metrics = summaries[arm]
        expected_metrics = {
            metric: integer_summary([int(sample[metric]) for sample in measured[arm]])
            for metric in ("setup_ns", "witness_ns", "direct_ns", "peak_rss_bytes")
        }
        if metrics != expected_metrics:
            raise CohortReportError(f"summary is not bound to embedded samples for {arm}")
    return log_size
