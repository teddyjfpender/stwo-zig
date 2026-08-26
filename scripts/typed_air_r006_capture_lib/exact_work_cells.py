"""Cell-local V2 executed-work authority and observational comparisons.

The prover receipt counts the algorithm schedule that actually completed.
Worker and backend partitions may therefore change counters without changing
the proof.  Equality is authoritative only inside one immutable
``(lane, workload, worker_count)`` execution cell; comparisons between cells
are validator-derived observations, never admission predicates.
"""

from __future__ import annotations

from typing import Any, Iterable

from .codec import canonical_bytes, exact_object, sha256_bytes
from .model import DIGEST_RE, CaptureError
from .report import (
    PRODUCER_COUNT,
    PRODUCER_LEDGER_VERSION,
    U64_MAX,
    WORK_COUNTER_FIELDS,
    WORK_PROFILE_ALL_SOURCES,
    WORK_PROFILE_SCHEMA,
    WORK_PROFILE_SEMANTICS,
    WORK_PROFILE_VERSION,
)


AUTHORITY_SCHEMA = "stwo.typed-air.r006-cell-exact-work-authority.v1"
COMPARISON_SCHEMA = "stwo.typed-air.r006-executed-work-comparison.v1"
DISCLOSURE_FIELDS = {
    "schema",
    "source_mask",
    "record_count",
    "producer_ledger_schema_version",
    "producer_counts",
    "producer_coverage_terminal_sealed",
    *WORK_COUNTER_FIELDS,
    "profile_sha256",
}


def _u64(value: Any, name: str) -> int:
    if type(value) is not int or not 0 <= value <= U64_MAX:
        raise CaptureError(f"{name} is not an unsigned 64-bit counter")
    return value


def validate_disclosure(value: Any) -> dict[str, Any]:
    """Revalidate the journal projection without trusting capture-time parsing."""

    work = exact_object(value, DISCLOSURE_FIELDS, "exact-work disclosure")
    if (
        work["schema"] != WORK_PROFILE_SCHEMA
        or work["source_mask"] != WORK_PROFILE_ALL_SOURCES
        or work["producer_ledger_schema_version"] != PRODUCER_LEDGER_VERSION
        or work["producer_coverage_terminal_sealed"] is not True
    ):
        raise CaptureError("exact-work disclosure is incomplete or changed")
    record_count = _u64(work["record_count"], "exact-work record count")
    if record_count == 0:
        raise CaptureError("exact-work record count is empty")
    counts = work["producer_counts"]
    if type(counts) is not list or len(counts) != PRODUCER_COUNT:
        raise CaptureError("exact-work producer-count shape changed")
    for index, count in enumerate(counts):
        _u64(count, f"exact-work producer count {index}")
    if sum(counts) != record_count:
        raise CaptureError("exact-work producer counts do not close")
    for name in WORK_COUNTER_FIELDS:
        _u64(work[name], f"exact-work {name}")
    digest = work["profile_sha256"]
    if type(digest) is not str or DIGEST_RE.fullmatch(digest) is None:
        raise CaptureError("exact-work profile digest is not canonical")
    return work


def _coverage_projection(work: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": work["schema"],
        "source_mask": work["source_mask"],
        "record_count": work["record_count"],
        "producer_ledger_schema_version": work[
            "producer_ledger_schema_version"
        ],
        "producer_counts": list(work["producer_counts"]),
        "producer_coverage_terminal_sealed": work[
            "producer_coverage_terminal_sealed"
        ],
    }


def validate_cell_authority(
    plan: dict[str, Any],
    lane_records: dict[str, list[dict[str, Any]]],
    lane_order: tuple[str, ...],
) -> dict[str, Any]:
    """Derive deterministic exact-work cells from plan-bound lane journals."""

    if set(lane_records) != set(lane_order):
        raise CaptureError("exact-work lane inventory changed")
    expected: dict[tuple[str, str, int], int] = {}
    observed: dict[tuple[str, str, int], dict[str, Any]] = {}
    verified_exact_attempts = 0
    for lane in lane_order:
        attempts = plan["lanes"][lane]["attempts"]
        records = lane_records[lane]
        if len(records) != len(attempts):
            raise CaptureError("exact-work lane cardinality changed")
        for attempt, record in zip(attempts, records, strict=True):
            workers = attempt["worker_count"]
            if type(workers) is not int or workers <= 0:
                raise CaptureError("exact-work plan worker count is invalid")
            key = (lane, attempt["workload_id"], workers)
            expected[key] = expected.get(key, 0) + 1
            if record["status"] != "verified":
                continue
            metrics = record["metrics"]
            disclosure = (
                metrics.get("work_disclosure") if type(metrics) is dict else None
            )
            if type(disclosure) is not dict:
                raise CaptureError("verified attempt lacks exact V2 work authority")
            work = validate_disclosure(disclosure)
            prior = observed.get(key)
            if prior is None:
                observed[key] = {
                    "disclosure": work,
                    "verified_records": 1,
                }
            else:
                if prior["disclosure"] != work:
                    raise CaptureError(
                        "exact V2 work changed within execution cell "
                        f"{lane}/{attempt['workload_id']}/{workers}"
                    )
                prior["verified_records"] += 1
            verified_exact_attempts += 1

    lane_rank = {lane: index for index, lane in enumerate(lane_order)}
    cells: list[dict[str, Any]] = []
    complete_cells = 0
    for key in sorted(observed, key=lambda item: (lane_rank[item[0]], item[1], item[2])):
        lane, workload, workers = key
        state = observed[key]
        work = state["disclosure"]
        expected_records = expected[key]
        verified_records = state["verified_records"]
        complete_cells += verified_records == expected_records
        cells.append(
            {
                "lane": lane,
                "workload_id": workload,
                "worker_count": workers,
                "expected_records": expected_records,
                "verified_records": verified_records,
                "profile_sha256": work["profile_sha256"],
                "disclosure_sha256": sha256_bytes(canonical_bytes(work)),
                "coverage_sha256": sha256_bytes(
                    canonical_bytes(_coverage_projection(work))
                ),
                "work_disclosure": work,
            }
        )
    expected_attempts = sum(expected.values())
    every_attempt_complete = (
        verified_exact_attempts == expected_attempts
        and len(cells) == len(expected)
        and complete_cells == len(expected)
    )
    return {
        "schema": AUTHORITY_SCHEMA,
        "schema_version": 1,
        "work_profile_schema": WORK_PROFILE_SCHEMA,
        "work_profile_schema_version": WORK_PROFILE_VERSION,
        "counter_semantics": WORK_PROFILE_SEMANTICS,
        "expected_attempts": expected_attempts,
        "verified_exact_attempts": verified_exact_attempts,
        "expected_cells": len(expected),
        "populated_cells": len(cells),
        "complete_cells": complete_cells,
        "every_attempt_complete_exact_work": every_attempt_complete,
        "every_cell_deterministic": True,
        "cells": cells,
    }


def cell_index(authority: dict[str, Any]) -> dict[tuple[str, str, int], dict[str, Any]]:
    if (
        authority.get("schema") != AUTHORITY_SCHEMA
        or authority.get("schema_version") != 1
        or authority.get("work_profile_schema") != WORK_PROFILE_SCHEMA
        or authority.get("work_profile_schema_version") != WORK_PROFILE_VERSION
        or authority.get("counter_semantics") != WORK_PROFILE_SEMANTICS
        or type(authority.get("cells")) is not list
    ):
        raise CaptureError("exact-work cell authority changed")
    result: dict[tuple[str, str, int], dict[str, Any]] = {}
    for cell in authority["cells"]:
        if type(cell) is not dict:
            raise CaptureError("exact-work cell is not an object")
        key = (cell.get("lane"), cell.get("workload_id"), cell.get("worker_count"))
        if key in result:
            raise CaptureError("exact-work authority repeats a cell")
        result[key] = cell
    return result


def _summary(cell: dict[str, Any]) -> dict[str, Any]:
    work = validate_disclosure(cell["work_disclosure"])
    if (
        cell["profile_sha256"] != work["profile_sha256"]
        or cell["disclosure_sha256"] != sha256_bytes(canonical_bytes(work))
        or cell["coverage_sha256"]
        != sha256_bytes(canonical_bytes(_coverage_projection(work)))
    ):
        raise CaptureError("exact-work cell summary disagrees with its profile")
    return {
        "lane": cell["lane"],
        "workload_id": cell["workload_id"],
        "worker_count": cell["worker_count"],
        "verified_records": cell["verified_records"],
        "profile_sha256": cell["profile_sha256"],
        "disclosure_sha256": cell["disclosure_sha256"],
        "coverage_sha256": cell["coverage_sha256"],
        "record_count": work["record_count"],
        "producer_counts": list(work["producer_counts"]),
        "counters": {name: work[name] for name in WORK_COUNTER_FIELDS},
    }


def _ratio(reference: int, subject: int) -> dict[str, Any]:
    if reference == 0:
        return {
            "availability": "undefined_zero_reference",
            "numerator": subject,
            "denominator": 0,
        }
    return {
        "availability": "available",
        "numerator": subject,
        "denominator": reference,
    }


def counter_comparison(reference: Any, subject: Any) -> dict[str, Any]:
    base = _u64(reference, "executed-work reference counter")
    current = _u64(subject, "executed-work subject counter")
    delta = current - base
    if not -U64_MAX <= delta <= U64_MAX:  # Defensive if integer inputs widen.
        raise CaptureError("executed-work signed delta overflowed")
    return {
        "reference": base,
        "subject": current,
        "signed_delta": delta,
        "ratio": _ratio(base, current),
    }


def compare_cells(
    reference: dict[str, Any],
    subject: dict[str, Any],
    *,
    relation: str,
    blocking: bool,
) -> dict[str, Any]:
    reference_summary = _summary(reference)
    subject_summary = _summary(subject)
    if reference_summary["workload_id"] != subject_summary["workload_id"]:
        raise CaptureError("executed-work comparison crossed workloads")
    return {
        "schema": COMPARISON_SCHEMA,
        "schema_version": 1,
        "counter_semantics": WORK_PROFILE_SEMANTICS,
        "relation": relation,
        "blocking": blocking,
        "reference": reference_summary,
        "subject": subject_summary,
        "profile_identical": (
            reference_summary["disclosure_sha256"]
            == subject_summary["disclosure_sha256"]
        ),
        "counter_comparisons": {
            name: counter_comparison(
                reference_summary["counters"][name],
                subject_summary["counters"][name],
            )
            for name in WORK_COUNTER_FIELDS
        },
    }


def require_cells(
    index: dict[tuple[str, str, int], dict[str, Any]],
    keys: Iterable[tuple[str, str, int]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for key in keys:
        cell = index.get(key)
        if cell is None:
            raise CaptureError(
                f"exact-work authority lacks cell {key[0]}/{key[1]}/{key[2]}"
            )
        result.append(cell)
    return result
