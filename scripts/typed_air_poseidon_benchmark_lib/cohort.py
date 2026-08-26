"""Deterministic H-010 cohort scheduling, admission, and summaries."""

from __future__ import annotations

from typing import Callable, Sequence

from .contract import (
    ARMS,
    ARM_PINS,
    MEASURED_ROUNDS,
    STABLE_SAMPLE_KEYS,
    VECTOR_FORMAT,
    VECTOR_GENERATOR,
    WARMUP_ROUNDS,
)


METRICS = ("setup_ns", "witness_ns", "direct_ns", "peak_rss_bytes")
SampleRunner = Callable[[str, int], dict[str, object]]


class SampleFailure(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def launch_order(round_index: int) -> tuple[str, ...]:
    """Return the ADR-0022 arm rotation for one zero-based round."""

    if type(round_index) is not int or round_index < 0:
        raise ValueError("round index must be a non-negative integer")
    offset = round_index % len(ARMS)
    return ARMS[offset:] + ARMS[:offset]


def integer_summary(values: Sequence[int]) -> dict[str, object]:
    """Return lossless eleven-sample median/MAD/min/max statistics."""

    if len(values) != MEASURED_ROUNDS:
        raise ValueError(f"summary requires exactly {MEASURED_ROUNDS} values")
    if any(type(value) is not int or value < 0 for value in values):
        raise ValueError("summary values must be non-negative integers")
    ordered = sorted(values)
    median = ordered[len(ordered) // 2]
    deviations = sorted(abs(value - median) for value in values)
    return {
        "raw": list(values),
        "median": median,
        "mad": deviations[len(deviations) // 2],
        "minimum": ordered[0],
        "maximum": ordered[-1],
    }


def failure_record(
    code: str,
    message: str,
    phase: str,
    *,
    log_size: int | None = None,
    round_index: int | None = None,
    phase_round: int | None = None,
    launch_ordinal: int | None = None,
    arm: str | None = None,
) -> dict[str, object]:
    return {
        "code": code,
        "message": message,
        "phase": phase,
        "log_size": log_size,
        "round": round_index,
        "phase_round": phase_round,
        "launch_ordinal": launch_ordinal,
        "arm": arm,
    }


def _require_stable_samples(
    samples: Sequence[dict[str, object]],
    *,
    arm: str,
    log_size: int,
) -> None:
    reference = samples[0]
    for ordinal, sample in enumerate(samples[1:], start=1):
        for key in STABLE_SAMPLE_KEYS:
            if sample[key] != reference[key]:
                raise SampleFailure(
                    "sample-identity-drift",
                    f"{key} drift for arm={arm} log={log_size} at sample={ordinal}",
                )


def _cohort_document(
    log_size: int,
    schedule: list[dict[str, object]],
    warmups: list[dict[str, object]],
    measured: list[dict[str, object]],
    *,
    valid: bool,
    summaries: dict[str, object] | None = None,
    failure: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "log_size": log_size,
        "rows": 1 << log_size,
        "warmup_rounds": WARMUP_ROUNDS,
        "measured_rounds": MEASURED_ROUNDS,
        "schedule": schedule,
        "warmups": warmups,
        "samples": measured,
        "summaries": {} if summaries is None else summaries,
        "failure": failure,
        "valid": valid,
    }


def collect_log(log_size: int, run_sample: SampleRunner) -> dict[str, object]:
    """Collect one complete serial log-size cohort or one explicit failure."""

    warmups: list[dict[str, object]] = []
    measured: list[dict[str, object]] = []
    all_by_arm: dict[str, list[dict[str, object]]] = {arm: [] for arm in ARMS}
    measured_by_arm: dict[str, list[dict[str, object]]] = {arm: [] for arm in ARMS}
    schedule: list[dict[str, object]] = []
    total_rounds = WARMUP_ROUNDS + MEASURED_ROUNDS

    for round_index in range(total_rounds):
        phase = "warmup" if round_index < WARMUP_ROUNDS else "measured"
        phase_round = round_index if phase == "warmup" else round_index - WARMUP_ROUNDS
        arms = launch_order(round_index)
        schedule.append(
            {
                "round": round_index,
                "phase": phase,
                "phase_round": phase_round,
                "arms": list(arms),
            }
        )
        for launch_ordinal, arm in enumerate(arms):
            try:
                sample = run_sample(arm, log_size)
            except SampleFailure as error:
                failure = failure_record(
                    error.code,
                    str(error),
                    phase,
                    log_size=log_size,
                    round_index=round_index,
                    phase_round=phase_round,
                    launch_ordinal=launch_ordinal,
                    arm=arm,
                )
                return _cohort_document(
                    log_size,
                    schedule,
                    warmups,
                    measured,
                    valid=False,
                    failure=failure,
                )
            record = {
                "round": round_index,
                "phase_round": phase_round,
                "launch_ordinal": launch_ordinal,
                "child_exit": 0,
                "sample": sample,
            }
            all_by_arm[arm].append(sample)
            if phase == "warmup":
                warmups.append(record)
            else:
                measured.append(record)
                measured_by_arm[arm].append(sample)

    try:
        summaries: dict[str, object] = {}
        output_digest: str | None = None
        call_digest: str | None = None
        vector_seal: str | None = None
        vector_artifact: str | None = None
        for arm in ARMS:
            arm_samples = measured_by_arm[arm]
            if len(arm_samples) != MEASURED_ROUNDS:
                raise SampleFailure(
                    "incomplete-cohort",
                    f"incomplete measured cohort for arm={arm} log={log_size}",
                )
            _require_stable_samples(all_by_arm[arm], arm=arm, log_size=log_size)
            arm_output = str(arm_samples[0]["output_digest"])
            arm_call = str(arm_samples[0]["call_digest"])
            arm_vector_seal = str(arm_samples[0]["vector_seal"])
            arm_vector_artifact = str(arm_samples[0]["vector_artifact_sha256"])
            if output_digest is None:
                output_digest = arm_output
                call_digest = arm_call
                vector_seal = arm_vector_seal
                vector_artifact = arm_vector_artifact
            elif (
                arm_output != output_digest
                or arm_call != call_digest
                or arm_vector_seal != vector_seal
                or arm_vector_artifact != vector_artifact
            ):
                raise SampleFailure(
                    "cross-arm-identity",
                    f"semantic output/call/vector digest disagrees at log={log_size}",
                )
            summaries[arm] = {
                metric: integer_summary([int(sample[metric]) for sample in arm_samples])
                for metric in METRICS
            }
    except SampleFailure as error:
        failure = failure_record(
            error.code,
            str(error),
            "cohort-validation",
            log_size=log_size,
        )
        return _cohort_document(
            log_size,
            schedule,
            warmups,
            measured,
            valid=False,
            failure=failure,
        )
    return _cohort_document(
        log_size,
        schedule,
        warmups,
        measured,
        valid=True,
        summaries=summaries,
    )


def arm_table() -> list[dict[str, object]]:
    return [
        {
            "arm": pin.arm,
            "selection_class": pin.selection_class,
            "quantile_numerator": pin.quantile_numerator,
            "quantile_denominator": pin.quantile_denominator,
            "sorted_rank": pin.sorted_rank,
            "frontier_ordinal": pin.frontier_ordinal,
            "removed_value_id": pin.removed_value_id,
            "added_value_id": pin.added_value_id,
            "proposal_digest": pin.proposal_digest,
            "cut_digest": pin.cut_digest,
            "parent_cut_digest": pin.parent_cut_digest,
        }
        for pin in ARM_PINS
    ]


def all_samples(cohorts: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for cohort in cohorts:
        for key in ("warmups", "samples"):
            records = cohort[key]
            assert isinstance(records, list)
            for record in records:
                assert isinstance(record, dict)
                sample = record["sample"]
                assert isinstance(sample, dict)
                result.append(sample)
    return result


def execution_identity(
    cohorts: Sequence[dict[str, object]],
) -> dict[str, object] | None:
    samples = all_samples(cohorts)
    if not samples:
        return None
    keys = (
        "optimization_mode",
        "zig_version",
        "target",
        "allocator",
        "monotonic_clock",
    )
    identity = {key: samples[0][key] for key in keys}
    for ordinal, sample in enumerate(samples[1:], start=1):
        for key, value in identity.items():
            if sample[key] != value:
                raise SampleFailure(
                    "execution-identity-drift",
                    f"{key} changed at collected sample {ordinal}",
                )
    return identity


def vector_table(cohorts: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for cohort in cohorts:
        if not cohort["valid"]:
            continue
        samples = all_samples([cohort])
        if not samples:
            continue
        first = samples[0]
        traces = {
            arm: next(
                str(sample["trace_digest"])
                for sample in samples
                if sample["arm"] == arm
            )
            for arm in ARMS
        }
        result.append(
            {
                "format": VECTOR_FORMAT,
                "generator": VECTOR_GENERATOR,
                "log_size": first["log_size"],
                "rows": first["rows"],
                "storage_class": first["vector_storage_class"],
                "bytes": first["vector_bytes"],
                "seal": first["vector_seal"],
                "artifact_sha256": first["vector_artifact_sha256"],
                "call_digest": first["call_digest"],
                "output_digest": first["output_digest"],
                "trace_digest_class": first["trace_digest_class"],
                "trace_digests": traces,
            }
        )
    return result
