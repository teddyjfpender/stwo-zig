"""Explicit authority for recovering an interrupted paired R-006 attempt.

The normal protocol never retries an attempt.  This module defines a narrower
operator-authorized exception for the only ambiguous crash window: a durable
publication intent exists, but no prepared record or retained output exists.
The exception is append-only, content-bound, and remains visible in every
derived validation/reduction receipt.
"""

from __future__ import annotations

from typing import Any, Mapping

from .codec import content_digest, exact_object
from .model import DIGEST_RE, UTC_RE, CaptureError


AUTHORIZATION_SCHEMA = "stwo.typed-air.r006-interrupted-attempt-retry.v1"
AUTHORIZATION_POLICY = "explicit-operator-authorized-no-output-retry-v1"

AUTHORIZATION_FIELDS = {
    "schema",
    "schema_version",
    "policy",
    "global_ordinal",
    "lane",
    "lane_ordinal",
    "attempt_id",
    "durable_prefix",
    "retry_index",
    "prior_intent_sha256",
    "from_power_source",
    "to_power_source",
    "retained_output_files",
    "operator_confirmed_no_live_child",
    "authorized_at_utc",
    "controller_commit",
    "content_sha256",
}


def schedule_identity(schedule: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "global_ordinal": schedule["global_ordinal"],
        "lane": schedule["lane"],
        "lane_ordinal": schedule["lane_ordinal"],
        "attempt_id": schedule["attempt_id"],
    }


def build_authorization(
    schedule: dict[str, Any],
    *,
    durable_prefix: int,
    retry_index: int,
    prior_intent_sha256: str,
    from_power_source: str,
    to_power_source: str,
    authorized_at_utc: str,
    controller_commit: str,
) -> dict[str, Any]:
    result = {
        "schema": AUTHORIZATION_SCHEMA,
        "schema_version": 1,
        "policy": AUTHORIZATION_POLICY,
        **schedule_identity(schedule),
        "durable_prefix": durable_prefix,
        "retry_index": retry_index,
        "prior_intent_sha256": prior_intent_sha256,
        "from_power_source": from_power_source,
        "to_power_source": to_power_source,
        "retained_output_files": [],
        "operator_confirmed_no_live_child": True,
        "authorized_at_utc": authorized_at_utc,
        "controller_commit": controller_commit,
    }
    result["content_sha256"] = content_digest(result)
    return validate_authorization(
        result,
        schedule=schedule,
        durable_prefix=durable_prefix,
        retry_index=retry_index,
        prior_intent_sha256=prior_intent_sha256,
        from_power_source=from_power_source,
    )


def validate_authorization(
    value: Any,
    *,
    schedule: dict[str, Any],
    durable_prefix: int,
    retry_index: int,
    prior_intent_sha256: str,
    from_power_source: str,
) -> dict[str, Any]:
    record = exact_object(value, AUTHORIZATION_FIELDS, "attempt retry authorization")
    if (
        record["schema"] != AUTHORIZATION_SCHEMA
        or record["schema_version"] != 1
        or record["policy"] != AUTHORIZATION_POLICY
        or any(
            record[name] != expected
            for name, expected in schedule_identity(schedule).items()
        )
        or record["durable_prefix"] != durable_prefix
        or record["retry_index"] != retry_index
        or record["prior_intent_sha256"] != prior_intent_sha256
        or record["from_power_source"] != from_power_source
        or type(record["to_power_source"]) is not str
        or not record["to_power_source"]
        or record["retained_output_files"] != []
        or record["operator_confirmed_no_live_child"] is not True
        or type(record["authorized_at_utc"]) is not str
        or UTC_RE.fullmatch(record["authorized_at_utc"]) is None
        or type(record["controller_commit"]) is not str
        or len(record["controller_commit"]) != 40
        or any(character not in "0123456789abcdef" for character in record["controller_commit"])
        or type(record["content_sha256"]) is not str
        or DIGEST_RE.fullmatch(record["content_sha256"]) is None
        or record["content_sha256"] != content_digest(record)
    ):
        raise CaptureError("interrupted-attempt retry authorization changed")
    return record


def power_source_at_prefix(
    plan: dict[str, Any],
    authorizations: list[dict[str, Any]],
    completed_attempts: int,
) -> str:
    source = plan["host_preflight"]["host"]["power_source"]
    for authorization in authorizations:
        if authorization["durable_prefix"] <= completed_attempts:
            source = authorization["to_power_source"]
    return source


def require_host_at_prefix(
    actual: dict[str, Any],
    expected: dict[str, Any],
    *,
    power_source: str,
) -> None:
    if type(power_source) is not str or not power_source:
        raise CaptureError("authorized recovery power source is invalid")
    projected = dict(actual)
    observed_source = projected.pop("power_source", None)
    expected_projected = dict(expected)
    expected_projected.pop("power_source", None)
    if projected != expected_projected or observed_source != power_source:
        raise CaptureError("paired preflight boundary host identity drifted")


def disclosure(authorizations: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": "stwo.typed-air.r006-recovery-disclosure.v1",
        "operator_authorized": bool(authorizations),
        "authorized_retry_count": len(authorizations),
        "authorizations": authorizations,
    }
