"""Explicit CPU/Metal semantic-identity authority for paired R-006 capture."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .model import DIGEST_RE, CaptureError
from .workload_profile import (
    GUEST_ARTIFACT_FORMAT_VERSION,
    GUEST_ARTIFACT_KIND,
    GUEST_PROFILE_MANIFEST_SHA256,
    GUEST_PROFILE_VERSION,
    GUEST_TASK_PROFILE_EXAMPLE,
    is_guest_workload,
    workload_for_attempt,
)


COMMON_FIELDS = {
    "statement_sha256",
    "transcript_state_blake2s",
    "proof_sha256",
    "proof_bytes",
    "total_steps",
    "n_components",
}
BASE_FIELDS = COMMON_FIELDS | {
    "verifier_proof_sha256",
    "verifier_proof_bytes",
}
GUEST_FIELDS = COMMON_FIELDS | {
    "artifact_kind",
    "artifact_schema_version",
    "profile_identity",
    "profile_version",
    "profile_manifest_sha256",
    "guest_calls",
}
BASE_PROJECTION_SCHEMA = "stwo.typed-air.r006-base-semantic-identity.v1"
GUEST_PROJECTION_SCHEMA = "stwo.typed-air.r006-guest-semantic-identity.v1"


def _digest(value: Any, name: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise CaptureError(f"paired semantic identity {name} is invalid")
    return value


def _positive(value: Any, name: str) -> int:
    if type(value) is not int or value <= 0:
        raise CaptureError(f"paired semantic identity {name} is invalid")
    return value


def cross_lane_semantic_identity(
    workload: dict[str, Any], identity: Any
) -> dict[str, Any]:
    if type(identity) is not dict:
        raise CaptureError("paired proof identity must be an object")
    fields = set(identity)
    guest = is_guest_workload(workload)
    expected_fields = GUEST_FIELDS if guest else BASE_FIELDS
    if fields != expected_fields:
        raise CaptureError("paired proof identity fields drifted")
    statement = _digest(identity["statement_sha256"], "statement digest")
    transcript = _digest(
        identity["transcript_state_blake2s"], "transcript digest"
    )
    artifact_bytes = _positive(identity["proof_bytes"], "artifact bytes")
    artifact_sha256 = _digest(identity["proof_sha256"], "artifact digest")
    total_steps = _positive(identity["total_steps"], "total steps")
    n_components = _positive(identity["n_components"], "component count")
    if not guest:
        return {
            "schema": BASE_PROJECTION_SCHEMA,
            "family": "base-v4-decoded-proof",
            "statement_sha256": statement,
            "transcript_state_blake2s": transcript,
            "verifier_proof_bytes": _positive(
                identity["verifier_proof_bytes"], "verifier proof bytes"
            ),
            "verifier_proof_sha256": _digest(
                identity["verifier_proof_sha256"], "verifier proof digest"
            ),
            "total_steps": total_steps,
            "n_components": n_components,
        }
    guest_fixed = {
        "artifact_kind": GUEST_ARTIFACT_KIND,
        "artifact_schema_version": GUEST_ARTIFACT_FORMAT_VERSION,
        "profile_identity": GUEST_TASK_PROFILE_EXAMPLE,
        "profile_version": GUEST_PROFILE_VERSION,
        "profile_manifest_sha256": GUEST_PROFILE_MANIFEST_SHA256,
        "guest_calls": workload["parameters"]["calls"],
    }
    for name, expected in guest_fixed.items():
        if type(identity[name]) is not type(expected) or identity[name] != expected:
            raise CaptureError(f"paired guest semantic identity {name} changed")
    return {
        "schema": GUEST_PROJECTION_SCHEMA,
        "family": "guest-stwgpf01",
        **guest_fixed,
        "statement_sha256": statement,
        "transcript_state_blake2s": transcript,
        "artifact_bytes": artifact_bytes,
        "artifact_sha256": artifact_sha256,
        "total_steps": total_steps,
        "n_components": n_components,
    }


def validate_pair_identity_authority(
    plan: dict[str, Any],
    lane_records: Mapping[str, list[dict[str, Any]]],
    lanes: Sequence[str],
) -> dict[str, dict[str, Any]]:
    """Retain exact lane artifacts while comparing semantics across lanes."""
    semantics: dict[str, dict[str, Any]] = {}
    for lane in lanes:
        lane_full: dict[str, dict[str, Any]] = {}
        for attempt, record in zip(
            plan["lanes"][lane]["attempts"], lane_records[lane], strict=True
        ):
            if record["status"] != "verified":
                continue
            workload = attempt["workload_id"]
            identity = record["identity"]
            prior_full = lane_full.setdefault(workload, identity)
            if prior_full != identity:
                raise CaptureError(
                    f"within-lane proof artifact identity changed for {lane}/{workload}"
                )
            selected_workload = workload_for_attempt(
                plan["lanes"][lane], attempt
            )
            projected = cross_lane_semantic_identity(selected_workload, identity)
            prior = semantics.setdefault(workload, projected)
            if prior != projected:
                raise CaptureError(
                    f"CPU/Metal semantic proof identity changed for paired workload {workload}"
                )
    return semantics
