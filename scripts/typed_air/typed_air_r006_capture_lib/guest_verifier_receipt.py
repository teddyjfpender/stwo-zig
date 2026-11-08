"""Strict receipt for independent STWGPF01 guest-profile verification."""

from __future__ import annotations

import json
from typing import Any

from .codec import decode_strict, exact_object
from .model import DIGEST_RE, GIT_OID_RE, CaptureError
from .workload_profile import (
    GUEST_ARTIFACT_FORMAT_VERSION,
    GUEST_ARTIFACT_KIND,
    GUEST_ARTIFACT_MAGIC,
    GUEST_PROFILE_MANIFEST_SHA256,
    GUEST_PROFILE_VERSION,
    GUEST_TASK_PROFILE_EXAMPLE,
)


SCHEMA = "riscv_guest_poseidon2_verify_v1"
MAX_RECEIPT_BYTES = 4 * 1024
FIELDS_IN_WIRE_ORDER = (
    "schema",
    "status",
    "artifact_kind",
    "artifact_schema_version",
    "artifact_magic",
    "profile_identity",
    "profile_version",
    "profile_manifest_sha256",
    "release_status",
    "security_policy",
    "statement_sha256",
    "artifact_bytes",
    "artifact_sha256",
    "transcript_state_blake2s",
    "implementation_commit",
    "implementation_dirty",
    "executable_sha256",
)


def _digest(value: Any, name: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise CaptureError(f"guest verifier receipt {name} digest is invalid")
    return value


def _canonical(receipt: dict[str, Any]) -> bytes:
    ordered = {name: receipt[name] for name in FIELDS_IN_WIRE_ORDER}
    return (
        json.dumps(
            ordered,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def validate_guest_verifier_receipt(
    raw: bytes,
    *,
    plan: dict[str, Any],
    identity: dict[str, Any],
) -> dict[str, Any]:
    if (
        type(raw) is not bytes
        or not raw
        or len(raw) > MAX_RECEIPT_BYTES
        or not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or b"\r" in raw
    ):
        raise CaptureError("guest verifier stdout must be one bounded JSON line")
    receipt = exact_object(
        decode_strict(raw, maximum=MAX_RECEIPT_BYTES),
        set(FIELDS_IN_WIRE_ORDER),
        "guest verifier receipt",
    )
    statement = _digest(identity.get("statement_sha256"), "statement")
    transcript = _digest(
        identity.get("transcript_state_blake2s"), "transcript state"
    )
    artifact_sha256 = _digest(identity.get("proof_sha256"), "artifact")
    artifact_bytes = identity.get("proof_bytes")
    if type(artifact_bytes) is not int or artifact_bytes <= 0:
        raise CaptureError("guest verifier receipt artifact byte count is invalid")
    executable = _digest(plan["build"].get("executable_sha256"), "executable")
    commit = plan["source"].get("commit")
    if type(commit) is not str or GIT_OID_RE.fullmatch(commit) is None:
        raise CaptureError("guest verifier receipt implementation commit is invalid")
    expected = {
        "schema": SCHEMA,
        "status": "verified",
        "artifact_kind": GUEST_ARTIFACT_KIND,
        "artifact_schema_version": GUEST_ARTIFACT_FORMAT_VERSION,
        "artifact_magic": GUEST_ARTIFACT_MAGIC.decode("ascii"),
        "profile_identity": GUEST_TASK_PROFILE_EXAMPLE,
        "profile_version": GUEST_PROFILE_VERSION,
        "profile_manifest_sha256": GUEST_PROFILE_MANIFEST_SHA256,
        "release_status": "release_gated",
        "security_policy": "secure",
        "statement_sha256": statement,
        "artifact_bytes": artifact_bytes,
        "artifact_sha256": artifact_sha256,
        "transcript_state_blake2s": transcript,
        "implementation_commit": commit,
        "implementation_dirty": False,
        "executable_sha256": executable,
    }
    for name, value in expected.items():
        if type(receipt[name]) is not type(value) or receipt[name] != value:
            raise CaptureError(f"guest verifier receipt {name} identity changed")
    if raw != _canonical(expected):
        raise CaptureError("guest verifier receipt is not canonical production JSON")
    return receipt
