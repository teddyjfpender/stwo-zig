"""Strict authentication of one production RISC-V verifier receipt."""

from __future__ import annotations

import json
from typing import Any

from .codec import decode_strict, exact_object
from .model import DIGEST_RE, GIT_OID_RE, CaptureError


SCHEMA = "riscv_verify_v1"
ARTIFACT_KIND = "stwo_riscv_proof"
ARTIFACT_SCHEMA_VERSION = 4
RELEASE_STATUS = "release_gated"
SECURITY_POLICY = "secure"
MAX_RECEIPT_BYTES = 4 * 1024
U64_MAX = (1 << 64) - 1
FIELDS_IN_WIRE_ORDER = (
    "schema",
    "status",
    "artifact_kind",
    "artifact_schema_version",
    "release_status",
    "security_policy",
    "statement_sha256",
    "proof_bytes",
    "proof_sha256",
    "transcript_state_blake2s",
    "implementation_commit",
    "implementation_dirty",
    "executable_sha256",
)
FIELDS = set(FIELDS_IN_WIRE_ORDER)


def _digest(value: Any, name: str) -> str:
    if type(value) is not str or DIGEST_RE.fullmatch(value) is None:
        raise CaptureError(f"verifier receipt {name} digest is invalid")
    return value


def _wire_bytes(receipt: dict[str, Any]) -> bytes:
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


def validate_verifier_receipt(
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
        raise CaptureError("verifier stdout must be one bounded JSON line")
    receipt = exact_object(
        decode_strict(raw, maximum=MAX_RECEIPT_BYTES),
        FIELDS,
        "verifier receipt",
    )

    statement = _digest(identity.get("statement_sha256"), "statement")
    transcript = _digest(
        identity.get("transcript_state_blake2s"), "transcript state"
    )
    executable = _digest(plan["build"].get("executable_sha256"), "executable")
    commit = plan["source"].get("commit")
    if type(commit) is not str or GIT_OID_RE.fullmatch(commit) is None:
        raise CaptureError("verifier receipt planned implementation commit is invalid")

    fixed = {
        "schema": SCHEMA,
        "status": "verified",
        "artifact_kind": ARTIFACT_KIND,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "release_status": RELEASE_STATUS,
        "security_policy": SECURITY_POLICY,
        "statement_sha256": statement,
        "transcript_state_blake2s": transcript,
        "implementation_commit": commit,
        "implementation_dirty": False,
        "executable_sha256": executable,
    }
    for name, expected in fixed.items():
        if type(receipt[name]) is not type(expected) or receipt[name] != expected:
            raise CaptureError(f"verifier receipt {name} identity changed")

    proof_bytes = receipt["proof_bytes"]
    if type(proof_bytes) is not int or not 0 < proof_bytes <= U64_MAX:
        raise CaptureError("verifier receipt proof byte count is invalid")
    proof_sha256 = _digest(receipt["proof_sha256"], "proof")
    expected_proof_bytes = identity.get("verifier_proof_bytes")
    if (
        type(expected_proof_bytes) is not int
        or not 0 < expected_proof_bytes <= U64_MAX
    ):
        raise CaptureError("verifier receipt expected proof byte count is invalid")
    expected_proof_sha256 = _digest(
        identity.get("verifier_proof_sha256"), "expected proof"
    )
    if proof_bytes != expected_proof_bytes:
        raise CaptureError("verifier receipt proof_bytes identity changed")
    if proof_sha256 != expected_proof_sha256:
        raise CaptureError("verifier receipt proof_sha256 identity changed")

    expected = {
        **fixed,
        "proof_bytes": expected_proof_bytes,
        "proof_sha256": expected_proof_sha256,
    }
    if raw != _wire_bytes(expected):
        raise CaptureError("verifier receipt is not the canonical production JSON line")
    return receipt
