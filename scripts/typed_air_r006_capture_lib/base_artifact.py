"""Retained V4 artifact custody for the base RISC-V verifier payload."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .codec import decode_strict, exact_object, sha256_bytes
from .model import MAX_STREAM_BYTES, CaptureError


ARTIFACT_FIELDS = {
    "artifact_kind",
    "schema_version",
    "exchange_mode",
    "release_status",
    "generator",
    "air",
    "backend",
    "protocol",
    "source",
    "provenance",
    "pcs_config",
    "statement",
    "interaction_claim",
    "proof_bytes_hex",
}


def verifier_payload_identity(
    path: Path,
    *,
    artifact_bytes: int,
    artifact_sha256: str,
    expected_backend: str,
) -> dict[str, Any]:
    """Derive the receipt payload identity from one admitted artifact snapshot."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CaptureError("cannot read retained V4 proof artifact") from error
    if len(raw) != artifact_bytes or sha256_bytes(raw) != artifact_sha256:
        raise CaptureError("retained V4 proof artifact changed during validation")
    artifact = exact_object(
        decode_strict(raw, maximum=MAX_STREAM_BYTES),
        ARTIFACT_FIELDS,
        "retained V4 proof artifact",
    )
    expected = {
        "artifact_kind": "stwo_riscv_proof",
        "schema_version": 4,
        "exchange_mode": "riscv_proof_json_wire_v4",
        "release_status": "release_gated",
        "backend": expected_backend,
        "protocol": "secure",
    }
    for name, value in expected.items():
        if type(artifact[name]) is not type(value) or artifact[name] != value:
            raise CaptureError(f"retained V4 proof artifact {name} changed")
    proof_hex = artifact["proof_bytes_hex"]
    if (
        type(proof_hex) is not str
        or not proof_hex
        or len(proof_hex) % 2 != 0
        or any(byte not in "0123456789abcdef" for byte in proof_hex)
    ):
        raise CaptureError(
            "retained V4 proof artifact proof_bytes_hex is not canonical"
        )
    payload = bytes.fromhex(proof_hex)
    return {
        "verifier_proof_bytes": len(payload),
        "verifier_proof_sha256": sha256_bytes(payload),
    }
