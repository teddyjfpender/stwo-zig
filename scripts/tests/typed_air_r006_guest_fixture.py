"""Canonical STWGPF01 fixture bytes shared by focused R-006 tests."""

from __future__ import annotations

import hashlib
import json
import struct


def guest_artifact(proof_payload: bytes = b"guest-postcard-proof") -> bytes:
    sections = (b"s", bytes(278), bytes(152), b"c", proof_payload)
    total_bytes = 80 + sum(len(section) for section in sections)
    header = bytearray(80)
    header[:8] = b"STWGPF01"
    struct.pack_into("<HHIQHH", header, 8, 1, 80, 0, total_bytes, 1, 1)
    struct.pack_into("<IIIII", header, 60, *(len(section) for section in sections))
    return bytes(header) + b"".join(sections)


def guest_verifier_receipt(
    plan: dict[str, object],
    artifact: bytes,
    *,
    statement_sha256: str = "4" * 64,
    transcript_state_blake2s: str = "5" * 64,
) -> bytes:
    receipt = {
        "schema": "riscv_guest_poseidon2_verify_v1",
        "status": "verified",
        "artifact_kind": "stwo_riscv_guest_poseidon2_proof",
        "artifact_schema_version": 1,
        "artifact_magic": "STWGPF01",
        "profile_identity": "rv32im-zkvm-poseidon2-v1",
        "profile_version": 1,
        "profile_manifest_sha256": (
            "265df524ca93ba5f240aec9e5ce2f9f616c302850410ee812c220aa3e59fb891"
        ),
        "release_status": "release_gated",
        "security_policy": "secure",
        "statement_sha256": statement_sha256,
        "artifact_bytes": len(artifact),
        "artifact_sha256": hashlib.sha256(artifact).hexdigest(),
        "transcript_state_blake2s": transcript_state_blake2s,
        "implementation_commit": plan["source"]["commit"],
        "implementation_dirty": False,
        "executable_sha256": plan["build"]["executable_sha256"],
    }
    return json.dumps(receipt, separators=(",", ":")).encode("ascii") + b"\n"
