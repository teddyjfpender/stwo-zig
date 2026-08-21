"""Production-shaped base RISC-V V4 artifacts for R-006 tests."""

from __future__ import annotations

import json


def base_artifact(
    proof_payload: bytes = b"verified-pcs-proof", *, backend: str = "cpu"
) -> bytes:
    document = {
        "artifact_kind": "stwo_riscv_proof",
        "schema_version": 4,
        "exchange_mode": "riscv_proof_json_wire_v4",
        "release_status": "release_gated",
        "generator": "zig",
        "air": "sail_rv32im_zkvm_v1",
        "backend": backend,
        "protocol": "secure",
        "source": {"elf_sha256": "1" * 64, "input_sha256": "2" * 64},
        "provenance": {
            "oracle_repository": "fixture-oracle",
            "oracle_commit": "3" * 40,
            "implementation_repository": "fixture-implementation",
            "implementation_commit": "4" * 40,
            "implementation_dirty": False,
            "witness_layout_sha256": "5" * 64,
        },
        "pcs_config": {
            "pow_bits": 16,
            "fri_config": {
                "log_blowup_factor": 1,
                "log_last_layer_degree_bound": 0,
                "n_queries": 193,
                "fold_step": 1,
            },
            "lifting_log_size": None,
        },
        "statement": {},
        "interaction_claim": {},
        "proof_bytes_hex": proof_payload.hex(),
    }
    return json.dumps(document, separators=(",", ":")).encode("ascii") + b"\n"


def base_artifact_payload(artifact: bytes) -> bytes:
    return bytes.fromhex(json.loads(artifact)["proof_bytes_hex"])
