"""Shared receipt fixtures for RISC-V release contract tests."""

import hashlib
import json

from scripts.riscv_release_gate_lib import contract as contract_module
from scripts.riscv_release_gate_lib.contract import (
    BOUNDARIES,
    ELF_CORPUS_BOUNDARIES,
    GENERATED_CORPUS_KEYS,
    IMPLEMENTATION_REPOSITORY,
    ORACLE_REPOSITORY,
    expected_case_result_keys,
    NONEMPTY_RELATION_CASE,
    NONEMPTY_RELATION_ELF_SHA256,
    NONEMPTY_RELATION_GENERATOR,
    NONEMPTY_RELATION_INPUT_SHA256,
    NONEMPTY_RELATION_PUBLIC_FIELDS,
    PINNED_ORACLE,
)


# The gate library is reachable under two module spellings (see contract.py's
# import fallback). Tests must patch the exact policy object the contract holds,
# so expose that one rather than importing a second copy.
air_divergence = contract_module.air_divergence

TEST_COMMIT = "a" * 40
TEST_DIGEST = "b" * 64


def nonempty_relation_case(boundary: str) -> dict[str, object]:
    return {
        "name": NONEMPTY_RELATION_CASE,
        "generator": NONEMPTY_RELATION_GENERATOR,
        "elf_sha256": NONEMPTY_RELATION_ELF_SHA256,
        "input_sha256": NONEMPTY_RELATION_INPUT_SHA256,
        "input_len": 9,
        "proof_admitted": True,
        "evidence_mode": "nonempty_public_input",
        "agree": True,
        "first_divergence": None,
        "component_count": 27,
        "relation_count": 12,
        "observation": (
            "canonical_nonzero_tuple_streams"
            if boundary == "relation_tuples"
            else "all_component_prefixes_and_relation_domains"
        ),
        "rust_sha256": TEST_DIGEST,
        "zig_sha256": TEST_DIGEST,
        "public_data": {
            "agree": True,
            "fields": list(NONEMPTY_RELATION_PUBLIC_FIELDS),
            "mismatches": [],
            "normalized_sha256": TEST_DIGEST,
        },
        "zig_binding": {
            "implementation_commit": TEST_COMMIT,
            "implementation_dirty": False,
            "oracle_commit": PINNED_ORACLE,
            "elf_sha256": NONEMPTY_RELATION_ELF_SHA256,
            "input_sha256": NONEMPTY_RELATION_INPUT_SHA256,
            "witness_layout_sha256": TEST_DIGEST,
            "diagnostic_preprocessed_commitment": TEST_DIGEST,
            "diagnostic_main_commitment": TEST_DIGEST,
            "diagnostic_interaction_commitment": TEST_DIGEST,
        },
        **({
            "public_relation_count": 3,
            "public_memory_sum_nonzero": True,
            "balanced_sum": [0, 0, 0, 0],
        } if boundary == "relation_sums" else {}),
    }


def canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def bind_case_digests(receipt: dict[str, object]) -> None:
    """Rebind every case-result digest to the receipt's current boundary content.

    The producer rebinds as its last step, so a test that mutates a boundary must
    rebind too rather than hand-edit a digest.
    """
    boundaries = receipt["boundaries"]
    digests = {key: TEST_DIGEST for key in receipt["expected_case_result_keys"]}
    for boundary in BOUNDARIES:
        digests[f"{boundary}/aggregate"] = canonical_digest(boundaries[boundary])
        if boundary in ELF_CORPUS_BOUNDARIES:
            digests[f"{boundary}/alu"] = canonical_digest(
                boundaries[boundary]["corpus"][0]
            )
            if boundary in {"relation_tuples", "relation_sums"}:
                digests[f"{boundary}/{NONEMPTY_RELATION_CASE}"] = canonical_digest(
                    boundaries[boundary]["nonempty_public_input"]
                )
        if boundary in GENERATED_CORPUS_KEYS:
            digests[GENERATED_CORPUS_KEYS[boundary]] = digests[f"{boundary}/aggregate"]
    receipt["case_result_digests"] = digests


def valid_receipt(now: int) -> dict[str, object]:
    """Complete, candidate-bound receipt in which every boundary agrees."""
    boundaries = {
        name: {
            "status": "pass",
            **({"corpus": [{"name": "alu", "agree": True}]}
               if name in ELF_CORPUS_BOUNDARIES else {}),
        }
        for name in BOUNDARIES
    }
    for name in ("relation_tuples", "relation_sums"):
        boundaries[name]["corpus"][0].update({
            "proof_admission": {"status": "supported"},
            "proof_admitted": True,
            "evidence_mode": "balanced_full",
        })
        boundaries[name]["nonempty_public_input"] = nonempty_relation_case(name)
    receipt: dict[str, object] = {
        "schema": "riscv-oracle-receipt-v2",
        "candidate_commit": TEST_COMMIT,
        "created_at_unix": now,
        "witness_layout_digest_sha256": TEST_DIGEST,
        "corpus_digest_sha256": TEST_DIGEST,
        "expected_case_result_keys": expected_case_result_keys(("alu",)),
        "verdict": "PASS",
        "oracle": {
            "repository": ORACLE_REPOSITORY,
            "commit": PINNED_ORACLE,
            "clean": True,
            "tree_digest_sha256": TEST_DIGEST,
            "lockfile_sha256": TEST_DIGEST,
            "executable_sha256": TEST_DIGEST,
            "toolchain": "rustc 1.90",
            "build_command": "cargo build --locked --release -p prover",
            "build_mode": "release",
            "host_arch": "aarch64",
            "host_os": "macOS",
            "submodule_status": [],
            "adapter_overlay": {
                "path": "crates/prover/src/bin/cp11_dump.rs",
                "sha256": TEST_DIGEST,
            },
        },
        "implementation": {
            "repository": IMPLEMENTATION_REPOSITORY,
            "commit": TEST_COMMIT,
            "clean": True,
            "executables": {
                "riscv-trace-dump": TEST_DIGEST,
                "stwo-zig": TEST_DIGEST,
            },
        },
        "boundaries": boundaries,
    }
    bind_case_digests(receipt)
    return receipt


def superseded_receipt(now: int, boundary: str, paths: list[str]) -> dict[str, object]:
    """Receipt in which one demoted boundary reports a pinned divergence shape."""
    receipt = valid_receipt(now)
    ordered = sorted(paths)
    target = receipt["boundaries"][boundary]
    target.update({
        "status": air_divergence.SUPERSEDED_STATUS,
        "superseded_by": air_divergence.LEDGER_REFERENCE,
        "divergence_paths": ordered,
        "divergence_shape_sha256": air_divergence.shape_digest(ordered),
        "lineage": {
            "agree": True,
            "comparison": "family set and per-family column names",
        },
    })
    target["corpus"][0].update({"agree": False, "divergence_paths": ordered})
    special = target.get("nonempty_public_input")
    if isinstance(special, dict):
        special.update({
            "agree": False,
            "first_divergence": {"path": ordered[0]},
            "divergence_paths": ordered,
        })
    bind_case_digests(receipt)
    return receipt
