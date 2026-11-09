"""Cross-arm proof, semantic, executable, and platform identity gates."""

from __future__ import annotations

import json
from typing import Any, Callable

from .model import BenchmarkError


def _stable_by_arm(
    samples: list[dict[str, Any]],
    label: str,
    value: Callable[[dict[str, Any]], str],
) -> dict[str, str]:
    grouped: dict[str, set[str]] = {}
    for sample in samples:
        grouped.setdefault(sample["arm"], set()).add(value(sample))
    if any(len(identities) != 1 for identities in grouped.values()):
        raise BenchmarkError(f"CUDA {label} changed within one arm")
    return {
        arm: next(iter(identities))
        for arm, identities in grouped.items()
    }


def validate_proof_identity(
    cold: dict[str, list[dict[str, Any]]],
    sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    samples = [
        sample
        for values in cold.values()
        for sample in values
    ] + [session["raw"] for session in sessions]
    proofs = {
        (
            sample["proof"]["canonical_sha256"],
            sample["proof"]["canonical_bytes"],
        )
        for sample in samples
    }
    if len(proofs) != 1:
        raise BenchmarkError("CUDA proof identity changed across arms or sessions")

    statements = {
        json.dumps(sample["statement"], sort_keys=True)
        for sample in samples
    }
    protocols = {sample["protocol"] for sample in samples}
    devices = {
        json.dumps(sample["device"], sort_keys=True)
        for sample in samples
    }
    if len(statements) != 1 or len(protocols) != 1 or len(devices) != 1:
        raise BenchmarkError(
            "CUDA statement, protocol, or device changed across arms"
        )

    schemas = _stable_by_arm(
        samples,
        "report schema",
        lambda sample: str(sample["report_schema_version"]),
    )
    programs = _stable_by_arm(
        samples,
        "full ProofProgram identity",
        lambda sample: sample["plan"]["program_sha256"],
    )
    identities = _stable_by_arm(
        samples,
        "product identity",
        lambda sample: json.dumps(sample["product_identity"], sort_keys=True),
    )

    current_arms = {
        arm for arm, schema in schemas.items() if schema == "6"
    }
    historical_arms = set(schemas) - current_arms
    if historical_arms - {"baseline"}:
        raise BenchmarkError("historical CUDA schema escaped the baseline arm")
    semantics = _stable_by_arm(
        [sample for sample in samples if sample["arm"] in current_arms],
        "semantic ProofProgram identity",
        lambda sample: sample["semantic_sha256"],
    )
    if len(set(semantics.values())) != 1:
        raise BenchmarkError("CUDA semantic ProofProgram identity changed across arms")

    proof = next(iter(proofs))
    program_values = set(programs.values())
    return {
        "canonical_sha256": proof[0],
        "canonical_bytes": proof[1],
        "program_sha256": (
            next(iter(program_values)) if len(program_values) == 1 else None
        ),
        "program_sha256_by_arm": programs,
        "semantic_sha256": next(iter(semantics.values())),
        "semantic_sha256_by_arm": semantics,
        "semantic_comparison": (
            "canonical_proof_statement_protocol_device"
            if historical_arms
            else "schema_v6_semantic_digest"
        ),
        "report_schema_versions_by_arm": {
            arm: int(schema) for arm, schema in schemas.items()
        },
        "historical_baseline": bool(historical_arms),
        "all_arms_byte_identical": True,
        "statement": json.loads(next(iter(statements))),
        "protocol": next(iter(protocols)),
        "device": json.loads(next(iter(devices))),
        "product_identities": {
            arm: json.loads(identity)
            for arm, identity in identities.items()
        },
    }
