#!/usr/bin/env python3
"""Generate and check the exact 46-entry RISC-V proof certificate index.

The aggregate preserves evidence grades.  Team A entries are bound directly
to generated per-selector ``ConstraintProgram`` values; Team B entries retain
their reviewed family-capsule AIR and Sail boundary.  Neither grade is silently
promoted to publication-level or whole-frontend verification.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

try:
    from . import riscv_team_a as team_a
    from . import riscv_team_b as team_b
except ImportError:
    import riscv_team_a as team_a
    import riscv_team_b as team_b


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
INDEX_PATH = (
    REPOSITORY_ROOT / "formal/riscv-refinement/opcode-coverage.json"
)
AIR_PROGRAM_ROOT = (
    REPOSITORY_ROOT / "formal/riscv-refinement/generated/air"
)
FULL_OPCODE_COUNT = 46


class CoverageError(RuntimeError):
    """An aggregate certificate failure."""


def _air_digest(mnemonic: str) -> str:
    path = AIR_PROGRAM_ROOT / f"{mnemonic}.air-ir-v2.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoverageError(
            f"production AIR program for {mnemonic} is unreadable"
        ) from exc
    digest = payload.get("content_digest")
    if not isinstance(digest, str):
        raise CoverageError(
            f"production AIR program for {mnemonic} has no digest"
        )
    return digest


def _team_b_certificates() -> dict[str, dict[str, Any]]:
    try:
        team_b.check_coverage()
        payload = team_b.load_certificates()
    except team_b.TeamBError as exc:
        raise CoverageError(str(exc)) from exc
    return {
        certificate["mnemonic"]: certificate
        for certificate in payload["certificates"]
    }


def _team_a_certificates() -> dict[str, dict[str, Any]]:
    try:
        team_a.check_coverage()
        team_a.check_air_programs()
        payload = team_a.load_certificates()
    except team_a.TeamAError as exc:
        raise CoverageError(str(exc)) from exc
    return {
        certificate["mnemonic"]: certificate
        for certificate in payload["certificates"]
    }


def build_index() -> dict[str, Any]:
    a_certificates = _team_a_certificates()
    b_certificates = _team_b_certificates()
    manifest = team_a.manifest_opcodes()
    if len(manifest) != FULL_OPCODE_COUNT:
        raise CoverageError("production opcode manifest is not 46 entries")
    if set(a_certificates) & set(b_certificates):
        raise CoverageError("Team A and Team B certificate sets overlap")
    if set(a_certificates) | set(b_certificates) != {
        mnemonic for mnemonic, _, _ in manifest
    }:
        raise CoverageError("Team A and Team B certificates do not partition 46")

    certificates: list[dict[str, Any]] = []
    for mnemonic, family, manifest_id in manifest:
        if mnemonic in a_certificates:
            source = a_certificates[mnemonic]
            team = "A"
            air_binding = "exact-generated-local-program"
            selector_theorem = source["selector_theorem"]
        else:
            source = b_certificates[mnemonic]
            team = "B"
            air_binding = "reviewed-family-capsule"
            selector_theorem = None
        entry = {
            "air_binding": air_binding,
            "air_digest": _air_digest(mnemonic),
            "axioms": source.get("axioms"),
            "family": family,
            "manifest_id": manifest_id,
            "mnemonic": mnemonic,
            "mutation": source.get("mutation"),
            "mutation_theorem": source.get("mutation_theorem"),
            "non_vacuity_theorem": source.get("non_vacuity_theorem"),
            "refinement_theorem": source.get("refinement_theorem"),
            "sail_binding": source.get(
                "sail_binding",
                team_b.DEFAULT_SAIL_BINDING,
            ),
            "selector_theorem": selector_theorem,
            "state": source.get("state"),
            "team": team,
            "proof_time_ms": source.get("proof_time_ms"),
            "tuple_theorem": source.get("tuple_theorem"),
        }
        if source.get("sail_receipt"):
            entry["sail_receipt"] = source["sail_receipt"]
        if source.get("sail_artifact"):
            entry["sail_artifact"] = source["sail_artifact"]
        if source.get("sail_digest"):
            entry["sail_digest"] = source["sail_digest"]
        if source.get("sail_theorem"):
            entry["sail_theorem"] = source["sail_theorem"]
        certificates.append(entry)

    generated_sail_inputs = sum(
        certificate["sail_binding"]
        in ("generated-clause-input", "generated-retirement")
        for certificate in certificates
    )
    generated_sail_retirements = sum(
        certificate["sail_binding"] == "generated-retirement"
        for certificate in certificates
    )
    reviewed_sail = sum(
        certificate["sail_binding"] == "reviewed-capsule"
        for certificate in certificates
    )
    unbound_sail = sum(
        certificate["sail_binding"] == "unbound"
        for certificate in certificates
    )
    generated_sail_input_only = (
        generated_sail_inputs - generated_sail_retirements
    )
    if (
        generated_sail_input_only
        + generated_sail_retirements
        + reviewed_sail
        + unbound_sail
        != FULL_OPCODE_COUNT
    ):
        raise CoverageError("aggregate Sail evidence grades do not partition 46")
    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "stwo-riscv-opcode-coverage",
        "claim_boundary": {
            "exact_manifest_partition": True,
            "production_air_programs": FULL_OPCODE_COUNT,
            "team_a_exact_air_refinements": len(a_certificates),
            "team_a_axiom_bound_certificates": len(a_certificates),
            "team_a_timed_certificates": len(a_certificates),
            "team_b_reviewed_capsule_refinements": len(b_certificates),
            "generated_sail_clause_bindings": generated_sail_inputs,
            "generated_sail_retirement_bindings":
                generated_sail_retirements,
            "generated_sail_input_only_bindings":
                generated_sail_input_only,
            "reviewed_sail_capsule_bindings": reviewed_sail,
            "unbound_sail_selectors": unbound_sail,
            "publication_level_opcodes": 0,
            "whole_frontend_verified": False,
        },
        "source_indexes": {
            "team_a": team_a.load_certificates()["canonical_digest"],
            "team_b": team_b.load_certificates()["canonical_digest"],
        },
        "certificates": certificates,
    }
    payload["canonical_digest"] = team_b.canonical_digest(payload)
    return payload


def check_index() -> str:
    expected = build_index()
    try:
        actual = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoverageError(
            f"aggregate opcode index is unreadable at {INDEX_PATH}"
        ) from exc
    if actual.get("canonical_digest") != team_b.canonical_digest(actual):
        raise CoverageError("aggregate opcode index digest mismatch")
    if actual != expected:
        raise CoverageError(
            "aggregate opcode index drifted; regenerate with "
            "`python3 scripts/riscv_opcode_coverage.py write`"
        )
    return (
        "aggregate opcode coverage: exact 46/46 manifest partition; "
        f"{expected['claim_boundary']['generated_sail_clause_bindings']}/46 "
        "generated-Sail clause bindings; "
        f"{expected['claim_boundary']['generated_sail_retirement_bindings']}"
        "/46 normalized retirements; 0/46 publication-level"
    )


def write_index() -> str:
    payload = build_index()
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
        + "\n"
    )
    temporary = INDEX_PATH.with_suffix(".json.tmp")
    temporary.write_text(encoded, encoding="utf-8")
    temporary.replace(INDEX_PATH)
    return (
        f"wrote {len(payload['certificates'])} opcode certificates to "
        f"{INDEX_PATH.relative_to(REPOSITORY_ROOT)}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "write"))
    args = parser.parse_args(argv)
    try:
        print(write_index() if args.command == "write" else check_index())
    except CoverageError as exc:
        print(f"aggregate coverage gate failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
