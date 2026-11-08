"""Construction of cross-bound refinement receipt payloads."""

from __future__ import annotations

from dataclasses import dataclass

if __package__:
    from . import riscv_refinement_publication as publication
    from .riscv_refinement_lib import air_program, air_program_contract, codec, render, sail
    from .riscv_refinement_lib.model import FULL_OPCODE_COUNT, Paths, RefinementError
    from .riscv_refinement_receipt_constants import (
        APPROVED_LEAN_AXIOMS,
        MUTATION_THEOREMS,
        NEGATIVE_CONTROLS,
        RECEIPT_CLAIM_BOUNDARY,
        RECEIPT_SCHEMA_VERSION,
        RECEIPT_TIER,
    )
    from .riscv_refinement_receipt_identity import (
        _certificate_index_identities,
        _fixed_table_schemas,
        _generated_manifest_identity,
        _opcode_mutations,
        _payload_identity,
        _sha256_identity,
        _team_a_proof_time_diagnostics,
        _toolchain,
        _validate_certificate_mappings,
    )
    from .riscv_refinement_receipt_validate import (
        _validate_receipt_structure,
        _validate_receipt_theorem_axioms,
    )
else:
    import riscv_refinement_publication as publication
    from riscv_refinement_lib import air_program, air_program_contract, codec, render, sail
    from riscv_refinement_lib.model import FULL_OPCODE_COUNT, Paths, RefinementError
    from riscv_refinement_receipt_constants import (
        APPROVED_LEAN_AXIOMS,
        MUTATION_THEOREMS,
        NEGATIVE_CONTROLS,
        RECEIPT_CLAIM_BOUNDARY,
        RECEIPT_SCHEMA_VERSION,
        RECEIPT_TIER,
    )
    from riscv_refinement_receipt_identity import (
        _certificate_index_identities,
        _fixed_table_schemas,
        _generated_manifest_identity,
        _opcode_mutations,
        _payload_identity,
        _sha256_identity,
        _team_a_proof_time_diagnostics,
        _toolchain,
        _validate_certificate_mappings,
    )
    from riscv_refinement_receipt_validate import (
        _validate_receipt_structure,
        _validate_receipt_theorem_axioms,
    )
@dataclass(frozen=True)
class Verification:
    theorem_axioms: dict[str, list[str]]


def _production_inputs(
    paths: Paths,
    mappings: list[dict[str, object]],
    manifest: dict[str, object],
) -> dict[str, object]:
    render.validate_air_export(paths.uniqueness_ir)
    unsigned_programs = render.validate_air_program_export(
        paths.air_program_ir
    )
    family_exports = []
    for family in sorted(air_program_contract.FAMILIES):
        artifact = paths.uniqueness_ir / f"{family}.json"
        family_exports.append(
            {
                "family": family,
                "artifact": f"fresh-family-air/{family}.json",
                "sha256": codec.sha256_file(artifact),
            }
        )
    programs = []
    by_mnemonic = {
        mapping["mnemonic"]: mapping for mapping in mappings
    }
    for manifest_id, mnemonic, family in air_program_contract.OPCODES:
        unsigned = unsigned_programs[mnemonic]
        packaged_path = (
            paths.generated_air / f"{mnemonic}.air-ir-v2.json"
        )
        packaged = air_program.load_canonical(packaged_path)
        air_program.verify_production_binding(
            packaged,
            unsigned,
            paths.root,
        )
        source_identity = packaged.get("source_identity")
        if (
            packaged.get("content_digest")
            != by_mnemonic[mnemonic]["air_digest"]
            or not isinstance(source_identity, dict)
        ):
            raise RefinementError(
                f"receipt AIR program binding drifted for {mnemonic}"
            )
        source_closure = _sha256_identity(
            source_identity.get("source_closure_sha256"),
            f"{mnemonic} AIR source closure",
        )
        programs.append(
            {
                "manifest_id": manifest_id,
                "mnemonic": mnemonic,
                "family": family,
                "content_digest": packaged["content_digest"],
                "source_closure_sha256": source_closure,
                "unsigned_sha256": codec.sha256_file(
                    paths.air_program_ir
                    / f"{mnemonic}.unsigned.json"
                ),
                "packaged_artifact": packaged_path.relative_to(
                    paths.root
                ).as_posix(),
                "packaged_sha256": codec.sha256_file(packaged_path),
            }
        )
    production_sources = manifest.get("production_sources")
    if (
        not isinstance(production_sources, dict)
        or not production_sources
        or any(
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or air_program_contract.HEX_SHA256.fullmatch(digest) is None
            for relative, digest in production_sources.items()
        )
    ):
        raise RefinementError(
            "generated manifest production source closure is invalid"
        )
    opcode_manifest_path = (
        paths.root / "src/frontends/riscv/opcode_manifest.zig"
    )
    return {
        "opcode_manifest": {
            "artifact": "src/frontends/riscv/opcode_manifest.zig",
            "sha256": codec.sha256_file(opcode_manifest_path),
        },
        "source_closure": {
            "canonical_digest": codec.sha256_bytes(
                codec.canonical_bytes(production_sources)
            ),
            "files": production_sources,
        },
        "family_air_exports": family_exports,
        "opcode_air_programs": programs,
    }


def _sail_inputs(
    paths: Paths,
    sail_evidence: sail.SailEvidence,
) -> dict[str, object]:
    provenance = sail.provenance(sail_evidence)
    if sail_evidence.evidence_source != sail.LIVE_EVIDENCE:
        raise RefinementError(
            "release receipt Sail inputs require live-toolchain evidence"
        )
    generated = sail_evidence.generated_file
    if (
        generated is None
        or generated.is_symlink()
        or not generated.is_file()
        or codec.sha256_file(generated)
        != sail_evidence.generated_file_sha256
    ):
        raise RefinementError(
            "live generated Sail backend identity is invalid"
        )
    exact_configuration_path = (
        paths.formal / sail.COMMITTED_CONFIGURATION
    )
    if (
        exact_configuration_path.is_symlink()
        or not exact_configuration_path.is_file()
        or exact_configuration_path.read_bytes()
        != sail_evidence.exact_configuration
    ):
        raise RefinementError(
            "committed exact Sail configuration differs from live evidence"
        )
    definitions = []
    for name, relative in sorted(sail.COMMITTED_DEFINITIONS.items()):
        artifact = paths.formal / relative
        digest = _sha256_identity(
            sail_evidence.definition_hashes.get(name),
            f"{name} generated definition",
        )
        if (
            artifact.is_symlink()
            or not artifact.is_file()
            or codec.sha256_file(artifact) != digest
        ):
            raise RefinementError(
                f"generated Sail definition identity drifted: {name}"
            )
        definitions.append(
            {
                "name": name,
                "artifact": artifact.relative_to(paths.root).as_posix(),
                "sha256": digest,
            }
        )
    translation = _payload_identity(
        paths,
        (
            paths.formal / sail.COMMITTED_TRANSLATION_RECEIPT
        ).relative_to(paths.root),
        expected_schema="stwo-sail-translation-receipt-v1",
        expected_payload=sail_evidence.translation_receipt,
    )
    monad_bridge = _payload_identity(
        paths,
        (
            paths.formal / sail.COMMITTED_MONAD_BRIDGE_RECEIPT
        ).relative_to(paths.root),
        expected_kind="stwo-generated-sail-monad-bridge",
        expected_schema="stwo-generated-sail-monad-bridge-v1",
        expected_payload=sail_evidence.monad_bridge_receipt,
    )
    return {
        "provenance": provenance,
        "provenance_digest": codec.sha256_bytes(
            codec.canonical_bytes(provenance)
        ),
        "generated_backend": {
            "artifact": sail.GENERATED_FILE.as_posix(),
            "sha256": sail_evidence.generated_file_sha256,
            "size_bytes": generated.stat().st_size,
        },
        "exact_configuration": {
            "artifact": exact_configuration_path.relative_to(
                paths.root
            ).as_posix(),
            "sha256": sail_evidence.exact_configuration_sha256,
        },
        "generated_definitions": definitions,
        "translation_receipt": translation,
        "monad_bridge_receipt": monad_bridge,
    }


def _theorem_axiom_index(
    theorem_axioms: dict[str, list[str]],
) -> dict[str, object]:
    _validate_receipt_theorem_axioms(theorem_axioms)
    return {
        "canonical_digest": codec.sha256_bytes(
            codec.canonical_bytes(theorem_axioms)
        ),
        "theorem_count": len(theorem_axioms),
        "axiom_occurrence_count": sum(
            len(axioms) for axioms in theorem_axioms.values()
        ),
        "entries": theorem_axioms,
    }


def _build_receipt_payload(
    paths: Paths,
    verification: Verification,
    sail_evidence: sail.SailEvidence,
    repository_revision: str,
) -> dict[str, object]:
    generated_manifest = _generated_manifest_identity(paths)
    coverage_indexes = _certificate_index_identities(paths)
    aggregate_payload = coverage_indexes["aggregate"]["payload"]
    mappings = _validate_certificate_mappings(
        aggregate_payload["certificates"],
        coverage_indexes,
    )
    if aggregate_payload.get("claim_boundary") != {
        "exact_manifest_partition": True,
        "production_air_programs": FULL_OPCODE_COUNT,
        "team_a_exact_air_refinements": 24,
        "team_a_axiom_bound_certificates": 24,
        "team_a_timed_certificates": 24,
        "team_b_reviewed_capsule_refinements": 22,
        "generated_sail_clause_bindings": 24,
        "generated_sail_retirement_bindings": 24,
        "generated_sail_input_only_bindings": 0,
        "reviewed_sail_capsule_bindings": 22,
        "unbound_sail_selectors": 0,
        "publication_level_opcodes": 0,
        "whole_frontend_verified": False,
    }:
        raise RefinementError(
            "aggregate coverage claim boundary is not the exact "
            "FV-1/FV-2 source-certificate boundary"
        )
    payload: dict[str, object] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": "stwo-riscv-refinement-receipt",
        "tier": RECEIPT_TIER,
        "claim_boundary": RECEIPT_CLAIM_BOUNDARY,
        "repository_revision": repository_revision,
        "repository_dirty": False,
        "repository_dirty_paths": [],
        "generated_manifest": generated_manifest,
        "coverage_indexes": coverage_indexes,
        "certificate_mappings": mappings,
        "fixed_table_schemas": _fixed_table_schemas(),
        "production_inputs": _production_inputs(
            paths,
            mappings,
            generated_manifest["payload"],
        ),
        "publication_evidence": publication.build_publication_evidence(
            paths,
            sail_evidence.monad_bridge_receipt,
            verification.theorem_axioms,
        ),
        "sail_inputs": _sail_inputs(paths, sail_evidence),
        "opcode_mutations": _opcode_mutations(mappings),
        "team_a_proof_time_diagnostics":
            _team_a_proof_time_diagnostics(mappings),
        "negative_controls": list(NEGATIVE_CONTROLS),
        "pilot_mutation_theorems": MUTATION_THEOREMS,
        "approved_lean_axioms": sorted(APPROVED_LEAN_AXIOMS),
        "theorem_axiom_index": _theorem_axiom_index(
            verification.theorem_axioms
        ),
        "lean_build": "passed",
        "proof_escape_scan": "passed",
        "toolchain": _toolchain(paths),
        "semantic_toolchain": sail.toolchain(sail_evidence),
    }
    payload["canonical_digest"] = codec.content_digest(payload)
    _validate_receipt_structure(payload)
    return payload
