"""Fail-closed structural validation for refinement receipts."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

if __package__:
    from . import riscv_refinement_publication as publication
    from .riscv_refinement_lib import air_program_contract, codec, render, sail
    from .riscv_refinement_lib.audited_inventory import AUDITED_THEOREMS
    from .riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
    )
    from .riscv_refinement_receipt_constants import (
        APPROVED_LEAN_AXIOMS,
        MUTATION_THEOREMS,
        NEGATIVE_CONTROLS,
        OPCODE_INDEX_RELATIVE,
        RECEIPT_CLAIM_BOUNDARY,
        RECEIPT_SCHEMA_VERSION,
        RECEIPT_TIER,
        TEAM_A_INDEX_RELATIVE,
        TEAM_B_INDEX_RELATIVE,
    )
    from .riscv_refinement_receipt_identity import (
        _fixed_table_schemas,
        _opcode_mutations,
        _payload_identity,
        _repository_state,
        _sha256_identity,
        _strict_identity,
        _team_a_proof_time_diagnostics,
        _validate_certificate_mappings,
        _validate_payload_identity,
    )
else:
    import riscv_refinement_publication as publication
    from riscv_refinement_lib import air_program_contract, codec, render, sail
    from riscv_refinement_lib.audited_inventory import AUDITED_THEOREMS
    from riscv_refinement_lib.model import (
        FULL_OPCODE_COUNT,
        SCHEMA_VERSION,
        Paths,
        RefinementError,
    )
    from riscv_refinement_receipt_constants import (
        APPROVED_LEAN_AXIOMS,
        MUTATION_THEOREMS,
        NEGATIVE_CONTROLS,
        OPCODE_INDEX_RELATIVE,
        RECEIPT_CLAIM_BOUNDARY,
        RECEIPT_SCHEMA_VERSION,
        RECEIPT_TIER,
        TEAM_A_INDEX_RELATIVE,
        TEAM_B_INDEX_RELATIVE,
    )
    from riscv_refinement_receipt_identity import (
        _fixed_table_schemas,
        _opcode_mutations,
        _payload_identity,
        _repository_state,
        _sha256_identity,
        _strict_identity,
        _team_a_proof_time_diagnostics,
        _validate_certificate_mappings,
        _validate_payload_identity,
    )

def _receipt_revision_matches(paths: Paths, revision: str) -> None:
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise RefinementError("refinement receipt repository revision is invalid")
    current, dirty_paths = _repository_state(paths)
    if dirty_paths:
        raise RefinementError(
            "receipt verification requires a clean repository; dirty paths: "
            + ", ".join(dirty_paths)
        )
    if current == revision:
        return
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", revision, current],
            cwd=paths.root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        unchanged = subprocess.run(
            [
                "git",
                "diff",
                "--quiet",
                revision,
                current,
                "--",
                ".",
                f":(exclude){paths.receipt.relative_to(paths.root).as_posix()}",
            ],
            cwd=paths.root,
            check=False,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RefinementError(
            "could not validate refinement receipt repository revision"
        ) from exc
    if unchanged.returncode != 0:
        raise RefinementError(
            "repository changed beyond the committed refinement receipt"
        )


def _validate_receipt_theorem_axioms(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != set(AUDITED_THEOREMS)
    ):
        raise RefinementError("refinement receipt theorem set is invalid")
    for theorem, axioms in value.items():
        if (
            not isinstance(theorem, str)
            or not isinstance(axioms, list)
            or any(not isinstance(axiom, str) for axiom in axioms)
            or axioms != sorted(set(axioms))
            or not set(axioms) <= APPROVED_LEAN_AXIOMS
        ):
            raise RefinementError(
                "refinement receipt theorem-axiom schema is invalid"
            )


def _validate_receipt_numeric_identity(payload: dict[str, object]) -> None:
    if (
        type(payload.get("schema_version")) is not int
        or payload["schema_version"] != RECEIPT_SCHEMA_VERSION
        or not _strict_identity(
            payload.get("claim_boundary"),
            RECEIPT_CLAIM_BOUNDARY,
        )
    ):
        raise RefinementError(
            "refinement receipt numeric identity is invalid"
        )


def _validate_theorem_axiom_index(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "axiom_occurrence_count",
            "canonical_digest",
            "entries",
            "theorem_count",
        }
    ):
        raise RefinementError(
            "refinement receipt theorem/axiom index schema is invalid"
        )
    entries = value["entries"]
    _validate_receipt_theorem_axioms(entries)
    if (
        type(value["theorem_count"]) is not int
        or value["theorem_count"] != len(entries)
        or type(value["axiom_occurrence_count"]) is not int
        or value["axiom_occurrence_count"]
        != sum(len(axioms) for axioms in entries.values())
        or value["canonical_digest"]
        != codec.sha256_bytes(codec.canonical_bytes(entries))
    ):
        raise RefinementError(
            "refinement receipt theorem/axiom index identity is invalid"
        )


def _validate_production_inputs(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "family_air_exports",
            "opcode_air_programs",
            "opcode_manifest",
            "source_closure",
        }
    ):
        raise RefinementError(
            "refinement receipt production input schema is invalid"
        )
    opcode_manifest_value = value["opcode_manifest"]
    if (
        not isinstance(opcode_manifest_value, dict)
        or set(opcode_manifest_value) != {"artifact", "sha256"}
        or opcode_manifest_value["artifact"]
        != "src/frontends/riscv/opcode_manifest.zig"
    ):
        raise RefinementError(
            "refinement receipt opcode manifest identity is invalid"
        )
    _sha256_identity(
        opcode_manifest_value.get("sha256"),
        "receipt opcode manifest",
    )
    source_closure = value["source_closure"]
    if (
        not isinstance(source_closure, dict)
        or set(source_closure) != {"canonical_digest", "files"}
        or not isinstance(source_closure["files"], dict)
        or not source_closure["files"]
        or source_closure["canonical_digest"]
        != codec.sha256_bytes(
            codec.canonical_bytes(source_closure["files"])
        )
    ):
        raise RefinementError(
            "refinement receipt production source closure is invalid"
        )
    for relative, digest in source_closure["files"].items():
        if not isinstance(relative, str) or not relative:
            raise RefinementError(
                "refinement receipt production source path is invalid"
            )
        _sha256_identity(digest, f"production source {relative}")
    family_exports = value["family_air_exports"]
    expected_families = sorted(air_program_contract.FAMILIES)
    if (
        not isinstance(family_exports, list)
        or len(family_exports) != len(expected_families)
    ):
        raise RefinementError(
            "refinement receipt family AIR inventory is incomplete"
        )
    for family, identity in zip(expected_families, family_exports):
        if (
            not isinstance(identity, dict)
            or set(identity) != {"artifact", "family", "sha256"}
            or identity.get("family") != family
            or identity.get("artifact")
            != f"fresh-family-air/{family}.json"
        ):
            raise RefinementError(
                f"refinement receipt family AIR identity drifted: {family}"
            )
        _sha256_identity(identity.get("sha256"), f"{family} AIR export")
    programs = value["opcode_air_programs"]
    if not isinstance(programs, list) or len(programs) != FULL_OPCODE_COUNT:
        raise RefinementError(
            "refinement receipt opcode AIR inventory is incomplete"
        )
    required = {
        "content_digest",
        "family",
        "manifest_id",
        "mnemonic",
        "packaged_artifact",
        "packaged_sha256",
        "source_closure_sha256",
        "unsigned_sha256",
    }
    for expected, identity in zip(
        air_program_contract.OPCODES,
        programs,
    ):
        manifest_id, mnemonic, family = expected
        if (
            not isinstance(identity, dict)
            or set(identity) != required
            or type(identity.get("manifest_id")) is not int
            or identity["manifest_id"] != manifest_id
            or identity.get("mnemonic") != mnemonic
            or identity.get("family") != family
            or identity.get("packaged_artifact")
            != (
                "formal/riscv-refinement/generated/air/"
                f"{mnemonic}.air-ir-v2.json"
            )
        ):
            raise RefinementError(
                f"refinement receipt opcode AIR identity drifted: {mnemonic}"
            )
        for field in (
            "content_digest",
            "packaged_sha256",
            "source_closure_sha256",
            "unsigned_sha256",
        ):
            _sha256_identity(
                identity.get(field),
                f"{mnemonic} {field}",
            )


def _validate_production_certificate_bindings(
    production_inputs: object,
    mappings: list[dict[str, object]],
) -> None:
    if not isinstance(production_inputs, dict):
        raise RefinementError(
            "refinement receipt production inputs cannot bind certificates"
        )
    programs = production_inputs.get("opcode_air_programs")
    if (
        not isinstance(programs, list)
        or len(programs) != len(mappings)
    ):
        raise RefinementError(
            "refinement receipt production/certificate inventory drifted"
        )
    for mapping, program in zip(mappings, programs):
        mnemonic = mapping["mnemonic"]
        if (
            not isinstance(program, dict)
            or program.get("manifest_id") != mapping["manifest_id"]
            or program.get("mnemonic") != mnemonic
            or program.get("family") != mapping["family"]
            or program.get("content_digest") != mapping["air_digest"]
        ):
            raise RefinementError(
                "refinement receipt production AIR digest differs from "
                f"certificate mapping for {mnemonic}"
            )


def _validate_sail_inputs(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "exact_configuration",
            "generated_backend",
            "generated_definitions",
            "monad_bridge_receipt",
            "provenance",
            "provenance_digest",
            "translation_receipt",
        }
    ):
        raise RefinementError(
            "refinement receipt Sail input schema is invalid"
        )
    provenance = value["provenance"]
    if (
        not isinstance(provenance, dict)
        or provenance.get("evidence_source") != sail.LIVE_EVIDENCE
        or value["provenance_digest"]
        != codec.sha256_bytes(codec.canonical_bytes(provenance))
    ):
        raise RefinementError(
            "refinement receipt Sail provenance identity is invalid"
        )
    backend = value["generated_backend"]
    if (
        not isinstance(backend, dict)
        or set(backend) != {"artifact", "sha256", "size_bytes"}
        or backend.get("artifact") != sail.GENERATED_FILE.as_posix()
        or type(backend.get("size_bytes")) is not int
        or backend["size_bytes"] <= 0
    ):
        raise RefinementError(
            "refinement receipt generated Sail backend identity is invalid"
        )
    _sha256_identity(backend.get("sha256"), "generated Sail backend")
    configuration = value["exact_configuration"]
    if (
        not isinstance(configuration, dict)
        or set(configuration) != {"artifact", "sha256"}
        or configuration.get("artifact")
        != (
            "formal/riscv-refinement/"
            + sail.COMMITTED_CONFIGURATION.as_posix()
        )
    ):
        raise RefinementError(
            "refinement receipt exact Sail configuration is invalid"
        )
    _sha256_identity(
        configuration.get("sha256"),
        "exact Sail configuration",
    )
    definitions = value["generated_definitions"]
    expected_definitions = sorted(sail.COMMITTED_DEFINITIONS)
    if (
        not isinstance(definitions, list)
        or len(definitions) != len(expected_definitions)
    ):
        raise RefinementError(
            "refinement receipt generated Sail definitions are incomplete"
        )
    for name, identity in zip(expected_definitions, definitions):
        relative = sail.COMMITTED_DEFINITIONS[name]
        if (
            not isinstance(identity, dict)
            or set(identity) != {"artifact", "name", "sha256"}
            or identity.get("name") != name
            or identity.get("artifact")
            != f"formal/riscv-refinement/{relative.as_posix()}"
        ):
            raise RefinementError(
                f"refinement receipt generated Sail definition drifted: {name}"
            )
        _sha256_identity(identity.get("sha256"), f"{name} definition")
    definition_hashes = {
        identity["name"]: identity["sha256"]
        for identity in definitions
    }
    if not _strict_identity(
        provenance.get("generated_definition_sha256"),
        definition_hashes,
    ):
        raise RefinementError(
            "refinement receipt generated Sail definitions do not "
            "cross-bind to provenance"
        )
    _validate_payload_identity(
        value["translation_receipt"],
        "Sail translation receipt",
    )
    _validate_payload_identity(
        value["monad_bridge_receipt"],
        "Sail monad bridge receipt",
    )
    translation = value["translation_receipt"]
    monad = value["monad_bridge_receipt"]
    translation_provenance = provenance.get(
        "generated_ast_translation_receipt"
    )
    monad_provenance = provenance.get(
        "generated_monad_bridge_receipt"
    )
    if (
        translation["payload"].get("schema_version")
        != "stwo-sail-translation-receipt-v1"
        or translation.get("artifact")
        != (
            "formal/riscv-refinement/"
            + sail.COMMITTED_TRANSLATION_RECEIPT.as_posix()
        )
        or monad["payload"].get("schema_version")
        != "stwo-generated-sail-monad-bridge-v1"
        or monad["payload"].get("kind")
        != "stwo-generated-sail-monad-bridge"
        or monad.get("artifact")
        != (
            "formal/riscv-refinement/"
            + sail.COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()
        )
        or provenance.get("generated_backend_file_sha256")
        != backend["sha256"]
        or provenance.get("exact_configuration_sha256")
        != configuration["sha256"]
        or not isinstance(translation_provenance, dict)
        or translation_provenance.get("canonical_digest")
        != translation["canonical_digest"]
        or not isinstance(monad_provenance, dict)
        or monad_provenance.get("canonical_digest")
        != monad["canonical_digest"]
    ):
        raise RefinementError(
            "refinement receipt Sail inputs do not cross-bind"
        )


def _validate_certificate_sail_bindings(
    sail_inputs: object,
    mappings: list[dict[str, object]],
) -> None:
    if not isinstance(sail_inputs, dict):
        raise RefinementError(
            "refinement receipt Sail inputs cannot bind certificates"
        )
    monad = sail_inputs.get("monad_bridge_receipt")
    if not isinstance(monad, dict):
        raise RefinementError(
            "refinement receipt has no monad bridge certificate binding"
        )
    payload = monad.get("payload")
    theorems = payload.get("theorems") if isinstance(payload, dict) else None
    if (
        not isinstance(theorems, list)
        or any(not isinstance(theorem, str) for theorem in theorems)
    ):
        raise RefinementError(
            "refinement receipt monad bridge theorem inventory is invalid"
        )
    for mapping in mappings:
        if mapping["team"] != "A":
            continue
        mnemonic = mapping["mnemonic"]
        if (
            mapping.get("sail_receipt") != monad.get("artifact")
            or mapping.get("sail_digest") != monad.get("canonical_digest")
            or mapping.get("sail_theorem") not in theorems
        ):
            raise RefinementError(
                "refinement receipt generated Sail metadata differs from "
                f"the monad bridge for {mnemonic}"
            )


def _validate_publication_bindings(
    value: object,
    production_inputs: object,
    sail_inputs: object,
    theorem_axiom_index: object,
) -> None:
    publication.validate_publication_evidence(value)
    if (
        not isinstance(value, dict)
        or not isinstance(production_inputs, dict)
        or not isinstance(sail_inputs, dict)
        or not isinstance(theorem_axiom_index, dict)
    ):
        raise RefinementError(
            "publication evidence cannot bind the receipt inputs"
        )
    entries = value["entries"]
    production_programs = production_inputs.get("opcode_air_programs")
    theorem_entries = theorem_axiom_index.get("entries")
    monad_identity = sail_inputs.get("monad_bridge_receipt")
    monad = (
        monad_identity.get("payload")
        if isinstance(monad_identity, dict)
        else None
    )
    source_identities = (
        monad.get("selector_source_digests")
        if isinstance(monad, dict)
        else None
    )
    monad_axioms = (
        monad.get("theorem_axioms")
        if isinstance(monad, dict)
        else None
    )
    if (
        not isinstance(production_programs, list)
        or not isinstance(theorem_entries, dict)
        or not isinstance(source_identities, list)
        or not isinstance(monad_axioms, dict)
        or len(entries) != len(production_programs)
        or len(entries) != len(source_identities)
    ):
        raise RefinementError(
            "publication evidence input inventory is incomplete"
        )
    for universal in value["universal_theorems"]:
        if universal not in theorem_entries:
            raise RefinementError(
                f"publication local theorem is not audited: {universal}"
            )
    for entry, program, source_identity in zip(
        entries,
        production_programs,
        source_identities,
    ):
        selector = entry["mnemonic"].upper()
        if (
            not isinstance(program, dict)
            or entry["manifest_id"] != program.get("manifest_id")
            or entry["mnemonic"] != program.get("mnemonic")
            or entry["family"] != program.get("family")
            or entry["production_air_digest"]
            != program.get("content_digest")
            or not isinstance(source_identity, dict)
            or source_identity.get("selector") != selector
            or source_identity.get("sha256")
            != entry["generated_sail_source_digest"]
        ):
            raise RefinementError(
                f"publication input binding drifted for {selector}"
            )
        for field in (
            "tuple_theorem",
            "non_vacuity_theorem",
            "mutation_theorem",
        ):
            if entry[field] not in theorem_entries:
                raise RefinementError(
                    f"publication retained theorem is not audited: "
                    f"{entry[field]}"
                )
        for field in (
            "generated_sail_retirement_theorem",
            "accepted_air_refinement_theorem",
        ):
            theorem = entry[field]
            if (
                theorem not in monad_axioms
                or monad_axioms[theorem]
                != value["generated_sail_theorem_axioms"].get(theorem)
            ):
                raise RefinementError(
                    f"publication Sail theorem is not cross-bound: {theorem}"
                )
    for boundary, label in (
        (value["full_step_theorem"], "full-step"),
        (
            value["cross_project_contract_theorem"],
            "cross-project contract",
        ),
    ):
        if (
            boundary not in monad_axioms
            or monad_axioms[boundary]
            != value["generated_sail_theorem_axioms"].get(boundary)
        ):
            raise RefinementError(
                f"publication {label} theorem is not cross-bound"
            )


def _validate_receipt_structure(payload: dict[str, object]) -> None:
    required = {
        "approved_lean_axioms",
        "canonical_digest",
        "certificate_mappings",
        "claim_boundary",
        "coverage_indexes",
        "fixed_table_schemas",
        "generated_manifest",
        "kind",
        "lean_build",
        "negative_controls",
        "opcode_mutations",
        "pilot_mutation_theorems",
        "production_inputs",
        "publication_evidence",
        "proof_escape_scan",
        "repository_dirty",
        "repository_dirty_paths",
        "repository_revision",
        "sail_inputs",
        "schema_version",
        "semantic_toolchain",
        "team_a_proof_time_diagnostics",
        "theorem_axiom_index",
        "tier",
        "toolchain",
    }
    if set(payload) != required:
        raise RefinementError("refinement receipt schema drifted")
    _validate_receipt_numeric_identity(payload)
    if (
        payload.get("kind") != "stwo-riscv-refinement-receipt"
        or payload.get("tier") != RECEIPT_TIER
        or payload.get("canonical_digest") != codec.content_digest(payload)
        or payload.get("negative_controls") != list(NEGATIVE_CONTROLS)
        or payload.get("pilot_mutation_theorems") != MUTATION_THEOREMS
        or payload.get("lean_build") != "passed"
        or payload.get("proof_escape_scan") != "passed"
        or payload.get("repository_dirty") is not False
        or payload.get("repository_dirty_paths") != []
        or payload.get("approved_lean_axioms")
        != sorted(APPROVED_LEAN_AXIOMS)
        or not isinstance(payload.get("toolchain"), dict)
        or not isinstance(payload.get("semantic_toolchain"), dict)
    ):
        raise RefinementError(
            "refinement receipt fixed identity is invalid"
        )
    revision = payload.get("repository_revision")
    if (
        not isinstance(revision, str)
        or re.fullmatch(r"[0-9a-f]{40}", revision) is None
    ):
        raise RefinementError(
            "refinement receipt repository revision is invalid"
        )
    _validate_payload_identity(
        payload["generated_manifest"],
        "generated manifest",
        content_digest=render.manifest_content_digest,
    )
    if payload["generated_manifest"].get("artifact") != (
        "formal/riscv-refinement/generated-manifest.json"
    ):
        raise RefinementError(
            "refinement receipt generated manifest path drifted"
        )
    manifest_payload = payload["generated_manifest"]["payload"]
    if (
        manifest_payload.get("schema_version") != SCHEMA_VERSION
        or manifest_payload.get("kind")
        != "stwo-riscv-refinement-generated-manifest"
    ):
        raise RefinementError(
            "refinement receipt generated manifest identity drifted"
        )
    indexes = payload.get("coverage_indexes")
    if (
        not isinstance(indexes, dict)
        or set(indexes) != {"aggregate", "team_a", "team_b"}
    ):
        raise RefinementError(
            "refinement receipt coverage index schema is invalid"
        )
    expected_indexes = {
        "team_a": (
            "stwo-riscv-team-a-coverage",
            24,
            TEAM_A_INDEX_RELATIVE.as_posix(),
        ),
        "team_b": (
            "stwo-riscv-team-b-coverage",
            22,
            TEAM_B_INDEX_RELATIVE.as_posix(),
        ),
        "aggregate": (
            "stwo-riscv-opcode-coverage",
            46,
            OPCODE_INDEX_RELATIVE.as_posix(),
        ),
    }
    for name, (kind, count, artifact) in expected_indexes.items():
        _validate_payload_identity(indexes[name], f"{name} coverage index")
        index_payload = indexes[name]["payload"]
        if (
            indexes[name].get("artifact") != artifact
            or index_payload.get("schema_version") != 1
            or index_payload.get("kind") != kind
            or not isinstance(index_payload.get("certificates"), list)
            or len(index_payload["certificates"]) != count
        ):
            raise RefinementError(
                f"refinement receipt {name} coverage identity drifted"
            )
    source_indexes = indexes["aggregate"]["payload"].get("source_indexes")
    if (
        source_indexes
        != {
            "team_a": indexes["team_a"]["canonical_digest"],
            "team_b": indexes["team_b"]["canonical_digest"],
        }
    ):
        raise RefinementError(
            "refinement receipt aggregate source identities drifted"
        )
    mappings = _validate_certificate_mappings(
        payload.get("certificate_mappings"),
        indexes,
    )
    if not _strict_identity(
        mappings,
        indexes["aggregate"]["payload"]["certificates"],
    ):
        raise RefinementError(
            "refinement receipt mappings differ from the aggregate payload"
        )
    if not _strict_identity(
        payload.get("fixed_table_schemas"),
        _fixed_table_schemas(),
    ):
        raise RefinementError(
            "refinement receipt fixed-table schemas drifted"
        )
    expected_mutations = _opcode_mutations(mappings)
    if not _strict_identity(
        payload.get("opcode_mutations"),
        expected_mutations,
    ):
        raise RefinementError(
            "refinement receipt opcode mutation inventory drifted"
        )
    expected_diagnostics = _team_a_proof_time_diagnostics(mappings)
    if not _strict_identity(
        payload.get("team_a_proof_time_diagnostics"),
        expected_diagnostics,
    ):
        raise RefinementError(
            "refinement receipt Team A timing diagnostics drifted"
        )
    _validate_theorem_axiom_index(payload.get("theorem_axiom_index"))
    production_inputs = payload.get("production_inputs")
    _validate_production_inputs(production_inputs)
    _validate_production_certificate_bindings(
        production_inputs,
        mappings,
    )
    sail_inputs = payload.get("sail_inputs")
    _validate_sail_inputs(sail_inputs)
    _validate_certificate_sail_bindings(
        sail_inputs,
        mappings,
    )
    _validate_publication_bindings(
        payload.get("publication_evidence"),
        production_inputs,
        sail_inputs,
        payload.get("theorem_axiom_index"),
    )
