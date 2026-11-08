"""Fail-closed FV-1/FV-2 publication evidence.

This module deliberately treats theorem names as evidence only after the two
Lean audits have reported them with approved axioms.  It also binds every
selector to its exact production AIR digest and an exact generated-Sail source
digest.  Merely adding a string to a manifest cannot increase either proof
count.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

if __package__:
    from . import riscv_opcode_coverage
    from .riscv_refinement_lib import (
        air_program,
        air_program_contract,
        sail_lean_bridge,
    )
    from .riscv_refinement_lib.model import Paths, RefinementError
    from .riscv_refinement_receipt_constants import APPROVED_LEAN_AXIOMS
else:
    import riscv_opcode_coverage
    from riscv_refinement_lib import (
        air_program,
        air_program_contract,
        sail_lean_bridge,
    )
    from riscv_refinement_lib.model import Paths, RefinementError
    from riscv_refinement_receipt_constants import APPROVED_LEAN_AXIOMS


FULL_OPCODE_COUNT = 46
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
# Keep receipt validation and the kernel bridge on one exact assumption policy.
# The pinned generated full step retains disabled extension callbacks in its
# syntactic dependency closure; accepting only the older seven-name subset
# would make every complete publication receipt impossible to validate.
APPROVED_SAIL_AXIOMS = sail_lean_bridge.APPROVED_AXIOMS

PROGRAM_IDENTITY_THEOREM = (
    "RiscvRefinement.Publication.exactProductionProgramIdentities"
)
PROGRAM_COUNT_THEOREM = (
    "RiscvRefinement.Publication.exactProductionProgramCount"
)
MANIFEST_ORDER_THEOREM = (
    "RiscvRefinement.Publication.exactProductionManifestOrder"
)
MANIFEST_UNIQUENESS_THEOREM = (
    "RiscvRefinement.Publication.exactProductionManifestIdsNodup"
)
MNEMONIC_UNIQUENESS_THEOREM = (
    "RiscvRefinement.Publication.exactProductionMnemonicUnique"
)
ADMISSION_DECODE_THEOREM = (
    "RiscvRefinement.Publication.universalAdmissionDecode"
)
FIXED_TABLE_SCHEMA_THEOREM = (
    "RiscvRefinement.Publication.universalFixedTableSchemas"
)
FIXED_TABLE_INTERPRETATION_THEOREM = (
    "RiscvRefinement.Publication.universalFixedTableInterpretation"
)
LOCAL_MANIFEST_COVERAGE_THEOREM = (
    "RiscvRefinement.Publication.exactLocalManifestCoverage"
)
LOCAL_MANIFEST_ORDER_THEOREM = (
    "RiscvRefinement.Publication.exactLocalManifestOrderFilter"
)
LOCAL_THEOREM_IDENTITY_COVERAGE_THEOREM = (
    "RiscvRefinement.Publication.exactLocalTheoremIdentityCoverage"
)
OPCODE_PUBLICATION_INVENTORY_THEOREM = (
    "RiscvRefinement.Publication.exactOpcodePublicationInventory"
)
FULL_STEP_THEOREM = (
    "LeanRV32IM.Functions.generated_full_step_retirement_composition"
)
CROSS_PROJECT_CONTRACT_THEOREM = (
    "LeanRV32IM.Publication.universal_publication_contract"
)


def _selector(mnemonic: str) -> str:
    return mnemonic.upper()


def normalized_theorem(mnemonic: str) -> str:
    return (
        "LeanRV32IM.Functions."
        f"complete_{_selector(mnemonic)}_normalizes"
    )


def composition_theorem(mnemonic: str) -> str:
    return (
        "LeanRV32IM.Publication."
        f"{_selector(mnemonic)}_accepted_air_refines"
    )


NORMALIZED_THEOREMS = {
    mnemonic: normalized_theorem(mnemonic)
    for _, mnemonic, _ in air_program_contract.OPCODES
}
COMPOSITION_THEOREMS = {
    mnemonic: composition_theorem(mnemonic)
    for _, mnemonic, _ in air_program_contract.OPCODES
}
LOCAL_UNIVERSAL_THEOREMS = frozenset(
    {
        PROGRAM_IDENTITY_THEOREM,
        PROGRAM_COUNT_THEOREM,
        MANIFEST_ORDER_THEOREM,
        MANIFEST_UNIQUENESS_THEOREM,
        MNEMONIC_UNIQUENESS_THEOREM,
        ADMISSION_DECODE_THEOREM,
        FIXED_TABLE_SCHEMA_THEOREM,
        FIXED_TABLE_INTERPRETATION_THEOREM,
        LOCAL_MANIFEST_COVERAGE_THEOREM,
        LOCAL_MANIFEST_ORDER_THEOREM,
        LOCAL_THEOREM_IDENTITY_COVERAGE_THEOREM,
        OPCODE_PUBLICATION_INVENTORY_THEOREM,
    }
)


def _validate_axiom_entry(
    theorem: str,
    report: Mapping[str, object],
    approved: frozenset[str],
    boundary: str,
) -> list[str]:
    raw = report.get(theorem)
    if (
        not isinstance(raw, list)
        or any(not isinstance(axiom, str) for axiom in raw)
        or raw != sorted(set(raw))
    ):
        raise RefinementError(
            f"{boundary} audit is missing a valid record for {theorem}"
        )
    unexpected = set(raw) - approved
    if unexpected:
        raise RefinementError(
            f"{boundary} theorem {theorem} uses unapproved axioms: "
            + ", ".join(sorted(unexpected))
        )
    return raw


def _validate_source_digests(value: object) -> dict[str, str]:
    expected_selectors = [
        _selector(mnemonic)
        for _, mnemonic, _ in air_program_contract.OPCODES
    ]
    if not isinstance(value, list) or len(value) != FULL_OPCODE_COUNT:
        raise RefinementError(
            "generated Sail selector source-digest inventory is not the "
            "exact 46-entry manifest order"
        )
    result: dict[str, str] = {}
    for expected, identity in zip(expected_selectors, value):
        if (
            not isinstance(identity, dict)
            or set(identity) != {"selector", "sha256"}
            or identity.get("selector") != expected
        ):
            raise RefinementError(
                "generated Sail selector source-digest inventory is not the "
                "exact 46-entry manifest order"
            )
        digest = identity.get("sha256")
        if not isinstance(digest, str) or HEX_SHA256.fullmatch(digest) is None:
            raise RefinementError(
                f"generated Sail source digest is invalid for {expected}"
            )
        result[expected] = digest
    return result


def _validate_sail_receipt(
    receipt: Mapping[str, object],
) -> tuple[dict[str, list[str]], dict[str, str]]:
    boundary = receipt.get("claim_boundary")
    theorem_axioms = receipt.get("theorem_axioms")
    if not isinstance(boundary, dict) or not isinstance(theorem_axioms, dict):
        raise RefinementError(
            "generated Sail bridge receipt has no publication evidence"
        )
    expected_selectors = [
        _selector(mnemonic)
        for _, mnemonic, _ in air_program_contract.OPCODES
    ]
    if (
        boundary.get("input_bound_selectors") != expected_selectors
        or boundary.get("normalized_retirement_selectors")
        != expected_selectors
        or boundary.get("fetch_interrupt_trap_and_step_loop_framing")
        is not True
        or boundary.get("constructive_row_local_execution") is not True
        or boundary.get("publication_binding") is not True
    ):
        raise RefinementError(
            "generated Sail bridge receipt does not establish FV-1/FV-2"
        )
    source_digests = _validate_source_digests(
        receipt.get("selector_source_digests")
    )
    required = {
        FULL_STEP_THEOREM,
        CROSS_PROJECT_CONTRACT_THEOREM,
        *NORMALIZED_THEOREMS.values(),
        *COMPOSITION_THEOREMS.values(),
    }
    for theorem in sorted(required):
        _validate_axiom_entry(
            theorem,
            theorem_axioms,
            APPROVED_SAIL_AXIOMS,
            "generated Sail",
        )
    return (
        {
            theorem: theorem_axioms[theorem]
            for theorem in sorted(required)
        },
        source_digests,
    )


def _air_digest(paths: Paths, mnemonic: str) -> str:
    path = paths.generated_air / f"{mnemonic}.air-ir-v2.json"
    program = air_program.load_canonical(path)
    air_program.verify_source_files(program, paths.root)
    digest = program.get("content_digest")
    if not isinstance(digest, str) or HEX_SHA256.fullmatch(digest) is None:
        raise RefinementError(
            f"production AIR digest is invalid for {mnemonic}"
        )
    return digest


def validate_publication_evidence(value: object) -> None:
    """Validate the self-contained FV-1/FV-2 receipt section."""
    if not isinstance(value, dict) or set(value) != {
        "entries",
        "cross_project_contract_theorem",
        "full_generated_sail_step",
        "full_step_theorem",
        "generated_sail_theorem_axioms",
        "normalized_retirements",
        "publication_level",
        "universal_theorems",
    }:
        raise RefinementError("publication evidence schema is invalid")
    exact_count = {"proved": FULL_OPCODE_COUNT, "total": FULL_OPCODE_COUNT}
    if (
        value.get("normalized_retirements") != exact_count
        or value.get("publication_level") != exact_count
        or value.get("full_generated_sail_step") is not True
        or value.get("full_step_theorem") != FULL_STEP_THEOREM
        or value.get("cross_project_contract_theorem")
        != CROSS_PROJECT_CONTRACT_THEOREM
        or value.get("universal_theorems")
        != sorted(LOCAL_UNIVERSAL_THEOREMS)
    ):
        raise RefinementError("publication evidence claim boundary is invalid")

    sail_axioms = value.get("generated_sail_theorem_axioms")
    required_sail_theorems = {
        FULL_STEP_THEOREM,
        CROSS_PROJECT_CONTRACT_THEOREM,
        *NORMALIZED_THEOREMS.values(),
        *COMPOSITION_THEOREMS.values(),
    }
    if (
        not isinstance(sail_axioms, dict)
        or set(sail_axioms) != required_sail_theorems
    ):
        raise RefinementError(
            "publication generated-Sail theorem index is incomplete"
        )
    for theorem in sorted(required_sail_theorems):
        _validate_axiom_entry(
            theorem,
            sail_axioms,
            APPROVED_SAIL_AXIOMS,
            "publication generated Sail",
        )

    entries = value.get("entries")
    if not isinstance(entries, list) or len(entries) != FULL_OPCODE_COUNT:
        raise RefinementError("publication opcode evidence is incomplete")
    required_entry_fields = {
        "accepted_air_refinement_theorem",
        "family",
        "generated_sail_retirement_theorem",
        "generated_sail_source_digest",
        "manifest_id",
        "mnemonic",
        "mutation_theorem",
        "non_vacuity_theorem",
        "production_air_digest",
        "production_program_identity_theorem",
        "tuple_theorem",
    }
    seen_source_digests: list[str] = []
    for expected, entry in zip(air_program_contract.OPCODES, entries):
        manifest_id, mnemonic, family = expected
        if (
            not isinstance(entry, dict)
            or set(entry) != required_entry_fields
            or type(entry.get("manifest_id")) is not int
            or entry.get("manifest_id") != manifest_id
            or entry.get("mnemonic") != mnemonic
            or entry.get("family") != family
            or entry.get("production_program_identity_theorem")
            != PROGRAM_IDENTITY_THEOREM
            or entry.get("generated_sail_retirement_theorem")
            != NORMALIZED_THEOREMS[mnemonic]
            or entry.get("accepted_air_refinement_theorem")
            != COMPOSITION_THEOREMS[mnemonic]
        ):
            raise RefinementError(
                f"publication opcode identity drifted for {mnemonic}"
            )
        for field in (
            "production_air_digest",
            "generated_sail_source_digest",
        ):
            digest = entry.get(field)
            if (
                not isinstance(digest, str)
                or HEX_SHA256.fullmatch(digest) is None
            ):
                raise RefinementError(
                    f"publication {field} is invalid for {mnemonic}"
                )
        for field in (
            "tuple_theorem",
            "non_vacuity_theorem",
            "mutation_theorem",
        ):
            theorem = entry.get(field)
            if not isinstance(theorem, str) or not theorem:
                raise RefinementError(
                    f"publication {field} is invalid for {mnemonic}"
                )
        seen_source_digests.append(entry["generated_sail_source_digest"])
    if not seen_source_digests:
        raise RefinementError("publication Sail source inventory is empty")


def build_publication_evidence(
    paths: Paths,
    monad_bridge_receipt: Mapping[str, object],
    local_theorem_axioms: Mapping[str, object],
) -> dict[str, object]:
    """Build the exact 46-entry publication section or fail closed."""
    sail_axioms, source_digests = _validate_sail_receipt(
        monad_bridge_receipt
    )
    for theorem in sorted(LOCAL_UNIVERSAL_THEOREMS):
        _validate_axiom_entry(
            theorem,
            local_theorem_axioms,
            APPROVED_LEAN_AXIOMS,
            "repository Lean",
        )

    coverage = riscv_opcode_coverage.build_index()
    certificates = coverage.get("certificates")
    if not isinstance(certificates, list) or len(certificates) != 46:
        raise RefinementError(
            "graded opcode certificates do not provide a 46-entry "
            "non-vacuity/mutation inventory"
        )
    certificate_by_mnemonic = {
        certificate.get("mnemonic"): certificate
        for certificate in certificates
        if isinstance(certificate, dict)
    }

    entries: list[dict[str, object]] = []
    for manifest_id, mnemonic, family in air_program_contract.OPCODES:
        selector = _selector(mnemonic)
        certificate = certificate_by_mnemonic.get(mnemonic)
        if not isinstance(certificate, dict):
            raise RefinementError(
                f"publication evidence has no certificate for {mnemonic}"
            )
        retained_theorems: dict[str, str] = {}
        for field in (
            "tuple_theorem",
            "non_vacuity_theorem",
            "mutation_theorem",
        ):
            theorem = certificate.get(field)
            if not isinstance(theorem, str) or not theorem:
                raise RefinementError(
                    f"{mnemonic} certificate has no {field}"
                )
            _validate_axiom_entry(
                theorem,
                local_theorem_axioms,
                APPROVED_LEAN_AXIOMS,
                "repository Lean",
            )
            retained_theorems[field] = theorem
        entries.append(
            {
                "manifest_id": manifest_id,
                "mnemonic": mnemonic,
                "family": family,
                "production_air_digest": _air_digest(paths, mnemonic),
                "production_program_identity_theorem":
                    PROGRAM_IDENTITY_THEOREM,
                "generated_sail_source_digest": source_digests[selector],
                "generated_sail_retirement_theorem":
                    NORMALIZED_THEOREMS[mnemonic],
                "accepted_air_refinement_theorem":
                    COMPOSITION_THEOREMS[mnemonic],
                **retained_theorems,
            }
        )

    if (
        len(entries) != FULL_OPCODE_COUNT
        or [entry["manifest_id"] for entry in entries]
        != list(range(FULL_OPCODE_COUNT))
        or len(set(NORMALIZED_THEOREMS.values())) != FULL_OPCODE_COUNT
        or len(set(COMPOSITION_THEOREMS.values())) != FULL_OPCODE_COUNT
    ):
        raise RefinementError(
            "publication evidence does not form an exact 46-selector index"
        )

    result = {
        "normalized_retirements": {
            "proved": FULL_OPCODE_COUNT,
            "total": FULL_OPCODE_COUNT,
        },
        "publication_level": {
            "proved": FULL_OPCODE_COUNT,
            "total": FULL_OPCODE_COUNT,
        },
        "full_generated_sail_step": True,
        "cross_project_contract_theorem":
            CROSS_PROJECT_CONTRACT_THEOREM,
        "universal_theorems": sorted(LOCAL_UNIVERSAL_THEOREMS),
        "full_step_theorem": FULL_STEP_THEOREM,
        "entries": entries,
        "generated_sail_theorem_axioms": sail_axioms,
    }
    validate_publication_evidence(result)
    return result
