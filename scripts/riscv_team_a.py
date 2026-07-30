#!/usr/bin/env python3
"""Fail-closed Team A certificate and production-AIR binding gate.

Issue #136 assigns 24 RV32IM opcodes to Team A.  This gate keeps three
different claims separate:

* ``air-proved`` means the certificate names a universal Lean refinement,
  exact tuple/selector facts, an honest witness, and a load-bearing mutation;
* ``air_digest`` binds that certificate to the exact per-selector production
  ``ConstraintProgram`` committed under ``generated/air``;
* ``axioms`` is checked against the live kernel audit, while
  ``proof_time_ms`` is a bounded diagnostic rather than semantic evidence;
* ``sail_binding`` records the architectural evidence grade.  An opcode may
  remain explicitly ``unbound``; a reviewed capsule must bind its exact file,
  and generated Sail distinguishes exact execute-clause input binding from
  the stronger normalized-retirement theorem.

The gate deliberately does not promote a production-AIR proof to
publication-level or whole-frontend verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

try:
    from . import riscv_team_b as shared
    from .riscv_refinement_lib import air_program, render
    from .riscv_refinement_lib.model import RefinementError
except ImportError:
    import riscv_team_b as shared
    from riscv_refinement_lib import air_program, render
    from riscv_refinement_lib.model import RefinementError


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORMAL_ROOT = REPOSITORY_ROOT / "formal/riscv-refinement"
LEAN_ROOT = REPOSITORY_ROOT / "formal/riscv-refinement/RiscvRefinement"
AIR_PROGRAM_ROOT = REPOSITORY_ROOT / "formal/riscv-refinement/generated/air"
CERTIFICATE_INDEX = (
    REPOSITORY_ROOT / "formal/riscv-refinement/team-a-coverage.json"
)
GENERATED_SAIL_RECEIPT = (
    REPOSITORY_ROOT
    / "formal/riscv-refinement/generated/sail/"
    "generated-monad-bridge-receipt-v1.json"
)

TEAM_A_FAMILIES = (
    "base_alu_reg",
    "base_alu_imm",
    "lt_reg",
    "lt_imm",
    "branch_eq",
    "branch_lt",
    "lui",
    "auipc",
    "jal",
    "jalr",
    "fence",
)
TEAM_A_OPCODE_COUNT = 24
FULL_OPCODE_COUNT = 46

CERTIFICATE_FIELDS = {
    "air_digest",
    "axioms",
    "family",
    "manifest_id",
    "mnemonic",
    "mutation",
    "mutation_theorem",
    "non_vacuity_theorem",
    "refinement_theorem",
    "sail_binding",
    "selector_theorem",
    "state",
    "proof_target",
    "proof_time_ms",
    "tuple_theorem",
}
OPTIONAL_CERTIFICATE_FIELDS = {
    "sail_artifact",
    "sail_digest",
    "sail_receipt",
    "sail_theorem",
}
THEOREM_FIELDS = (
    "selector_theorem",
    "refinement_theorem",
    "tuple_theorem",
    "non_vacuity_theorem",
    "mutation_theorem",
)
SAIL_BINDINGS = (
    "unbound",
    "reviewed-capsule",
    "generated-clause-input",
    "generated-retirement",
)
GENERATED_SAIL_INPUT_THEOREMS = {
    "add": "LeanRV32IM.Functions.execute_RTYPE_ADD_eq",
    "sub": "LeanRV32IM.Functions.execute_RTYPE_SUB_eq",
    "slt": "LeanRV32IM.Functions.execute_RTYPE_SLT_eq",
    "sltu": "LeanRV32IM.Functions.execute_RTYPE_SLTU_eq",
    "xor": "LeanRV32IM.Functions.execute_RTYPE_XOR_eq",
    "or": "LeanRV32IM.Functions.execute_RTYPE_OR_eq",
    "and": "LeanRV32IM.Functions.execute_RTYPE_AND_eq",
    "addi": "LeanRV32IM.Functions.execute_ITYPE_ADDI_eq",
    "slti": "LeanRV32IM.Functions.execute_ITYPE_SLTI_eq",
    "sltiu": "LeanRV32IM.Functions.execute_ITYPE_SLTIU_eq",
    "xori": "LeanRV32IM.Functions.execute_ITYPE_XORI_eq",
    "ori": "LeanRV32IM.Functions.execute_ITYPE_ORI_eq",
    "andi": "LeanRV32IM.Functions.execute_ITYPE_ANDI_eq",
    "beq": "LeanRV32IM.Functions.execute_BTYPE_BEQ_eq",
    "bne": "LeanRV32IM.Functions.execute_BTYPE_BNE_eq",
    "blt": "LeanRV32IM.Functions.execute_BTYPE_BLT_eq",
    "bge": "LeanRV32IM.Functions.execute_BTYPE_BGE_eq",
    "bltu": "LeanRV32IM.Functions.execute_BTYPE_BLTU_eq",
    "bgeu": "LeanRV32IM.Functions.execute_BTYPE_BGEU_eq",
    "jal": "LeanRV32IM.Functions.execute_JAL_eq",
    "jalr": "LeanRV32IM.Functions.execute_JALR_eq",
    "lui": "LeanRV32IM.Functions.execute_UTYPE_LUI_eq",
    "auipc": "LeanRV32IM.Functions.execute_UTYPE_AUIPC_eq",
    "fence": "LeanRV32IM.Functions.execute_FENCE_eq",
}
GENERATED_SAIL_RETIREMENT_THEOREMS = {
    "addi": "LeanRV32IM.Functions.complete_ADDI_normalizes",
    "lui": "LeanRV32IM.Functions.complete_LUI_normalizes",
}
EXPECTED_PROOF_BINDINGS = {
    "add": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.add_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.add_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.add_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.add_overflow_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Reg.add_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluRegOp.add-"
            "wrong-next-pc-state-emit",
    },
    "sub": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.sub_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.sub_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.sub_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.sub_borrow_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Reg.sub_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluRegOp.sub-"
            "wrong-next-pc-state-emit",
    },
    "xor": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.xor_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.xor_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.xor_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.xor_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Reg.xor_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluRegOp.xor-"
            "wrong-next-pc-state-emit",
    },
    "or": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.or_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.or_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.or_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.or_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Reg.or_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluRegOp.or-"
            "wrong-next-pc-state-emit",
    },
    "and": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.and_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.and_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.and_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluReg.and_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Reg.and_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluRegOp.and-"
            "wrong-next-pc-state-emit",
    },
    "addi": {
        "selector_theorem":
            "RiscvRefinement.Air.Bridge.Addi.selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.addi_production_refines",
        "tuple_theorem":
            "RiscvRefinement.Air.Bridge.Addi.lookup_projection",
        "non_vacuity_theorem":
            "RiscvRefinement.NonVacuity.addi_production_overflow_exists",
        "mutation_theorem":
            "RiscvRefinement.Air.Bridge.Mutations."
            "addiCarry_strictly_weaker",
        "mutation": "addi-free-high-carry",
    },
    "xori": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.xori_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.xori_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.xori_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.xori_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Imm.xori_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluImmOp.xori-"
            "wrong-next-pc-state-emit",
    },
    "ori": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.ori_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.ori_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.ori_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.ori_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Imm.ori_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluImmOp.ori-"
            "wrong-next-pc-state-emit",
    },
    "andi": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.andi_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.andi_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.andi_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.BaseAluImm.andi_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BaseAluMutation.Imm.andi_mutation",
        "mutation":
            "RiscvRefinement.Decode.BaseAluImmOp.andi-"
            "wrong-next-pc-state-emit",
    },
    "slt": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.slt_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.slt_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.slt_exactLookupTuples",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.slt_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.LtMutation.Reg."
            "slt_wrongManifest_strictly_weaker",
        "mutation": "slt-manifest-replaced-by-sltu",
    },
    "sltu": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.sltu_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.sltu_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.sltu_exactLookupTuples",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Lt.Reg.sltu_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.LtMutation.Reg."
            "sltu_wrongManifest_strictly_weaker",
        "mutation": "sltu-manifest-replaced-by-slt",
    },
    "slti": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.slti_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.slti_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.slti_exactLookupTuples",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.slti_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.LtMutation.Imm."
            "slti_wrongManifest_strictly_weaker",
        "mutation": "slti-manifest-replaced-by-sltiu",
    },
    "sltiu": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.sltiu_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.sltiu_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.sltiu_exactLookupTuples",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Lt.Imm.sltiu_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.LtMutation.Imm."
            "sltiu_wrongManifest_strictly_weaker",
        "mutation": "sltiu-manifest-replaced-by-slti",
    },
    "beq": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.beq_selector_theorem",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.beq_refinement_theorem",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.beq_tuple_theorem",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.beq_nonvacuity_theorem",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BranchesMutation."
            "beqStateProjection_mutation_theorem",
        "mutation": "beq-state-projection-load-bearing",
    },
    "bne": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.bne_selector_theorem",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.bne_refinement_theorem",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.bne_tuple_theorem",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Branches.Eq.bne_nonvacuity_theorem",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BranchesMutation."
            "bneStateProjection_mutation_theorem",
        "mutation": "bne-state-projection-load-bearing",
    },
    "blt": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.blt_selector_theorem",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.blt_refinement_theorem",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.blt_tuple_theorem",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.blt_nonvacuity_theorem",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BranchesMutation."
            "bltStateProjection_mutation_theorem",
        "mutation": "blt-state-projection-load-bearing",
    },
    "bge": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bge_selector_theorem",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bge_refinement_theorem",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bge_tuple_theorem",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bge_nonvacuity_theorem",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BranchesMutation."
            "bgeStateProjection_mutation_theorem",
        "mutation": "bge-state-projection-load-bearing",
    },
    "bltu": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bltu_selector_theorem",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bltu_refinement_theorem",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bltu_tuple_theorem",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bltu_nonvacuity_theorem",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BranchesMutation."
            "bltuStateProjection_mutation_theorem",
        "mutation": "bltu-state-projection-load-bearing",
    },
    "bgeu": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bgeu_selector_theorem",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bgeu_refinement_theorem",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bgeu_tuple_theorem",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Branches.Lt.bgeu_nonvacuity_theorem",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.BranchesMutation."
            "bgeuStateProjection_mutation_theorem",
        "mutation": "bgeu-state-projection-load-bearing",
    },
    "jal": {
        "selector_theorem":
            "RiscvRefinement.Air.Bridge.Jal.selectorAccepted",
        "refinement_theorem": "RiscvRefinement.Opcodes.Jal.refines",
        "tuple_theorem":
            "RiscvRefinement.Air.Bridge.Jal.lookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Jal.jalExists",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.JalMutation."
            "wrongStateEmit_strictly_weaker",
        "mutation": "jal-wrong-jump-state-emit",
    },
    "jalr": {
        "selector_theorem":
            "RiscvRefinement.Opcodes.Jalr.jalr_selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Jalr.jalr_refines",
        "tuple_theorem":
            "RiscvRefinement.Opcodes.Jalr.jalr_exactLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Jalr.jalr_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.JalrMutation."
            "wrongStateEmit_strictly_weaker",
        "mutation": "jalr-target-replaced-by-link-pc",
    },
    "lui": {
        "selector_theorem":
            "RiscvRefinement.Air.Bridge.Lui.selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.lui_production_refines",
        "tuple_theorem":
            "RiscvRefinement.Air.Bridge.Lui.lookup_projection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.lui_production_nonvacuous",
        "mutation_theorem":
            "RiscvRefinement.Air.Bridge.Mutations."
            "luiLowLimb_strictly_weaker",
        "mutation": "lui-free-low-limb",
    },
    "auipc": {
        "selector_theorem":
            "RiscvRefinement.Air.Bridge.Auipc.selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Auipc.refines",
        "tuple_theorem":
            "RiscvRefinement.Air.Bridge.Auipc.allLookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Auipc.auipcExists",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.AuipcMutation."
            "wrongDestination_strictly_weaker",
        "mutation": "auipc-destination-low-byte-plus-four",
    },
    "fence": {
        "selector_theorem":
            "RiscvRefinement.Air.Bridge.Fence.selectorAccepted",
        "refinement_theorem":
            "RiscvRefinement.Opcodes.Fence.refines",
        "tuple_theorem":
            "RiscvRefinement.Air.Bridge.Fence.lookupProjection",
        "non_vacuity_theorem":
            "RiscvRefinement.Opcodes.Fence.fence_exists",
        "mutation_theorem":
            "RiscvRefinement.Opcodes.FenceMutation."
            "wrongStateEmit_strictly_weaker",
        "mutation": "fence-wrong-next-pc-state-emit",
    },
}
PROOF_TIMING_TARGETS = {
    **{
        mnemonic: "RiscvRefinement.Opcodes.BaseAluMutation"
        for mnemonic in (
            "add", "sub", "xor", "or", "and", "xori", "ori", "andi",
        )
    },
    **{
        mnemonic: "RiscvRefinement.Opcodes.BranchesMutation"
        for mnemonic in ("beq", "bne", "blt", "bge", "bltu", "bgeu")
    },
    "addi": "RiscvRefinement.Air.Bridge.Mutations",
    "lui": "RiscvRefinement.Air.Bridge.Mutations",
    "auipc": "RiscvRefinement.Opcodes.AuipcMutation",
    "jal": "RiscvRefinement.Opcodes.JalMutation",
    "jalr": "RiscvRefinement.Opcodes.JalrMutation",
    "fence": "RiscvRefinement.Opcodes.FenceMutation",
    "slt": "RiscvRefinement.Opcodes.LtMutation",
    "sltu": "RiscvRefinement.Opcodes.LtMutation",
    "slti": "RiscvRefinement.Opcodes.LtMutation",
    "sltiu": "RiscvRefinement.Opcodes.LtMutation",
}
HEX_DIGEST = re.compile(r"[0-9a-f]{64}")
APPROVED_AXIOMS = frozenset(
    {
        "Classical.choice",
        "Quot.sound",
        "propext",
    }
)
MAX_PROOF_TIME_MS = 1_200_000
RAW_COLUMN_MODELS = {
    "Air/Bridge/BaseAluImm.lean": {
        "blocks": 1,
        "forbidden": (
            "bitwiseBytes op",
            "architecturalValue",
            "executeValue op",
        ),
    },
    "Air/Bridge/BaseAluReg.lean": {
        "blocks": 1,
        "forbidden": (
            "bitwiseBytes op",
            "architecturalValue",
            "executeValue op",
        ),
    },
    "Air/Bridge/Auipc.lean": {
        "blocks": 1,
        "forbidden": (),
        "admission_forbidden": (
            "immediateWordBinds",
            "immediateSignBinds",
        ),
    },
    "Air/Bridge/Branches.lean": {
        "blocks": 2,
        "forbidden": (
            "taken row",
            "less row",
            "mostSignificantField row.kind",
        ),
    },
    "Air/Bridge/Jalr.lean": {
        "blocks": 1,
        "forbidden": (
            "rdNext row",
            "result row",
            "targetBytes row",
            "jumpTarget row.",
            "targetWordLow20 row.",
            "targetWordHigh8 row.",
            "immediateByte row.",
            "immediateNibble row.",
            "immediateSign row.",
        ),
    },
    "Air/Bridge/LtReg.lean": {
        "blocks": 1,
        "forbidden": (
            "semanticLess row.",
            "mslField row.kind",
        ),
    },
    "Air/Bridge/LtImm.lean": {
        "blocks": 1,
        "forbidden": (
            "comparison row.",
            "destinationBytes row.",
        ),
    },
}


class TeamAError(RuntimeError):
    """A Team A gate failure."""


def manifest_opcodes() -> list[tuple[str, str, int]]:
    try:
        entries = shared.manifest_opcodes()
    except shared.TeamBError as exc:
        raise TeamAError(str(exc)) from exc
    return entries


def team_a_opcodes() -> list[tuple[str, str, int]]:
    selected = [
        entry
        for entry in manifest_opcodes()
        if entry[1] in TEAM_A_FAMILIES
    ]
    if len(selected) != TEAM_A_OPCODE_COUNT:
        raise TeamAError(
            f"Team A families cover {len(selected)} opcodes, "
            f"expected {TEAM_A_OPCODE_COUNT}"
        )
    families = {family for _, family, _ in selected}
    if families != set(TEAM_A_FAMILIES):
        raise TeamAError(
            "Team A family assignment drifted; missing "
            + ", ".join(sorted(set(TEAM_A_FAMILIES) - families))
        )
    return selected


def load_certificates() -> dict[str, Any]:
    if not CERTIFICATE_INDEX.is_file():
        raise TeamAError(
            f"Team A certificate index is absent at {CERTIFICATE_INDEX}"
        )
    try:
        index = json.loads(CERTIFICATE_INDEX.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TeamAError("Team A certificate index is unreadable") from exc
    if index.get("canonical_digest") != shared.canonical_digest(index):
        raise TeamAError("Team A certificate index digest mismatch")
    expected_top_level = {
        "canonical_digest",
        "certificates",
        "claim_boundary",
        "families",
        "issue",
        "kind",
        "schema_version",
    }
    if set(index) != expected_top_level:
        raise TeamAError("Team A certificate index schema drifted")
    if (
        index.get("schema_version") != 1
        or index.get("kind") != "stwo-riscv-team-a-coverage"
        or index.get("issue") != 136
        or index.get("families") != list(TEAM_A_FAMILIES)
        or not isinstance(index.get("claim_boundary"), dict)
    ):
        raise TeamAError("Team A certificate index identity drifted")
    return index


def _certificates_by_mnemonic() -> dict[str, dict[str, Any]]:
    certificates = load_certificates().get("certificates")
    if not isinstance(certificates, list):
        raise TeamAError("Team A certificate index has no certificates list")
    result: dict[str, dict[str, Any]] = {}
    for certificate in certificates:
        if not isinstance(certificate, dict):
            raise TeamAError("a Team A certificate is not an object")
        fields = set(certificate)
        if (
            not CERTIFICATE_FIELDS <= fields
            or fields - CERTIFICATE_FIELDS - OPTIONAL_CERTIFICATE_FIELDS
        ):
            raise TeamAError("a Team A certificate schema drifted")
        mnemonic = certificate.get("mnemonic")
        if not isinstance(mnemonic, str) or not mnemonic:
            raise TeamAError("a Team A certificate has no string mnemonic")
        if mnemonic in result:
            raise TeamAError(f"duplicate Team A certificate for {mnemonic}")
        result[mnemonic] = certificate
    return result


def _check_generated_sail_binding(
    mnemonic: str,
    binding: str,
    certificate: dict[str, Any],
) -> None:
    receipt = certificate.get("sail_receipt")
    digest = certificate.get("sail_digest")
    theorem = certificate.get("sail_theorem")
    if (
        not isinstance(receipt, str)
        or not receipt
        or not isinstance(digest, str)
        or HEX_DIGEST.fullmatch(digest) is None
        or not isinstance(theorem, str)
        or not theorem
    ):
        raise TeamAError(
            f"{mnemonic} claims generated Sail without a complete "
            "receipt binding"
        )
    expected_theorem = (
        GENERATED_SAIL_RETIREMENT_THEOREMS.get(mnemonic)
        if binding == "generated-retirement"
        else GENERATED_SAIL_INPUT_THEOREMS.get(mnemonic)
    )
    if theorem != expected_theorem:
        raise TeamAError(
            f"{mnemonic} generated Sail theorem is {theorem!r}, expected "
            f"{expected_theorem!r} for {binding}"
        )
    receipt_path = REPOSITORY_ROOT / receipt
    if not receipt_path.is_file():
        raise TeamAError(
            f"{mnemonic} Sail receipt is absent at {receipt}"
        )
    try:
        receipt_payload = json.loads(
            receipt_path.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TeamAError(
            f"{mnemonic} Sail receipt is unreadable"
        ) from exc
    if (
        receipt_payload.get("schema_version")
        != "stwo-generated-sail-monad-bridge-v1"
        or receipt_payload.get("evidence_source")
        != "exact-pinned-generated-backend"
    ):
        raise TeamAError(
            f"{mnemonic} generated Sail receipt identity drifted"
        )
    claim_boundary = receipt_payload.get("claim_boundary")
    theorems = receipt_payload.get("theorems")
    if not isinstance(claim_boundary, dict):
        raise TeamAError(
            f"{mnemonic} generated Sail receipt has no claim boundary"
        )
    normalized = claim_boundary.get("normalized_retirement_selectors")
    input_bound = claim_boundary.get("input_bound_team_a_selectors")
    if (
        not isinstance(normalized, list)
        or any(not isinstance(selector, str) for selector in normalized)
        or normalized != list(dict.fromkeys(normalized))
        or normalized != ["LUI", "ADDI"]
    ):
        raise TeamAError(
            f"{mnemonic} generated Sail receipt has a malformed normalized "
            "selector set"
        )
    if (
        not isinstance(input_bound, list)
        or any(not isinstance(selector, str) for selector in input_bound)
        or input_bound != list(dict.fromkeys(input_bound))
        or set(input_bound)
        != {
            selector.upper()
            for selector in GENERATED_SAIL_INPUT_THEOREMS
        }
    ):
        raise TeamAError(
            f"{mnemonic} generated Sail receipt does not bind exactly the "
            "24 Team A execute-clause inputs"
        )
    if (
        not isinstance(theorems, list)
        or any(not isinstance(name, str) for name in theorems)
        or theorems != list(dict.fromkeys(theorems))
        or receipt_payload.get("canonical_digest")
        != shared.canonical_digest(receipt_payload)
        or receipt_payload.get("canonical_digest") != digest
        or theorem not in theorems
        or claim_boundary.get(
            "team_a_execute_clause_input_binding",
            False,
        ) is not True
    ):
        raise TeamAError(
            f"{mnemonic} generated Sail receipt does not bind its "
            "named theorem"
        )
    if (
        binding == "generated-retirement"
        and (
            claim_boundary.get(
                "generated_execute_clause_monad_normalization",
                False,
            ) is not True
            or mnemonic.upper() not in normalized
        )
    ):
        raise TeamAError(
            f"{mnemonic} claims generated retirement normalization "
            "outside the receipt's normalized selector set"
        )


def check_coverage() -> str:
    expected_entries = team_a_opcodes()
    certificates = _certificates_by_mnemonic()
    expected = {mnemonic for mnemonic, _, _ in expected_entries}
    if set(GENERATED_SAIL_INPUT_THEOREMS) != expected:
        raise TeamAError(
            "generated Sail selector/theorem map does not exactly cover "
            "Team A"
        )
    if set(GENERATED_SAIL_RETIREMENT_THEOREMS) != {"lui", "addi"}:
        raise TeamAError(
            "generated Sail retirement map drifted beyond LUI/ADDI"
        )
    if set(EXPECTED_PROOF_BINDINGS) != expected:
        raise TeamAError(
            "expected Team A proof-binding map does not exactly cover "
            "all 24 selectors"
        )
    if set(PROOF_TIMING_TARGETS) != expected:
        raise TeamAError(
            "Team A proof-timing target map does not exactly cover all "
            "24 selectors"
        )
    if set(certificates) != expected:
        missing = sorted(expected - set(certificates))
        extra = sorted(set(certificates) - expected)
        raise TeamAError(
            f"Team A certificate coverage drifted; missing {missing}, "
            f"unexpected {extra}"
        )
    for mnemonic, family, manifest_id in expected_entries:
        certificate = certificates[mnemonic]
        if certificate["family"] != family:
            raise TeamAError(
                f"{mnemonic} certificate records family "
                f"{certificate['family']!r}, manifest says {family!r}"
            )
        if (
            type(certificate["manifest_id"]) is not int
            or certificate["manifest_id"] != manifest_id
        ):
            raise TeamAError(
                f"{mnemonic} certificate manifest id drifted"
            )
        if certificate["state"] != "air-proved":
            raise TeamAError(
                f"{mnemonic} is {certificate['state']!r}, "
                "not 'air-proved'"
            )
        for field in THEOREM_FIELDS:
            if not isinstance(certificate[field], str) or not certificate[field]:
                raise TeamAError(f"{mnemonic} has no valid {field}")
        if (
            not isinstance(certificate["mutation"], str)
            or not certificate["mutation"]
        ):
            raise TeamAError(f"{mnemonic} has no mutation identity")
        if (
            not isinstance(certificate["air_digest"], str)
            or HEX_DIGEST.fullmatch(certificate["air_digest"]) is None
        ):
            raise TeamAError(f"{mnemonic} has no canonical AIR digest")
        axioms = certificate["axioms"]
        if (
            not isinstance(axioms, list)
            or any(not isinstance(axiom, str) for axiom in axioms)
            or axioms != sorted(set(axioms))
            or not set(axioms) <= APPROVED_AXIOMS
        ):
            raise TeamAError(
                f"{mnemonic} has an invalid or unapproved axiom inventory"
            )
        proof_time = certificate["proof_time_ms"]
        if (
            type(proof_time) is not int
            or proof_time <= 0
            or proof_time > MAX_PROOF_TIME_MS
        ):
            raise TeamAError(
                f"{mnemonic} has no positive bounded proof-time diagnostic"
            )
        proof_target = certificate["proof_target"]
        if (
            not isinstance(proof_target, str)
            or proof_target != PROOF_TIMING_TARGETS[mnemonic]
        ):
            raise TeamAError(
                f"{mnemonic} proof_target is not its pinned build target"
            )
        binding = certificate["sail_binding"]
        if binding not in SAIL_BINDINGS:
            raise TeamAError(
                f"{mnemonic} has unrecognised Sail binding {binding!r}"
            )
        sail_metadata = {
            field
            for field in OPTIONAL_CERTIFICATE_FIELDS
            if certificate.get(field) is not None
        }
        if binding == "unbound" and sail_metadata:
            raise TeamAError(
                f"{mnemonic} is Sail-unbound but records Sail proof metadata"
            )
        if binding == "reviewed-capsule":
            artifact = certificate.get("sail_artifact")
            digest = certificate.get("sail_digest")
            theorem = certificate.get("sail_theorem")
            if (
                not isinstance(artifact, str)
                or not artifact
                or not isinstance(digest, str)
                or HEX_DIGEST.fullmatch(digest) is None
                or not isinstance(theorem, str)
                or not theorem
            ):
                raise TeamAError(
                    f"{mnemonic} reviewed Sail binding has incomplete "
                    "artifact, digest, or theorem metadata"
                )
            artifact_path = REPOSITORY_ROOT / artifact
            if (
                not artifact_path.is_file()
                or hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                != digest
            ):
                raise TeamAError(
                    f"{mnemonic} reviewed Sail artifact digest drifted"
                )
        if binding in ("generated-clause-input", "generated-retirement"):
            _check_generated_sail_binding(
                mnemonic,
                binding,
                certificate,
            )

    for field in THEOREM_FIELDS:
        values = [
            certificate[field]
            for certificate in certificates.values()
        ]
        if len(set(values)) != TEAM_A_OPCODE_COUNT:
            raise TeamAError(
                f"Team A certificates reuse {field}; every selector needs "
                "its own named theorem instance"
            )
    mutations = [
        certificate["mutation"]
        for certificate in certificates.values()
    ]
    if len(set(mutations)) != TEAM_A_OPCODE_COUNT:
        raise TeamAError(
            "Team A certificates reuse a mutation identity; every opcode "
            "needs a distinct load-bearing control"
        )
    for mnemonic, expected_binding in EXPECTED_PROOF_BINDINGS.items():
        certificate = certificates[mnemonic]
        for field, expected_value in expected_binding.items():
            if certificate[field] != expected_value:
                raise TeamAError(
                    f"{mnemonic} {field} is not its pinned selector-specific "
                    "proof binding"
                )

    generated_inputs = sum(
        certificate["sail_binding"]
        in ("generated-clause-input", "generated-retirement")
        for certificate in certificates.values()
    )
    generated_retirements = sum(
        certificate["sail_binding"] == "generated-retirement"
        for certificate in certificates.values()
    )
    reviewed = sum(
        certificate["sail_binding"] == "reviewed-capsule"
        for certificate in certificates.values()
    )
    expected_boundary = {
        "air_refinement_scope": "exact-production-local-program",
        "production_air_refinements": TEAM_A_OPCODE_COUNT,
        "axiom_bound_certificates": TEAM_A_OPCODE_COUNT,
        "timed_certificates": TEAM_A_OPCODE_COUNT,
        "proof_times_are_diagnostic": True,
        "generated_sail_clause_bindings": generated_inputs,
        "generated_sail_retirement_bindings": generated_retirements,
        "generated_sail_input_only_bindings":
            generated_inputs - generated_retirements,
        "reviewed_sail_capsule_bindings": reviewed,
        "unbound_sail_selectors":
            TEAM_A_OPCODE_COUNT - generated_inputs - reviewed,
        "full_generated_sail_step_framing": False,
        "publication_level_opcodes": 0,
        "whole_frontend_verified": False,
    }
    if load_certificates()["claim_boundary"] != expected_boundary:
        raise TeamAError("Team A certificate claim boundary drifted")
    return (
        f"team A coverage: {len(certificates)}/{TEAM_A_OPCODE_COUNT} "
        "production-AIR proved "
        f"of {FULL_OPCODE_COUNT} admitted opcodes; "
        f"Sail bindings generated-input={generated_inputs}, "
        f"generated-retirement={generated_retirements}, reviewed={reviewed}, "
        f"unbound={TEAM_A_OPCODE_COUNT - generated_inputs - reviewed}"
    )


def check_air_programs(
    air_program_ir_dir: Path | None = None,
) -> str:
    fresh_unsigned: dict[str, dict[str, Any]] | None = None
    if air_program_ir_dir is not None:
        try:
            fresh_unsigned = render.validate_air_program_export(
                air_program_ir_dir
            )
        except (OSError, RefinementError) as exc:
            raise TeamAError(
                "fresh unsigned AIR IR v2 export is invalid: "
                f"{exc}"
            ) from exc

    certificates = _certificates_by_mnemonic()
    for mnemonic, family, manifest_id in team_a_opcodes():
        path = AIR_PROGRAM_ROOT / f"{mnemonic}.air-ir-v2.json"
        if not path.is_file():
            raise TeamAError(
                f"{mnemonic} production AIR program is absent at {path}"
            )
        try:
            program = air_program.load_canonical(path)
        except RefinementError as exc:
            raise TeamAError(
                f"{mnemonic} production AIR program is invalid"
            ) from exc
        selector = program.get("opcode_selector")
        certificate = certificates[mnemonic]
        if (
            program.get("schema_version") != 2
            or program.get("kind")
            != "stwo-riscv-air-constraint-program"
            or program.get("family") != family
            or not isinstance(selector, dict)
            or selector.get("manifest_id") != manifest_id
            or selector.get("mnemonic") != mnemonic
            or program.get("content_digest") != certificate["air_digest"]
        ):
            raise TeamAError(
                f"{mnemonic} certificate does not bind its exact "
                "production AIR program"
            )
        if fresh_unsigned is not None:
            try:
                air_program.verify_production_binding(
                    program,
                    fresh_unsigned[mnemonic],
                    REPOSITORY_ROOT,
                )
            except (KeyError, OSError, RefinementError) as exc:
                raise TeamAError(
                    f"{mnemonic} packaged production AIR program does not "
                    "match the fresh unsigned AIR IR v2 export"
                ) from exc
    fresh_suffix = (
        "; all 24 match the exact fresh 46-program unsigned export"
        if fresh_unsigned is not None
        else ""
    )
    return (
        f"team A AIR bindings: {TEAM_A_OPCODE_COUNT} exact selector programs "
        f"match their certificates{fresh_suffix}"
    )


def check_theorems() -> str:
    declared = {
        certificate[field]
        for certificate in _certificates_by_mnemonic().values()
        for field in THEOREM_FIELDS
    }
    claimable: set[str] = set()
    for path in sorted(LEAN_ROOT.rglob("*.lean")):
        try:
            claimable |= shared.lean_claimable_theorems(
                path.read_text(encoding="utf-8"),
                str(path.relative_to(LEAN_ROOT)),
            )
        except shared.TeamBError as exc:
            raise TeamAError(str(exc)) from exc
    absent = sorted(declared - claimable)
    if absent:
        raise TeamAError(
            "Team A certificate index names absent or misattributed Lean "
            "theorems: " + ", ".join(absent)
        )
    return (
        f"team A certificates: {len(declared)} named theorem slots resolve "
        "to their Lean namespaces"
    )


def check_axiom_bindings(report: dict[str, list[str]]) -> str:
    """Match every certificate's axiom inventory to the live Lean audit."""
    certificates = _certificates_by_mnemonic()
    for mnemonic, certificate in certificates.items():
        theorem_names = [
            certificate[field]
            for field in THEOREM_FIELDS
        ]
        absent = sorted(set(theorem_names) - set(report))
        if absent:
            raise TeamAError(
                f"{mnemonic} axiom audit is missing named theorems: "
                + ", ".join(absent)
            )
        actual = sorted(
            {
                axiom
                for theorem in theorem_names
                for axiom in report[theorem]
            }
        )
        unapproved = sorted(set(actual) - APPROVED_AXIOMS)
        if unapproved:
            raise TeamAError(
                f"{mnemonic} depends on unapproved axioms: "
                + ", ".join(unapproved)
            )
        if certificate["axioms"] != actual:
            raise TeamAError(
                f"{mnemonic} certificate axiom inventory drifted; "
                f"recorded {certificate['axioms']!r}, live {actual!r}"
            )
    return (
        f"team A axiom bindings: {TEAM_A_OPCODE_COUNT} certificate "
        "inventories match the live kernel audit"
    )


def parse_audit_output(path: Path) -> dict[str, list[str]]:
    try:
        output = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TeamAError(f"axiom audit transcript is unreadable at {path}") from exc
    theorem_pattern = re.compile(
        r"^REFINEMENT_THEOREM (?P<theorem>RiscvRefinement\.\S+)$"
    )
    axiom_pattern = re.compile(
        r"^REFINEMENT_AXIOM "
        r"(?P<theorem>RiscvRefinement\.\S+) "
        r"(?P<axiom>\S+)$"
    )
    report: dict[str, list[str]] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        theorem_match = theorem_pattern.fullmatch(line)
        if theorem_match is not None:
            theorem = theorem_match.group("theorem")
            if theorem in report:
                raise TeamAError(
                    f"axiom audit repeated theorem record {theorem}"
                )
            report[theorem] = []
            continue
        axiom_match = axiom_pattern.fullmatch(line)
        if axiom_match is None:
            continue
        theorem = axiom_match.group("theorem")
        axiom = axiom_match.group("axiom")
        if theorem not in report:
            raise TeamAError(
                f"axiom audit records {axiom} before theorem {theorem}"
            )
        if axiom in report[theorem]:
            raise TeamAError(
                f"axiom audit repeats {axiom} for {theorem}"
            )
        report[theorem].append(axiom)
    if not report:
        raise TeamAError("axiom audit transcript contains no theorem records")
    return report


def _proof_times() -> dict[str, int]:
    """Measure each distinct Lean build target once.

    These timings are intentionally diagnostic.  The theorem identities,
    axiom inventories, AIR digests, and mutation controls carry the evidence;
    elapsed wall time only records that each complete target was checked in
    the indexing run.
    """
    timings: dict[str, int] = {}
    for target in sorted(set(PROOF_TIMING_TARGETS.values())):
        source = FORMAL_ROOT / (target.replace(".", "/") + ".lean")
        if not source.is_file():
            raise TeamAError(
                f"proof timing target {target} is absent at {source}"
            )
        started = time.perf_counter_ns()
        completed = subprocess.run(
            ("lake", "env", "lean", str(source.relative_to(FORMAL_ROOT))),
            cwd=FORMAL_ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        elapsed_ms = max(
            1,
            (time.perf_counter_ns() - started + 999_999) // 1_000_000,
        )
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout).strip()
            raise TeamAError(
                f"proof timing target {target} failed"
                + (f": {detail}" if detail else "")
            )
        if elapsed_ms > MAX_PROOF_TIME_MS:
            raise TeamAError(
                f"proof timing target {target} exceeded "
                f"{MAX_PROOF_TIME_MS}ms"
            )
        timings[target] = elapsed_ms
    return timings


def build_index(
    audit_report: dict[str, list[str]],
    proof_times: dict[str, int],
) -> dict[str, Any]:
    """Build the exact Team A index from live source-bound evidence."""
    expected = {mnemonic for mnemonic, _, _ in team_a_opcodes()}
    if (
        set(EXPECTED_PROOF_BINDINGS) != expected
        or set(PROOF_TIMING_TARGETS) != expected
    ):
        raise TeamAError(
            "proof and timing maps must exactly cover Team A before indexing"
        )
    expected_targets = set(PROOF_TIMING_TARGETS.values())
    if set(proof_times) != expected_targets:
        raise TeamAError(
            "measured proof targets do not exactly cover the pinned target set"
        )
    try:
        sail_payload = json.loads(
            GENERATED_SAIL_RECEIPT.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TeamAError("generated Sail receipt is unreadable") from exc
    sail_digest = sail_payload.get("canonical_digest")
    if (
        not isinstance(sail_digest, str)
        or HEX_DIGEST.fullmatch(sail_digest) is None
        or sail_digest != shared.canonical_digest(sail_payload)
    ):
        raise TeamAError("generated Sail receipt digest mismatch")
    try:
        sail_receipt = str(
            GENERATED_SAIL_RECEIPT.relative_to(REPOSITORY_ROOT)
        )
    except ValueError as exc:
        raise TeamAError(
            "generated Sail receipt is outside the repository"
        ) from exc

    certificates: list[dict[str, Any]] = []
    for mnemonic, family, manifest_id in team_a_opcodes():
        binding = (
            "generated-retirement"
            if mnemonic in GENERATED_SAIL_RETIREMENT_THEOREMS
            else "generated-clause-input"
        )
        sail_theorem = (
            GENERATED_SAIL_RETIREMENT_THEOREMS[mnemonic]
            if binding == "generated-retirement"
            else GENERATED_SAIL_INPUT_THEOREMS[mnemonic]
        )
        proof_binding = EXPECTED_PROOF_BINDINGS[mnemonic]
        theorem_names = [
            proof_binding[field]
            for field in THEOREM_FIELDS
        ]
        absent = sorted(set(theorem_names) - set(audit_report))
        if absent:
            raise TeamAError(
                f"{mnemonic} audit is missing named theorems: "
                + ", ".join(absent)
            )
        axioms = sorted(
            {
                axiom
                for theorem in theorem_names
                for axiom in audit_report[theorem]
            }
        )
        unapproved = sorted(set(axioms) - APPROVED_AXIOMS)
        if unapproved:
            raise TeamAError(
                f"{mnemonic} depends on unapproved axioms: "
                + ", ".join(unapproved)
            )
        air_path = AIR_PROGRAM_ROOT / f"{mnemonic}.air-ir-v2.json"
        try:
            air_payload = air_program.load_canonical(air_path)
        except RefinementError as exc:
            raise TeamAError(
                f"{mnemonic} production AIR program is invalid"
            ) from exc
        air_digest = air_payload.get("content_digest")
        if (
            not isinstance(air_digest, str)
            or HEX_DIGEST.fullmatch(air_digest) is None
        ):
            raise TeamAError(
                f"{mnemonic} production AIR program has no digest"
            )
        proof_target = PROOF_TIMING_TARGETS[mnemonic]
        certificate = {
            "air_digest": air_digest,
            "axioms": axioms,
            "family": family,
            "manifest_id": manifest_id,
            "mnemonic": mnemonic,
            **proof_binding,
            "proof_target": proof_target,
            "proof_time_ms": proof_times[proof_target],
            "sail_binding": binding,
            "sail_digest": sail_digest,
            "sail_receipt": sail_receipt,
            "sail_theorem": sail_theorem,
            "state": "air-proved",
        }
        certificates.append(certificate)

    payload: dict[str, Any] = {
        "schema_version": 1,
        "kind": "stwo-riscv-team-a-coverage",
        "issue": 136,
        "families": list(TEAM_A_FAMILIES),
        "claim_boundary": {
            "air_refinement_scope": "exact-production-local-program",
            "production_air_refinements": TEAM_A_OPCODE_COUNT,
            "axiom_bound_certificates": TEAM_A_OPCODE_COUNT,
            "timed_certificates": TEAM_A_OPCODE_COUNT,
            "proof_times_are_diagnostic": True,
            "generated_sail_clause_bindings": TEAM_A_OPCODE_COUNT,
            "generated_sail_retirement_bindings":
                len(GENERATED_SAIL_RETIREMENT_THEOREMS),
            "generated_sail_input_only_bindings":
                TEAM_A_OPCODE_COUNT
                - len(GENERATED_SAIL_RETIREMENT_THEOREMS),
            "reviewed_sail_capsule_bindings": 0,
            "unbound_sail_selectors": 0,
            "full_generated_sail_step_framing": False,
            "publication_level_opcodes": 0,
            "whole_frontend_verified": False,
        },
        "certificates": certificates,
    }
    payload["canonical_digest"] = shared.canonical_digest(payload)
    return payload


def write_index(audit_output: Path) -> str:
    payload = build_index(
        parse_audit_output(audit_output),
        _proof_times(),
    )
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True)
        + "\n"
    )
    temporary = CERTIFICATE_INDEX.with_suffix(".json.tmp")
    temporary.write_text(encoded, encoding="utf-8")
    temporary.replace(CERTIFICATE_INDEX)
    return (
        f"wrote {len(payload['certificates'])} Team A certificates to "
        f"{CERTIFICATE_INDEX.relative_to(REPOSITORY_ROOT)}"
    )


def check_raw_column_models() -> str:
    """Reject the audited canonical-by-construction soundness failure.

    A production refinement must quantify over raw output/witness columns and
    derive their architectural values from accepted constraints.  Calling the
    desired architectural result while constructing those columns proves only
    that an honest row is accepted.  It does not prove that every accepted row
    is honest.
    """
    checked = 0
    for relative, contract in RAW_COLUMN_MODELS.items():
        path = LEAN_ROOT / relative
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise TeamAError(
                f"raw-column model is unreadable at {relative}"
            ) from exc
        blocks = re.findall(
            r"\ndef columns\b.*?(?=\ndef evaluation\b)",
            source,
            flags=re.DOTALL,
        )
        if len(blocks) != contract["blocks"]:
            raise TeamAError(
                f"{relative} exposes {len(blocks)} column models, expected "
                f"{contract['blocks']}"
            )
        for block in blocks:
            for token in contract["forbidden"]:
                if token in block:
                    raise TeamAError(
                        f"{relative} constructs a production column from "
                        f"architectural helper {token!r}; model the raw "
                        "column and derive it from Acceptance instead"
                    )
        admission_forbidden = contract.get("admission_forbidden", ())
        if admission_forbidden:
            admission_blocks = re.findall(
                r"\nstructure Admission\b.*?(?=\ndef \w)",
                source,
                flags=re.DOTALL,
            )
            if len(admission_blocks) != 1:
                raise TeamAError(
                    f"{relative} exposes {len(admission_blocks)} Admission "
                    "models, expected 1"
                )
            for token in admission_forbidden:
                if token in admission_blocks[0]:
                    raise TeamAError(
                        f"{relative} assumes witness/output fact {token!r} "
                        "in Admission; derive it from Acceptance instead"
                    )
        checked += len(blocks)
    return (
        f"team A raw-column guard: {checked} high-risk family models do not "
        "bake architectural outputs into production columns"
    )


def inventory() -> str:
    check_coverage()
    certificates = _certificates_by_mnemonic()
    rows = [("id", "mnemonic", "family", "Sail", "mutation")]
    for mnemonic, family, manifest_id in team_a_opcodes():
        certificate = certificates[mnemonic]
        rows.append(
            (
                str(manifest_id),
                mnemonic,
                family,
                certificate["sail_binding"],
                certificate["mutation"],
            )
        )
    widths = [
        max(len(row[index]) for row in rows)
        for index in range(len(rows[0]))
    ]
    return "\n".join(
        "  ".join(
            value.ljust(width)
            for value, width in zip(row, widths)
        ).rstrip()
        for row in rows
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=(
            "write",
            "coverage",
            "air-programs",
            "theorems",
            "axioms",
            "raw-columns",
            "inventory",
            "check",
        ),
    )
    parser.add_argument(
        "--audit-output",
        type=Path,
        help="Lean AxiomAudit transcript, required by the axioms command",
    )
    parser.add_argument(
        "--air-program-ir-dir",
        type=Path,
        help=(
            "exact fresh 46-file unsigned production AIR IR v2 export, "
            "consumed by air-programs or check"
        ),
    )
    args = parser.parse_args(argv)
    try:
        if (
            args.air_program_ir_dir is not None
            and args.command not in ("air-programs", "check")
        ):
            raise TeamAError(
                "--air-program-ir-dir is only valid with air-programs or check"
            )
        if args.command == "write":
            if args.audit_output is None:
                raise TeamAError("write requires --audit-output")
            print(write_index(args.audit_output))
        elif args.command == "coverage":
            print(check_coverage())
        elif args.command == "air-programs":
            print(check_air_programs(args.air_program_ir_dir))
        elif args.command == "theorems":
            print(check_theorems())
        elif args.command == "axioms":
            if args.audit_output is None:
                raise TeamAError("axioms requires --audit-output")
            print(check_axiom_bindings(parse_audit_output(args.audit_output)))
        elif args.command == "raw-columns":
            print(check_raw_column_models())
        elif args.command == "inventory":
            print(inventory())
        else:
            print(check_coverage())
            print(check_air_programs(args.air_program_ir_dir))
            print(check_theorems())
            print(check_raw_column_models())
    except TeamAError as exc:
        print(f"team A gate failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
