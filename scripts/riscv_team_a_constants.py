"""Constants and pinned evidence tables for the Team A gate."""

from __future__ import annotations

import re
from pathlib import Path

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
