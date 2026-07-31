import RiscvRefinement.Common

/-!
# Team A publication interface

This module gives the twenty-four Team A production selectors one closed,
injective identity space.  Family modules use `AcceptedAirCertificate` to
package the required implication:

* an admitted, accepted production row;
* its exact generated program/lookup projection;
* its canonical decode and local normalized retirement; and
* uniqueness of the manifest selector and of admission evidence.

The `sailTheoremIdentity` strings are intentionally metadata.  The generated
Sail project is checked in a separate Lean invocation and cannot be imported
by the `RiscvRefinement` Lake library.  A local certificate is therefore not
publication-complete until the receipt binds it to the named generated-Sail
normalization theorem.
-/

namespace RiscvRefinement.Publication.TeamA

/-- The exact Team A selector set, in production-manifest order. -/
inductive Selector where
  | add
  | sub
  | slt
  | sltu
  | xor
  | or
  | and
  | addi
  | slti
  | sltiu
  | xori
  | ori
  | andi
  | beq
  | bne
  | blt
  | bge
  | bltu
  | bgeu
  | jal
  | jalr
  | lui
  | auipc
  | fence
deriving DecidableEq, Repr

def Selector.manifestId : Selector → Nat
  | .add => 0
  | .sub => 1
  | .slt => 3
  | .sltu => 4
  | .xor => 5
  | .or => 8
  | .and => 9
  | .addi => 10
  | .slti => 11
  | .sltiu => 12
  | .xori => 13
  | .ori => 14
  | .andi => 15
  | .beq => 27
  | .bne => 28
  | .blt => 29
  | .bge => 30
  | .bltu => 31
  | .bgeu => 32
  | .jal => 33
  | .jalr => 34
  | .lui => 35
  | .auipc => 36
  | .fence => 45

def Selector.mnemonic : Selector → String
  | .add => "add"
  | .sub => "sub"
  | .slt => "slt"
  | .sltu => "sltu"
  | .xor => "xor"
  | .or => "or"
  | .and => "and"
  | .addi => "addi"
  | .slti => "slti"
  | .sltiu => "sltiu"
  | .xori => "xori"
  | .ori => "ori"
  | .andi => "andi"
  | .beq => "beq"
  | .bne => "bne"
  | .blt => "blt"
  | .bge => "bge"
  | .bltu => "bltu"
  | .bgeu => "bgeu"
  | .jal => "jal"
  | .jalr => "jalr"
  | .lui => "lui"
  | .auipc => "auipc"
  | .fence => "fence"

/--
The external generated-Sail normalization theorem expected by the publication
receipt.  This string is an identity, not proof evidence in this Lake library.
-/
def Selector.sailTheoremIdentity : Selector → String
  | .add => "LeanRV32IM.Functions.complete_ADD_normalizes"
  | .sub => "LeanRV32IM.Functions.complete_SUB_normalizes"
  | .slt => "LeanRV32IM.Functions.complete_SLT_normalizes"
  | .sltu => "LeanRV32IM.Functions.complete_SLTU_normalizes"
  | .xor => "LeanRV32IM.Functions.complete_XOR_normalizes"
  | .or => "LeanRV32IM.Functions.complete_OR_normalizes"
  | .and => "LeanRV32IM.Functions.complete_AND_normalizes"
  | .addi => "LeanRV32IM.Functions.complete_ADDI_normalizes"
  | .slti => "LeanRV32IM.Functions.complete_SLTI_normalizes"
  | .sltiu => "LeanRV32IM.Functions.complete_SLTIU_normalizes"
  | .xori => "LeanRV32IM.Functions.complete_XORI_normalizes"
  | .ori => "LeanRV32IM.Functions.complete_ORI_normalizes"
  | .andi => "LeanRV32IM.Functions.complete_ANDI_normalizes"
  | .beq => "LeanRV32IM.Functions.complete_BEQ_normalizes"
  | .bne => "LeanRV32IM.Functions.complete_BNE_normalizes"
  | .blt => "LeanRV32IM.Functions.complete_BLT_normalizes"
  | .bge => "LeanRV32IM.Functions.complete_BGE_normalizes"
  | .bltu => "LeanRV32IM.Functions.complete_BLTU_normalizes"
  | .bgeu => "LeanRV32IM.Functions.complete_BGEU_normalizes"
  | .jal => "LeanRV32IM.Functions.complete_JAL_normalizes"
  | .jalr => "LeanRV32IM.Functions.complete_JALR_normalizes"
  | .lui => "LeanRV32IM.Functions.complete_LUI_normalizes"
  | .auipc => "LeanRV32IM.Functions.complete_AUIPC_normalizes"
  | .fence => "LeanRV32IM.Functions.complete_FENCE_normalizes"

def Selector.localTheoremIdentity : Selector → String
  | .add =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.add_accepted_air_implies_retirement"
  | .sub =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.sub_accepted_air_implies_retirement"
  | .slt =>
      "RiscvRefinement.Publication.TeamA.Compare.slt_accepted_air_implies_retirement"
  | .sltu =>
      "RiscvRefinement.Publication.TeamA.Compare.sltu_accepted_air_implies_retirement"
  | .xor =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.xor_accepted_air_implies_retirement"
  | .or =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.or_accepted_air_implies_retirement"
  | .and =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.and_accepted_air_implies_retirement"
  | .addi =>
      "RiscvRefinement.Publication.TeamA.Pilots.addi_accepted_air_implies_retirement"
  | .slti =>
      "RiscvRefinement.Publication.TeamA.Compare.slti_accepted_air_implies_retirement"
  | .sltiu =>
      "RiscvRefinement.Publication.TeamA.Compare.sltiu_accepted_air_implies_retirement"
  | .xori =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.xori_accepted_air_implies_retirement"
  | .ori =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.ori_accepted_air_implies_retirement"
  | .andi =>
      "RiscvRefinement.Publication.TeamA.BaseAlu.andi_accepted_air_implies_retirement"
  | .beq =>
      "RiscvRefinement.Publication.TeamA.Branches.beq_accepted_air_implies_retirement"
  | .bne =>
      "RiscvRefinement.Publication.TeamA.Branches.bne_accepted_air_implies_retirement"
  | .blt =>
      "RiscvRefinement.Publication.TeamA.Branches.blt_accepted_air_implies_retirement"
  | .bge =>
      "RiscvRefinement.Publication.TeamA.Branches.bge_accepted_air_implies_retirement"
  | .bltu =>
      "RiscvRefinement.Publication.TeamA.Branches.bltu_accepted_air_implies_retirement"
  | .bgeu =>
      "RiscvRefinement.Publication.TeamA.Branches.bgeu_accepted_air_implies_retirement"
  | .jal =>
      "RiscvRefinement.Publication.TeamA.Control.jal_accepted_air_implies_retirement"
  | .jalr =>
      "RiscvRefinement.Publication.TeamA.Control.jalr_accepted_air_implies_retirement"
  | .lui =>
      "RiscvRefinement.Publication.TeamA.Pilots.lui_accepted_air_implies_retirement"
  | .auipc =>
      "RiscvRefinement.Publication.TeamA.Control.auipc_accepted_air_implies_retirement"
  | .fence =>
      "RiscvRefinement.Publication.TeamA.Control.fence_accepted_air_implies_retirement"

/--
The result of the local, kernel-checked half of FV-2.  `ExactProduction`
contains the exact production-program identity and complete ordered lookup
projection.  `SemanticRefinement` contains canonical decode and the
program/register/memory bindings.  The two explicit conclusions make the
architectural retirement and program tuple easy for downstream composition to
consume without unpacking family-specific structures.
-/
structure AcceptedAirCertificate
    (selector : Selector)
    (Admission Acceptance ExactProduction SemanticRefinement
      RetirementConclusion ProgramTupleConclusion : Prop) : Prop where
  admission : Admission
  acceptance : Acceptance
  exactProduction : ExactProduction
  semanticRefinement : SemanticRefinement
  retirement : RetirementConclusion
  exactProgramTuple : ProgramTupleConclusion
  selectorUnique :
    ∀ candidate : Selector,
      candidate.manifestId = selector.manifestId → candidate = selector
  admissionProofUnique :
    ∀ other : Admission, other = admission

theorem Selector.manifestId_injective :
    Function.Injective Selector.manifestId := by
  intro left right equality
  cases left <;> cases right <;>
    simp_all [Selector.manifestId]

theorem selectorUnique
    (selector candidate : Selector)
    (sameId : candidate.manifestId = selector.manifestId) :
    candidate = selector :=
  Selector.manifestId_injective sameId

theorem admissionProofUnique
    {Admission : Prop}
    (admission other : Admission) :
    other = admission :=
  Subsingleton.elim _ _

def selectors : List Selector := [
  .add, .sub, .slt, .sltu, .xor, .or, .and,
  .addi, .slti, .sltiu, .xori, .ori, .andi,
  .beq, .bne, .blt, .bge, .bltu, .bgeu,
  .jal, .jalr, .lui, .auipc, .fence
]

def manifestIds : List Nat :=
  selectors.map Selector.manifestId

def localTheoremIdentities : List String :=
  selectors.map Selector.localTheoremIdentity

/--
External identities awaited from the generated-Sail build.  Keeping this list
separate prevents its mere presence from being confused with a proof.
-/
def externalSailTheoremIdentities : List String :=
  selectors.map Selector.sailTheoremIdentity

theorem selectors_length : selectors.length = 24 := by decide

theorem selectors_nodup : selectors.Nodup := by decide

theorem manifestIds_exact :
    manifestIds =
      [0, 1, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15,
        27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 45] := by
  rfl

theorem manifestIds_length : manifestIds.length = 24 := by decide

theorem manifestIds_nodup : manifestIds.Nodup := by decide

theorem localTheoremIdentities_length :
    localTheoremIdentities.length = 24 := by decide

theorem localTheoremIdentities_nodup :
    localTheoremIdentities.Nodup := by decide

theorem externalSailTheoremIdentities_length :
    externalSailTheoremIdentities.length = 24 := by decide

theorem externalSailTheoremIdentities_nodup :
    externalSailTheoremIdentities.Nodup := by decide

end RiscvRefinement.Publication.TeamA
