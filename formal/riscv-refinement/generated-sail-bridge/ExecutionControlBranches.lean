import ExecutionControl

/-!
# Constructive execution for generated conditional branches

The BEQ/BNE and ordered-comparison families instantiate the shared exact
branch constructor without accepting generated outcomes or trace premises.
-/

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication.ExecutionControl

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

theorem signedLess_eq_generated
    (left right : BitVec 32) :
    RiscvRefinement.Air.Bridge.Branches.Lt.signedLess left right =
      Functions.zopz0zI_s left right := by
  have leftBound := left.isLt
  have rightBound := right.isLt
  cases leftSign : left.msb <;> cases rightSign : right.msb
  · simp [
      RiscvRefinement.Air.Bridge.Branches.Lt.signedLess,
      Functions.zopz0zI_s,
      BitVec.toInt_eq_msb_cond,
      leftSign,
      rightSign,
    ]
  · have leftHalf :=
      BitVec.msb_eq_false_iff_two_mul_lt.mp leftSign
    have rightHalf :=
      BitVec.msb_eq_true_iff_two_mul_ge.mp rightSign
    simp [
      RiscvRefinement.Air.Bridge.Branches.Lt.signedLess,
      Functions.zopz0zI_s,
      BitVec.toInt_eq_msb_cond,
      leftSign,
      rightSign,
    ] <;> omega
  · have leftHalf :=
      BitVec.msb_eq_true_iff_two_mul_ge.mp leftSign
    have rightHalf :=
      BitVec.msb_eq_false_iff_two_mul_lt.mp rightSign
    simp [
      RiscvRefinement.Air.Bridge.Branches.Lt.signedLess,
      Functions.zopz0zI_s,
      BitVec.toInt_eq_msb_cond,
      leftSign,
      rightSign,
    ] <;> omega
  · simp [
      RiscvRefinement.Air.Bridge.Branches.Lt.signedLess,
      Functions.zopz0zI_s,
      BitVec.toInt_eq_msb_cond,
      leftSign,
      rightSign,
    ]

theorem signedGe_eq_not_less
    (left right : BitVec 32) :
    Functions.zopz0zKzJ_s left right =
      !Functions.zopz0zI_s left right := by
  rw [Bool.eq_iff_iff]
  simp [Functions.zopz0zKzJ_s, Functions.zopz0zI_s]

theorem unsignedGe_eq_not_less
    (left right : BitVec 32) :
    Functions.zopz0zKzJ_u left right =
      !Functions.zopz0zI_u left right := by
  rw [Bool.eq_iff_iff]
  simp [
    Functions.zopz0zKzJ_u,
    Functions.zopz0zI_u,
    Sail.BitVec.toNatInt,
  ]

/-- Constructive generated execution for the BEQ/BNE production family. -/
theorem eq_branch_constructive
    (kind : RiscvRefinement.Air.Bridge.Branches.Eq.Kind)
    (row : RiscvRefinement.Opcodes.Branches.Eq.RawRow)
    (witness : RiscvRefinement.Opcodes.Branches.Eq.RawWitness row)
    (kindBinds : row.kind = kind)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (stateBindings :
      GeneratedInstructionStateBindings row.pc
          (Functions.encodeBranchControl (eqBranchDecodeKind kind)
            row.immediateEncoded row.rs2 row.rs1) initial ∧
        GeneratedReadPairStateBindings initial row.rs1 row.rs2
          row.rs1Previous.word row.rs2Previous.word)
    (profileAdmission :
      GeneratedInstructionProfileAdmission row.pc
        (Functions.encodeBranchControl (eqBranchDecodeKind kind)
          row.immediateEncoded row.rs2 row.rs1) initial)
    (localRefinement :
      RiscvRefinement.Opcodes.Branches.Eq.RawRefinement row witness) :
    Functions.ConstructiveGeneratedExecution stepNo
      (Functions.encodeBranchControl (eqBranchDecodeKind kind)
        row.immediateEncoded row.rs2 row.rs1)
      (Functions.decodedBranchControl (eqBranchDecodeKind kind)
        row.immediateEncoded row.rs2 row.rs1)
      (Functions.completeBaseExecution row.pc
        (Functions.execute
          (Functions.decodedBranchControl (eqBranchDecodeKind kind)
            row.immediateEncoded row.rs2 row.rs1)))
      (Functions.normalizedBranchCompletion row.pc
        (do
          let source1 ← Functions.rX_bits (.Regidx row.rs1)
          let source2 ← Functions.rX_bits (.Regidx row.rs2)
          pure (eqBranchCompute kind source1 source2))
        (do
          let currentPc ← Sail.readReg Register.PC
          pure (currentPc + Functions.sign_extend (m := 32)
            (RiscvRefinement.Decode.branchImmediate
              row.immediateEncoded))))
      initial
      (RiscvRefinement.Publication.TeamA.Branches.Eq.normalizedRetirement
        row) := by
  have conditionMatches :
      eqBranchCompute kind row.rs1Previous.word row.rs2Previous.word =
        RiscvRefinement.Opcodes.Branches.Eq.rawExpectedTaken row := by
    cases kind <;>
      simp [
        eqBranchCompute,
        RiscvRefinement.Opcodes.Branches.Eq.rawExpectedTaken,
        kindBinds,
        localRefinement.sourcesReadOnly.1,
        localRefinement.sourcesReadOnly.2,
      ] <;>
      rw [Bool.eq_iff_iff] <;>
      simp
  have targetEq := generated_branch_target_eq row.pc row.immediateEncoded
    localRefinement.targetNoWrap
  have retirementEq :
      RiscvRefinement.Publication.TeamA.Branches.Eq.normalizedRetirement row = {
        nextPc :=
          if RiscvRefinement.Opcodes.Branches.Eq.rawExpectedTaken row then
            row.pc + Functions.sign_extend (m := 32)
              (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          else RiscvRefinement.nextPc row.pc
        write := none
        read := none
        store := none
      } := by
    simp [
      RiscvRefinement.Publication.TeamA.Branches.Eq.normalizedRetirement,
      RiscvRefinement.Air.Bridge.Branches.selectedPc,
      targetEq,
    ]
  apply branch_constructive stepNo
    (Functions.encodeBranchControl (eqBranchDecodeKind kind)
      row.immediateEncoded row.rs2 row.rs1)
    (Functions.decodedBranchControl (eqBranchDecodeKind kind)
      row.immediateEncoded row.rs2 row.rs1)
    row.pc
    (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
    row.rs1 row.rs2 row.rs1Previous.word row.rs2Previous.word
    (eqBranchCompute kind)
    (RiscvRefinement.Opcodes.Branches.Eq.rawExpectedTaken row)
    (RiscvRefinement.Publication.TeamA.Branches.Eq.normalizedRetirement row)
    initial stateBindings.1.programCounter stateBindings.1.landingPadClear
    stateBindings.2.sourceOne stateBindings.2.sourceTwo
    stateBindings.1.decodeState
    profileAdmission.instructionAligned
  · simpa [RiscvRefinement.Air.Bridge.Branches.immediate] using
      localRefinement.targetAligned
  · exact conditionMatches
  · cases kind
    · simpa [eqBranchDecodeKind, eqBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.execute_BTYPE_BEQ_eq
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          (.Regidx row.rs2) (.Regidx row.rs1)
    · simpa [eqBranchDecodeKind, eqBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.execute_BTYPE_BNE_eq
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          (.Regidx row.rs2) (.Regidx row.rs1)
  · cases kind
    · simpa [eqBranchDecodeKind, eqBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.complete_BEQ_normalizes row.pc
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          row.rs2 row.rs1
    · simpa [eqBranchDecodeKind, eqBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.complete_BNE_normalizes row.pc
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          row.rs2 row.rs1
  · exact retirementEq

/-- Constructive generated execution for BLT/BGE/BLTU/BGEU. -/
theorem lt_branch_constructive
    (kind : RiscvRefinement.Air.Bridge.Branches.Lt.Kind)
    (row : RiscvRefinement.Opcodes.Branches.Lt.RawRow)
    (witness : RiscvRefinement.Opcodes.Branches.Lt.RawWitness row)
    (kindBinds : row.kind = kind)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (stateBindings :
      GeneratedInstructionStateBindings row.pc
          (Functions.encodeBranchControl (ltBranchDecodeKind kind)
            row.immediateEncoded row.rs2 row.rs1) initial ∧
        GeneratedReadPairStateBindings initial row.rs1 row.rs2
          row.rs1Previous.word row.rs2Previous.word)
    (profileAdmission :
      GeneratedInstructionProfileAdmission row.pc
        (Functions.encodeBranchControl (ltBranchDecodeKind kind)
          row.immediateEncoded row.rs2 row.rs1) initial)
    (localRefinement :
      RiscvRefinement.Opcodes.Branches.Lt.RawRefinement row witness) :
    Functions.ConstructiveGeneratedExecution stepNo
      (Functions.encodeBranchControl (ltBranchDecodeKind kind)
        row.immediateEncoded row.rs2 row.rs1)
      (Functions.decodedBranchControl (ltBranchDecodeKind kind)
        row.immediateEncoded row.rs2 row.rs1)
      (Functions.completeBaseExecution row.pc
        (Functions.execute
          (Functions.decodedBranchControl (ltBranchDecodeKind kind)
            row.immediateEncoded row.rs2 row.rs1)))
      (Functions.normalizedBranchCompletion row.pc
        (do
          let source1 ← Functions.rX_bits (.Regidx row.rs1)
          let source2 ← Functions.rX_bits (.Regidx row.rs2)
          pure (ltBranchCompute kind source1 source2))
        (do
          let currentPc ← Sail.readReg Register.PC
          pure (currentPc + Functions.sign_extend (m := 32)
            (RiscvRefinement.Decode.branchImmediate
              row.immediateEncoded))))
      initial
      (RiscvRefinement.Publication.TeamA.Branches.Lt.normalizedRetirement
        row) := by
  have conditionMatches :
      ltBranchCompute kind row.rs1Previous.word row.rs2Previous.word =
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken row := by
    cases kind
    · simp [
        ltBranchCompute,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedLess,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.lessOpcode,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.signed,
        kindBinds,
        localRefinement.sourcesReadOnly.1,
        localRefinement.sourcesReadOnly.2,
        signedLess_eq_generated,
      ] <;>
      rw [Bool.eq_iff_iff] <;>
      simp
    · simp [
        ltBranchCompute,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedLess,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.lessOpcode,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.signed,
        kindBinds,
        localRefinement.sourcesReadOnly.1,
        localRefinement.sourcesReadOnly.2,
        signedLess_eq_generated,
        signedGe_eq_not_less,
      ] <;>
      rw [Bool.eq_iff_iff] <;>
      simp
    · simp [
        ltBranchCompute,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedLess,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.lessOpcode,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.signed,
        kindBinds,
        localRefinement.sourcesReadOnly.1,
        localRefinement.sourcesReadOnly.2,
        Functions.zopz0zI_u,
        Sail.BitVec.toNatInt,
      ] <;>
      rw [Bool.eq_iff_iff] <;>
      simp
    · simp [
        ltBranchCompute,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken,
        RiscvRefinement.Opcodes.Branches.Lt.rawExpectedLess,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.lessOpcode,
        RiscvRefinement.Air.Bridge.Branches.Lt.Kind.signed,
        kindBinds,
        localRefinement.sourcesReadOnly.1,
        localRefinement.sourcesReadOnly.2,
        Functions.zopz0zI_u,
        Sail.BitVec.toNatInt,
        unsignedGe_eq_not_less,
      ] <;>
      rw [Bool.eq_iff_iff] <;>
      simp
  have targetEq := generated_branch_target_eq row.pc row.immediateEncoded
    localRefinement.targetNoWrap
  have retirementEq :
      RiscvRefinement.Publication.TeamA.Branches.Lt.normalizedRetirement row = {
        nextPc :=
          if RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken row then
            row.pc + Functions.sign_extend (m := 32)
              (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          else RiscvRefinement.nextPc row.pc
        write := none
        read := none
        store := none
      } := by
    simp [
      RiscvRefinement.Publication.TeamA.Branches.Lt.normalizedRetirement,
      RiscvRefinement.Air.Bridge.Branches.selectedPc,
      targetEq,
    ]
  apply branch_constructive stepNo
    (Functions.encodeBranchControl (ltBranchDecodeKind kind)
      row.immediateEncoded row.rs2 row.rs1)
    (Functions.decodedBranchControl (ltBranchDecodeKind kind)
      row.immediateEncoded row.rs2 row.rs1)
    row.pc
    (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
    row.rs1 row.rs2 row.rs1Previous.word row.rs2Previous.word
    (ltBranchCompute kind)
    (RiscvRefinement.Opcodes.Branches.Lt.rawExpectedTaken row)
    (RiscvRefinement.Publication.TeamA.Branches.Lt.normalizedRetirement row)
    initial stateBindings.1.programCounter stateBindings.1.landingPadClear
    stateBindings.2.sourceOne stateBindings.2.sourceTwo
    stateBindings.1.decodeState
    profileAdmission.instructionAligned
  · simpa [RiscvRefinement.Air.Bridge.Branches.immediate] using
      localRefinement.targetAligned
  · exact conditionMatches
  · cases kind
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.execute_BTYPE_BLT_eq
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          (.Regidx row.rs2) (.Regidx row.rs1)
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.execute_BTYPE_BGE_eq
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          (.Regidx row.rs2) (.Regidx row.rs1)
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.execute_BTYPE_BLTU_eq
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          (.Regidx row.rs2) (.Regidx row.rs1)
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.execute_BTYPE_BGEU_eq
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          (.Regidx row.rs2) (.Regidx row.rs1)
  · cases kind
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.complete_BLT_normalizes row.pc
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          row.rs2 row.rs1
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.complete_BGE_normalizes row.pc
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          row.rs2 row.rs1
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.complete_BLTU_normalizes row.pc
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          row.rs2 row.rs1
    · simpa [ltBranchDecodeKind, ltBranchCompute,
          Functions.decodedBranchControl, Functions.generatedBranchOp] using
        Functions.complete_BGEU_normalizes row.pc
          (RiscvRefinement.Decode.branchImmediate row.immediateEncoded)
          row.rs2 row.rs1
  · exact retirementEq


end LeanRV32IM.Publication.ExecutionControl
