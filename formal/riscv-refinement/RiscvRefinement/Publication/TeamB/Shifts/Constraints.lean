import RiscvRefinement.Publication.TeamB.Shifts.Model

/-! Bounded shift publication proof owner: Constraints. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem immSourceLimb0
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.rs1Next.limb0 = row.semantic.rs1Previous.limb0 := by
  have root :=
    immConstraintRootZero row witness direct 305
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    apply byteEq
    apply (M31.sub_eq_zero_iff _ _).mp
    simpa [
      immEvaluation, immProgram, kind,
      Programs.slli, Programs.srli, Programs.srai,
      Programs.slliSource, Programs.srliSource, Programs.sraiSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, immColumns,
      kindIs, boolM31,
    ] using root

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem immSourceReadOnly
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.rs1Next = row.semantic.rs1Previous := by
  apply WordBytes.eq_of_limbs
  · exact immSourceLimb0 row witness direct
  all_goals
    apply byteEq
    apply (M31.sub_eq_zero_iff _ _).mp
  · have root :=
      immConstraintRootZero row witness direct 307
        (by simp [immConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      immConstraintRootZero row witness direct 309
        (by simp [immConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      immConstraintRootZero row witness direct 311
        (by simp [immConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using root

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem regSourceReadOnly
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.semantic.rs1Next = row.semantic.rs1Previous := by
  apply WordBytes.eq_of_limbs <;> apply byteEq <;>
    apply (M31.sub_eq_zero_iff _ _).mp
  · have root :=
      regConstraintRootZero row witness direct 314
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 316
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 318
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 320
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem regSecondSourceReadOnly
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.rs2Next = row.rs2Previous := by
  apply WordBytes.eq_of_limbs <;> apply byteEq <;>
    apply (M31.sub_eq_zero_iff _ _).mp
  · have root :=
      regConstraintRootZero row witness direct 322
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 324
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 326
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 328
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root

structure DestinationConsequences (row : ShiftRow) : Prop where
  flag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  bytes : row.rdNext = if row.rdNonzero then row.result else WordBytes.zero

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem immDestinationConsequences
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    DestinationConsequences row.semantic := by
  have zeroRoot :=
    immConstraintRootZero row witness direct 293
      (by simp [immConstraintRoots])
  have inverseRoot :=
    immConstraintRootZero row witness direct 295
      (by simp [immConstraintRoots])
  have limb0 :=
    immConstraintRootZero row witness direct 297
      (by simp [immConstraintRoots])
  have limb1 :=
    immConstraintRootZero row witness direct 299
      (by simp [immConstraintRoots])
  have limb2 :=
    immConstraintRootZero row witness direct 301
      (by simp [immConstraintRoots])
  have limb3 :=
    immConstraintRootZero row witness direct 303
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have zeroEquation :
        bitVecM31 row.semantic.rd *
            (1 - boolM31 row.semantic.rdNonzero) = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using zeroRoot
    have inverseEquation :
        bitVecM31 row.semantic.rd * witness.destinationInverse -
            boolM31 row.semantic.rdNonzero = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using inverseRoot
    have e0 :
        bitVecM31 row.semantic.rdNext.limb0 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb0 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb0
    have e1 :
        bitVecM31 row.semantic.rdNext.limb1 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb1 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb1
    have e2 :
        bitVecM31 row.semantic.rdNext.limb2 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb2 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb2
    have e3 :
        bitVecM31 row.semantic.rdNext.limb3 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb3 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb3
    exact {
      flag :=
        Air.Bridge.TeamACommon.destinationFlag_of_equations
          row.semantic.rd row.semantic.rdNonzero witness.destinationInverse
          zeroEquation inverseEquation
      bytes :=
        Air.Bridge.TeamACommon.destinationBytes_of_equations
          row.semantic.rdNext row.semantic.result row.semantic.rdNonzero
          e0 e1 e2 e3
    }

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem regDestinationConsequences
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    DestinationConsequences row.semantic := by
  have zeroRoot :=
    regConstraintRootZero row witness direct 302
      (by simp [regConstraintRoots])
  have inverseRoot :=
    regConstraintRootZero row witness direct 304
      (by simp [regConstraintRoots])
  have limb0 :=
    regConstraintRootZero row witness direct 306
      (by simp [regConstraintRoots])
  have limb1 :=
    regConstraintRootZero row witness direct 308
      (by simp [regConstraintRoots])
  have limb2 :=
    regConstraintRootZero row witness direct 310
      (by simp [regConstraintRoots])
  have limb3 :=
    regConstraintRootZero row witness direct 312
      (by simp [regConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have zeroEquation :
        bitVecM31 row.semantic.rd *
            (1 - boolM31 row.semantic.rdNonzero) = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using zeroRoot
    have inverseEquation :
        bitVecM31 row.semantic.rd * witness.destinationInverse -
            boolM31 row.semantic.rdNonzero = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using inverseRoot
    have e0 :
        bitVecM31 row.semantic.rdNext.limb0 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb0 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb0
    have e1 :
        bitVecM31 row.semantic.rdNext.limb1 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb1 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb1
    have e2 :
        bitVecM31 row.semantic.rdNext.limb2 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb2 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb2
    have e3 :
        bitVecM31 row.semantic.rdNext.limb3 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb3 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb3
    exact {
      flag :=
        Air.Bridge.TeamACommon.destinationFlag_of_equations
          row.semantic.rd row.semantic.rdNonzero witness.destinationInverse
          zeroEquation inverseEquation
      bytes :=
        Air.Bridge.TeamACommon.destinationBytes_of_equations
          row.semantic.rdNext row.semantic.result row.semantic.rdNonzero
          e0 e1 e2 e3
    }

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem immIndexRanges
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4 := by
  have bitRoot :=
    immConstraintRootZero row witness direct 157
      (by simp [immConstraintRoots])
  have limbRoot :=
    immConstraintRootZero row witness direct 158
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have bitEquation :
        marker row.semantic.bitIndex 0 +
            marker row.semantic.bitIndex 1 +
            marker row.semantic.bitIndex 2 +
            marker row.semantic.bitIndex 3 +
            marker row.semantic.bitIndex 4 +
            marker row.semantic.bitIndex 5 +
            marker row.semantic.bitIndex 6 +
            marker row.semantic.bitIndex 7 -
          1 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using bitRoot
    have limbEquation :
        marker row.semantic.limbIndex 0 +
            marker row.semantic.limbIndex 1 +
            marker row.semantic.limbIndex 2 +
            marker row.semantic.limbIndex 3 -
          1 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limbRoot
    constructor
    · by_cases inside : row.semantic.bitIndex < 8
      · exact inside
      · exfalso
        have h0 : row.semantic.bitIndex ≠ 0 := by omega
        have h1 : row.semantic.bitIndex ≠ 1 := by omega
        have h2 : row.semantic.bitIndex ≠ 2 := by omega
        have h3 : row.semantic.bitIndex ≠ 3 := by omega
        have h4 : row.semantic.bitIndex ≠ 4 := by omega
        have h5 : row.semantic.bitIndex ≠ 5 := by omega
        have h6 : row.semantic.bitIndex ≠ 6 := by omega
        have h7 : row.semantic.bitIndex ≠ 7 := by omega
        simp [marker, h0, h1, h2, h3, h4, h5, h6, h7] at bitEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) bitEquation
    · by_cases inside : row.semantic.limbIndex < 4
      · exact inside
      · exfalso
        have h0 : row.semantic.limbIndex ≠ 0 := by omega
        have h1 : row.semantic.limbIndex ≠ 1 := by omega
        have h2 : row.semantic.limbIndex ≠ 2 := by omega
        have h3 : row.semantic.limbIndex ≠ 3 := by omega
        simp [marker, h0, h1, h2, h3] at limbEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) limbEquation

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem regIndexRanges
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4 := by
  have bitRoot :=
    regConstraintRootZero row witness direct 166
      (by simp [regConstraintRoots])
  have limbRoot :=
    regConstraintRootZero row witness direct 167
      (by simp [regConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have bitEquation :
        marker row.semantic.bitIndex 0 +
            marker row.semantic.bitIndex 1 +
            marker row.semantic.bitIndex 2 +
            marker row.semantic.bitIndex 3 +
            marker row.semantic.bitIndex 4 +
            marker row.semantic.bitIndex 5 +
            marker row.semantic.bitIndex 6 +
            marker row.semantic.bitIndex 7 -
          1 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using bitRoot
    have limbEquation :
        marker row.semantic.limbIndex 0 +
            marker row.semantic.limbIndex 1 +
            marker row.semantic.limbIndex 2 +
            marker row.semantic.limbIndex 3 -
          1 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limbRoot
    constructor
    · by_cases inside : row.semantic.bitIndex < 8
      · exact inside
      · exfalso
        have h0 : row.semantic.bitIndex ≠ 0 := by omega
        have h1 : row.semantic.bitIndex ≠ 1 := by omega
        have h2 : row.semantic.bitIndex ≠ 2 := by omega
        have h3 : row.semantic.bitIndex ≠ 3 := by omega
        have h4 : row.semantic.bitIndex ≠ 4 := by omega
        have h5 : row.semantic.bitIndex ≠ 5 := by omega
        have h6 : row.semantic.bitIndex ≠ 6 := by omega
        have h7 : row.semantic.bitIndex ≠ 7 := by omega
        simp [marker, h0, h1, h2, h3, h4, h5, h6, h7] at bitEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) bitEquation
    · by_cases inside : row.semantic.limbIndex < 4
      · exact inside
      · exfalso
        have h0 : row.semantic.limbIndex ≠ 0 := by omega
        have h1 : row.semantic.limbIndex ≠ 1 := by omega
        have h2 : row.semantic.limbIndex ≠ 2 := by omega
        have h3 : row.semantic.limbIndex ≠ 3 := by omega
        simp [marker, h0, h1, h2, h3] at limbEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) limbEquation

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem immSignIsLogicalZero
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.kind ≠ ShiftKind.sra → row.semantic.rs1Sign = false := by
  have root :=
    immConstraintRootZero row witness direct 132
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          immEvaluation, immProgram, kind, sign,
          Programs.slli, Programs.srli, Programs.srai,
          Programs.slliSource, Programs.srliSource, Programs.sraiSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          immEvaluation, immProgram, kind, sign,
          Programs.slli, Programs.srli, Programs.srai,
          Programs.slliSource, Programs.srliSource, Programs.sraiSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro notSra
    exact False.elim (notSra rfl)

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem regSignIsLogicalZero
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.semantic.kind ≠ ShiftKind.sra → row.semantic.rs1Sign = false := by
  have root :=
    regConstraintRootZero row witness direct 141
      (by simp [regConstraintRoots])
  cases kind : row.semantic.kind
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          regEvaluation, regProgram, kind, sign,
          Programs.sll, Programs.srl, Programs.sra,
          Programs.sllSource, Programs.srlSource, Programs.sraSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          regEvaluation, regProgram, kind, sign,
          Programs.sll, Programs.srl, Programs.sra,
          Programs.sllSource, Programs.srlSource, Programs.sraSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro notSra
    exact False.elim (notSra rfl)

private theorem bitIndexCases {index : Nat} (bound : index < 8) :
    index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
      index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 := by
  omega

theorem limbIndexCases {index : Nat} (bound : index < 4) :
    index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 := by
  omega

theorem bitMarkerMultiplier
    (index : Nat)
    (bound : index < 8) :
    marker index 0 +
          marker index 1 * M31.reduce 2 +
          marker index 2 * M31.reduce 4 +
          marker index 3 * M31.reduce 8 +
          marker index 4 * M31.reduce 16 +
          marker index 5 * M31.reduce 32 +
          marker index 6 * M31.reduce 64 +
          marker index 7 * M31.reduce 128 =
      M31.reduce (2 ^ index) := by
  rcases bitIndexCases bound with h | h | h | h | h | h | h | h <;>
    subst index <;> decide

theorem bitMarkerIndex
    (index : Nat)
    (bound : index < 8) :
    marker index 0 * M31.reduce 0 +
          marker index 1 * M31.reduce 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 +
          marker index 4 * M31.reduce 4 +
          marker index 5 * M31.reduce 5 +
          marker index 6 * M31.reduce 6 +
          marker index 7 * M31.reduce 7 =
      M31.reduce index := by
  rcases bitIndexCases bound with h | h | h | h | h | h | h | h <;>
    subst index <;> decide

theorem limbMarkerIndex
    (index : Nat)
    (bound : index < 4) :
    marker index 0 * M31.reduce 0 +
          marker index 1 * M31.reduce 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 =
      M31.reduce index := by
  rcases limbIndexCases bound with h | h | h | h <;>
    subst index <;> decide

theorem bitMarkerIndex'
    (index : Nat)
    (bound : index < 8) :
    marker index 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 +
          marker index 4 * M31.reduce 4 +
          marker index 5 * M31.reduce 5 +
          marker index 6 * M31.reduce 6 +
          marker index 7 * M31.reduce 7 =
      M31.reduce index := by
  simpa using bitMarkerIndex index bound

theorem limbMarkerIndex'
    (index : Nat)
    (bound : index < 4) :
    marker index 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 =
      M31.reduce index := by
  simpa using limbMarkerIndex index bound

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem immImmediateBinds
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (admission : ImmAdmission row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.immTruncated = row.semantic.shiftAmount := by
  have ranges := immIndexRanges row witness direct
  have root :=
    immConstraintRootZero row witness direct 312
      (by simp [immConstraintRoots])
  have fieldEquation :
      M31.reduce row.immTruncated -
          M31.reduce row.semantic.shiftAmount = 0 := by
    cases kind : row.semantic.kind
    all_goals
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, ShiftRow.shiftAmount,
        limbMarkerIndex' row.semantic.limbIndex ranges.2,
        bitMarkerIndex' row.semantic.bitIndex ranges.1,
        Air.Bridge.TeamACommon.reduceMul,
        Air.Bridge.TeamACommon.reduceAdd,
        Nat.mul_comm,
      ] using root
  apply
    (M31.reduce_injective_of_lt
      admission.immediateCanonical
      (by
        have h := ranges
        simp only [ShiftRow.shiftAmount]
        simp [M31.modulus_eq]
        omega)).mp
  exact (M31.sub_eq_zero_iff _ _).mp fieldEquation

end RiscvRefinement.Publication.TeamB.Shifts
