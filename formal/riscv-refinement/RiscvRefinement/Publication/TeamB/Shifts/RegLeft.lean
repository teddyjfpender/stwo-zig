import RiscvRefinement.Publication.TeamB.Shifts.ImmRight

/-! Bounded shift publication proof owner: RegLeft. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem regLeftMovement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : RegFixedConsequences row)
    (kind : row.semantic.kind = .sll) :
    shiftLeftEquations row.semantic.limbIndex row.semantic.multiplier
      row.semantic.rs1Next row.semantic.result
      row.semantic.carry0 row.semantic.carry1
      row.semantic.carry2 row.semantic.carry3 := by
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  rcases limbIndexCases ranges.2 with limb | limb | limb | limb
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          M31.reduce row.semantic.result.limb0.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 179
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have equation :
          (M31.reduce row.semantic.result.limb1.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 186
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 193
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry2 -
                M31.reduce 256 * M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.rs1Next.limb3.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 200
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 fixed.carry2 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · apply byteNatZero row.semantic.result.limb0
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 202
          (by simp [regConstraintRoots])
    · have equation :
          M31.reduce row.semantic.result.limb1.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 207
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 212
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 217
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · apply byteNatZero row.semantic.result.limb0
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 219
          (by simp [regConstraintRoots])
    · apply byteNatZero row.semantic.result.limb1
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 220
          (by simp [regConstraintRoots])
    · have equation :
          M31.reduce row.semantic.result.limb2.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 225
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 230
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · apply byteNatZero row.semantic.result.limb0
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 232
          (by simp [regConstraintRoots])
    · apply byteNatZero row.semantic.result.limb1
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 233
          (by simp [regConstraintRoots])
    · apply byteNatZero row.semantic.result.limb2
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 234
          (by simp [regConstraintRoots])
    · have equation :
          M31.reduce row.semantic.result.limb3.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 239
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)

end RiscvRefinement.Publication.TeamB.Shifts
