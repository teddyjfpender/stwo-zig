import RiscvRefinement.Publication.TeamB.Shifts.FixedConsequences

/-! Bounded shift publication proof owner: ImmLeft. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem immLeftMovement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : ImmFixedConsequences row)
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
    · have root :=
        immConstraintRootZero row witness direct 170
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb0.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have root :=
        immConstraintRootZero row witness direct 177
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb1.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 184
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 191
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry2 -
                M31.reduce 256 * M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.rs1Next.limb3.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 fixed.carry2 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 193
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb0
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 198
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb1.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have root :=
        immConstraintRootZero row witness direct 203
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 208
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 210
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb0
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 211
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb1
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 216
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb2.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have root :=
        immConstraintRootZero row witness direct 221
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 223
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb0
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 224
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb1
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 225
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb2
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 230
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb3.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)

end RiscvRefinement.Publication.TeamB.Shifts
