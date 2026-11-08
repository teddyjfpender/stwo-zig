import RiscvRefinement.Publication.TeamB.Shifts.ImmLeft

/-! Bounded shift publication proof owner: ImmRight. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem immRightMovement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : ImmFixedConsequences row)
    (notLeft : row.semantic.kind ≠ .sll) :
    shiftRightEquations row.semantic.limbIndex row.semantic.multiplier
      row.semantic.signNat row.semantic.rs1Next row.semantic.result
      row.semantic.carry0 row.semantic.carry1
      row.semantic.carry2 row.semantic.carry3 := by
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  rcases limbIndexCases ranges.2 with limb | limb | limb | limb
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 238
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry1 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb0.toNat -
                M31.reduce row.semantic.carry0)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 fixed.carry1 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 246
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 254
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 263
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb3.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 265
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 267
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 269
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 274
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 276
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 278
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 281
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have root :=
        immConstraintRootZero row witness direct 282
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 284
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 287
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb1 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb1
          row.semantic.rs1Sign equation
    · have root :=
        immConstraintRootZero row witness direct 288
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have root :=
        immConstraintRootZero row witness direct 289
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation

end RiscvRefinement.Publication.TeamB.Shifts
