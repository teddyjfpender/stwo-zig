import RiscvRefinement.Publication.TeamB.Shifts.RegLeft

/-! Bounded shift publication proof owner: RegRight. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem regRightMovement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : RegFixedConsequences row)
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
    · have equation :
          (M31.reduce row.semantic.carry1 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb0.toNat -
                M31.reduce row.semantic.carry0)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 247
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 247
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 fixed.carry1 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 255
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 255
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 263
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 263
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have equation :
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
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 272
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 272
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 274
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 274
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 276
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 276
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have equation :
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
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 278
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 278
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 283
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 283
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 285
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 285
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have equation :
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
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 287
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 287
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 290
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 290
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 291
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 291
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
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
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 293
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 293
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have equation :
          bitVecM31 row.semantic.result.limb1 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 296
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 296
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb1
          row.semantic.rs1Sign equation
    · have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 297
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 297
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 298
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 298
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation

end RiscvRefinement.Publication.TeamB.Shifts
