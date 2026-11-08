import RiscvRefinement.Publication.TeamB.Shifts.Arithmetic

/-! Bounded shift publication proof owner: FixedConsequences. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

structure ImmFixedConsequences (row : ShiftsImmRow) : Prop where
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2)
  carry0 : row.semantic.carry0 < row.semantic.multiplier
  carry1 : row.semantic.carry1 < row.semantic.multiplier
  carry2 : row.semantic.carry2 < row.semantic.multiplier
  carry3 : row.semantic.carry3 < row.semantic.multiplier
  signLower :
    row.semantic.kind = .sra →
      128 * row.semantic.signNat ≤ row.semantic.rs1Next.limb3.toNat
  signUpper :
    row.semantic.kind = .sra →
      row.semantic.rs1Next.limb3.toNat <
        128 * row.semantic.signNat + 128

structure RegFixedConsequences (row : ShiftsRegRow) : Prop where
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  carry0 : row.semantic.carry0 < row.semantic.multiplier
  carry1 : row.semantic.carry1 < row.semantic.multiplier
  carry2 : row.semantic.carry2 < row.semantic.multiplier
  carry3 : row.semantic.carry3 < row.semantic.multiplier
  shiftAmountBinds :
    ∃ high,
      high ≤ 7 ∧
        row.rs2Next.limb0.toNat =
          32 * high + row.semantic.shiftAmount
  signLower :
    row.semantic.kind = .sra →
      128 * row.semantic.signNat ≤ row.semantic.rs1Next.limb3.toNat
  signUpper :
    row.semantic.kind = .sra →
      row.semantic.rs1Next.limb3.toNat <
        128 * row.semantic.signNat + 128

theorem immFixedConsequences
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (admission : ImmAdmission row)
    (direct : (immEvaluation row witness).constraintsHold = true)
    (fixed : (immEvaluation row witness).fixedLookupsHold = true) :
    ImmFixedConsequences row := by
  have ranges := immIndexRanges row witness direct
  have projection := imm_exactFixedProjection row witness ranges.1
  have multiplierPositive := row.semantic.multiplier_pos
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  refine {
    sourceClock :=
      validClockOfGap row.clock 1 row.rs1PreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.sourcePreviousBound
        (clockGapBoundOfLookup
          (immEvaluation row witness) 72 1 row.clock row.rs1PreviousClock
          fixed projection.sourceClock)
    destinationClock :=
      validClockOfGap row.clock 2 row.rdPreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.destinationPreviousBound
        (clockGapBoundOfLookup
          (immEvaluation row witness) 81 2 row.clock row.rdPreviousClock
          fixed projection.destinationClock)
    carry0 :=
      carryLtMultiplier row.semantic.carry0 row.semantic.multiplier
        admission.carry0Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 73 row.semantic.carry0
          row.semantic.multiplier fixed projection.carry0)
    carry1 :=
      carryLtMultiplier row.semantic.carry1 row.semantic.multiplier
        admission.carry1Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 74 row.semantic.carry1
          row.semantic.multiplier fixed projection.carry1)
    carry2 :=
      carryLtMultiplier row.semantic.carry2 row.semantic.multiplier
        admission.carry2Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 75 row.semantic.carry2
          row.semantic.multiplier fixed projection.carry2)
    carry3 :=
      carryLtMultiplier row.semantic.carry3 row.semantic.multiplier
        admission.carry3Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 76 row.semantic.carry3
          row.semantic.multiplier fixed projection.carry3)
    signLower := ?_
    signUpper := ?_
  }
  · intro kind
    exact
      (signBoundsOfLookup (immEvaluation row witness) 82 row.semantic
        kind fixed projection.sign).1
  · intro kind
    exact
      (signBoundsOfLookup (immEvaluation row witness) 82 row.semantic
        kind fixed projection.sign).2

theorem regFixedConsequences
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (admission : RegAdmission row)
    (direct : (regEvaluation row witness).constraintsHold = true)
    (fixed : (regEvaluation row witness).fixedLookupsHold = true) :
    RegFixedConsequences row := by
  have ranges := regIndexRanges row witness direct
  have projection :=
    reg_exactFixedProjection row witness ranges.1 ranges.2
  have multiplierPositive := row.semantic.multiplier_pos
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  refine {
    sourceClock :=
      validClockOfGap row.clock 1 row.rs1PreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.sourcePreviousBound
        (clockGapBoundOfLookup
          (regEvaluation row witness) 75 1 row.clock row.rs1PreviousClock
          fixed projection.sourceClock)
    secondSourceClock :=
      validClockOfGap row.clock 2 row.rs2PreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.secondSourcePreviousBound
        (clockGapBoundOfLookup
          (regEvaluation row witness) 78 2 row.clock row.rs2PreviousClock
          fixed projection.secondSourceClock)
    destinationClock :=
      validClockOfGap row.clock 3 row.rdPreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.destinationPreviousBound
        (clockGapBoundOfLookup
          (regEvaluation row witness) 88 3 row.clock row.rdPreviousClock
          fixed projection.destinationClock)
    carry0 :=
      carryLtMultiplier row.semantic.carry0 row.semantic.multiplier
        admission.carry0Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 80 row.semantic.carry0
          row.semantic.multiplier fixed projection.carry0)
    carry1 :=
      carryLtMultiplier row.semantic.carry1 row.semantic.multiplier
        admission.carry1Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 81 row.semantic.carry1
          row.semantic.multiplier fixed projection.carry1)
    carry2 :=
      carryLtMultiplier row.semantic.carry2 row.semantic.multiplier
        admission.carry2Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 82 row.semantic.carry2
          row.semantic.multiplier fixed projection.carry2)
    carry3 :=
      carryLtMultiplier row.semantic.carry3 row.semantic.multiplier
        admission.carry3Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 83 row.semantic.carry3
          row.semantic.multiplier fixed projection.carry3)
    shiftAmountBinds := ?_
    signLower := ?_
    signUpper := ?_
  }
  · let shift : Fin 32 := {
      val := row.semantic.shiftAmount
      isLt := by
        simp only [ShiftRow.shiftAmount]
        omega
    }
    obtain ⟨high, equality⟩ :=
      amountMaskUnique row.rs2Next.limb0 shift
        (amountMaskBoundOfLookup row witness fixed projection.amountMask)
    exact ⟨high.val, by omega, by simpa [shift] using equality⟩
  · intro kind
    exact
      (signBoundsOfLookup (regEvaluation row witness) 89 row.semantic
        kind fixed projection.sign).1
  · intro kind
    exact
      (signBoundsOfLookup (regEvaluation row witness) 89 row.semantic
        kind fixed projection.sign).2

end RiscvRefinement.Publication.TeamB.Shifts
