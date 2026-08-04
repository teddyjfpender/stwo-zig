import RiscvRefinement.Publication.TeamB.MulhDiv.Division.NegCarryStep

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family

namespace Division

set_option maxRecDepth 30000 in
opaque initialNegCarryStep
    (row : Row)
    (root :
      negCarry0Field row * (negCarry0Field row - 1) = 0) :
    ∃ next : Bool,
      false.toNat + row.remainder.limb0.toNat +
            row.remainderAbs.limb0.toNat =
          256 * next.toNat ∧
      negCarry0Field row = boolM31 next ∧
      (next = false ∨ next = true) := by
  have carryDefinition :
      negCarry0Field row =
        (boolM31 false +
            bitVecM31 row.remainder.limb0 +
            bitVecM31 row.remainderAbs.limb0) *
          M31.reduce 8388608 := by
    simp [negCarry0Field, boolM31]
  have falseRoot :
      (negCarry0Field row - boolM31 false) *
          (negCarry0Field row - 1) = 0 := by
    simpa only [boolM31, M31.sub_zero] using root
  exact
    negCarryStep false
      row.remainder.limb0 row.remainderAbs.limb0
      (negCarry0Field row) carryDefinition falseRoot


set_option maxRecDepth 30000 in
theorem negationRecurrenceOfEquations
    (row : Row)
    (witness : Witness row)
    (equations : DirectEquations row witness) :
    row.signXor = true →
      ∃ n0 n1 n2 n3 : Bool,
        row.remainder.limb0.toNat +
              row.remainderAbs.limb0.toNat =
            256 * n0.toNat ∧
        n0.toNat + row.remainder.limb1.toNat +
              row.remainderAbs.limb1.toNat =
            256 * n1.toNat ∧
        n1.toNat + row.remainder.limb2.toNat +
              row.remainderAbs.limb2.toNat =
            256 * n2.toNat ∧
        n2.toNat + row.remainder.limb3.toNat +
              row.remainderAbs.limb3.toNat =
            256 * n3.toNat ∧
        (n0 = false → row.remainderAbs.limb0 = 0) ∧
        (n1 = false → row.remainderAbs.limb1 = 0) ∧
        (n2 = false → row.remainderAbs.limb2 = 0) ∧
        (n3 = false → row.remainderAbs.limb3 = 0) ∧
        (n1 = n0 ∨ n1 = true) ∧
        (n2 = n1 ∨ n2 = true) ∧
        (n3 = n2 ∨ n3 = true) := by
  intro negated
  have root0 := equations.c.negCarryBool0
  rw [negated] at root0
  simp only [boolM31, M31.one_mul] at root0
  rcases initialNegCarryStep row root0 with
    ⟨n0, recurrence0, carry0, _⟩
  have root1 := equations.d.negCarryBool1
  rw [negated, carry0] at root1
  simp only [boolM31, M31.one_mul] at root1
  have carryDefinition1 :
      negCarry1Field row =
        (boolM31 n0 +
            bitVecM31 row.remainder.limb1 +
            bitVecM31 row.remainderAbs.limb1) *
          M31.reduce 8388608 := by
    simp [negCarry1Field, carry0]
  rcases
      negCarryStep n0
        row.remainder.limb1 row.remainderAbs.limb1
        (negCarry1Field row) carryDefinition1 root1 with
    ⟨n1, recurrence1, carry1, monotone1⟩
  have root2 := equations.d.negCarryBool2
  rw [negated, carry1] at root2
  simp only [boolM31, M31.one_mul] at root2
  have carryDefinition2 :
      negCarry2Field row =
        (boolM31 n1 +
            bitVecM31 row.remainder.limb2 +
            bitVecM31 row.remainderAbs.limb2) *
          M31.reduce 8388608 := by
    simp [negCarry2Field, carry1]
  rcases
      negCarryStep n1
        row.remainder.limb2 row.remainderAbs.limb2
        (negCarry2Field row) carryDefinition2 root2 with
    ⟨n2, recurrence2, carry2, monotone2⟩
  have root3 := equations.e.negCarryBool3
  rw [negated, carry2] at root3
  simp only [boolM31, M31.one_mul] at root3
  have carryDefinition3 :
      negCarry3Field row =
        (boolM31 n2 +
            bitVecM31 row.remainder.limb3 +
            bitVecM31 row.remainderAbs.limb3) *
          M31.reduce 8388608 := by
    simp [negCarry3Field, carry2]
  rcases
      negCarryStep n2
        row.remainder.limb3 row.remainderAbs.limb3
        (negCarry3Field row) carryDefinition3 root3 with
    ⟨n3, recurrence3, carry3, monotone3⟩
  have zeroRoot0 := equations.c.negCarryZero0
  rw [negated, carry0] at zeroRoot0
  simp only [boolM31, M31.one_mul] at zeroRoot0
  have zero0 :=
    negCarryZeroAbsolute n0 row.remainderAbs.limb0 zeroRoot0
  have zeroRoot1 := equations.d.negCarryZero1
  rw [negated, carry1] at zeroRoot1
  simp only [boolM31, M31.one_mul] at zeroRoot1
  have zero1 :=
    negCarryZeroAbsolute n1 row.remainderAbs.limb1 zeroRoot1
  have zeroRoot2 := equations.d.negCarryZero2
  rw [negated, carry2] at zeroRoot2
  simp only [boolM31, M31.one_mul] at zeroRoot2
  have zero2 :=
    negCarryZeroAbsolute n2 row.remainderAbs.limb2 zeroRoot2
  have zeroRoot3 := equations.e.negCarryZero3
  rw [negated, carry3] at zeroRoot3
  simp only [boolM31, M31.one_mul] at zeroRoot3
  have zero3 :=
    negCarryZeroAbsolute n3 row.remainderAbs.limb3 zeroRoot3
  exact
    ⟨n0, n1, n2, n3,
      by simpa using recurrence0,
      recurrence1, recurrence2, recurrence3,
      zero0, zero1, zero2, zero3,
      monotone1, monotone2, monotone3⟩


end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
