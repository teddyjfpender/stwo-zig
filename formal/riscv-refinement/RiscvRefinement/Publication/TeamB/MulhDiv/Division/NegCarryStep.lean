import RiscvRefinement.Publication.TeamB.MulhDiv.Division.NegationArithmetic

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family

namespace Division

theorem scaledCarryMinusBool
    (previous : Bool)
    (carry : M31)
    (accumulated : Nat)
    (carryScaled :
      carry * M31.reduce 256 = M31.reduce accumulated) :
    (carry - boolM31 previous) * M31.reduce 256 =
      M31.reduce accumulated -
        M31.reduce (256 * previous.toNat) := by
  cases previous with
  | false =>
      simpa [boolM31] using carryScaled
  | true =>
      simp only [boolM31, Bool.toNat_true, Nat.mul_one]
      rw [m31SubOneScaled256, carryScaled]

set_option maxRecDepth 30000 in
theorem negCarryStep
    (previous : Bool)
    (limb absolute : Byte)
    (carry : M31)
    (carryDefinition :
      carry =
        (boolM31 previous +
            bitVecM31 limb +
            bitVecM31 absolute) *
          M31.reduce 8388608)
    (root :
      (carry - boolM31 previous) *
        (carry - 1) = 0) :
    ∃ next : Bool,
      previous.toNat + limb.toNat + absolute.toNat =
          256 * next.toNat ∧
      carry = boolM31 next ∧
      (next = previous ∨ next = true) := by
  let accumulated :=
    previous.toNat + limb.toNat + absolute.toNat
  have accumulatedBound : accumulated < 512 := by
    have limbBound := byteLt256 limb
    have absoluteBound := byteLt256 absolute
    cases previous <;>
      simp [accumulated] <;>
      omega
  have accumulatedImage :
      boolM31 previous +
            bitVecM31 limb +
            bitVecM31 absolute =
        M31.reduce accumulated := by
    simp only [
      boolM31_eq_reduce,
      bitVecM31,
      accumulated,
      Air.Bridge.TeamACommon.reduceAdd,
    ]
  have carryScaled :
      carry * M31.reduce 256 =
        M31.reduce accumulated := by
    rw [
      carryDefinition,
      accumulatedImage,
      MulhDiv.m31MulAssoc,
      MulhDiv.inverse256,
      M31.mul_one,
    ]
  have scaled :=
    congrArg
      (fun value : M31 =>
        (value * M31.reduce 256) * M31.reduce 256)
      root
  change
    (((carry - boolM31 previous) * (carry - 1)) *
        M31.reduce 256) * M31.reduce 256 =
      (0 * M31.reduce 256) * M31.reduce 256 at scaled
  rw [
    m31ScaleProduct,
    M31.zero_mul,
  ] at scaled
  have integerRoot :
      (M31.reduce accumulated -
          M31.reduce (256 * previous.toNat)) *
        (M31.reduce accumulated - M31.reduce 256) = 0 := by
    rw [
      scaledCarryMinusBool previous carry accumulated carryScaled,
      m31SubOneScaled256,
      carryScaled,
      M31.zero_mul,
    ] at scaled
    exact scaled
  rcases
      boundedNegCarryRoot previous accumulated
        accumulatedBound integerRoot with
    same | one
  · refine ⟨previous, ?_, ?_, Or.inl rfl⟩
    · simpa [accumulated] using same
    · rw [carryDefinition, accumulatedImage, same]
      cases previous <;>
        decide
  · refine ⟨true, ?_, ?_, Or.inr rfl⟩
    · simpa [accumulated] using one
    · rw [carryDefinition, accumulatedImage, one]
      decide

theorem negCarryZeroAbsolute
    (next : Bool)
    (absolute : Byte)
    (equation :
      (1 - boolM31 next) * bitVecM31 absolute = 0) :
    next = false → absolute = 0 := by
  intro nextFalse
  rw [nextFalse] at equation
  simp only [
    boolM31,
    M31.sub_zero,
    M31.one_mul,
  ] at equation
  exact byteEqZeroOfField absolute equation


end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
