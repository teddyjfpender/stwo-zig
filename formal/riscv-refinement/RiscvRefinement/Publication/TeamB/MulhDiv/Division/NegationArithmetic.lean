import RiscvRefinement.Publication.TeamB.MulhDiv.Division.Requests

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family

namespace Division

theorem byteLt256 (value : Byte) :
    value.toNat < 256 := by
  simpa only [Nat.reducePow] using value.isLt

theorem boolM31_eq_reduce (value : Bool) :
    boolM31 value = M31.reduce value.toNat := by
  cases value <;> rfl

theorem m31MulComm (left right : M31) :
    left * right = right * left := by
  apply M31.ext
  change
    (left.val * right.val) % M31.modulus =
      (right.val * left.val) % M31.modulus
  rw [Nat.mul_comm]

theorem m31ScaleProduct
    (left right scale : M31) :
    ((left * right) * scale) * scale =
      (left * scale) * (right * scale) := by
  calc
    ((left * right) * scale) * scale =
        (left * right) * (scale * scale) :=
          MulhDiv.m31MulAssoc (left * right) scale scale
    _ = left * (right * (scale * scale)) :=
          MulhDiv.m31MulAssoc left right (scale * scale)
    _ = left * ((right * scale) * scale) := by
          rw [MulhDiv.m31MulAssoc right scale scale]
    _ = left * (scale * (right * scale)) := by
          rw [m31MulComm (right * scale) scale]
    _ = (left * scale) * (right * scale) :=
          (MulhDiv.m31MulAssoc left scale (right * scale)).symm

theorem m31ScaleRight
    (left right scale : M31) :
    scale * (left * right) =
      left * (scale * right) := by
  calc
    scale * (left * right) =
        (scale * left) * right := by
          rw [MulhDiv.m31MulAssoc]
    _ = (left * scale) * right := by
          rw [m31MulComm scale left]
    _ = left * (scale * right) := by
          rw [MulhDiv.m31MulAssoc]

theorem m31ReduceSubOfLe
    (left right : Nat)
    (ordered : right ≤ left) :
    M31.reduce left - M31.reduce right =
      M31.reduce (left - right) := by
  apply M31.ext
  change
    ((left % M31.modulus + M31.modulus -
        right % M31.modulus) % M31.modulus) =
      (left - right) % M31.modulus
  rw [M31.modulus_eq]
  omega

set_option maxRecDepth 10000 in
theorem m31SubOneScaled256
    (value : M31) :
    (value - 1) * M31.reduce 256 =
      value * M31.reduce 256 - M31.reduce 256 := by
  by_cases zero : value = 0
  · subst value
    decide
  · have positive : 1 ≤ value.val := by
      have valueNonzero : value.val ≠ 0 := by
        intro valueZero
        apply zero
        apply M31.ext
        simpa using valueZero
      omega
    change
      (value - M31.reduce 1) * M31.reduce 256 =
        value * M31.reduce 256 - M31.reduce 256
    rw [← M31.reduce_toNat value]
    change
      (M31.reduce value.val - M31.reduce 1) * M31.reduce 256 =
        M31.reduce value.val * M31.reduce 256 - M31.reduce 256
    rw [
      m31ReduceSubOfLe value.val 1 positive,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceMul,
      m31ReduceSubOfLe (value.val * 256) 256 (by omega),
    ]
    have arithmetic :
        (value.val - 1) * 256 = value.val * 256 - 256 := by

      omega
    rw [arithmetic]

theorem reducedProductZero
    (left right : Nat)
    (bound : left * right < M31.modulus)
    (equation :
      M31.reduce left * M31.reduce right = 0) :
    left = 0 ∨ right = 0 := by
  rw [Air.Bridge.TeamACommon.reduceMul] at equation
  exact
    Nat.mul_eq_zero.mp
      ((M31.reduce_eq_zero_of_lt bound).mp equation)

theorem productLtModulusOfLt512
    {left right : Nat}
    (leftBound : left < 512)
    (rightBound : right < 512) :
    left * right < M31.modulus := by
  have productBound :=
    Nat.mul_le_mul
      (Nat.le_of_lt leftBound)
      (Nat.le_of_lt rightBound)
  rw [M31.modulus_eq]
  omega

theorem m31ReduceSubOfLt
    {left right : Nat}
    (leftBound : left < M31.modulus)
    (rightBound : right < M31.modulus)
    (ordered : left < right) :
    M31.reduce left - M31.reduce right =
      M31.reduce (left + M31.modulus - right) := by
  apply M31.ext
  have fieldOrdered :
      (M31.reduce left).val < (M31.reduce right).val := by
    rw [
      M31.reduce_val_of_lt left leftBound,
      M31.reduce_val_of_lt right rightBound,
    ]
    exact ordered
  have differenceBound :
      left + M31.modulus - right < M31.modulus := by
    omega
  rw [
    M31.sub_val_of_lt _ _ fieldOrdered,
    M31.reduce_val_of_lt left leftBound,
    M31.reduce_val_of_lt right rightBound,
    M31.reduce_val_of_lt _ differenceBound,
  ]
  omega

/--
The carry residual is evaluated in `M31`, but after multiplying both factors
by `256` it is a product of integer differences in `[-256, 511]`.  Its absolute
product is below the field modulus, so a zero field product is an actual
integer root; no finite enumeration or field primality argument is needed.
-/
theorem boundedNegCarryRoot
    (previous : Bool)
    (accumulated : Nat)
    (bound : accumulated < 512)
    (equation :
      (M31.reduce accumulated -
          M31.reduce (256 * previous.toNat)) *
        (M31.reduce accumulated - M31.reduce 256) = 0) :
    accumulated = 256 * previous.toNat ∨
      accumulated = 256 := by
  cases previous with
  | false =>
      simp only [Bool.toNat_false, Nat.mul_zero, M31.reduce_zero,
        M31.sub_zero] at equation ⊢
      by_cases low : accumulated < 256
      · by_cases zero : accumulated = 0
        · exact Or.inl zero
        · let difference := 256 - accumulated
          have differencePositive : 0 < difference := by
            dsimp [difference]
            omega
          have differenceBound : difference < M31.modulus := by
            rw [M31.modulus_eq]
            dsimp [difference]
            omega
          have accumulatedBound : accumulated < M31.modulus := by
            rw [M31.modulus_eq]
            omega
          have constantBound : 256 < M31.modulus := by
            rw [M31.modulus_eq]
            omega
          rw [
            m31ReduceSubOfLt accumulatedBound constantBound low,
          ] at equation
          have wrapped :
              accumulated + M31.modulus - 256 =
                M31.modulus - difference := by
            dsimp [difference]
            omega
          rw [wrapped] at equation
          have negated :=
            congrArg
              (fun value : M31 =>
                M31.reduce (M31.modulus - 1) * value)
              equation
          change
            M31.reduce (M31.modulus - 1) *
                (M31.reduce accumulated *
                  M31.reduce (M31.modulus - difference)) =
              M31.reduce (M31.modulus - 1) * 0 at negated
          rw [
            m31ScaleRight,
            m31Negate difference differenceBound,
            M31.mul_zero,
          ] at negated
          have productBound :
              accumulated * difference < M31.modulus := by
            apply productLtModulusOfLt512
            · exact bound
            · dsimp [difference]
              omega
          rcases
              reducedProductZero accumulated difference
                productBound negated with
            accumulatedZero | differenceZero
          · exact absurd accumulatedZero zero
          · exact absurd differenceZero (by omega)
      · have ordered : 256 ≤ accumulated := by omega
        rw [
          m31ReduceSubOfLe accumulated 256 ordered,
        ] at equation
        have productBound :
            accumulated * (accumulated - 256) <
              M31.modulus := by
          apply productLtModulusOfLt512
          · exact bound
          · omega
        rcases
            reducedProductZero accumulated (accumulated - 256)
              productBound equation with
          accumulatedZero | differenceZero
        · omega
        · exact Or.inr (by omega)
  | true =>
      simp only [Bool.toNat_true, Nat.mul_one] at equation ⊢
      by_cases low : accumulated < 256
      · let difference := 256 - accumulated
        have differencePositive : 0 < difference := by
          dsimp [difference]
          omega
        have differenceBound : difference < M31.modulus := by
          rw [M31.modulus_eq]
          dsimp [difference]
          omega
        have accumulatedBound : accumulated < M31.modulus := by
          rw [M31.modulus_eq]
          omega
        have constantBound : 256 < M31.modulus := by
          rw [M31.modulus_eq]
          omega
        rw [
          m31ReduceSubOfLt accumulatedBound constantBound low,
        ] at equation
        have wrapped :
            accumulated + M31.modulus - 256 =
              M31.modulus - difference := by
          dsimp [difference]
          omega
        rw [wrapped] at equation
        have negated :=
          congrArg
            (fun value : M31 =>
              (value * M31.reduce (M31.modulus - 1)) *
                M31.reduce (M31.modulus - 1))
            equation
        change
          ((M31.reduce (M31.modulus - difference) *
                M31.reduce (M31.modulus - difference)) *
              M31.reduce (M31.modulus - 1)) *
              M31.reduce (M31.modulus - 1) =
            (0 * M31.reduce (M31.modulus - 1)) *
              M31.reduce (M31.modulus - 1) at negated
        have negatedFactor :
            M31.reduce (M31.modulus - difference) *
                M31.reduce (M31.modulus - 1) =
              M31.reduce difference := by
          rw [
            m31MulComm,
            m31Negate difference differenceBound,
          ]
        rw [
          m31ScaleProduct,
          negatedFactor,
          M31.zero_mul,
        ] at negated
        have productBound :
            difference * difference < M31.modulus := by
          apply productLtModulusOfLt512 <;>
            dsimp [difference] <;>
            omega
        rcases
            reducedProductZero difference difference
              productBound negated with
          differenceZero | differenceZero <;>
            exact absurd differenceZero (by omega)
      · have ordered : 256 ≤ accumulated := by omega
        rw [
          m31ReduceSubOfLe accumulated 256 ordered,
        ] at equation
        have productBound :
            (accumulated - 256) * (accumulated - 256) <
              M31.modulus := by
          apply productLtModulusOfLt512 <;>
            omega
        rcases
            reducedProductZero
              (accumulated - 256) (accumulated - 256)
              productBound equation with
          differenceZero | differenceZero <;>
            exact Or.inl (by omega)


end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
