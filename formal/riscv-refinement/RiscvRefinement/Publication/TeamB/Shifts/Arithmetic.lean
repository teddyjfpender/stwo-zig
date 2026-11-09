import RiscvRefinement.Publication.TeamB.Shifts.LookupProjection

/-! Bounded shift publication proof owner: Arithmetic. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

theorem multiplierLe128
    (row : ShiftRow)
    (bitRange : row.bitIndex < 8) :
    row.multiplier ≤ 128 := by
  simp only [ShiftRow.multiplier]
  have := Nat.pow_le_pow_right (by omega : 0 < (2 : Nat))
    (show row.bitIndex ≤ 7 by omega)
  simpa using this

/-!
The movement roots are field equations.  These small cancellation lemmas keep
the reverse bridge honest about subtraction wrap: no natural-number
subtraction is substituted for field subtraction until both sides have been
rearranged into non-negative, canonically bounded sums.
-/

private theorem m31EqAddOfSubEq
    (left right offset : M31)
    (equation : left - right = offset) :
    left = right + offset := by
  have values := congrArg M31.val equation
  have leftBound : left.val < M31.modulus := by
    simpa [M31.modulus_eq] using left.isLt
  have rightBound : right.val < M31.modulus := by
    simpa [M31.modulus_eq] using right.isLt
  have offsetBound : offset.val < M31.modulus := by
    simpa [M31.modulus_eq] using offset.isLt
  by_cases ordered : right.val ≤ left.val
  · rw [M31.sub_val_of_le left right ordered] at values
    have sumBound : right.val + offset.val < M31.modulus := by omega
    apply M31.ext
    rw [M31.add_val_of_lt right offset sumBound]
    omega
  · have reverse : left.val < right.val := Nat.lt_of_not_ge ordered
    rw [M31.sub_val_of_lt left right reverse] at values
    apply M31.ext
    change left.val = (right.val + offset.val) % M31.modulus
    have sum :
        right.val + offset.val = M31.modulus + left.val := by
      omega
    rw [sum, Nat.add_mod_left]
    exact (Nat.mod_eq_of_lt leftBound).symm

private theorem m31AddComm (left right : M31) :
    left + right = right + left := by
  apply M31.ext
  change
    (left.val + right.val) % M31.modulus =
      (right.val + left.val) % M31.modulus
  rw [Nat.add_comm]

private theorem m31AddAssoc (first second third : M31) :
    (first + second) + third = first + (second + third) := by
  rw [
    ← M31.reduce_toNat first,
    ← M31.reduce_toNat second,
    ← M31.reduce_toNat third,
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceAdd,
  ]
  congr 1
  omega

private theorem leftContinuationRearrange
    (result previousCarry shiftedCarry scaledSource : M31)
    (equation :
      (result - (previousCarry - shiftedCarry)) - scaledSource = 0) :
    result + shiftedCarry = scaledSource + previousCarry := by
  have first :
      result - (previousCarry - shiftedCarry) = scaledSource :=
    (M31.sub_eq_zero_iff _ _).mp equation
  have resultExpansion :
      result = (previousCarry - shiftedCarry) + scaledSource :=
    m31EqAddOfSubEq _ _ _ first
  have previousExpansion :
      previousCarry = shiftedCarry + (previousCarry - shiftedCarry) :=
    m31EqAddOfSubEq _ _ _ rfl
  calc
    result + shiftedCarry =
        ((previousCarry - shiftedCarry) + scaledSource) + shiftedCarry := by
          rw [resultExpansion]
    _ = (previousCarry - shiftedCarry) +
        (scaledSource + shiftedCarry) :=
      m31AddAssoc _ _ _
    _ = (previousCarry - shiftedCarry) +
        (shiftedCarry + scaledSource) := by
      rw [m31AddComm scaledSource shiftedCarry]
    _ = ((previousCarry - shiftedCarry) + shiftedCarry) +
        scaledSource :=
      (m31AddAssoc _ _ _).symm
    _ = (shiftedCarry + (previousCarry - shiftedCarry)) +
        scaledSource := by
      rw [m31AddComm (previousCarry - shiftedCarry) shiftedCarry]
    _ = previousCarry + scaledSource := by
      rw [← previousExpansion]
    _ = scaledSource + previousCarry :=
      m31AddComm _ _

private theorem rightMovementRearrange
    (shiftedCarry source carry scaledResult : M31)
    (equation :
      (shiftedCarry + (source - carry)) - scaledResult = 0) :
    scaledResult + carry = source + shiftedCarry := by
  have resultExpansion :
      shiftedCarry + (source - carry) = scaledResult :=
    (M31.sub_eq_zero_iff _ _).mp equation
  have sourceExpansion :
      source = carry + (source - carry) :=
    m31EqAddOfSubEq _ _ _ rfl
  calc
    scaledResult + carry =
        (shiftedCarry + (source - carry)) + carry := by
          rw [← resultExpansion]
    _ = shiftedCarry + ((source - carry) + carry) :=
      m31AddAssoc _ _ _
    _ = shiftedCarry + (carry + (source - carry)) := by
      rw [m31AddComm (source - carry) carry]
    _ = shiftedCarry + source := by
      rw [← sourceExpansion]
    _ = source + shiftedCarry :=
      m31AddComm _ _

private theorem rightTopRearrange
    (fill source carry scaledResult baseFill : M31)
    (equation : (fill + (source - carry)) - scaledResult = 0) :
    (scaledResult + carry) + baseFill =
      source + (fill + baseFill) := by
  have base :=
    rightMovementRearrange fill source carry scaledResult equation
  calc
    (scaledResult + carry) + baseFill =
        (source + fill) + baseFill := by rw [base]
    _ = source + (fill + baseFill) :=
      m31AddAssoc _ _ _

private theorem naturalEqualityOfReduced
    (left right : Nat)
    (leftBound : left < M31.modulus)
    (rightBound : right < M31.modulus)
    (equation : M31.reduce left = M31.reduce right) :
    left = right :=
  (M31.reduce_injective_of_lt leftBound rightBound).mp equation

theorem leftStartNatural
    (result carry multiplier source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (equation :
      M31.reduce result + M31.reduce 256 * M31.reduce carry =
        M31.reduce source * M31.reduce multiplier) :
    result + 256 * carry = multiplier * source := by
  have productBound :
      multiplier * source < M31.modulus := by
    have productLe :
        multiplier * source ≤ 128 * 255 :=
      Nat.mul_le_mul multiplierBound (by omega)
    rw [M31.modulus_eq]
    omega
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    omega
  · exact productBound
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
  ] using equation

theorem leftContinuationNatural
    (result carry previousCarry multiplier source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < multiplier)
    (previousCarryBound : previousCarry < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (equation :
      (M31.reduce result -
          (M31.reduce previousCarry -
            M31.reduce 256 * M31.reduce carry)) -
        M31.reduce source * M31.reduce multiplier = 0) :
    result + 256 * carry =
      multiplier * source + previousCarry := by
  have productLe :
      multiplier * source ≤ 128 * 255 :=
    Nat.mul_le_mul multiplierBound (by omega)
  have rearranged :=
    leftContinuationRearrange
      (M31.reduce result)
      (M31.reduce previousCarry)
      (M31.reduce 256 * M31.reduce carry)
      (M31.reduce source * M31.reduce multiplier)
      equation
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    omega
  · rw [M31.modulus_eq]
    omega
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
  ] using rearranged

theorem rightMovementNatural
    (result carry nextCarry multiplier source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < multiplier)
    (nextCarryBound : nextCarry < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (equation :
      (M31.reduce nextCarry * M31.reduce 256 +
          (M31.reduce source - M31.reduce carry)) -
        M31.reduce result * M31.reduce multiplier = 0) :
    multiplier * result + carry = source + 256 * nextCarry := by
  have productLe :
      multiplier * result ≤ 128 * 255 :=
    Nat.mul_le_mul multiplierBound (by omega)
  have rearranged :=
    rightMovementRearrange
      (M31.reduce nextCarry * M31.reduce 256)
      (M31.reduce source)
      (M31.reduce carry)
      (M31.reduce result * M31.reduce multiplier)
      equation
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    omega
  · rw [M31.modulus_eq]
    omega
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
  ] using rearranged

private theorem boolM31SignNat (row : ShiftRow) :
    boolM31 row.rs1Sign = M31.reduce row.signNat := by
  cases sign : row.rs1Sign <;>
    simp [boolM31, ShiftRow.signNat, sign]

private theorem reduceSubOne
    (value : Nat)
    (positive : 0 < value)
    (canonical : value < M31.modulus) :
    M31.reduce value - M31.reduce 1 = M31.reduce (value - 1) := by
  have ordered :
      (M31.reduce 1).val ≤ (M31.reduce value).val := by
    rw [
      M31.reduce_val_of_lt 1 (by decide),
      M31.reduce_val_of_lt value canonical,
    ]
    omega
  apply M31.ext
  rw [
    M31.sub_val_of_le _ _ ordered,
    M31.reduce_val_of_lt 1 (by decide),
    M31.reduce_val_of_lt value canonical,
    M31.reduce_val_of_lt (value - 1) (by omega),
  ]

private theorem signFillIdentity
    (row : ShiftRow)
    (multiplierBound : row.multiplier ≤ 128) :
    let multiplier := row.multiplier
    boolM31 row.rs1Sign * (M31.reduce multiplier - 1) * M31.reduce 256 +
        boolM31 row.rs1Sign * M31.reduce 256 =
      M31.reduce (256 * row.signNat * multiplier) := by
  cases sign : row.rs1Sign
  · simp [boolM31, ShiftRow.signNat, sign]
  · have positive := row.multiplier_pos
    have canonical : row.multiplier < M31.modulus := by
      rw [M31.modulus_eq]
      omega
    simp only [sign, boolM31, ShiftRow.signNat, ↓reduceIte, M31.one_mul]
    change
      (M31.reduce row.multiplier - M31.reduce 1) * M31.reduce 256 +
          M31.reduce 256 =
        M31.reduce (256 * 1 * row.multiplier)
    rw [
      reduceSubOne row.multiplier positive canonical,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]
    congr 1
    omega

theorem rightTopNatural
    (row : ShiftRow)
    (result carry source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < row.multiplier)
    (multiplierBound : row.multiplier ≤ 128)
    (equation :
      (boolM31 row.rs1Sign *
            (M31.reduce row.multiplier - 1) *
            M31.reduce 256 +
          (M31.reduce source - M31.reduce carry)) -
        M31.reduce result * M31.reduce row.multiplier = 0) :
    row.multiplier * result + carry + 256 * row.signNat =
      source + 256 * row.signNat * row.multiplier := by
  have productLe :
      row.multiplier * result ≤ 128 * 255 :=
    Nat.mul_le_mul multiplierBound (by omega)
  have fillProductLe :
      256 * row.signNat * row.multiplier ≤ 256 * 1 * 128 := by
    have signBound : row.signNat ≤ 1 := by
      unfold ShiftRow.signNat
      split <;> omega
    exact
      Nat.mul_le_mul
        (Nat.mul_le_mul (Nat.le_refl 256) signBound)
        multiplierBound
  have rearranged :=
    rightTopRearrange
      (boolM31 row.rs1Sign *
        (M31.reduce row.multiplier - 1) *
        M31.reduce 256)
      (M31.reduce source)
      (M31.reduce carry)
      (M31.reduce result * M31.reduce row.multiplier)
      (boolM31 row.rs1Sign * M31.reduce 256)
      equation
  rw [signFillIdentity row multiplierBound] at rearranged
  rw [boolM31SignNat row] at rearranged
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    have signBound : row.signNat ≤ 1 := by
      unfold ShiftRow.signNat
      split <;> omega
    omega
  · rw [M31.modulus_eq]
    have signBound : row.signNat ≤ 1 := by
      unfold ShiftRow.signNat
      split <;> omega
    omega
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
    Nat.mul_left_comm,
    Nat.mul_assoc,
  ] using rearranged

end RiscvRefinement.Publication.TeamB.Shifts
