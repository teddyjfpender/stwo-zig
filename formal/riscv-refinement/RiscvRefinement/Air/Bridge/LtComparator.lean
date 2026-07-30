import RiscvRefinement.Air.Bridge.TeamACommon

/-!
# Pure production less-than comparator contract

This module isolates the four-limb comparator shared by the LT opcode and
branch AIR gadgets.  Callers supply raw M31 columns plus equations and bounds
derived from their own accepted generated constraints and fixed lookups.
-/

namespace RiscvRefinement.Air.Bridge.LtComparator

open RiscvRefinement

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

def comparisonSign (result : Bool) : M31 :=
  boolM31 result * M31.reduce 2 - 1

private theorem m31SubEqOfEqAdd
    (left right offset : M31)
    (equation : left = right + offset) :
    left - offset = right := by
  have values := congrArg M31.val equation
  have leftBound : left.val < M31.modulus := by
    simpa [M31.modulus_eq] using left.isLt
  have rightBound : right.val < M31.modulus := by
    simpa [M31.modulus_eq] using right.isLt
  have offsetBound : offset.val < M31.modulus := by
    simpa [M31.modulus_eq] using offset.isLt
  by_cases sumBound : right.val + offset.val < M31.modulus
  · rw [M31.add_val_of_lt right offset sumBound] at values
    apply M31.ext
    rw [M31.sub_val_of_le left offset (by omega)]
    omega
  · have sumUpper :
        right.val + offset.val < 2 * M31.modulus := by
      omega
    have sumLower : M31.modulus ≤ right.val + offset.val :=
      Nat.le_of_not_gt sumBound
    have addValue :
        (right + offset).val =
          right.val + offset.val - M31.modulus := by
      change
        (right.val + offset.val) % M31.modulus =
          right.val + offset.val - M31.modulus
      rw [Nat.mod_eq_sub_mod sumLower]
      exact Nat.mod_eq_of_lt (by omega)
    rw [addValue] at values
    have reverse : left.val < offset.val := by omega
    apply M31.ext
    rw [M31.sub_val_of_lt left offset reverse]
    omega

private def keyMslField (signed : Bool) (key : Byte) : M31 :=
  bitVecM31 key - boolM31 signed * M31.reduce 128

private def keyByte (value : M31) : Byte :=
  BitVec.ofNat 8 value.val

private theorem keyByteField
    (value : M31)
    (bound : value.val < 256) :
    bitVecM31 (keyByte value) = value := by
  change M31.reduce (BitVec.ofNat 8 value.val).toNat = value
  have toNat : (BitVec.ofNat 8 value.val).toNat = value.val := by
    simp [Nat.mod_eq_of_lt bound]
  rw [toNat]
  exact M31.reduce_toNat value

 /-
Finite uniqueness of the MSL normalization polynomial over byte inputs.
-/
set_option maxHeartbeats 0 in
set_option maxRecDepth 100000 in
theorem keyPolynomialUnique
    (signed : Bool)
    (byte key : Byte)
    (polynomial :
      let difference := bitVecM31 byte - keyMslField signed key
      difference * (M31.reduce 256 - difference) = 0) :
    key.toNat =
      if signed then (byte.toNat + 128) % 256 else byte.toNat := by
  cases signed <;> revert byte key <;> decide

/-- The unsigned byte order, rotated by 128 for signed comparison. -/
def byteKey (signed : Bool) (byte : Byte) : Nat :=
  if signed then (byte.toNat + 128) % 256 else byte.toNat

/--
The raw MSL polynomial and a live `< 256` shifted-key lookup uniquely bind the
shifted raw MSL to the signed-rotated (or unsigned) byte key.
-/
theorem normalizedKey
    (signed : Bool)
    (byte : Byte)
    (rawMsl : M31)
    (keyBound :
      (rawMsl + boolM31 signed * M31.reduce 128).val < 256)
    (polynomial :
      (bitVecM31 byte - rawMsl) *
        (M31.reduce 256 - (bitVecM31 byte - rawMsl)) = 0) :
    (rawMsl + boolM31 signed * M31.reduce 128).val =
      byteKey signed byte := by
  let key := rawMsl + boolM31 signed * M31.reduce 128
  let encodedKey := keyByte key
  have encodedKeyField : bitVecM31 encodedKey = key :=
    keyByteField key keyBound
  have rawFromKey :
      rawMsl = key - boolM31 signed * M31.reduce 128 := by
    symm
    apply m31SubEqOfEqAdd
    rfl
  have normalizedPolynomial :
      let difference :=
        bitVecM31 byte - keyMslField signed encodedKey
      difference * (M31.reduce 256 - difference) = 0 := by
    simpa [keyMslField, encodedKeyField, rawFromKey] using polynomial
  have finite :=
    keyPolynomialUnique signed byte encodedKey normalizedPolynomial
  have encodedKeyValue : encodedKey.toNat = key.val := by
    simp [encodedKey, keyByte]
    exact keyBound
  simpa [key, encodedKeyValue, byteKey] using finite

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
        right.val + offset.val = M31.modulus + left.val := by omega
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
    TeamACommon.reduceAdd,
    TeamACommon.reduceAdd,
    TeamACommon.reduceAdd,
    TeamACommon.reduceAdd,
  ]
  congr 1
  omega

/-- Adding the same M31 offset preserves subtraction. -/
theorem translatedSub
    (left right offset : M31) :
    right - left = (right + offset) - (left + offset) := by
  let difference := right - left
  have rightEquation : right = left + difference :=
    m31EqAddOfSubEq right left difference rfl
  have shifted :
      right + offset = difference + (left + offset) := by
    calc
      right + offset = (left + difference) + offset := by
        rw [rightEquation]
      _ = left + (difference + offset) :=
        m31AddAssoc left difference offset
      _ = left + (offset + difference) := by
        rw [m31AddComm difference offset]
      _ = (left + offset) + difference :=
        (m31AddAssoc left offset difference).symm
      _ = difference + (left + offset) :=
        m31AddComm (left + offset) difference
  exact
    (m31SubEqOfEqAdd
      (right + offset) difference (left + offset) shifted).symm

private theorem reduceCongr {left right : Nat}
    (congruent : left % M31.modulus = right % M31.modulus) :
    M31.reduce left = M31.reduce right := by
  apply M31.ext
  simpa only [M31.reduce_val] using congruent

private theorem negOneMulPositive
    (value : Nat)
    (positive : 0 < value)
    (bound : value < M31.modulus) :
    M31.reduce (M31.modulus - 1) * M31.reduce value =
      M31.reduce (M31.modulus - value) := by
  rw [TeamACommon.reduceMul]
  apply reduceCongr
  have expand :
      (M31.modulus - 1) * value =
        M31.modulus * (value - 1) + (M31.modulus - value) := by
    simp only [M31.modulus_eq] at positive bound ⊢
    omega
  rw [expand, Nat.mul_add_mod]

private theorem negOneMulNegative
    (value : Nat)
    (bound : value < M31.modulus) :
    M31.reduce (M31.modulus - 1) *
        M31.reduce (M31.modulus - value) =
      M31.reduce value := by
  rw [TeamACommon.reduceMul]
  apply reduceCongr
  have expand :
      (M31.modulus - 1) * (M31.modulus - value) =
        M31.modulus * (M31.modulus - value - 1) + value := by
    simp only [M31.modulus_eq] at bound ⊢
    omega
  rw [expand, Nat.mul_add_mod]

private theorem negOneMulSub (left right : M31) :
    ((0 : M31) - 1) * (right - left) = left - right := by
  have negOne : (0 : M31) - 1 =
      M31.reduce (M31.modulus - 1) := by decide
  rw [negOne]
  rcases Nat.lt_trichotomy left.val right.val with order | equal | order
  · have differenceBound : right.val - left.val < M31.modulus := by
      have rightBound : right.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using right.isLt
      exact Nat.lt_of_le_of_lt (Nat.sub_le _ _) rightBound
    have rightSubLeft :
        right - left = M31.reduce (right.val - left.val) := by
      apply M31.ext
      calc
        (right - left).val = right.val - left.val :=
          M31.sub_val_of_le right left (Nat.le_of_lt order)
        _ = (M31.reduce (right.val - left.val)).val :=
          (M31.reduce_val_of_lt _ differenceBound).symm
    have leftSubRight :
        left - right =
          M31.reduce (M31.modulus - (right.val - left.val)) := by
      apply M31.ext
      have rightBound : right.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using right.isLt
      have reducedBound :
          M31.modulus - (right.val - left.val) < M31.modulus := by
        omega
      calc
        (left - right).val = M31.modulus + left.val - right.val :=
          M31.sub_val_of_lt left right order
        _ = M31.modulus - (right.val - left.val) := by omega
        _ = (M31.reduce
              (M31.modulus - (right.val - left.val))).val :=
          (M31.reduce_val_of_lt _ reducedBound).symm
    rw [rightSubLeft, leftSubRight]
    exact negOneMulPositive _ (by omega) differenceBound
  · have fieldEqual : left = right := M31.ext equal
    subst right
    simp
  · have differenceBound : left.val - right.val < M31.modulus := by
      have leftBound : left.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using left.isLt
      exact Nat.lt_of_le_of_lt (Nat.sub_le _ _) leftBound
    have rightSubLeft :
        right - left =
          M31.reduce (M31.modulus - (left.val - right.val)) := by
      apply M31.ext
      have leftBound : left.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using left.isLt
      have reducedBound :
          M31.modulus - (left.val - right.val) < M31.modulus := by
        omega
      calc
        (right - left).val = M31.modulus + right.val - left.val :=
          M31.sub_val_of_lt right left order
        _ = M31.modulus - (left.val - right.val) := by omega
        _ = (M31.reduce
              (M31.modulus - (left.val - right.val))).val :=
          (M31.reduce_val_of_lt _ reducedBound).symm
    have leftSubRight :
        left - right = M31.reduce (left.val - right.val) := by
      apply M31.ext
      calc
        (left - right).val = left.val - right.val :=
          M31.sub_val_of_le left right (Nat.le_of_lt order)
        _ = (M31.reduce (left.val - right.val)).val :=
          (M31.reduce_val_of_lt _ differenceBound).symm
    rw [rightSubLeft, leftSubRight]
    exact negOneMulNegative _ differenceBound

@[simp]
private theorem comparisonSignFalse :
    comparisonSign false = (0 : M31) - 1 := by rfl

@[simp]
private theorem comparisonSignTrue :
    comparisonSign true = 1 := by decide

theorem orientedZero
    (result : Bool)
    (left right : M31)
    (equation : comparisonSign result * (right - left) = 0) :
    left = right := by
  cases result
  · have reversed : left - right = 0 := by
      rw [comparisonSignFalse, negOneMulSub] at equation
      exact equation
    exact (M31.sub_eq_zero_iff _ _).mp reversed
  · have forward : right - left = 0 := by
      rw [comparisonSignTrue, M31.one_mul] at equation
      exact equation
    exact (M31.sub_eq_zero_iff _ _).mp forward |>.symm

private theorem positiveFieldSubImpliesLt
    (left right difference : M31)
    (leftBound : left.val < 256)
    (rightBound : right.val < 256)
    (differencePositive : 0 < difference.val)
    (differenceBound : difference.val ≤ 2 ^ 20)
    (equation : difference = right - left) :
    left.val < right.val := by
  have values := congrArg M31.val equation
  rcases Nat.lt_trichotomy left.val right.val with less | equal | reverse
  · exact less
  · have fieldsEqual : left = right := M31.ext equal
    rw [fieldsEqual, M31.sub_self] at equation
    have impossible := congrArg M31.val equation
    change difference.val = 0 at impossible
    omega
  · rw [M31.sub_val_of_lt right left reverse] at values
    simp only [M31.modulus_eq] at values
    omega

/--
An oriented, positive, small M31 difference fixes both the comparison bit and
the inequality of the selected fields.
-/
theorem orientedPositiveField
    (result : Bool)
    (left right difference : M31)
    (leftBound : left.val < 256)
    (rightBound : right.val < 256)
    (differencePositive : 0 < difference.val)
    (differenceBound : difference.val ≤ 2 ^ 20)
    (equation :
      difference = comparisonSign result * (right - left)) :
    result = decide (left.val < right.val) ∧ left ≠ right := by
  cases result
  · have reversed : difference = left - right := by
      rw [comparisonSignFalse, negOneMulSub] at equation
      exact equation
    have order :=
      positiveFieldSubImpliesLt right left difference
        rightBound leftBound differencePositive differenceBound reversed
    refine ⟨by simp [show ¬ left.val < right.val by omega], ?_⟩
    intro equal
    have := congrArg M31.val equal
    omega
  · have forward : difference = right - left := by
      rw [comparisonSignTrue, M31.one_mul] at equation
      exact equation
    have order :=
      positiveFieldSubImpliesLt left right difference
        leftBound rightBound differencePositive differenceBound forward
    refine ⟨by simp [order], ?_⟩
    intro equal
    have := congrArg M31.val equal
    omega

structure ComparatorContract where
  result : Bool
  leftTop : M31
  rightTop : M31
  left2 : M31
  right2 : M31
  left1 : M31
  right1 : M31
  left0 : M31
  right0 : M31
  marker0 : Bool
  marker1 : Bool
  marker2 : Bool
  marker3 : Bool
  difference : M31
  leftTopBound : leftTop.val < 256
  rightTopBound : rightTop.val < 256
  left2Bound : left2.val < 256
  right2Bound : right2.val < 256
  left1Bound : left1.val < 256
  right1Bound : right1.val < 256
  left0Bound : left0.val < 256
  right0Bound : right0.val < 256
  differencePositive :
    marker0 = true ∨ marker1 = true ∨
      marker2 = true ∨ marker3 = true →
        0 < difference.val
  differenceBound :
    marker0 = true ∨ marker1 = true ∨
      marker2 = true ∨ marker3 = true →
        difference.val ≤ 2 ^ 20
  topEqual :
    marker3 = false →
      comparisonSign result * (rightTop - leftTop) = 0
  topSelected :
    marker3 = true →
      difference =
        comparisonSign result * (rightTop - leftTop)
  limb2Equal :
    marker3 = false → marker2 = false →
      comparisonSign result * (right2 - left2) = 0
  limb2Selected :
    marker2 = true →
      difference =
        comparisonSign result * (right2 - left2)
  limb1Equal :
    marker3 = false → marker2 = false → marker1 = false →
      comparisonSign result * (right1 - left1) = 0
  limb1Selected :
    marker1 = true →
      difference =
        comparisonSign result * (right1 - left1)
  limb0Equal :
    marker3 = false → marker2 = false → marker1 = false →
      marker0 = false →
        comparisonSign result * (right0 - left0) = 0
  limb0Selected :
    marker0 = true →
      difference =
        comparisonSign result * (right0 - left0)
  noMarkerResult :
    marker3 = false → marker2 = false → marker1 = false →
      marker0 = false → result = false

def ComparatorContract.lexicographicLess
    (contract : ComparatorContract) : Bool :=
  if contract.leftTop = contract.rightTop then
    if contract.left2 = contract.right2 then
      if contract.left1 = contract.right1 then
        if contract.left0 = contract.right0 then
          false
        else
          decide (contract.left0.val < contract.right0.val)
      else
        decide (contract.left1.val < contract.right1.val)
    else
      decide (contract.left2.val < contract.right2.val)
  else
    decide (contract.leftTop.val < contract.rightTop.val)

theorem comparisonCorrectOfContract
    (contract : ComparatorContract) :
    contract.result = contract.lexicographicLess := by
  cases marker3Case : contract.marker3
  · have top :=
      orientedZero contract.result contract.leftTop contract.rightTop
        (contract.topEqual marker3Case)
    cases marker2Case : contract.marker2
    · have limb2 :=
        orientedZero contract.result contract.left2 contract.right2
          (contract.limb2Equal marker3Case marker2Case)
      cases marker1Case : contract.marker1
      · have limb1 :=
          orientedZero contract.result contract.left1 contract.right1
            (contract.limb1Equal marker3Case marker2Case marker1Case)
        cases marker0Case : contract.marker0
        · have limb0 :=
            orientedZero contract.result contract.left0 contract.right0
              (contract.limb0Equal marker3Case marker2Case marker1Case
                marker0Case)
          simpa [ComparatorContract.lexicographicLess, top, limb2, limb1,
            limb0] using
            contract.noMarkerResult marker3Case marker2Case marker1Case
              marker0Case
        · have selected :=
            orientedPositiveField contract.result contract.left0
              contract.right0 contract.difference contract.left0Bound
              contract.right0Bound
              (contract.differencePositive (Or.inl marker0Case))
              (contract.differenceBound (Or.inl marker0Case))
              (contract.limb0Selected marker0Case)
          simpa [ComparatorContract.lexicographicLess, top, limb2, limb1,
            selected.2] using selected.1
      · have selected :=
          orientedPositiveField contract.result contract.left1
            contract.right1 contract.difference contract.left1Bound
            contract.right1Bound
            (contract.differencePositive (Or.inr (Or.inl marker1Case)))
            (contract.differenceBound (Or.inr (Or.inl marker1Case)))
            (contract.limb1Selected marker1Case)
        simpa [ComparatorContract.lexicographicLess, top, limb2,
          selected.2] using selected.1
    · have selected :=
        orientedPositiveField contract.result contract.left2
          contract.right2 contract.difference contract.left2Bound
          contract.right2Bound
          (contract.differencePositive
            (Or.inr (Or.inr (Or.inl marker2Case))))
          (contract.differenceBound
            (Or.inr (Or.inr (Or.inl marker2Case))))
          (contract.limb2Selected marker2Case)
      simpa [ComparatorContract.lexicographicLess, top, selected.2] using
        selected.1
  · have selected :=
      orientedPositiveField contract.result contract.leftTop
        contract.rightTop contract.difference contract.leftTopBound
        contract.rightTopBound
        (contract.differencePositive
          (Or.inr (Or.inr (Or.inr marker3Case))))
        (contract.differenceBound
          (Or.inr (Or.inr (Or.inr marker3Case))))
        (contract.topSelected marker3Case)
    simpa [ComparatorContract.lexicographicLess, selected.2] using selected.1

end RiscvRefinement.Air.Bridge.LtComparator
