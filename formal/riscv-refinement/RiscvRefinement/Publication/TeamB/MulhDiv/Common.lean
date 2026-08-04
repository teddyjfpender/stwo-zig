import RiscvRefinement.Air.Generated.Programs
import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Opcodes.Multiply
import RiscvRefinement.Opcodes.Div
import RiscvRefinement.Publication.Acceptance
import RiscvRefinement.Publication.TeamB.Common
import RiscvRefinement.Publication.Universal

/-!
# Publication bridge for Team B high multiply and division

This file is developed alongside `TeamB/Multiply.lean`.  The small arithmetic
lemmas below are stated over the production `M31` implementation and are used
to lift range-checked computed nodes back to their unique bounded integer
meaning.
-/

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated

/-- Apply a compact semantic interpreter to one accepted fixed-table lookup.
Keeping this composition in the shared module prevents a large caller-specific
symbolic evaluator from being normalized into the downstream proof term. -/
theorem consequenceOfFixedLookup
    (production : SymbolicEvaluation)
    (ordinal : Nat)
    (lookup : EvaluatedLookup)
    (fixed : production.fixedLookupsHold = true)
    (selected : production.lookup? ordinal = some lookup)
    (consequence : Prop)
    (interpret : lookup.fixedRequestHolds = true → consequence) :
    consequence :=
  interpret (SymbolicEvaluation.fixedRequestHolds_of_lookup
    production ordinal lookup fixed selected)

/-- Interpret an accepted live `range_check_8_11` request without exposing the
caller's symbolic evaluator in the resulting proof term. -/
theorem fixedRange811BoundsOfLookup
    (production : SymbolicEvaluation)
    (ordinal : Nat)
    (numerator low high : M31)
    (fixed : production.fixedLookupsHold = true)
    (selected :
      production.lookup? ordinal = some ({
        ordinal
        domain := .rangeCheck811
        numerator
        tuple := #[low, high]
        role := .request
        tableId := some .rangeCheck811
        accessOrdinal := none
      } : EvaluatedLookup))
    (live : numerator ≠ 0) :
    low.val < 2 ^ 8 ∧ high.val < 2 ^ 11 := by
  have request := SymbolicEvaluation.fixedRequestHolds_of_lookup
    production ordinal _ fixed selected
  simpa [EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive, EvaluatedLookup.fixedMembership,
    FixedTableId.rangeCheck811_contains_iff, live] using request

/-- Interpret an accepted live `range_check_8_8` request. -/
theorem fixedRange88BoundsOfLookup
    (production : SymbolicEvaluation)
    (ordinal : Nat)
    (numerator low high : M31)
    (fixed : production.fixedLookupsHold = true)
    (selected :
      production.lookup? ordinal = some ({
        ordinal
        domain := .rangeCheck88
        numerator
        tuple := #[low, high]
        role := .request
        tableId := some .rangeCheck88
        accessOrdinal := none
      } : EvaluatedLookup))
    (live : numerator ≠ 0) :
    low.val < 2 ^ 8 ∧ high.val < 2 ^ 8 := by
  have request := SymbolicEvaluation.fixedRequestHolds_of_lookup
    production ordinal _ fixed selected
  simpa [EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive, EvaluatedLookup.fixedMembership,
    FixedTableId.rangeCheck88_contains_iff, live] using request

/-- Interpret the high-limb component of an accepted live M31 request. -/
theorem fixedRangeM31HighBoundOfLookup
    (production : SymbolicEvaluation)
    (ordinal : Nat)
    (numerator low high : M31)
    (fixed : production.fixedLookupsHold = true)
    (selected :
      production.lookup? ordinal = some ({
        ordinal
        domain := .rangeCheckM31
        numerator
        tuple := #[low, high]
        role := .request
        tableId := some .rangeCheckM31
        accessOrdinal := none
      } : EvaluatedLookup))
    (live : numerator ≠ 0) :
    high.val < 2 ^ 7 := by
  have request := SymbolicEvaluation.fixedRequestHolds_of_lookup
    production ordinal _ fixed selected
  have bounds := (FixedTableId.rangeCheckM31_contains_iff low high).mp
    (by simpa [EvaluatedLookup.fixedRequestHolds,
      EvaluatedLookup.isLive, EvaluatedLookup.fixedMembership, live]
      using request)
  exact bounds.2.1

/-- Interpret an accepted live 20-bit request. -/
theorem fixedRange20BoundOfLookup
    (production : SymbolicEvaluation)
    (ordinal : Nat)
    (numerator value : M31)
    (accessOrdinal : Option Nat)
    (fixed : production.fixedLookupsHold = true)
    (selected :
      production.lookup? ordinal = some ({
        ordinal
        domain := .rangeCheck20
        numerator
        tuple := #[value]
        role := .request
        tableId := some .rangeCheck20
        accessOrdinal
      } : EvaluatedLookup))
    (live : numerator ≠ 0) :
    value.val < 2 ^ 20 := by
  have request := SymbolicEvaluation.fixedRequestHolds_of_lookup
    production ordinal _ fixed selected
  exact (FixedTableId.rangeCheck20_contains_iff value).mp
    (by simpa [EvaluatedLookup.fixedRequestHolds,
      EvaluatedLookup.isLive, EvaluatedLookup.fixedMembership, live]
      using request)

theorem m31MulAssoc (a b c : M31) :
    (a * b) * c = a * (b * c) := by
  apply M31.ext
  change
    (((a.val * b.val) % M31.modulus) * c.val) % M31.modulus =
      (a.val * ((b.val * c.val) % M31.modulus)) % M31.modulus
  calc
    (((a.val * b.val) % M31.modulus) * c.val) % M31.modulus =
        (a.val * b.val * c.val) % M31.modulus := by
          simpa [Nat.mod_eq_of_lt c.isLt] using
            (Nat.mul_mod (a.val * b.val) c.val M31.modulus).symm
    _ = (a.val * (b.val * c.val)) % M31.modulus := by
          rw [Nat.mul_assoc]
    _ = (a.val * ((b.val * c.val) % M31.modulus)) % M31.modulus := by
          simpa [Nat.mod_eq_of_lt a.isLt] using
            Nat.mul_mod a.val (b.val * c.val) M31.modulus

theorem m31AddAssoc (a b c : M31) :
    (a + b) + c = a + (b + c) := by
  apply M31.ext
  change
    (((a.val + b.val) % M31.modulus) + c.val) % M31.modulus =
      (a.val + ((b.val + c.val) % M31.modulus)) % M31.modulus
  calc
    (((a.val + b.val) % M31.modulus) + c.val) % M31.modulus =
        (a.val + b.val + c.val) % M31.modulus := by
          simpa [Nat.mod_eq_of_lt c.isLt] using
            (Nat.add_mod (a.val + b.val) c.val M31.modulus).symm
    _ = (a.val + (b.val + c.val)) % M31.modulus := by
          rw [Nat.add_assoc]
    _ = (a.val + ((b.val + c.val) % M31.modulus)) % M31.modulus := by
          simpa [Nat.mod_eq_of_lt a.isLt] using
            Nat.add_mod a.val (b.val + c.val) M31.modulus

theorem reduceValAdd (left : M31) (right : Nat) :
    M31.reduce (left.val + right) =
      left + M31.reduce right := by
  calc
    M31.reduce (left.val + right) =
        M31.reduce left.val + M31.reduce right :=
      (Air.Bridge.TeamACommon.reduceAdd _ _).symm
    _ = left + M31.reduce right := by
      exact congrArg
        (fun value : M31 => value + M31.reduce right)
        (M31.reduce_toNat left)

theorem reduceAddSubCancelOfBound
    (prefixValue last : Nat)
    (prefixBound : prefixValue < M31.modulus)
    (lastBound : last < M31.modulus)
    (totalBound : prefixValue + last < M31.modulus) :
    (M31.reduce prefixValue + M31.reduce last) - M31.reduce last =
      M31.reduce prefixValue := by
  have prefixVal : (M31.reduce prefixValue).val = prefixValue :=
    M31.reduce_val_of_lt prefixValue prefixBound
  have lastVal : (M31.reduce last).val = last :=
    M31.reduce_val_of_lt last lastBound
  have sumVal :
      (M31.reduce prefixValue + M31.reduce last).val =
        prefixValue + last := by
    have fieldBound :
        (M31.reduce prefixValue).val +
            (M31.reduce last).val < M31.modulus := by
      rw [prefixVal, lastVal]
      exact totalBound
    have sum :=
      M31.add_val_of_lt
        (M31.reduce prefixValue) (M31.reduce last) fieldBound
    rw [prefixVal, lastVal] at sum
    exact sum
  have ordered :
      (M31.reduce last).val ≤
        (M31.reduce prefixValue + M31.reduce last).val := by
    rw [sumVal, lastVal]
    omega
  apply M31.ext
  rw [
    M31.sub_val_of_le _ _ ordered,
    sumVal,
    lastVal,
    prefixVal,
  ]
  omega

theorem inverse256 :
    M31.reduce 8388608 * M31.reduce 256 = 1 := by
  decide

private theorem m31ReduceCongr
    {left right : Nat}
    (congruent :
      left % M31.modulus = right % M31.modulus) :
    M31.reduce left = M31.reduce right := by
  apply M31.ext
  simpa only [M31.reduce_val, congruent]

theorem m31Negate
    (value : Nat)
    (bound : value < M31.modulus) :
    M31.reduce (M31.modulus - 1) *
        M31.reduce (M31.modulus - value) =
      M31.reduce value := by
  rw [Air.Bridge.TeamACommon.reduceMul]
  apply m31ReduceCongr
  have small : value < 2147483647 := by
    simpa [M31.modulus_eq] using bound
  have expand :
      (M31.modulus - 1) * (M31.modulus - value) =
        M31.modulus * (M31.modulus - value - 1) + value := by
    rw [M31.modulus_eq]
    omega
  rw [expand, Nat.mul_add_mod]

theorem carryEquationOfField
    (accumulated result carry : Nat)
    (accumulatedBound : accumulated < M31.modulus)
    (resultByteBound : result < 2 ^ 8)
    (carryBound : carry < 2 ^ 11)
    (equation :
      ((M31.reduce accumulated - M31.reduce result) *
          M31.reduce 8388608).val = carry) :
    accumulated = result + 256 * carry := by
  have carryFieldBound : carry < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have scaledCarryBound : carry * 256 < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have resultBound : result < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have fieldEquation :
      (M31.reduce accumulated - M31.reduce result) *
          M31.reduce 8388608 =
        M31.reduce carry := by
    apply M31.ext
    rw [equation, M31.reduce_val_of_lt carry carryFieldBound]
  have scaled :=
    congrArg (fun value : M31 => value * M31.reduce 256) fieldEquation
  change
    ((M31.reduce accumulated - M31.reduce result) *
          M31.reduce 8388608) * M31.reduce 256 =
      M31.reduce carry * M31.reduce 256 at scaled
  rw [m31MulAssoc, inverse256, M31.mul_one,
    Air.Bridge.TeamACommon.reduceMul] at scaled
  have values := congrArg M31.val scaled
  rw [M31.reduce_val_of_lt (carry * 256) scaledCarryBound] at values
  by_cases ordered : result ≤ accumulated
  · have fieldOrdered :
        (M31.reduce result).val ≤ (M31.reduce accumulated).val := by
      rw [M31.reduce_val_of_lt result resultBound,
        M31.reduce_val_of_lt accumulated accumulatedBound]
      exact ordered
    rw [M31.sub_val_of_le _ _ fieldOrdered,
      M31.reduce_val_of_lt accumulated accumulatedBound,
      M31.reduce_val_of_lt result resultBound] at values
    omega
  · have reverse : accumulated < result := Nat.lt_of_not_ge ordered
    have fieldReverse :
        (M31.reduce accumulated).val < (M31.reduce result).val := by
      rw [M31.reduce_val_of_lt accumulated accumulatedBound,
        M31.reduce_val_of_lt result resultBound]
      exact reverse
    rw [M31.sub_val_of_lt _ _ fieldReverse,
      M31.reduce_val_of_lt accumulated accumulatedBound,
      M31.reduce_val_of_lt result resultBound,
      M31.modulus_eq] at values
    omega

theorem accessClockFieldVal
    (clock ordinal : Nat)
    (clockPositive : 0 < clock)
    (clockBound : clock ≤ 2 ^ 24)
    (ordinalPositive : 0 < ordinal)
    (ordinalBound : ordinal ≤ 3) :
    (Air.Bridge.TeamACommon.accessClockField clock ordinal).val =
      accessClock clock ordinal := by
  have clockFieldBound : clock < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have ordinalFieldBound : ordinal < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have clockImage :
      (M31.reduce clock).val = clock :=
    M31.reduce_val_of_lt clock clockFieldBound
  have oneImage : (1 : M31).val = 1 := rfl
  have oneBelowClock :
      (1 : M31).val ≤ (M31.reduce clock).val := by
    rw [oneImage, clockImage]
    omega
  have predecessorImage :
      (M31.reduce clock - 1).val = clock - 1 := by
    rw [M31.sub_val_of_le _ _ oneBelowClock, clockImage, oneImage]
  have fourImage : (M31.reduce 4).val = 4 := by decide
  have ordinalImage : (M31.reduce ordinal).val = ordinal :=
    M31.reduce_val_of_lt ordinal ordinalFieldBound
  have productBound :
      (M31.reduce clock - 1).val * (M31.reduce 4).val <
        M31.modulus := by
    rw [predecessorImage, fourImage, M31.modulus_eq]
    omega
  have productImage :
      ((M31.reduce clock - 1) * M31.reduce 4).val =
        (clock - 1) * 4 := by
    rw [M31.mul_val_of_lt _ _ productBound, predecessorImage, fourImage]
  have sumBound :
      ((M31.reduce clock - 1) * M31.reduce 4).val +
          (M31.reduce ordinal).val <
        M31.modulus := by
    rw [productImage, ordinalImage, M31.modulus_eq]
    omega
  unfold Air.Bridge.TeamACommon.accessClockField accessClock
  rw [M31.add_val_of_lt _ _ sumBound, productImage, ordinalImage]

theorem validPreviousClockOfGap
    (clock ordinal previous : Nat)
    (clockPositive : 0 < clock)
    (clockBound : clock ≤ 2 ^ 24)
    (ordinalPositive : 0 < ordinal)
    (ordinalBound : ordinal ≤ 3)
    (previousBound : previous < 2 ^ 26)
    (gapBound :
      (Air.Bridge.TeamACommon.clockGapField
        clock ordinal previous).val < 2 ^ 20) :
    validPreviousClock previous (accessClock clock ordinal) := by
  let current := accessClock clock ordinal
  have currentImage :
      (Air.Bridge.TeamACommon.accessClockField clock ordinal).val =
        current := by
    exact
      accessClockFieldVal clock ordinal clockPositive clockBound
        ordinalPositive ordinalBound
  have previousFieldBound : previous < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have previousImage :
      (M31.reduce previous).val = previous :=
    M31.reduce_val_of_lt previous previousFieldBound
  have oneImage : (1 : M31).val = 1 := rfl
  have zeroImage : (0 : M31).val = 0 := rfl
  by_cases ordered : previous < current
  · have firstOrdered :
        (M31.reduce previous).val ≤
          (Air.Bridge.TeamACommon.accessClockField clock ordinal).val := by
      rw [previousImage, currentImage]
      omega
    have firstImage :
        (Air.Bridge.TeamACommon.accessClockField clock ordinal -
            M31.reduce previous).val =
          current - previous := by
      rw [M31.sub_val_of_le _ _ firstOrdered, currentImage, previousImage]
    have secondOrdered :
        (1 : M31).val ≤
          (Air.Bridge.TeamACommon.accessClockField clock ordinal -
            M31.reduce previous).val := by
      rw [oneImage, firstImage]
      omega
    have exactGap :
        (Air.Bridge.TeamACommon.clockGapField
          clock ordinal previous).val =
            current - previous - 1 := by
      unfold Air.Bridge.TeamACommon.clockGapField
      rw [M31.sub_val_of_le _ _ secondOrdered, firstImage, oneImage]
    constructor
    · exact ordered
    · rw [exactGap] at gapBound
      exact gapBound
  · have reverse : current ≤ previous := Nat.le_of_not_gt ordered
    by_cases equal : current = previous
    · have fieldEqual :
          Air.Bridge.TeamACommon.accessClockField clock ordinal =
            M31.reduce previous := by
        apply M31.ext
        rw [currentImage, previousImage, equal]
      have impossible := gapBound
      unfold Air.Bridge.TeamACommon.clockGapField at impossible
      rw [fieldEqual, M31.sub_self] at impossible
      have zeroBelowOne : (0 : M31).val < (1 : M31).val := by decide
      rw [M31.sub_val_of_lt _ _ zeroBelowOne, zeroImage, oneImage,
        M31.modulus_eq] at impossible
      omega
    · have strict : current < previous := by omega
      have fieldStrict :
          (Air.Bridge.TeamACommon.accessClockField clock ordinal).val <
            (M31.reduce previous).val := by
        rw [currentImage, previousImage]
        exact strict
      have firstImage :
          (Air.Bridge.TeamACommon.accessClockField clock ordinal -
              M31.reduce previous).val =
            M31.modulus + current - previous := by
        rw [M31.sub_val_of_lt _ _ fieldStrict, currentImage, previousImage]
      have oneBelowFirst :
          (1 : M31).val ≤
            (Air.Bridge.TeamACommon.accessClockField clock ordinal -
              M31.reduce previous).val := by
        rw [oneImage, firstImage, M31.modulus_eq]
        omega
      have impossible := gapBound
      unfold Air.Bridge.TeamACommon.clockGapField at impossible
      rw [M31.sub_val_of_le _ _ oneBelowFirst, firstImage, oneImage,
        M31.modulus_eq] at impossible
      omega

end RiscvRefinement.Publication.TeamB.MulhDiv
