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

private theorem m31Negate
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

/-! ## MULH / MULHSU / MULHU exact production rows -/

namespace HighMultiply

abbrev Row := MulhRow

structure Witness (row : Row) where
  destinationInverse : M31

private def bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  M31.reduce value.toNat

private def boolM31 : Bool → M31
  | false => 0
  | true => 1

private def mulhBit : MulhSelector → M31
  | .mulh => 1
  | _ => 0

private def mulhsuBit : MulhSelector → M31
  | .mulhsu => 1
  | _ => 0

private def mulhuBit : MulhSelector → M31
  | .mulhu => 1
  | _ => 0

def program : MulhSelector → LocalProgram
  | .mulh => Programs.mulh
  | .mulhsu => Programs.mulhsu
  | .mulhu => Programs.mulhu

/-- Exact 47-column order shared by the three production AIR programs. -/
def columns (row : Row) (witness : Witness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.rd
  | 3 => bitVecM31 row.rdPrevious.limb0
  | 4 => bitVecM31 row.rdPrevious.limb1
  | 5 => bitVecM31 row.rdPrevious.limb2
  | 6 => bitVecM31 row.rdPrevious.limb3
  | 7 => M31.reduce row.rdPreviousClock
  | 8 => bitVecM31 row.rdNext.limb0
  | 9 => bitVecM31 row.rdNext.limb1
  | 10 => bitVecM31 row.rdNext.limb2
  | 11 => bitVecM31 row.rdNext.limb3
  | 12 => bitVecM31 row.rs1
  | 13 => bitVecM31 row.rs1Previous.limb0
  | 14 => bitVecM31 row.rs1Previous.limb1
  | 15 => bitVecM31 row.rs1Previous.limb2
  | 16 => bitVecM31 row.rs1Previous.limb3
  | 17 => M31.reduce row.rs1PreviousClock
  | 18 => bitVecM31 row.rs1Next.limb0
  | 19 => bitVecM31 row.rs1Next.limb1
  | 20 => bitVecM31 row.rs1Next.limb2
  | 21 => bitVecM31 row.rs1Next.limb3
  | 22 => bitVecM31 row.rs2
  | 23 => bitVecM31 row.rs2Previous.limb0
  | 24 => bitVecM31 row.rs2Previous.limb1
  | 25 => bitVecM31 row.rs2Previous.limb2
  | 26 => bitVecM31 row.rs2Previous.limb3
  | 27 => M31.reduce row.rs2PreviousClock
  | 28 => bitVecM31 row.rs2Next.limb0
  | 29 => bitVecM31 row.rs2Next.limb1
  | 30 => bitVecM31 row.rs2Next.limb2
  | 31 => bitVecM31 row.rs2Next.limb3
  | 32 => bitVecM31 row.rdHigh.limb0
  | 33 => bitVecM31 row.rdHigh.limb1
  | 34 => bitVecM31 row.rdHigh.limb2
  | 35 => bitVecM31 row.rdHigh.limb3
  | 36 => boolM31 row.rs1Sign
  | 37 => boolM31 row.rs2Sign
  | 38 => mulhBit row.selector
  | 39 => mulhsuBit row.selector
  | 40 => mulhuBit row.selector
  | 41 => bitVecM31 row.result.limb0
  | 42 => bitVecM31 row.result.limb1
  | 43 => bitVecM31 row.result.limb2
  | 44 => bitVecM31 row.result.limb3
  | 45 => boolM31 row.rdNonzero
  | 46 => witness.destinationInverse
  | _ => 0

def evaluation (row : Row) (witness : Witness row) : SymbolicEvaluation :=
  (program row.selector).evalSymbolic (columns row witness)

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourceOnePreviousBound : row.rs1PreviousClock < 2 ^ 26
  sourceTwoPreviousBound : row.rs2PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcBound : row.pc.toNat + 4 < M31.modulus

abbrev Acceptance
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  Publication.AcceptedProductionEvaluation
    (evaluation row witness) relationHolds

private def accessClockField (row : Row) (ordinal : Nat) : M31 :=
  (M31.reduce row.clock - 1) * M31.reduce 4 +
    M31.reduce ordinal

private def activeField (row : Row) : M31 :=
  mulhBit row.selector + mulhsuBit row.selector + mulhuBit row.selector

private theorem activeField_eq_one (row : Row) :
    activeField row = 1 := by
  cases selector : row.selector <;>
    simp [activeField, selector, mulhBit, mulhsuBit, mulhuBit]

/-!
The generated programs store lookup events as node references.  Keeping this
small, exact copy of the common lookup-event suffix lets projection proofs use
`LocalProgram.lookup?_evalSymbolic_of_event`: event selection is checked once
against the generated source, independently of evaluating the complete event
array.  This is materially shallower than unfolding `lookup?` at every field.
-/
private def rawLookupEvent : Nat → LookupEvent
  | 24 => {
      ordinal := 24, domain := .programAccess, numerator := 177,
      tuple := #[1, 185, 2, 12, 22], role := .request, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 25 => {
      ordinal := 25, domain := .registersState, numerator := 177,
      tuple := #[1, 0], role := .consume, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 26 => {
      ordinal := 26, domain := .registersState, numerator := 49,
      tuple := #[187, 188], role := .emit, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 27 => {
      ordinal := 27, domain := .memoryAccess, numerator := 177,
      tuple := #[99, 12, 17, 13, 14, 15, 16], role := .consume,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 1
    }
  | 28 => {
      ordinal := 28, domain := .memoryAccess, numerator := 49,
      tuple := #[99, 12, 191, 18, 19, 20, 21], role := .emit,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 1
    }
  | 29 => {
      ordinal := 29, domain := .rangeCheck20, numerator := 177,
      tuple := #[193], role := .request, tableId := some .rangeCheck20,
      liveness := .nonzeroNumerator, accessOrdinal := some 1
    }
  | 30 => {
      ordinal := 30, domain := .memoryAccess, numerator := 177,
      tuple := #[99, 22, 27, 23, 24, 25, 26], role := .consume,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 2
    }
  | 31 => {
      ordinal := 31, domain := .memoryAccess, numerator := 49,
      tuple := #[99, 22, 195, 28, 29, 30, 31], role := .emit,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 2
    }
  | 32 => {
      ordinal := 32, domain := .rangeCheck20, numerator := 177,
      tuple := #[197], role := .request, tableId := some .rangeCheck20,
      liveness := .nonzeroNumerator, accessOrdinal := some 2
    }
  | 33 => {
      ordinal := 33, domain := .rangeCheck811, numerator := 177,
      tuple := #[32, 104], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 34 => {
      ordinal := 34, domain := .rangeCheck811, numerator := 177,
      tuple := #[33, 110], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 35 => {
      ordinal := 35, domain := .rangeCheck811, numerator := 177,
      tuple := #[34, 118], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 36 => {
      ordinal := 36, domain := .rangeCheck811, numerator := 177,
      tuple := #[35, 128], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 37 => {
      ordinal := 37, domain := .rangeCheck811, numerator := 177,
      tuple := #[41, 140], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 38 => {
      ordinal := 38, domain := .rangeCheck811, numerator := 177,
      tuple := #[42, 152], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 39 => {
      ordinal := 39, domain := .rangeCheck811, numerator := 177,
      tuple := #[43, 164], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 40 => {
      ordinal := 40, domain := .rangeCheck811, numerator := 177,
      tuple := #[44, 176], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 41 => {
      ordinal := 41, domain := .rangeCheckM31, numerator := 201,
      tuple := #[99, 200], role := .request, tableId := some .rangeCheckM31,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 42 => {
      ordinal := 42, domain := .rangeCheckM31, numerator := 204,
      tuple := #[99, 203], role := .request, tableId := some .rangeCheckM31,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 43 => {
      ordinal := 43, domain := .memoryAccess, numerator := 177,
      tuple := #[99, 2, 7, 3, 4, 5, 6], role := .consume,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 3
    }
  | 44 => {
      ordinal := 44, domain := .memoryAccess, numerator := 49,
      tuple := #[99, 2, 206, 8, 9, 10, 11], role := .emit,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 3
    }
  | 45 => {
      ordinal := 45, domain := .rangeCheck20, numerator := 177,
      tuple := #[208], role := .request, tableId := some .rangeCheck20,
      liveness := .nonzeroNumerator, accessOrdinal := some 3
    }
  | ordinal => {
      ordinal, domain := .programAccess, numerator := 0, tuple := #[],
      role := .request, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }

set_option maxRecDepth 30000 in
private theorem rawLookupEvent_selected
    (selector : MulhSelector)
    (ordinal : Nat)
    (lower : 24 ≤ ordinal)
    (upper : ordinal ≤ 45) :
    (program selector).source.events[ordinal]? =
      some (.lookup (rawLookupEvent ordinal)) := by
  have possibilities :
      ordinal = 24 ∨ ordinal = 25 ∨ ordinal = 26 ∨ ordinal = 27 ∨
      ordinal = 28 ∨ ordinal = 29 ∨ ordinal = 30 ∨ ordinal = 31 ∨
      ordinal = 32 ∨ ordinal = 33 ∨ ordinal = 34 ∨ ordinal = 35 ∨
      ordinal = 36 ∨ ordinal = 37 ∨ ordinal = 38 ∨ ordinal = 39 ∨
      ordinal = 40 ∨ ordinal = 41 ∨ ordinal = 42 ∨ ordinal = 43 ∨
      ordinal = 44 ∨ ordinal = 45 := by
    omega
  rcases possibilities with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    cases selector <;> rfl

private def evaluatedRawLookup
    (row : Row)
    (witness : Witness row)
    (event : LookupEvent) : EvaluatedLookup where
  ordinal := event.ordinal
  domain := event.domain
  numerator :=
    ((program row.selector).evalNodesSymbolic
      (columns row witness)).getSymbolic event.numerator
  tuple :=
    event.tuple.map
      ((program row.selector).evalNodesSymbolic
        (columns row witness)).getSymbolic
  role := event.role
  tableId := event.tableId
  accessOrdinal := event.accessOrdinal

private theorem rawLookupProjection
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (lower : 24 ≤ ordinal)
    (upper : ordinal ≤ 45) :
    (evaluation row witness).lookup? ordinal =
      some (evaluatedRawLookup row witness (rawLookupEvent ordinal)) := by
  unfold evaluation evaluatedRawLookup
  exact
    LocalProgram.lookup?_evalSymbolic_of_event
      (program row.selector) (columns row witness) ordinal
      (rawLookupEvent ordinal)
      (rawLookupEvent_selected row.selector ordinal lower upper)

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 24
  domain := .programAccess
  numerator := -activeField row
  tuple := #[
    bitVecM31 row.pc, M31.reduce row.selector.opcodeId,
    bitVecM31 row.rd, bitVecM31 row.rs1, bitVecM31 row.rs2
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 25
  domain := .registersState
  numerator := -activeField row
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 26
  domain := .registersState
  numerator := activeField row
  tuple := #[bitVecM31 row.pc + M31.reduce 4, M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

private def registerConsume
    (row : Row)
    (ordinal accessOrdinal : Nat)
    (address : RegisterIndex)
    (previousClock : Nat)
    (previous : WordBytes) : EvaluatedLookup where
  ordinal
  domain := .memoryAccess
  numerator := -activeField row
  tuple := #[
    0, bitVecM31 address, M31.reduce previousClock,
    bitVecM31 previous.limb0, bitVecM31 previous.limb1,
    bitVecM31 previous.limb2, bitVecM31 previous.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some accessOrdinal

private def registerEmit
    (row : Row)
    (ordinal accessOrdinal : Nat)
    (address : RegisterIndex)
    (next : WordBytes) : EvaluatedLookup where
  ordinal
  domain := .memoryAccess
  numerator := activeField row
  tuple := #[
    0, bitVecM31 address, accessClockField row accessOrdinal,
    bitVecM31 next.limb0, bitVecM31 next.limb1,
    bitVecM31 next.limb2, bitVecM31 next.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some accessOrdinal

private def tupleOrdinals : List Nat :=
  [24, 25, 26, 27, 28, 30, 31, 43, 44]

private def expectedTupleLookup (row : Row) : Nat → EvaluatedLookup
  | 24 => programLookup row
  | 25 => stateConsumeLookup row
  | 26 => stateEmitLookup row
  | 27 =>
      registerConsume row 27 1
        row.rs1 row.rs1PreviousClock row.rs1Previous
  | 28 => registerEmit row 28 1 row.rs1 row.rs1Next
  | 30 =>
      registerConsume row 30 2
        row.rs2 row.rs2PreviousClock row.rs2Previous
  | 31 => registerEmit row 31 2 row.rs2 row.rs2Next
  | 43 =>
      registerConsume row 43 3
        row.rd row.rdPreviousClock row.rdPrevious
  | 44 => registerEmit row 44 3 row.rd row.rdNext
  | _ => programLookup row

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_tuple_all
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 24) =
        expectedTupleLookup row 24 ∧
      evaluatedRawLookup row witness (rawLookupEvent 25) =
        expectedTupleLookup row 25 ∧
      evaluatedRawLookup row witness (rawLookupEvent 26) =
        expectedTupleLookup row 26 ∧
      evaluatedRawLookup row witness (rawLookupEvent 27) =
        expectedTupleLookup row 27 ∧
      evaluatedRawLookup row witness (rawLookupEvent 28) =
        expectedTupleLookup row 28 ∧
      evaluatedRawLookup row witness (rawLookupEvent 30) =
        expectedTupleLookup row 30 ∧
      evaluatedRawLookup row witness (rawLookupEvent 31) =
        expectedTupleLookup row 31 ∧
      evaluatedRawLookup row witness (rawLookupEvent 43) =
        expectedTupleLookup row 43 ∧
      evaluatedRawLookup row witness (rawLookupEvent 44) =
        expectedTupleLookup row 44 := by
  cases selector : row.selector <;>
    simp [
      evaluatedRawLookup, rawLookupEvent, expectedTupleLookup,
      program, selector,
      Programs.mulh, Programs.mulhsu, Programs.mulhu,
      Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
      LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic,
      columns, programLookup, stateConsumeLookup, stateEmitLookup,
      registerConsume, registerEmit, accessClockField, activeField,
      bitVecM31, boolM31, mulhBit, mulhsuBit, mulhuBit,
      MulhSelector.opcodeId,
    ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_tuple
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ tupleOrdinals) :
    evaluatedRawLookup row witness (rawLookupEvent ordinal) =
      expectedTupleLookup row ordinal := by
  obtain ⟨h24, h25, h26, h27, h28, h30, h31, h43, h44⟩ :=
    evaluatedRawLookup_tuple_all row witness
  simp [tupleOrdinals] at member
  rcases member with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals assumption

private theorem tupleProjectionAt
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ tupleOrdinals) :
    (evaluation row witness).lookup? ordinal =
      some (expectedTupleLookup row ordinal) := by
  have lower : 24 ≤ ordinal := by
    have choices := member
    simp [tupleOrdinals] at choices
    omega
  have upper : ordinal ≤ 45 := by
    have choices := member
    simp [tupleOrdinals] at choices
    omega
  exact
    (rawLookupProjection row witness ordinal lower upper).trans
      (congrArg some (evaluatedRawLookup_tuple row witness ordinal member))

structure ExactTupleProjection (row : Row) (witness : Witness row) : Prop where
  program :
    (evaluation row witness).lookup? 24 = some (programLookup row)
  stateConsume :
    (evaluation row witness).lookup? 25 = some (stateConsumeLookup row)
  stateEmit :
    (evaluation row witness).lookup? 26 = some (stateEmitLookup row)
  sourceOneConsume :
    (evaluation row witness).lookup? 27 =
      some (registerConsume row 27 1
        row.rs1 row.rs1PreviousClock row.rs1Previous)
  sourceOneEmit :
    (evaluation row witness).lookup? 28 =
      some (registerEmit row 28 1 row.rs1 row.rs1Next)
  sourceTwoConsume :
    (evaluation row witness).lookup? 30 =
      some (registerConsume row 30 2
        row.rs2 row.rs2PreviousClock row.rs2Previous)
  sourceTwoEmit :
    (evaluation row witness).lookup? 31 =
      some (registerEmit row 31 2 row.rs2 row.rs2Next)
  destinationConsume :
    (evaluation row witness).lookup? 43 =
      some (registerConsume row 43 3
        row.rd row.rdPreviousClock row.rdPrevious)
  destinationEmit :
    (evaluation row witness).lookup? 44 =
      some (registerEmit row 44 3 row.rd row.rdNext)

set_option maxRecDepth 30000 in
theorem exactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection row witness := by
  exact {
    program := tupleProjectionAt row witness 24 (by decide)
    stateConsume := tupleProjectionAt row witness 25 (by decide)
    stateEmit := tupleProjectionAt row witness 26 (by decide)
    sourceOneConsume := tupleProjectionAt row witness 27 (by decide)
    sourceOneEmit := tupleProjectionAt row witness 28 (by decide)
    sourceTwoConsume := tupleProjectionAt row witness 30 (by decide)
    sourceTwoEmit := tupleProjectionAt row witness 31 (by decide)
    destinationConsume := tupleProjectionAt row witness 43 (by decide)
    destinationEmit := tupleProjectionAt row witness 44 (by decide)
  }

private def signFillField : Bool → M31
  | false => 0
  | true => M31.reduce 255

private def carry0Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.rdHigh.limb0) * M31.reduce 8388608

private def carry1Field (row : Row) : M31 :=
  (carry0Field row +
        bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb1 +
        bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.rdHigh.limb1) * M31.reduce 8388608

private def carry2Field (row : Row) : M31 :=
  (carry1Field row +
        bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb2 +
        bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb1 +
        bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.rdHigh.limb2) * M31.reduce 8388608

private def carry3Field (row : Row) : M31 :=
  (carry2Field row +
        bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb3 +
        bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb2 +
        bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb1 +
        bitVecM31 row.rs1Next.limb3 * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.rdHigh.limb3) * M31.reduce 8388608

private def carry4Field (row : Row) : M31 :=
  (carry3Field row +
        bitVecM31 row.rs1Next.limb0 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb3 +
        bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb2 +
        bitVecM31 row.rs1Next.limb3 * bitVecM31 row.rs2Next.limb1 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.result.limb0) * M31.reduce 8388608

private def carry5Field (row : Row) : M31 :=
  (carry4Field row +
        bitVecM31 row.rs1Next.limb0 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb1 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb3 +
        bitVecM31 row.rs1Next.limb3 * bitVecM31 row.rs2Next.limb2 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb1 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.result.limb1) * M31.reduce 8388608

private def carry6Field (row : Row) : M31 :=
  (carry5Field row +
        bitVecM31 row.rs1Next.limb0 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb1 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb2 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb3 * bitVecM31 row.rs2Next.limb3 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb2 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb1 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.result.limb2) * M31.reduce 8388608

private def carry7Field (row : Row) : M31 :=
  (carry6Field row +
        bitVecM31 row.rs1Next.limb0 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb1 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb2 * signFillField row.rs2Sign +
        bitVecM31 row.rs1Next.limb3 * signFillField row.rs2Sign +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb3 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb2 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb1 +
        signFillField row.rs1Sign * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.result.limb3) * M31.reduce 8388608

private def clockGapField
    (row : Row) (ordinal previous : Nat) : M31 :=
  accessClockField row ordinal - M31.reduce previous - 1

private def clockLookup
    (row : Row)
    (ordinal eventOrdinal previous : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck20
  numerator := -activeField row
  tuple := #[clockGapField row ordinal previous]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some ordinal

private def carryLookup
    (row : Row)
    (ordinal : Nat) (result : Byte) (carry : M31) : EvaluatedLookup where
  ordinal
  domain := .rangeCheck811
  numerator := -activeField row
  tuple := #[bitVecM31 result, carry]
  role := .request
  tableId := some .rangeCheck811
  accessOrdinal := none

private def signLookup
    (ordinal : Nat)
    (active : M31)
    (top : Byte)
    (sign : Bool) : EvaluatedLookup where
  ordinal
  domain := .rangeCheckM31
  numerator := -active
  tuple := #[
    0,
    bitVecM31 top - boolM31 sign * M31.reduce 128
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def fixedOrdinals : List Nat :=
  [29, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 45]

private def expectedFixedLookup (row : Row) : Nat → EvaluatedLookup
  | 29 => clockLookup row 1 29 row.rs1PreviousClock
  | 32 => clockLookup row 2 32 row.rs2PreviousClock
  | 33 => carryLookup row 33 row.rdHigh.limb0 (carry0Field row)
  | 34 => carryLookup row 34 row.rdHigh.limb1 (carry1Field row)
  | 35 => carryLookup row 35 row.rdHigh.limb2 (carry2Field row)
  | 36 => carryLookup row 36 row.rdHigh.limb3 (carry3Field row)
  | 37 => carryLookup row 37 row.result.limb0 (carry4Field row)
  | 38 => carryLookup row 38 row.result.limb1 (carry5Field row)
  | 39 => carryLookup row 39 row.result.limb2 (carry6Field row)
  | 40 => carryLookup row 40 row.result.limb3 (carry7Field row)
  | 41 =>
      signLookup 41
        (mulhBit row.selector + mulhsuBit row.selector)
        row.rs1Next.limb3 row.rs1Sign
  | 42 =>
      signLookup 42 (mulhBit row.selector)
        row.rs2Next.limb3 row.rs2Sign
  | 45 => clockLookup row 3 45 row.rdPreviousClock
  | _ => clockLookup row 1 29 row.rs1PreviousClock

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_fixed_all
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 29) =
        expectedFixedLookup row 29 ∧
      evaluatedRawLookup row witness (rawLookupEvent 32) =
        expectedFixedLookup row 32 ∧
      evaluatedRawLookup row witness (rawLookupEvent 33) =
        expectedFixedLookup row 33 ∧
      evaluatedRawLookup row witness (rawLookupEvent 34) =
        expectedFixedLookup row 34 ∧
      evaluatedRawLookup row witness (rawLookupEvent 35) =
        expectedFixedLookup row 35 ∧
      evaluatedRawLookup row witness (rawLookupEvent 36) =
        expectedFixedLookup row 36 ∧
      evaluatedRawLookup row witness (rawLookupEvent 37) =
        expectedFixedLookup row 37 ∧
      evaluatedRawLookup row witness (rawLookupEvent 38) =
        expectedFixedLookup row 38 ∧
      evaluatedRawLookup row witness (rawLookupEvent 39) =
        expectedFixedLookup row 39 ∧
      evaluatedRawLookup row witness (rawLookupEvent 40) =
        expectedFixedLookup row 40 ∧
      evaluatedRawLookup row witness (rawLookupEvent 41) =
        expectedFixedLookup row 41 ∧
      evaluatedRawLookup row witness (rawLookupEvent 42) =
        expectedFixedLookup row 42 ∧
      evaluatedRawLookup row witness (rawLookupEvent 45) =
        expectedFixedLookup row 45 := by
  cases selector : row.selector <;>
    cases sourceOneSign : row.rs1Sign <;>
    cases sourceTwoSign : row.rs2Sign <;>
    simp [
      evaluatedRawLookup, rawLookupEvent, expectedFixedLookup,
      program, selector,
      Programs.mulh, Programs.mulhsu, Programs.mulhu,
      Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
      LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic,
      columns, clockLookup, carryLookup, signLookup,
      clockGapField, accessClockField, activeField,
      carry0Field, carry1Field, carry2Field, carry3Field,
      carry4Field, carry5Field, carry6Field, carry7Field,
      signFillField, bitVecM31, boolM31,
      sourceOneSign, sourceTwoSign,
      mulhBit, mulhsuBit, mulhuBit,
    ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_fixed
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ fixedOrdinals) :
    evaluatedRawLookup row witness (rawLookupEvent ordinal) =
      expectedFixedLookup row ordinal := by
  obtain
      ⟨h29, h32, h33, h34, h35, h36, h37,
        h38, h39, h40, h41, h42, h45⟩ :=
    evaluatedRawLookup_fixed_all row witness
  simp [fixedOrdinals] at member
  rcases member with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl
  all_goals assumption

private theorem fixedProjectionAt
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ fixedOrdinals) :
    (evaluation row witness).lookup? ordinal =
      some (expectedFixedLookup row ordinal) := by
  have lower : 24 ≤ ordinal := by
    have choices := member
    simp [fixedOrdinals] at choices
    omega
  have upper : ordinal ≤ 45 := by
    have choices := member
    simp [fixedOrdinals] at choices
    omega
  exact
    (rawLookupProjection row witness ordinal lower upper).trans
      (congrArg some (evaluatedRawLookup_fixed row witness ordinal member))

structure ExactFixedProjection (row : Row) (witness : Witness row) : Prop where
  sourceOneClock :
    (evaluation row witness).lookup? 29 =
      some (clockLookup row 1 29 row.rs1PreviousClock)
  sourceTwoClock :
    (evaluation row witness).lookup? 32 =
      some (clockLookup row 2 32 row.rs2PreviousClock)
  carry0 :
    (evaluation row witness).lookup? 33 =
      some (carryLookup row 33 row.rdHigh.limb0 (carry0Field row))
  carry1 :
    (evaluation row witness).lookup? 34 =
      some (carryLookup row 34 row.rdHigh.limb1 (carry1Field row))
  carry2 :
    (evaluation row witness).lookup? 35 =
      some (carryLookup row 35 row.rdHigh.limb2 (carry2Field row))
  carry3 :
    (evaluation row witness).lookup? 36 =
      some (carryLookup row 36 row.rdHigh.limb3 (carry3Field row))
  carry4 :
    (evaluation row witness).lookup? 37 =
      some (carryLookup row 37 row.result.limb0 (carry4Field row))
  carry5 :
    (evaluation row witness).lookup? 38 =
      some (carryLookup row 38 row.result.limb1 (carry5Field row))
  carry6 :
    (evaluation row witness).lookup? 39 =
      some (carryLookup row 39 row.result.limb2 (carry6Field row))
  carry7 :
    (evaluation row witness).lookup? 40 =
      some (carryLookup row 40 row.result.limb3 (carry7Field row))
  sourceOneSign :
    (evaluation row witness).lookup? 41 =
      some (signLookup 41
        (mulhBit row.selector + mulhsuBit row.selector)
        row.rs1Next.limb3 row.rs1Sign)
  sourceTwoSign :
    (evaluation row witness).lookup? 42 =
      some (signLookup 42 (mulhBit row.selector)
        row.rs2Next.limb3 row.rs2Sign)
  destinationClock :
    (evaluation row witness).lookup? 45 =
      some (clockLookup row 3 45 row.rdPreviousClock)

set_option maxRecDepth 30000 in
theorem exactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection row witness := by
  exact {
    sourceOneClock := fixedProjectionAt row witness 29 (by decide)
    sourceTwoClock := fixedProjectionAt row witness 32 (by decide)
    carry0 := fixedProjectionAt row witness 33 (by decide)
    carry1 := fixedProjectionAt row witness 34 (by decide)
    carry2 := fixedProjectionAt row witness 35 (by decide)
    carry3 := fixedProjectionAt row witness 36 (by decide)
    carry4 := fixedProjectionAt row witness 37 (by decide)
    carry5 := fixedProjectionAt row witness 38 (by decide)
    carry6 := fixedProjectionAt row witness 39 (by decide)
    carry7 := fixedProjectionAt row witness 40 (by decide)
    sourceOneSign := fixedProjectionAt row witness 41 (by decide)
    sourceTwoSign := fixedProjectionAt row witness 42 (by decide)
    destinationClock := fixedProjectionAt row witness 45 (by decide)
  }

private theorem byteBound (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byteEqOfFieldEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

def constraintRoots : Array Nat := #[
  51, 53, 55, 57, 59, 61, 63, 64, 66, 68, 70, 72,
  74, 76, 78, 80, 82, 84, 86, 88, 90, 92, 94, 95
]

set_option maxHeartbeats 800000 in
set_option maxRecDepth 30000 in
private theorem constraintsHoldEvents
    (selector : MulhSelector)
    (nodes : LocalValues) :
    ((program selector).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      constraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  cases selector
  · simpa [program, Programs.mulh, Programs.mulhSource, constraintRoots,
      Event.evalSymbolic]
  · simpa [program, Programs.mulhsu, Programs.mulhsuSource, constraintRoots,
      Event.evalSymbolic]
  · simpa [program, Programs.mulhu, Programs.mulhuSource, constraintRoots,
      Event.evalSymbolic]

theorem constraintsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      constraintRoots.all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) :=
  constraintsHoldEvents row.selector (evaluation row witness).nodes

theorem constraintRootZero
    (row : Row)
    (witness : Witness row)
    (accepted : (evaluation row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ constraintRoots) :
    (evaluation row witness).nodes.getSymbolic root = 0 := by
  rw [constraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

structure DirectEquations (row : Row) (witness : Witness row) : Prop where
  unsignedOne :
    (1 - mulhBit row.selector - mulhsuBit row.selector) *
      boolM31 row.rs1Sign = 0
  unsignedTwo :
    (1 - mulhBit row.selector) * boolM31 row.rs2Sign = 0
  destinationZero :
    bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) = 0
  destinationInverse :
    bitVecM31 row.rd * witness.destinationInverse -
      boolM31 row.rdNonzero = 0
  destination0 :
    bitVecM31 row.rdNext.limb0 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb0 = 0
  destination1 :
    bitVecM31 row.rdNext.limb1 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb1 = 0
  destination2 :
    bitVecM31 row.rdNext.limb2 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb2 = 0
  destination3 :
    bitVecM31 row.rdNext.limb3 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb3 = 0
  sourceOne0 :
    bitVecM31 row.rs1Next.limb0 -
      bitVecM31 row.rs1Previous.limb0 = 0
  sourceOne1 :
    bitVecM31 row.rs1Next.limb1 -
      bitVecM31 row.rs1Previous.limb1 = 0
  sourceOne2 :
    bitVecM31 row.rs1Next.limb2 -
      bitVecM31 row.rs1Previous.limb2 = 0
  sourceOne3 :
    bitVecM31 row.rs1Next.limb3 -
      bitVecM31 row.rs1Previous.limb3 = 0
  sourceTwo0 :
    bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.rs2Previous.limb0 = 0
  sourceTwo1 :
    bitVecM31 row.rs2Next.limb1 -
      bitVecM31 row.rs2Previous.limb1 = 0
  sourceTwo2 :
    bitVecM31 row.rs2Next.limb2 -
      bitVecM31 row.rs2Previous.limb2 = 0
  sourceTwo3 :
    bitVecM31 row.rs2Next.limb3 -
      bitVecM31 row.rs2Previous.limb3 = 0

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquations
    (row : Row)
    (witness : Witness row)
    (direct : (evaluation row witness).constraintsHold = true) :
    DirectEquations row witness := by
  have unsignedOne :=
    constraintRootZero row witness direct 63 (by simp [constraintRoots])
  have unsignedTwo :=
    constraintRootZero row witness direct 64 (by simp [constraintRoots])
  have destinationZero :=
    constraintRootZero row witness direct 68 (by simp [constraintRoots])
  have destinationInverse :=
    constraintRootZero row witness direct 70 (by simp [constraintRoots])
  have destination0 :=
    constraintRootZero row witness direct 72 (by simp [constraintRoots])
  have destination1 :=
    constraintRootZero row witness direct 74 (by simp [constraintRoots])
  have destination2 :=
    constraintRootZero row witness direct 76 (by simp [constraintRoots])
  have destination3 :=
    constraintRootZero row witness direct 78 (by simp [constraintRoots])
  have sourceOne0 :=
    constraintRootZero row witness direct 80 (by simp [constraintRoots])
  have sourceOne1 :=
    constraintRootZero row witness direct 82 (by simp [constraintRoots])
  have sourceOne2 :=
    constraintRootZero row witness direct 84 (by simp [constraintRoots])
  have sourceOne3 :=
    constraintRootZero row witness direct 86 (by simp [constraintRoots])
  have sourceTwo0 :=
    constraintRootZero row witness direct 88 (by simp [constraintRoots])
  have sourceTwo1 :=
    constraintRootZero row witness direct 90 (by simp [constraintRoots])
  have sourceTwo2 :=
    constraintRootZero row witness direct 92 (by simp [constraintRoots])
  have sourceTwo3 :=
    constraintRootZero row witness direct 94 (by simp [constraintRoots])
  cases selector : row.selector
  all_goals
    exact {
      unsignedOne := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic,
          columns, mulhBit, mulhsuBit, mulhuBit, boolM31,
        ] using unsignedOne
      unsignedTwo := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic,
          columns, mulhBit, mulhsuBit, mulhuBit, boolM31,
        ] using unsignedTwo
      destinationZero := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
        ] using destinationZero
      destinationInverse := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
        ] using destinationInverse
      destination0 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
        ] using destination0
      destination1 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
        ] using destination1
      destination2 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
        ] using destination2
      destination3 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
        ] using destination3
      sourceOne0 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceOne0
      sourceOne1 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceOne1
      sourceOne2 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceOne2
      sourceOne3 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceOne3
      sourceTwo0 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceTwo0
      sourceTwo1 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceTwo1
      sourceTwo2 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceTwo2
      sourceTwo3 := by
        simpa [
          evaluation, program, selector,
          Programs.mulh, Programs.mulhsu, Programs.mulhu,
          Programs.mulhSource, Programs.mulhsuSource, Programs.mulhuSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, columns,
          mulhBit, mulhsuBit, mulhuBit,
        ] using sourceTwo3
    }

structure DirectConsequences (row : Row) : Prop where
  unsignedSourceOne :
    row.selector.signedSourceOne = false → row.rs1Sign = false
  unsignedSourceTwo :
    row.selector.signedSourceTwo = false → row.rs2Sign = false
  destinationFlag :
    row.rdNonzero = decide (row.rd ≠ zeroRegister)
  destination :
    row.rdNext =
      if row.rdNonzero then row.result else WordBytes.zero
  sourceOne : row.rs1Next = row.rs1Previous
  sourceTwo : row.rs2Next = row.rs2Previous

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem directConsequences
    (row : Row)
    (witness : Witness row)
    (direct : (evaluation row witness).constraintsHold = true) :
    DirectConsequences row := by
  rcases directEquations row witness direct with
    ⟨unsignedOne, unsignedTwo, destinationZero, destinationInverse,
      destination0, destination1, destination2, destination3,
      sourceOne0, sourceOne1, sourceOne2, sourceOne3,
      sourceTwo0, sourceTwo1, sourceTwo2, sourceTwo3⟩
  have oneNeZero : (1 : M31) ≠ 0 := by decide
  refine {
    unsignedSourceOne := ?_
    unsignedSourceTwo := ?_
    destinationFlag :=
      Air.Bridge.TeamACommon.destinationFlag_of_equations
        row.rd row.rdNonzero witness.destinationInverse
        (by simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using destinationZero)
        (by simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using destinationInverse)
    destination :=
      Air.Bridge.TeamACommon.destinationBytes_of_equations
        row.rdNext row.result row.rdNonzero
        (by simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using destination0)
        (by simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using destination1)
        (by simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using destination2)
        (by simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using destination3)
    sourceOne := ?_
    sourceTwo := ?_
  }
  · intro unsigned
    cases selector : row.selector <;>
      cases sign : row.rs1Sign <;>
      simp_all [
        MulhSelector.signedSourceOne,
        mulhBit,
        mulhsuBit,
        mulhuBit,
        boolM31,
        oneNeZero,
      ]
  · intro unsigned
    cases selector : row.selector <;>
      cases sign : row.rs2Sign <;>
      simp_all [
        MulhSelector.signedSourceTwo,
        mulhBit,
        mulhsuBit,
        mulhuBit,
        boolM31,
        oneNeZero,
      ]
  · apply WordBytes.eq_of_limbs <;> apply byteEqOfFieldEq
    · exact (M31.sub_eq_zero_iff _ _).mp sourceOne0
    · exact (M31.sub_eq_zero_iff _ _).mp sourceOne1
    · exact (M31.sub_eq_zero_iff _ _).mp sourceOne2
    · exact (M31.sub_eq_zero_iff _ _).mp sourceOne3
  · apply WordBytes.eq_of_limbs <;> apply byteEqOfFieldEq
    · exact (M31.sub_eq_zero_iff _ _).mp sourceTwo0
    · exact (M31.sub_eq_zero_iff _ _).mp sourceTwo1
    · exact (M31.sub_eq_zero_iff _ _).mp sourceTwo2
    · exact (M31.sub_eq_zero_iff _ _).mp sourceTwo3

private theorem range20BoundOfLookup
    (row : Row)
    (witness : Witness row)
    (ordinal accessOrdinal previous : Nat)
    (fixed : (evaluation row witness).fixedLookupsHold = true)
    (selected :
      (evaluation row witness).lookup? ordinal =
        some (clockLookup row accessOrdinal ordinal previous)) :
    (clockGapField row accessOrdinal previous).val < 2 ^ 20 := by
  let production := evaluation row witness
  change production.fixedLookupsHold = true at fixed
  change
    production.lookup? ordinal =
      some (clockLookup row accessOrdinal ordinal previous) at selected
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      production ordinal
      (clockLookup row accessOrdinal ordinal previous) fixed selected
  have canonicalRequest :
      (EvaluatedLookup.fixedRequestHolds {
        ordinal
        domain := .rangeCheck20
        numerator := -(1 : M31)
        tuple := #[clockGapField row accessOrdinal previous]
        role := .request
        tableId := some .rangeCheck20
        accessOrdinal := some accessOrdinal
      }) = true := by
    simpa [clockLookup, activeField_eq_one] using request
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      ordinal (some accessOrdinal)
      (clockGapField row accessOrdinal previous)).mp canonicalRequest

private theorem range811BoundsOfLookup
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (result : Byte)
    (carry : M31)
    (fixed : (evaluation row witness).fixedLookupsHold = true)
    (selected :
      (evaluation row witness).lookup? ordinal =
        some (carryLookup row ordinal result carry)) :
    (bitVecM31 result).val < 2 ^ 8 ∧ carry.val < 2 ^ 11 := by
  let production := evaluation row witness
  change production.fixedLookupsHold = true at fixed
  change
    production.lookup? ordinal =
      some (carryLookup row ordinal result carry) at selected
  have request :
      (carryLookup row ordinal result carry).fixedRequestHolds = true :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      production ordinal
      (carryLookup row ordinal result carry) fixed selected
  have negOneNeZero : -(1 : M31) ≠ 0 := by decide
  simpa [
    carryLookup,
    activeField_eq_one,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    FixedTableId.rangeCheck811_contains_iff,
    negOneNeZero,
  ] using request

private theorem signRemainderOfBound
    (top : Byte)
    (sign : Bool)
    (highBound :
      (bitVecM31 top - boolM31 sign * M31.reduce 128).val < 2 ^ 7) :
    ∃ rest : BitVec 7,
      top.toNat = 128 * multiplySignBit sign + rest.toNat := by
  have topBound : top.toNat < M31.modulus := by
    have byteBound := top.isLt
    simp only [Nat.reducePow] at byteBound
    rw [M31.modulus_eq]
    omega
  have topImage : (bitVecM31 top).val = top.toNat := by
    exact M31.reduce_val_of_lt top.toNat topBound
  cases sign with
  | false =>
      simp only [boolM31, M31.zero_mul, M31.sub_zero] at highBound
      rw [topImage] at highBound
      refine ⟨BitVec.ofNat 7 top.toNat, ?_⟩
      have rest :
          (BitVec.ofNat 7 top.toNat).toNat = top.toNat := by
        rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt highBound]
      rw [rest]
      simp [multiplySignBit]
  | true =>
      have oneImage : boolM31 true = 1 := rfl
      have constantImage : (M31.reduce 128).val = 128 := by decide
      have productImage :
          (boolM31 true * M31.reduce 128).val = 128 := by
        rw [oneImage, M31.one_mul, constantImage]
      by_cases low : top.toNat < 128
      · have fieldLow :
          (bitVecM31 top).val <
            (boolM31 true * M31.reduce 128).val := by
          rw [topImage, productImage]
          exact low
        have wrapped :=
          M31.sub_val_of_lt
            (bitVecM31 top) (boolM31 true * M31.reduce 128) fieldLow
        rw [topImage, productImage, M31.modulus_eq] at wrapped
        rw [wrapped] at highBound
        omega
      · have order : 128 ≤ top.toNat := Nat.le_of_not_gt low
        have fieldOrder :
            (boolM31 true * M31.reduce 128).val ≤
              (bitVecM31 top).val := by
          rw [topImage, productImage]
          exact order
        have difference :=
          M31.sub_val_of_le
            (bitVecM31 top) (boolM31 true * M31.reduce 128) fieldOrder
        rw [topImage, productImage] at difference
        refine ⟨BitVec.ofNat 7 (top.toNat - 128), ?_⟩
        have differenceBound : top.toNat - 128 < 2 ^ 7 := by
          rw [difference] at highBound
          exact highBound
        have rest :
            (BitVec.ofNat 7 (top.toNat - 128)).toNat =
              top.toNat - 128 := by
          rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt differenceBound]
        rw [rest]
        simp [multiplySignBit]
        omega

structure FixedConsequences (row : Row) : Prop where
  sourceOneGap :
    (clockGapField row 1 row.rs1PreviousClock).val < 2 ^ 20
  sourceTwoGap :
    (clockGapField row 2 row.rs2PreviousClock).val < 2 ^ 20
  destinationGap :
    (clockGapField row 3 row.rdPreviousClock).val < 2 ^ 20
  carry0Bound : (carry0Field row).val < 2 ^ 11
  carry1Bound : (carry1Field row).val < 2 ^ 11
  carry2Bound : (carry2Field row).val < 2 ^ 11
  carry3Bound : (carry3Field row).val < 2 ^ 11
  carry4Bound : (carry4Field row).val < 2 ^ 11
  carry5Bound : (carry5Field row).val < 2 ^ 11
  carry6Bound : (carry6Field row).val < 2 ^ 11
  carry7Bound : (carry7Field row).val < 2 ^ 11
  sourceOneSign :
    row.selector.signedSourceOne = true →
      ∃ rest : BitVec 7,
        row.rs1Next.limb3.toNat =
          128 * multiplySignBit row.rs1Sign + rest.toNat
  sourceTwoSign :
    row.selector.signedSourceTwo = true →
      ∃ rest : BitVec 7,
        row.rs2Next.limb3.toNat =
          128 * multiplySignBit row.rs2Sign + rest.toNat

theorem fixedConsequences
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation row witness).fixedLookupsHold = true) :
    FixedConsequences row := by
  have projection := exactFixedProjection row witness
  exact {
    sourceOneGap :=
      range20BoundOfLookup row witness 29 1 row.rs1PreviousClock
        fixed projection.sourceOneClock
    sourceTwoGap :=
      range20BoundOfLookup row witness 32 2 row.rs2PreviousClock
        fixed projection.sourceTwoClock
    destinationGap :=
      range20BoundOfLookup row witness 45 3 row.rdPreviousClock
        fixed projection.destinationClock
    carry0Bound :=
      (range811BoundsOfLookup row witness 33 row.rdHigh.limb0
        (carry0Field row) fixed projection.carry0).2
    carry1Bound :=
      (range811BoundsOfLookup row witness 34 row.rdHigh.limb1
        (carry1Field row) fixed projection.carry1).2
    carry2Bound :=
      (range811BoundsOfLookup row witness 35 row.rdHigh.limb2
        (carry2Field row) fixed projection.carry2).2
    carry3Bound :=
      (range811BoundsOfLookup row witness 36 row.rdHigh.limb3
        (carry3Field row) fixed projection.carry3).2
    carry4Bound :=
      (range811BoundsOfLookup row witness 37 row.result.limb0
        (carry4Field row) fixed projection.carry4).2
    carry5Bound :=
      (range811BoundsOfLookup row witness 38 row.result.limb1
        (carry5Field row) fixed projection.carry5).2
    carry6Bound :=
      (range811BoundsOfLookup row witness 39 row.result.limb2
        (carry6Field row) fixed projection.carry6).2
    carry7Bound :=
      (range811BoundsOfLookup row witness 40 row.result.limb3
        (carry7Field row) fixed projection.carry7).2
    sourceOneSign := by
      intro active
      apply signRemainderOfBound
      have activeOne :
          mulhBit row.selector + mulhsuBit row.selector = 1 := by
        cases selector : row.selector <;>
          simp_all [
            selector,
            MulhSelector.signedSourceOne,
            mulhBit,
            mulhsuBit,
          ]
      have request :=
        SymbolicEvaluation.fixedRequestHolds_of_lookup
          (evaluation row witness) 41
          (signLookup 41
            (mulhBit row.selector + mulhsuBit row.selector)
            row.rs1Next.limb3 row.rs1Sign)
          fixed projection.sourceOneSign
      apply
        RiscvRefinement.Publication.rangeCheckM31HighBoundOfFixedRequest
          41 none 0
          (bitVecM31 row.rs1Next.limb3 -
            boolM31 row.rs1Sign * M31.reduce 128)
      simpa [signLookup, activeOne] using request
    sourceTwoSign := by
      intro active
      apply signRemainderOfBound
      have activeOne : mulhBit row.selector = 1 := by
        cases selector : row.selector <;>
          simp_all [
            selector,
            MulhSelector.signedSourceTwo,
            mulhBit,
          ]
      have request :=
        SymbolicEvaluation.fixedRequestHolds_of_lookup
          (evaluation row witness) 42
          (signLookup 42 (mulhBit row.selector)
            row.rs2Next.limb3 row.rs2Sign)
          fixed projection.sourceTwoSign
      apply
        RiscvRefinement.Publication.rangeCheckM31HighBoundOfFixedRequest
          42 none 0
          (bitVecM31 row.rs2Next.limb3 -
            boolM31 row.rs2Sign * M31.reduce 128)
      simpa [signLookup, activeOne] using request
  }

private structure PreservedA
    (source normalized : Row) : Prop where
  pc : normalized.pc = source.pc
  clock : normalized.clock = source.clock
  rd : normalized.rd = source.rd
  rdPreviousClock :
    normalized.rdPreviousClock = source.rdPreviousClock

private structure PreservedB
    (source normalized : Row) : Prop where
  rdPrevious : normalized.rdPrevious = source.rdPrevious
  rdNext : normalized.rdNext = source.rdNext
  rs1 : normalized.rs1 = source.rs1
  rs1PreviousClock :
    normalized.rs1PreviousClock = source.rs1PreviousClock

private structure PreservedC
    (source normalized : Row) : Prop where
  rs1Previous : normalized.rs1Previous = source.rs1Previous
  rs1Next : normalized.rs1Next = source.rs1Next
  rs2 : normalized.rs2 = source.rs2
  rs2PreviousClock :
    normalized.rs2PreviousClock = source.rs2PreviousClock

private structure PreservedD
    (source normalized : Row) : Prop where
  rs2Previous : normalized.rs2Previous = source.rs2Previous
  rs2Next : normalized.rs2Next = source.rs2Next
  rdHigh : normalized.rdHigh = source.rdHigh
  result : normalized.result = source.result

private structure PreservedE
    (source normalized : Row) : Prop where
  rs1Sign : normalized.rs1Sign = source.rs1Sign
  rs2Sign : normalized.rs2Sign = source.rs2Sign
  selector : normalized.selector = source.selector
  rdNonzero : normalized.rdNonzero = source.rdNonzero

private structure NormalizedCarriesLow
    (source normalized : Row) : Prop where
  carry0 :
    normalized.carry0 =
      BitVec.ofNat 11 (carry0Field source).val
  carry1 :
    normalized.carry1 =
      BitVec.ofNat 11 (carry1Field source).val
  carry2 :
    normalized.carry2 =
      BitVec.ofNat 11 (carry2Field source).val
  carry3 :
    normalized.carry3 =
      BitVec.ofNat 11 (carry3Field source).val

private structure NormalizedCarriesHigh
    (source normalized : Row) : Prop where
  carry4 :
    normalized.carry4 =
      BitVec.ofNat 11 (carry4Field source).val
  carry5 :
    normalized.carry5 =
      BitVec.ofNat 11 (carry5Field source).val
  carry6 :
    normalized.carry6 =
      BitVec.ofNat 11 (carry6Field source).val
  carry7 :
    normalized.carry7 =
      BitVec.ofNat 11 (carry7Field source).val

private structure NormalizationSpec
    (source normalized : Row) : Prop where
  preservedA : PreservedA source normalized
  preservedB : PreservedB source normalized
  preservedC : PreservedC source normalized
  preservedD : PreservedD source normalized
  preservedE : PreservedE source normalized
  carriesLow : NormalizedCarriesLow source normalized
  carriesHigh : NormalizedCarriesHigh source normalized
  claimedNextPc : normalized.claimedNextPc = nextPc source.pc

private theorem normalizationExists (row : Row) :
    ∃ normalized : Row, NormalizationSpec row normalized := by
  let normalized : Row := {
    pc := row.pc
    clock := row.clock
    rd := row.rd
    rdPreviousClock := row.rdPreviousClock
    rdPrevious := row.rdPrevious
    rdNext := row.rdNext
    rs1 := row.rs1
    rs1PreviousClock := row.rs1PreviousClock
    rs1Previous := row.rs1Previous
    rs1Next := row.rs1Next
    rs2 := row.rs2
    rs2PreviousClock := row.rs2PreviousClock
    rs2Previous := row.rs2Previous
    rs2Next := row.rs2Next
    rdHigh := row.rdHigh
    rs1Sign := row.rs1Sign
    rs2Sign := row.rs2Sign
    selector := row.selector
    result := row.result
    carry0 := BitVec.ofNat 11 (carry0Field row).val
    carry1 := BitVec.ofNat 11 (carry1Field row).val
    carry2 := BitVec.ofNat 11 (carry2Field row).val
    carry3 := BitVec.ofNat 11 (carry3Field row).val
    carry4 := BitVec.ofNat 11 (carry4Field row).val
    carry5 := BitVec.ofNat 11 (carry5Field row).val
    carry6 := BitVec.ofNat 11 (carry6Field row).val
    carry7 := BitVec.ofNat 11 (carry7Field row).val
    rdNonzero := row.rdNonzero
    claimedNextPc := nextPc row.pc
  }
  have preservedA : PreservedA row normalized := by
    exact {
      pc := rfl
      clock := rfl
      rd := rfl
      rdPreviousClock := rfl
    }
  have preservedB : PreservedB row normalized := by
    exact {
      rdPrevious := rfl
      rdNext := rfl
      rs1 := rfl
      rs1PreviousClock := rfl
    }
  have preservedC : PreservedC row normalized := by
    exact {
      rs1Previous := rfl
      rs1Next := rfl
      rs2 := rfl
      rs2PreviousClock := rfl
    }
  have preservedD : PreservedD row normalized := by
    exact {
      rs2Previous := rfl
      rs2Next := rfl
      rdHigh := rfl
      result := rfl
    }
  have preservedE : PreservedE row normalized := by
    exact {
      rs1Sign := rfl
      rs2Sign := rfl
      selector := rfl
      rdNonzero := rfl
    }
  have carriesLow : NormalizedCarriesLow row normalized := by
    exact {
      carry0 := rfl
      carry1 := rfl
      carry2 := rfl
      carry3 := rfl
    }
  have carriesHigh : NormalizedCarriesHigh row normalized := by
    exact {
      carry4 := rfl
      carry5 := rfl
      carry6 := rfl
      carry7 := rfl
    }
  exact ⟨normalized, {
    preservedA := preservedA
    preservedB := preservedB
    preservedC := preservedC
    preservedD := preservedD
    preservedE := preservedE
    carriesLow := carriesLow
    carriesHigh := carriesHigh
    claimedNextPc := rfl
  }⟩

noncomputable def normalize (row : Row) : Row :=
  Classical.choose (normalizationExists row)

private theorem normalize_spec (row : Row) :
    NormalizationSpec row (normalize row) :=
  Classical.choose_spec (normalizationExists row)

private theorem normalize_pc (row : Row) :
    (normalize row).pc = row.pc :=
  (normalize_spec row).preservedA.pc

private theorem normalize_rd (row : Row) :
    (normalize row).rd = row.rd :=
  (normalize_spec row).preservedA.rd

private theorem normalize_rdPrevious (row : Row) :
    (normalize row).rdPrevious = row.rdPrevious :=
  (normalize_spec row).preservedB.rdPrevious

private theorem normalize_rs1 (row : Row) :
    (normalize row).rs1 = row.rs1 :=
  (normalize_spec row).preservedB.rs1

private theorem normalize_rs1Previous (row : Row) :
    (normalize row).rs1Previous = row.rs1Previous :=
  (normalize_spec row).preservedC.rs1Previous

private theorem normalize_rs2 (row : Row) :
    (normalize row).rs2 = row.rs2 :=
  (normalize_spec row).preservedC.rs2

private theorem normalize_rs2Previous (row : Row) :
    (normalize row).rs2Previous = row.rs2Previous :=
  (normalize_spec row).preservedD.rs2Previous

private theorem normalize_clock (row : Row) :
    (normalize row).clock = row.clock :=
  (normalize_spec row).preservedA.clock

private theorem normalize_rdPreviousClock (row : Row) :
    (normalize row).rdPreviousClock = row.rdPreviousClock :=
  (normalize_spec row).preservedA.rdPreviousClock

private theorem normalize_rs1PreviousClock (row : Row) :
    (normalize row).rs1PreviousClock = row.rs1PreviousClock :=
  (normalize_spec row).preservedB.rs1PreviousClock

private theorem normalize_rs2PreviousClock (row : Row) :
    (normalize row).rs2PreviousClock = row.rs2PreviousClock :=
  (normalize_spec row).preservedC.rs2PreviousClock

private theorem normalize_rdNext (row : Row) :
    (normalize row).rdNext = row.rdNext :=
  (normalize_spec row).preservedB.rdNext

private theorem normalize_rs1Next (row : Row) :
    (normalize row).rs1Next = row.rs1Next :=
  (normalize_spec row).preservedC.rs1Next

private theorem normalize_rs2Next (row : Row) :
    (normalize row).rs2Next = row.rs2Next :=
  (normalize_spec row).preservedD.rs2Next

private theorem normalize_rdHigh (row : Row) :
    (normalize row).rdHigh = row.rdHigh :=
  (normalize_spec row).preservedD.rdHigh

private theorem normalize_result (row : Row) :
    (normalize row).result = row.result :=
  (normalize_spec row).preservedD.result

private theorem normalize_rs1Sign (row : Row) :
    (normalize row).rs1Sign = row.rs1Sign :=
  (normalize_spec row).preservedE.rs1Sign

private theorem normalize_rs2Sign (row : Row) :
    (normalize row).rs2Sign = row.rs2Sign :=
  (normalize_spec row).preservedE.rs2Sign

private theorem normalize_selector (row : Row) :
    (normalize row).selector = row.selector :=
  (normalize_spec row).preservedE.selector

private theorem normalize_carry0 (row : Row) :
    (normalize row).carry0 =
      BitVec.ofNat 11 (carry0Field row).val :=
  (normalize_spec row).carriesLow.carry0

private theorem normalize_carry1 (row : Row) :
    (normalize row).carry1 =
      BitVec.ofNat 11 (carry1Field row).val :=
  (normalize_spec row).carriesLow.carry1

private theorem normalize_carry2 (row : Row) :
    (normalize row).carry2 =
      BitVec.ofNat 11 (carry2Field row).val :=
  (normalize_spec row).carriesLow.carry2

private theorem normalize_carry3 (row : Row) :
    (normalize row).carry3 =
      BitVec.ofNat 11 (carry3Field row).val :=
  (normalize_spec row).carriesLow.carry3

private theorem normalize_carry4 (row : Row) :
    (normalize row).carry4 =
      BitVec.ofNat 11 (carry4Field row).val :=
  (normalize_spec row).carriesHigh.carry4

private theorem normalize_carry5 (row : Row) :
    (normalize row).carry5 =
      BitVec.ofNat 11 (carry5Field row).val :=
  (normalize_spec row).carriesHigh.carry5

private theorem normalize_carry6 (row : Row) :
    (normalize row).carry6 =
      BitVec.ofNat 11 (carry6Field row).val :=
  (normalize_spec row).carriesHigh.carry6

private theorem normalize_carry7 (row : Row) :
    (normalize row).carry7 =
      BitVec.ofNat 11 (carry7Field row).val :=
  (normalize_spec row).carriesHigh.carry7

private theorem normalize_rdNonzero (row : Row) :
    (normalize row).rdNonzero = row.rdNonzero :=
  (normalize_spec row).preservedE.rdNonzero

private theorem normalize_claimedNextPc (row : Row) :
    (normalize row).claimedNextPc = nextPc row.pc :=
  (normalize_spec row).claimedNextPc

private theorem normalizedCarryValue
    (carry : M31)
    (bound : carry.val < 2 ^ 11) :
    (BitVec.ofNat 11 carry.val).toNat = carry.val := by
  rw [BitVec.toNat_ofNat, Nat.mod_eq_of_lt bound]

private theorem byteLt256 (value : Byte) :
    value.toNat < 256 := by
  simpa only [Nat.reducePow] using value.isLt

private theorem byteLe255 (value : Byte) :
    value.toNat ≤ 255 := by
  have bound := byteLt256 value
  omega

private theorem multiplySignFillBound (sign : Bool) :
    multiplySignFill sign ≤ 255 := by
  cases sign <;> simp [multiplySignFill]

private theorem productLe65025
    (left right : Nat)
    (leftBound : left ≤ 255)
    (rightBound : right ≤ 255) :
    left * right ≤ 65025 := by
  simpa using Nat.mul_le_mul leftBound rightBound

private theorem signFillField_eq_reduce (sign : Bool) :
    signFillField sign = M31.reduce (multiplySignFill sign) := by
  cases sign <;> rfl

private theorem reduce_val_image (value : M31) :
    M31.reduce value.val = value := by
  simpa only [M31.toNat] using M31.reduce_toNat value

set_option maxRecDepth 30000 in
private theorem productLimb0_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    row.rs1Next.limb0.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb0.toNat +
        256 * (BitVec.ofNat 11 (carry0Field row).val).toNat := by
  rw [normalizedCarryValue (carry0Field row) fixed.carry0Bound]
  apply MulhDiv.carryEquationOfField
  · have left := byteLt256 row.rs1Next.limb0
    have right := byteLt256 row.rs2Next.limb0
    have product :=
      productLe65025
        row.rs1Next.limb0.toNat row.rs2Next.limb0.toNat
        (by omega) (by omega)
    rw [M31.modulus_eq]
    omega
  · exact byteLt256 row.rdHigh.limb0
  · exact fixed.carry0Bound
  · simpa [
      carry0Field,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
    ]

private theorem carryAndTwoProductsLtModulus
    (carry firstProduct secondProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025) :
    carry + firstProduct + secondProduct < M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb1FieldEquation
    (row : Row) :
    ((M31.reduce
          ((carry0Field row).val +
            row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat) -
        M31.reduce row.rdHigh.limb1.toNat) *
      M31.reduce 8388608).val =
        (carry1Field row).val := by
  have accumulatedImage :
      M31.reduce
          ((carry0Field row).val +
            row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat) =
        carry0Field row +
            bitVecM31 row.rs1Next.limb0 *
              bitVecM31 row.rs2Next.limb1 +
          bitVecM31 row.rs1Next.limb1 *
            bitVecM31 row.rs2Next.limb0 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [carry1Field, accumulatedImage]
  rfl

set_option maxRecDepth 30000 in
private theorem productLimb1_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (BitVec.ofNat 11 (carry0Field row).val).toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb1.toNat +
        256 * (BitVec.ofNat 11 (carry1Field row).val).toNat := by
  rw [
    normalizedCarryValue (carry0Field row) fixed.carry0Bound,
    normalizedCarryValue (carry1Field row) fixed.carry1Bound,
  ]
  apply MulhDiv.carryEquationOfField
  · exact
      carryAndTwoProductsLtModulus
        (carry0Field row).val
        (row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat)
        (row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat)
        fixed.carry0Bound
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb0)
          (byteLe255 row.rs2Next.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb1)
          (byteLe255 row.rs2Next.limb0))
  · exact byteLt256 row.rdHigh.limb1
  · exact fixed.carry1Bound
  · exact productLimb1FieldEquation row

private theorem carryAndThreeProductsLtModulus
    (carry firstProduct secondProduct thirdProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct <
      M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb2FieldEquation
    (row : Row) :
    ((M31.reduce
          ((carry1Field row).val +
            row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat) -
        M31.reduce row.rdHigh.limb2.toNat) *
      M31.reduce 8388608).val =
        (carry2Field row).val := by
  have accumulatedImage :
      M31.reduce
          ((carry1Field row).val +
            row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat) =
        carry1Field row +
              bitVecM31 row.rs1Next.limb0 *
                bitVecM31 row.rs2Next.limb2 +
            bitVecM31 row.rs1Next.limb1 *
              bitVecM31 row.rs2Next.limb1 +
          bitVecM31 row.rs1Next.limb2 *
            bitVecM31 row.rs2Next.limb0 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [carry2Field, accumulatedImage]
  rfl

set_option maxRecDepth 30000 in
private theorem productLimb2_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (BitVec.ofNat 11 (carry1Field row).val).toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
          row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb2.toNat +
        256 * (BitVec.ofNat 11 (carry2Field row).val).toNat := by
  rw [
    normalizedCarryValue (carry1Field row) fixed.carry1Bound,
    normalizedCarryValue (carry2Field row) fixed.carry2Bound,
  ]
  apply MulhDiv.carryEquationOfField
  · exact
      carryAndThreeProductsLtModulus
        (carry1Field row).val
        (row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat)
        (row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat)
        (row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat)
        fixed.carry1Bound
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb0)
          (byteLe255 row.rs2Next.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb1)
          (byteLe255 row.rs2Next.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb2)
          (byteLe255 row.rs2Next.limb0))
  · exact byteLt256 row.rdHigh.limb2
  · exact fixed.carry2Bound
  · exact productLimb2FieldEquation row

private theorem carryAndFourProductsLtModulus
    (carry firstProduct secondProduct thirdProduct fourthProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025)
    (fourthBound : fourthProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct +
        fourthProduct <
      M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb3FieldEquation
    (row : Row) :
    ((M31.reduce
          ((carry2Field row).val +
            row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat) -
        M31.reduce row.rdHigh.limb3.toNat) *
      M31.reduce 8388608).val =
        (carry3Field row).val := by
  have accumulatedImage :
      M31.reduce
          ((carry2Field row).val +
            row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat) =
        carry2Field row +
                bitVecM31 row.rs1Next.limb0 *
                  bitVecM31 row.rs2Next.limb3 +
              bitVecM31 row.rs1Next.limb1 *
                bitVecM31 row.rs2Next.limb2 +
            bitVecM31 row.rs1Next.limb2 *
              bitVecM31 row.rs2Next.limb1 +
          bitVecM31 row.rs1Next.limb3 *
            bitVecM31 row.rs2Next.limb0 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [carry3Field, accumulatedImage]
  rfl

set_option maxRecDepth 30000 in
private theorem productLimb3_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (BitVec.ofNat 11 (carry2Field row).val).toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
          row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
          row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat =
      row.rdHigh.limb3.toNat +
        256 * (BitVec.ofNat 11 (carry3Field row).val).toNat := by
  rw [
    normalizedCarryValue (carry2Field row) fixed.carry2Bound,
    normalizedCarryValue (carry3Field row) fixed.carry3Bound,
  ]
  apply MulhDiv.carryEquationOfField
  · exact
      carryAndFourProductsLtModulus
        (carry2Field row).val
        (row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat)
        (row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat)
        (row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat)
        (row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat)
        fixed.carry2Bound
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb0)
          (byteLe255 row.rs2Next.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb1)
          (byteLe255 row.rs2Next.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb2)
          (byteLe255 row.rs2Next.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb3)
          (byteLe255 row.rs2Next.limb0))
  · exact byteLt256 row.rdHigh.limb3
  · exact fixed.carry3Bound
  · exact productLimb3FieldEquation row

private theorem carryAndFiveProductsLtModulus
    (carry firstProduct secondProduct thirdProduct fourthProduct
      fifthProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025)
    (fourthBound : fourthProduct ≤ 65025)
    (fifthBound : fifthProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct +
        fourthProduct + fifthProduct <
      M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb4FieldEquation
    (row : Row) :
    ((M31.reduce
          ((carry3Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * row.rs2Next.limb3.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb3.toNat * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) -
        M31.reduce row.result.limb0.toNat) *
      M31.reduce 8388608).val =
        (carry4Field row).val := by
  have accumulatedImage :
      M31.reduce
          ((carry3Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * row.rs2Next.limb3.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb3.toNat * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) =
        carry3Field row +
                  bitVecM31 row.rs1Next.limb0 *
                    M31.reduce (multiplySignFill row.rs2Sign) +
                bitVecM31 row.rs1Next.limb1 *
                  bitVecM31 row.rs2Next.limb3 +
              bitVecM31 row.rs1Next.limb2 *
                bitVecM31 row.rs2Next.limb2 +
            bitVecM31 row.rs1Next.limb3 *
              bitVecM31 row.rs2Next.limb1 +
          M31.reduce (multiplySignFill row.rs1Sign) *
            bitVecM31 row.rs2Next.limb0 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [
    carry4Field,
    signFillField_eq_reduce,
    signFillField_eq_reduce,
    accumulatedImage,
  ]
  rfl

set_option maxRecDepth 30000 in
private theorem productLimb4_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (BitVec.ofNat 11 (carry3Field row).val).toNat +
          row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb1.toNat * row.rs2Next.limb3.toNat +
          row.rs1Next.limb2.toNat * row.rs2Next.limb2.toNat +
          row.rs1Next.limb3.toNat * row.rs2Next.limb1.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb0.toNat +
        256 * (BitVec.ofNat 11 (carry4Field row).val).toNat := by
  rw [
    normalizedCarryValue (carry3Field row) fixed.carry3Bound,
    normalizedCarryValue (carry4Field row) fixed.carry4Bound,
  ]
  apply MulhDiv.carryEquationOfField
  · exact
      carryAndFiveProductsLtModulus
        (carry3Field row).val
        (row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb1.toNat * row.rs2Next.limb3.toNat)
        (row.rs1Next.limb2.toNat * row.rs2Next.limb2.toNat)
        (row.rs1Next.limb3.toNat * row.rs2Next.limb1.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat)
        fixed.carry3Bound
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb0)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb1)
          (byteLe255 row.rs2Next.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb2)
          (byteLe255 row.rs2Next.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb3)
          (byteLe255 row.rs2Next.limb1))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb0))
  · exact byteLt256 row.result.limb0
  · exact fixed.carry4Bound
  · exact productLimb4FieldEquation row

private theorem carryAndSixProductsLtModulus
    (carry firstProduct secondProduct thirdProduct fourthProduct
      fifthProduct sixthProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025)
    (fourthBound : fourthProduct ≤ 65025)
    (fifthBound : fifthProduct ≤ 65025)
    (sixthBound : sixthProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct +
        fourthProduct + fifthProduct + sixthProduct <
      M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb5FieldEquation
    (row : Row) :
    ((M31.reduce
          ((carry4Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb2.toNat * row.rs2Next.limb3.toNat +
            row.rs1Next.limb3.toNat * row.rs2Next.limb2.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) -
        M31.reduce row.result.limb1.toNat) *
      M31.reduce 8388608).val =
        (carry5Field row).val := by
  have accumulatedImage :
      M31.reduce
          ((carry4Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb2.toNat * row.rs2Next.limb3.toNat +
            row.rs1Next.limb3.toNat * row.rs2Next.limb2.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) =
        carry4Field row +
                    bitVecM31 row.rs1Next.limb0 *
                      M31.reduce (multiplySignFill row.rs2Sign) +
                  bitVecM31 row.rs1Next.limb1 *
                    M31.reduce (multiplySignFill row.rs2Sign) +
                bitVecM31 row.rs1Next.limb2 *
                  bitVecM31 row.rs2Next.limb3 +
              bitVecM31 row.rs1Next.limb3 *
                bitVecM31 row.rs2Next.limb2 +
            M31.reduce (multiplySignFill row.rs1Sign) *
              bitVecM31 row.rs2Next.limb1 +
          M31.reduce (multiplySignFill row.rs1Sign) *
            bitVecM31 row.rs2Next.limb0 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [
    carry5Field,
    signFillField_eq_reduce,
    signFillField_eq_reduce,
    accumulatedImage,
  ]
  rfl

set_option maxRecDepth 30000 in
private theorem productLimb5_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (BitVec.ofNat 11 (carry4Field row).val).toNat +
          row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb2.toNat * row.rs2Next.limb3.toNat +
          row.rs1Next.limb3.toNat * row.rs2Next.limb2.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb1.toNat +
        256 * (BitVec.ofNat 11 (carry5Field row).val).toNat := by
  rw [
    normalizedCarryValue (carry4Field row) fixed.carry4Bound,
    normalizedCarryValue (carry5Field row) fixed.carry5Bound,
  ]
  apply MulhDiv.carryEquationOfField
  · exact
      carryAndSixProductsLtModulus
        (carry4Field row).val
        (row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb2.toNat * row.rs2Next.limb3.toNat)
        (row.rs1Next.limb3.toNat * row.rs2Next.limb2.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat)
        fixed.carry4Bound
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb0)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb1)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb2)
          (byteLe255 row.rs2Next.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb3)
          (byteLe255 row.rs2Next.limb2))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb1))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb0))
  · exact byteLt256 row.result.limb1
  · exact fixed.carry5Bound
  · exact productLimb5FieldEquation row

private theorem carryAndSevenProductsLtModulus
    (carry firstProduct secondProduct thirdProduct fourthProduct
      fifthProduct sixthProduct seventhProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025)
    (fourthBound : fourthProduct ≤ 65025)
    (fifthBound : fifthProduct ≤ 65025)
    (sixthBound : sixthProduct ≤ 65025)
    (seventhBound : seventhProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct +
        fourthProduct + fifthProduct + sixthProduct + seventhProduct <
      M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb6FieldEquation
    (row : Row) :
    ((M31.reduce
          ((carry5Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb3.toNat * row.rs2Next.limb3.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) -
        M31.reduce row.result.limb2.toNat) *
      M31.reduce 8388608).val =
        (carry6Field row).val := by
  have accumulatedImage :
      M31.reduce
          ((carry5Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb3.toNat * row.rs2Next.limb3.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) =
        carry5Field row +
                      bitVecM31 row.rs1Next.limb0 *
                        M31.reduce (multiplySignFill row.rs2Sign) +
                    bitVecM31 row.rs1Next.limb1 *
                      M31.reduce (multiplySignFill row.rs2Sign) +
                  bitVecM31 row.rs1Next.limb2 *
                    M31.reduce (multiplySignFill row.rs2Sign) +
                bitVecM31 row.rs1Next.limb3 *
                  bitVecM31 row.rs2Next.limb3 +
              M31.reduce (multiplySignFill row.rs1Sign) *
                bitVecM31 row.rs2Next.limb2 +
            M31.reduce (multiplySignFill row.rs1Sign) *
              bitVecM31 row.rs2Next.limb1 +
          M31.reduce (multiplySignFill row.rs1Sign) *
            bitVecM31 row.rs2Next.limb0 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [
    carry6Field,
    signFillField_eq_reduce,
    signFillField_eq_reduce,
    accumulatedImage,
  ]
  rfl

set_option maxRecDepth 30000 in
private theorem productLimb6_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (BitVec.ofNat 11 (carry5Field row).val).toNat +
          row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb3.toNat * row.rs2Next.limb3.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb2.toNat +
        256 * (BitVec.ofNat 11 (carry6Field row).val).toNat := by
  rw [
    normalizedCarryValue (carry5Field row) fixed.carry5Bound,
    normalizedCarryValue (carry6Field row) fixed.carry6Bound,
  ]
  apply MulhDiv.carryEquationOfField
  · exact
      carryAndSevenProductsLtModulus
        (carry5Field row).val
        (row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb3.toNat * row.rs2Next.limb3.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat)
        fixed.carry5Bound
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb0)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb1)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb2)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb3)
          (byteLe255 row.rs2Next.limb3))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb2))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb1))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb0))
  · exact byteLt256 row.result.limb2
  · exact fixed.carry6Bound
  · exact productLimb6FieldEquation row

private theorem carryAndEightProductsLtModulus
    (carry firstProduct secondProduct thirdProduct fourthProduct
      fifthProduct sixthProduct seventhProduct eighthProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025)
    (fourthBound : fourthProduct ≤ 65025)
    (fifthBound : fifthProduct ≤ 65025)
    (sixthBound : sixthProduct ≤ 65025)
    (seventhBound : seventhProduct ≤ 65025)
    (eighthBound : eighthProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct +
        fourthProduct + fifthProduct + sixthProduct + seventhProduct +
        eighthProduct <
      M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb7FieldEquation
    (row : Row) :
    ((M31.reduce
          ((carry6Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb3.toNat * multiplySignFill row.rs2Sign +
            multiplySignFill row.rs1Sign * row.rs2Next.limb3.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) -
        M31.reduce row.result.limb3.toNat) *
      M31.reduce 8388608).val =
        (carry7Field row).val := by
  have accumulatedImage :
      M31.reduce
          ((carry6Field row).val +
            row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
            row.rs1Next.limb3.toNat * multiplySignFill row.rs2Sign +
            multiplySignFill row.rs1Sign * row.rs2Next.limb3.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
            multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat) =
        carry6Field row +
                        bitVecM31 row.rs1Next.limb0 *
                          M31.reduce (multiplySignFill row.rs2Sign) +
                      bitVecM31 row.rs1Next.limb1 *
                        M31.reduce (multiplySignFill row.rs2Sign) +
                    bitVecM31 row.rs1Next.limb2 *
                      M31.reduce (multiplySignFill row.rs2Sign) +
                  bitVecM31 row.rs1Next.limb3 *
                    M31.reduce (multiplySignFill row.rs2Sign) +
                M31.reduce (multiplySignFill row.rs1Sign) *
                  bitVecM31 row.rs2Next.limb3 +
              M31.reduce (multiplySignFill row.rs1Sign) *
                bitVecM31 row.rs2Next.limb2 +
            M31.reduce (multiplySignFill row.rs1Sign) *
              bitVecM31 row.rs2Next.limb1 +
          M31.reduce (multiplySignFill row.rs1Sign) *
            bitVecM31 row.rs2Next.limb0 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [
    carry7Field,
    signFillField_eq_reduce,
    signFillField_eq_reduce,
    accumulatedImage,
  ]
  rfl

set_option maxRecDepth 30000 in
private theorem productLimb7_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (BitVec.ofNat 11 (carry6Field row).val).toNat +
          row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign +
          row.rs1Next.limb3.toNat * multiplySignFill row.rs2Sign +
          multiplySignFill row.rs1Sign * row.rs2Next.limb3.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat +
          multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat =
      row.result.limb3.toNat +
        256 * (BitVec.ofNat 11 (carry7Field row).val).toNat := by
  rw [
    normalizedCarryValue (carry6Field row) fixed.carry6Bound,
    normalizedCarryValue (carry7Field row) fixed.carry7Bound,
  ]
  apply MulhDiv.carryEquationOfField
  · exact
      carryAndEightProductsLtModulus
        (carry6Field row).val
        (row.rs1Next.limb0.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb1.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb2.toNat * multiplySignFill row.rs2Sign)
        (row.rs1Next.limb3.toNat * multiplySignFill row.rs2Sign)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb3.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb2.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb1.toNat)
        (multiplySignFill row.rs1Sign * row.rs2Next.limb0.toNat)
        fixed.carry6Bound
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb0)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb1)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb2)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (byteLe255 row.rs1Next.limb3)
          (multiplySignFillBound row.rs2Sign))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb3))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb2))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb1))
        (productLe65025 _ _
          (multiplySignFillBound row.rs1Sign)
          (byteLe255 row.rs2Next.limb0))
  · exact byteLt256 row.result.limb3
  · exact fixed.carry7Bound
  · exact productLimb7FieldEquation row

theorem mulh_programIdentity :
    Programs.mulh.source.opcodeSelector.manifestId = 38 ∧
      Programs.mulh.source.opcodeSelector.mnemonic = "mulh" ∧
      Programs.mulh.source.family = .mulh ∧
      Programs.mulh.source.contentDigest =
        "2874db65e8b666a49a929e8f123cf10d43153e9ac4476e089cac57f50cc5b9c5" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem mulhsu_programIdentity :
    Programs.mulhsu.source.opcodeSelector.manifestId = 39 ∧
      Programs.mulhsu.source.opcodeSelector.mnemonic = "mulhsu" ∧
      Programs.mulhsu.source.family = .mulh ∧
      Programs.mulhsu.source.contentDigest =
        "336969932d87fa57b8c1119d9a6417de90fbbb5d273767fd9d3ebf9f5f3f0b41" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem mulhu_programIdentity :
    Programs.mulhu.source.opcodeSelector.manifestId = 40 ∧
      Programs.mulhu.source.opcodeSelector.mnemonic = "mulhu" ∧
      Programs.mulhu.source.family = .mulh ∧
      Programs.mulhu.source.contentDigest =
        "d045f97955a2e27478f22ce67ec51e15d62f8fe055886c66415da9b053b63fb5" :=
  ⟨rfl, rfl, rfl, rfl⟩

private theorem validClock_of_fixed
    (row : Row)
    (admission : Admission row)
    (ordinal previous : Nat)
    (ordinalPositive : 0 < ordinal)
    (ordinalBound : ordinal ≤ 3)
    (previousBound : previous < 2 ^ 26)
    (gap :
      (clockGapField row ordinal previous).val < 2 ^ 20) :
    validPreviousClock previous (accessClock row.clock ordinal) := by
  apply
    MulhDiv.validPreviousClockOfGap
      row.clock ordinal previous admission.clockPositive admission.clockBound
      ordinalPositive ordinalBound previousBound
  simpa [
    clockGapField,
    accessClockField,
    Air.Bridge.TeamACommon.clockGapField,
    Air.Bridge.TeamACommon.accessClockField,
  ] using gap

/-
Exact generated-program acceptance determines a canonical semantic row.  In
particular, all eight carry witnesses come from the fixed range requests; no
caller-provided semantic carry equality is assumed.
-/
set_option maxRecDepth 30000 in
theorem acceptedAir_implies_holds
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance row witness relationHolds)
    (admission : Admission row) :
    MulhHolds (normalize row) := by
  have direct :=
    directConsequences row witness accepted.directConstraints
  have fixed :=
    fixedConsequences row witness accepted.fixedTableRequests
  refine {
    clockPositive := by
      simpa only [normalize_clock] using admission.clockPositive
    sourceOneClock := by
      simpa only [normalize_rs1PreviousClock, normalize_clock] using
        validClock_of_fixed row admission 1 row.rs1PreviousClock
          (by decide) (by decide) admission.sourceOnePreviousBound
          fixed.sourceOneGap
    sourceTwoClock := by
      simpa only [normalize_rs2PreviousClock, normalize_clock] using
        validClock_of_fixed row admission 2 row.rs2PreviousClock
          (by decide) (by decide) admission.sourceTwoPreviousBound
          fixed.sourceTwoGap
    destinationClock := by
      simpa only [normalize_rdPreviousClock, normalize_clock] using
        validClock_of_fixed row admission 3 row.rdPreviousClock
          (by decide) (by decide) admission.destinationPreviousBound
          fixed.destinationGap
    sourceOneLimb0 := by
      simpa only [normalize_rs1Next, normalize_rs1Previous] using
        congrArg WordBytes.limb0 direct.sourceOne
    sourceOneLimb1 := by
      simpa only [normalize_rs1Next, normalize_rs1Previous] using
        congrArg WordBytes.limb1 direct.sourceOne
    sourceOneLimb2 := by
      simpa only [normalize_rs1Next, normalize_rs1Previous] using
        congrArg WordBytes.limb2 direct.sourceOne
    sourceOneLimb3 := by
      simpa only [normalize_rs1Next, normalize_rs1Previous] using
        congrArg WordBytes.limb3 direct.sourceOne
    sourceTwoLimb0 := by
      simpa only [normalize_rs2Next, normalize_rs2Previous] using
        congrArg WordBytes.limb0 direct.sourceTwo
    sourceTwoLimb1 := by
      simpa only [normalize_rs2Next, normalize_rs2Previous] using
        congrArg WordBytes.limb1 direct.sourceTwo
    sourceTwoLimb2 := by
      simpa only [normalize_rs2Next, normalize_rs2Previous] using
        congrArg WordBytes.limb2 direct.sourceTwo
    sourceTwoLimb3 := by
      simpa only [normalize_rs2Next, normalize_rs2Previous] using
        congrArg WordBytes.limb3 direct.sourceTwo
    unsignedSourceOne := by
      simpa only [normalize_selector, normalize_rs1Sign] using
        direct.unsignedSourceOne
    unsignedSourceTwo := by
      simpa only [normalize_selector, normalize_rs2Sign] using
        direct.unsignedSourceTwo
    signedSourceOne := by
      simpa only [
        normalize_selector, normalize_rs1Next, normalize_rs1Sign,
      ] using fixed.sourceOneSign
    signedSourceTwo := by
      simpa only [
        normalize_selector, normalize_rs2Next, normalize_rs2Sign,
      ] using fixed.sourceTwoSign
    productLimb0 := by
      simpa only [
        normalize_rs1Next, normalize_rs2Next, normalize_rdHigh,
        normalize_carry0,
      ] using productLimb0_of_acceptance row fixed
    productLimb1 := by
      simpa only [
        normalize_carry0, normalize_rs1Next, normalize_rs2Next,
        normalize_rdHigh, normalize_carry1,
      ] using productLimb1_of_acceptance row fixed
    productLimb2 := by
      simpa only [
        normalize_carry1, normalize_rs1Next, normalize_rs2Next,
        normalize_rdHigh, normalize_carry2,
      ] using productLimb2_of_acceptance row fixed
    productLimb3 := by
      simpa only [
        normalize_carry2, normalize_rs1Next, normalize_rs2Next,
        normalize_rdHigh, normalize_carry3,
      ] using productLimb3_of_acceptance row fixed
    productLimb4 := by
      simpa only [
        normalize_carry3, normalize_rs1Next, normalize_rs2Next,
        normalize_rs1Sign, normalize_rs2Sign, normalize_result,
        normalize_carry4,
      ] using productLimb4_of_acceptance row fixed
    productLimb5 := by
      simpa only [
        normalize_carry4, normalize_rs1Next, normalize_rs2Next,
        normalize_rs1Sign, normalize_rs2Sign, normalize_result,
        normalize_carry5,
      ] using productLimb5_of_acceptance row fixed
    productLimb6 := by
      simpa only [
        normalize_carry5, normalize_rs1Next, normalize_rs2Next,
        normalize_rs1Sign, normalize_rs2Sign, normalize_result,
        normalize_carry6,
      ] using productLimb6_of_acceptance row fixed
    productLimb7 := by
      simpa only [
        normalize_carry6, normalize_rs1Next, normalize_rs2Next,
        normalize_rs1Sign, normalize_rs2Sign, normalize_result,
        normalize_carry7,
      ] using productLimb7_of_acceptance row fixed
    destinationFlag := by
      simpa only [normalize_rdNonzero, normalize_rd] using
        direct.destinationFlag
    destinationLimb0 := by
      cases flag : row.rdNonzero <;>
        simpa only [
          normalize_rdNext, normalize_rdNonzero, normalize_result, flag,
        ] using
          congrArg WordBytes.limb0 direct.destination
    destinationLimb1 := by
      cases flag : row.rdNonzero <;>
        simpa only [
          normalize_rdNext, normalize_rdNonzero, normalize_result, flag,
        ] using
          congrArg WordBytes.limb1 direct.destination
    destinationLimb2 := by
      cases flag : row.rdNonzero <;>
        simpa only [
          normalize_rdNext, normalize_rdNonzero, normalize_result, flag,
        ] using
          congrArg WordBytes.limb2 direct.destination
    destinationLimb3 := by
      cases flag : row.rdNonzero <;>
        simpa only [
          normalize_rdNext, normalize_rdNonzero, normalize_result, flag,
        ] using
          congrArg WordBytes.limb3 direct.destination
    nextPcResult := by
      simp only [normalize_claimedNextPc, normalize_pc]
  }

set_option maxRecDepth 30000 in
def normalizeEnvironment
    (row : Row)
    (environment : Opcodes.MulhEnvironment row) :
    Opcodes.MulhEnvironment (normalize row) where
  pre := environment.pre
  pcBinds := by
    simpa only [normalize_pc] using environment.pcBinds
  sourceOneBinds := by
    simpa only [normalize_rs1Previous, normalize_rs1] using
      environment.sourceOneBinds
  sourceTwoBinds := by
    simpa only [normalize_rs2Previous, normalize_rs2] using
      environment.sourceTwoBinds
  destinationBinds := by
    simpa only [normalize_rdPrevious, normalize_rd] using
      environment.destinationBinds

/--
Exact selector admission evidence: the semantic selector, selected generated
program, manifest identity, family admission and unique Team B selector are
all tied together in one proposition.
-/
structure SelectorAdmission
    (row : Row)
    (semantic : MulhSelector)
    (published : TeamB.Selector)
    (selectedProgram : LocalProgram)
    (manifestId : Nat)
    (mnemonic digest : String) : Prop where
  rowSelector : row.selector = semantic
  exactProgram : program row.selector = selectedProgram
  manifest :
    selectedProgram.source.opcodeSelector.manifestId = manifestId
  publishedManifest :
    manifestId = TeamB.Selector.manifestId published
  programMnemonic :
    selectedProgram.source.opcodeSelector.mnemonic = mnemonic
  publishedMnemonic :
    mnemonic = TeamB.Selector.mnemonic published
  unique :
    ∀ candidate : TeamB.Selector,
      TeamB.Selector.manifestId candidate = manifestId →
        candidate = published
  familyAdmits :
    selectedProgram.source.family.validOpcode manifestId mnemonic = true
  universalIdentity :
    Publication.actualProgramIdentities[manifestId]? =
      some {
        manifestId := manifestId
        mnemonic := mnemonic
        family := selectedProgram.source.family
        contentDigest := digest
      }

theorem mulh_selectorAdmission
    (row : Row)
    (selector : row.selector = .mulh) :
    SelectorAdmission row .mulh .mulh Programs.mulh 38 "mulh"
      "2874db65e8b666a49a929e8f123cf10d43153e9ac4476e089cac57f50cc5b9c5" := by
  refine {
    rowSelector := selector
    exactProgram := by simpa [program, selector]
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := ?_
    familyAdmits := by decide
    universalIdentity := ?_
  }
  · intro candidate same
    apply TeamB.Selector.manifestId_injective
    simpa [TeamB.Selector.manifestId] using same
  · rw [Publication.exactProductionProgramIdentities]
    rfl

theorem mulhsu_selectorAdmission
    (row : Row)
    (selector : row.selector = .mulhsu) :
    SelectorAdmission row .mulhsu .mulhsu Programs.mulhsu 39 "mulhsu"
      "336969932d87fa57b8c1119d9a6417de90fbbb5d273767fd9d3ebf9f5f3f0b41" := by
  refine {
    rowSelector := selector
    exactProgram := by simpa [program, selector]
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := ?_
    familyAdmits := by decide
    universalIdentity := ?_
  }
  · intro candidate same
    apply TeamB.Selector.manifestId_injective
    simpa [TeamB.Selector.manifestId] using same
  · rw [Publication.exactProductionProgramIdentities]
    rfl

theorem mulhu_selectorAdmission
    (row : Row)
    (selector : row.selector = .mulhu) :
    SelectorAdmission row .mulhu .mulhu Programs.mulhu 40 "mulhu"
      "d045f97955a2e27478f22ce67ec51e15d62f8fe055886c66415da9b053b63fb5" := by
  refine {
    rowSelector := selector
    exactProgram := by simpa [program, selector]
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := ?_
    familyAdmits := by decide
    universalIdentity := ?_
  }
  · intro candidate same
    apply TeamB.Selector.manifestId_injective
    simpa [TeamB.Selector.manifestId] using same
  · rw [Publication.exactProductionProgramIdentities]
    rfl

private theorem programNodesShared (selector : MulhSelector) :
    (program selector).nodes = Programs.mulh.nodes := by
  cases selector <;> rfl

private theorem evaluatedNodesShared
    (left right : MulhSelector)
    (row : Row)
    (witness : Witness row) :
    (program left).evalNodesSymbolic (columns row witness) =
      (program right).evalNodesSymbolic (columns row witness) := by
  simp only [LocalProgram.evalNodesSymbolic]
  rw [programNodesShared left, programNodesShared right]

private theorem actualSelectorNode
    (row : Row)
    (witness : Witness row) :
    ((program row.selector).evalNodesSymbolic
        (columns row witness)).getSymbolic 185 =
      M31.reduce row.selector.opcodeId := by
  have lookup :=
    evaluatedRawLookup_tuple row witness 24 (by decide)
  have selected :=
    congrArg
      (fun evaluated : EvaluatedLookup => evaluated.tuple[1]?)
      lookup
  simpa [
    evaluatedRawLookup,
    rawLookupEvent,
    expectedTupleLookup,
    programLookup,
  ] using selected

private theorem selectedProgramManifestId (selected : MulhSelector) :
    (program selected).source.opcodeSelector.manifestId =
      selected.opcodeId := by
  cases selected <;> rfl

private theorem selectedProgramOpcodeExpression
    (selected : MulhSelector) :
    (program selected).source.opcodeSelector.expression = 185 := by
  cases selected <;> rfl

private theorem selectedEvaluationManifestId
    (selected : MulhSelector)
    (row : Row)
    (witness : Witness row) :
    ((program selected).evalSymbolic
      (columns row witness)).manifestId = selected.opcodeId := by
  simp only [LocalProgram.evalSymbolic]
  rw [selectedProgramManifestId selected]

private theorem selectedEvaluationOpcodeSelector
    (selected : MulhSelector)
    (row : Row)
    (witness : Witness row) :
    ((program selected).evalSymbolic
        (columns row witness)).opcodeSelector =
      ((program selected).evalNodesSymbolic
        (columns row witness)).getSymbolic 185 := by
  simp only [LocalProgram.evalSymbolic]
  rw [selectedProgramOpcodeExpression selected]

private theorem selectorManifestImage (selected : MulhSelector) :
    M31.ofNat? selected.opcodeId =
      some (M31.reduce selected.opcodeId) := by
  cases selected <;> rfl

private theorem acceptedSelectorNode
    (selected : MulhSelector)
    (row : Row)
    (witness : Witness row)
    (active :
      ((program selected).evalSymbolic
        (columns row witness)).activeSelectorsAccepted = true) :
    ((program selected).evalNodesSymbolic
        (columns row witness)).getSymbolic 185 =
      M31.reduce selected.opcodeId := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have opcodeAccepted := selectorsAccepted.2
  rw [selectedEvaluationManifestId selected row witness] at opcodeAccepted
  rw [selectorManifestImage selected] at opcodeAccepted
  rw [
    selectedEvaluationOpcodeSelector selected row witness,
  ] at opcodeAccepted
  simpa only [beq_iff_eq] using opcodeAccepted

private theorem selectorOpcodeBound (selector : MulhSelector) :
    selector.opcodeId < M31.modulus := by
  cases selector <;>
    simp [MulhSelector.opcodeId, M31.modulus_eq]

private theorem selector_eq_of_program_active
    (selected : MulhSelector)
    (row : Row)
    (witness : Witness row)
    (active :
      ((program selected).evalSymbolic
        (columns row witness)).activeSelectorsAccepted = true) :
    row.selector = selected := by
  have opcodeFields :
      M31.reduce row.selector.opcodeId =
        M31.reduce selected.opcodeId := by
    calc
      M31.reduce row.selector.opcodeId =
          ((program row.selector).evalNodesSymbolic
            (columns row witness)).getSymbolic 185 :=
        (actualSelectorNode row witness).symm
      _ =
          ((program selected).evalNodesSymbolic
            (columns row witness)).getSymbolic 185 := by
        rw [evaluatedNodesShared row.selector selected row witness]
      _ = M31.reduce selected.opcodeId :=
        acceptedSelectorNode selected row witness active
  have opcodeIds :
      row.selector.opcodeId = selected.opcodeId :=
    (M31.reduce_injective_of_lt
      (selectorOpcodeBound row.selector)
      (selectorOpcodeBound selected)).mp opcodeFields
  cases selected <;>
    cases actual : row.selector <;>
    simp_all [MulhSelector.opcodeId]

private theorem selectedAcceptance_is_generic
    (selected : MulhSelector)
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (selector : row.selector = selected)
    (accepted :
      Publication.AcceptedProductionEvaluation
        ((program selected).evalSymbolic (columns row witness))
        relationHolds) :
    Acceptance row witness relationHolds := by
  subst selected
  exact accepted

/-
Stable publication wrapper for manifest selector 38 (`MULH`).
-/
set_option maxRecDepth 30000 in
theorem mulh_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.MulhEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.mulh.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission row .mulh .mulh Programs.mulh 38 "mulh"
        "2874db65e8b666a49a929e8f123cf10d43153e9ac4476e089cac57f50cc5b9c5" ∧
      MulhHolds (normalize row) ∧
      mulhRetirement (normalize row) =
        Sail.Reviewed.executeMulh
          environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)
          row.rd ∧
      ExactTupleProjection row witness ∧
      ExactFixedProjection row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.mulh.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have selector : row.selector = .mulh :=
    selector_eq_of_program_active
      .mulh row witness accepted.activeProductionRow
  have generic :=
    selectedAcceptance_is_generic
      .mulh row witness relationHolds selector accepted
  have holds :=
    acceptedAir_implies_holds
      row witness relationHolds generic admission
  have normalizedSelector : (normalize row).selector = .mulh := by
    simpa only [normalize_selector] using selector
  have refinement :=
    Opcodes.mulh_refines
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have retirement := refinement.retirement
  have reviewedRetirement :
    mulhRetirement (normalize row) =
      Sail.Reviewed.executeMulh
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact ⟨mulh_selectorAdmission row selector, holds,
    reviewedRetirement,
    exactTupleProjection row witness,
    exactFixedProjection row witness,
    accepted.liveRelations⟩

/-
Stable publication wrapper for manifest selector 39 (`MULHSU`).
-/
set_option maxRecDepth 30000 in
theorem mulhsu_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.MulhEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.mulhsu.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission row .mulhsu .mulhsu Programs.mulhsu 39 "mulhsu"
        "336969932d87fa57b8c1119d9a6417de90fbbb5d273767fd9d3ebf9f5f3f0b41" ∧
      MulhHolds (normalize row) ∧
      mulhRetirement (normalize row) =
        Sail.Reviewed.executeMulhsu
          environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)
          row.rd ∧
      ExactTupleProjection row witness ∧
      ExactFixedProjection row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.mulhsu.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have selector : row.selector = .mulhsu :=
    selector_eq_of_program_active
      .mulhsu row witness accepted.activeProductionRow
  have generic :=
    selectedAcceptance_is_generic
      .mulhsu row witness relationHolds selector accepted
  have holds :=
    acceptedAir_implies_holds
      row witness relationHolds generic admission
  have normalizedSelector : (normalize row).selector = .mulhsu := by
    simpa only [normalize_selector] using selector
  have refinement :=
    Opcodes.mulhsu_refines
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have retirement := refinement.retirement
  have reviewedRetirement :
    mulhRetirement (normalize row) =
      Sail.Reviewed.executeMulhsu
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact ⟨mulhsu_selectorAdmission row selector, holds,
    reviewedRetirement,
    exactTupleProjection row witness,
    exactFixedProjection row witness,
    accepted.liveRelations⟩

/-
Stable publication wrapper for manifest selector 40 (`MULHU`).
-/
set_option maxRecDepth 30000 in
theorem mulhu_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.MulhEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.mulhu.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission row .mulhu .mulhu Programs.mulhu 40 "mulhu"
        "d045f97955a2e27478f22ce67ec51e15d62f8fe055886c66415da9b053b63fb5" ∧
      MulhHolds (normalize row) ∧
      mulhRetirement (normalize row) =
        Sail.Reviewed.executeMulhu
          environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)
          row.rd ∧
      ExactTupleProjection row witness ∧
      ExactFixedProjection row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.mulhu.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have selector : row.selector = .mulhu :=
    selector_eq_of_program_active
      .mulhu row witness accepted.activeProductionRow
  have generic :=
    selectedAcceptance_is_generic
      .mulhu row witness relationHolds selector accepted
  have holds :=
    acceptedAir_implies_holds
      row witness relationHolds generic admission
  have normalizedSelector : (normalize row).selector = .mulhu := by
    simpa only [normalize_selector] using selector
  have refinement :=
    Opcodes.mulhu_refines
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have retirement := refinement.retirement
  have reviewedRetirement :
    mulhRetirement (normalize row) =
      Sail.Reviewed.executeMulhu
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact ⟨mulhu_selectorAdmission row selector, holds,
    reviewedRetirement,
    exactTupleProjection row witness,
    exactFixedProjection row witness,
    accepted.liveRelations⟩

end HighMultiply

/-! ## DIV / DIVU / REM / REMU exact production rows -/

namespace Division

inductive Selector where
  | div
  | divu
  | rem
  | remu
deriving DecidableEq, Repr

abbrev Row := DivRow

structure Witness (row : Row) where
  divisorSumInverse : M31
  remainderSumInverse : M31
  remainderInverse0 : M31
  remainderInverse1 : M31
  remainderInverse2 : M31
  remainderInverse3 : M31
  destinationInverse : M31

private def bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  M31.reduce value.toNat

private def boolM31 : Bool → M31
  | false => 0
  | true => 1

private def activeField (row : Row) : M31 :=
  boolM31 row.isDiv + boolM31 row.isDivu +
    boolM31 row.isRem + boolM31 row.isRemu

private def opcodeField (row : Row) : M31 :=
  boolM31 row.isDiv * M31.reduce 41 +
    boolM31 row.isDivu * M31.reduce 42 +
    boolM31 row.isRem * M31.reduce 43 +
    boolM31 row.isRemu * M31.reduce 44

def program : Selector → LocalProgram
  | .div => Programs.div
  | .divu => Programs.divu
  | .rem => Programs.rem
  | .remu => Programs.remu

private theorem programEventsShared (selector : Selector) :
    (program selector).source.events = Programs.divSource.events := by
  cases selector <;> rfl

private theorem programNodesShared (selector : Selector) :
    (program selector).nodes = Programs.div.nodes := by
  cases selector <;> rfl

/-- Exact 67-column order shared by the four production DIV-family programs. -/
def columns (row : Row) (witness : Witness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.rd
  | 3 => bitVecM31 row.rdPrevious.limb0
  | 4 => bitVecM31 row.rdPrevious.limb1
  | 5 => bitVecM31 row.rdPrevious.limb2
  | 6 => bitVecM31 row.rdPrevious.limb3
  | 7 => M31.reduce row.rdPreviousClock
  | 8 => bitVecM31 row.rdNext.limb0
  | 9 => bitVecM31 row.rdNext.limb1
  | 10 => bitVecM31 row.rdNext.limb2
  | 11 => bitVecM31 row.rdNext.limb3
  | 12 => bitVecM31 row.rs1
  | 13 => bitVecM31 row.rs1Previous.limb0
  | 14 => bitVecM31 row.rs1Previous.limb1
  | 15 => bitVecM31 row.rs1Previous.limb2
  | 16 => bitVecM31 row.rs1Previous.limb3
  | 17 => M31.reduce row.rs1PreviousClock
  | 18 => bitVecM31 row.rs1Next.limb0
  | 19 => bitVecM31 row.rs1Next.limb1
  | 20 => bitVecM31 row.rs1Next.limb2
  | 21 => bitVecM31 row.rs1Next.limb3
  | 22 => bitVecM31 row.rs2
  | 23 => bitVecM31 row.rs2Previous.limb0
  | 24 => bitVecM31 row.rs2Previous.limb1
  | 25 => bitVecM31 row.rs2Previous.limb2
  | 26 => bitVecM31 row.rs2Previous.limb3
  | 27 => M31.reduce row.rs2PreviousClock
  | 28 => bitVecM31 row.rs2Next.limb0
  | 29 => bitVecM31 row.rs2Next.limb1
  | 30 => bitVecM31 row.rs2Next.limb2
  | 31 => bitVecM31 row.rs2Next.limb3
  | 32 => boolM31 row.zeroDivisor
  | 33 => boolM31 row.rZero
  | 34 => bitVecM31 row.quotient.limb0
  | 35 => bitVecM31 row.quotient.limb1
  | 36 => bitVecM31 row.quotient.limb2
  | 37 => bitVecM31 row.quotient.limb3
  | 38 => bitVecM31 row.remainder.limb0
  | 39 => bitVecM31 row.remainder.limb1
  | 40 => bitVecM31 row.remainder.limb2
  | 41 => bitVecM31 row.remainder.limb3
  | 42 => boolM31 row.bSign
  | 43 => boolM31 row.cSign
  | 44 => boolM31 row.qSign
  | 45 => boolM31 row.signXor
  | 46 => witness.divisorSumInverse
  | 47 => witness.remainderSumInverse
  | 48 => bitVecM31 row.remainderAbs.limb0
  | 49 => bitVecM31 row.remainderAbs.limb1
  | 50 => bitVecM31 row.remainderAbs.limb2
  | 51 => bitVecM31 row.remainderAbs.limb3
  | 52 => witness.remainderInverse0
  | 53 => witness.remainderInverse1
  | 54 => witness.remainderInverse2
  | 55 => witness.remainderInverse3
  | 56 => boolM31 row.ltMarker0
  | 57 => boolM31 row.ltMarker1
  | 58 => boolM31 row.ltMarker2
  | 59 => boolM31 row.ltMarker3
  | 60 => M31.reduce row.ltDiff
  | 61 => boolM31 row.isDiv
  | 62 => boolM31 row.isDivu
  | 63 => boolM31 row.isRem
  | 64 => boolM31 row.isRemu
  | 65 => boolM31 row.destinationNonzero
  | 66 => witness.destinationInverse
  | _ => 0

def evaluation
    (selector : Selector)
    (row : Row)
    (witness : Witness row) : SymbolicEvaluation :=
  (program selector).evalSymbolic (columns row witness)

/-- A representative evaluator for the node graph shared by the four
production DIV-family programs.  The generated programs differ only in
committed selector metadata. -/
def baseEvaluation
    (row : Row)
    (witness : Witness row) : SymbolicEvaluation :=
  Programs.div.evalSymbolic (columns row witness)

private theorem evaluationNodesShared
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selector row witness).nodes =
      (baseEvaluation row witness).nodes := by
  simp only [
    evaluation, baseEvaluation, LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic, programNodesShared,
  ]

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourceOnePreviousBound : row.rs1PreviousClock < 2 ^ 26
  sourceTwoPreviousBound : row.rs2PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcBound : row.pc.toNat + 4 < M31.modulus

abbrev Acceptance
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  Publication.AcceptedProductionEvaluation
    (evaluation selector row witness) relationHolds

private def accessClockField (row : Row) (ordinal : Nat) : M31 :=
  (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 +
    M31.reduce ordinal

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 79
  domain := .programAccess
  numerator := -activeField row
  tuple := #[
    bitVecM31 row.pc, opcodeField row,
    bitVecM31 row.rd, bitVecM31 row.rs1, bitVecM31 row.rs2
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 80
  domain := .registersState
  numerator := -activeField row
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 81
  domain := .registersState
  numerator := activeField row
  tuple := #[bitVecM31 row.pc + M31.reduce 4, M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

private def registerConsume
    (row : Row)
    (ordinal accessOrdinal : Nat)
    (address : RegisterIndex)
    (previousClock : Nat)
    (previous : WordBytes) : EvaluatedLookup where
  ordinal
  domain := .memoryAccess
  numerator := -activeField row
  tuple := #[
    0, bitVecM31 address, M31.reduce previousClock,
    bitVecM31 previous.limb0, bitVecM31 previous.limb1,
    bitVecM31 previous.limb2, bitVecM31 previous.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some accessOrdinal

private def registerEmit
    (row : Row)
    (ordinal accessOrdinal : Nat)
    (address : RegisterIndex)
    (next : WordBytes) : EvaluatedLookup where
  ordinal
  domain := .memoryAccess
  numerator := activeField row
  tuple := #[
    0, bitVecM31 address, accessClockField row accessOrdinal,
    bitVecM31 next.limb0, bitVecM31 next.limb1,
    bitVecM31 next.limb2, bitVecM31 next.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some accessOrdinal

private def difficultTupleOrdinals : List Nat :=
  [79, 80, 81, 82, 83, 85, 86, 101, 102]

private def difficultTupleRawLookup : Nat → LookupEvent
  | 79 => {
      ordinal := 79
      domain := .programAccess
      numerator := 388
      tuple := #[1, 399, 2, 12, 22]
      role := .request
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 80 => {
      ordinal := 80
      domain := .registersState
      numerator := 388
      tuple := #[1, 0]
      role := .consume
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 81 => {
      ordinal := 81
      domain := .registersState
      numerator := 70
      tuple := #[401, 402]
      role := .emit
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 82 => {
      ordinal := 82
      domain := .memoryAccess
      numerator := 388
      tuple := #[91, 12, 17, 13, 14, 15, 16]
      role := .consume
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := some 1
    }
  | 83 => {
      ordinal := 83
      domain := .memoryAccess
      numerator := 70
      tuple := #[91, 12, 405, 18, 19, 20, 21]
      role := .emit
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := some 1
    }
  | 85 => {
      ordinal := 85
      domain := .memoryAccess
      numerator := 388
      tuple := #[91, 22, 27, 23, 24, 25, 26]
      role := .consume
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := some 2
    }
  | 86 => {
      ordinal := 86
      domain := .memoryAccess
      numerator := 70
      tuple := #[91, 22, 408, 28, 29, 30, 31]
      role := .emit
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := some 2
    }
  | 101 => {
      ordinal := 101
      domain := .memoryAccess
      numerator := 388
      tuple := #[91, 2, 7, 3, 4, 5, 6]
      role := .consume
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := some 3
    }
  | 102 => {
      ordinal := 102
      domain := .memoryAccess
      numerator := 70
      tuple := #[91, 2, 419, 8, 9, 10, 11]
      role := .emit
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := some 3
    }
  | ordinal => {
      ordinal
      domain := .programAccess
      numerator := 0
      tuple := #[]
      role := .request
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }

private def expectedDifficultTupleLookup (row : Row) : Nat → EvaluatedLookup
  | 79 => programLookup row
  | 80 => stateConsumeLookup row
  | 81 => stateEmitLookup row
  | 82 =>
      registerConsume row 82 1
        row.rs1 row.rs1PreviousClock row.rs1Previous
  | 83 => registerEmit row 83 1 row.rs1 row.rs1Next
  | 85 =>
      registerConsume row 85 2
        row.rs2 row.rs2PreviousClock row.rs2Previous
  | 86 => registerEmit row 86 2 row.rs2 row.rs2Next
  | 101 =>
      registerConsume row 101 3
        row.rd row.rdPreviousClock row.rdPrevious
  | 102 => registerEmit row 102 3 row.rd row.rdNext
  | _ => programLookup row

set_option maxRecDepth 30000 in
private theorem difficultTupleRawLookup_selected
    (selector : Selector)
    (ordinal : Nat)
    (member : ordinal ∈ difficultTupleOrdinals) :
    (program selector).source.events[ordinal]? =
      some (.lookup (difficultTupleRawLookup ordinal)) := by
  have choices := member
  simp [difficultTupleOrdinals] at choices
  rcases choices with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    rw [programEventsShared]
    rfl

private def evaluatedSelectedLookup
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (event : LookupEvent) : EvaluatedLookup where
  ordinal := event.ordinal
  domain := event.domain
  numerator :=
    ((program selector).evalNodesSymbolic
      (columns row witness)).getSymbolic event.numerator
  tuple :=
    event.tuple.map
      ((program selector).evalNodesSymbolic
        (columns row witness)).getSymbolic
  role := event.role
  tableId := event.tableId
  accessOrdinal := event.accessOrdinal

private def sourceOneConsumeRawLookup : LookupEvent where
  ordinal := 82
  domain := .memoryAccess
  numerator := 388
  tuple := #[91, 12, 17, 13, 14, 15, 16]
  role := .consume
  tableId := none
  liveness := .nonzeroNumerator
  accessOrdinal := some 1

private theorem sourceOneConsumeRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[82]? =
      some (.lookup sourceOneConsumeRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
private theorem sourceOneConsumeProjectionAt
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selector row witness).lookup? 82 =
      some
        (registerConsume row 82 1
          row.rs1 row.rs1PreviousClock row.rs1Previous) := by
  have projected :
      (evaluation selector row witness).lookup? 82 =
        some
          (evaluatedSelectedLookup selector row witness
            sourceOneConsumeRawLookup) := by
    unfold evaluation evaluatedSelectedLookup
    exact
      LocalProgram.lookup?_evalSymbolic_of_event
        (program selector) (columns row witness) 82
        sourceOneConsumeRawLookup
        (sourceOneConsumeRawLookup_selected selector)
  have evaluated :
      evaluatedSelectedLookup selector row witness
          sourceOneConsumeRawLookup =
        registerConsume row 82 1
          row.rs1 row.rs1PreviousClock row.rs1Previous := by
    simp [
      evaluatedSelectedLookup,
      sourceOneConsumeRawLookup,
      LocalProgram.evalNodesSymbolic,
      programNodesShared,
      Programs.div,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      columns,
      registerConsume,
      activeField,
      bitVecM31,
      boolM31,
    ]
  exact projected.trans (congrArg some evaluated)

private def sourceOneEmitRawLookup : LookupEvent where
  ordinal := 83
  domain := .memoryAccess
  numerator := 70
  tuple := #[91, 12, 405, 18, 19, 20, 21]
  role := .emit
  tableId := none
  liveness := .nonzeroNumerator
  accessOrdinal := some 1

private theorem sourceOneEmitRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[83]? =
      some (.lookup sourceOneEmitRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
private theorem sourceOneEmitProjectionAt
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selector row witness).lookup? 83 =
      some (registerEmit row 83 1 row.rs1 row.rs1Next) := by
  have projected :
      (evaluation selector row witness).lookup? 83 =
        some
          (evaluatedSelectedLookup selector row witness
            sourceOneEmitRawLookup) := by
    unfold evaluation evaluatedSelectedLookup
    exact
      LocalProgram.lookup?_evalSymbolic_of_event
        (program selector) (columns row witness) 83
        sourceOneEmitRawLookup
        (sourceOneEmitRawLookup_selected selector)
  have evaluated :
      evaluatedSelectedLookup selector row witness
          sourceOneEmitRawLookup =
        registerEmit row 83 1 row.rs1 row.rs1Next := by
    simp [
      evaluatedSelectedLookup,
      sourceOneEmitRawLookup,
      LocalProgram.evalNodesSymbolic,
      programNodesShared,
      Programs.div,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      columns,
      registerEmit,
      accessClockField,
      activeField,
      bitVecM31,
      boolM31,
    ]
  exact projected.trans (congrArg some evaluated)

private theorem selectedLookupProjection
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ difficultTupleOrdinals) :
    (evaluation selector row witness).lookup? ordinal =
      some
        (evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup ordinal)) := by
  unfold evaluation evaluatedSelectedLookup
  exact
    LocalProgram.lookup?_evalSymbolic_of_event
      (program selector) (columns row witness) ordinal
      (difficultTupleRawLookup ordinal)
      (difficultTupleRawLookup_selected selector ordinal member)

set_option maxRecDepth 30000 in
private theorem evaluatedEarlyTupleLookups
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 79) =
        expectedDifficultTupleLookup row 79 ∧
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 80) =
        expectedDifficultTupleLookup row 80 ∧
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 81) =
        expectedDifficultTupleLookup row 81 ∧
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 82) =
        expectedDifficultTupleLookup row 82 ∧
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 83) =
        expectedDifficultTupleLookup row 83 := by
  simp [
    evaluatedSelectedLookup,
    difficultTupleRawLookup,
    expectedDifficultTupleLookup,
    LocalProgram.evalNodesSymbolic,
    programNodesShared,
    Programs.div,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    columns,
    programLookup,
    stateConsumeLookup,
    stateEmitLookup,
    registerConsume,
    registerEmit,
    accessClockField,
    activeField,
    opcodeField,
    bitVecM31,
    boolM31,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedDifficultTupleLookups
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 85) =
        expectedDifficultTupleLookup row 85 ∧
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 86) =
        expectedDifficultTupleLookup row 86 ∧
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 101) =
        expectedDifficultTupleLookup row 101 ∧
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup 102) =
        expectedDifficultTupleLookup row 102 := by
  simp [
    evaluatedSelectedLookup, difficultTupleRawLookup,
    expectedDifficultTupleLookup,
    LocalProgram.evalNodesSymbolic, programNodesShared,
    Programs.div,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic,
    columns, registerConsume, registerEmit, accessClockField,
    activeField, bitVecM31, boolM31,
  ]

private theorem difficultTupleProjectionAt
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ difficultTupleOrdinals) :
    (evaluation selector row witness).lookup? ordinal =
      some (expectedDifficultTupleLookup row ordinal) := by
  obtain ⟨h79, h80, h81, h82, h83⟩ :=
    evaluatedEarlyTupleLookups selector row witness
  obtain ⟨h85, h86, h101, h102⟩ :=
    evaluatedDifficultTupleLookups selector row witness
  have evaluated :
      evaluatedSelectedLookup selector row witness
          (difficultTupleRawLookup ordinal) =
        expectedDifficultTupleLookup row ordinal := by
    have choices := member
    simp [difficultTupleOrdinals] at choices
    rcases choices with
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  exact
    (selectedLookupProjection selector row witness ordinal member).trans
      (congrArg some evaluated)

structure ExactTupleProjection
    (selector : Selector)
    (row : Row)
    (witness : Witness row) : Prop where
  program :
    (evaluation selector row witness).lookup? 79 =
      some (programLookup row)
  stateConsume :
    (evaluation selector row witness).lookup? 80 =
      some (stateConsumeLookup row)
  stateEmit :
    (evaluation selector row witness).lookup? 81 =
      some (stateEmitLookup row)
  sourceOneConsume :
    (evaluation selector row witness).lookup? 82 =
      some (registerConsume row 82 1
        row.rs1 row.rs1PreviousClock row.rs1Previous)
  sourceOneEmit :
    (evaluation selector row witness).lookup? 83 =
      some (registerEmit row 83 1 row.rs1 row.rs1Next)
  sourceTwoConsume :
    (evaluation selector row witness).lookup? 85 =
      some (registerConsume row 85 2
        row.rs2 row.rs2PreviousClock row.rs2Previous)
  sourceTwoEmit :
    (evaluation selector row witness).lookup? 86 =
      some (registerEmit row 86 2 row.rs2 row.rs2Next)
  destinationConsume :
    (evaluation selector row witness).lookup? 101 =
      some (registerConsume row 101 3
        row.rd row.rdPreviousClock row.rdPrevious)
  destinationEmit :
    (evaluation selector row witness).lookup? 102 =
      some (registerEmit row 102 3 row.rd row.rdNext)

private theorem exactTupleProjectionFor
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection selector row witness := by
  exact {
    program :=
      difficultTupleProjectionAt selector row witness 79 (by decide)
    stateConsume :=
      difficultTupleProjectionAt selector row witness 80 (by decide)
    stateEmit :=
      difficultTupleProjectionAt selector row witness 81 (by decide)
    sourceOneConsume :=
      difficultTupleProjectionAt selector row witness 82 (by decide)
    sourceOneEmit :=
      difficultTupleProjectionAt selector row witness 83 (by decide)
    sourceTwoConsume :=
      difficultTupleProjectionAt selector row witness 85 (by decide)
    sourceTwoEmit :=
      difficultTupleProjectionAt selector row witness 86 (by decide)
    destinationConsume :=
      difficultTupleProjectionAt selector row witness 101 (by decide)
    destinationEmit :=
      difficultTupleProjectionAt selector row witness 102 (by decide)
  }

set_option maxRecDepth 30000 in
private theorem divExactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection .div row witness := by
  exact exactTupleProjectionFor .div row witness

set_option maxRecDepth 30000 in
private theorem divuExactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection .divu row witness := by
  exact exactTupleProjectionFor .divu row witness

set_option maxRecDepth 30000 in
private theorem remExactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection .rem row witness := by
  exact exactTupleProjectionFor .rem row witness

set_option maxRecDepth 30000 in
private theorem remuExactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection .remu row witness := by
  exact exactTupleProjectionFor .remu row witness

theorem exactTupleProjection
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection selector row witness := by
  cases selector with
  | div => exact divExactTupleProjection row witness
  | divu => exact divuExactTupleProjection row witness
  | rem => exact remExactTupleProjection row witness
  | remu => exact remuExactTupleProjection row witness

private def clockGapField
    (row : Row) (ordinal previous : Nat) : M31 :=
  accessClockField row ordinal - M31.reduce previous - M31.reduce 1

private def clockLookup
    (row : Row)
    (ordinal eventOrdinal previous : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck20
  numerator := -activeField row
  tuple := #[clockGapField row ordinal previous]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some ordinal

private def quotientHighField (row : Row) : M31 :=
  boolM31 row.qSign * M31.reduce 255

private def divisorHighField (row : Row) : M31 :=
  boolM31 row.cSign * M31.reduce 255

private def dividendHighField (row : Row) : M31 :=
  boolM31 row.bSign * M31.reduce 255

private def remainderHighField (row : Row) : M31 :=
  boolM31 row.bSign * (1 - boolM31 row.rZero) * M31.reduce 255

private def carry0Field (row : Row) : M31 :=
  (bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb0 +
      bitVecM31 row.remainder.limb0 -
      bitVecM31 row.rs1Next.limb0) * M31.reduce 8388608

private def carry1Field (row : Row) : M31 :=
  (carry0Field row +
        bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb1 +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb1 -
      bitVecM31 row.rs1Next.limb1) * M31.reduce 8388608

private def carry2Field (row : Row) : M31 :=
  (carry1Field row +
        bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb2 +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb1 +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb2 -
      bitVecM31 row.rs1Next.limb2) * M31.reduce 8388608

private def carry3Field (row : Row) : M31 :=
  (carry2Field row +
        bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb3 +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb2 +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb1 +
        bitVecM31 row.rs2Next.limb3 * bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb3 -
      bitVecM31 row.rs1Next.limb3) * M31.reduce 8388608

private def carry4Field (row : Row) : M31 :=
  (carry3Field row +
        bitVecM31 row.rs2Next.limb0 * quotientHighField row +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb3 +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb2 +
        bitVecM31 row.rs2Next.limb3 * bitVecM31 row.quotient.limb1 +
        divisorHighField row * bitVecM31 row.quotient.limb0 +
        remainderHighField row -
      dividendHighField row) * M31.reduce 8388608

private def carry5Field (row : Row) : M31 :=
  (carry4Field row +
        (bitVecM31 row.rs2Next.limb0 + bitVecM31 row.rs2Next.limb1) *
          quotientHighField row +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb3 +
        bitVecM31 row.rs2Next.limb3 * bitVecM31 row.quotient.limb2 +
        divisorHighField row *
          (bitVecM31 row.quotient.limb0 + bitVecM31 row.quotient.limb1) +
        remainderHighField row -
      dividendHighField row) * M31.reduce 8388608

private def carry6Field (row : Row) : M31 :=
  (carry5Field row +
        (bitVecM31 row.rs2Next.limb0 +
            bitVecM31 row.rs2Next.limb1 +
            bitVecM31 row.rs2Next.limb2 +
            bitVecM31 row.rs2Next.limb3 -
          bitVecM31 row.rs2Next.limb3) *
          quotientHighField row +
        bitVecM31 row.rs2Next.limb3 * bitVecM31 row.quotient.limb3 +
        divisorHighField row *
          (bitVecM31 row.quotient.limb0 +
            bitVecM31 row.quotient.limb1 +
            bitVecM31 row.quotient.limb2 +
            bitVecM31 row.quotient.limb3 -
          bitVecM31 row.quotient.limb3) +
        remainderHighField row -
      dividendHighField row) * M31.reduce 8388608

private def carry7Field (row : Row) : M31 :=
  (carry6Field row +
        (bitVecM31 row.rs2Next.limb0 +
            bitVecM31 row.rs2Next.limb1 +
            bitVecM31 row.rs2Next.limb2 +
            bitVecM31 row.rs2Next.limb3) *
          quotientHighField row +
        divisorHighField row *
          (bitVecM31 row.quotient.limb0 +
            bitVecM31 row.quotient.limb1 +
            bitVecM31 row.quotient.limb2 +
            bitVecM31 row.quotient.limb3) +
        remainderHighField row -
      dividendHighField row) * M31.reduce 8388608

private def wordSumField (bytes : WordBytes) : M31 :=
  bitVecM31 bytes.limb0 + bitVecM31 bytes.limb1 +
    bitVecM31 bytes.limb2 + bitVecM31 bytes.limb3

private def wordSumNat (bytes : WordBytes) : Nat :=
  bytes.limb0.toNat + bytes.limb1.toNat +
    bytes.limb2.toNat + bytes.limb3.toNat

private def divisorSumField (row : Row) : M31 :=
  wordSumField row.rs2Next

private def remainderSumField (row : Row) : M31 :=
  wordSumField row.remainder

private def quotientSumField (row : Row) : M31 :=
  wordSumField row.quotient

private def specialField (row : Row) : M31 :=
  boolM31 row.zeroDivisor + boolM31 row.rZero

private def divisionField (row : Row) : M31 :=
  boolM31 row.isDiv + boolM31 row.isDivu

private def negCarry0Field (row : Row) : M31 :=
  (bitVecM31 row.remainder.limb0 +
      bitVecM31 row.remainderAbs.limb0) * M31.reduce 8388608

private def negCarry1Field (row : Row) : M31 :=
  (negCarry0Field row +
      bitVecM31 row.remainder.limb1 +
      bitVecM31 row.remainderAbs.limb1) * M31.reduce 8388608

private def negCarry2Field (row : Row) : M31 :=
  (negCarry1Field row +
      bitVecM31 row.remainder.limb2 +
      bitVecM31 row.remainderAbs.limb2) * M31.reduce 8388608

private def negCarry3Field (row : Row) : M31 :=
  (negCarry2Field row +
      bitVecM31 row.remainder.limb3 +
      bitVecM31 row.remainderAbs.limb3) * M31.reduce 8388608

private def compareDiffField
    (row : Row)
    (divisor absolute : Byte) : M31 :=
  (1 - boolM31 row.cSign * M31.reduce 2) *
    (bitVecM31 divisor - bitVecM31 absolute)

private def prefix3Field (row : Row) : M31 :=
  specialField row + boolM31 row.ltMarker3

private def prefix2Field (row : Row) : M31 :=
  prefix3Field row + boolM31 row.ltMarker2

private def prefix1Field (row : Row) : M31 :=
  prefix2Field row + boolM31 row.ltMarker1

private def prefix0Field (row : Row) : M31 :=
  prefix1Field row + boolM31 row.ltMarker0

private def resultLimbField
    (row : Row)
    (quotient remainder : Byte) : M31 :=
  divisionField row * bitVecM31 quotient +
    (1 - divisionField row) * bitVecM31 remainder

private def bytePairLookup
    (row : Row)
    (ordinal : Nat)
    (left right : Byte) : EvaluatedLookup where
  ordinal
  domain := .rangeCheck88
  numerator := -activeField row
  tuple := #[bitVecM31 left, bitVecM31 right]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def carryLookup
    (row : Row)
    (ordinal : Nat)
    (result : Byte)
    (carry : M31) : EvaluatedLookup where
  ordinal
  domain := .rangeCheck811
  numerator := -activeField row
  tuple := #[bitVecM31 result, carry]
  role := .request
  tableId := some .rangeCheck811
  accessOrdinal := none

private def signedField (row : Row) : M31 :=
  boolM31 row.isDiv + boolM31 row.isRem

private def quotientSignActiveField (row : Row) : M31 :=
  signedField row * (activeField row - boolM31 row.zeroDivisor) -
    boolM31 row.bSign * boolM31 row.cSign

private def quotientSignLookup (row : Row) : EvaluatedLookup where
  ordinal := 98
  domain := .rangeCheckM31
  numerator := -quotientSignActiveField row
  tuple := #[
    0,
    bitVecM31 row.quotient.limb3 -
      boolM31 row.qSign * M31.reduce 128
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def signRangeLookup (row : Row) : EvaluatedLookup where
  ordinal := 99
  domain := .rangeCheck88
  numerator := -activeField row
  tuple := #[
    signedField row *
        (bitVecM31 row.rs1Next.limb3 -
          boolM31 row.bSign * M31.reduce 128) *
      M31.reduce 2,
    signedField row *
        (bitVecM31 row.rs2Next.limb3 -
          boolM31 row.cSign * M31.reduce 128) *
      M31.reduce 2
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def positiveDiffLookup (row : Row) : EvaluatedLookup where
  ordinal := 100
  domain := .rangeCheck20
  numerator :=
    -(activeField row -
      (boolM31 row.zeroDivisor + boolM31 row.rZero))
  tuple := #[M31.reduce row.ltDiff - M31.reduce 1]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

private def difficultFixedOrdinals : List Nat :=
  [84, 87, 88, 89, 90, 91, 92, 93,
    94, 95, 96, 97, 98, 99, 100, 103]

private def difficultFixedRawLookup : Nat → LookupEvent
  | 84 => {
      ordinal := 84
      domain := .rangeCheck20
      numerator := 388
      tuple := #[407]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := some 1
    }
  | 87 => {
      ordinal := 87
      domain := .rangeCheck20
      numerator := 388
      tuple := #[410]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := some 2
    }
  | 88 => {
      ordinal := 88
      domain := .rangeCheck88
      numerator := 388
      tuple := #[28, 29]
      role := .request
      tableId := some .rangeCheck88
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 89 => {
      ordinal := 89
      domain := .rangeCheck88
      numerator := 388
      tuple := #[30, 31]
      role := .request
      tableId := some .rangeCheck88
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 90 => {
      ordinal := 90
      domain := .rangeCheck811
      numerator := 388
      tuple := #[34, 134]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 91 => {
      ordinal := 91
      domain := .rangeCheck811
      numerator := 388
      tuple := #[35, 141]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 92 => {
      ordinal := 92
      domain := .rangeCheck811
      numerator := 388
      tuple := #[36, 150]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 93 => {
      ordinal := 93
      domain := .rangeCheck811
      numerator := 388
      tuple := #[37, 161]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 94 => {
      ordinal := 94
      domain := .rangeCheck811
      numerator := 388
      tuple := #[38, 174]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 95 => {
      ordinal := 95
      domain := .rangeCheck811
      numerator := 388
      tuple := #[39, 185]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 96 => {
      ordinal := 96
      domain := .rangeCheck811
      numerator := 388
      tuple := #[40, 196]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 97 => {
      ordinal := 97
      domain := .rangeCheck811
      numerator := 388
      tuple := #[41, 203]
      role := .request
      tableId := some .rangeCheck811
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 98 => {
      ordinal := 98
      domain := .rangeCheckM31
      numerator := 415
      tuple := #[91, 414]
      role := .request
      tableId := some .rangeCheckM31
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 99 => {
      ordinal := 99
      domain := .rangeCheck88
      numerator := 388
      tuple := #[210, 214]
      role := .request
      tableId := some .rangeCheck88
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 100 => {
      ordinal := 100
      domain := .rangeCheck20
      numerator := 416
      tuple := #[417]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 103 => {
      ordinal := 103
      domain := .rangeCheck20
      numerator := 388
      tuple := #[421]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := some 3
    }
  | ordinal => {
      ordinal
      domain := .programAccess
      numerator := 0
      tuple := #[]
      role := .request
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }

private def expectedDifficultFixedLookup (row : Row) : Nat → EvaluatedLookup
  | 84 => clockLookup row 1 84 row.rs1PreviousClock
  | 87 => clockLookup row 2 87 row.rs2PreviousClock
  | 88 =>
      bytePairLookup row 88 row.rs2Next.limb0 row.rs2Next.limb1
  | 89 =>
      bytePairLookup row 89 row.rs2Next.limb2 row.rs2Next.limb3
  | 90 => carryLookup row 90 row.quotient.limb0 (carry0Field row)
  | 91 => carryLookup row 91 row.quotient.limb1 (carry1Field row)
  | 92 => carryLookup row 92 row.quotient.limb2 (carry2Field row)
  | 93 => carryLookup row 93 row.quotient.limb3 (carry3Field row)
  | 94 => carryLookup row 94 row.remainder.limb0 (carry4Field row)
  | 95 => carryLookup row 95 row.remainder.limb1 (carry5Field row)
  | 96 => carryLookup row 96 row.remainder.limb2 (carry6Field row)
  | 97 => carryLookup row 97 row.remainder.limb3 (carry7Field row)
  | 98 => quotientSignLookup row
  | 99 => signRangeLookup row
  | 100 => positiveDiffLookup row
  | 103 => clockLookup row 3 103 row.rdPreviousClock
  | _ => signRangeLookup row

set_option maxRecDepth 30000 in
private theorem difficultFixedRawLookup_selected
    (selector : Selector)
    (ordinal : Nat)
    (member : ordinal ∈ difficultFixedOrdinals) :
    (program selector).source.events[ordinal]? =
      some (.lookup (difficultFixedRawLookup ordinal)) := by
  have choices := member
  simp [difficultFixedOrdinals] at choices
  rcases choices with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    rw [programEventsShared]
    rfl

private theorem selectedFixedLookupProjection
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ difficultFixedOrdinals) :
    (evaluation selector row witness).lookup? ordinal =
      some
        (evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup ordinal)) := by
  unfold evaluation evaluatedSelectedLookup
  exact
    LocalProgram.lookup?_evalSymbolic_of_event
      (program selector) (columns row witness) ordinal
      (difficultFixedRawLookup ordinal)
      (difficultFixedRawLookup_selected selector ordinal member)

set_option maxRecDepth 30000 in
private theorem evaluatedFixedLookupsA
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 84) =
        expectedDifficultFixedLookup row 84 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 87) =
        expectedDifficultFixedLookup row 87 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 88) =
        expectedDifficultFixedLookup row 88 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 89) =
        expectedDifficultFixedLookup row 89 := by
  simp [
    evaluatedSelectedLookup,
    difficultFixedRawLookup,
    expectedDifficultFixedLookup,
    LocalProgram.evalNodesSymbolic,
    programNodesShared,
    Programs.div,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    columns,
    clockLookup,
    clockGapField,
    bytePairLookup,
    accessClockField,
    activeField,
    bitVecM31,
    boolM31,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedFixedLookupsB
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 90) =
        expectedDifficultFixedLookup row 90 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 91) =
        expectedDifficultFixedLookup row 91 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 92) =
        expectedDifficultFixedLookup row 92 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 93) =
        expectedDifficultFixedLookup row 93 := by
  simp [
    evaluatedSelectedLookup,
    difficultFixedRawLookup,
    expectedDifficultFixedLookup,
    LocalProgram.evalNodesSymbolic,
    programNodesShared,
    Programs.div,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    columns,
    carryLookup,
    carry0Field,
    carry1Field,
    carry2Field,
    carry3Field,
    activeField,
    bitVecM31,
    boolM31,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedFixedLookupsC
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 94) =
        expectedDifficultFixedLookup row 94 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 95) =
        expectedDifficultFixedLookup row 95 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 96) =
        expectedDifficultFixedLookup row 96 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 97) =
        expectedDifficultFixedLookup row 97 := by
  simp [
    evaluatedSelectedLookup,
    difficultFixedRawLookup,
    expectedDifficultFixedLookup,
    LocalProgram.evalNodesSymbolic,
    programNodesShared,
    Programs.div,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    columns,
    carryLookup,
    carry0Field,
    carry1Field,
    carry2Field,
    carry3Field,
    carry4Field,
    carry5Field,
    carry6Field,
    carry7Field,
    quotientHighField,
    divisorHighField,
    remainderHighField,
    dividendHighField,
    activeField,
    bitVecM31,
    boolM31,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedDifficultFixedLookups
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 98) =
        expectedDifficultFixedLookup row 98 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 99) =
        expectedDifficultFixedLookup row 99 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 100) =
        expectedDifficultFixedLookup row 100 ∧
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup 103) =
        expectedDifficultFixedLookup row 103 := by
  simp [
    evaluatedSelectedLookup, difficultFixedRawLookup,
    expectedDifficultFixedLookup,
    LocalProgram.evalNodesSymbolic, programNodesShared,
    Programs.div,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic,
    columns, quotientSignLookup, signRangeLookup, positiveDiffLookup,
    clockLookup, clockGapField, accessClockField,
    quotientSignActiveField, signedField, activeField, bitVecM31, boolM31,
  ]

private theorem difficultFixedProjectionAt
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ difficultFixedOrdinals) :
    (evaluation selector row witness).lookup? ordinal =
      some (expectedDifficultFixedLookup row ordinal) := by
  obtain ⟨h84, h87, h88, h89⟩ :=
    evaluatedFixedLookupsA selector row witness
  obtain ⟨h90, h91, h92, h93⟩ :=
    evaluatedFixedLookupsB selector row witness
  obtain ⟨h94, h95, h96, h97⟩ :=
    evaluatedFixedLookupsC selector row witness
  obtain ⟨h98, h99, h100, h103⟩ :=
    evaluatedDifficultFixedLookups selector row witness
  have evaluated :
      evaluatedSelectedLookup selector row witness
          (difficultFixedRawLookup ordinal) =
        expectedDifficultFixedLookup row ordinal := by
    have choices := member
    simp [difficultFixedOrdinals] at choices
    rcases choices with
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
      rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  exact
    (selectedFixedLookupProjection
      selector row witness ordinal member).trans
      (congrArg some evaluated)

private def carrySixRawLookup : LookupEvent where
  ordinal := 96
  domain := .rangeCheck811
  numerator := 388
  tuple := #[40, 196]
  role := .request
  tableId := some .rangeCheck811
  liveness := .nonzeroNumerator
  accessOrdinal := none

private theorem carrySixRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[96]? =
      some (.lookup carrySixRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
private theorem carrySixProjectionAt
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selector row witness).lookup? 96 =
      some
        (carryLookup row 96 row.remainder.limb2 (carry6Field row)) := by
  have projected :
      (evaluation selector row witness).lookup? 96 =
        some
          (evaluatedSelectedLookup selector row witness
            carrySixRawLookup) := by
    unfold evaluation evaluatedSelectedLookup
    exact
      LocalProgram.lookup?_evalSymbolic_of_event
        (program selector) (columns row witness) 96
        carrySixRawLookup
        (carrySixRawLookup_selected selector)
  have evaluated :
      evaluatedSelectedLookup selector row witness carrySixRawLookup =
        carryLookup row 96 row.remainder.limb2 (carry6Field row) := by
    simp [
      evaluatedSelectedLookup,
      carrySixRawLookup,
      LocalProgram.evalNodesSymbolic,
      programNodesShared,
      Programs.div,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      columns,
      carryLookup,
      carry0Field,
      carry1Field,
      carry2Field,
      carry3Field,
      carry4Field,
      carry5Field,
      carry6Field,
      quotientHighField,
      divisorHighField,
      remainderHighField,
      dividendHighField,
      activeField,
      bitVecM31,
      boolM31,
    ]
  exact projected.trans (congrArg some evaluated)

private def carrySevenRawLookup : LookupEvent where
  ordinal := 97
  domain := .rangeCheck811
  numerator := 388
  tuple := #[41, 203]
  role := .request
  tableId := some .rangeCheck811
  liveness := .nonzeroNumerator
  accessOrdinal := none

private theorem carrySevenRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[97]? =
      some (.lookup carrySevenRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
private theorem carrySevenProjectionAt
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selector row witness).lookup? 97 =
      some
        (carryLookup row 97 row.remainder.limb3 (carry7Field row)) := by
  have projected :
      (evaluation selector row witness).lookup? 97 =
        some
          (evaluatedSelectedLookup selector row witness
            carrySevenRawLookup) := by
    unfold evaluation evaluatedSelectedLookup
    exact
      LocalProgram.lookup?_evalSymbolic_of_event
        (program selector) (columns row witness) 97
        carrySevenRawLookup
        (carrySevenRawLookup_selected selector)
  have evaluated :
      evaluatedSelectedLookup selector row witness carrySevenRawLookup =
        carryLookup row 97 row.remainder.limb3 (carry7Field row) := by
    simp [
      evaluatedSelectedLookup,
      carrySevenRawLookup,
      LocalProgram.evalNodesSymbolic,
      programNodesShared,
      Programs.div,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      columns,
      carryLookup,
      carry0Field,
      carry1Field,
      carry2Field,
      carry3Field,
      carry4Field,
      carry5Field,
      carry6Field,
      carry7Field,
      quotientHighField,
      divisorHighField,
      remainderHighField,
      dividendHighField,
      activeField,
      bitVecM31,
      boolM31,
    ]
  exact projected.trans (congrArg some evaluated)

structure ExactFixedProjection
    (selector : Selector)
    (row : Row)
    (witness : Witness row) : Prop where
  sourceOneClock :
    (evaluation selector row witness).lookup? 84 =
      some (clockLookup row 1 84 row.rs1PreviousClock)
  sourceTwoClock :
    (evaluation selector row witness).lookup? 87 =
      some (clockLookup row 2 87 row.rs2PreviousClock)
  divisorLow :
    (evaluation selector row witness).lookup? 88 =
      some (bytePairLookup row 88
        row.rs2Next.limb0 row.rs2Next.limb1)
  divisorHigh :
    (evaluation selector row witness).lookup? 89 =
      some (bytePairLookup row 89
        row.rs2Next.limb2 row.rs2Next.limb3)
  carry0 :
    (evaluation selector row witness).lookup? 90 =
      some (carryLookup row 90 row.quotient.limb0 (carry0Field row))
  carry1 :
    (evaluation selector row witness).lookup? 91 =
      some (carryLookup row 91 row.quotient.limb1 (carry1Field row))
  carry2 :
    (evaluation selector row witness).lookup? 92 =
      some (carryLookup row 92 row.quotient.limb2 (carry2Field row))
  carry3 :
    (evaluation selector row witness).lookup? 93 =
      some (carryLookup row 93 row.quotient.limb3 (carry3Field row))
  carry4 :
    (evaluation selector row witness).lookup? 94 =
      some (carryLookup row 94 row.remainder.limb0 (carry4Field row))
  carry5 :
    (evaluation selector row witness).lookup? 95 =
      some (carryLookup row 95 row.remainder.limb1 (carry5Field row))
  carry6 :
    (evaluation selector row witness).lookup? 96 =
      some (carryLookup row 96 row.remainder.limb2 (carry6Field row))
  carry7 :
    (evaluation selector row witness).lookup? 97 =
      some (carryLookup row 97 row.remainder.limb3 (carry7Field row))
  quotientSign :
    (evaluation selector row witness).lookup? 98 =
      some (quotientSignLookup row)
  operandSigns :
    (evaluation selector row witness).lookup? 99 =
      some (signRangeLookup row)
  positiveDiff :
    (evaluation selector row witness).lookup? 100 =
      some (positiveDiffLookup row)
  destinationClock :
    (evaluation selector row witness).lookup? 103 =
      some (clockLookup row 3 103 row.rdPreviousClock)

private theorem exactFixedProjectionFor
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection selector row witness := by
  exact {
    sourceOneClock :=
      difficultFixedProjectionAt selector row witness 84 (by decide)
    sourceTwoClock :=
      difficultFixedProjectionAt selector row witness 87 (by decide)
    divisorLow :=
      difficultFixedProjectionAt selector row witness 88 (by decide)
    divisorHigh :=
      difficultFixedProjectionAt selector row witness 89 (by decide)
    carry0 :=
      difficultFixedProjectionAt selector row witness 90 (by decide)
    carry1 :=
      difficultFixedProjectionAt selector row witness 91 (by decide)
    carry2 :=
      difficultFixedProjectionAt selector row witness 92 (by decide)
    carry3 :=
      difficultFixedProjectionAt selector row witness 93 (by decide)
    carry4 :=
      difficultFixedProjectionAt selector row witness 94 (by decide)
    carry5 :=
      difficultFixedProjectionAt selector row witness 95 (by decide)
    carry6 :=
      difficultFixedProjectionAt selector row witness 96 (by decide)
    carry7 :=
      difficultFixedProjectionAt selector row witness 97 (by decide)
    quotientSign :=
      difficultFixedProjectionAt selector row witness 98 (by decide)
    operandSigns :=
      difficultFixedProjectionAt selector row witness 99 (by decide)
    positiveDiff :=
      difficultFixedProjectionAt selector row witness 100 (by decide)
    destinationClock :=
      difficultFixedProjectionAt selector row witness 103 (by decide)
  }

set_option maxRecDepth 30000 in
private theorem divExactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection .div row witness := by
  exact exactFixedProjectionFor .div row witness

set_option maxRecDepth 30000 in
private theorem divuExactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection .divu row witness := by
  exact exactFixedProjectionFor .divu row witness

set_option maxRecDepth 30000 in
private theorem remExactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection .rem row witness := by
  exact exactFixedProjectionFor .rem row witness

set_option maxRecDepth 30000 in
private theorem remuExactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection .remu row witness := by
  exact exactFixedProjectionFor .remu row witness

theorem exactFixedProjection
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection selector row witness := by
  cases selector with
  | div => exact divExactFixedProjection row witness
  | divu => exact divuExactFixedProjection row witness
  | rem => exact remExactFixedProjection row witness
  | remu => exact remuExactFixedProjection row witness

def constraintRoots : Array Nat := #[
  216, 218, 220, 222, 224, 226, 227, 229, 231, 233, 235,
  237, 239, 241, 243, 245, 247, 249, 250, 251, 252, 253,
  255, 257, 259, 261, 264, 265, 266, 267, 268, 271, 273,
  274, 280, 283, 285, 287, 289, 292, 295, 300, 302, 306,
  309, 313, 315, 319, 322, 326, 328, 332, 335, 339, 341,
  343, 345, 347, 349, 351, 353, 355, 356, 358, 360, 362,
  364, 366, 368, 370, 372, 374, 376, 378, 380, 382, 384,
  386, 387
]

set_option maxHeartbeats 800000 in
set_option maxRecDepth 30000 in
private theorem constraintsHoldEvents
    (selector : Selector)
    (nodes : LocalValues) :
    ((program selector).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      constraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  rw [programEventsShared]
  simp [Programs.divSource, constraintRoots, Event.evalSymbolic]

theorem constraintsHold_eq
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selector row witness).constraintsHold =
      constraintRoots.all
        (fun root =>
          (evaluation selector row witness).nodes.getSymbolic root == 0) :=
  constraintsHoldEvents selector (evaluation selector row witness).nodes

theorem constraintRootZero
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (accepted :
      (evaluation selector row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ constraintRoots) :
    (evaluation selector row witness).nodes.getSymbolic root = 0 := by
  rw [constraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

theorem baseConstraintRootZero
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (accepted :
      (evaluation selector row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ constraintRoots) :
    (baseEvaluation row witness).nodes.getSymbolic root = 0 := by
  rw [← evaluationNodesShared selector row witness]
  exact
    constraintRootZero selector row witness accepted root member

theorem baseConstraintRootZeroAt
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (accepted :
      (evaluation selector row witness).constraintsHold = true)
    (index : Fin constraintRoots.size) :
    (baseEvaluation row witness).nodes.getSymbolic
        constraintRoots[index] = 0 := by
  rw [← evaluationNodesShared selector row witness]
  rw [constraintsHold_eq, Array.all_eq_true] at accepted
  have selected := accepted index.1 index.2
  simpa only [beq_iff_eq] using selected

structure DirectEquationsA
    (row : Row)
    (witness : Witness row) : Prop where
  specialExclusive :
    specialField row * (1 - specialField row) = 0
  zeroDivisor0 :
    boolM31 row.zeroDivisor * bitVecM31 row.rs2Next.limb0 = 0
  zeroDivisor1 :
    boolM31 row.zeroDivisor * bitVecM31 row.rs2Next.limb1 = 0
  zeroDivisor2 :
    boolM31 row.zeroDivisor * bitVecM31 row.rs2Next.limb2 = 0
  zeroDivisor3 :
    boolM31 row.zeroDivisor * bitVecM31 row.rs2Next.limb3 = 0
  zeroQuotient0 :
    boolM31 row.zeroDivisor *
      (bitVecM31 row.quotient.limb0 - M31.reduce 255) = 0
  zeroQuotient1 :
    boolM31 row.zeroDivisor *
      (bitVecM31 row.quotient.limb1 - M31.reduce 255) = 0
  zeroQuotient2 :
    boolM31 row.zeroDivisor *
      (bitVecM31 row.quotient.limb2 - M31.reduce 255) = 0

structure DirectEquationsB
    (row : Row)
    (witness : Witness row) : Prop where
  zeroQuotient3 :
    boolM31 row.zeroDivisor *
      (bitVecM31 row.quotient.limb3 - M31.reduce 255) = 0
  divisorInverse :
    (activeField row - boolM31 row.zeroDivisor) *
      (divisorSumField row * witness.divisorSumInverse - 1) = 0
  remainderZero0 :
    boolM31 row.rZero * bitVecM31 row.remainder.limb0 = 0
  remainderZero1 :
    boolM31 row.rZero * bitVecM31 row.remainder.limb1 = 0
  remainderZero2 :
    boolM31 row.rZero * bitVecM31 row.remainder.limb2 = 0
  remainderZero3 :
    boolM31 row.rZero * bitVecM31 row.remainder.limb3 = 0
  remainderInverse :
    (activeField row - specialField row) *
      (remainderSumField row * witness.remainderSumInverse - 1) = 0
  unsignedDividendSign :
    (1 - signedField row) * boolM31 row.bSign = 0

structure DirectEquationsC
    (row : Row)
    (witness : Witness row) : Prop where
  unsignedDivisorSign :
    (1 - signedField row) * boolM31 row.cSign = 0
  signXor :
    activeField row *
      (boolM31 row.signXor - boolM31 row.bSign -
        boolM31 row.cSign +
        boolM31 row.bSign * boolM31 row.cSign * M31.reduce 2) = 0
  quotientSignMatches :
    (1 - boolM31 row.zeroDivisor) * quotientSumField row *
      (boolM31 row.qSign - boolM31 row.signXor) = 0
  quotientSignImplies :
    (1 - boolM31 row.zeroDivisor) *
      (boolM31 row.qSign - boolM31 row.signXor) *
      boolM31 row.qSign = 0
  zeroDivisorQuotientSign :
    boolM31 row.zeroDivisor *
      (boolM31 row.qSign - signedField row) = 0
  absSame0 :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb0 -
        bitVecM31 row.remainder.limb0) = 0
  negCarryBool0 :
    boolM31 row.signXor * negCarry0Field row *
      (negCarry0Field row - 1) = 0
  negCarryZero0 :
    boolM31 row.signXor * (1 - negCarry0Field row) *
      bitVecM31 row.remainderAbs.limb0 = 0

structure DirectEquationsD
    (row : Row)
    (witness : Witness row) : Prop where
  negCarryInverse0 :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb0 - M31.reduce 256) *
        witness.remainderInverse0 - 1) = 0
  absSame1 :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb1 -
        bitVecM31 row.remainder.limb1) = 0
  negCarryBool1 :
    boolM31 row.signXor *
      (negCarry1Field row - negCarry0Field row) *
      (negCarry1Field row - 1) = 0
  negCarryZero1 :
    boolM31 row.signXor * (1 - negCarry1Field row) *
      bitVecM31 row.remainderAbs.limb1 = 0
  negCarryInverse1 :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb1 - M31.reduce 256) *
        witness.remainderInverse1 - 1) = 0
  absSame2 :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb2 -
        bitVecM31 row.remainder.limb2) = 0
  negCarryBool2 :
    boolM31 row.signXor *
      (negCarry2Field row - negCarry1Field row) *
      (negCarry2Field row - 1) = 0
  negCarryZero2 :
    boolM31 row.signXor * (1 - negCarry2Field row) *
      bitVecM31 row.remainderAbs.limb2 = 0

structure DirectEquationsE
    (row : Row)
    (witness : Witness row) : Prop where
  negCarryInverse2 :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb2 - M31.reduce 256) *
        witness.remainderInverse2 - 1) = 0
  absSame3 :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb3 -
        bitVecM31 row.remainder.limb3) = 0
  negCarryBool3 :
    boolM31 row.signXor *
      (negCarry3Field row - negCarry2Field row) *
      (negCarry3Field row - 1) = 0
  negCarryZero3 :
    boolM31 row.signXor * (1 - negCarry3Field row) *
      bitVecM31 row.remainderAbs.limb3 = 0
  negCarryInverse3 :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb3 - M31.reduce 256) *
        witness.remainderInverse3 - 1) = 0
  scanEqual3 :
    (1 - prefix3Field row) *
      compareDiffField row row.rs2Next.limb3 row.remainderAbs.limb3 = 0
  scanMarker3 :
    boolM31 row.ltMarker3 *
      (M31.reduce row.ltDiff -
        compareDiffField row row.rs2Next.limb3 row.remainderAbs.limb3) = 0
  scanEqual2 :
    (1 - prefix2Field row) *
      compareDiffField row row.rs2Next.limb2 row.remainderAbs.limb2 = 0

structure DirectEquationsF
    (row : Row)
    (witness : Witness row) : Prop where
  scanMarker2 :
    boolM31 row.ltMarker2 *
      (M31.reduce row.ltDiff -
        compareDiffField row row.rs2Next.limb2 row.remainderAbs.limb2) = 0
  scanEqual1 :
    (1 - prefix1Field row) *
      compareDiffField row row.rs2Next.limb1 row.remainderAbs.limb1 = 0
  scanMarker1 :
    boolM31 row.ltMarker1 *
      (M31.reduce row.ltDiff -
        compareDiffField row row.rs2Next.limb1 row.remainderAbs.limb1) = 0
  scanEqual0 :
    (1 - prefix0Field row) *
      compareDiffField row row.rs2Next.limb0 row.remainderAbs.limb0 = 0
  scanMarker0 :
    boolM31 row.ltMarker0 *
      (M31.reduce row.ltDiff -
        compareDiffField row row.rs2Next.limb0 row.remainderAbs.limb0) = 0
  scanTotal :
    activeField row * (1 - prefix0Field row) = 0
  destinationZero :
    bitVecM31 row.rd * (1 - boolM31 row.destinationNonzero) = 0
  destinationInverse :
    bitVecM31 row.rd * witness.destinationInverse -
      boolM31 row.destinationNonzero = 0

structure DirectEquationsG
    (row : Row)
    (witness : Witness row) : Prop where
  destination0 :
    bitVecM31 row.rdNext.limb0 -
      boolM31 row.destinationNonzero *
        resultLimbField row row.quotient.limb0 row.remainder.limb0 = 0
  destination1 :
    bitVecM31 row.rdNext.limb1 -
      boolM31 row.destinationNonzero *
        resultLimbField row row.quotient.limb1 row.remainder.limb1 = 0
  destination2 :
    bitVecM31 row.rdNext.limb2 -
      boolM31 row.destinationNonzero *
        resultLimbField row row.quotient.limb2 row.remainder.limb2 = 0
  destination3 :
    bitVecM31 row.rdNext.limb3 -
      boolM31 row.destinationNonzero *
        resultLimbField row row.quotient.limb3 row.remainder.limb3 = 0
  sourceOne0 :
    activeField row *
      (bitVecM31 row.rs1Next.limb0 -
        bitVecM31 row.rs1Previous.limb0) = 0
  sourceOne1 :
    activeField row *
      (bitVecM31 row.rs1Next.limb1 -
        bitVecM31 row.rs1Previous.limb1) = 0
  sourceOne2 :
    activeField row *
      (bitVecM31 row.rs1Next.limb2 -
        bitVecM31 row.rs1Previous.limb2) = 0
  sourceOne3 :
    activeField row *
      (bitVecM31 row.rs1Next.limb3 -
        bitVecM31 row.rs1Previous.limb3) = 0

structure DirectEquationsH
    (row : Row)
    (witness : Witness row) : Prop where
  sourceTwo0 :
    activeField row *
      (bitVecM31 row.rs2Next.limb0 -
        bitVecM31 row.rs2Previous.limb0) = 0
  sourceTwo1 :
    activeField row *
      (bitVecM31 row.rs2Next.limb1 -
        bitVecM31 row.rs2Previous.limb1) = 0
  sourceTwo2 :
    activeField row *
      (bitVecM31 row.rs2Next.limb2 -
        bitVecM31 row.rs2Previous.limb2) = 0
  sourceTwo3 :
    activeField row *
      (bitVecM31 row.rs2Next.limb3 -
        bitVecM31 row.rs2Previous.limb3) = 0

structure DirectEquations
    (row : Row)
    (witness : Witness row) : Prop where
  a : DirectEquationsA row witness
  b : DirectEquationsB row witness
  c : DirectEquationsC row witness
  d : DirectEquationsD row witness
  e : DirectEquationsE row witness
  f : DirectEquationsF row witness
  g : DirectEquationsG row witness
  h : DirectEquationsH row witness

set_option maxRecDepth 30000 in
private theorem specialExclusiveEquation
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    (boolM31 row.zeroDivisor + boolM31 row.rZero) *
        (1 - (boolM31 row.zeroDivisor + boolM31 row.rZero)) = 0 := by
  have root :=
    baseConstraintRootZeroAt selector row witness direct
      ⟨15, by decide⟩
  change
    (boolM31 row.zeroDivisor + boolM31 row.rZero) *
        (1 - (boolM31 row.zeroDivisor + boolM31 row.rZero)) = 0 at root
  exact root

set_option maxRecDepth 30000 in
private theorem sourceOneLimb0Equation
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    activeField row *
        (bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0) = 0 := by
  have root :=
    baseConstraintRootZeroAt selector row witness direct
      ⟨70, by decide⟩
  change
    activeField row *
        (bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0) = 0 at root
  exact root

macro "division_root " selector:term ", " row:term ", " witness:term ", "
    direct:term ", " index:term : tactic =>
  `(tactic|
    exact
      (show
        (baseEvaluation $row $witness).nodes.getSymbolic
            constraintRoots[$index] = 0
        from
          baseConstraintRootZeroAt $selector $row $witness $direct
            ⟨$index, by decide⟩))

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsA
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsA row witness := by
  exact {
    specialExclusive := by
      division_root selector, row, witness, direct, 15
    zeroDivisor0 := by
      division_root selector, row, witness, direct, 18
    zeroDivisor1 := by
      division_root selector, row, witness, direct, 19
    zeroDivisor2 := by
      division_root selector, row, witness, direct, 20
    zeroDivisor3 := by
      division_root selector, row, witness, direct, 21
    zeroQuotient0 := by
      division_root selector, row, witness, direct, 22
    zeroQuotient1 := by
      division_root selector, row, witness, direct, 23
    zeroQuotient2 := by
      division_root selector, row, witness, direct, 24
  }

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsB
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsB row witness := by
  exact {
    zeroQuotient3 := by
      division_root selector, row, witness, direct, 25
    divisorInverse := by
      division_root selector, row, witness, direct, 26
    remainderZero0 := by
      division_root selector, row, witness, direct, 27
    remainderZero1 := by
      division_root selector, row, witness, direct, 28
    remainderZero2 := by
      division_root selector, row, witness, direct, 29
    remainderZero3 := by
      division_root selector, row, witness, direct, 30
    remainderInverse := by
      division_root selector, row, witness, direct, 31
    unsignedDividendSign := by
      division_root selector, row, witness, direct, 32
  }

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsC
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsC row witness := by
  exact {
    unsignedDivisorSign := by
      division_root selector, row, witness, direct, 33
    signXor := by
      division_root selector, row, witness, direct, 34
    quotientSignMatches := by
      division_root selector, row, witness, direct, 35
    quotientSignImplies := by
      division_root selector, row, witness, direct, 36
    zeroDivisorQuotientSign := by
      division_root selector, row, witness, direct, 37
    absSame0 := by
      division_root selector, row, witness, direct, 38
    negCarryBool0 := by
      division_root selector, row, witness, direct, 39
    negCarryZero0 := by
      division_root selector, row, witness, direct, 40
  }

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsD
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsD row witness := by
  exact {
    negCarryInverse0 := by
      division_root selector, row, witness, direct, 41
    absSame1 := by
      division_root selector, row, witness, direct, 42
    negCarryBool1 := by
      division_root selector, row, witness, direct, 43
    negCarryZero1 := by
      division_root selector, row, witness, direct, 44
    negCarryInverse1 := by
      division_root selector, row, witness, direct, 45
    absSame2 := by
      division_root selector, row, witness, direct, 46
    negCarryBool2 := by
      division_root selector, row, witness, direct, 47
    negCarryZero2 := by
      division_root selector, row, witness, direct, 48
  }

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsE
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsE row witness := by
  exact {
    negCarryInverse2 := by
      division_root selector, row, witness, direct, 49
    absSame3 := by
      division_root selector, row, witness, direct, 50
    negCarryBool3 := by
      division_root selector, row, witness, direct, 51
    negCarryZero3 := by
      division_root selector, row, witness, direct, 52
    negCarryInverse3 := by
      division_root selector, row, witness, direct, 53
    scanEqual3 := by
      division_root selector, row, witness, direct, 54
    scanMarker3 := by
      division_root selector, row, witness, direct, 55
    scanEqual2 := by
      division_root selector, row, witness, direct, 56
  }

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsF
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsF row witness := by
  exact {
    scanMarker2 := by
      division_root selector, row, witness, direct, 57
    scanEqual1 := by
      division_root selector, row, witness, direct, 58
    scanMarker1 := by
      division_root selector, row, witness, direct, 59
    scanEqual0 := by
      division_root selector, row, witness, direct, 60
    scanMarker0 := by
      division_root selector, row, witness, direct, 61
    scanTotal := by
      division_root selector, row, witness, direct, 62
    destinationZero := by
      division_root selector, row, witness, direct, 64
    destinationInverse := by
      division_root selector, row, witness, direct, 65
  }

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsG
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsG row witness := by
  exact {
    destination0 := by
      division_root selector, row, witness, direct, 66
    destination1 := by
      division_root selector, row, witness, direct, 67
    destination2 := by
      division_root selector, row, witness, direct, 68
    destination3 := by
      division_root selector, row, witness, direct, 69
    sourceOne0 := by
      division_root selector, row, witness, direct, 70
    sourceOne1 := by
      division_root selector, row, witness, direct, 71
    sourceOne2 := by
      division_root selector, row, witness, direct, 72
    sourceOne3 := by
      division_root selector, row, witness, direct, 73
  }

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquationsH
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsH row witness := by
  exact {
    sourceTwo0 := by
      division_root selector, row, witness, direct, 74
    sourceTwo1 := by
      division_root selector, row, witness, direct, 75
    sourceTwo2 := by
      division_root selector, row, witness, direct, 76
    sourceTwo3 := by
      division_root selector, row, witness, direct, 77
  }

private theorem directEquations
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquations row witness :=
  ⟨directEquationsA selector row witness direct,
    directEquationsB selector row witness direct,
    directEquationsC selector row witness direct,
    directEquationsD selector row witness direct,
    directEquationsE selector row witness direct,
    directEquationsF selector row witness direct,
    directEquationsG selector row witness direct,
    directEquationsH selector row witness direct⟩

private def selectorManifestId : Selector → Nat
  | .div => 41
  | .divu => 42
  | .rem => 43
  | .remu => 44

private theorem activeEquation
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    activeField row - 1 = 0 := by
  have root :=
    baseConstraintRootZeroAt selector row witness direct
      ⟨78, by decide⟩
  change activeField row - 1 = 0 at root
  exact root

private theorem actualOpcodeNode
    (selector : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selector row witness).nodes.getSymbolic 399 =
      opcodeField row := by
  have lookup :=
    (evaluatedEarlyTupleLookups selector row witness).1
  have selected :=
    congrArg
      (fun evaluated : EvaluatedLookup => evaluated.tuple[1]?)
      lookup
  change
    ((program selector).evalNodesSymbolic
        (columns row witness)).getSymbolic 399 =
      opcodeField row
  simpa [
    evaluatedSelectedLookup,
    difficultTupleRawLookup,
    expectedDifficultTupleLookup,
    programLookup,
  ] using selected

private theorem selectedProgramManifestId (selected : Selector) :
    (program selected).source.opcodeSelector.manifestId =
      selectorManifestId selected := by
  cases selected <;> rfl

private theorem selectedProgramOpcodeExpression
    (selected : Selector) :
    (program selected).source.opcodeSelector.expression = 399 := by
  cases selected <;> rfl

private theorem selectedEvaluationManifestId
    (selected : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selected row witness).manifestId =
      selectorManifestId selected := by
  simp only [evaluation, LocalProgram.evalSymbolic]
  rw [selectedProgramManifestId selected]

private theorem selectedEvaluationOpcodeSelector
    (selected : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selected row witness).opcodeSelector =
      (evaluation selected row witness).nodes.getSymbolic 399 := by
  simp only [evaluation, LocalProgram.evalSymbolic]
  rw [selectedProgramOpcodeExpression selected]

private theorem selectorManifestImage (selected : Selector) :
    M31.ofNat? (selectorManifestId selected) =
      some (M31.reduce (selectorManifestId selected)) := by
  cases selected <;> rfl

private theorem acceptedOpcodeNode
    (selected : Selector)
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation selected row witness).activeSelectorsAccepted = true) :
    (evaluation selected row witness).nodes.getSymbolic 399 =
      M31.reduce (selectorManifestId selected) := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have opcodeAccepted := selectorsAccepted.2
  rw [
    selectedEvaluationManifestId selected row witness,
  ] at opcodeAccepted
  rw [selectorManifestImage selected] at opcodeAccepted
  rw [
    selectedEvaluationOpcodeSelector selected row witness,
  ] at opcodeAccepted
  simpa only [beq_iff_eq] using opcodeAccepted

private theorem opcodeEquation
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (accepted :
      (evaluation selector row witness).activeSelectorsAccepted = true) :
    opcodeField row = M31.reduce (selectorManifestId selector) := by
  have acceptedNode :=
    acceptedOpcodeNode selector row witness accepted
  rw [actualOpcodeNode selector row witness] at acceptedNode
  exact acceptedNode

structure SelectorConsequences
    (selector : Selector)
    (row : Row) : Prop where
  activeOne : activeField row = 1
  selectorUnique :
    row.isDiv.toNat + row.isDivu.toNat +
      row.isRem.toNat + row.isRemu.toNat = 1
  selected :
    match selector with
    | .div =>
        row.isDiv = true ∧ row.isDivu = false ∧
          row.isRem = false ∧ row.isRemu = false
    | .divu =>
        row.isDiv = false ∧ row.isDivu = true ∧
          row.isRem = false ∧ row.isRemu = false
    | .rem =>
        row.isDiv = false ∧ row.isDivu = false ∧
          row.isRem = true ∧ row.isRemu = false
    | .remu =>
        row.isDiv = false ∧ row.isDivu = false ∧
          row.isRem = false ∧ row.isRemu = true

private theorem divSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .div row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .div row witness).constraintsHold = true) :
    SelectorConsequences .div row := by
  have activeEq := activeEquation .div row witness direct
  have opcodeEq := opcodeEquation .div row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu <;>
    simp_all [
      activeField,
      opcodeField,
      boolM31,
      selectorManifestId,
    ]

private theorem divuSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .divu row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .divu row witness).constraintsHold = true) :
    SelectorConsequences .divu row := by
  have activeEq := activeEquation .divu row witness direct
  have opcodeEq := opcodeEquation .divu row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu <;>
    simp_all [
      activeField,
      opcodeField,
      boolM31,
      selectorManifestId,
    ]

private theorem remSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .rem row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .rem row witness).constraintsHold = true) :
    SelectorConsequences .rem row := by
  have activeEq := activeEquation .rem row witness direct
  have opcodeEq := opcodeEquation .rem row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu <;>
    simp_all [
      activeField,
      opcodeField,
      boolM31,
      selectorManifestId,
    ]

private theorem remuSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .remu row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .remu row witness).constraintsHold = true) :
    SelectorConsequences .remu row := by
  have activeEq := activeEquation .remu row witness direct
  have opcodeEq := opcodeEquation .remu row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu <;>
    simp_all [
      activeField,
      opcodeField,
      boolM31,
      selectorManifestId,
    ]

theorem selectorConsequences
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation selector row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    SelectorConsequences selector row := by
  cases selector with
  | div => exact divSelectorConsequences row witness active direct
  | divu => exact divuSelectorConsequences row witness active direct
  | rem => exact remSelectorConsequences row witness active direct
  | remu => exact remuSelectorConsequences row witness active direct

private theorem byteBound (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byteEqOfFieldEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

private theorem byteEqZeroOfField
    (value : Byte)
    (equality : bitVecM31 value = 0) :
    value = 0 := by
  apply byteEqOfFieldEq
  simpa [bitVecM31] using equality

private theorem byteEq255OfField
    (value : Byte)
    (equality : bitVecM31 value = M31.reduce 255) :
    value = 255 := by
  apply byteEqOfFieldEq
  simpa [bitVecM31] using equality

private theorem gatedByteZero
    (flag : Bool)
    (value : Byte)
    (equation : boolM31 flag * bitVecM31 value = 0) :
    flag = true → value = 0 := by
  intro active
  rw [active] at equation
  simp only [boolM31, M31.one_mul] at equation
  exact byteEqZeroOfField value equation

private theorem gatedByte255
    (flag : Bool)
    (value : Byte)
    (equation :
      boolM31 flag *
        (bitVecM31 value - M31.reduce 255) = 0) :
    flag = true → value = 255 := by
  intro active
  rw [active] at equation
  simp only [boolM31, M31.one_mul] at equation
  exact
    byteEq255OfField value
      ((M31.sub_eq_zero_iff _ _).mp equation)

private theorem gatedBytesEqual
    (flag : Bool)
    (left right : Byte)
    (equation :
      (1 - boolM31 flag) *
        (bitVecM31 left - bitVecM31 right) = 0) :
    flag = false → left = right := by
  intro inactive
  rw [inactive] at equation
  simp only [
    boolM31,
    M31.sub_zero,
    M31.one_mul,
  ] at equation
  exact
    byteEqOfFieldEq left right
      ((M31.sub_eq_zero_iff _ _).mp equation)

private theorem destinationLimbOfEquation
    (destination division : Bool)
    (next quotient remainder : Byte)
    (equation :
      bitVecM31 next -
        boolM31 destination *
          (boolM31 division * bitVecM31 quotient +
            (1 - boolM31 division) * bitVecM31 remainder) = 0) :
    next =
      if destination then
        (if division then quotient else remainder)
      else 0 := by
  cases destination <;> cases division <;>
    simp only [
      boolM31,
      M31.zero_mul,
      M31.one_mul,
      M31.sub_zero,
      M31.zero_add,
      M31.sub_self,
      M31.mul_zero,
      M31.add_zero,
      Bool.false_eq_true,
      ↓reduceIte,
    ] at equation ⊢
  · exact byteEqZeroOfField next equation
  · exact byteEqZeroOfField next equation
  · exact
      byteEqOfFieldEq next remainder
        ((M31.sub_eq_zero_iff _ _).mp equation)
  · exact
      byteEqOfFieldEq next quotient
        ((M31.sub_eq_zero_iff _ _).mp equation)

private theorem sourceBytesOfEquations
    (next previous : WordBytes)
    (active : M31)
    (activeOne : active = 1)
    (limb0 :
      active * (bitVecM31 next.limb0 - bitVecM31 previous.limb0) = 0)
    (limb1 :
      active * (bitVecM31 next.limb1 - bitVecM31 previous.limb1) = 0)
    (limb2 :
      active * (bitVecM31 next.limb2 - bitVecM31 previous.limb2) = 0)
    (limb3 :
      active * (bitVecM31 next.limb3 - bitVecM31 previous.limb3) = 0) :
    next = previous := by
  rw [activeOne, M31.one_mul] at limb0 limb1 limb2 limb3
  apply WordBytes.eq_of_limbs <;> apply byteEqOfFieldEq
  · exact (M31.sub_eq_zero_iff _ _).mp limb0
  · exact (M31.sub_eq_zero_iff _ _).mp limb1
  · exact (M31.sub_eq_zero_iff _ _).mp limb2
  · exact (M31.sub_eq_zero_iff _ _).mp limb3

private theorem specialExclusiveOfEquation
    (row : Row)
    (equation :
      (boolM31 row.zeroDivisor + boolM31 row.rZero) *
          (1 - (boolM31 row.zeroDivisor + boolM31 row.rZero)) = 0) :
    row.zeroDivisor = true → row.rZero = false := by
  cases zero : row.zeroDivisor <;>
    cases remainder : row.rZero <;>
    simp_all [boolM31]

private theorem sourceOneLimb0OfAcceptance
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true)
    (selectors : SelectorConsequences selector row) :
    row.rs1Next.limb0 = row.rs1Previous.limb0 := by
  have equation :=
    sourceOneLimb0Equation selector row witness direct
  rw [selectors.activeOne, M31.one_mul] at equation
  exact
    byteEqOfFieldEq
      ((M31.sub_eq_zero_iff _ _).mp equation)

private theorem wordSumNat_lt (bytes : WordBytes) :
    wordSumNat bytes < M31.modulus := by
  have limb0 := bytes.limb0.isLt
  have limb1 := bytes.limb1.isLt
  have limb2 := bytes.limb2.isLt
  have limb3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at limb0 limb1 limb2 limb3
  rw [M31.modulus_eq]
  simp only [wordSumNat]
  omega

private theorem wordSumField_eq_reduce (bytes : WordBytes) :
    wordSumField bytes = M31.reduce (wordSumNat bytes) := by
  simp [
    wordSumField,
    wordSumNat,
    bitVecM31,
    Air.Bridge.TeamACommon.reduceAdd,
  ]

private theorem wordSumNat_pos
    (bytes : WordBytes)
    (nonzero : bytes.value ≠ 0) :
    0 < wordSumNat bytes := by
  have limb0 := bytes.limb0.isLt
  have limb1 := bytes.limb1.isLt
  have limb2 := bytes.limb2.isLt
  have limb3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at limb0 limb1 limb2 limb3
  simp only [WordBytes.value] at nonzero
  simp only [wordSumNat]
  omega

private theorem wordSumField_ne_zero
    (bytes : WordBytes)
    (nonzero : bytes.value ≠ 0) :
    wordSumField bytes ≠ 0 := by
  rw [wordSumField_eq_reduce]
  intro equality
  have values := congrArg M31.val equality
  rw [M31.reduce_val_of_lt _ (wordSumNat_lt bytes)] at values
  have positive := wordSumNat_pos bytes nonzero
  simp at values
  omega

private theorem wordSumField_eq_zero_of_value_eq_zero
    (bytes : WordBytes)
    (zero : bytes.value = 0) :
    wordSumField bytes = 0 := by
  rw [wordSumField_eq_reduce]
  have limb0 := bytes.limb0.isLt
  have limb1 := bytes.limb1.isLt
  have limb2 := bytes.limb2.isLt
  have limb3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at limb0 limb1 limb2 limb3
  simp only [WordBytes.value] at zero
  have sumZero : wordSumNat bytes = 0 := by
    simp only [wordSumNat]
    omega
  rw [sumZero]
  rfl

structure DirectConsequences (row : Row) : Prop where
  specialExclusive : row.zeroDivisor = true → row.rZero = false
  zeroDivisorLimb0 : row.zeroDivisor = true → row.rs2Next.limb0 = 0
  zeroDivisorLimb1 : row.zeroDivisor = true → row.rs2Next.limb1 = 0
  zeroDivisorLimb2 : row.zeroDivisor = true → row.rs2Next.limb2 = 0
  zeroDivisorLimb3 : row.zeroDivisor = true → row.rs2Next.limb3 = 0
  zeroDivisorQuotient0 : row.zeroDivisor = true → row.quotient.limb0 = 255
  zeroDivisorQuotient1 : row.zeroDivisor = true → row.quotient.limb1 = 255
  zeroDivisorQuotient2 : row.zeroDivisor = true → row.quotient.limb2 = 255
  zeroDivisorQuotient3 : row.zeroDivisor = true → row.quotient.limb3 = 255
  divisorNonzero : row.zeroDivisor = false → row.rs2Next.value ≠ 0
  remainderZeroLimb0 : row.rZero = true → row.remainder.limb0 = 0
  remainderZeroLimb1 : row.rZero = true → row.remainder.limb1 = 0
  remainderZeroLimb2 : row.rZero = true → row.remainder.limb2 = 0
  remainderZeroLimb3 : row.rZero = true → row.remainder.limb3 = 0
  remainderNonzero :
    row.zeroDivisor = false → row.rZero = false →
      row.remainder.value ≠ 0
  unsignedDividendSign : row.isSigned = false → row.bSign = false
  unsignedDivisorSign : row.isSigned = false → row.cSign = false
  signXorDefinition : row.signXor = (row.bSign != row.cSign)
  quotientSignMatches :
    row.zeroDivisor = false → row.quotient.value ≠ 0 →
      row.qSign = row.signXor
  quotientSignImpliesXor :
    row.zeroDivisor = false → row.qSign = true →
      row.signXor = true
  zeroDivisorQuotientSign :
    row.zeroDivisor = true → row.qSign = row.isSigned
  absSameLimb0 :
    row.signXor = false →
      row.remainderAbs.limb0 = row.remainder.limb0
  absSameLimb1 :
    row.signXor = false →
      row.remainderAbs.limb1 = row.remainder.limb1
  absSameLimb2 :
    row.signXor = false →
      row.remainderAbs.limb2 = row.remainder.limb2
  absSameLimb3 :
    row.signXor = false →
      row.remainderAbs.limb3 = row.remainder.limb3
  destinationFlag :
    row.destinationNonzero = decide (row.rd ≠ zeroRegister)
  destinationLimb0 :
    row.rdNext.limb0 =
      if row.destinationNonzero then (divResultBytes row).limb0 else 0
  destinationLimb1 :
    row.rdNext.limb1 =
      if row.destinationNonzero then (divResultBytes row).limb1 else 0
  destinationLimb2 :
    row.rdNext.limb2 =
      if row.destinationNonzero then (divResultBytes row).limb2 else 0
  destinationLimb3 :
    row.rdNext.limb3 =
      if row.destinationNonzero then (divResultBytes row).limb3 else 0
  sourceOne : row.rs1Next = row.rs1Previous
  sourceTwo : row.rs2Next = row.rs2Previous

set_option maxRecDepth 30000 in
private theorem directConsequences
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (selectors : SelectorConsequences selector row)
    (equations : DirectEquations row witness) :
    DirectConsequences row := by
  have signedImage :
      signedField row = boolM31 row.isSigned := by
    cases selector <;>
      simp_all [
        signedField,
        DivRow.isSigned,
        boolM31,
      ]
  have divisionImage :
      divisionField row = boolM31 row.isDivision := by
    cases selector <;>
      simp_all [
        divisionField,
        DivRow.isDivision,
        boolM31,
      ]
  have special :=
    specialExclusiveOfEquation row (by
      simpa [specialField] using equations.a.specialExclusive)
  refine {
    specialExclusive := special
    zeroDivisorLimb0 :=
        gatedByteZero row.zeroDivisor row.rs2Next.limb0
        equations.a.zeroDivisor0
    zeroDivisorLimb1 :=
        gatedByteZero row.zeroDivisor row.rs2Next.limb1
        equations.a.zeroDivisor1
    zeroDivisorLimb2 :=
        gatedByteZero row.zeroDivisor row.rs2Next.limb2
        equations.a.zeroDivisor2
    zeroDivisorLimb3 :=
        gatedByteZero row.zeroDivisor row.rs2Next.limb3
        equations.a.zeroDivisor3
    zeroDivisorQuotient0 :=
        gatedByte255 row.zeroDivisor row.quotient.limb0
        equations.a.zeroQuotient0
    zeroDivisorQuotient1 :=
        gatedByte255 row.zeroDivisor row.quotient.limb1
        equations.a.zeroQuotient1
    zeroDivisorQuotient2 :=
        gatedByte255 row.zeroDivisor row.quotient.limb2
        equations.a.zeroQuotient2
    zeroDivisorQuotient3 :=
        gatedByte255 row.zeroDivisor row.quotient.limb3
        equations.b.zeroQuotient3
    divisorNonzero := ?_
    remainderZeroLimb0 :=
      gatedByteZero row.rZero row.remainder.limb0
        equations.b.remainderZero0
    remainderZeroLimb1 :=
      gatedByteZero row.rZero row.remainder.limb1
        equations.b.remainderZero1
    remainderZeroLimb2 :=
      gatedByteZero row.rZero row.remainder.limb2
        equations.b.remainderZero2
    remainderZeroLimb3 :=
      gatedByteZero row.rZero row.remainder.limb3
        equations.b.remainderZero3
    remainderNonzero := ?_
    unsignedDividendSign := ?_
    unsignedDivisorSign := ?_
    signXorDefinition := ?_
    quotientSignMatches := ?_
    quotientSignImpliesXor := ?_
    zeroDivisorQuotientSign := ?_
    absSameLimb0 :=
      gatedBytesEqual row.signXor
        row.remainderAbs.limb0 row.remainder.limb0
        equations.c.absSame0
    absSameLimb1 :=
      gatedBytesEqual row.signXor
        row.remainderAbs.limb1 row.remainder.limb1
        equations.d.absSame1
    absSameLimb2 :=
      gatedBytesEqual row.signXor
        row.remainderAbs.limb2 row.remainder.limb2
        equations.d.absSame2
    absSameLimb3 :=
      gatedBytesEqual row.signXor
        row.remainderAbs.limb3 row.remainder.limb3
        equations.e.absSame3
    destinationFlag :=
      Air.Bridge.TeamACommon.destinationFlag_of_equations
        row.rd row.destinationNonzero witness.destinationInverse
        (by simpa [
          bitVecM31,
          boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using equations.f.destinationZero)
        (by simpa [
          bitVecM31,
          boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using equations.f.destinationInverse)
    destinationLimb0 := ?_
    destinationLimb1 := ?_
    destinationLimb2 := ?_
    destinationLimb3 := ?_
    sourceOne :=
      sourceBytesOfEquations
        row.rs1Next row.rs1Previous (activeField row)
        selectors.activeOne
        equations.g.sourceOne0 equations.g.sourceOne1
        equations.g.sourceOne2 equations.g.sourceOne3
    sourceTwo :=
      sourceBytesOfEquations
        row.rs2Next row.rs2Previous (activeField row)
        selectors.activeOne
        equations.h.sourceTwo0 equations.h.sourceTwo1
        equations.h.sourceTwo2 equations.h.sourceTwo3
  }
  · intro zeroDivisor valueZero
    have inverseEquation := equations.b.divisorInverse
    rw [selectors.activeOne, zeroDivisor] at inverseEquation
    simp only [
      boolM31,
      M31.sub_zero,
      M31.one_mul,
    ] at inverseEquation
    have productOne :
        divisorSumField row * witness.divisorSumInverse = 1 :=
      (M31.sub_eq_zero_iff _ _).mp inverseEquation
    have sumZero :
        divisorSumField row = 0 := by
      exact
        wordSumField_eq_zero_of_value_eq_zero
          row.rs2Next valueZero
    rw [sumZero, M31.zero_mul] at productOne
    exact (by decide : (0 : M31) ≠ 1) productOne
  · intro zeroDivisor remainderZero valueZero
    have inverseEquation := equations.b.remainderInverse
    rw [selectors.activeOne, zeroDivisor, remainderZero] at inverseEquation
    simp only [
      specialField,
      boolM31,
      M31.zero_add,
      M31.sub_zero,
      M31.one_mul,
    ] at inverseEquation
    have productOne :
        remainderSumField row * witness.remainderSumInverse = 1 :=
      (M31.sub_eq_zero_iff _ _).mp inverseEquation
    have sumZero :
        remainderSumField row = 0 := by
      exact
        wordSumField_eq_zero_of_value_eq_zero
          row.remainder valueZero
    rw [sumZero, M31.zero_mul] at productOne
    exact (by decide : (0 : M31) ≠ 1) productOne
  · intro unsigned
    have equation := equations.b.unsignedDividendSign
    rw [signedImage, unsigned] at equation
    cases sign : row.bSign <;>
      simp_all [boolM31]
  · intro unsigned
    have equation := equations.c.unsignedDivisorSign
    rw [signedImage, unsigned] at equation
    cases sign : row.cSign <;>
      simp_all [boolM31]
  · have equation := equations.c.signXor
    rw [selectors.activeOne, M31.one_mul] at equation
    cases dividendSign : row.bSign <;>
      cases divisorSign : row.cSign <;>
      cases xorSign : row.signXor <;>
      simp_all [boolM31]
  · intro zeroDivisor quotientNonzero
    have sumNonzero :
        quotientSumField row ≠ 0 := by
      exact wordSumField_ne_zero row.quotient quotientNonzero
    have equation := equations.c.quotientSignMatches
    rw [zeroDivisor] at equation
    cases quotientSign : row.qSign <;>
      cases xorSign : row.signXor <;>
      simp_all [boolM31, quotientSumField]
  · intro zeroDivisor quotientSign
    have equation := equations.c.quotientSignImplies
    rw [zeroDivisor, quotientSign] at equation
    cases xorSign : row.signXor <;>
      simp_all [boolM31]
  · intro zeroDivisor
    have equation := equations.c.zeroDivisorQuotientSign
    rw [zeroDivisor, signedImage] at equation
    cases quotientSign : row.qSign <;>
      cases signed : row.isSigned <;>
      simp_all [boolM31]
  · have equation := equations.g.destination0
    rw [divisionImage] at equation
    simpa [divResultBytes] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb0 row.quotient.limb0 row.remainder.limb0
        equation
  · have equation := equations.g.destination1
    rw [divisionImage] at equation
    simpa [divResultBytes] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb1 row.quotient.limb1 row.remainder.limb1
        equation
  · have equation := equations.g.destination2
    rw [divisionImage] at equation
    simpa [divResultBytes] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb2 row.quotient.limb2 row.remainder.limb2
        equation
  · have equation := equations.g.destination3
    rw [divisionImage] at equation
    simpa [divResultBytes] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb3 row.quotient.limb3 row.remainder.limb3
        equation

private theorem range20BoundOfLookup
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (ordinal accessOrdinal previous : Nat)
    (activeOne : activeField row = 1)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true)
    (selected :
      (evaluation selector row witness).lookup? ordinal =
        some (clockLookup row accessOrdinal ordinal previous)) :
    (clockGapField row accessOrdinal previous).val < 2 ^ 20 := by
  let production := evaluation selector row witness
  change production.fixedLookupsHold = true at fixed
  change
    production.lookup? ordinal =
      some (clockLookup row accessOrdinal ordinal previous) at selected
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      production ordinal
      (clockLookup row accessOrdinal ordinal previous) fixed selected
  have canonicalRequest :
      (EvaluatedLookup.fixedRequestHolds {
        ordinal
        domain := .rangeCheck20
        numerator := -(1 : M31)
        tuple := #[clockGapField row accessOrdinal previous]
        role := .request
        tableId := some .rangeCheck20
        accessOrdinal := some accessOrdinal
      }) = true := by
    simpa [clockLookup, activeOne] using request
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      ordinal (some accessOrdinal)
      (clockGapField row accessOrdinal previous)).mp canonicalRequest

private theorem range811BoundsOfLookup
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (result : Byte)
    (carry : M31)
    (activeOne : activeField row = 1)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true)
    (selected :
      (evaluation selector row witness).lookup? ordinal =
        some (carryLookup row ordinal result carry)) :
    (bitVecM31 result).val < 2 ^ 8 ∧ carry.val < 2 ^ 11 := by
  let production := evaluation selector row witness
  change production.fixedLookupsHold = true at fixed
  change
    production.lookup? ordinal =
      some (carryLookup row ordinal result carry) at selected
  have request :
      (carryLookup row ordinal result carry).fixedRequestHolds = true :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      production ordinal
      (carryLookup row ordinal result carry) fixed selected
  have negOneNeZero : -(1 : M31) ≠ 0 := by decide
  simpa [
    carryLookup,
    activeOne,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    FixedTableId.rangeCheck811_contains_iff,
    negOneNeZero,
  ] using request

private theorem signRangeBoundsOfLookup
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (activeOne : activeField row = 1)
    (signedOne : signedField row = 1)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true)
    (selected :
      (evaluation selector row witness).lookup? 99 =
        some (signRangeLookup row)) :
    ((bitVecM31 row.rs1Next.limb3 -
          boolM31 row.bSign * M31.reduce 128) *
        M31.reduce 2).val < 2 ^ 8 ∧
      ((bitVecM31 row.rs2Next.limb3 -
            boolM31 row.cSign * M31.reduce 128) *
          M31.reduce 2).val < 2 ^ 8 := by
  let production := evaluation selector row witness
  change production.fixedLookupsHold = true at fixed
  change production.lookup? 99 = some (signRangeLookup row) at selected
  have request :
      (signRangeLookup row).fixedRequestHolds = true :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      production 99 (signRangeLookup row) fixed selected
  have live : (signRangeLookup row).isLive = true := by
    have negOneNeZero : -(1 : M31) ≠ 0 := by decide
    simp [
      signRangeLookup,
      EvaluatedLookup.isLive,
      activeOne,
      negOneNeZero,
    ]
  rw [EvaluatedLookup.fixedRequestHolds, live] at request
  change
    FixedTableId.rangeCheck88.contains #[
      signedField row *
          (bitVecM31 row.rs1Next.limb3 -
            boolM31 row.bSign * M31.reduce 128) *
        M31.reduce 2,
      signedField row *
          (bitVecM31 row.rs2Next.limb3 -
            boolM31 row.cSign * M31.reduce 128) *
        M31.reduce 2
    ] = true at request
  rw [signedOne, M31.one_mul, M31.one_mul] at request
  exact
    (FixedTableId.rangeCheck88_contains_iff _ _).mp request

private theorem quotientSignBoundOfLookup
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (requestActive : quotientSignActiveField row = 1)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true)
    (selected :
      (evaluation selector row witness).lookup? 98 =
        some (quotientSignLookup row)) :
    (bitVecM31 row.quotient.limb3 -
        boolM31 row.qSign * M31.reduce 128).val < 2 ^ 7 := by
  let production := evaluation selector row witness
  change production.fixedLookupsHold = true at fixed
  change production.lookup? 98 = some (quotientSignLookup row) at selected
  have request :
      (quotientSignLookup row).fixedRequestHolds = true :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      production 98 (quotientSignLookup row) fixed selected
  have live : (quotientSignLookup row).isLive = true := by
    have negOneNeZero : -(1 : M31) ≠ 0 := by decide
    simp [
      quotientSignLookup,
      EvaluatedLookup.isLive,
      requestActive,
      negOneNeZero,
    ]
  rw [EvaluatedLookup.fixedRequestHolds, live] at request
  change
    FixedTableId.rangeCheckM31.contains #[
      0,
      bitVecM31 row.quotient.limb3 -
        boolM31 row.qSign * M31.reduce 128
    ] = true at request
  exact
    ((FixedTableId.rangeCheckM31_contains_iff _ _).mp request).2.1

private theorem positiveDiffBoundOfLookup
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (requestActive : activeField row - specialField row = 1)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true)
    (selected :
      (evaluation selector row witness).lookup? 100 =
        some (positiveDiffLookup row)) :
    (M31.reduce row.ltDiff - M31.reduce 1).val < 2 ^ 20 := by
  let production := evaluation selector row witness
  change production.fixedLookupsHold = true at fixed
  change production.lookup? 100 = some (positiveDiffLookup row) at selected
  have request :
      (positiveDiffLookup row).fixedRequestHolds = true :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      production 100 (positiveDiffLookup row) fixed selected
  have canonicalRequest :
      (EvaluatedLookup.fixedRequestHolds {
        ordinal := 100
        domain := .rangeCheck20
        numerator := -(1 : M31)
        tuple := #[M31.reduce row.ltDiff - M31.reduce 1]
        role := .request
        tableId := some .rangeCheck20
        accessOrdinal := none
      }) = true := by
    simpa [
      positiveDiffLookup,
      specialField,
      requestActive,
    ] using request
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      100 none (M31.reduce row.ltDiff - M31.reduce 1)).mp
      canonicalRequest

structure FixedConsequences
    (selector : Selector)
    (row : Row) : Prop where
  sourceOneGap :
    (clockGapField row 1 row.rs1PreviousClock).val < 2 ^ 20
  sourceTwoGap :
    (clockGapField row 2 row.rs2PreviousClock).val < 2 ^ 20
  destinationGap :
    (clockGapField row 3 row.rdPreviousClock).val < 2 ^ 20
  carry0Bound : (carry0Field row).val < 2 ^ 11
  carry1Bound : (carry1Field row).val < 2 ^ 11
  carry2Bound : (carry2Field row).val < 2 ^ 11
  carry3Bound : (carry3Field row).val < 2 ^ 11
  carry4Bound : (carry4Field row).val < 2 ^ 11
  carry5Bound : (carry5Field row).val < 2 ^ 11
  carry6Bound : (carry6Field row).val < 2 ^ 11
  carry7Bound : (carry7Field row).val < 2 ^ 11
  operandSignBounds :
    signedField row = 1 →
      ((bitVecM31 row.rs1Next.limb3 -
            boolM31 row.bSign * M31.reduce 128) *
          M31.reduce 2).val < 2 ^ 8 ∧
        ((bitVecM31 row.rs2Next.limb3 -
              boolM31 row.cSign * M31.reduce 128) *
            M31.reduce 2).val < 2 ^ 8
  quotientSignBound :
    quotientSignActiveField row = 1 →
      (bitVecM31 row.quotient.limb3 -
          boolM31 row.qSign * M31.reduce 128).val < 2 ^ 7
  positiveDiffBound :
    activeField row - specialField row = 1 →
      (M31.reduce row.ltDiff - M31.reduce 1).val < 2 ^ 20

theorem fixedConsequences
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (selectors : SelectorConsequences selector row)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true) :
    FixedConsequences selector row := by
  have projection := exactFixedProjection selector row witness
  exact {
    sourceOneGap :=
      range20BoundOfLookup selector row witness 84 1
        row.rs1PreviousClock selectors.activeOne fixed
        projection.sourceOneClock
    sourceTwoGap :=
      range20BoundOfLookup selector row witness 87 2
        row.rs2PreviousClock selectors.activeOne fixed
        projection.sourceTwoClock
    destinationGap :=
      range20BoundOfLookup selector row witness 103 3
        row.rdPreviousClock selectors.activeOne fixed
        projection.destinationClock
    carry0Bound :=
      (range811BoundsOfLookup selector row witness 90
        row.quotient.limb0 (carry0Field row)
        selectors.activeOne fixed projection.carry0).2
    carry1Bound :=
      (range811BoundsOfLookup selector row witness 91
        row.quotient.limb1 (carry1Field row)
        selectors.activeOne fixed projection.carry1).2
    carry2Bound :=
      (range811BoundsOfLookup selector row witness 92
        row.quotient.limb2 (carry2Field row)
        selectors.activeOne fixed projection.carry2).2
    carry3Bound :=
      (range811BoundsOfLookup selector row witness 93
        row.quotient.limb3 (carry3Field row)
        selectors.activeOne fixed projection.carry3).2
    carry4Bound :=
      (range811BoundsOfLookup selector row witness 94
        row.remainder.limb0 (carry4Field row)
        selectors.activeOne fixed projection.carry4).2
    carry5Bound :=
      (range811BoundsOfLookup selector row witness 95
        row.remainder.limb1 (carry5Field row)
        selectors.activeOne fixed projection.carry5).2
    carry6Bound :=
      (range811BoundsOfLookup selector row witness 96
        row.remainder.limb2 (carry6Field row)
        selectors.activeOne fixed projection.carry6).2
    carry7Bound :=
      (range811BoundsOfLookup selector row witness 97
        row.remainder.limb3 (carry7Field row)
        selectors.activeOne fixed projection.carry7).2
    operandSignBounds := by
      intro signedOne
      exact
        signRangeBoundsOfLookup selector row witness
          selectors.activeOne signedOne fixed projection.operandSigns
    quotientSignBound := by
      intro requestActive
      exact
        quotientSignBoundOfLookup selector row witness
          requestActive fixed projection.quotientSign
    positiveDiffBound := by
      intro requestActive
      exact
        positiveDiffBoundOfLookup selector row witness
          requestActive fixed projection.positiveDiff
  }

private theorem signBitOfBound
    (top : Byte)
    (sign : Bool)
    (bound :
      (bitVecM31 top -
        boolM31 sign * M31.reduce 128).val < 2 ^ 7) :
    sign = decide (128 ≤ top.toNat) := by
  have topImage :
      (bitVecM31 top).val = top.toNat :=
    M31.reduce_val_of_lt top.toNat (byteBound top)
  have constantImage : (M31.reduce 128).val = 128 := by decide
  cases sign with
  | false =>
      simp only [boolM31, M31.zero_mul, M31.sub_zero] at bound
      rw [topImage] at bound
      simp [show ¬ 128 ≤ top.toNat by omega]
  | true =>
      simp only [boolM31, M31.one_mul] at bound
      by_cases high : 128 ≤ top.toNat
      · simp [high]
      · have low : top.toNat < 128 := by omega
        have wrapped :=
          M31.sub_val_of_lt
            (bitVecM31 top) (M31.reduce 128)
            (by rw [topImage, constantImage]; exact low)
        rw [topImage, constantImage, M31.modulus_eq] at wrapped
        rw [wrapped] at bound
        omega

private theorem signBitOfDoubledBound
    (top : Byte)
    (sign : Bool)
    (bound :
      ((bitVecM31 top -
          boolM31 sign * M31.reduce 128) *
        M31.reduce 2).val < 2 ^ 8) :
    sign = decide (128 ≤ top.toNat) := by
  have topImage :
      (bitVecM31 top).val = top.toNat :=
    M31.reduce_val_of_lt top.toNat (byteBound top)
  have constantImage : (M31.reduce 128).val = 128 := by decide
  have twoImage : (M31.reduce 2).val = 2 := by decide
  cases sign with
  | false =>
      simp only [boolM31, M31.zero_mul, M31.sub_zero] at bound
      have productBound :
          (bitVecM31 top).val * (M31.reduce 2).val <
            M31.modulus := by
        rw [topImage, twoImage, M31.modulus_eq]
        have topBound := top.isLt
        simp only [Nat.reducePow] at topBound
        omega
      rw [
        M31.mul_val_of_lt _ _ productBound,
        topImage,
        twoImage,
      ] at bound
      simp [show ¬ 128 ≤ top.toNat by omega]
  | true =>
      simp only [boolM31, M31.one_mul] at bound
      by_cases high : 128 ≤ top.toNat
      · simp [high]
      · have low : top.toNat < 128 := by omega
        have difference :=
          M31.sub_val_of_lt
            (bitVecM31 top) (M31.reduce 128)
            (by rw [topImage, constantImage]; exact low)
        rw [topImage, constantImage] at difference
        change
          (((bitVecM31 top - M31.reduce 128).val *
              (M31.reduce 2).val) % M31.modulus) < 2 ^ 8
            at bound
        rw [difference, twoImage]
        have productShape :
            (M31.modulus + top.toNat - 128) * 2 =
              M31.modulus +
                (M31.modulus + 2 * top.toNat - 256) := by
          rw [M31.modulus_eq]
          omega
        rw [productShape, Nat.add_mod_left]
        have remainderBound :
            M31.modulus + 2 * top.toNat - 256 < M31.modulus := by
          rw [M31.modulus_eq]
          omega
        rw [Nat.mod_eq_of_lt remainderBound] at bound
        rw [M31.modulus_eq] at bound
        omega

private theorem canonicalPositiveDiffBounds
    (value : Nat)
    (bound :
      (M31.reduce value - M31.reduce 1).val < 2 ^ 20) :
    1 ≤ (M31.reduce value).val ∧
      (M31.reduce value).val ≤ 2 ^ 20 := by
  have oneImage : (M31.reduce 1).val = 1 := by decide
  by_cases zero : (M31.reduce value).val = 0
  · have wrapped :=
      M31.sub_val_of_lt
        (M31.reduce value) (M31.reduce 1)
        (by rw [zero, oneImage]; omega)
    rw [zero, oneImage, M31.modulus_eq] at wrapped
    rw [wrapped] at bound
    omega
  · have positive : 1 ≤ (M31.reduce value).val := by omega
    have difference :=
      M31.sub_val_of_le
        (M31.reduce value) (M31.reduce 1)
        (by rw [oneImage]; exact positive)
    rw [oneImage] at difference
    rw [difference] at bound
    omega

structure FixedSemanticConsequences
    (row : Row) : Prop where
  productCarry0 : (carry0Field row).val < 2 ^ 11
  productCarry1 : (carry1Field row).val < 2 ^ 11
  productCarry2 : (carry2Field row).val < 2 ^ 11
  productCarry3 : (carry3Field row).val < 2 ^ 11
  productCarry4 : (carry4Field row).val < 2 ^ 11
  productCarry5 : (carry5Field row).val < 2 ^ 11
  productCarry6 : (carry6Field row).val < 2 ^ 11
  productCarry7 : (carry7Field row).val < 2 ^ 11
  dividendSignBit :
    row.isSigned = true →
      row.bSign = decide (128 ≤ row.rs1Next.limb3.toNat)
  divisorSignBit :
    row.isSigned = true →
      row.cSign = decide (128 ≤ row.rs2Next.limb3.toNat)
  quotientSignBit :
    row.isSigned = true →
      row.zeroDivisor = false →
      ¬(row.bSign = true ∧ row.cSign = true) →
      row.qSign = decide (128 ≤ row.quotient.limb3.toNat)
  ltDiffLower :
    row.zeroDivisor = false → row.rZero = false →
      1 ≤ (M31.reduce row.ltDiff).val
  ltDiffUpper :
    row.zeroDivisor = false → row.rZero = false →
      (M31.reduce row.ltDiff).val ≤ 1048576
  sourceOneClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  sourceTwoClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)

private theorem fixedSemanticConsequences
    (selector : Selector)
    (row : Row)
    (admission : Admission row)
    (selectors : SelectorConsequences selector row)
    (fixed : FixedConsequences selector row) :
    FixedSemanticConsequences row := by
  have signedImage :
      signedField row = boolM31 row.isSigned := by
    cases selector <;>
      simp_all [
        signedField,
        DivRow.isSigned,
        boolM31,
      ]
  exact {
    productCarry0 := fixed.carry0Bound
    productCarry1 := fixed.carry1Bound
    productCarry2 := fixed.carry2Bound
    productCarry3 := fixed.carry3Bound
    productCarry4 := fixed.carry4Bound
    productCarry5 := fixed.carry5Bound
    productCarry6 := fixed.carry6Bound
    productCarry7 := fixed.carry7Bound
    dividendSignBit := by
      intro signed
      apply signBitOfDoubledBound
      apply fixed.operandSignBounds
      rw [signedImage, signed]
      rfl
    divisorSignBit := by
      intro signed
      apply signBitOfDoubledBound
      apply fixed.operandSignBounds
      rw [signedImage, signed]
      rfl
    quotientSignBit := by
      intro signed zeroDivisor notBoth
      apply signBitOfBound
      apply fixed.quotientSignBound
      rw [
        quotientSignActiveField,
        signedImage,
        signed,
        zeroDivisor,
      ]
      cases dividendSign : row.bSign <;>
        cases divisorSign : row.cSign <;>
        simp_all [boolM31, selectors.activeOne]
    ltDiffLower := by
      intro zeroDivisor remainderZero
      exact
        (canonicalPositiveDiffBounds row.ltDiff
          (fixed.positiveDiffBound (by
            rw [
              selectors.activeOne,
              specialField,
              zeroDivisor,
              remainderZero,
            ]
            rfl))).1
    ltDiffUpper := by
      intro zeroDivisor remainderZero
      exact
        (canonicalPositiveDiffBounds row.ltDiff
          (fixed.positiveDiffBound (by
            rw [
              selectors.activeOne,
              specialField,
              zeroDivisor,
              remainderZero,
            ]
            rfl))).2
    sourceOneClock :=
      MulhDiv.validPreviousClockOfGap
        row.clock 1 row.rs1PreviousClock
        admission.clockPositive admission.clockBound
        (by omega) (by omega)
        admission.sourceOnePreviousBound
        (by simpa [
          clockGapField,
          accessClockField,
          Air.Bridge.TeamACommon.clockGapField,
          Air.Bridge.TeamACommon.accessClockField,
        ] using fixed.sourceOneGap)
    sourceTwoClock :=
      MulhDiv.validPreviousClockOfGap
        row.clock 2 row.rs2PreviousClock
        admission.clockPositive admission.clockBound
        (by omega) (by omega)
        admission.sourceTwoPreviousBound
        (by simpa [
          clockGapField,
          accessClockField,
          Air.Bridge.TeamACommon.clockGapField,
          Air.Bridge.TeamACommon.accessClockField,
        ] using fixed.sourceTwoGap)
    destinationClock :=
      MulhDiv.validPreviousClockOfGap
        row.clock 3 row.rdPreviousClock
        admission.clockPositive admission.clockBound
        (by omega) (by omega)
        admission.destinationPreviousBound
        (by simpa [
          clockGapField,
          accessClockField,
          Air.Bridge.TeamACommon.clockGapField,
          Air.Bridge.TeamACommon.accessClockField,
        ] using fixed.destinationGap)
  }

private theorem byteLt256 (value : Byte) :
    value.toNat < 256 := by
  simpa only [Nat.reducePow] using value.isLt

private theorem boolM31_eq_reduce (value : Bool) :
    boolM31 value = M31.reduce value.toNat := by
  cases value <;> rfl

private theorem m31MulComm (left right : M31) :
    left * right = right * left := by
  apply M31.ext
  change
    (left.val * right.val) % M31.modulus =
      (right.val * left.val) % M31.modulus
  rw [Nat.mul_comm]

private theorem m31ScaleProduct
    (left right scale : M31) :
    ((left * right) * scale) * scale =
      (left * scale) * (right * scale) := by
  calc
    ((left * right) * scale) * scale =
        (left * (right * scale)) * scale := by
          rw [MulhDiv.m31MulAssoc]
    _ = left * ((right * scale) * scale) := by
          rw [MulhDiv.m31MulAssoc]
    _ = left * (scale * (right * scale)) := by
          rw [m31MulComm (right * scale) scale]
    _ = (left * scale) * (right * scale) := by
          rw [MulhDiv.m31MulAssoc]

private theorem m31ScaleRight
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

private theorem m31ReduceSubOfLe
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

private theorem m31SubOneScaled256
    (value : M31) :
    (value - 1) * M31.reduce 256 =
      value * M31.reduce 256 - M31.reduce 256 := by
  by_cases zero : value = 0
  · subst value
    decide
  · have positive : 1 ≤ value.val := by
      by_contra notPositive
      have valueZero : value.val = 0 := by omega
      apply zero
      exact M31.ext valueZero
    rw [← M31.reduce_toNat value]
    rw [
      m31ReduceSubOfLe value.val 1 positive,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceMul,
      m31ReduceSubOfLe (value.val * 256) 256 (by omega),
    ]
    congr 1
    omega

private theorem reducedProductZero
    (left right : Nat)
    (bound : left * right < M31.modulus)
    (equation :
      M31.reduce left * M31.reduce right = 0) :
    left = 0 ∨ right = 0 := by
  rw [Air.Bridge.TeamACommon.reduceMul] at equation
  exact
    Nat.mul_eq_zero.mp
      ((M31.reduce_eq_zero_of_lt bound).mp equation)

private theorem productLtModulusOfLt512
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

private theorem m31ReduceSubOfLt
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

/--
The carry residual is evaluated in `M31`, but after multiplying both factors
by `256` it is a product of integer differences in `[-256, 511]`.  Its absolute
product is below the field modulus, so a zero field product is an actual
integer root; no finite enumeration or field primality argument is needed.
-/
private theorem boundedNegCarryRoot
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

private theorem negCarryStep
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
  rw [
    m31ScaleProduct,
    M31.zero_mul,
  ] at scaled
  have integerRoot :
      (M31.reduce accumulated -
          M31.reduce (256 * previous.toNat)) *
        (M31.reduce accumulated - M31.reduce 256) = 0 := by
    cases previous with
    | false =>
        simpa [boolM31, carryScaled] using scaled
    | true =>
        rw [
          m31SubOneScaled256,
          m31SubOneScaled256,
          carryScaled,
        ] at scaled
        simpa using scaled
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

private theorem negCarryZeroAbsolute
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

private theorem negationRecurrenceOfEquations
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
  have carryDefinition0 :
      negCarry0Field row =
        (boolM31 false +
            bitVecM31 row.remainder.limb0 +
            bitVecM31 row.remainderAbs.limb0) *
          M31.reduce 8388608 := by
    simp [negCarry0Field, boolM31]
  rcases
      negCarryStep false
        row.remainder.limb0 row.remainderAbs.limb0
        (negCarry0Field row) carryDefinition0 root0 with
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

private theorem divHighBound (value : Bool) :
    255 * value.toNat ≤ 255 := by
  cases value <;> simp

private theorem remainderHighBound (row : Row) :
    divRemainderHigh row ≤ 255 := by
  cases row.bSign <;> cases row.rZero <;>
    simp [divRemainderHigh]

private theorem productLe65025
    (left right : Nat)
    (leftBound : left ≤ 255)
    (rightBound : right ≤ 255) :
    left * right ≤ 65025 := by
  simpa using Nat.mul_le_mul leftBound rightBound

private theorem byteLe255 (value : Byte) :
    value.toNat ≤ 255 := by
  have bound := byteLt256 value
  omega

private theorem eightProductsAndRemainderLt600000
    (product0 product1 product2 product3 product4 product5 product6
      product7 remainder : Nat)
    (product0Bound : product0 ≤ 65025)
    (product1Bound : product1 ≤ 65025)
    (product2Bound : product2 ≤ 65025)
    (product3Bound : product3 ≤ 65025)
    (product4Bound : product4 ≤ 65025)
    (product5Bound : product5 ≤ 65025)
    (product6Bound : product6 ≤ 65025)
    (product7Bound : product7 ≤ 65025)
    (remainderBound : remainder ≤ 255) :
    product0 + product1 + product2 + product3 + product4 + product5 +
        product6 + product7 + remainder <
      600000 := by
  omega

private theorem quotientHighField_eq_reduce (row : Row) :
    quotientHighField row = M31.reduce (divQuotientHigh row) := by
  cases row.qSign <;>
    simp [
      quotientHighField,
      divQuotientHigh,
      boolM31,
      Air.Bridge.TeamACommon.reduceMul,
      Nat.mul_comm,
    ]

private theorem divisorHighField_eq_reduce (row : Row) :
    divisorHighField row = M31.reduce (divDivisorHigh row) := by
  cases row.cSign <;>
    simp [
      divisorHighField,
      divDivisorHigh,
      boolM31,
      Air.Bridge.TeamACommon.reduceMul,
      Nat.mul_comm,
    ]

private theorem dividendHighField_eq_reduce (row : Row) :
    dividendHighField row = M31.reduce (divDividendHigh row) := by
  cases row.bSign <;>
    simp [
      dividendHighField,
      divDividendHigh,
      boolM31,
      Air.Bridge.TeamACommon.reduceMul,
      Nat.mul_comm,
    ]

private theorem remainderHighField_eq_reduce (row : Row) :
    remainderHighField row = M31.reduce (divRemainderHigh row) := by
  cases row.bSign <;> cases row.rZero <;>
    simp [
      remainderHighField,
      divRemainderHigh,
      boolM31,
      Air.Bridge.TeamACommon.reduceMul,
    ]

private theorem divConvBounds (row : Row) :
    divConv0 row < 600000 ∧
      divConv1 row < 600000 ∧
      divConv2 row < 600000 ∧
      divConv3 row < 600000 ∧
      divConv4 row < 600000 ∧
      divConv5 row < 600000 ∧
      divConv6 row < 600000 ∧
      divConv7 row < 600000 := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa [divConv0] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb0.toNat)
        0 0 0 0 0 0 0 row.remainder.limb0.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide)
        (by decide) (by decide) (by decide)
        (byteLe255 row.remainder.limb0)
  · simpa [divConv1] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb1.toNat)
        (row.rs2Next.limb1.toNat * row.quotient.limb0.toNat)
        0 0 0 0 0 0 row.remainder.limb1.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide)
        (by decide) (by decide)
        (byteLe255 row.remainder.limb1)
  · simpa [divConv2] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb2.toNat)
        (row.rs2Next.limb1.toNat * row.quotient.limb1.toNat)
        (row.rs2Next.limb2.toNat * row.quotient.limb0.toNat)
        0 0 0 0 0 row.remainder.limb2.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide) (by decide)
        (byteLe255 row.remainder.limb2)
  · simpa [divConv3] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * row.quotient.limb3.toNat)
        (row.rs2Next.limb1.toNat * row.quotient.limb2.toNat)
        (row.rs2Next.limb2.toNat * row.quotient.limb1.toNat)
        (row.rs2Next.limb3.toNat * row.quotient.limb0.toNat)
        0 0 0 0 row.remainder.limb3.toNat
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide) (by decide)
        (byteLe255 row.remainder.limb3)
  · simpa [divConv4] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * row.quotient.limb3.toNat)
        (row.rs2Next.limb2.toNat * row.quotient.limb2.toNat)
        (row.rs2Next.limb3.toNat * row.quotient.limb1.toNat)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        0 0 0 (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (by decide) (by decide) (by decide)
        (remainderHighBound row)
  · simpa [divConv5] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * divQuotientHigh row)
        (row.rs2Next.limb2.toNat * row.quotient.limb3.toNat)
        (row.rs2Next.limb3.toNat * row.quotient.limb2.toNat)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        (divDivisorHigh row * row.quotient.limb1.toNat)
        0 0 (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb1))
        (by decide) (by decide)
        (remainderHighBound row)
  · simpa [divConv6] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * divQuotientHigh row)
        (row.rs2Next.limb2.toNat * divQuotientHigh row)
        (row.rs2Next.limb3.toNat * row.quotient.limb3.toNat)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        (divDivisorHigh row * row.quotient.limb1.toNat)
        (divDivisorHigh row * row.quotient.limb2.toNat)
        0 (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3)
          (byteLe255 row.quotient.limb3))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb2))
        (by decide)
        (remainderHighBound row)
  · simpa [divConv7] using
      eightProductsAndRemainderLt600000
        (row.rs2Next.limb0.toNat * divQuotientHigh row)
        (row.rs2Next.limb1.toNat * divQuotientHigh row)
        (row.rs2Next.limb2.toNat * divQuotientHigh row)
        (row.rs2Next.limb3.toNat * divQuotientHigh row)
        (divDivisorHigh row * row.quotient.limb0.toNat)
        (divDivisorHigh row * row.quotient.limb1.toNat)
        (divDivisorHigh row * row.quotient.limb2.toNat)
        (divDivisorHigh row * row.quotient.limb3.toNat)
        (divRemainderHigh row)
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb0) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb1) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb2) (divHighBound row.qSign))
        (productLe65025 _ _
          (byteLe255 row.rs2Next.limb3) (divHighBound row.qSign))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb0))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb1))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb2))
        (productLe65025 _ _
          (divHighBound row.cSign) (byteLe255 row.quotient.limb3))
        (remainderHighBound row)

private structure PreservedA
    (source normalized : Row) : Prop where
  pc : normalized.pc = source.pc
  clock : normalized.clock = source.clock
  rd : normalized.rd = source.rd
  rdPreviousClock :
    normalized.rdPreviousClock = source.rdPreviousClock

private structure PreservedB
    (source normalized : Row) : Prop where
  rdPrevious : normalized.rdPrevious = source.rdPrevious
  rdNext : normalized.rdNext = source.rdNext
  rs1 : normalized.rs1 = source.rs1
  rs1PreviousClock :
    normalized.rs1PreviousClock = source.rs1PreviousClock

private structure PreservedC
    (source normalized : Row) : Prop where
  rs1Previous : normalized.rs1Previous = source.rs1Previous
  rs1Next : normalized.rs1Next = source.rs1Next
  rs2 : normalized.rs2 = source.rs2
  rs2PreviousClock :
    normalized.rs2PreviousClock = source.rs2PreviousClock

private structure PreservedD
    (source normalized : Row) : Prop where
  rs2Previous : normalized.rs2Previous = source.rs2Previous
  rs2Next : normalized.rs2Next = source.rs2Next
  zeroDivisor : normalized.zeroDivisor = source.zeroDivisor
  rZero : normalized.rZero = source.rZero

private structure PreservedE
    (source normalized : Row) : Prop where
  quotient : normalized.quotient = source.quotient
  remainder : normalized.remainder = source.remainder
  bSign : normalized.bSign = source.bSign
  cSign : normalized.cSign = source.cSign

private structure PreservedF
    (source normalized : Row) : Prop where
  qSign : normalized.qSign = source.qSign
  signXor : normalized.signXor = source.signXor
  remainderAbs : normalized.remainderAbs = source.remainderAbs
  ltMarker0 : normalized.ltMarker0 = source.ltMarker0

private structure PreservedG
    (source normalized : Row) : Prop where
  ltMarker1 : normalized.ltMarker1 = source.ltMarker1
  ltMarker2 : normalized.ltMarker2 = source.ltMarker2
  ltMarker3 : normalized.ltMarker3 = source.ltMarker3
  isDiv : normalized.isDiv = source.isDiv

private structure PreservedH
    (source normalized : Row) : Prop where
  isDivu : normalized.isDivu = source.isDivu
  isRem : normalized.isRem = source.isRem
  isRemu : normalized.isRemu = source.isRemu
  destinationNonzero :
    normalized.destinationNonzero = source.destinationNonzero

private structure NormalizedControl
    (source normalized : Row) : Prop where
  ltDiff :
    normalized.ltDiff = (M31.reduce source.ltDiff).val
  claimedNextPc :
    normalized.claimedNextPc = nextPc source.pc

private structure NormalizationTailSpec
    (source normalized : Row) : Prop where
  preservedG : PreservedG source normalized
  preservedH : PreservedH source normalized
  control : NormalizedControl source normalized

private structure NormalizationSpec
    (source normalized : Row) : Prop where
  preservedA : PreservedA source normalized
  preservedB : PreservedB source normalized
  preservedC : PreservedC source normalized
  preservedD : PreservedD source normalized
  preservedE : PreservedE source normalized
  preservedF : PreservedF source normalized
  tail : NormalizationTailSpec source normalized

private theorem normalizationExists (row : Row) :
    ∃ normalized : Row, NormalizationSpec row normalized := by
  let normalized : Row := {
    pc := row.pc
    clock := row.clock
    rd := row.rd
    rdPreviousClock := row.rdPreviousClock
    rdPrevious := row.rdPrevious
    rdNext := row.rdNext
    rs1 := row.rs1
    rs1PreviousClock := row.rs1PreviousClock
    rs1Previous := row.rs1Previous
    rs1Next := row.rs1Next
    rs2 := row.rs2
    rs2PreviousClock := row.rs2PreviousClock
    rs2Previous := row.rs2Previous
    rs2Next := row.rs2Next
    zeroDivisor := row.zeroDivisor
    rZero := row.rZero
    quotient := row.quotient
    remainder := row.remainder
    bSign := row.bSign
    cSign := row.cSign
    qSign := row.qSign
    signXor := row.signXor
    remainderAbs := row.remainderAbs
    ltMarker0 := row.ltMarker0
    ltMarker1 := row.ltMarker1
    ltMarker2 := row.ltMarker2
    ltMarker3 := row.ltMarker3
    ltDiff := (M31.reduce row.ltDiff).val
    isDiv := row.isDiv
    isDivu := row.isDivu
    isRem := row.isRem
    isRemu := row.isRemu
    destinationNonzero := row.destinationNonzero
    claimedNextPc := nextPc row.pc
  }
  have preservedA : PreservedA row normalized := by
    exact {
      pc := rfl
      clock := rfl
      rd := rfl
      rdPreviousClock := rfl
    }
  have preservedB : PreservedB row normalized := by
    exact {
      rdPrevious := rfl
      rdNext := rfl
      rs1 := rfl
      rs1PreviousClock := rfl
    }
  have preservedC : PreservedC row normalized := by
    exact {
      rs1Previous := rfl
      rs1Next := rfl
      rs2 := rfl
      rs2PreviousClock := rfl
    }
  have preservedD : PreservedD row normalized := by
    exact {
      rs2Previous := rfl
      rs2Next := rfl
      zeroDivisor := rfl
      rZero := rfl
    }
  have preservedE : PreservedE row normalized := by
    exact {
      quotient := rfl
      remainder := rfl
      bSign := rfl
      cSign := rfl
    }
  have preservedF : PreservedF row normalized := by
    exact {
      qSign := rfl
      signXor := rfl
      remainderAbs := rfl
      ltMarker0 := rfl
    }
  have preservedG : PreservedG row normalized := by
    exact {
      ltMarker1 := rfl
      ltMarker2 := rfl
      ltMarker3 := rfl
      isDiv := rfl
    }
  have preservedH : PreservedH row normalized := by
    exact {
      isDivu := rfl
      isRem := rfl
      isRemu := rfl
      destinationNonzero := rfl
    }
  have control : NormalizedControl row normalized := by
    exact {
      ltDiff := rfl
      claimedNextPc := rfl
    }
  have tail : NormalizationTailSpec row normalized := by
    exact {
      preservedG := preservedG
      preservedH := preservedH
      control := control
    }
  exact ⟨normalized, {
    preservedA := preservedA
    preservedB := preservedB
    preservedC := preservedC
    preservedD := preservedD
    preservedE := preservedE
    preservedF := preservedF
    tail := tail
  }⟩

noncomputable def normalize (row : Row) : Row :=
  Classical.choose (normalizationExists row)

private theorem normalize_spec (row : Row) :
    NormalizationSpec row (normalize row) :=
  Classical.choose_spec (normalizationExists row)

@[simp] private theorem normalize_pc (row : Row) :
    (normalize row).pc = row.pc :=
  (normalize_spec row).preservedA.pc

@[simp] private theorem normalize_clock (row : Row) :
    (normalize row).clock = row.clock :=
  (normalize_spec row).preservedA.clock

@[simp] private theorem normalize_rd (row : Row) :
    (normalize row).rd = row.rd :=
  (normalize_spec row).preservedA.rd

@[simp] private theorem normalize_rdPreviousClock (row : Row) :
    (normalize row).rdPreviousClock = row.rdPreviousClock :=
  (normalize_spec row).preservedA.rdPreviousClock

@[simp] private theorem normalize_rdPrevious (row : Row) :
    (normalize row).rdPrevious = row.rdPrevious :=
  (normalize_spec row).preservedB.rdPrevious

@[simp] private theorem normalize_rdNext (row : Row) :
    (normalize row).rdNext = row.rdNext :=
  (normalize_spec row).preservedB.rdNext

@[simp] private theorem normalize_rs1 (row : Row) :
    (normalize row).rs1 = row.rs1 :=
  (normalize_spec row).preservedB.rs1

@[simp] private theorem normalize_rs1PreviousClock (row : Row) :
    (normalize row).rs1PreviousClock = row.rs1PreviousClock :=
  (normalize_spec row).preservedB.rs1PreviousClock

@[simp] private theorem normalize_rs1Previous (row : Row) :
    (normalize row).rs1Previous = row.rs1Previous :=
  (normalize_spec row).preservedC.rs1Previous

@[simp] private theorem normalize_rs1Next (row : Row) :
    (normalize row).rs1Next = row.rs1Next :=
  (normalize_spec row).preservedC.rs1Next

@[simp] private theorem normalize_rs2 (row : Row) :
    (normalize row).rs2 = row.rs2 :=
  (normalize_spec row).preservedC.rs2

@[simp] private theorem normalize_rs2PreviousClock (row : Row) :
    (normalize row).rs2PreviousClock = row.rs2PreviousClock :=
  (normalize_spec row).preservedC.rs2PreviousClock

@[simp] private theorem normalize_rs2Previous (row : Row) :
    (normalize row).rs2Previous = row.rs2Previous :=
  (normalize_spec row).preservedD.rs2Previous

@[simp] private theorem normalize_rs2Next (row : Row) :
    (normalize row).rs2Next = row.rs2Next :=
  (normalize_spec row).preservedD.rs2Next

@[simp] private theorem normalize_zeroDivisor (row : Row) :
    (normalize row).zeroDivisor = row.zeroDivisor :=
  (normalize_spec row).preservedD.zeroDivisor

@[simp] private theorem normalize_rZero (row : Row) :
    (normalize row).rZero = row.rZero :=
  (normalize_spec row).preservedD.rZero

@[simp] private theorem normalize_quotient (row : Row) :
    (normalize row).quotient = row.quotient :=
  (normalize_spec row).preservedE.quotient

@[simp] private theorem normalize_remainder (row : Row) :
    (normalize row).remainder = row.remainder :=
  (normalize_spec row).preservedE.remainder

@[simp] private theorem normalize_bSign (row : Row) :
    (normalize row).bSign = row.bSign :=
  (normalize_spec row).preservedE.bSign

@[simp] private theorem normalize_cSign (row : Row) :
    (normalize row).cSign = row.cSign :=
  (normalize_spec row).preservedE.cSign

@[simp] private theorem normalize_qSign (row : Row) :
    (normalize row).qSign = row.qSign :=
  (normalize_spec row).preservedF.qSign

@[simp] private theorem normalize_signXor (row : Row) :
    (normalize row).signXor = row.signXor :=
  (normalize_spec row).preservedF.signXor

@[simp] private theorem normalize_remainderAbs (row : Row) :
    (normalize row).remainderAbs = row.remainderAbs :=
  (normalize_spec row).preservedF.remainderAbs

@[simp] private theorem normalize_ltMarker0 (row : Row) :
    (normalize row).ltMarker0 = row.ltMarker0 :=
  (normalize_spec row).preservedF.ltMarker0

@[simp] private theorem normalize_ltMarker1 (row : Row) :
    (normalize row).ltMarker1 = row.ltMarker1 :=
  (normalize_spec row).tail.preservedG.ltMarker1

@[simp] private theorem normalize_ltMarker2 (row : Row) :
    (normalize row).ltMarker2 = row.ltMarker2 :=
  (normalize_spec row).tail.preservedG.ltMarker2

@[simp] private theorem normalize_ltMarker3 (row : Row) :
    (normalize row).ltMarker3 = row.ltMarker3 :=
  (normalize_spec row).tail.preservedG.ltMarker3

@[simp] private theorem normalize_isDiv (row : Row) :
    (normalize row).isDiv = row.isDiv :=
  (normalize_spec row).tail.preservedG.isDiv

@[simp] private theorem normalize_isDivu (row : Row) :
    (normalize row).isDivu = row.isDivu :=
  (normalize_spec row).tail.preservedH.isDivu

@[simp] private theorem normalize_isRem (row : Row) :
    (normalize row).isRem = row.isRem :=
  (normalize_spec row).tail.preservedH.isRem

@[simp] private theorem normalize_isRemu (row : Row) :
    (normalize row).isRemu = row.isRemu :=
  (normalize_spec row).tail.preservedH.isRemu

@[simp] private theorem normalize_destinationNonzero (row : Row) :
    (normalize row).destinationNonzero = row.destinationNonzero :=
  (normalize_spec row).tail.preservedH.destinationNonzero

@[simp] private theorem normalize_ltDiff (row : Row) :
    (normalize row).ltDiff = (M31.reduce row.ltDiff).val :=
  (normalize_spec row).tail.control.ltDiff

@[simp] private theorem normalize_claimedNextPc (row : Row) :
    (normalize row).claimedNextPc = nextPc row.pc :=
  (normalize_spec row).tail.control.claimedNextPc

@[simp] private theorem normalize_isSigned (row : Row) :
    (normalize row).isSigned = row.isSigned := by
  simp only [DivRow.isSigned, normalize_isDiv, normalize_isRem]

@[simp] private theorem normalize_isDivision (row : Row) :
    (normalize row).isDivision = row.isDivision := by
  simp only [DivRow.isDivision, normalize_isDiv, normalize_isDivu]

@[simp] private theorem normalize_divDividendHigh (row : Row) :
    divDividendHigh (normalize row) = divDividendHigh row := by
  simp only [divDividendHigh, normalize_bSign]

@[simp] private theorem normalize_divDivisorHigh (row : Row) :
    divDivisorHigh (normalize row) = divDivisorHigh row := by
  simp only [divDivisorHigh, normalize_cSign]

@[simp] private theorem normalize_divQuotientHigh (row : Row) :
    divQuotientHigh (normalize row) = divQuotientHigh row := by
  simp only [divQuotientHigh, normalize_qSign]

@[simp] private theorem normalize_divRemainderHigh (row : Row) :
    divRemainderHigh (normalize row) = divRemainderHigh row := by
  simp only [
    divRemainderHigh,
    normalize_bSign,
    normalize_rZero,
  ]

@[simp] private theorem normalize_divConv0 (row : Row) :
    divConv0 (normalize row) = divConv0 row := by
  simp only [
    divConv0,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv1 (row : Row) :
    divConv1 (normalize row) = divConv1 row := by
  simp only [
    divConv1,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv2 (row : Row) :
    divConv2 (normalize row) = divConv2 row := by
  simp only [
    divConv2,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv3 (row : Row) :
    divConv3 (normalize row) = divConv3 row := by
  simp only [
    divConv3,
    normalize_rs2Next,
    normalize_quotient,
    normalize_remainder,
  ]

@[simp] private theorem normalize_divConv4 (row : Row) :
    divConv4 (normalize row) = divConv4 row := by
  simp only [
    divConv4,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divConv5 (row : Row) :
    divConv5 (normalize row) = divConv5 row := by
  simp only [
    divConv5,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divConv6 (row : Row) :
    divConv6 (normalize row) = divConv6 row := by
  simp only [
    divConv6,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divConv7 (row : Row) :
    divConv7 (normalize row) = divConv7 row := by
  simp only [
    divConv7,
    normalize_rs2Next,
    normalize_quotient,
    normalize_divQuotientHigh,
    normalize_divDivisorHigh,
    normalize_divRemainderHigh,
  ]

@[simp] private theorem normalize_divCompareDiff0 (row : Row) :
    divCompareDiff0 (normalize row) = divCompareDiff0 row := by
  simp only [
    divCompareDiff0,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divCompareDiff1 (row : Row) :
    divCompareDiff1 (normalize row) = divCompareDiff1 row := by
  simp only [
    divCompareDiff1,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divCompareDiff2 (row : Row) :
    divCompareDiff2 (normalize row) = divCompareDiff2 row := by
  simp only [
    divCompareDiff2,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divCompareDiff3 (row : Row) :
    divCompareDiff3 (normalize row) = divCompareDiff3 row := by
  simp only [
    divCompareDiff3,
    divCompareDiff,
    normalize_cSign,
    normalize_rs2Next,
    normalize_remainderAbs,
  ]

@[simp] private theorem normalize_divResultBytes (row : Row) :
    divResultBytes (normalize row) = divResultBytes row := by
  simp only [
    divResultBytes,
    normalize_isDivision,
    normalize_quotient,
    normalize_remainder,
  ]

def normalizeEnvironment
    (row : Row)
    (environment : Opcodes.DivEnvironment row) :
    Opcodes.DivEnvironment (normalize row) where
  pre := environment.pre
  pcBinds := by
    simpa only [normalize_pc] using environment.pcBinds
  dividendBinds := by
    simpa only [normalize_rs1Previous, normalize_rs1] using
      environment.dividendBinds
  divisorBinds := by
    simpa only [normalize_rs2Previous, normalize_rs2] using
      environment.divisorBinds
  destinationBinds := by
    simpa only [normalize_rdPrevious, normalize_rd] using
      environment.destinationBinds

private theorem divConvLtModulus
    {convolution : Nat}
    (bound : convolution < 600000) :
    convolution < M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem carryPlusDivConvLtModulus
    (carry convolution : Nat)
    (carryBound : carry < 2 ^ 11)
    (convolutionBound : convolution < 600000) :
    carry + convolution < M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem divHighLt256 (value : Bool) :
    255 * value.toNat < 2 ^ 8 := by
  have bound := divHighBound value
  omega

set_option maxRecDepth 30000 in
private theorem productRecurrence0
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv0 row < 600000) :
    divConv0 row =
      row.rs1Next.limb0.toNat + 256 * (carry0Field row).val := by
  apply MulhDiv.carryEquationOfField
  · exact divConvLtModulus convBound
  · exact byteLt256 row.rs1Next.limb0
  · exact fixed.productCarry0
  · simpa [
      carry0Field,
      divConv0,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence1
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv1 row < 600000) :
    (carry0Field row).val + divConv1 row =
      row.rs1Next.limb1.toNat + 256 * (carry1Field row).val := by
  have carryImage :
      carry0Field row = M31.reduce (carry0Field row).val :=
    (M31.reduce_toNat (carry0Field row)).symm
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry0Field row).val (divConv1 row)
        fixed.productCarry0 convBound
  · exact byteLt256 row.rs1Next.limb1
  · exact fixed.productCarry1
  · simpa [
      carry1Field,
      divConv1,
      carryImage,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence2
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv2 row < 600000) :
    (carry1Field row).val + divConv2 row =
      row.rs1Next.limb2.toNat + 256 * (carry2Field row).val := by
  have carryImage :
      carry1Field row = M31.reduce (carry1Field row).val :=
    (M31.reduce_toNat (carry1Field row)).symm
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry1Field row).val (divConv2 row)
        fixed.productCarry1 convBound
  · exact byteLt256 row.rs1Next.limb2
  · exact fixed.productCarry2
  · simpa [
      carry2Field,
      divConv2,
      carryImage,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence3
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv3 row < 600000) :
    (carry2Field row).val + divConv3 row =
      row.rs1Next.limb3.toNat + 256 * (carry3Field row).val := by
  have carryImage :
      carry2Field row = M31.reduce (carry2Field row).val :=
    (M31.reduce_toNat (carry2Field row)).symm
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry2Field row).val (divConv3 row)
        fixed.productCarry2 convBound
  · exact byteLt256 row.rs1Next.limb3
  · exact fixed.productCarry3
  · simpa [
      carry3Field,
      divConv3,
      carryImage,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence4
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv4 row < 600000) :
    (carry3Field row).val + divConv4 row =
      divDividendHigh row + 256 * (carry4Field row).val := by
  have carryImage :
      carry3Field row = M31.reduce (carry3Field row).val :=
    (M31.reduce_toNat (carry3Field row)).symm
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry3Field row).val (divConv4 row)
        fixed.productCarry3 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry4
  · simpa [
      carry4Field,
      divConv4,
      carryImage,
      quotientHighField_eq_reduce,
      divisorHighField_eq_reduce,
      remainderHighField_eq_reduce,
      dividendHighField_eq_reduce,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence5
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv5 row < 600000) :
    (carry4Field row).val + divConv5 row =
      divDividendHigh row + 256 * (carry5Field row).val := by
  have carryImage :
      carry4Field row = M31.reduce (carry4Field row).val :=
    (M31.reduce_toNat (carry4Field row)).symm
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry4Field row).val (divConv5 row)
        fixed.productCarry4 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry5
  · simpa [
      carry5Field,
      divConv5,
      carryImage,
      quotientHighField_eq_reduce,
      divisorHighField_eq_reduce,
      remainderHighField_eq_reduce,
      dividendHighField_eq_reduce,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence6
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv6 row < 600000) :
    (carry5Field row).val + divConv6 row =
      divDividendHigh row + 256 * (carry6Field row).val := by
  have carryImage :
      carry5Field row = M31.reduce (carry5Field row).val :=
    (M31.reduce_toNat (carry5Field row)).symm
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry5Field row).val (divConv6 row)
        fixed.productCarry5 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry6
  · simpa [
      carry6Field,
      divConv6,
      carryImage,
      quotientSumField,
      divisorSumField,
      wordSumField,
      quotientHighField_eq_reduce,
      divisorHighField_eq_reduce,
      remainderHighField_eq_reduce,
      dividendHighField_eq_reduce,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrence7
    (row : Row)
    (fixed : FixedSemanticConsequences row)
    (convBound : divConv7 row < 600000) :
    (carry6Field row).val + divConv7 row =
      divDividendHigh row + 256 * (carry7Field row).val := by
  have carryImage :
      carry6Field row = M31.reduce (carry6Field row).val :=
    (M31.reduce_toNat (carry6Field row)).symm
  apply MulhDiv.carryEquationOfField
  · exact
      carryPlusDivConvLtModulus
        (carry6Field row).val (divConv7 row)
        fixed.productCarry6 convBound
  · exact divHighLt256 row.bSign
  · exact fixed.productCarry7
  · simpa [
      carry7Field,
      divConv7,
      carryImage,
      quotientSumField,
      divisorSumField,
      wordSumField,
      quotientHighField_eq_reduce,
      divisorHighField_eq_reduce,
      remainderHighField_eq_reduce,
      dividendHighField_eq_reduce,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

set_option maxRecDepth 30000 in
private theorem productRecurrenceOfFixed
    (row : Row)
    (fixed : FixedSemanticConsequences row) :
    ∃ k0 k1 k2 k3 k4 k5 k6 k7 : Nat,
      k0 < 2048 ∧ k1 < 2048 ∧ k2 < 2048 ∧ k3 < 2048 ∧
      k4 < 2048 ∧ k5 < 2048 ∧ k6 < 2048 ∧ k7 < 2048 ∧
      divConv0 (normalize row) =
        (normalize row).rs1Next.limb0.toNat + 256 * k0 ∧
      k0 + divConv1 (normalize row) =
        (normalize row).rs1Next.limb1.toNat + 256 * k1 ∧
      k1 + divConv2 (normalize row) =
        (normalize row).rs1Next.limb2.toNat + 256 * k2 ∧
      k2 + divConv3 (normalize row) =
        (normalize row).rs1Next.limb3.toNat + 256 * k3 ∧
      k3 + divConv4 (normalize row) =
        divDividendHigh (normalize row) + 256 * k4 ∧
      k4 + divConv5 (normalize row) =
        divDividendHigh (normalize row) + 256 * k5 ∧
      k5 + divConv6 (normalize row) =
        divDividendHigh (normalize row) + 256 * k6 ∧
      k6 + divConv7 (normalize row) =
        divDividendHigh (normalize row) + 256 * k7 := by
  rcases divConvBounds row with
    ⟨conv0, conv1, conv2, conv3, conv4, conv5, conv6, conv7⟩
  refine ⟨
    (carry0Field row).val,
    (carry1Field row).val,
    (carry2Field row).val,
    (carry3Field row).val,
    (carry4Field row).val,
    (carry5Field row).val,
    (carry6Field row).val,
    (carry7Field row).val,
    fixed.productCarry0,
    fixed.productCarry1,
    fixed.productCarry2,
    fixed.productCarry3,
    fixed.productCarry4,
    fixed.productCarry5,
    fixed.productCarry6,
    fixed.productCarry7,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa only [normalize_divConv0, normalize_rs1Next] using
      productRecurrence0 row fixed conv0
  · simpa only [normalize_divConv1, normalize_rs1Next] using
      productRecurrence1 row fixed conv1
  · simpa only [normalize_divConv2, normalize_rs1Next] using
      productRecurrence2 row fixed conv2
  · simpa only [normalize_divConv3, normalize_rs1Next] using
      productRecurrence3 row fixed conv3
  · simpa only [
      normalize_divConv4,
      normalize_divDividendHigh,
    ] using productRecurrence4 row fixed conv4
  · simpa only [
      normalize_divConv5,
      normalize_divDividendHigh,
    ] using productRecurrence5 row fixed conv5
  · simpa only [
      normalize_divConv6,
      normalize_divDividendHigh,
    ] using productRecurrence6 row fixed conv6
  · simpa only [
      normalize_divConv7,
      normalize_divDividendHigh,
    ] using productRecurrence7 row fixed conv7

private theorem compareDiffZeroOfField
    (row : Row)
    (divisor absolute : Byte)
    (equation : compareDiffField row divisor absolute = 0) :
    divCompareDiff row divisor absolute = 0 := by
  cases sign : row.cSign with
  | false =>
      rw [sign] at equation
      simp only [
        compareDiffField,
        boolM31,
        M31.zero_mul,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      have equal :=
        byteEqOfFieldEq divisor absolute
          ((M31.sub_eq_zero_iff _ _).mp equation)
      simp [divCompareDiff, sign, equal]
  | true =>
      rw [sign] at equation
      simp only [
        compareDiffField,
        boolM31,
        M31.one_mul,
      ] at equation
      have factor :
          (1 : M31) - M31.reduce 2 =
            M31.reduce (M31.modulus - 1) := by
        decide
      rw [factor] at equation
      have square :
          M31.reduce (M31.modulus - 1) *
              M31.reduce (M31.modulus - 1) =
            1 := by
        decide
      have negated :=
        congrArg
          (fun value : M31 =>
            M31.reduce (M31.modulus - 1) * value)
          equation
      rw [
        ← MulhDiv.m31MulAssoc,
        square,
        M31.one_mul,
        M31.mul_zero,
      ] at negated
      have equal :=
        byteEqOfFieldEq divisor absolute
          ((M31.sub_eq_zero_iff _ _).mp negated)
      simp [divCompareDiff, sign, equal]

private theorem compareMarkerOfField
    (row : Row)
    (divisor absolute : Byte)
    (upper : (M31.reduce row.ltDiff).val ≤ 1048576)
    (equation :
      M31.reduce row.ltDiff =
        compareDiffField row divisor absolute) :
    ((M31.reduce row.ltDiff).val : Int) =
      divCompareDiff row divisor absolute := by
  have divisorImage :
      (bitVecM31 divisor).val = divisor.toNat :=
    M31.reduce_val_of_lt _ (byteBound divisor)
  have absoluteImage :
      (bitVecM31 absolute).val = absolute.toNat :=
    M31.reduce_val_of_lt _ (byteBound absolute)
  cases sign : row.cSign with
  | false =>
      rw [sign] at equation
      simp only [
        compareDiffField,
        boolM31,
        M31.zero_mul,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      by_cases ordered : absolute.toNat ≤ divisor.toNat
      · have fieldOrdered :
            (bitVecM31 absolute).val ≤
              (bitVecM31 divisor).val := by
          rw [divisorImage, absoluteImage]
          exact ordered
        have difference :=
          M31.sub_val_of_le
            (bitVecM31 divisor) (bitVecM31 absolute) fieldOrdered
        rw [divisorImage, absoluteImage] at difference
        have values := congrArg M31.val equation
        rw [difference] at values
        simp [divCompareDiff, sign]
        omega
      · have reverse : divisor.toNat < absolute.toNat := by omega
        have fieldReverse :
            (bitVecM31 divisor).val <
              (bitVecM31 absolute).val := by
          rw [divisorImage, absoluteImage]
          exact reverse
        have wrapped :=
          M31.sub_val_of_lt
            (bitVecM31 divisor) (bitVecM31 absolute) fieldReverse
        rw [divisorImage, absoluteImage] at wrapped
        have values := congrArg M31.val equation
        rw [wrapped] at values
        have absoluteBound := byteLt256 absolute
        rw [M31.modulus_eq] at values
        omega
  | true =>
      rw [sign] at equation
      simp only [
        compareDiffField,
        boolM31,
        M31.one_mul,
      ] at equation
      have factor :
          (1 : M31) - M31.reduce 2 =
            M31.reduce (M31.modulus - 1) := by
        decide
      rw [factor] at equation
      by_cases equal : divisor.toNat = absolute.toNat
      · have bytesEqual : divisor = absolute :=
          BitVec.eq_of_toNat_eq equal
        subst absolute
        rw [M31.sub_self, M31.mul_zero] at equation
        have values := congrArg M31.val equation
        simp [divCompareDiff, sign] at values ⊢
        exact values
      · by_cases ordered : divisor.toNat < absolute.toNat
        · let gap := absolute.toNat - divisor.toNat
          have gapPositive : 0 < gap := by
            dsimp [gap]
            omega
          have gapBound : gap < M31.modulus := by
            have absoluteBound := byteLt256 absolute
            rw [M31.modulus_eq]
            dsimp [gap]
            omega
          have differenceField :
              bitVecM31 divisor - bitVecM31 absolute =
                M31.reduce (M31.modulus - gap) := by
            apply M31.ext
            have fieldOrder :
                (bitVecM31 divisor).val <
                  (bitVecM31 absolute).val := by
              rw [divisorImage, absoluteImage]
              exact ordered
            rw [
              M31.sub_val_of_lt _ _ fieldOrder,
              divisorImage,
              absoluteImage,
              M31.reduce_val_of_lt
                (M31.modulus - gap) (by omega),
            ]
            dsimp [gap]
            omega
          rw [
            differenceField,
            m31Negate gap gapBound,
          ] at equation
          have values := congrArg M31.val equation
          rw [M31.reduce_val_of_lt gap gapBound] at values
          simp [divCompareDiff, sign]
          dsimp [gap] at values
          omega
        · have reverse : absolute.toNat < divisor.toNat := by omega
          let gap := divisor.toNat - absolute.toNat
          have gapPositive : 0 < gap := by
            dsimp [gap]
            omega
          have gapBound : gap < M31.modulus := by
            have divisorBound := byteLt256 divisor
            rw [M31.modulus_eq]
            dsimp [gap]
            omega
          have differenceField :
              bitVecM31 divisor - bitVecM31 absolute =
                M31.reduce gap := by
            unfold bitVecM31
            rw [m31ReduceSubOfLe _ _ (by omega)]
            congr 1
          have square :
              M31.reduce (M31.modulus - 1) *
                  M31.reduce (M31.modulus - 1) =
                1 := by
            decide
          have doubleNegation :=
            congrArg
              (fun value : M31 =>
                M31.reduce (M31.modulus - 1) * value)
              (m31Negate gap gapBound)
          rw [
            ← MulhDiv.m31MulAssoc,
            square,
            M31.one_mul,
          ] at doubleNegation
          have negativeGap :
              M31.reduce (M31.modulus - 1) * M31.reduce gap =
                M31.reduce (M31.modulus - gap) :=
            doubleNegation.symm
          rw [differenceField, negativeGap] at equation
          have remainderBound :
              M31.modulus - gap < M31.modulus := by
            omega
          have values := congrArg M31.val equation
          rw [
            M31.reduce_val_of_lt
              (M31.modulus - gap) remainderBound,
          ] at values
          have divisorBound := byteLt256 divisor
          rw [M31.modulus_eq] at values
          dsimp [gap] at values
          omega

private theorem scanTotalOfEquations
    (row : Row)
    (activeOne : activeField row = 1)
    (equation : activeField row * (1 - prefix0Field row) = 0) :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1 := by
  rw [activeOne, M31.one_mul] at equation
  cases zeroDivisor : row.zeroDivisor <;>
    cases remainderZero : row.rZero <;>
    cases marker3 : row.ltMarker3 <;>
    cases marker2 : row.ltMarker2 <;>
    cases marker1 : row.ltMarker1 <;>
    cases marker0 : row.ltMarker0 <;>
    simp_all [
      prefix0Field,
      prefix1Field,
      prefix2Field,
      prefix3Field,
      specialField,
      boolM31,
    ]

structure ScanConsequences (row : Row) : Prop where
  total :
    row.zeroDivisor.toNat + row.rZero.toNat +
        row.ltMarker3.toNat + row.ltMarker2.toNat +
        row.ltMarker1.toNat + row.ltMarker0.toNat = 1
  equal3 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false →
      divCompareDiff3 row = 0
  equal2 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false → row.ltMarker2 = false →
      divCompareDiff2 row = 0
  equal1 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false → row.ltMarker2 = false →
      row.ltMarker1 = false →
      divCompareDiff1 row = 0
  equal0 :
    row.zeroDivisor = false → row.rZero = false →
      row.ltMarker3 = false → row.ltMarker2 = false →
      row.ltMarker1 = false → row.ltMarker0 = false →
      divCompareDiff0 row = 0
  marker3 :
    row.ltMarker3 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff3 row
  marker2 :
    row.ltMarker2 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff2 row
  marker1 :
    row.ltMarker1 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff1 row
  marker0 :
    row.ltMarker0 = true →
      ((M31.reduce row.ltDiff).val : Int) = divCompareDiff0 row

private theorem scanConsequences
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (selectors : SelectorConsequences selector row)
    (equations : DirectEquations row witness)
    (fixed : FixedSemanticConsequences row) :
    ScanConsequences row := by
  have total :=
    scanTotalOfEquations row selectors.activeOne equations.f.scanTotal
  exact {
    total := total
    equal3 := by
      intro zeroDivisor remainderZero marker3
      have equation := equations.e.scanEqual3
      rw [zeroDivisor, remainderZero, marker3] at equation
      simp only [
        prefix3Field,
        specialField,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb3 row.remainderAbs.limb3 equation
    equal2 := by
      intro zeroDivisor remainderZero marker3 marker2
      have equation := equations.e.scanEqual2
      rw [zeroDivisor, remainderZero, marker3, marker2] at equation
      simp only [
        prefix2Field,
        prefix3Field,
        specialField,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb2 row.remainderAbs.limb2 equation
    equal1 := by
      intro zeroDivisor remainderZero marker3 marker2 marker1
      have equation := equations.f.scanEqual1
      rw [
        zeroDivisor,
        remainderZero,
        marker3,
        marker2,
        marker1,
      ] at equation
      simp only [
        prefix1Field,
        prefix2Field,
        prefix3Field,
        specialField,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb1 row.remainderAbs.limb1 equation
    equal0 := by
      intro zeroDivisor remainderZero marker3 marker2 marker1 marker0
      have equation := equations.f.scanEqual0
      rw [
        zeroDivisor,
        remainderZero,
        marker3,
        marker2,
        marker1,
        marker0,
      ] at equation
      simp only [
        prefix0Field,
        prefix1Field,
        prefix2Field,
        prefix3Field,
        specialField,
        boolM31,
        M31.zero_add,
        M31.sub_zero,
        M31.one_mul,
      ] at equation
      exact
        compareDiffZeroOfField row
          row.rs2Next.limb0 row.remainderAbs.limb0 equation
    marker3 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all
      have equation := equations.e.scanMarker3
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb3 row.remainderAbs.limb3
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
    marker2 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all
      have equation := equations.f.scanMarker2
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb2 row.remainderAbs.limb2
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
    marker1 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all
      have equation := equations.f.scanMarker1
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb1 row.remainderAbs.limb1
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
    marker0 := by
      intro marker
      have zeroDivisor : row.zeroDivisor = false := by
        cases value : row.zeroDivisor <;>
          simp_all
      have remainderZero : row.rZero = false := by
        cases value : row.rZero <;>
          simp_all
      have equation := equations.f.scanMarker0
      rw [marker] at equation
      simp only [boolM31, M31.one_mul] at equation
      exact
        compareMarkerOfField row
          row.rs2Next.limb0 row.remainderAbs.limb0
          (fixed.ltDiffUpper zeroDivisor remainderZero)
          ((M31.sub_eq_zero_iff _ _).mp equation)
  }

set_option maxRecDepth 30000 in
theorem acceptedAir_implies_holds
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance selector row witness relationHolds)
    (admission : Admission row) :
    DivHolds (normalize row) := by
  have selectors :=
    selectorConsequences selector row witness
      accepted.activeProductionRow accepted.directConstraints
  have equations :=
    directEquations selector row witness
      accepted.directConstraints
  have direct :=
    directConsequences selector row witness selectors equations
  have fixedRequests :=
    fixedConsequences selector row witness selectors
      accepted.fixedTableRequests
  have fixed :=
    fixedSemanticConsequences selector row admission
      selectors fixedRequests
  have scan :=
    scanConsequences selector row witness selectors equations fixed
  refine {
    selectorUnique := by
      simpa using selectors.selectorUnique
    specialExclusive := by
      simpa using direct.specialExclusive
    zeroDivisorLimb0 := by
      simpa using direct.zeroDivisorLimb0
    zeroDivisorLimb1 := by
      simpa using direct.zeroDivisorLimb1
    zeroDivisorLimb2 := by
      simpa using direct.zeroDivisorLimb2
    zeroDivisorLimb3 := by
      simpa using direct.zeroDivisorLimb3
    zeroDivisorQuotient0 := by
      simpa using direct.zeroDivisorQuotient0
    zeroDivisorQuotient1 := by
      simpa using direct.zeroDivisorQuotient1
    zeroDivisorQuotient2 := by
      simpa using direct.zeroDivisorQuotient2
    zeroDivisorQuotient3 := by
      simpa using direct.zeroDivisorQuotient3
    divisorNonzero := by
      simpa using direct.divisorNonzero
    remainderZeroLimb0 := by
      simpa using direct.remainderZeroLimb0
    remainderZeroLimb1 := by
      simpa using direct.remainderZeroLimb1
    remainderZeroLimb2 := by
      simpa using direct.remainderZeroLimb2
    remainderZeroLimb3 := by
      simpa using direct.remainderZeroLimb3
    remainderNonzero := by
      simpa using direct.remainderNonzero
    unsignedDividendSign := by
      simpa using direct.unsignedDividendSign
    unsignedDivisorSign := by
      simpa using direct.unsignedDivisorSign
    signXorDefinition := by
      simpa using direct.signXorDefinition
    quotientSignMatches := by
      simpa using direct.quotientSignMatches
    quotientSignImpliesXor := by
      simpa using direct.quotientSignImpliesXor
    zeroDivisorQuotientSign := by
      simpa using direct.zeroDivisorQuotientSign
    absSameLimb0 := by
      simpa using direct.absSameLimb0
    absSameLimb1 := by
      simpa using direct.absSameLimb1
    absSameLimb2 := by
      simpa using direct.absSameLimb2
    absSameLimb3 := by
      simpa using direct.absSameLimb3
    negationRecurrence := by
      simpa using
        negationRecurrenceOfEquations row witness equations
    productRecurrence :=
      productRecurrenceOfFixed row fixed
    dividendSignBit := by
      simpa using fixed.dividendSignBit
    divisorSignBit := by
      simpa using fixed.divisorSignBit
    quotientSignBit := by
      simpa using fixed.quotientSignBit
    scanTotal := by
      simpa using scan.total
    scanEqual3 := by
      simpa using scan.equal3
    scanEqual2 := by
      simpa using scan.equal2
    scanEqual1 := by
      simpa using scan.equal1
    scanEqual0 := by
      simpa using scan.equal0
    scanMarker3 := by
      simpa using scan.marker3
    scanMarker2 := by
      simpa using scan.marker2
    scanMarker1 := by
      simpa using scan.marker1
    scanMarker0 := by
      simpa using scan.marker0
    ltDiffLower := by
      simpa using fixed.ltDiffLower
    ltDiffUpper := by
      simpa using fixed.ltDiffUpper
    destinationFlag := by
      simpa using direct.destinationFlag
    destinationLimb0 := by
      simpa using direct.destinationLimb0
    destinationLimb1 := by
      simpa using direct.destinationLimb1
    destinationLimb2 := by
      simpa using direct.destinationLimb2
    destinationLimb3 := by
      simpa using direct.destinationLimb3
    sourceOneLimb0 := by
      simpa using congrArg WordBytes.limb0 direct.sourceOne
    sourceOneLimb1 := by
      simpa using congrArg WordBytes.limb1 direct.sourceOne
    sourceOneLimb2 := by
      simpa using congrArg WordBytes.limb2 direct.sourceOne
    sourceOneLimb3 := by
      simpa using congrArg WordBytes.limb3 direct.sourceOne
    sourceTwoLimb0 := by
      simpa using congrArg WordBytes.limb0 direct.sourceTwo
    sourceTwoLimb1 := by
      simpa using congrArg WordBytes.limb1 direct.sourceTwo
    sourceTwoLimb2 := by
      simpa using congrArg WordBytes.limb2 direct.sourceTwo
    sourceTwoLimb3 := by
      simpa using congrArg WordBytes.limb3 direct.sourceTwo
    clockPositive := by
      simpa using admission.clockPositive
    sourceOneClock := by
      simpa using fixed.sourceOneClock
    sourceTwoClock := by
      simpa using fixed.sourceTwoClock
    destinationClock := by
      simpa using fixed.destinationClock
    nextPcResult := normalize_claimedNextPc row
  }

theorem div_programIdentity :
    Programs.div.source.opcodeSelector.manifestId = 41 ∧
      Programs.div.source.opcodeSelector.mnemonic = "div" ∧
      Programs.div.source.family = .div ∧
      Programs.div.source.contentDigest =
        "4355b265b09fdf7a737b66b6a7bb54b52eba0d3dad450fe67dd5e7eda0763b74" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem divu_programIdentity :
    Programs.divu.source.opcodeSelector.manifestId = 42 ∧
      Programs.divu.source.opcodeSelector.mnemonic = "divu" ∧
      Programs.divu.source.family = .div ∧
      Programs.divu.source.contentDigest =
        "243f9632581ae182ca454dca0cdd71956cfdcacd91877b601547acf1188bb99f" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem rem_programIdentity :
    Programs.rem.source.opcodeSelector.manifestId = 43 ∧
      Programs.rem.source.opcodeSelector.mnemonic = "rem" ∧
      Programs.rem.source.family = .div ∧
      Programs.rem.source.contentDigest =
        "88d1f5d7c3d50d5471a537b5fc19e43bd44a688b59a275d7a656ed6fcdfc6108" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem remu_programIdentity :
    Programs.remu.source.opcodeSelector.manifestId = 44 ∧
      Programs.remu.source.opcodeSelector.mnemonic = "remu" ∧
      Programs.remu.source.family = .div ∧
      Programs.remu.source.contentDigest =
        "02c4fe4d503963e01dc955428525ce9f2050613f2b0cad3538aea04feef7a072" :=
  ⟨rfl, rfl, rfl, rfl⟩

structure SelectorAdmission
    (selector : Selector)
    (row : Row)
    (published : TeamB.Selector)
    (selectedProgram : LocalProgram)
    (manifestId : Nat)
    (mnemonic digest : String) : Prop where
  rowSelected :
    match selector with
    | .div =>
        row.isDiv = true ∧ row.isDivu = false ∧
          row.isRem = false ∧ row.isRemu = false
    | .divu =>
        row.isDiv = false ∧ row.isDivu = true ∧
          row.isRem = false ∧ row.isRemu = false
    | .rem =>
        row.isDiv = false ∧ row.isDivu = false ∧
          row.isRem = true ∧ row.isRemu = false
    | .remu =>
        row.isDiv = false ∧ row.isDivu = false ∧
          row.isRem = false ∧ row.isRemu = true
  exactProgram : program selector = selectedProgram
  manifest :
    selectedProgram.source.opcodeSelector.manifestId = manifestId
  publishedManifest :
    manifestId = TeamB.Selector.manifestId published
  programMnemonic :
    selectedProgram.source.opcodeSelector.mnemonic = mnemonic
  publishedMnemonic :
    mnemonic = TeamB.Selector.mnemonic published
  unique :
    ∀ candidate : TeamB.Selector,
      TeamB.Selector.manifestId candidate = manifestId →
        candidate = published
  familyAdmits :
    selectedProgram.source.family.validOpcode manifestId mnemonic = true
  universalIdentity :
    Publication.actualProgramIdentities[manifestId]? =
      some {
        manifestId := manifestId
        mnemonic := mnemonic
        family := selectedProgram.source.family
        contentDigest := digest
      }

private theorem selectorAdmissionUnique
    (published : TeamB.Selector)
    (manifestId : Nat)
    (identity :
      TeamB.Selector.manifestId published = manifestId) :
    ∀ candidate : TeamB.Selector,
      TeamB.Selector.manifestId candidate = manifestId →
        candidate = published := by
  intro candidate same
  apply TeamB.Selector.manifestId_injective
  rw [identity]
  exact same

theorem div_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = true ∧ row.isDivu = false ∧
        row.isRem = false ∧ row.isRemu = false) :
    SelectorAdmission .div row .div Programs.div 41 "div"
      "4355b265b09fdf7a737b66b6a7bb54b52eba0d3dad450fe67dd5e7eda0763b74" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .div 41 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

theorem divu_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = false ∧ row.isDivu = true ∧
        row.isRem = false ∧ row.isRemu = false) :
    SelectorAdmission .divu row .divu Programs.divu 42 "divu"
      "243f9632581ae182ca454dca0cdd71956cfdcacd91877b601547acf1188bb99f" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .divu 42 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

theorem rem_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = false ∧ row.isDivu = false ∧
        row.isRem = true ∧ row.isRemu = false) :
    SelectorAdmission .rem row .rem Programs.rem 43 "rem"
      "88d1f5d7c3d50d5471a537b5fc19e43bd44a688b59a275d7a656ed6fcdfc6108" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .rem 43 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

theorem remu_selectorAdmission
    (row : Row)
    (selected :
      row.isDiv = false ∧ row.isDivu = false ∧
        row.isRem = false ∧ row.isRemu = true) :
    SelectorAdmission .remu row .remu Programs.remu 44 "remu"
      "02c4fe4d503963e01dc955428525ce9f2050613f2b0cad3538aea04feef7a072" := by
  refine {
    rowSelected := selected
    exactProgram := rfl
    manifest := rfl
    publishedManifest := rfl
    programMnemonic := rfl
    publishedMnemonic := rfl
    unique := selectorAdmissionUnique .remu 44 rfl
    familyAdmits := by decide
    universalIdentity := ?_
  }
  rw [Publication.exactProductionProgramIdentities]
  rfl

private theorem selectedAcceptance_is_generic
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        ((program selector).evalSymbolic (columns row witness))
        relationHolds) :
    Acceptance selector row witness relationHolds := by
  simpa only [evaluation] using accepted

/-
Stable publication wrapper for manifest selector 41 (`DIV`).  The premise is
the exact generated `Programs.div` evaluation; the row selector is recovered
from that acceptance rather than supplied by the caller.
-/
set_option maxRecDepth 30000 in
theorem div_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.div.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .div row .div Programs.div 41 "div"
        "4355b265b09fdf7a737b66b6a7bb54b52eba0d3dad450fe67dd5e7eda0763b74" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeDiv
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .div row witness ∧
      ExactFixedProjection .div row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.div.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .div row witness relationHolds :=
    selectedAcceptance_is_generic .div row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .div row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .div row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isDiv = true := by
    simpa using selectors.selected.1
  have retirement :=
    Opcodes.div_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeDiv
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨div_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .div row witness,
      exactFixedProjection .div row witness,
      accepted.liveRelations⟩

/- Stable publication wrapper for manifest selector 42 (`DIVU`). -/
set_option maxRecDepth 30000 in
theorem divu_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.divu.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .divu row .divu Programs.divu 42 "divu"
        "243f9632581ae182ca454dca0cdd71956cfdcacd91877b601547acf1188bb99f" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeDivu
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .divu row witness ∧
      ExactFixedProjection .divu row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.divu.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .divu row witness relationHolds :=
    selectedAcceptance_is_generic .divu row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .divu row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .divu row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isDivu = true := by
    simpa using selectors.selected.2.1
  have retirement :=
    Opcodes.divu_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeDivu
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨divu_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .divu row witness,
      exactFixedProjection .divu row witness,
      accepted.liveRelations⟩

/- Stable publication wrapper for manifest selector 43 (`REM`). -/
set_option maxRecDepth 30000 in
theorem rem_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.rem.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .rem row .rem Programs.rem 43 "rem"
        "88d1f5d7c3d50d5471a537b5fc19e43bd44a688b59a275d7a656ed6fcdfc6108" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeRem
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .rem row witness ∧
      ExactFixedProjection .rem row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.rem.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .rem row witness relationHolds :=
    selectedAcceptance_is_generic .rem row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .rem row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .rem row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isRem = true := by
    simpa using selectors.selected.2.2.1
  have retirement :=
    Opcodes.rem_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeRem
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨rem_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .rem row witness,
      exactFixedProjection .rem row witness,
      accepted.liveRelations⟩

/- Stable publication wrapper for manifest selector 44 (`REMU`). -/
set_option maxRecDepth 30000 in
theorem remu_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.DivEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      Publication.AcceptedProductionEvaluation
        (Programs.remu.evalSymbolic (columns row witness))
        relationHolds)
    (admission : Admission row) :
    SelectorAdmission .remu row .remu Programs.remu 44 "remu"
        "02c4fe4d503963e01dc955428525ce9f2050613f2b0cad3538aea04feef7a072" ∧
      DivHolds (normalize row) ∧
      divRetirement (normalize row) =
        Sail.Reviewed.executeRemu
          environment.pre.pc row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) ∧
      ExactTupleProjection .remu row witness ∧
      ExactFixedProjection .remu row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.remu.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have generic : Acceptance .remu row witness relationHolds :=
    selectedAcceptance_is_generic .remu row witness relationHolds
      (by simpa [program] using accepted)
  have selectors :=
    selectorConsequences .remu row witness
      generic.activeProductionRow generic.directConstraints
  have holds :=
    acceptedAir_implies_holds
      .remu row witness relationHolds generic admission
  have normalizedSelector : (normalize row).isRemu = true := by
    simpa using selectors.selected.2.2.2
  have retirement :=
    Opcodes.remu_retires_as_reviewed
      (normalize row) (normalizeEnvironment row environment)
      holds normalizedSelector
  have reviewedRetirement :
    divRetirement (normalize row) =
      Sail.Reviewed.executeRemu
        environment.pre.pc row.rd
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2) := by
    simpa only [normalize_rd, normalize_rs1, normalize_rs2] using retirement
  exact
    ⟨remu_selectorAdmission row selectors.selected,
      holds, reviewedRetirement,
      exactTupleProjection .remu row witness,
      exactFixedProjection .remu row witness,
      accepted.liveRelations⟩

end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
