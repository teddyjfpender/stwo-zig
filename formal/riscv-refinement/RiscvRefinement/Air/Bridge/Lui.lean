import RiscvRefinement.Air.Generated.Pilot
import RiscvRefinement.Air.Generated.Programs

/-!
# Production LUI AIR bridge

This module projects the typed normalized `LuiRow` into the exact columns of
the generated production program.  Every theorem below evaluates
`Generated.Programs.lui`; no constraint or lookup tuple is copied into a
parallel predicate.
-/

namespace RiscvRefinement.Air.Bridge

open RiscvRefinement
open RiscvRefinement.Air.Generated

namespace Lui

def boolM31 : Bool → M31
  | false => 0
  | true => 1

def bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  M31.reduce value.toNat

theorem bitVecM31_val
    {width : Nat}
    (value : BitVec width)
    (bound : value.toNat < M31.modulus) :
    (bitVecM31 value).val = value.toNat := by
  exact M31.reduce_val_of_lt value.toNat bound

structure Witness (row : LuiRow) where
  destinationInverse : M31

def columns
    (row : LuiRow)
    (witness : Witness row) :
    Nat → M31
  | 0 => 1
  | 1 => M31.reduce row.clock
  | 2 => bitVecM31 row.pc
  | 3 => bitVecM31 row.rd
  | 4 => bitVecM31 row.rdPrevious.limb0
  | 5 => bitVecM31 row.rdPrevious.limb1
  | 6 => bitVecM31 row.rdPrevious.limb2
  | 7 => bitVecM31 row.rdPrevious.limb3
  | 8 => M31.reduce row.rdPreviousClock
  | 9 => bitVecM31 row.rdNext.limb0
  | 10 => bitVecM31 row.rdNext.limb1
  | 11 => bitVecM31 row.rdNext.limb2
  | 12 => bitVecM31 row.rdNext.limb3
  | 13 => bitVecM31 row.imm0
  | 14 => bitVecM31 row.imm1
  | 15 => bitVecM31 row.imm2
  | 16 => boolM31 row.rdNonzero
  | 17 => witness.destinationInverse
  | _ => 0

def evaluation
    (row : LuiRow)
    (witness : Witness row) :
    SymbolicEvaluation :=
  Programs.lui.evalSymbolic (columns row witness)

/-!
The production statement admits at most `2^24` instruction rows and every
predecessor clock is decomposed below `2^26`.  These are cross-row statement
facts, not extra opcode constraints.
-/
structure Admission (row : LuiRow) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26

def accessClockField (row : LuiRow) : M31 :=
  (M31.reduce row.clock - 1) * M31.reduce 4 + 1

def clockGapField (row : LuiRow) : M31 :=
  accessClockField row - M31.reduce row.rdPreviousClock - 1

def programLookup (row : LuiRow) : EvaluatedLookup where
  ordinal := 9
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce 35,
    bitVecM31 row.rd,
    bitVecM31 row.imm0 +
      bitVecM31 row.imm1 * M31.reduce 16 +
      bitVecM31 row.imm2 * M31.reduce 4096,
    0
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def stateConsumeLookup (row : LuiRow) : EvaluatedLookup where
  ordinal := 10
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : LuiRow) : EvaluatedLookup where
  ordinal := 11
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc + M31.reduce 4,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def immediateLookup (row : LuiRow) : EvaluatedLookup where
  ordinal := 12
  domain := .rangeCheck884
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.imm1,
    bitVecM31 row.imm2,
    bitVecM31 row.imm0
  ]
  role := .request
  tableId := some .rangeCheck884
  accessOrdinal := none

def destinationConsumeLookup (row : LuiRow) : EvaluatedLookup where
  ordinal := 13
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0,
    bitVecM31 row.rd,
    M31.reduce row.rdPreviousClock,
    bitVecM31 row.rdPrevious.limb0,
    bitVecM31 row.rdPrevious.limb1,
    bitVecM31 row.rdPrevious.limb2,
    bitVecM31 row.rdPrevious.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 1

def destinationEmitLookup (row : LuiRow) : EvaluatedLookup where
  ordinal := 14
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0,
    bitVecM31 row.rd,
    accessClockField row,
    bitVecM31 row.rdNext.limb0,
    bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2,
    bitVecM31 row.rdNext.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def clockLookup (row : LuiRow) : EvaluatedLookup where
  ordinal := 15
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

macro "reduce_lui_lookup" : tactic =>
  `(tactic|
    (simp only [
      LocalProgram.evalNodesSymbolic,
      Programs.lui,
      Programs.luiSource,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      List.length_cons,
      List.length_nil,
      List.map_toArray,
      Array.map_push,
      Array.map_empty,
      columns,
      programLookup,
      stateConsumeLookup,
      stateEmitLookup,
      immediateLookup,
      destinationConsumeLookup,
      destinationEmitLookup,
      clockLookup,
      accessClockField,
      clockGapField
    ] <;> rfl))

set_option maxRecDepth 20000 in
theorem clockLookup_projection
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).lookup? 15 = some (clockLookup row) := by
  rw [evaluation]
  have selected :
      Programs.lui.source.events[15]? =
        some (.lookup {
          ordinal := 15
          domain := .rangeCheck20
          numerator := 50
          tuple := #[43]
          role := .request
          tableId := some .rangeCheck20
          liveness := .nonzeroNumerator
          accessOrdinal := some 1
        }) := by decide
  rw [
    LocalProgram.lookup?_evalSymbolic_of_event
      Programs.lui (columns row witness) 15 _ selected,
  ]
  reduce_lui_lookup

set_option maxRecDepth 20000 in
theorem lookup_projection
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).lookup? 9 = some (programLookup row) ∧
    (evaluation row witness).lookup? 10 = some (stateConsumeLookup row) ∧
    (evaluation row witness).lookup? 11 = some (stateEmitLookup row) ∧
    (evaluation row witness).lookup? 12 = some (immediateLookup row) ∧
    (evaluation row witness).lookup? 13 =
      some (destinationConsumeLookup row) ∧
    (evaluation row witness).lookup? 14 =
      some (destinationEmitLookup row) ∧
    (evaluation row witness).lookup? 15 = some (clockLookup row) := by
  rw [evaluation]
  constructor
  · have selected :
        Programs.lui.source.events[9]? =
          some (.lookup {
            ordinal := 9
            domain := .programAccess
            numerator := 50
            tuple := #[2, 44, 3, 49, 27]
            role := .request
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.lui (columns row witness) 9 _ selected,
    ]
    reduce_lui_lookup
  constructor
  · have selected :
        Programs.lui.source.events[10]? =
          some (.lookup {
            ordinal := 10
            domain := .registersState
            numerator := 50
            tuple := #[2, 1]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.lui (columns row witness) 10 _ selected,
    ]
    reduce_lui_lookup
  constructor
  · have selected :
        Programs.lui.source.events[11]? =
          some (.lookup {
            ordinal := 11
            domain := .registersState
            numerator := 0
            tuple := #[51, 52]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.lui (columns row witness) 11 _ selected,
    ]
    reduce_lui_lookup
  constructor
  · have selected :
        Programs.lui.source.events[12]? =
          some (.lookup {
            ordinal := 12
            domain := .rangeCheck884
            numerator := 50
            tuple := #[14, 15, 13]
            role := .request
            tableId := some .rangeCheck884
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.lui (columns row witness) 12 _ selected,
    ]
    reduce_lui_lookup
  constructor
  · have selected :
        Programs.lui.source.events[13]? =
          some (.lookup {
            ordinal := 13
            domain := .memoryAccess
            numerator := 50
            tuple := #[27, 3, 8, 4, 5, 6, 7]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.lui (columns row witness) 13 _ selected,
    ]
    reduce_lui_lookup
  constructor
  · have selected :
        Programs.lui.source.events[14]? =
          some (.lookup {
            ordinal := 14
            domain := .memoryAccess
            numerator := 0
            tuple := #[27, 3, 41, 9, 10, 11, 12]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.lui (columns row witness) 14 _ selected,
    ]
    reduce_lui_lookup
  · have selected :
        Programs.lui.source.events[15]? =
          some (.lookup {
            ordinal := 15
            domain := .rangeCheck20
            numerator := 50
            tuple := #[43]
            role := .request
            tableId := some .rangeCheck20
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.lui (columns row witness) 15 _ selected,
    ]
    reduce_lui_lookup

set_option maxRecDepth 20000 in
theorem selectorAccepted
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  simp only [
    evaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    Programs.lui,
    Programs.luiSource,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    SymbolicEvaluation.activeSelectorsAccepted,
    columns,
    M31.ofNat?,
  ]
  rfl

private theorem constraintsHoldEvents
    (nodes : LocalValues) :
    (Programs.luiSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      #[20, 22, 24, 26, 31, 33, 35, 37, 19].all
        (fun root => nodes.getSymbolic root == 0) := by
  simp [Programs.luiSource, Event.evalSymbolic]

theorem constraintsHold_eq
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      #[20, 22, 24, 26, 31, 33, 35, 37, 19].all
        (fun root => (evaluation row witness).nodes.getSymbolic root == 0) := by
  exact constraintsHoldEvents (evaluation row witness).nodes

set_option maxRecDepth 20000 in
private theorem node20
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 20 =
      (1 : M31) * (1 - 1) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node22
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 22 =
      boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node24
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 24 =
      bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node26
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 26 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  rfl

set_option maxRecDepth 20000 in
private theorem node31
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 31 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero * 0 := by
  rfl

set_option maxRecDepth 20000 in
private theorem node33
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 33 =
      bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero *
          (bitVecM31 row.imm0 * M31.reduce 16) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node35
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 35 =
      bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero * bitVecM31 row.imm1 := by
  rfl

set_option maxRecDepth 20000 in
private theorem node37
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 37 =
      bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero * bitVecM31 row.imm2 := by
  rfl

set_option maxRecDepth 20000 in
private theorem node19
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 19 =
      (1 : M31) - 1 := by
  rfl

def ConstraintEquations
    (row : LuiRow)
    (witness : Witness row) :
    Prop :=
  bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) = 0 ∧
  bitVecM31 row.rd * witness.destinationInverse -
      boolM31 row.rdNonzero = 0 ∧
  bitVecM31 row.rdNext.limb0 = 0 ∧
  bitVecM31 row.rdNext.limb1 -
      boolM31 row.rdNonzero *
        (bitVecM31 row.imm0 * M31.reduce 16) = 0 ∧
  bitVecM31 row.rdNext.limb2 -
      boolM31 row.rdNonzero * bitVecM31 row.imm1 = 0 ∧
  bitVecM31 row.rdNext.limb3 -
      boolM31 row.rdNonzero * bitVecM31 row.imm2 = 0

theorem constraintsHold_iff
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold = true ↔
      ConstraintEquations row witness := by
  rw [constraintsHold_eq]
  cases flag : row.rdNonzero <;>
    simp [
      flag,
      ConstraintEquations,
      node20,
      node22,
      node24,
      node26,
      node31,
      node33,
      node35,
      node37,
      node19,
      boolM31,
    ]

private theorem constraintsHoldExceptLowLimbEvents
    (nodes : LocalValues) :
    (Programs.luiSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event =>
              if event.ordinal == 4 then true else event.value == 0
          | .lookup _ => true) =
      #[20, 22, 24, 26, 33, 35, 37, 19].all
        (fun root => nodes.getSymbolic root == 0) := by
  simp [Programs.luiSource, Event.evalSymbolic]

theorem constraintsHoldExceptLowLimb_eq
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).constraintsHoldExcept 4 =
      #[20, 22, 24, 26, 33, 35, 37, 19].all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) := by
  exact
    constraintsHoldExceptLowLimbEvents
      (evaluation row witness).nodes

def ConstraintEquationsWithoutLowLimb
    (row : LuiRow)
    (witness : Witness row) :
    Prop :=
  bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) = 0 ∧
  bitVecM31 row.rd * witness.destinationInverse -
      boolM31 row.rdNonzero = 0 ∧
  bitVecM31 row.rdNext.limb1 -
      boolM31 row.rdNonzero *
        (bitVecM31 row.imm0 * M31.reduce 16) = 0 ∧
  bitVecM31 row.rdNext.limb2 -
      boolM31 row.rdNonzero * bitVecM31 row.imm1 = 0 ∧
  bitVecM31 row.rdNext.limb3 -
      boolM31 row.rdNonzero * bitVecM31 row.imm2 = 0

theorem constraintsHoldExceptLowLimb_iff
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).constraintsHoldExcept 4 = true ↔
      ConstraintEquationsWithoutLowLimb row witness := by
  rw [constraintsHoldExceptLowLimb_eq]
  cases flag : row.rdNonzero <;>
    simp [
      flag,
      ConstraintEquationsWithoutLowLimb,
      node20,
      node22,
      node24,
      node26,
      node33,
      node35,
      node37,
      node19,
      boolM31,
    ]

private theorem negOneLive :
    ((-(1 : M31)) != 0) = true := by
  decide

theorem clockRequestHolds
    (row : LuiRow)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (clockLookup row).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) 15 (clockLookup row) fixed
    (clockLookup_projection row witness)

private theorem rangeCheck20RequestHolds_iff
    (value : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal := 15
      domain := .rangeCheck20
      numerator := -(1 : M31)
      tuple := #[value]
      role := .request
      tableId := some .rangeCheck20
      accessOrdinal := some 1
    }) = true ↔ value.val < 2 ^ 20 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    negOneLive,
    ↓reduceIte,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
    decide_eq_true_eq,
  ]

theorem clockRequestHolds_iff
    (row : LuiRow) :
    (clockLookup row).fixedRequestHolds = true ↔
      (clockGapField row).val < 2 ^ 20 :=
  rangeCheck20RequestHolds_iff (clockGapField row)

theorem clockGapBound_of_fixedLookups
    (row : LuiRow)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (clockGapField row).val < 2 ^ 20 :=
  (clockRequestHolds_iff row).mp
    (clockRequestHolds row witness fixed)

private theorem clock_lt_modulus
    (row : LuiRow)
    (admission : Admission row) :
    row.clock < M31.modulus := by
  have := admission.clockBound
  simp [M31.modulus_eq] at *
  omega

private theorem clockSubOne_val
    (row : LuiRow)
    (admission : Admission row) :
    (M31.reduce row.clock - 1).val = row.clock - 1 := by
  have clockBound := clock_lt_modulus row admission
  have clockVal :
      (M31.reduce row.clock).val = row.clock :=
    M31.reduce_val_of_lt row.clock clockBound
  rw [M31.sub_val_of_le]
  · rw [clockVal]
    change row.clock - 1 = row.clock - 1
    rfl
  · rw [clockVal]
    change 1 ≤ row.clock
    have := admission.clockPositive
    omega

private theorem accessClockProduct_val
    (row : LuiRow)
    (admission : Admission row) :
    ((M31.reduce row.clock - 1) * M31.reduce 4).val =
      (row.clock - 1) * 4 := by
  have subVal := clockSubOne_val row admission
  have fourVal : (M31.reduce 4).val = 4 :=
    M31.reduce_val_of_lt 4 (by decide)
  have productBound :
      (M31.reduce row.clock - 1).val *
          (M31.reduce 4).val < M31.modulus := by
    rw [subVal, fourVal]
    have := admission.clockBound
    simp [M31.modulus_eq] at *
    omega
  rw [
    M31.mul_val_of_lt
      (M31.reduce row.clock - 1) (M31.reduce 4) productBound,
    subVal,
    fourVal,
  ]

theorem accessClockField_val
    (row : LuiRow)
    (admission : Admission row) :
    (accessClockField row).val = accessClock row.clock 1 := by
  have productVal := accessClockProduct_val row admission
  have sumBound :
      ((M31.reduce row.clock - 1) * M31.reduce 4).val +
          (1 : M31).val < M31.modulus := by
    rw [productVal]
    change (row.clock - 1) * 4 + 1 < M31.modulus
    have := admission.clockBound
    simp [M31.modulus_eq] at *
    omega
  change
    (((M31.reduce row.clock - 1) * M31.reduce 4) + 1).val =
      (row.clock - 1) * 4 + 1
  rw [
    M31.add_val_of_lt
      ((M31.reduce row.clock - 1) * M31.reduce 4) 1 sumBound,
    productVal,
  ]
  rfl

private theorem validPreviousClock_of_gap
    (previous current : Nat)
    (currentPositive : 0 < current)
    (currentBound : current < 2 ^ 26)
    (previousBound : previous < 2 ^ 26)
    (gapBound :
      (M31.reduce current - M31.reduce previous - 1).val < 2 ^ 20) :
    validPreviousClock previous current := by
  have currentModulusBound : current < M31.modulus := by
    simp [M31.modulus_eq] at *
    omega
  have previousModulusBound : previous < M31.modulus := by
    simp [M31.modulus_eq] at *
    omega
  have currentVal :
      (M31.reduce current).val = current :=
    M31.reduce_val_of_lt current currentModulusBound
  have previousVal :
      (M31.reduce previous).val = previous :=
    M31.reduce_val_of_lt previous previousModulusBound
  have ordered : previous < current := by
    by_cases isOrdered : previous < current
    · exact isOrdered
    have currentLePrevious : current ≤ previous := Nat.le_of_not_gt isOrdered
    rcases Nat.eq_or_lt_of_le currentLePrevious with equal | currentLtPrevious
    · subst previous
      have firstVal :
          (M31.reduce current - M31.reduce current).val = 0 := by
        rw [M31.sub_self]
        rfl
      have secondVal :=
        M31.sub_val_of_lt
          (M31.reduce current - M31.reduce current) 1
          (by
            rw [firstVal]
            change 0 < 1
            omega)
      rw [secondVal, firstVal] at gapBound
      change M31.modulus + 0 - 1 < 2 ^ 20 at gapBound
      simp [M31.modulus_eq] at gapBound
    · have firstVal :=
        M31.sub_val_of_lt
          (M31.reduce current) (M31.reduce previous)
          (by
            rw [currentVal, previousVal]
            exact currentLtPrevious)
      have firstPositive :
          1 ≤ (M31.reduce current - M31.reduce previous).val := by
        rw [firstVal, currentVal, previousVal]
        simp [M31.modulus_eq]
        omega
      have secondVal :=
        M31.sub_val_of_le
          (M31.reduce current - M31.reduce previous) 1
          (by
            change 1 ≤ (M31.reduce current - M31.reduce previous).val
            exact firstPositive)
      rw [secondVal, firstVal, currentVal, previousVal] at gapBound
      change M31.modulus + current - previous - 1 < 2 ^ 20 at gapBound
      simp [M31.modulus_eq] at gapBound
      omega
  constructor
  · exact ordered
  · have firstVal :=
      M31.sub_val_of_le
        (M31.reduce current) (M31.reduce previous)
        (by
          rw [currentVal, previousVal]
          omega)
    have firstPositive :
        1 ≤ (M31.reduce current - M31.reduce previous).val := by
      rw [firstVal, currentVal, previousVal]
      omega
    have secondVal :=
      M31.sub_val_of_le
        (M31.reduce current - M31.reduce previous) 1
        (by
          change 1 ≤ (M31.reduce current - M31.reduce previous).val
          exact firstPositive)
    rw [secondVal, firstVal, currentVal, previousVal] at gapBound
    exact gapBound

theorem destinationClock_of_air
    (row : LuiRow)
    (witness : Witness row)
    (admission : Admission row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 1) := by
  have currentPositive : 0 < accessClock row.clock 1 := by
    simp only [accessClock]
    omega
  have currentBound : accessClock row.clock 1 < 2 ^ 26 := by
    have := admission.clockBound
    simp only [accessClock]
    simp at *
    omega
  have currentModulusBound :
      accessClock row.clock 1 < M31.modulus := by
    simp [M31.modulus_eq] at *
    omega
  have accessClockFieldEq :
      accessClockField row = M31.reduce (accessClock row.clock 1) := by
    apply M31.ext
    rw [
      accessClockField_val row admission,
      M31.reduce_val_of_lt _ currentModulusBound,
    ]
  have gapBound := clockGapBound_of_fixedLookups row witness fixed
  rw [clockGapField, accessClockFieldEq] at gapBound
  exact
    validPreviousClock_of_gap
      row.rdPreviousClock
      (accessClock row.clock 1)
      currentPositive
      currentBound
      admission.destinationPreviousBound
      gapBound

private theorem bitVecM31_injective_of_bounds
    {width : Nat}
    (left right : BitVec width)
    (leftBound : left.toNat < M31.modulus)
    (rightBound : right.toNat < M31.modulus)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right := by
  apply BitVec.eq_of_toNat_eq
  have values := congrArg M31.val equality
  rw [
    bitVecM31_val left leftBound,
    bitVecM31_val right rightBound,
  ] at values
  exact values

private theorem bitVecM31_eq_zero_of_bound
    {width : Nat}
    (value : BitVec width)
    (bound : value.toNat < M31.modulus)
    (equality : bitVecM31 value = 0) :
    value = BitVec.ofNat width 0 := by
  apply
    bitVecM31_injective_of_bounds
      value (BitVec.ofNat width 0) bound (by simp [M31.modulus_eq])
  simpa [bitVecM31] using equality

theorem destinationFlag_of_constraints
    (row : LuiRow)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) := by
  rcases equations with ⟨zeroProduct, inverseProduct, _⟩
  cases flag : row.rdNonzero
  · have rdFieldZero : bitVecM31 row.rd = 0 := by
      simpa [flag, boolM31] using zeroProduct
    have rdBound : row.rd.toNat < M31.modulus := by
      have := row.rd.isLt
      simp [M31.modulus_eq] at *
      omega
    have rdZero :
        row.rd = BitVec.ofNat 5 0 :=
      bitVecM31_eq_zero_of_bound row.rd rdBound rdFieldZero
    simp [zeroRegister, rdZero]
  · have inverseEquality :
        bitVecM31 row.rd * witness.destinationInverse = 1 :=
      (M31.sub_eq_zero_iff _ _).mp (by
        simpa [flag, boolM31] using inverseProduct)
    have rdNonzero : row.rd ≠ zeroRegister := by
      intro rdZero
      rw [rdZero, zeroRegister] at inverseEquality
      have impossible : (0 : M31) = 1 := by
        simpa [bitVecM31] using inverseEquality
      cases impossible
    simp [rdNonzero]

private theorem byteM31Bound
    (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem nibbleM31Bound
    (value : BitVec 4) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byte_eq_of_bitVecM31_eq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  bitVecM31_injective_of_bounds
    left right (byteM31Bound left) (byteM31Bound right) equality

private theorem byte_eq_zero_of_bitVecM31
    (value : Byte)
    (equality : bitVecM31 value = 0) :
    value = BitVec.ofNat 8 0 :=
  bitVecM31_eq_zero_of_bound value (byteM31Bound value) equality

private theorem limb1_eq_of_field
    (result : Byte)
    (immediate : BitVec 4)
    (equation :
      bitVecM31 result -
          (bitVecM31 immediate * M31.reduce 16) = 0) :
    result = immediate.append (BitVec.ofNat 4 0) := by
  have fieldEquality :
      bitVecM31 result =
        bitVecM31 immediate * M31.reduce 16 :=
    (M31.sub_eq_zero_iff _ _).mp equation
  have immediateBound := nibbleM31Bound immediate
  have sixteenVal : (M31.reduce 16).val = 16 :=
    M31.reduce_val_of_lt 16 (by decide)
  have productBound :
      (bitVecM31 immediate).val * (M31.reduce 16).val <
        M31.modulus := by
    rw [bitVecM31_val immediate immediateBound, sixteenVal]
    have := immediate.isLt
    simp [M31.modulus_eq] at *
    omega
  have productVal :=
    M31.mul_val_of_lt
      (bitVecM31 immediate) (M31.reduce 16) productBound
  have values := congrArg M31.val fieldEquality
  rw [
    bitVecM31_val result (byteM31Bound result),
    productVal,
    bitVecM31_val immediate immediateBound,
    sixteenVal,
  ] at values
  apply BitVec.eq_of_toNat_eq
  rw [BitVec.append_eq, toNat_append_arith]
  simp
  omega

theorem destinationLimbs_of_constraints
    (row : LuiRow)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rdNext.limb0 = (
        if row.rdNonzero
        then (luiResultBytes row.imm0 row.imm1 row.imm2).limb0
        else WordBytes.zero.limb0) ∧
    row.rdNext.limb1 = (
        if row.rdNonzero
        then (luiResultBytes row.imm0 row.imm1 row.imm2).limb1
        else WordBytes.zero.limb1) ∧
    row.rdNext.limb2 = (
        if row.rdNonzero
        then (luiResultBytes row.imm0 row.imm1 row.imm2).limb2
        else WordBytes.zero.limb2) ∧
    row.rdNext.limb3 = (
        if row.rdNonzero
        then (luiResultBytes row.imm0 row.imm1 row.imm2).limb3
        else WordBytes.zero.limb3) := by
  rcases equations with
    ⟨_, _, limb0Equation, limb1Equation, limb2Equation, limb3Equation⟩
  have limb0Zero :
      row.rdNext.limb0 = BitVec.ofNat 8 0 :=
    byte_eq_zero_of_bitVecM31 row.rdNext.limb0 limb0Equation
  constructor
  · simpa [luiResultBytes, WordBytes.zero] using limb0Zero
  constructor
  · cases flag : row.rdNonzero
    · have limb1FieldZero :
          bitVecM31 row.rdNext.limb1 = 0 := by
        simpa [flag, boolM31] using limb1Equation
      have limb1Zero :=
        byte_eq_zero_of_bitVecM31 row.rdNext.limb1 limb1FieldZero
      simpa [flag, WordBytes.zero] using limb1Zero
    · have limb1FieldEquation :
          bitVecM31 row.rdNext.limb1 -
              (bitVecM31 row.imm0 * M31.reduce 16) = 0 := by
        simpa [flag, boolM31] using limb1Equation
      have limb1Value :=
        limb1_eq_of_field
          row.rdNext.limb1 row.imm0 limb1FieldEquation
      simpa [flag, luiResultBytes] using limb1Value
  constructor
  · cases flag : row.rdNonzero
    · have limb2FieldZero :
          bitVecM31 row.rdNext.limb2 = 0 := by
        simpa [flag, boolM31] using limb2Equation
      have limb2Zero :=
        byte_eq_zero_of_bitVecM31 row.rdNext.limb2 limb2FieldZero
      simpa [flag, WordBytes.zero] using limb2Zero
    · have limb2FieldEquation :
          bitVecM31 row.rdNext.limb2 = bitVecM31 row.imm1 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31] using limb2Equation)
      have limb2Value :=
        byte_eq_of_bitVecM31_eq
          row.rdNext.limb2 row.imm1 limb2FieldEquation
      simpa [flag, luiResultBytes] using limb2Value
  · cases flag : row.rdNonzero
    · have limb3FieldZero :
          bitVecM31 row.rdNext.limb3 = 0 := by
        simpa [flag, boolM31] using limb3Equation
      have limb3Zero :=
        byte_eq_zero_of_bitVecM31 row.rdNext.limb3 limb3FieldZero
      simpa [flag, WordBytes.zero] using limb3Zero
    · have limb3FieldEquation :
          bitVecM31 row.rdNext.limb3 = bitVecM31 row.imm2 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31] using limb3Equation)
      have limb3Value :=
        byte_eq_of_bitVecM31_eq
          row.rdNext.limb3 row.imm2 limb3FieldEquation
      simpa [flag, luiResultBytes] using limb3Value

structure Acceptance
    (row : LuiRow)
    (witness : Witness row) : Prop where
  selectors :
    (evaluation row witness).activeSelectorsAccepted = true
  constraints :
    (evaluation row witness).constraintsHold = true
  fixedLookups :
    (evaluation row witness).fixedLookupsHold = true

def interpretedRow (row : LuiRow) : LuiRow :=
  { row with claimedNextPc := nextPc row.pc }

theorem sound
    (row : LuiRow)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    LuiHolds (interpretedRow row) := by
  have equations :
      ConstraintEquations row witness :=
    (constraintsHold_iff row witness).mp accepted.constraints
  have destinationFlag :=
    destinationFlag_of_constraints row witness equations
  rcases destinationLimbs_of_constraints row witness equations with
    ⟨limb0, limb1, limb2, limb3⟩
  refine {
    clockPositive := ?_
    destinationClock := ?_
    destinationFlag := ?_
    destinationLimb0 := ?_
    destinationLimb1 := ?_
    destinationLimb2 := ?_
    destinationLimb3 := ?_
    nextPcResult := ?_
  }
  · simpa [interpretedRow] using admission.clockPositive
  · simpa [interpretedRow] using
      destinationClock_of_air
        row witness admission accepted.fixedLookups
  · simpa [interpretedRow] using destinationFlag
  · simpa [interpretedRow] using limb0
  · simpa [interpretedRow] using limb1
  · simpa [interpretedRow] using limb2
  · simpa [interpretedRow] using limb3
  · rfl

private def immediateLookupAt
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 12
  domain := .rangeCheck884
  numerator := nodes.getSymbolic 50
  tuple := #[
    nodes.getSymbolic 14,
    nodes.getSymbolic 15,
    nodes.getSymbolic 13
  ]
  role := .request
  tableId := some .rangeCheck884
  accessOrdinal := none

private def clockLookupAt
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 15
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 50
  tuple := #[nodes.getSymbolic 43]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

private theorem fixedLookupsHoldEvents
    (nodes : LocalValues) :
    (Programs.luiSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((immediateLookupAt nodes).fixedRequestHolds &&
        (clockLookupAt nodes).fixedRequestHolds) := by
  simp [
    Programs.luiSource,
    Event.evalSymbolic,
    immediateLookupAt,
    clockLookupAt,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.fixedMembership,
  ]

set_option maxRecDepth 20000 in
private theorem immediateLookupAt_evaluation
    (row : LuiRow)
    (witness : Witness row) :
    immediateLookupAt (evaluation row witness).nodes =
      immediateLookup row := by
  simp only [evaluation]
  reduce_lui_lookup

set_option maxRecDepth 20000 in
private theorem clockLookupAt_evaluation
    (row : LuiRow)
    (witness : Witness row) :
    clockLookupAt (evaluation row witness).nodes =
      clockLookup row := by
  simp only [evaluation]
  reduce_lui_lookup

theorem fixedLookupsHold_eq
    (row : LuiRow)
    (witness : Witness row) :
    (evaluation row witness).fixedLookupsHold =
      ((immediateLookup row).fixedRequestHolds &&
        (clockLookup row).fixedRequestHolds) := by
  rw [SymbolicEvaluation.fixedLookupsHold]
  change
    (Programs.luiSource.events.map
      (Event.evalSymbolic (evaluation row witness).nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((immediateLookup row).fixedRequestHolds &&
        (clockLookup row).fixedRequestHolds)
  rw [fixedLookupsHoldEvents]
  rw [
    immediateLookupAt_evaluation row witness,
    clockLookupAt_evaluation row witness,
  ]

def zeroRow (zeroDestination : Bool) : LuiRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rd := if zeroDestination then zeroRegister else BitVec.ofNat 5 1
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := WordBytes.zero
  imm0 := BitVec.ofNat 4 0
  imm1 := BitVec.ofNat 8 0
  imm2 := BitVec.ofNat 8 0
  rdNonzero := !zeroDestination
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

def zeroWitness
    (zeroDestination : Bool) :
    Witness (zeroRow zeroDestination) where
  destinationInverse := if zeroDestination then 0 else 1

theorem zeroAdmission
    (zeroDestination : Bool) :
    Admission (zeroRow zeroDestination) := by
  constructor <;> simp [zeroRow]

set_option maxRecDepth 20000 in
theorem zeroAcceptance
    (zeroDestination : Bool) :
    Acceptance (zeroRow zeroDestination) (zeroWitness zeroDestination) := by
  refine {
    selectors :=
      selectorAccepted
        (zeroRow zeroDestination)
        (zeroWitness zeroDestination)
    constraints := ?_
    fixedLookups := ?_
  }
  · apply
      (constraintsHold_iff
        (zeroRow zeroDestination)
        (zeroWitness zeroDestination)).mpr
    cases zeroDestination <;>
      simp [
        ConstraintEquations,
        zeroRow,
        zeroWitness,
        zeroRegister,
        boolM31,
        bitVecM31,
        WordBytes.zero,
      ]
  · rw [fixedLookupsHold_eq]
    simp [
      immediateLookup,
      clockLookup,
      EvaluatedLookup.fixedRequestHolds,
      EvaluatedLookup.fixedMembership,
      EvaluatedLookup.isLive,
      FixedTableId.contains,
      clockGapField,
      accessClockField,
      zeroRow,
      bitVecM31,
      WordBytes.zero,
      M31.toNat,
    ] <;> decide

def exampleRow : LuiRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rd := BitVec.ofNat 5 1
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := WordBytes.zero
  imm0 := BitVec.ofNat 4 0
  imm1 := BitVec.ofNat 8 0
  imm2 := BitVec.ofNat 8 0
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

def exampleWitness : Witness exampleRow where
  destinationInverse := 1

theorem exampleAdmission : Admission exampleRow := by
  constructor <;> decide

set_option maxRecDepth 20000 in
theorem exampleAcceptance : Acceptance exampleRow exampleWitness := by
  refine {
    selectors := selectorAccepted exampleRow exampleWitness
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff exampleRow exampleWitness).mpr
    simp [
      ConstraintEquations,
      exampleRow,
      exampleWitness,
      boolM31,
      bitVecM31,
      WordBytes.zero,
    ]
  · rw [fixedLookupsHold_eq]
    decide

theorem acceptance_nonvacuous :
    ∃ (row : LuiRow) (witness : Witness row),
      Admission row ∧ Acceptance row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance⟩

end Lui

end RiscvRefinement.Air.Bridge
