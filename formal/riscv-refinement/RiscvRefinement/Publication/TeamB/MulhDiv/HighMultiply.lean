import RiscvRefinement.Publication.TeamB.MulhDiv.Common

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated

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
        "3b14ad48cc6a791aec8963128a38c6397ff52a4cdf99839a40d0cd326782d489" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem mulhsu_programIdentity :
    Programs.mulhsu.source.opcodeSelector.manifestId = 39 ∧
      Programs.mulhsu.source.opcodeSelector.mnemonic = "mulhsu" ∧
      Programs.mulhsu.source.family = .mulh ∧
      Programs.mulhsu.source.contentDigest =
        "890244c6d80ee3ab146fec5d8d32f15d152c64658ed03ee49c9cdf807d421eaa" :=
  ⟨rfl, rfl, rfl, rfl⟩

theorem mulhu_programIdentity :
    Programs.mulhu.source.opcodeSelector.manifestId = 40 ∧
      Programs.mulhu.source.opcodeSelector.mnemonic = "mulhu" ∧
      Programs.mulhu.source.family = .mulh ∧
      Programs.mulhu.source.contentDigest =
        "e4a0c26eac2c45390d08a38ac632f2c10a8719041ebd54293e11449dc75859f3" :=
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
      "3b14ad48cc6a791aec8963128a38c6397ff52a4cdf99839a40d0cd326782d489" := by
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
      "890244c6d80ee3ab146fec5d8d32f15d152c64658ed03ee49c9cdf807d421eaa" := by
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
      "e4a0c26eac2c45390d08a38ac632f2c10a8719041ebd54293e11449dc75859f3" := by
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
        "3b14ad48cc6a791aec8963128a38c6397ff52a4cdf99839a40d0cd326782d489" ∧
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
        "890244c6d80ee3ab146fec5d8d32f15d152c64658ed03ee49c9cdf807d421eaa" ∧
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
        "e4a0c26eac2c45390d08a38ac632f2c10a8719041ebd54293e11449dc75859f3" ∧
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

end RiscvRefinement.Publication.TeamB.MulhDiv
