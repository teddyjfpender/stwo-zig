import RiscvRefinement.Air.Generated.Programs
import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Opcodes.Multiply
import RiscvRefinement.Publication.Acceptance
import RiscvRefinement.Publication.TeamB.MulhDiv
import RiscvRefinement.Publication.TeamB.Common
import RiscvRefinement.Publication.Universal

/-!
# Publication bridge for the Team B multiply family

This module starts from the exact committed AIR IR v2 `LocalProgram` rather
than the older reviewed expression-table transcription.  In particular, the
current `mul` program has 39 columns: next-PC, next-clock, access clocks, and
product carries are computed nodes/lookup arguments, not independently
trusted columns.
-/

namespace RiscvRefinement.Publication.TeamB.Multiply

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated

abbrev Row := MulRow

/-- The only `mul` column not represented by the typed semantic row. -/
structure Witness (row : Row) where
  destinationInverse : M31

private def bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  M31.reduce value.toNat

private def boolM31 : Bool → M31
  | false => 0
  | true => 1

/-- Exact 39-column order of `Programs.mulSource`. -/
def columns (row : Row) (witness : Witness row) : Nat → M31
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
  | 13 => bitVecM31 row.rs1
  | 14 => bitVecM31 row.rs1Previous.limb0
  | 15 => bitVecM31 row.rs1Previous.limb1
  | 16 => bitVecM31 row.rs1Previous.limb2
  | 17 => bitVecM31 row.rs1Previous.limb3
  | 18 => M31.reduce row.rs1PreviousClock
  | 19 => bitVecM31 row.rs1Next.limb0
  | 20 => bitVecM31 row.rs1Next.limb1
  | 21 => bitVecM31 row.rs1Next.limb2
  | 22 => bitVecM31 row.rs1Next.limb3
  | 23 => bitVecM31 row.rs2
  | 24 => bitVecM31 row.rs2Previous.limb0
  | 25 => bitVecM31 row.rs2Previous.limb1
  | 26 => bitVecM31 row.rs2Previous.limb2
  | 27 => bitVecM31 row.rs2Previous.limb3
  | 28 => M31.reduce row.rs2PreviousClock
  | 29 => bitVecM31 row.rs2Next.limb0
  | 30 => bitVecM31 row.rs2Next.limb1
  | 31 => bitVecM31 row.rs2Next.limb2
  | 32 => bitVecM31 row.rs2Next.limb3
  | 33 => bitVecM31 row.result.limb0
  | 34 => bitVecM31 row.result.limb1
  | 35 => bitVecM31 row.result.limb2
  | 36 => bitVecM31 row.result.limb3
  | 37 => boolM31 row.rdNonzero
  | 38 => witness.destinationInverse
  | _ => 0

def evaluation (row : Row) (witness : Witness row) : SymbolicEvaluation :=
  Programs.mul.evalSymbolic (columns row witness)

/-- Publication inputs that are genuinely outside one local AIR row. -/
structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourceOnePreviousBound : row.rs1PreviousClock < 2 ^ 26
  sourceTwoPreviousBound : row.rs2PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcBound : row.pc.toNat + 4 < M31.modulus

/--
Acceptance by the exact production interpreter.  Relation requests remain
explicit because local AIR interpretation does not assume global multiset
closure.
-/
abbrev Acceptance
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  Publication.AcceptedProductionEvaluation
    (evaluation row witness) relationHolds

private def rawLookupEvent : Nat → LookupEvent
  | 17 => {
      ordinal := 17, domain := .programAccess, numerator := 101,
      tuple := #[2, 102, 3, 13, 23], role := .request, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 18 => {
      ordinal := 18, domain := .registersState, numerator := 101,
      tuple := #[2, 1], role := .consume, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 19 => {
      ordinal := 19, domain := .registersState, numerator := 0,
      tuple := #[104, 105], role := .emit, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 20 => {
      ordinal := 20, domain := .memoryAccess, numerator := 101,
      tuple := #[109, 13, 18, 14, 15, 16, 17], role := .consume,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 1
    }
  | 21 => {
      ordinal := 21, domain := .memoryAccess, numerator := 0,
      tuple := #[109, 13, 108, 19, 20, 21, 22], role := .emit,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 1
    }
  | 22 => {
      ordinal := 22, domain := .rangeCheck20, numerator := 101,
      tuple := #[111], role := .request, tableId := some .rangeCheck20,
      liveness := .nonzeroNumerator, accessOrdinal := some 1
    }
  | 23 => {
      ordinal := 23, domain := .memoryAccess, numerator := 101,
      tuple := #[109, 23, 28, 24, 25, 26, 27], role := .consume,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 2
    }
  | 24 => {
      ordinal := 24, domain := .memoryAccess, numerator := 0,
      tuple := #[109, 23, 113, 29, 30, 31, 32], role := .emit,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 2
    }
  | 25 => {
      ordinal := 25, domain := .rangeCheck20, numerator := 101,
      tuple := #[115], role := .request, tableId := some .rangeCheck20,
      liveness := .nonzeroNumerator, accessOrdinal := some 2
    }
  | 26 => {
      ordinal := 26, domain := .rangeCheck811, numerator := 101,
      tuple := #[33, 76], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 27 => {
      ordinal := 27, domain := .rangeCheck811, numerator := 101,
      tuple := #[34, 82], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 28 => {
      ordinal := 28, domain := .rangeCheck811, numerator := 101,
      tuple := #[35, 90], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 29 => {
      ordinal := 29, domain := .rangeCheck811, numerator := 101,
      tuple := #[36, 100], role := .request, tableId := some .rangeCheck811,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }
  | 30 => {
      ordinal := 30, domain := .memoryAccess, numerator := 101,
      tuple := #[109, 3, 8, 4, 5, 6, 7], role := .consume,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 3
    }
  | 31 => {
      ordinal := 31, domain := .memoryAccess, numerator := 0,
      tuple := #[109, 3, 117, 9, 10, 11, 12], role := .emit,
      tableId := none, liveness := .nonzeroNumerator,
      accessOrdinal := some 3
    }
  | 32 => {
      ordinal := 32, domain := .rangeCheck20, numerator := 101,
      tuple := #[119], role := .request, tableId := some .rangeCheck20,
      liveness := .nonzeroNumerator, accessOrdinal := some 3
    }
  | ordinal => {
      ordinal, domain := .programAccess, numerator := 0, tuple := #[],
      role := .request, tableId := none,
      liveness := .nonzeroNumerator, accessOrdinal := none
    }

set_option maxRecDepth 30000 in
private theorem rawLookupEvent_selected
    (ordinal : Nat)
    (lower : 17 ≤ ordinal)
    (upper : ordinal ≤ 32) :
    Programs.mul.source.events[ordinal]? =
      some (.lookup (rawLookupEvent ordinal)) := by
  have possibilities :
      ordinal = 17 ∨ ordinal = 18 ∨ ordinal = 19 ∨ ordinal = 20 ∨
      ordinal = 21 ∨ ordinal = 22 ∨ ordinal = 23 ∨ ordinal = 24 ∨
      ordinal = 25 ∨ ordinal = 26 ∨ ordinal = 27 ∨ ordinal = 28 ∨
      ordinal = 29 ∨ ordinal = 30 ∨ ordinal = 31 ∨ ordinal = 32 := by
    omega
  rcases possibilities with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals rfl

private def evaluatedRawLookup
    (row : Row)
    (witness : Witness row)
    (event : LookupEvent) : EvaluatedLookup where
  ordinal := event.ordinal
  domain := event.domain
  numerator :=
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic event.numerator
  tuple :=
    event.tuple.map
      (Programs.mul.evalNodesSymbolic
        (columns row witness)).getSymbolic
  role := event.role
  tableId := event.tableId
  accessOrdinal := event.accessOrdinal

private theorem rawLookupProjection
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (lower : 17 ≤ ordinal)
    (upper : ordinal ≤ 32) :
    (evaluation row witness).lookup? ordinal =
      some (evaluatedRawLookup row witness (rawLookupEvent ordinal)) := by
  unfold evaluation evaluatedRawLookup
  exact
    LocalProgram.lookup?_evalSymbolic_of_event
      Programs.mul (columns row witness) ordinal
      (rawLookupEvent ordinal)
      (rawLookupEvent_selected ordinal lower upper)

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 17
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc, M31.reduce 37, bitVecM31 row.rd,
    bitVecM31 row.rs1, bitVecM31 row.rs2
  ]
  role := .request
  tableId := none
  accessOrdinal := none

private def accessClockField (row : Row) (ordinal : Nat) : M31 :=
  (M31.reduce row.clock - M31.reduce 1) * M31.reduce 4 +
    M31.reduce ordinal

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 18
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 19
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc + M31.reduce 4,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def sourceOneConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 20
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
    bitVecM31 row.rs1Previous.limb0, bitVecM31 row.rs1Previous.limb1,
    bitVecM31 row.rs1Previous.limb2, bitVecM31 row.rs1Previous.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 1

def sourceOneEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 21
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rs1, accessClockField row 1,
    bitVecM31 row.rs1Next.limb0, bitVecM31 row.rs1Next.limb1,
    bitVecM31 row.rs1Next.limb2, bitVecM31 row.rs1Next.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def sourceTwoConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 23
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rs2, M31.reduce row.rs2PreviousClock,
    bitVecM31 row.rs2Previous.limb0, bitVecM31 row.rs2Previous.limb1,
    bitVecM31 row.rs2Previous.limb2, bitVecM31 row.rs2Previous.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 2

def sourceTwoEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 24
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rs2, accessClockField row 2,
    bitVecM31 row.rs2Next.limb0, bitVecM31 row.rs2Next.limb1,
    bitVecM31 row.rs2Next.limb2, bitVecM31 row.rs2Next.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 2

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 30
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rd, M31.reduce row.rdPreviousClock,
    bitVecM31 row.rdPrevious.limb0, bitVecM31 row.rdPrevious.limb1,
    bitVecM31 row.rdPrevious.limb2, bitVecM31 row.rdPrevious.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 3

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 31
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rd, accessClockField row 3,
    bitVecM31 row.rdNext.limb0, bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2, bitVecM31 row.rdNext.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 3

private def clockGapField
    (row : Row)
    (ordinal previous : Nat) : M31 :=
  accessClockField row ordinal - M31.reduce previous - M31.reduce 1

private def carryField0 (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb0 -
      bitVecM31 row.result.limb0) * M31.reduce 8388608

private def carryField1 (row : Row) : M31 :=
  (carryField0 row +
        bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb0 +
        bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb1 -
      bitVecM31 row.result.limb1) * M31.reduce 8388608

private def carryField2 (row : Row) : M31 :=
  (carryField1 row +
        bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb0 +
        bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb1 +
        bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb2 -
      bitVecM31 row.result.limb2) * M31.reduce 8388608

private def carryField3 (row : Row) : M31 :=
  (carryField2 row +
        bitVecM31 row.rs1Next.limb3 * bitVecM31 row.rs2Next.limb0 +
        bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb1 +
        bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb2 +
        bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb3 -
      bitVecM31 row.result.limb3) * M31.reduce 8388608

private def clockLookup
    (row : Row)
    (ordinal eventOrdinal previous : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row ordinal previous]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some ordinal

private def carryLookup
    (ordinal : Nat)
    (result : Byte)
    (carry : M31) : EvaluatedLookup where
  ordinal := ordinal
  domain := .rangeCheck811
  numerator := -(1 : M31)
  tuple := #[bitVecM31 result, carry]
  role := .request
  tableId := some .rangeCheck811
  accessOrdinal := none

private def tupleOrdinals : List Nat :=
  [17, 18, 19, 20, 21, 23, 24, 30, 31]

private def expectedTupleLookup (row : Row) : Nat → EvaluatedLookup
  | 17 => programLookup row
  | 18 => stateConsumeLookup row
  | 19 => stateEmitLookup row
  | 20 => sourceOneConsumeLookup row
  | 21 => sourceOneEmitLookup row
  | 23 => sourceTwoConsumeLookup row
  | 24 => sourceTwoEmitLookup row
  | 30 => destinationConsumeLookup row
  | 31 => destinationEmitLookup row
  | _ => programLookup row

set_option maxRecDepth 30000 in
private theorem node0
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 0 = 1 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node104
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 104 =
        bitVecM31 row.pc + M31.reduce 4 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node105
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 105 =
        M31.reduce row.clock + 1 := by
  rfl

section NodeProjections

set_option maxRecDepth 30000

macro "mul_column_node " theoremName:ident index:num : command =>
  `(@[simp] private theorem $theoremName
      (row : Row) (witness : Witness row) :
      (Programs.mul.evalNodesSymbolic
        (columns row witness)).getSymbolic $index =
          columns row witness $index := by
    rfl)

mul_column_node node1 1
mul_column_node node2 2
mul_column_node node3 3
mul_column_node node4 4
mul_column_node node5 5
mul_column_node node6 6
mul_column_node node7 7
mul_column_node node8 8
mul_column_node node9 9
mul_column_node node10 10
mul_column_node node11 11
mul_column_node node12 12
mul_column_node node13 13
mul_column_node node14 14
mul_column_node node15 15
mul_column_node node16 16
mul_column_node node17 17
mul_column_node node18 18
mul_column_node node19 19
mul_column_node node20 20
mul_column_node node21 21
mul_column_node node22 22
mul_column_node node23 23
mul_column_node node24 24
mul_column_node node25 25
mul_column_node node26 26
mul_column_node node27 27
mul_column_node node28 28
mul_column_node node29 29
mul_column_node node30 30
mul_column_node node31 31
mul_column_node node32 32
mul_column_node node33 33
mul_column_node node34 34
mul_column_node node35 35
mul_column_node node36 36

private theorem node76
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 76 = carryField0 row := by
  rfl

private theorem node82
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 82 = carryField1 row := by
  rfl

private theorem node90
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 90 = carryField2 row := by
  rfl

private theorem node100
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 100 = carryField3 row := by
  rfl

private theorem node101
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 101 = -(1 : M31) := by
  rfl

private theorem node102
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 102 = M31.reduce 37 := by
  rfl

private theorem node108
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 108 =
        accessClockField row 1 := by
  rfl

private theorem node109
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 109 = 0 := by
  rfl

private theorem node111
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 111 =
        clockGapField row 1 row.rs1PreviousClock := by
  rfl

private theorem node113
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 113 =
        accessClockField row 2 := by
  rfl

private theorem node115
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 115 =
        clockGapField row 2 row.rs2PreviousClock := by
  rfl

private theorem node117
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 117 =
        accessClockField row 3 := by
  rfl

private theorem node119
    (row : Row) (witness : Witness row) :
    (Programs.mul.evalNodesSymbolic
      (columns row witness)).getSymbolic 119 =
        clockGapField row 3 row.rdPreviousClock := by
  rfl

end NodeProjections

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_19
    (row : Row) (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 19) =
      expectedTupleLookup row 19 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedTupleLookup, columns,
    stateEmitLookup, node0, node104, node105,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_23
    (row : Row) (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 23) =
      expectedTupleLookup row 23 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedTupleLookup, columns,
    sourceTwoConsumeLookup, node101, node109,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_31
    (row : Row) (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 31) =
      expectedTupleLookup row 31 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedTupleLookup, columns,
    destinationEmitLookup, node0, node109, node117,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_tuple_a
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 17) =
        expectedTupleLookup row 17 ∧
      evaluatedRawLookup row witness (rawLookupEvent 18) =
        expectedTupleLookup row 18 ∧
      evaluatedRawLookup row witness (rawLookupEvent 19) =
        expectedTupleLookup row 19 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedTupleLookup, columns,
    programLookup, stateConsumeLookup, stateEmitLookup,
    node0, node101, node102, node104, node105,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_tuple_b
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 20) =
        expectedTupleLookup row 20 ∧
      evaluatedRawLookup row witness (rawLookupEvent 21) =
        expectedTupleLookup row 21 ∧
      evaluatedRawLookup row witness (rawLookupEvent 23) =
        expectedTupleLookup row 23 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedTupleLookup, columns,
    sourceOneConsumeLookup, sourceOneEmitLookup,
    sourceTwoConsumeLookup, node0, node101, node108, node109,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_tuple_c
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 24) =
        expectedTupleLookup row 24 ∧
      evaluatedRawLookup row witness (rawLookupEvent 30) =
        expectedTupleLookup row 30 ∧
      evaluatedRawLookup row witness (rawLookupEvent 31) =
        expectedTupleLookup row 31 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedTupleLookup, columns,
    sourceTwoEmitLookup, destinationConsumeLookup,
    destinationEmitLookup, node0, node101, node109,
    node113, node117,
  ]

private theorem evaluatedRawLookup_tuple_all
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 17) =
        expectedTupleLookup row 17 ∧
      evaluatedRawLookup row witness (rawLookupEvent 18) =
        expectedTupleLookup row 18 ∧
      evaluatedRawLookup row witness (rawLookupEvent 19) =
        expectedTupleLookup row 19 ∧
      evaluatedRawLookup row witness (rawLookupEvent 20) =
        expectedTupleLookup row 20 ∧
      evaluatedRawLookup row witness (rawLookupEvent 21) =
        expectedTupleLookup row 21 ∧
      evaluatedRawLookup row witness (rawLookupEvent 23) =
        expectedTupleLookup row 23 ∧
      evaluatedRawLookup row witness (rawLookupEvent 24) =
        expectedTupleLookup row 24 ∧
      evaluatedRawLookup row witness (rawLookupEvent 30) =
        expectedTupleLookup row 30 ∧
      evaluatedRawLookup row witness (rawLookupEvent 31) =
        expectedTupleLookup row 31 := by
  obtain ⟨h17, h18, h19⟩ :=
    evaluatedRawLookup_tuple_a row witness
  obtain ⟨h20, h21, h23⟩ :=
    evaluatedRawLookup_tuple_b row witness
  obtain ⟨h24, h30, h31⟩ :=
    evaluatedRawLookup_tuple_c row witness
  exact ⟨h17, h18, h19, h20, h21, h23, h24, h30, h31⟩

private theorem evaluatedRawLookup_tuple
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ tupleOrdinals) :
    evaluatedRawLookup row witness (rawLookupEvent ordinal) =
      expectedTupleLookup row ordinal := by
  obtain ⟨h17, h18, h19, h20, h21, h23, h24, h30, h31⟩ :=
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
  have lower : 17 ≤ ordinal := by
    have choices := member
    simp [tupleOrdinals] at choices
    omega
  have upper : ordinal ≤ 32 := by
    have choices := member
    simp [tupleOrdinals] at choices
    omega
  exact
    (rawLookupProjection row witness ordinal lower upper).trans
      (congrArg some
        (evaluatedRawLookup_tuple row witness ordinal member))

private def fixedOrdinals : List Nat :=
  [22, 25, 26, 27, 28, 29, 32]

private def expectedFixedLookup (row : Row) : Nat → EvaluatedLookup
  | 22 => clockLookup row 1 22 row.rs1PreviousClock
  | 25 => clockLookup row 2 25 row.rs2PreviousClock
  | 26 => carryLookup 26 row.result.limb0 (carryField0 row)
  | 27 => carryLookup 27 row.result.limb1 (carryField1 row)
  | 28 => carryLookup 28 row.result.limb2 (carryField2 row)
  | 29 => carryLookup 29 row.result.limb3 (carryField3 row)
  | 32 => clockLookup row 3 32 row.rdPreviousClock
  | _ => clockLookup row 1 22 row.rs1PreviousClock

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_26
    (row : Row) (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 26) =
      expectedFixedLookup row 26 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedFixedLookup, columns,
    carryLookup, node76, node101,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_28
    (row : Row) (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 28) =
      expectedFixedLookup row 28 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedFixedLookup, columns,
    carryLookup, node90, node101,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_32
    (row : Row) (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 32) =
      expectedFixedLookup row 32 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedFixedLookup, columns,
    clockLookup, node101, node119,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_fixed_a
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 22) =
        expectedFixedLookup row 22 ∧
      evaluatedRawLookup row witness (rawLookupEvent 25) =
        expectedFixedLookup row 25 ∧
      evaluatedRawLookup row witness (rawLookupEvent 26) =
        expectedFixedLookup row 26 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedFixedLookup, columns,
    clockLookup, carryLookup, node76, node101, node111, node115,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_fixed_b
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 27) =
        expectedFixedLookup row 27 ∧
      evaluatedRawLookup row witness (rawLookupEvent 28) =
        expectedFixedLookup row 28 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedFixedLookup, columns,
    carryLookup, node82, node90, node101,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedRawLookup_fixed_c
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 29) =
        expectedFixedLookup row 29 ∧
      evaluatedRawLookup row witness (rawLookupEvent 32) =
        expectedFixedLookup row 32 := by
  simp [
    evaluatedRawLookup, rawLookupEvent, expectedFixedLookup, columns,
    clockLookup, carryLookup, node100, node101, node119,
  ]

private theorem evaluatedRawLookup_fixed_all
    (row : Row)
    (witness : Witness row) :
    evaluatedRawLookup row witness (rawLookupEvent 22) =
        expectedFixedLookup row 22 ∧
      evaluatedRawLookup row witness (rawLookupEvent 25) =
        expectedFixedLookup row 25 ∧
      evaluatedRawLookup row witness (rawLookupEvent 26) =
        expectedFixedLookup row 26 ∧
      evaluatedRawLookup row witness (rawLookupEvent 27) =
        expectedFixedLookup row 27 ∧
      evaluatedRawLookup row witness (rawLookupEvent 28) =
        expectedFixedLookup row 28 ∧
      evaluatedRawLookup row witness (rawLookupEvent 29) =
        expectedFixedLookup row 29 ∧
      evaluatedRawLookup row witness (rawLookupEvent 32) =
        expectedFixedLookup row 32 := by
  obtain ⟨h22, h25, h26⟩ :=
    evaluatedRawLookup_fixed_a row witness
  obtain ⟨h27, h28⟩ := evaluatedRawLookup_fixed_b row witness
  obtain ⟨h29, h32⟩ := evaluatedRawLookup_fixed_c row witness
  exact ⟨h22, h25, h26, h27, h28, h29, h32⟩

private theorem evaluatedRawLookup_fixed
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ fixedOrdinals) :
    evaluatedRawLookup row witness (rawLookupEvent ordinal) =
      expectedFixedLookup row ordinal := by
  obtain ⟨h22, h25, h26, h27, h28, h29, h32⟩ :=
    evaluatedRawLookup_fixed_all row witness
  simp [fixedOrdinals] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals assumption

private theorem fixedProjectionAt
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ fixedOrdinals) :
    (evaluation row witness).lookup? ordinal =
      some (expectedFixedLookup row ordinal) := by
  have lower : 17 ≤ ordinal := by
    have choices := member
    simp [fixedOrdinals] at choices
    omega
  have upper : ordinal ≤ 32 := by
    have choices := member
    simp [fixedOrdinals] at choices
    omega
  exact
    (rawLookupProjection row witness ordinal lower upper).trans
      (congrArg some
        (evaluatedRawLookup_fixed row witness ordinal member))

structure ExactTupleProjection (row : Row) (witness : Witness row) : Prop where
  program :
    (evaluation row witness).lookup? 17 = some (programLookup row)
  stateConsume :
    (evaluation row witness).lookup? 18 = some (stateConsumeLookup row)
  stateEmit :
    (evaluation row witness).lookup? 19 = some (stateEmitLookup row)
  sourceOneConsume :
    (evaluation row witness).lookup? 20 = some (sourceOneConsumeLookup row)
  sourceOneEmit :
    (evaluation row witness).lookup? 21 = some (sourceOneEmitLookup row)
  sourceTwoConsume :
    (evaluation row witness).lookup? 23 = some (sourceTwoConsumeLookup row)
  sourceTwoEmit :
    (evaluation row witness).lookup? 24 = some (sourceTwoEmitLookup row)
  destinationConsume :
    (evaluation row witness).lookup? 30 =
      some (destinationConsumeLookup row)
  destinationEmit :
    (evaluation row witness).lookup? 31 =
      some (destinationEmitLookup row)
  projectionMetadata :
    Programs.mul.source.projection.programEvent = 17 ∧
      Programs.mul.source.projection.stateEvents = #[18, 19] ∧
      Programs.mul.source.projection.sourceEvents = #[20, 21, 23, 24] ∧
      Programs.mul.source.projection.destinationEvents = #[30, 31] ∧
      Programs.mul.source.projection.nextPc = 104

structure ExactFixedProjection (row : Row) (witness : Witness row) : Prop where
  sourceOneClock :
    (evaluation row witness).lookup? 22 =
      some (clockLookup row 1 22 row.rs1PreviousClock)
  sourceTwoClock :
    (evaluation row witness).lookup? 25 =
      some (clockLookup row 2 25 row.rs2PreviousClock)
  carry0 :
    (evaluation row witness).lookup? 26 =
      some (carryLookup 26 row.result.limb0 (carryField0 row))
  carry1 :
    (evaluation row witness).lookup? 27 =
      some (carryLookup 27 row.result.limb1 (carryField1 row))
  carry2 :
    (evaluation row witness).lookup? 28 =
      some (carryLookup 28 row.result.limb2 (carryField2 row))
  carry3 :
    (evaluation row witness).lookup? 29 =
      some (carryLookup 29 row.result.limb3 (carryField3 row))
  destinationClock :
    (evaluation row witness).lookup? 32 =
      some (clockLookup row 3 32 row.rdPreviousClock)

set_option maxRecDepth 30000 in
theorem mul_exactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection row witness := by
  exact {
    program := tupleProjectionAt row witness 17 (by decide)
    stateConsume := tupleProjectionAt row witness 18 (by decide)
    stateEmit := tupleProjectionAt row witness 19 (by decide)
    sourceOneConsume := tupleProjectionAt row witness 20 (by decide)
    sourceOneEmit := tupleProjectionAt row witness 21 (by decide)
    sourceTwoConsume := tupleProjectionAt row witness 23 (by decide)
    sourceTwoEmit := tupleProjectionAt row witness 24 (by decide)
    destinationConsume := tupleProjectionAt row witness 30 (by decide)
    destinationEmit := tupleProjectionAt row witness 31 (by decide)
    projectionMetadata := ⟨rfl, rfl, rfl, rfl, rfl⟩
  }

set_option maxRecDepth 30000 in
theorem mul_exactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection row witness := by
  exact {
    sourceOneClock := fixedProjectionAt row witness 22 (by decide)
    sourceTwoClock := fixedProjectionAt row witness 25 (by decide)
    carry0 := fixedProjectionAt row witness 26 (by decide)
    carry1 := fixedProjectionAt row witness 27 (by decide)
    carry2 := fixedProjectionAt row witness 28 (by decide)
    carry3 := fixedProjectionAt row witness 29 (by decide)
    destinationClock := fixedProjectionAt row witness 32 (by decide)
  }

theorem mul_programIdentity :
    Programs.mul.source.schemaVersion = 2 ∧
      Programs.mul.source.family = .mul ∧
      Programs.mul.source.opcodeSelector.manifestId = 37 ∧
      Programs.mul.source.opcodeSelector.mnemonic = "mul" ∧
      Programs.mul.source.contentDigest =
        "806a22150acdc82df7208d96ff2fb9ec5ff3ad8fd75f8f6b087f1c8f993e09d6" ∧
      Programs.mul.source.columns.size = 39 ∧
      Programs.mul.source.nodes.size = 120 ∧
      Programs.mul.source.events.size = 33 := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

structure SelectorAdmission : Prop where
  manifest :
    Programs.mul.source.opcodeSelector.manifestId =
      TeamB.Selector.manifestId .mul
  mnemonic :
    Programs.mul.source.opcodeSelector.mnemonic =
      TeamB.Selector.mnemonic .mul
  unique :
    ∀ selector : TeamB.Selector,
      TeamB.Selector.manifestId selector =
          Programs.mul.source.opcodeSelector.manifestId →
        selector = .mul
  familyAdmits :
    Programs.mul.source.family.validOpcode
      Programs.mul.source.opcodeSelector.manifestId
      Programs.mul.source.opcodeSelector.mnemonic = true
  universalIdentity :
    Publication.actualProgramIdentities[37]? =
      some {
        manifestId := 37
        mnemonic := "mul"
        family := .mul
        contentDigest :=
          "806a22150acdc82df7208d96ff2fb9ec5ff3ad8fd75f8f6b087f1c8f993e09d6"
      }

theorem mul_selectorAdmission : SelectorAdmission := by
  refine {
    manifest := rfl
    mnemonic := rfl
    unique := ?_
    familyAdmits := by decide
    universalIdentity := ?_
  }
  · intro selector same
    apply TeamB.Selector.manifestId_injective
    simpa using same
  · rw [Publication.exactProductionProgramIdentities]
    rfl

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

def constraintRoots : Array Nat :=
  #[41, 43, 45, 47, 49, 51, 53, 55, 57, 59, 61, 63, 65, 67,
    69, 71, 72]

set_option maxRecDepth 20000 in
private theorem constraintsHoldEvents (nodes : LocalValues) :
    (Programs.mul.source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      constraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  simp [Programs.mul, Programs.mulSource, constraintRoots,
    Event.evalSymbolic]

theorem constraintsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      constraintRoots.all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) :=
  constraintsHoldEvents (evaluation row witness).nodes

theorem constraintRootZeroAt
    (row : Row)
    (witness : Witness row)
    (accepted : (evaluation row witness).constraintsHold = true)
    (index : Fin constraintRoots.size) :
    (evaluation row witness).nodes.getSymbolic
        constraintRoots[index] = 0 := by
  rw [constraintsHold_eq, Array.all_eq_true] at accepted
  have selected := accepted index.1 index.2
  simpa only [beq_iff_eq] using selected

structure DirectConsequences (row : Row) : Prop where
  destinationFlag :
    row.rdNonzero = decide (row.rd ≠ zeroRegister)
  destination :
    row.rdNext =
      if row.rdNonzero then row.result else WordBytes.zero
  sourceOne : row.rs1Next = row.rs1Previous
  sourceTwo : row.rs2Next = row.rs2Previous

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
theorem directConsequences
    (row : Row)
    (witness : Witness row)
    (direct : (evaluation row witness).constraintsHold = true) :
    DirectConsequences row := by
  have destinationZero :=
    constraintRootZeroAt row witness direct ⟨2, by decide⟩
  have destinationInverse :=
    constraintRootZeroAt row witness direct ⟨3, by decide⟩
  have destination0 :=
    constraintRootZeroAt row witness direct ⟨4, by decide⟩
  have destination1 :=
    constraintRootZeroAt row witness direct ⟨5, by decide⟩
  have destination2 :=
    constraintRootZeroAt row witness direct ⟨6, by decide⟩
  have destination3 :=
    constraintRootZeroAt row witness direct ⟨7, by decide⟩
  have sourceOne0 :=
    constraintRootZeroAt row witness direct ⟨8, by decide⟩
  have sourceOne1 :=
    constraintRootZeroAt row witness direct ⟨9, by decide⟩
  have sourceOne2 :=
    constraintRootZeroAt row witness direct ⟨10, by decide⟩
  have sourceOne3 :=
    constraintRootZeroAt row witness direct ⟨11, by decide⟩
  have sourceTwo0 :=
    constraintRootZeroAt row witness direct ⟨12, by decide⟩
  have sourceTwo1 :=
    constraintRootZeroAt row witness direct ⟨13, by decide⟩
  have sourceTwo2 :=
    constraintRootZeroAt row witness direct ⟨14, by decide⟩
  have sourceTwo3 :=
    constraintRootZeroAt row witness direct ⟨15, by decide⟩
  change
    bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) = 0
      at destinationZero
  change
    bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero = 0
      at destinationInverse
  change
    bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb0 = 0
      at destination0
  change
    bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb1 = 0
      at destination1
  change
    bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb2 = 0
      at destination2
  change
    bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb3 = 0
      at destination3
  change
    (1 : M31) *
        (bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0) = 0
      at sourceOne0
  change
    (1 : M31) *
        (bitVecM31 row.rs1Next.limb1 -
          bitVecM31 row.rs1Previous.limb1) = 0
      at sourceOne1
  change
    (1 : M31) *
        (bitVecM31 row.rs1Next.limb2 -
          bitVecM31 row.rs1Previous.limb2) = 0
      at sourceOne2
  change
    (1 : M31) *
        (bitVecM31 row.rs1Next.limb3 -
          bitVecM31 row.rs1Previous.limb3) = 0
      at sourceOne3
  change
    (1 : M31) *
        (bitVecM31 row.rs2Next.limb0 -
          bitVecM31 row.rs2Previous.limb0) = 0
      at sourceTwo0
  change
    (1 : M31) *
        (bitVecM31 row.rs2Next.limb1 -
          bitVecM31 row.rs2Previous.limb1) = 0
      at sourceTwo1
  change
    (1 : M31) *
        (bitVecM31 row.rs2Next.limb2 -
          bitVecM31 row.rs2Previous.limb2) = 0
      at sourceTwo2
  change
    (1 : M31) *
        (bitVecM31 row.rs2Next.limb3 -
          bitVecM31 row.rs2Previous.limb3) = 0
      at sourceTwo3
  simp only [M31.one_mul] at sourceOne0 sourceOne1 sourceOne2 sourceOne3
  simp only [M31.one_mul] at sourceTwo0 sourceTwo1 sourceTwo2 sourceTwo3
  refine {
    destinationFlag :=
      Air.Bridge.TeamACommon.destinationFlag_of_equations
        row.rd row.rdNonzero witness.destinationInverse
        (by simpa [bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31] using destinationZero)
        (by simpa [bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31] using destinationInverse)
    destination :=
      Air.Bridge.TeamACommon.destinationBytes_of_equations
        row.rdNext row.result row.rdNonzero
        (by simpa [bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31] using destination0)
        (by simpa [bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31] using destination1)
        (by simpa [bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31] using destination2)
        (by simpa [bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31] using destination3)
    sourceOne := ?_
    sourceTwo := ?_
  }
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
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation row witness) ordinal
      (clockLookup row accessOrdinal ordinal previous) fixed selected
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      ordinal (some accessOrdinal)
      (clockGapField row accessOrdinal previous)).mp request

private theorem range811BoundsOfLookup
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (result : Byte)
    (carry : M31)
    (fixed : (evaluation row witness).fixedLookupsHold = true)
    (selected :
      (evaluation row witness).lookup? ordinal =
        some (carryLookup ordinal result carry)) :
    (bitVecM31 result).val < 2 ^ 8 ∧ carry.val < 2 ^ 11 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation row witness) ordinal
      (carryLookup ordinal result carry) fixed selected
  have negOneNeZero : -(1 : M31) ≠ 0 := by decide
  simpa [
    carryLookup,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    FixedTableId.rangeCheck811_contains_iff,
    negOneNeZero,
  ] using request

structure FixedConsequences (row : Row) : Prop where
  sourceOneGap :
    (clockGapField row 1 row.rs1PreviousClock).val < 2 ^ 20
  sourceTwoGap :
    (clockGapField row 2 row.rs2PreviousClock).val < 2 ^ 20
  destinationGap :
    (clockGapField row 3 row.rdPreviousClock).val < 2 ^ 20
  carry0Bound : (carryField0 row).val < 2 ^ 11
  carry1Bound : (carryField1 row).val < 2 ^ 11
  carry2Bound : (carryField2 row).val < 2 ^ 11
  carry3Bound : (carryField3 row).val < 2 ^ 11

theorem fixedConsequences
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation row witness).fixedLookupsHold = true) :
    FixedConsequences row := by
  have projection := mul_exactFixedProjection row witness
  exact {
    sourceOneGap :=
      range20BoundOfLookup row witness 22 1 row.rs1PreviousClock
        fixed projection.sourceOneClock
    sourceTwoGap :=
      range20BoundOfLookup row witness 25 2 row.rs2PreviousClock
        fixed projection.sourceTwoClock
    destinationGap :=
      range20BoundOfLookup row witness 32 3 row.rdPreviousClock
        fixed projection.destinationClock
    carry0Bound :=
      (range811BoundsOfLookup row witness 26 row.result.limb0
        (carryField0 row) fixed projection.carry0).2
    carry1Bound :=
      (range811BoundsOfLookup row witness 27 row.result.limb1
        (carryField1 row) fixed projection.carry1).2
    carry2Bound :=
      (range811BoundsOfLookup row witness 28 row.result.limb2
        (carryField2 row) fixed projection.carry2).2
    carry3Bound :=
      (range811BoundsOfLookup row witness 29 row.result.limb3
        (carryField3 row) fixed projection.carry3).2
  }

/-!
## Lifting bounded production nodes to a canonical semantic row

The generated 39-column program computes its four carry nodes and next-PC; it
does not expose those values as input columns.  The reviewed `MulRow`, however,
stores copies of them.  Asking a caller to bind those copies would make the
fixed lookups non-load-bearing, so the publication bridge instead constructs
the unique bounded copies from the accepted production evaluation.
-/

private opaque normalizedCarry0Package
    (row : Row)
    (bound : (carryField0 row).val < 2 ^ 11) :
    { value : BitVec 11 // value.toNat = (carryField0 row).val } :=
  ⟨BitVec.ofNat 11 (carryField0 row).val, by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt bound]⟩

private opaque normalizedCarry1Package
    (row : Row)
    (bound : (carryField1 row).val < 2 ^ 11) :
    { value : BitVec 11 // value.toNat = (carryField1 row).val } :=
  ⟨BitVec.ofNat 11 (carryField1 row).val, by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt bound]⟩

private opaque normalizedCarry2Package
    (row : Row)
    (bound : (carryField2 row).val < 2 ^ 11) :
    { value : BitVec 11 // value.toNat = (carryField2 row).val } :=
  ⟨BitVec.ofNat 11 (carryField2 row).val, by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt bound]⟩

private opaque normalizedCarry3Package
    (row : Row)
    (bound : (carryField3 row).val < 2 ^ 11) :
    { value : BitVec 11 // value.toNat = (carryField3 row).val } :=
  ⟨BitVec.ofNat 11 (carryField3 row).val, by
    simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt bound]⟩

private def normalizedCarry0Value
    (row : Row) (fixed : FixedConsequences row) : BitVec 11 :=
  (normalizedCarry0Package row fixed.carry0Bound).1

private def normalizedCarry1Value
    (row : Row) (fixed : FixedConsequences row) : BitVec 11 :=
  (normalizedCarry1Package row fixed.carry1Bound).1

private def normalizedCarry2Value
    (row : Row) (fixed : FixedConsequences row) : BitVec 11 :=
  (normalizedCarry2Package row fixed.carry2Bound).1

private def normalizedCarry3Value
    (row : Row) (fixed : FixedConsequences row) : BitVec 11 :=
  (normalizedCarry3Package row fixed.carry3Bound).1

def normalize (row : Row) (fixed : FixedConsequences row) : Row where
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
  result := row.result
  carry0 := normalizedCarry0Value row fixed
  carry1 := normalizedCarry1Value row fixed
  carry2 := normalizedCarry2Value row fixed
  carry3 := normalizedCarry3Value row fixed
  rdNonzero := row.rdNonzero
  claimedNextPc := nextPc row.pc

private theorem normalizedCarry0
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row fixed).carry0.toNat = (carryField0 row).val := by
  change (normalizedCarry0Value row fixed).toNat = (carryField0 row).val
  exact (normalizedCarry0Package row fixed.carry0Bound).property

private theorem normalizedCarry1
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row fixed).carry1.toNat = (carryField1 row).val := by
  change (normalizedCarry1Value row fixed).toNat = (carryField1 row).val
  exact (normalizedCarry1Package row fixed.carry1Bound).property

private theorem normalizedCarry2
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row fixed).carry2.toNat = (carryField2 row).val := by
  change (normalizedCarry2Value row fixed).toNat = (carryField2 row).val
  exact (normalizedCarry2Package row fixed.carry2Bound).property

private theorem normalizedCarry3
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row fixed).carry3.toNat = (carryField3 row).val := by
  change (normalizedCarry3Value row fixed).toNat = (carryField3 row).val
  exact (normalizedCarry3Package row fixed.carry3Bound).property

set_option maxRecDepth 30000 in
private theorem normalizePc (row : Row) (fixed : FixedConsequences row) :
    (normalize row fixed).pc = row.pc := rfl

set_option maxRecDepth 30000 in
private theorem normalizeRd (row : Row) (fixed : FixedConsequences row) :
    (normalize row fixed).rd = row.rd := rfl

set_option maxRecDepth 30000 in
private theorem normalizeRs1 (row : Row) (fixed : FixedConsequences row) :
    (normalize row fixed).rs1 = row.rs1 := rfl

set_option maxRecDepth 30000 in
private theorem normalizeRs2 (row : Row) (fixed : FixedConsequences row) :
    (normalize row fixed).rs2 = row.rs2 := rfl

set_option maxRecDepth 30000 in
private theorem normalizeRs1Next (row : Row) (fixed : FixedConsequences row) :
    (normalize row fixed).rs1Next = row.rs1Next := rfl

set_option maxRecDepth 30000 in
private theorem normalizeRs2Next (row : Row) (fixed : FixedConsequences row) :
    (normalize row fixed).rs2Next = row.rs2Next := rfl

set_option maxRecDepth 30000 in
private theorem normalizeResult (row : Row) (fixed : FixedConsequences row) :
    (normalize row fixed).result = row.result := rfl

set_option maxRecDepth 5000 in
private theorem productLimb0_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    row.rs1Next.limb0.toNat * row.rs2Next.limb0.toNat =
      row.result.limb0.toNat + 256 * (carryField0 row).val := by
  apply MulhDiv.carryEquationOfField
  · have leftBound := row.rs1Next.limb0.isLt
    have rightBound := row.rs2Next.limb0.isLt
    simp only [Nat.reducePow] at leftBound rightBound
    have productBound :
        row.rs1Next.limb0.toNat * row.rs2Next.limb0.toNat ≤
          255 * 255 :=
      Nat.mul_le_mul (by omega) (by omega)
    rw [M31.modulus_eq]
    omega
  · simpa only [Nat.reducePow] using row.result.limb0.isLt
  · exact fixed.carry0Bound
  · simpa [
      carryField0,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
    ]

private theorem byteLt256 (value : Byte) : value.toNat < 256 := by
  simpa only [Nat.reducePow] using value.isLt

private theorem byteLe255 (value : Byte) : value.toNat ≤ 255 := by
  have bound := byteLt256 value
  omega

private theorem productLe65025
    (left right : Nat)
    (leftBound : left ≤ 255)
    (rightBound : right ≤ 255) :
    left * right ≤ 65025 := by
  simpa using Nat.mul_le_mul leftBound rightBound

private theorem reduce_val_image (value : M31) :
    M31.reduce value.val = value := by
  simpa only [M31.toNat] using M31.reduce_toNat value

private theorem carryAndTwoProductsLtModulus
    (carry firstProduct secondProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025) :
    carry + firstProduct + secondProduct < M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb1FieldEquation (row : Row) :
    ((M31.reduce
          ((carryField0 row).val +
            row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat +
            row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat) -
        M31.reduce row.result.limb1.toNat) *
      M31.reduce 8388608).val = (carryField1 row).val := by
  have accumulatedImage :
      M31.reduce
          ((carryField0 row).val +
            row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat +
            row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat) =
        carryField0 row +
            bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb0 +
          bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb1 := by
    rw [
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceAdd,
      ← Air.Bridge.TeamACommon.reduceMul,
      ← Air.Bridge.TeamACommon.reduceMul,
      reduce_val_image,
    ]
    rfl
  apply congrArg M31.val
  rw [carryField1, accumulatedImage]
  rfl

set_option maxRecDepth 10000 in
private theorem productLimb1_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (carryField0 row).val +
        row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat =
      row.result.limb1.toNat + 256 * (carryField1 row).val := by
  apply MulhDiv.carryEquationOfField
  · exact carryAndTwoProductsLtModulus _ _ _ fixed.carry0Bound
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb1) (byteLe255 row.rs2Next.limb0))
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb0) (byteLe255 row.rs2Next.limb1))
  · exact byteLt256 row.result.limb1
  · exact fixed.carry1Bound
  · exact productLimb1FieldEquation row

private theorem carryAndThreeProductsLtModulus
    (carry firstProduct secondProduct thirdProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct < M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb2FieldEquation (row : Row) :
    ((M31.reduce
          ((carryField1 row).val +
            row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat) -
        M31.reduce row.result.limb2.toNat) *
      M31.reduce 8388608).val = (carryField2 row).val := by
  have accumulatedImage :
      M31.reduce
          ((carryField1 row).val +
            row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat) =
        carryField1 row +
              bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb0 +
            bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb1 +
          bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb2 := by
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
  rw [carryField2, accumulatedImage]
  rfl

set_option maxRecDepth 10000 in
private theorem productLimb2_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (carryField1 row).val +
        row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat =
      row.result.limb2.toNat + 256 * (carryField2 row).val := by
  apply MulhDiv.carryEquationOfField
  · exact carryAndThreeProductsLtModulus _ _ _ _ fixed.carry1Bound
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb2) (byteLe255 row.rs2Next.limb0))
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb1) (byteLe255 row.rs2Next.limb1))
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb0) (byteLe255 row.rs2Next.limb2))
  · exact byteLt256 row.result.limb2
  · exact fixed.carry2Bound
  · exact productLimb2FieldEquation row

private theorem carryAndFourProductsLtModulus
    (carry firstProduct secondProduct thirdProduct fourthProduct : Nat)
    (carryBound : carry < 2 ^ 11)
    (firstBound : firstProduct ≤ 65025)
    (secondBound : secondProduct ≤ 65025)
    (thirdBound : thirdProduct ≤ 65025)
    (fourthBound : fourthProduct ≤ 65025) :
    carry + firstProduct + secondProduct + thirdProduct + fourthProduct <
      M31.modulus := by
  rw [M31.modulus_eq]
  omega

private theorem productLimb3FieldEquation (row : Row) :
    ((M31.reduce
          ((carryField2 row).val +
            row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat) -
        M31.reduce row.result.limb3.toNat) *
      M31.reduce 8388608).val = (carryField3 row).val := by
  have accumulatedImage :
      M31.reduce
          ((carryField2 row).val +
            row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat +
            row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
            row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
            row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat) =
        carryField2 row +
                bitVecM31 row.rs1Next.limb3 * bitVecM31 row.rs2Next.limb0 +
              bitVecM31 row.rs1Next.limb2 * bitVecM31 row.rs2Next.limb1 +
            bitVecM31 row.rs1Next.limb1 * bitVecM31 row.rs2Next.limb2 +
          bitVecM31 row.rs1Next.limb0 * bitVecM31 row.rs2Next.limb3 := by
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
  rw [carryField3, accumulatedImage]
  rfl

set_option maxRecDepth 10000 in
private theorem productLimb3_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (carryField2 row).val +
        row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat +
        row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
        row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
        row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat =
      row.result.limb3.toNat + 256 * (carryField3 row).val := by
  apply MulhDiv.carryEquationOfField
  · exact carryAndFourProductsLtModulus _ _ _ _ _ fixed.carry2Bound
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb3) (byteLe255 row.rs2Next.limb0))
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb2) (byteLe255 row.rs2Next.limb1))
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb1) (byteLe255 row.rs2Next.limb2))
      (productLe65025 _ _
        (byteLe255 row.rs1Next.limb0) (byteLe255 row.rs2Next.limb3))
  · exact byteLt256 row.result.limb3
  · exact fixed.carry3Bound
  · exact productLimb3FieldEquation row

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

set_option maxRecDepth 5000 in
/--
The reverse bridge missing from the reviewed Team B capsule: an active row
accepted by the exact generated `Programs.mul` evaluator, with its computed
nodes explicitly bound to the typed row, satisfies the complete semantic
`MulHolds` predicate.
-/
theorem mul_acceptedAir_implies_holds
    (row : Row)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance row witness relationHolds)
    (admission : Admission row) :
    MulHolds
      (normalize row
        (fixedConsequences row witness accepted.fixedTableRequests)) := by
  have direct :=
    directConsequences row witness accepted.directConstraints
  have fixed :=
    fixedConsequences row witness accepted.fixedTableRequests
  refine {
    clockPositive := admission.clockPositive
    sourceOneClock :=
      validClock_of_fixed row admission 1 row.rs1PreviousClock
        (by decide) (by decide) admission.sourceOnePreviousBound
        fixed.sourceOneGap
    sourceTwoClock :=
      validClock_of_fixed row admission 2 row.rs2PreviousClock
        (by decide) (by decide) admission.sourceTwoPreviousBound
        fixed.sourceTwoGap
    destinationClock :=
      validClock_of_fixed row admission 3 row.rdPreviousClock
        (by decide) (by decide) admission.destinationPreviousBound
        fixed.destinationGap
    sourceOneLimb0 := by
      simpa [normalize] using congrArg WordBytes.limb0 direct.sourceOne
    sourceOneLimb1 := by
      simpa [normalize] using congrArg WordBytes.limb1 direct.sourceOne
    sourceOneLimb2 := by
      simpa [normalize] using congrArg WordBytes.limb2 direct.sourceOne
    sourceOneLimb3 := by
      simpa [normalize] using congrArg WordBytes.limb3 direct.sourceOne
    sourceTwoLimb0 := by
      simpa [normalize] using congrArg WordBytes.limb0 direct.sourceTwo
    sourceTwoLimb1 := by
      simpa [normalize] using congrArg WordBytes.limb1 direct.sourceTwo
    sourceTwoLimb2 := by
      simpa [normalize] using congrArg WordBytes.limb2 direct.sourceTwo
    sourceTwoLimb3 := by
      simpa [normalize] using congrArg WordBytes.limb3 direct.sourceTwo
    productLimb0 := by
      simpa only [normalizeRs1Next, normalizeRs2Next, normalizeResult,
        normalizedCarry0 row fixed] using
        productLimb0_of_acceptance row fixed
    productLimb1 := by
      simpa only [normalizeRs1Next, normalizeRs2Next, normalizeResult,
        normalizedCarry0 row fixed, normalizedCarry1 row fixed] using
        productLimb1_of_acceptance row fixed
    productLimb2 := by
      simpa only [normalizeRs1Next, normalizeRs2Next, normalizeResult,
        normalizedCarry1 row fixed, normalizedCarry2 row fixed] using
        productLimb2_of_acceptance row fixed
    productLimb3 := by
      simpa only [normalizeRs1Next, normalizeRs2Next, normalizeResult,
        normalizedCarry2 row fixed, normalizedCarry3 row fixed] using
        productLimb3_of_acceptance row fixed
    destinationFlag := by simpa [normalize] using direct.destinationFlag
    destinationLimb0 := by
      cases flag : row.rdNonzero <;>
        simpa [normalize, flag] using
          congrArg WordBytes.limb0 direct.destination
    destinationLimb1 := by
      cases flag : row.rdNonzero <;>
        simpa [normalize, flag] using
          congrArg WordBytes.limb1 direct.destination
    destinationLimb2 := by
      cases flag : row.rdNonzero <;>
        simpa [normalize, flag] using
          congrArg WordBytes.limb2 direct.destination
    destinationLimb3 := by
      cases flag : row.rdNonzero <;>
        simpa [normalize, flag] using
          congrArg WordBytes.limb3 direct.destination
    nextPcResult := rfl
  }

set_option maxRecDepth 5000 in
def normalizeEnvironment
    (row : Row)
    (fixed : FixedConsequences row)
    (environment : Opcodes.MulEnvironment row) :
    Opcodes.MulEnvironment (normalize row fixed) where
  pre := environment.pre
  pcBinds := by simpa [normalize] using environment.pcBinds
  sourceOneBinds := by
    simpa [normalize] using environment.sourceOneBinds
  sourceTwoBinds := by
    simpa [normalize] using environment.sourceTwoBinds
  destinationBinds := by
    simpa [normalize] using environment.destinationBinds

/--
Publication-level FV-2 theorem for manifest selector 37.  Its premise contains
the complete production acceptance record (active, direct, every fixed request,
and every live non-fixed relation), explicit admission/bindings, and the
register/program environment.  Its conclusion includes both the exact
retirement refinement and the exact ordered production-event projection.
-/
theorem mul_acceptedAir_refines
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.MulEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance row witness relationHolds)
    (admission : Admission row) :
    let fixed :=
      fixedConsequences row witness accepted.fixedTableRequests
    MulHolds (normalize row fixed) ∧
      Opcodes.MulRefinement
        (normalize row fixed) (normalizeEnvironment row fixed environment) ∧
      ExactTupleProjection row witness ∧
      ExactFixedProjection row witness := by
  dsimp only
  let fixed :=
    fixedConsequences row witness accepted.fixedTableRequests
  have holds :=
    mul_acceptedAir_implies_holds
      row witness relationHolds accepted admission
  change MulHolds (normalize row fixed) at holds
  exact ⟨holds,
    Opcodes.mul_refines
      (normalize row fixed) (normalizeEnvironment row fixed environment) holds,
    mul_exactTupleProjection row witness,
    mul_exactFixedProjection row witness⟩

theorem mul_exactRetirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.MulEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance row witness relationHolds)
    (admission : Admission row) :
    let fixed :=
      fixedConsequences row witness accepted.fixedTableRequests
    mulRetirement (normalize row fixed) =
      Sail.Reviewed.executeMul
        environment.pre.pc
        (environment.pre.registers row.rs1)
        (environment.pre.registers row.rs2)
        row.rd :=
  (mul_acceptedAir_refines
    row witness environment relationHolds accepted admission).2.1.retirement

/--
Stable publication theorem identity consumed by the Team B inventory and the
cross-project Sail composition layer.
-/
theorem mul_accepted_air_implies_retirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.MulEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance row witness relationHolds)
    (admission : Admission row) :
    let fixed :=
      fixedConsequences row witness accepted.fixedTableRequests
    SelectorAdmission ∧
      MulHolds (normalize row fixed) ∧
      mulRetirement (normalize row fixed) =
        Sail.Reviewed.executeMul
          environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2)
          row.rd ∧
      ExactTupleProjection row witness ∧
      ExactFixedProjection row witness ∧
      (∀ lookup,
        lookup ∈
            (Programs.mul.evalSymbolic
              (columns row witness)).liveLookups →
          lookup.tableId = none →
          relationHolds lookup) := by
  have published :=
    mul_acceptedAir_refines
      row witness environment relationHolds accepted admission
  exact ⟨mul_selectorAdmission, published.1,
    published.2.1.retirement, published.2.2.1, published.2.2.2,
    accepted.liveRelations⟩

end RiscvRefinement.Publication.TeamB.Multiply
