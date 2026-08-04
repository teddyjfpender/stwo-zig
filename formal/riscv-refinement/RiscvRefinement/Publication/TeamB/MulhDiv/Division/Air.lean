import RiscvRefinement.Publication.TeamB.MulhDiv.Common

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated

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

def bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  M31.reduce value.toNat

def boolM31 : Bool → M31
  | false => 0
  | true => 1

def activeField (row : Row) : M31 :=
  boolM31 row.isDiv + boolM31 row.isDivu +
    boolM31 row.isRem + boolM31 row.isRemu

def opcodeField (row : Row) : M31 :=
  boolM31 row.isDiv * M31.reduce 41 +
    boolM31 row.isDivu * M31.reduce 42 +
    boolM31 row.isRem * M31.reduce 43 +
    boolM31 row.isRemu * M31.reduce 44

def program : Selector → LocalProgram
  | .div => Programs.div
  | .divu => Programs.divu
  | .rem => Programs.rem
  | .remu => Programs.remu

theorem programEventsShared (selector : Selector) :
    (program selector).source.events = Programs.divSource.events := by
  cases selector <;> rfl

theorem programNodesShared (selector : Selector) :
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

theorem evaluationNodesShared
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

def accessClockField (row : Row) (ordinal : Nat) : M31 :=
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

def registerConsume
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

def registerEmit
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

def difficultTupleOrdinals : List Nat :=
  [79, 80, 81, 82, 83, 85, 86, 101, 102]

def difficultTupleRawLookup : Nat → LookupEvent
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

def expectedDifficultTupleLookup (row : Row) : Nat → EvaluatedLookup
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
theorem difficultTupleRawLookup_selected
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

def evaluatedSelectedLookup
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

def sourceOneConsumeRawLookup : LookupEvent where

  ordinal := 82
  domain := .memoryAccess
  numerator := 388
  tuple := #[91, 12, 17, 13, 14, 15, 16]
  role := .consume
  tableId := none
  liveness := .nonzeroNumerator
  accessOrdinal := some 1

theorem sourceOneConsumeRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[82]? =
      some (.lookup sourceOneConsumeRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
theorem sourceOneConsumeProjectionAt
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

def sourceOneEmitRawLookup : LookupEvent where
  ordinal := 83
  domain := .memoryAccess
  numerator := 70
  tuple := #[91, 12, 405, 18, 19, 20, 21]
  role := .emit
  tableId := none
  liveness := .nonzeroNumerator
  accessOrdinal := some 1

theorem sourceOneEmitRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[83]? =
      some (.lookup sourceOneEmitRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
theorem sourceOneEmitProjectionAt
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

theorem selectedLookupProjection
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
theorem evaluatedEarlyTupleLookups
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
theorem evaluatedDifficultTupleLookups
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

theorem difficultTupleProjectionAt
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

theorem exactTupleProjectionFor
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
theorem divExactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection .div row witness := by
  exact exactTupleProjectionFor .div row witness

set_option maxRecDepth 30000 in
theorem divuExactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection .divu row witness := by
  exact exactTupleProjectionFor .divu row witness

set_option maxRecDepth 30000 in
theorem remExactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection .rem row witness := by
  exact exactTupleProjectionFor .rem row witness

set_option maxRecDepth 30000 in
theorem remuExactTupleProjection
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

def clockGapField
    (row : Row) (ordinal previous : Nat) : M31 :=
  accessClockField row ordinal - M31.reduce previous - M31.reduce 1

def clockLookup
    (row : Row)
    (ordinal eventOrdinal previous : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck20
  numerator := -activeField row
  tuple := #[clockGapField row ordinal previous]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some ordinal

def quotientHighField (row : Row) : M31 :=
  boolM31 row.qSign * M31.reduce 255

def divisorHighField (row : Row) : M31 :=
  boolM31 row.cSign * M31.reduce 255

def dividendHighField (row : Row) : M31 :=
  boolM31 row.bSign * M31.reduce 255

def remainderHighField (row : Row) : M31 :=
  boolM31 row.bSign * (1 - boolM31 row.rZero) * M31.reduce 255

def carry0Field (row : Row) : M31 :=
  (bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb0 +
      bitVecM31 row.remainder.limb0 -
      bitVecM31 row.rs1Next.limb0) * M31.reduce 8388608

def carry1Field (row : Row) : M31 :=
  (carry0Field row +
        bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb1 +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb1 -
      bitVecM31 row.rs1Next.limb1) * M31.reduce 8388608

def carry2Field (row : Row) : M31 :=
  (carry1Field row +
        bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb2 +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb1 +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb2 -
      bitVecM31 row.rs1Next.limb2) * M31.reduce 8388608

def carry3Field (row : Row) : M31 :=
  (carry2Field row +
        bitVecM31 row.rs2Next.limb0 * bitVecM31 row.quotient.limb3 +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb2 +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb1 +
        bitVecM31 row.rs2Next.limb3 * bitVecM31 row.quotient.limb0 +
        bitVecM31 row.remainder.limb3 -
      bitVecM31 row.rs1Next.limb3) * M31.reduce 8388608

def carry4Field (row : Row) : M31 :=
  (carry3Field row +
        bitVecM31 row.rs2Next.limb0 * quotientHighField row +
        bitVecM31 row.rs2Next.limb1 * bitVecM31 row.quotient.limb3 +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb2 +
        bitVecM31 row.rs2Next.limb3 * bitVecM31 row.quotient.limb1 +
        divisorHighField row * bitVecM31 row.quotient.limb0 +
        remainderHighField row -
      dividendHighField row) * M31.reduce 8388608

def carry5Field (row : Row) : M31 :=
  (carry4Field row +
        (bitVecM31 row.rs2Next.limb0 + bitVecM31 row.rs2Next.limb1) *

          quotientHighField row +
        bitVecM31 row.rs2Next.limb2 * bitVecM31 row.quotient.limb3 +
        bitVecM31 row.rs2Next.limb3 * bitVecM31 row.quotient.limb2 +
        divisorHighField row *
          (bitVecM31 row.quotient.limb0 + bitVecM31 row.quotient.limb1) +
        remainderHighField row -
      dividendHighField row) * M31.reduce 8388608

def carry6Field (row : Row) : M31 :=
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

def carry7Field (row : Row) : M31 :=
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

def wordSumField (bytes : WordBytes) : M31 :=
  bitVecM31 bytes.limb0 + bitVecM31 bytes.limb1 +
    bitVecM31 bytes.limb2 + bitVecM31 bytes.limb3

def wordSumNat (bytes : WordBytes) : Nat :=
  bytes.limb0.toNat + bytes.limb1.toNat +
    bytes.limb2.toNat + bytes.limb3.toNat

def divisorSumField (row : Row) : M31 :=
  wordSumField row.rs2Next

def remainderSumField (row : Row) : M31 :=
  wordSumField row.remainder

def quotientSumField (row : Row) : M31 :=
  wordSumField row.quotient

def specialField (row : Row) : M31 :=
  boolM31 row.zeroDivisor + boolM31 row.rZero

def divisionField (row : Row) : M31 :=
  boolM31 row.isDiv + boolM31 row.isDivu

def negCarry0Field (row : Row) : M31 :=
  (bitVecM31 row.remainder.limb0 +
      bitVecM31 row.remainderAbs.limb0) * M31.reduce 8388608

def negCarry1Field (row : Row) : M31 :=
  (negCarry0Field row +
      bitVecM31 row.remainder.limb1 +
      bitVecM31 row.remainderAbs.limb1) * M31.reduce 8388608

def negCarry2Field (row : Row) : M31 :=
  (negCarry1Field row +
      bitVecM31 row.remainder.limb2 +
      bitVecM31 row.remainderAbs.limb2) * M31.reduce 8388608

def negCarry3Field (row : Row) : M31 :=
  (negCarry2Field row +
      bitVecM31 row.remainder.limb3 +
      bitVecM31 row.remainderAbs.limb3) * M31.reduce 8388608

def compareDiffField
    (row : Row)
    (divisor absolute : Byte) : M31 :=
  (1 - boolM31 row.cSign * M31.reduce 2) *
    (bitVecM31 divisor - bitVecM31 absolute)

def prefix3Field (row : Row) : M31 :=
  specialField row + boolM31 row.ltMarker3

def prefix2Field (row : Row) : M31 :=
  prefix3Field row + boolM31 row.ltMarker2

def prefix1Field (row : Row) : M31 :=
  prefix2Field row + boolM31 row.ltMarker1

def prefix0Field (row : Row) : M31 :=
  prefix1Field row + boolM31 row.ltMarker0

def resultLimbField
    (row : Row)
    (quotient remainder : Byte) : M31 :=
  divisionField row * bitVecM31 quotient +
    (1 - divisionField row) * bitVecM31 remainder

def bytePairLookup
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

def carryLookup
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

def signedField (row : Row) : M31 :=
  boolM31 row.isDiv + boolM31 row.isRem

def quotientSignActiveField (row : Row) : M31 :=
  signedField row * (activeField row - boolM31 row.zeroDivisor) -
    boolM31 row.bSign * boolM31 row.cSign

def quotientSignLookup (row : Row) : EvaluatedLookup where
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

def signRangeLookup (row : Row) : EvaluatedLookup where
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

def positiveDiffLookup (row : Row) : EvaluatedLookup where
  ordinal := 100
  domain := .rangeCheck20
  numerator :=
    -(activeField row -
      (boolM31 row.zeroDivisor + boolM31 row.rZero))
  tuple := #[M31.reduce row.ltDiff - M31.reduce 1]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

def difficultFixedOrdinals : List Nat :=
  [84, 87, 88, 89, 90, 91, 92, 93,
    94, 95, 96, 97, 98, 99, 100, 103]

def difficultFixedRawLookup : Nat → LookupEvent
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

def expectedDifficultFixedLookup (row : Row) : Nat → EvaluatedLookup
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
theorem difficultFixedRawLookup_selected
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

theorem selectedFixedLookupProjection
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
theorem evaluatedFixedLookupsA
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
theorem evaluatedFixedLookupsB
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
theorem evaluatedFixedLookupsC
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
theorem evaluatedDifficultFixedLookups
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

theorem difficultFixedProjectionAt
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

def carrySixRawLookup : LookupEvent where
  ordinal := 96
  domain := .rangeCheck811
  numerator := 388
  tuple := #[40, 196]
  role := .request
  tableId := some .rangeCheck811
  liveness := .nonzeroNumerator
  accessOrdinal := none

theorem carrySixRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[96]? =
      some (.lookup carrySixRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
theorem carrySixProjectionAt
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

def carrySevenRawLookup : LookupEvent where
  ordinal := 97
  domain := .rangeCheck811
  numerator := 388
  tuple := #[41, 203]
  role := .request
  tableId := some .rangeCheck811
  liveness := .nonzeroNumerator
  accessOrdinal := none

theorem carrySevenRawLookup_selected
    (selector : Selector) :
    (program selector).source.events[97]? =
      some (.lookup carrySevenRawLookup) := by
  rw [programEventsShared]
  rfl

set_option maxRecDepth 30000 in
theorem carrySevenProjectionAt
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

theorem exactFixedProjectionFor
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
theorem divExactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection .div row witness := by
  exact exactFixedProjectionFor .div row witness

set_option maxRecDepth 30000 in
theorem divuExactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection .divu row witness := by
  exact exactFixedProjectionFor .divu row witness

set_option maxRecDepth 30000 in
theorem remExactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection .rem row witness := by
  exact exactFixedProjectionFor .rem row witness

set_option maxRecDepth 30000 in
theorem remuExactFixedProjection
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
theorem constraintsHoldEvents
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

/-!
Large generated DIV nodes are projected one edge at a time.  These lemmas
avoid asking the elaborator to normalize the entire 422-node DAG merely to
recognize one late constraint root.
-/

theorem evalAllSymbolic_append
    (row : Nat → M31)
    (before after : List LocalExprNode)
    (values : List M31) :
    LocalExprNode.evalAllSymbolic row (before ++ after) values =
      LocalExprNode.evalAllSymbolic row after
        (LocalExprNode.evalAllSymbolic row before values) := by
  induction before generalizing values with
  | nil => rfl
  | cons node tail induction =>
      simp only [List.cons_append, LocalExprNode.evalAllSymbolic]
      exact induction (LocalExprNode.evalSymbolic row values node :: values)

theorem newestValueSymbolic_evalAllSymbolic
    (row : Nat → M31)
    (nodes : List LocalExprNode)
    (values : List M31)
    (offset : Nat) :
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic row nodes values)
        (nodes.length + offset) =
      newestValueSymbolic values offset := by
  induction nodes generalizing values offset with
  | nil => simp [LocalExprNode.evalAllSymbolic]
  | cons node tail induction =>
      simp only [LocalExprNode.evalAllSymbolic, List.length_cons]
      rw [
        show tail.length + 1 + offset =
            tail.length + (offset + 1) by omega,
        induction,
      ]
      rfl

set_option maxRecDepth 30000 in
theorem getSymbolic_eq_prefix
    (row : Row)
    (witness : Witness row)
    (index : Nat)
    (bound : index < Programs.div.nodes.length) :
    (baseEvaluation row witness).nodes.getSymbolic index =
      newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness)
          (Programs.div.nodes.take (index + 1))
          [])
        0 := by
  change
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness) Programs.div.nodes [])
        (Programs.div.nodes.length - index - 1) =
      _
  have offset :
      (Programs.div.nodes.take (index + 1) ++
            Programs.div.nodes.drop (index + 1)).length -
            index - 1 =
        (Programs.div.nodes.drop (index + 1)).length + 0 := by
    simp only [List.length_append, List.length_take, List.length_drop]
    omega
  calc
    newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness) Programs.div.nodes [])
          (Programs.div.nodes.length - index - 1) =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.div.nodes.take (index + 1) ++
              Programs.div.nodes.drop (index + 1))
            [])
          ((Programs.div.nodes.take (index + 1) ++
              Programs.div.nodes.drop (index + 1)).length -
                index - 1) := by
      rw [List.take_append_drop]
    _ =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.div.nodes.take (index + 1))
            [])
          0 := by
      rw [
        evalAllSymbolic_append,
        offset,
        newestValueSymbolic_evalAllSymbolic,
      ]

set_option maxRecDepth 30000 in
theorem newestValueSymbolic_take_eq_getSymbolic
    (row : Row)
    (witness : Witness row)
    (count offset : Nat)
    (offsetBound : offset < count)
    (countBound : count ≤ Programs.div.nodes.length) :
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness)
          (Programs.div.nodes.take count)
          [])
        offset =
      (baseEvaluation row witness).nodes.getSymbolic
        (count - offset - 1) := by
  change
    _ =
      newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness) Programs.div.nodes [])
        (Programs.div.nodes.length -
            (count - offset - 1) - 1)
  have fullOffset :
      (Programs.div.nodes.take count ++
            Programs.div.nodes.drop count).length -
            (count - offset - 1) - 1 =
        (Programs.div.nodes.drop count).length + offset := by
    simp only [List.length_append, List.length_take, List.length_drop]
    omega
  symm
  calc
    newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness) Programs.div.nodes [])
          (Programs.div.nodes.length -
              (count - offset - 1) - 1) =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.div.nodes.take count ++
              Programs.div.nodes.drop count)
            [])
          ((Programs.div.nodes.take count ++
              Programs.div.nodes.drop count).length -
                (count - offset - 1) - 1) := by
      rw [List.take_append_drop]
    _ =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.div.nodes.take count)
            [])
          offset := by
      rw [
        evalAllSymbolic_append,
        fullOffset,
        newestValueSymbolic_evalAllSymbolic,
      ]

theorem getSymbolic_of_selected
    (row : Row)
    (witness : Witness row)
    (index : Nat)
    (node : LocalExprNode)
    (bound : index < Programs.div.nodes.length)
    (selected : Programs.div.nodes[index]? = some node) :
    (baseEvaluation row witness).nodes.getSymbolic index =
      node.evalSymbolic
        (columns row witness)
        (LocalExprNode.evalAllSymbolic
          (columns row witness)
          (Programs.div.nodes.take index)
          []) := by
  rw [getSymbolic_eq_prefix row witness index bound]
  rw [List.take_add_one, selected]
  simp only [
    Option.toList_some,
    evalAllSymbolic_append,
    LocalExprNode.evalAllSymbolic,
    newestValueSymbolic,
  ]

set_option maxRecDepth 10000 in
theorem nodeMulOfAbsolute
    (row : Row) (witness : Witness row)
    (index left right : Nat)
    (leftBefore : left < index)
    (rightBefore : right < index)
    (indexBound : index < Programs.div.nodes.length)
    (selected :
      Programs.div.nodes[index]? =
        some (.mul (index - left - 1) (index - right - 1))) :
    (baseEvaluation row witness).nodes.getSymbolic index =
      (baseEvaluation row witness).nodes.getSymbolic left *
        (baseEvaluation row witness).nodes.getSymbolic right := by
  have leftIndex : index - (index - left - 1) - 1 = left := by omega
  have rightIndex : index - (index - right - 1) - 1 = right := by omega
  rw [getSymbolic_of_selected row witness index
    (.mul (index - left - 1) (index - right - 1)) indexBound selected]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic row witness index
      (index - left - 1) (by omega) (by omega),
    newestValueSymbolic_take_eq_getSymbolic row witness index
      (index - right - 1) (by omega) (by omega),
    leftIndex,
    rightIndex,
  ]

set_option maxRecDepth 10000 in
theorem nodeSubOfAbsolute
    (row : Row) (witness : Witness row)
    (index left right : Nat)
    (leftBefore : left < index)
    (rightBefore : right < index)
    (indexBound : index < Programs.div.nodes.length)
    (selected :
      Programs.div.nodes[index]? =
        some (.sub (index - left - 1) (index - right - 1))) :
    (baseEvaluation row witness).nodes.getSymbolic index =
      (baseEvaluation row witness).nodes.getSymbolic left -
        (baseEvaluation row witness).nodes.getSymbolic right := by
  have leftIndex : index - (index - left - 1) - 1 = left := by omega
  have rightIndex : index - (index - right - 1) - 1 = right := by omega
  rw [getSymbolic_of_selected row witness index
    (.sub (index - left - 1) (index - right - 1)) indexBound selected]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic row witness index
      (index - left - 1) (by omega) (by omega),
    newestValueSymbolic_take_eq_getSymbolic row witness index
      (index - right - 1) (by omega) (by omega),
    leftIndex,
    rightIndex,
  ]

set_option maxRecDepth 10000 in
theorem nodeAddOfAbsolute
    (row : Row) (witness : Witness row)
    (index left right : Nat)
    (leftBefore : left < index)
    (rightBefore : right < index)
    (indexBound : index < Programs.div.nodes.length)
    (selected :
      Programs.div.nodes[index]? =
        some (.add (index - left - 1) (index - right - 1))) :
    (baseEvaluation row witness).nodes.getSymbolic index =
      (baseEvaluation row witness).nodes.getSymbolic left +
        (baseEvaluation row witness).nodes.getSymbolic right := by
  have leftIndex : index - (index - left - 1) - 1 = left := by omega
  have rightIndex : index - (index - right - 1) - 1 = right := by omega
  rw [getSymbolic_of_selected row witness index
    (.add (index - left - 1) (index - right - 1)) indexBound selected]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic row witness index
      (index - left - 1) (by omega) (by omega),
    newestValueSymbolic_take_eq_getSymbolic row witness index
      (index - right - 1) (by omega) (by omega),
    leftIndex,
    rightIndex,
  ]

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
theorem specialExclusiveEquation
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
theorem sourceOneLimb0Equation
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
theorem directEquationsA
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
theorem directEquationsB
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
opaque directUnsignedDivisorSign
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    (1 - signedField row) * boolM31 row.cSign = 0 := by
  division_root selector, row, witness, direct, 33

set_option maxRecDepth 30000 in
opaque directSignXor
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    activeField row *
      (boolM31 row.signXor - boolM31 row.bSign - boolM31 row.cSign +
        boolM31 row.bSign * boolM31 row.cSign * M31.reduce 2) = 0 := by
  division_root selector, row, witness, direct, 34

set_option maxRecDepth 30000 in
opaque directQuotientSignMatches
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - boolM31 row.zeroDivisor) * quotientSumField row *
      (boolM31 row.qSign - boolM31 row.signXor) = 0 := by
  division_root selector, row, witness, direct, 35

set_option maxRecDepth 30000 in
opaque directQuotientSignImplies
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - boolM31 row.zeroDivisor) *
      (boolM31 row.qSign - boolM31 row.signXor) * boolM31 row.qSign = 0 := by
  division_root selector, row, witness, direct, 36

set_option maxRecDepth 30000 in
opaque directZeroDivisorQuotientSign
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.zeroDivisor *
      (boolM31 row.qSign - signedField row) = 0 := by
  division_root selector, row, witness, direct, 37

set_option maxRecDepth 30000 in
opaque directAbsSame0
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb0 -
        bitVecM31 row.remainder.limb0) = 0 := by
  division_root selector, row, witness, direct, 38

set_option maxRecDepth 10000 in
theorem node45
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 45 =
      boolM31 row.signXor := by
  rw [getSymbolic_of_selected row witness 45 (.column 45)

    (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node67
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 67 = 1 := by
  rw [getSymbolic_of_selected row witness 67 (.const 1)
    (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node38
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 38 =
      bitVecM31 row.remainder.limb0 := by
  rw [getSymbolic_of_selected row witness 38 (.column 38)
    (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node48
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 48 =
      bitVecM31 row.remainderAbs.limb0 := by
  rw [getSymbolic_of_selected row witness 48 (.column 48)
    (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node91
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 91 = 0 := by
  rw [getSymbolic_of_selected row witness 91 (.const 0)
    (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node92
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 92 =
      bitVecM31 row.remainder.limb0 := by
  rw [getSymbolic_of_selected row witness 92 (.add 0 53)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 92 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 92 53 (by decide) (by decide),
    node91,
    node38,
    M31.zero_add,
  ]

set_option maxRecDepth 10000 in
theorem node93
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 93 =
      bitVecM31 row.remainder.limb0 +
        bitVecM31 row.remainderAbs.limb0 := by
  rw [getSymbolic_of_selected row witness 93 (.add 0 44)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 93 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 93 44 (by decide) (by decide),
    node92,
    node48,
  ]

set_option maxRecDepth 10000 in
theorem node94
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 94 =
      M31.reduce 8388608 := by
  rw [getSymbolic_of_selected row witness 94
    (.const (M31.reduce 8388608)) (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node95
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 95 =
      negCarry0Field row := by
  rw [getSymbolic_of_selected row witness 95 (.mul 1 0)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 95 1 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 95 0 (by decide) (by decide),
    node93,
    node94,
  ]
  rfl

macro "division_column_node " theoremName:ident index:num : command =>
  `(set_option maxRecDepth 10000 in
    private theorem $theoremName
        (row : Row) (witness : Witness row) :
        (baseEvaluation row witness).nodes.getSymbolic $index =
          columns row witness $index := by
      rw [getSymbolic_of_selected row witness $index (.column $index)
        (by decide) (by decide)]
      rfl)

division_column_node node39 39
division_column_node node40 40
division_column_node node41 41
division_column_node node30 30
division_column_node node31 31
division_column_node node32 32
division_column_node node33 33
division_column_node node43 43
division_column_node node49 49
division_column_node node50 50
division_column_node node51 51
division_column_node node52 52
division_column_node node53 53
division_column_node node54 54
division_column_node node55 55
division_column_node node56 56
division_column_node node57 57
division_column_node node58 58
division_column_node node59 59
division_column_node node60 60
division_column_node node61 61
division_column_node node62 62
division_column_node node63 63
division_column_node node64 64

set_option maxRecDepth 10000 in
theorem node103
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 103 =
      negCarry1Field row := by
  rw [
    nodeMulOfAbsolute row witness 103 102 94
      (by decide) (by decide) (by decide) (by decide),
    nodeAddOfAbsolute row witness 102 101 49
      (by decide) (by decide) (by decide) (by decide),
    nodeAddOfAbsolute row witness 101 95 39
      (by decide) (by decide) (by decide) (by decide),
    node95,
    node39,
    node49,
    node94,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node111
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 111 =
      negCarry2Field row := by
  rw [
    nodeMulOfAbsolute row witness 111 110 94
      (by decide) (by decide) (by decide) (by decide),
    nodeAddOfAbsolute row witness 110 109 50
      (by decide) (by decide) (by decide) (by decide),
    nodeAddOfAbsolute row witness 109 103 40
      (by decide) (by decide) (by decide) (by decide),
    node103,
    node40,
    node50,
    node94,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node119
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 119 =
      negCarry3Field row := by
  rw [
    nodeMulOfAbsolute row witness 119 118 94
      (by decide) (by decide) (by decide) (by decide),
    nodeAddOfAbsolute row witness 118 117 51
      (by decide) (by decide) (by decide) (by decide),
    nodeAddOfAbsolute row witness 117 111 41
      (by decide) (by decide) (by decide) (by decide),
    node111,
    node41,
    node51,
    node94,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node234
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 234 =
      1 - boolM31 row.signXor := by
  rw [
    nodeSubOfAbsolute row witness 234 67 45
      (by decide) (by decide) (by decide) (by decide),
    node67,
    node45,
  ]

set_option maxRecDepth 10000 in
theorem node296
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 296 =
      M31.reduce 256 := by
  rw [getSymbolic_of_selected row witness 296
    (.const (M31.reduce 256)) (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node72
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 72 =
      specialField row := by
  rw [
    nodeAddOfAbsolute row witness 72 32 33
      (by decide) (by decide) (by decide) (by decide),
    node32, node33,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node82
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 82 = M31.reduce 2 := by
  rw [getSymbolic_of_selected row witness 82
    (.const (M31.reduce 2)) (by decide) (by decide)]
  rfl

set_option maxRecDepth 10000 in
theorem node84
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 84 =
      1 - boolM31 row.cSign * M31.reduce 2 := by
  rw [
    nodeSubOfAbsolute row witness 84 67 83
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 83 43 82
      (by decide) (by decide) (by decide) (by decide),
    node67, node43, node82,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node105
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 105 =
      compareDiffField row row.rs2Next.limb2 row.remainderAbs.limb2 := by
  rw [
    nodeMulOfAbsolute row witness 105 84 104
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 104 30 50
      (by decide) (by decide) (by decide) (by decide),
    node84, node30, node50,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node113
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 113 =
      compareDiffField row row.rs2Next.limb3 row.remainderAbs.limb3 := by
  rw [
    nodeMulOfAbsolute row witness 113 84 112
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 112 31 51
      (by decide) (by decide) (by decide) (by decide),
    node84, node31, node51,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node120
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 120 =
      prefix3Field row := by
  rw [
    nodeAddOfAbsolute row witness 120 72 59
      (by decide) (by decide) (by decide) (by decide),
    node72, node59,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node121
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 121 =
      prefix2Field row := by
  rw [
    nodeAddOfAbsolute row witness 121 120 58
      (by decide) (by decide) (by decide) (by decide),
    node120, node58,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node68
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 68 =
      boolM31 row.isDiv + boolM31 row.isDivu := by
  rw [
    nodeAddOfAbsolute row witness 68 61 62
      (by decide) (by decide) (by decide) (by decide),
    node61, node62,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node69
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 69 =
      boolM31 row.isDiv + boolM31 row.isDivu + boolM31 row.isRem := by
  rw [
    nodeAddOfAbsolute row witness 69 68 63
      (by decide) (by decide) (by decide) (by decide),
    node68, node63,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node70
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 70 = activeField row := by
  rw [
    nodeAddOfAbsolute row witness 70 69 64
      (by decide) (by decide) (by decide) (by decide),
    node69, node64,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node387
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 387 =
      activeField row - 1 := by
  rw [
    nodeSubOfAbsolute row witness 387 70 67
      (by decide) (by decide) (by decide) (by decide),
    node70, node67,
  ]

set_option maxRecDepth 10000 in
theorem node290
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 290 =
      boolM31 row.signXor * negCarry0Field row := by
  rw [getSymbolic_of_selected row witness 290 (.mul 244 194)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 290 244 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 290 194 (by decide) (by decide),
    node45,
    node95,
  ]

set_option maxRecDepth 10000 in
theorem node291
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 291 =
      negCarry0Field row - 1 := by
  rw [getSymbolic_of_selected row witness 291 (.sub 195 223)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 291 195 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 291 223 (by decide) (by decide),
    node95,
    node67,
  ]

set_option maxRecDepth 10000 in
theorem node292
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 292 =
      boolM31 row.signXor * negCarry0Field row *
        (negCarry0Field row - 1) := by
  rw [getSymbolic_of_selected row witness 292 (.mul 1 0)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 292 1 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 292 0 (by decide) (by decide),
    node290,
    node291,
  ]

opaque directNegCarryBool0
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :

    boolM31 row.signXor * negCarry0Field row *
      (negCarry0Field row - 1) = 0 := by
  have root :=
    baseConstraintRootZeroAt selector row witness direct
      ⟨39, by decide⟩
  have root292 :
      (baseEvaluation row witness).nodes.getSymbolic 292 = 0 := by
    simpa [constraintRoots] using root
  rw [node292] at root292
  exact root292

set_option maxRecDepth 10000 in
theorem node293
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 293 =
      1 - negCarry0Field row := by
  rw [getSymbolic_of_selected row witness 293 (.sub 225 197)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 293 225 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 293 197 (by decide) (by decide),
    node67,
    node95,
  ]

set_option maxRecDepth 10000 in
theorem node294
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 294 =
      boolM31 row.signXor * (1 - negCarry0Field row) := by
  rw [getSymbolic_of_selected row witness 294 (.mul 248 0)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 294 248 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 294 0 (by decide) (by decide),
    node45,
    node293,
  ]

set_option maxRecDepth 10000 in
theorem node295
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 295 =
      boolM31 row.signXor * (1 - negCarry0Field row) *
        bitVecM31 row.remainderAbs.limb0 := by
  rw [getSymbolic_of_selected row witness 295 (.mul 0 246)
    (by decide) (by decide)]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 295 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 295 246 (by decide) (by decide),
    node294,
    node48,
  ]

opaque directNegCarryZero0
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor * (1 - negCarry0Field row) *
      bitVecM31 row.remainderAbs.limb0 = 0 := by
  have root :=
    baseConstraintRootZeroAt selector row witness direct
      ⟨40, by decide⟩
  have root295 :
      (baseEvaluation row witness).nodes.getSymbolic 295 = 0 := by
    simpa [constraintRoots] using root
  rw [node295] at root295
  exact root295

theorem directEquationsC
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsC row witness := {
  unsignedDivisorSign := directUnsignedDivisorSign selector row witness direct
  signXor := directSignXor selector row witness direct
  quotientSignMatches :=
    directQuotientSignMatches selector row witness direct
  quotientSignImplies :=
    directQuotientSignImplies selector row witness direct
  zeroDivisorQuotientSign :=
    directZeroDivisorQuotientSign selector row witness direct
  absSame0 := directAbsSame0 selector row witness direct
  negCarryBool0 := directNegCarryBool0 selector row witness direct
  negCarryZero0 := directNegCarryZero0 selector row witness direct
}

set_option maxRecDepth 10000 in
theorem node300
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 300 =
      boolM31 row.signXor *
        ((bitVecM31 row.remainderAbs.limb0 - M31.reduce 256) *
          witness.remainderInverse0 - 1) := by
  rw [
    nodeMulOfAbsolute row witness 300 45 299
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 299 298 67
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 298 297 52
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 297 48 296
      (by decide) (by decide) (by decide) (by decide),
    node45, node48, node296, node52, node67,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node302
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 302 =
      (1 - boolM31 row.signXor) *
        (bitVecM31 row.remainderAbs.limb1 -
          bitVecM31 row.remainder.limb1) := by
  rw [
    nodeMulOfAbsolute row witness 302 234 301
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 301 49 39
      (by decide) (by decide) (by decide) (by decide),
    node234, node49, node39,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node306
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 306 =
      boolM31 row.signXor *
        (negCarry1Field row - negCarry0Field row) *
          (negCarry1Field row - 1) := by
  rw [
    nodeMulOfAbsolute row witness 306 304 305
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 304 45 303
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 303 103 95
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 305 103 67
      (by decide) (by decide) (by decide) (by decide),
    node45, node103, node95, node67,
  ]

set_option maxRecDepth 10000 in
theorem node309
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 309 =
      boolM31 row.signXor * (1 - negCarry1Field row) *
        bitVecM31 row.remainderAbs.limb1 := by
  rw [
    nodeMulOfAbsolute row witness 309 308 49
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 308 45 307
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 307 67 103
      (by decide) (by decide) (by decide) (by decide),
    node45, node67, node103, node49,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node313
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 313 =
      boolM31 row.signXor *
        ((bitVecM31 row.remainderAbs.limb1 - M31.reduce 256) *
          witness.remainderInverse1 - 1) := by
  rw [
    nodeMulOfAbsolute row witness 313 45 312
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 312 311 67
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 311 310 53
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 310 49 296
      (by decide) (by decide) (by decide) (by decide),
    node45, node49, node296, node53, node67,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node315
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 315 =
      (1 - boolM31 row.signXor) *
        (bitVecM31 row.remainderAbs.limb2 -
          bitVecM31 row.remainder.limb2) := by
  rw [
    nodeMulOfAbsolute row witness 315 234 314
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 314 50 40
      (by decide) (by decide) (by decide) (by decide),
    node234, node50, node40,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node319
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 319 =
      boolM31 row.signXor *
        (negCarry2Field row - negCarry1Field row) *
          (negCarry2Field row - 1) := by
  rw [
    nodeMulOfAbsolute row witness 319 317 318
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 317 45 316
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 316 111 103
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 318 111 67
      (by decide) (by decide) (by decide) (by decide),
    node45, node111, node103, node67,
  ]

set_option maxRecDepth 10000 in
theorem node322
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 322 =
      boolM31 row.signXor * (1 - negCarry2Field row) *
        bitVecM31 row.remainderAbs.limb2 := by
  rw [
    nodeMulOfAbsolute row witness 322 321 50
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 321 45 320
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 320 67 111
      (by decide) (by decide) (by decide) (by decide),
    node45, node67, node111, node50,
  ]
  rfl

opaque directNegCarryInverse0
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb0 - M31.reduce 256) *
        witness.remainderInverse0 - 1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨41, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 300 = 0 := by
    simpa [constraintRoots] using root
  rw [node300] at exactRoot
  exact exactRoot

opaque directAbsSame1
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb1 -
        bitVecM31 row.remainder.limb1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨42, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 302 = 0 := by
    simpa [constraintRoots] using root
  rw [node302] at exactRoot
  exact exactRoot

opaque directNegCarryBool1
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor *
      (negCarry1Field row - negCarry0Field row) *
      (negCarry1Field row - 1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨43, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 306 = 0 := by
    simpa [constraintRoots] using root
  rw [node306] at exactRoot
  exact exactRoot

opaque directNegCarryZero1
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor * (1 - negCarry1Field row) *
      bitVecM31 row.remainderAbs.limb1 = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨44, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 309 = 0 := by
    simpa [constraintRoots] using root
  rw [node309] at exactRoot
  exact exactRoot

opaque directNegCarryInverse1
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb1 - M31.reduce 256) *
        witness.remainderInverse1 - 1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨45, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 313 = 0 := by
    simpa [constraintRoots] using root
  rw [node313] at exactRoot
  exact exactRoot

opaque directAbsSame2
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb2 -
        bitVecM31 row.remainder.limb2) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨46, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 315 = 0 := by
    simpa [constraintRoots] using root
  rw [node315] at exactRoot
  exact exactRoot

opaque directNegCarryBool2
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor *
      (negCarry2Field row - negCarry1Field row) *
      (negCarry2Field row - 1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨47, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 319 = 0 := by
    simpa [constraintRoots] using root
  rw [node319] at exactRoot
  exact exactRoot

opaque directNegCarryZero2
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor * (1 - negCarry2Field row) *
      bitVecM31 row.remainderAbs.limb2 = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨48, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 322 = 0 := by
    simpa [constraintRoots] using root
  rw [node322] at exactRoot
  exact exactRoot

theorem directEquationsD
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsD row witness := {
  negCarryInverse0 := directNegCarryInverse0 selector row witness direct
  absSame1 := directAbsSame1 selector row witness direct
  negCarryBool1 := directNegCarryBool1 selector row witness direct
  negCarryZero1 := directNegCarryZero1 selector row witness direct
  negCarryInverse1 := directNegCarryInverse1 selector row witness direct
  absSame2 := directAbsSame2 selector row witness direct
  negCarryBool2 := directNegCarryBool2 selector row witness direct
  negCarryZero2 := directNegCarryZero2 selector row witness direct
}

set_option maxRecDepth 10000 in
theorem node326
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 326 =
      boolM31 row.signXor *
        ((bitVecM31 row.remainderAbs.limb2 - M31.reduce 256) *
          witness.remainderInverse2 - 1) := by
  rw [
    nodeMulOfAbsolute row witness 326 45 325
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 325 324 67
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 324 323 54
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 323 50 296
      (by decide) (by decide) (by decide) (by decide),
    node45, node50, node296, node54, node67,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node328
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 328 =
      (1 - boolM31 row.signXor) *
        (bitVecM31 row.remainderAbs.limb3 -
          bitVecM31 row.remainder.limb3) := by
  rw [
    nodeMulOfAbsolute row witness 328 234 327
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 327 51 41
      (by decide) (by decide) (by decide) (by decide),
    node234, node51, node41,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node332
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 332 =

      boolM31 row.signXor *
        (negCarry3Field row - negCarry2Field row) *
          (negCarry3Field row - 1) := by
  rw [
    nodeMulOfAbsolute row witness 332 330 331
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 330 45 329
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 329 119 111
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 331 119 67
      (by decide) (by decide) (by decide) (by decide),
    node45, node119, node111, node67,
  ]

set_option maxRecDepth 10000 in
theorem node335
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 335 =
      boolM31 row.signXor * (1 - negCarry3Field row) *
        bitVecM31 row.remainderAbs.limb3 := by
  rw [
    nodeMulOfAbsolute row witness 335 334 51
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 334 45 333
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 333 67 119
      (by decide) (by decide) (by decide) (by decide),
    node45, node67, node119, node51,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node339
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 339 =
      boolM31 row.signXor *
        ((bitVecM31 row.remainderAbs.limb3 - M31.reduce 256) *
          witness.remainderInverse3 - 1) := by
  rw [
    nodeMulOfAbsolute row witness 339 45 338
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 338 337 67
      (by decide) (by decide) (by decide) (by decide),
    nodeMulOfAbsolute row witness 337 336 55
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 336 51 296
      (by decide) (by decide) (by decide) (by decide),
    node45, node51, node296, node55, node67,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node341
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 341 =
      (1 - prefix3Field row) *
        compareDiffField row row.rs2Next.limb3 row.remainderAbs.limb3 := by
  rw [
    nodeMulOfAbsolute row witness 341 340 113
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 340 67 120
      (by decide) (by decide) (by decide) (by decide),
    node67, node120, node113,
  ]

set_option maxRecDepth 10000 in
theorem node343
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 343 =
      boolM31 row.ltMarker3 *
        (M31.reduce row.ltDiff -
          compareDiffField row row.rs2Next.limb3 row.remainderAbs.limb3) := by
  rw [
    nodeMulOfAbsolute row witness 343 59 342
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 342 60 113
      (by decide) (by decide) (by decide) (by decide),
    node59, node60, node113,
  ]
  rfl

set_option maxRecDepth 10000 in
theorem node345
    (row : Row) (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 345 =
      (1 - prefix2Field row) *
        compareDiffField row row.rs2Next.limb2 row.remainderAbs.limb2 := by
  rw [
    nodeMulOfAbsolute row witness 345 344 105
      (by decide) (by decide) (by decide) (by decide),
    nodeSubOfAbsolute row witness 344 67 121
      (by decide) (by decide) (by decide) (by decide),
    node67, node121, node105,
  ]

opaque directNegCarryInverse2
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb2 - M31.reduce 256) *
        witness.remainderInverse2 - 1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨49, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 326 = 0 := by
    simpa [constraintRoots] using root
  rw [node326] at exactRoot
  exact exactRoot

opaque directAbsSame3
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - boolM31 row.signXor) *
      (bitVecM31 row.remainderAbs.limb3 -
        bitVecM31 row.remainder.limb3) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨50, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 328 = 0 := by
    simpa [constraintRoots] using root
  rw [node328] at exactRoot
  exact exactRoot

opaque directNegCarryBool3
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor *
      (negCarry3Field row - negCarry2Field row) *
      (negCarry3Field row - 1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨51, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 332 = 0 := by
    simpa [constraintRoots] using root
  rw [node332] at exactRoot
  exact exactRoot

opaque directNegCarryZero3
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor * (1 - negCarry3Field row) *
      bitVecM31 row.remainderAbs.limb3 = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨52, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 335 = 0 := by
    simpa [constraintRoots] using root
  rw [node335] at exactRoot
  exact exactRoot

opaque directNegCarryInverse3
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.signXor *
      ((bitVecM31 row.remainderAbs.limb3 - M31.reduce 256) *
        witness.remainderInverse3 - 1) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨53, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 339 = 0 := by
    simpa [constraintRoots] using root
  rw [node339] at exactRoot
  exact exactRoot

opaque directScanEqual3
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - prefix3Field row) *
      compareDiffField row row.rs2Next.limb3 row.remainderAbs.limb3 = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨54, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 341 = 0 := by
    simpa [constraintRoots] using root
  rw [node341] at exactRoot
  exact exactRoot

opaque directScanMarker3
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    boolM31 row.ltMarker3 *
      (M31.reduce row.ltDiff -
        compareDiffField row row.rs2Next.limb3 row.remainderAbs.limb3) = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨55, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 343 = 0 := by
    simpa [constraintRoots] using root
  rw [node343] at exactRoot
  exact exactRoot

opaque directScanEqual2
    (selector : Selector) (row : Row) (witness : Witness row)
    (direct : (evaluation selector row witness).constraintsHold = true) :
    (1 - prefix2Field row) *
      compareDiffField row row.rs2Next.limb2 row.remainderAbs.limb2 = 0 := by
  have root := baseConstraintRootZeroAt selector row witness direct
    ⟨56, by decide⟩
  have exactRoot : (baseEvaluation row witness).nodes.getSymbolic 345 = 0 := by
    simpa [constraintRoots] using root
  rw [node345] at exactRoot
  exact exactRoot

theorem directEquationsE
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    DirectEquationsE row witness := {
  negCarryInverse2 := directNegCarryInverse2 selector row witness direct
  absSame3 := directAbsSame3 selector row witness direct
  negCarryBool3 := directNegCarryBool3 selector row witness direct
  negCarryZero3 := directNegCarryZero3 selector row witness direct
  negCarryInverse3 := directNegCarryInverse3 selector row witness direct
  scanEqual3 := directScanEqual3 selector row witness direct
  scanMarker3 := directScanMarker3 selector row witness direct
  scanEqual2 := directScanEqual2 selector row witness direct
}

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem directEquationsF
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
theorem directEquationsG
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
theorem directEquationsH
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

theorem directEquations
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

def selectorManifestId : Selector → Nat
  | .div => 41
  | .divu => 42
  | .rem => 43
  | .remu => 44

theorem activeEquation
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (direct :
      (evaluation selector row witness).constraintsHold = true) :
    activeField row - 1 = 0 := by
  have root :=
    baseConstraintRootZeroAt selector row witness direct
      ⟨78, by decide⟩
  have exactRoot :
      (baseEvaluation row witness).nodes.getSymbolic 387 = 0 := by
    simpa [constraintRoots] using root
  rw [node387] at exactRoot
  exact exactRoot

theorem actualOpcodeNode
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

theorem selectedProgramManifestId (selected : Selector) :
    (program selected).source.opcodeSelector.manifestId =
      selectorManifestId selected := by
  cases selected <;> rfl

theorem selectedProgramOpcodeExpression
    (selected : Selector) :
    (program selected).source.opcodeSelector.expression = 399 := by
  cases selected <;> rfl

theorem selectedEvaluationManifestId
    (selected : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selected row witness).manifestId =
      selectorManifestId selected := by
  simp only [evaluation, LocalProgram.evalSymbolic]
  rw [selectedProgramManifestId selected]

theorem selectedEvaluationOpcodeSelector
    (selected : Selector)
    (row : Row)
    (witness : Witness row) :
    (evaluation selected row witness).opcodeSelector =
      (evaluation selected row witness).nodes.getSymbolic 399 := by
  simp only [evaluation, LocalProgram.evalSymbolic]
  rw [selectedProgramOpcodeExpression selected]

theorem selectorManifestImage (selected : Selector) :
    M31.ofNat? (selectorManifestId selected) =
      some (M31.reduce (selectorManifestId selected)) := by
  cases selected <;> rfl

theorem acceptedOpcodeNode
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

theorem opcodeEquation
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

theorem opcodeFieldVal (row : Row) :
    (opcodeField row).val =
      41 * row.isDiv.toNat + 42 * row.isDivu.toNat +
        43 * row.isRem.toNat + 44 * row.isRemu.toNat := by
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu <;>
    simp [opcodeField, boolM31, divFlag, divuFlag, remFlag, remuFlag]
  all_goals decide

theorem selectorManifestVal (selector : Selector) :
    (M31.reduce (selectorManifestId selector)).val =
      selectorManifestId selector := by
  cases selector <;> decide

theorem opcodeNatEquation
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation selector row witness).activeSelectorsAccepted = true) :
    41 * row.isDiv.toNat + 42 * row.isDivu.toNat +
        43 * row.isRem.toNat + 44 * row.isRemu.toNat =
      selectorManifestId selector := by
  have values :=
    congrArg M31.val (opcodeEquation selector row witness active)
  rw [opcodeFieldVal row, selectorManifestVal selector] at values
  exact values

theorem divSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .div row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .div row witness).constraintsHold = true) :
    SelectorConsequences .div row := by
  have opcodeNat := opcodeNatEquation .div row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu
  all_goals simp [selectorManifestId, divFlag, divuFlag,
    remFlag, remuFlag] at opcodeNat
  exact {
    activeOne := by simp [activeField, boolM31, divFlag,
      divuFlag, remFlag, remuFlag]
    selectorUnique := by simp [divFlag, divuFlag, remFlag, remuFlag]
    selected := by simp [divFlag, divuFlag, remFlag, remuFlag]
  }

theorem divuSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .divu row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .divu row witness).constraintsHold = true) :
    SelectorConsequences .divu row := by
  have opcodeNat := opcodeNatEquation .divu row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu
  all_goals simp [selectorManifestId, divFlag, divuFlag,
    remFlag, remuFlag] at opcodeNat
  exact {
    activeOne := by simp [activeField, boolM31, divFlag,
      divuFlag, remFlag, remuFlag]
    selectorUnique := by simp [divFlag, divuFlag, remFlag, remuFlag]
    selected := by simp [divFlag, divuFlag, remFlag, remuFlag]
  }

theorem remSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .rem row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .rem row witness).constraintsHold = true) :
    SelectorConsequences .rem row := by
  have opcodeNat := opcodeNatEquation .rem row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu
  all_goals simp [selectorManifestId, divFlag, divuFlag,
    remFlag, remuFlag] at opcodeNat
  exact {
    activeOne := by simp [activeField, boolM31, divFlag,
      divuFlag, remFlag, remuFlag]
    selectorUnique := by simp [divFlag, divuFlag, remFlag, remuFlag]
    selected := by simp [divFlag, divuFlag, remFlag, remuFlag]
  }

theorem remuSelectorConsequences
    (row : Row)
    (witness : Witness row)
    (active :
      (evaluation .remu row witness).activeSelectorsAccepted = true)
    (direct :
      (evaluation .remu row witness).constraintsHold = true) :
    SelectorConsequences .remu row := by
  have opcodeNat := opcodeNatEquation .remu row witness active
  cases divFlag : row.isDiv <;>
    cases divuFlag : row.isDivu <;>
    cases remFlag : row.isRem <;>
    cases remuFlag : row.isRemu
  all_goals simp [selectorManifestId, divFlag, divuFlag,
    remFlag, remuFlag] at opcodeNat
  exact {
    activeOne := by simp [activeField, boolM31, divFlag,
      divuFlag, remFlag, remuFlag]
    selectorUnique := by simp [divFlag, divuFlag, remFlag, remuFlag]
    selected := by simp [divFlag, divuFlag, remFlag, remuFlag]
  }

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

theorem byteBound (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

theorem byteEqOfFieldEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

theorem byteEqZeroOfField
    (value : Byte)
    (equality : bitVecM31 value = 0) :
    value = 0 := by
  apply byteEqOfFieldEq
  simpa [bitVecM31] using equality

theorem byteEq255OfField
    (value : Byte)
    (equality : bitVecM31 value = M31.reduce 255) :
    value = 255 := by
  apply byteEqOfFieldEq
  simpa [bitVecM31] using equality

theorem gatedByteZero
    (flag : Bool)
    (value : Byte)
    (equation : boolM31 flag * bitVecM31 value = 0) :
    flag = true → value = 0 := by
  intro active
  rw [active] at equation
  simp only [boolM31, M31.one_mul] at equation
  exact byteEqZeroOfField value equation

theorem gatedByte255
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

theorem gatedBytesEqual
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

theorem destinationLimbOfEquation
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

theorem sourceBytesOfEquations
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

theorem specialExclusiveOfEquation
    (row : Row)
    (equation :
      (boolM31 row.zeroDivisor + boolM31 row.rZero) *
          (1 - (boolM31 row.zeroDivisor + boolM31 row.rZero)) = 0) :
    row.zeroDivisor = true → row.rZero = false := by
  intro zeroDivisor
  cases remainder : row.rZero
  · rfl
  · exfalso
    rw [zeroDivisor, remainder] at equation
    exact (by decide :
      (boolM31 true + boolM31 true) *
        (1 - (boolM31 true + boolM31 true)) ≠ 0) equation

theorem sourceOneLimb0OfAcceptance
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
    byteEqOfFieldEq row.rs1Next.limb0 row.rs1Previous.limb0
      ((M31.sub_eq_zero_iff _ _).mp equation)

theorem wordSumNat_lt (bytes : WordBytes) :
    wordSumNat bytes < M31.modulus := by
  have limb0 := bytes.limb0.isLt
  have limb1 := bytes.limb1.isLt
  have limb2 := bytes.limb2.isLt
  have limb3 := bytes.limb3.isLt
  simp only [Nat.reducePow] at limb0 limb1 limb2 limb3
  rw [M31.modulus_eq]
  simp only [wordSumNat]
  omega

theorem wordSumField_eq_reduce (bytes : WordBytes) :
    wordSumField bytes = M31.reduce (wordSumNat bytes) := by
  simp [
    wordSumField,
    wordSumNat,
    bitVecM31,
    Air.Bridge.TeamACommon.reduceAdd,
  ]

theorem wordSumNat_pos
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

theorem wordSumField_ne_zero
    (bytes : WordBytes)
    (nonzero : bytes.value ≠ 0) :
    wordSumField bytes ≠ 0 := by
  rw [wordSumField_eq_reduce]
  intro equality
  have values := congrArg M31.val equality
  rw [M31.reduce_val_of_lt _ (wordSumNat_lt bytes)] at values
  have positive := wordSumNat_pos bytes nonzero
  change wordSumNat bytes = 0 at values
  omega

theorem wordSumField_eq_zero_of_value_eq_zero
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

theorem mulNegOneEqZero
    (value : M31)
    (equation : value * (0 - 1) = 0) :
    value = 0 := by
  have scaled := congrArg (fun result : M31 => result * (0 - 1)) equation
  change (value * (0 - 1)) * (0 - 1) = 0 * (0 - 1) at scaled
  have negOneSquared : (0 - 1 : M31) * (0 - 1) = 1 := by
    decide
  rw [m31MulAssoc, negOneSquared, M31.mul_one, M31.zero_mul] at scaled
  exact scaled


theorem unsignedSignOfEquation
    (signed sign : Bool)
    (equation : (1 - boolM31 signed) * boolM31 sign = 0)
    (unsigned : signed = false) :
    sign = false := by
  revert equation unsigned
  cases signed <;> cases sign <;> decide

theorem signXorOfEquation
    (dividendSign divisorSign signXor : Bool)
    (equation :
      boolM31 signXor - boolM31 dividendSign - boolM31 divisorSign +
        boolM31 dividendSign * boolM31 divisorSign * M31.reduce 2 = 0) :
    signXor = (dividendSign != divisorSign) := by
  revert equation
  cases dividendSign <;> cases divisorSign <;> cases signXor <;>
    decide

theorem quotientSignOfEquation
    (quotientSign signXor : Bool)
    (sum : M31)
    (equation :
      sum * (boolM31 quotientSign - boolM31 signXor) = 0)
    (sumNonzero : sum ≠ 0) :
    quotientSign = signXor := by
  cases quotientSign <;> cases signXor
  · rfl
  · exact False.elim (sumNonzero (mulNegOneEqZero sum equation))
  · simp only [boolM31, M31.sub_zero, M31.mul_one] at equation
    exact False.elim (sumNonzero equation)
  · rfl

theorem quotientSignImpliesOfEquation
    (quotientSign signXor : Bool)
    (equation :
      (boolM31 quotientSign - boolM31 signXor) *
        boolM31 quotientSign = 0) :
    quotientSign = true → signXor = true := by
  revert equation
  cases quotientSign <;> cases signXor <;> decide

theorem zeroDivisorSignOfEquation
    (quotientSign signed : Bool)
    (equation : boolM31 quotientSign - boolM31 signed = 0) :
    quotientSign = signed := by
  revert equation
  cases quotientSign <;> cases signed <;> decide

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
theorem directConsequences
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (selectors : SelectorConsequences selector row)
    (equations : DirectEquations row witness) :
    DirectConsequences row := by
  have selected := selectors.selected
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
    rw [selectors.activeOne] at inverseEquation
    simp [
      specialField,
      boolM31,
      zeroDivisor,
      remainderZero,
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
    exact unsignedSignOfEquation row.isSigned row.bSign
      (by simpa [signedImage] using equations.b.unsignedDividendSign)
      unsigned
  · intro unsigned
    exact unsignedSignOfEquation row.isSigned row.cSign
      (by simpa [signedImage] using equations.c.unsignedDivisorSign)
      unsigned
  · apply signXorOfEquation
    simpa [selectors.activeOne] using equations.c.signXor
  · intro zeroDivisor quotientNonzero
    have sumNonzero :
        quotientSumField row ≠ 0 := by
      exact wordSumField_ne_zero row.quotient quotientNonzero
    apply quotientSignOfEquation row.qSign row.signXor
      (quotientSumField row) _ sumNonzero
    simpa [zeroDivisor, boolM31] using equations.c.quotientSignMatches
  · intro zeroDivisor quotientSign
    apply quotientSignImpliesOfEquation row.qSign row.signXor
    · simpa [zeroDivisor, boolM31] using equations.c.quotientSignImplies
    · exact quotientSign
  · intro zeroDivisor
    apply zeroDivisorSignOfEquation row.qSign row.isSigned
    simpa [zeroDivisor, signedImage, boolM31] using
      equations.c.zeroDivisorQuotientSign
  · have equation := equations.g.destination0
    rw [resultLimbField, divisionImage] at equation
    cases division : row.isDivision <;> simpa [divResultBytes, division] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb0 row.quotient.limb0 row.remainder.limb0
        equation
  · have equation := equations.g.destination1
    rw [resultLimbField, divisionImage] at equation
    cases division : row.isDivision <;> simpa [divResultBytes, division] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb1 row.quotient.limb1 row.remainder.limb1
        equation
  · have equation := equations.g.destination2
    rw [resultLimbField, divisionImage] at equation
    cases division : row.isDivision <;> simpa [divResultBytes, division] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb2 row.quotient.limb2 row.remainder.limb2
        equation
  · have equation := equations.g.destination3
    rw [resultLimbField, divisionImage] at equation
    cases division : row.isDivision <;> simpa [divResultBytes, division] using
      destinationLimbOfEquation
        row.destinationNonzero row.isDivision
        row.rdNext.limb3 row.quotient.limb3 row.remainder.limb3
        equation


end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
