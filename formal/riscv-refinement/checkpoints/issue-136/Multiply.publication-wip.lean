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

set_option maxRecDepth 20000 in
theorem mul_exactTupleProjection
    (row : Row)
    (witness : Witness row) :
    ExactTupleProjection row witness := by
  exact {
    program := rfl
    stateConsume := rfl
    stateEmit := rfl
    sourceOneConsume := rfl
    sourceOneEmit := rfl
    sourceTwoConsume := rfl
    sourceTwoEmit := rfl
    destinationConsume := rfl
    destinationEmit := by congr 1
    projectionMetadata := ⟨rfl, rfl, rfl, rfl, rfl⟩
  }

set_option maxRecDepth 20000 in
theorem mul_exactFixedProjection
    (row : Row)
    (witness : Witness row) :
    ExactFixedProjection row witness := by
  exact {
    sourceOneClock := rfl
    sourceTwoClock := rfl
    carry0 := rfl
    carry1 := rfl
    carry2 := rfl
    carry3 := rfl
    destinationClock := by congr 1
  }

theorem mul_programIdentity :
    Programs.mul.source.schemaVersion = 2 ∧
      Programs.mul.source.family = .mul ∧
      Programs.mul.source.opcodeSelector.manifestId = 37 ∧
      Programs.mul.source.opcodeSelector.mnemonic = "mul" ∧
      Programs.mul.source.contentDigest =
        "e6ebc8ea809ed36e6e161ea0e4db802c659559076051841d97b95f2bbb5320c6" ∧
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
          "e6ebc8ea809ed36e6e161ea0e4db802c659559076051841d97b95f2bbb5320c6"
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
  have accepted := direct
  simp [
    evaluation,
    Programs.mul,
    Programs.mulSource,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    SymbolicEvaluation.constraintsHold,
    Event.evalSymbolic,
    columns,
  ] at accepted
  rcases accepted with
    ⟨_destinationBit, destinationZero, destinationInverse,
      destination0, destination1, destination2, destination3,
      sourceOne0, sourceOne1, sourceOne2, sourceOne3,
      sourceTwo0, sourceTwo1, sourceTwo2, sourceTwo3⟩
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

def normalize (row : Row) : Row where
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
  carry0 := BitVec.ofNat 11 (carryField0 row).val
  carry1 := BitVec.ofNat 11 (carryField1 row).val
  carry2 := BitVec.ofNat 11 (carryField2 row).val
  carry3 := BitVec.ofNat 11 (carryField3 row).val
  rdNonzero := row.rdNonzero
  claimedNextPc := nextPc row.pc

private theorem normalizedCarry0
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).carry0.toNat = (carryField0 row).val := by
  simp [normalize, BitVec.toNat_ofNat, Nat.mod_eq_of_lt fixed.carry0Bound]

private theorem normalizedCarry1
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).carry1.toNat = (carryField1 row).val := by
  simp [normalize, BitVec.toNat_ofNat, Nat.mod_eq_of_lt fixed.carry1Bound]

private theorem normalizedCarry2
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).carry2.toNat = (carryField2 row).val := by
  simp [normalize, BitVec.toNat_ofNat, Nat.mod_eq_of_lt fixed.carry2Bound]

private theorem normalizedCarry3
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).carry3.toNat = (carryField3 row).val := by
  simp [normalize, BitVec.toNat_ofNat, Nat.mod_eq_of_lt fixed.carry3Bound]

private theorem productLimb0_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).rs1Next.limb0.toNat *
        (normalize row).rs2Next.limb0.toNat =
      (normalize row).result.limb0.toNat +
        256 * (normalize row).carry0.toNat := by
  change
    row.rs1Next.limb0.toNat * row.rs2Next.limb0.toNat =
      row.result.limb0.toNat + 256 * (normalize row).carry0.toNat
  rw [normalizedCarry0 row fixed]
  apply MulhDiv.carryEquationOfField
  · have leftBound := row.rs1Next.limb0.isLt
    have rightBound := row.rs2Next.limb0.isLt
    simp only [Nat.reducePow] at leftBound rightBound
    rw [M31.modulus_eq]
    omega
  · simpa only [Nat.reducePow] using row.result.limb0.isLt
  · exact fixed.carry0Bound
  · simpa [
      carryField0,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
    ]

private theorem productLimb1_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).carry0.toNat +
          (normalize row).rs1Next.limb1.toNat *
            (normalize row).rs2Next.limb0.toNat +
          (normalize row).rs1Next.limb0.toNat *
            (normalize row).rs2Next.limb1.toNat =
      (normalize row).result.limb1.toNat +
        256 * (normalize row).carry1.toNat := by
  change
    (normalize row).carry0.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb0.toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb1.toNat =
      row.result.limb1.toNat + 256 * (normalize row).carry1.toNat
  rw [normalizedCarry0 row fixed, normalizedCarry1 row fixed]
  have carry0Image :
      carryField0 row = M31.reduce (carryField0 row).val := by
    exact (M31.reduce_toNat (carryField0 row)).symm
  apply MulhDiv.carryEquationOfField
  · have c := fixed.carry0Bound
    have a := row.rs1Next.limb1.isLt
    have b := row.rs2Next.limb0.isLt
    have d := row.rs1Next.limb0.isLt
    have e := row.rs2Next.limb1.isLt
    simp only [Nat.reducePow] at c a b d e
    rw [M31.modulus_eq]
    omega
  · simpa only [Nat.reducePow] using row.result.limb1.isLt
  · exact fixed.carry1Bound
  · simpa [
      carryField1,
      carry0Image,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

private theorem productLimb2_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).carry1.toNat +
          (normalize row).rs1Next.limb2.toNat *
            (normalize row).rs2Next.limb0.toNat +
          (normalize row).rs1Next.limb1.toNat *
            (normalize row).rs2Next.limb1.toNat +
          (normalize row).rs1Next.limb0.toNat *
            (normalize row).rs2Next.limb2.toNat =
      (normalize row).result.limb2.toNat +
        256 * (normalize row).carry2.toNat := by
  change
    (normalize row).carry1.toNat +
          row.rs1Next.limb2.toNat * row.rs2Next.limb0.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb1.toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb2.toNat =
      row.result.limb2.toNat + 256 * (normalize row).carry2.toNat
  rw [normalizedCarry1 row fixed, normalizedCarry2 row fixed]
  have carry1Image :
      carryField1 row = M31.reduce (carryField1 row).val := by
    exact (M31.reduce_toNat (carryField1 row)).symm
  apply MulhDiv.carryEquationOfField
  · have c := fixed.carry1Bound
    have a0 := row.rs1Next.limb2.isLt
    have b0 := row.rs2Next.limb0.isLt
    have a1 := row.rs1Next.limb1.isLt
    have b1 := row.rs2Next.limb1.isLt
    have a2 := row.rs1Next.limb0.isLt
    have b2 := row.rs2Next.limb2.isLt
    simp only [Nat.reducePow] at c a0 b0 a1 b1 a2 b2
    rw [M31.modulus_eq]
    omega
  · simpa only [Nat.reducePow] using row.result.limb2.isLt
  · exact fixed.carry2Bound
  · simpa [
      carryField2,
      carry1Image,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

private theorem productLimb3_of_acceptance
    (row : Row)
    (fixed : FixedConsequences row) :
    (normalize row).carry2.toNat +
          (normalize row).rs1Next.limb3.toNat *
            (normalize row).rs2Next.limb0.toNat +
          (normalize row).rs1Next.limb2.toNat *
            (normalize row).rs2Next.limb1.toNat +
          (normalize row).rs1Next.limb1.toNat *
            (normalize row).rs2Next.limb2.toNat +
          (normalize row).rs1Next.limb0.toNat *
            (normalize row).rs2Next.limb3.toNat =
      (normalize row).result.limb3.toNat +
        256 * (normalize row).carry3.toNat := by
  change
    (normalize row).carry2.toNat +
          row.rs1Next.limb3.toNat * row.rs2Next.limb0.toNat +
          row.rs1Next.limb2.toNat * row.rs2Next.limb1.toNat +
          row.rs1Next.limb1.toNat * row.rs2Next.limb2.toNat +
          row.rs1Next.limb0.toNat * row.rs2Next.limb3.toNat =
      row.result.limb3.toNat + 256 * (normalize row).carry3.toNat
  rw [normalizedCarry2 row fixed, normalizedCarry3 row fixed]
  have carry2Image :
      carryField2 row = M31.reduce (carryField2 row).val := by
    exact (M31.reduce_toNat (carryField2 row)).symm
  apply MulhDiv.carryEquationOfField
  · have c := fixed.carry2Bound
    have a0 := row.rs1Next.limb3.isLt
    have b0 := row.rs2Next.limb0.isLt
    have a1 := row.rs1Next.limb2.isLt
    have b1 := row.rs2Next.limb1.isLt
    have a2 := row.rs1Next.limb1.isLt
    have b2 := row.rs2Next.limb2.isLt
    have a3 := row.rs1Next.limb0.isLt
    have b3 := row.rs2Next.limb3.isLt
    simp only [Nat.reducePow] at c a0 b0 a1 b1 a2 b2 a3 b3
    rw [M31.modulus_eq]
    omega
  · simpa only [Nat.reducePow] using row.result.limb3.isLt
  · exact fixed.carry3Bound
  · simpa [
      carryField3,
      carry2Image,
      bitVecM31,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]

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
    MulHolds (normalize row) := by
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
    productLimb0 := productLimb0_of_acceptance row fixed
    productLimb1 := productLimb1_of_acceptance row fixed
    productLimb2 := productLimb2_of_acceptance row fixed
    productLimb3 := productLimb3_of_acceptance row fixed
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

def normalizeEnvironment
    (row : Row)
    (environment : Opcodes.MulEnvironment row) :
    Opcodes.MulEnvironment (normalize row) where
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
    MulHolds (normalize row) ∧
      Opcodes.MulRefinement
        (normalize row) (normalizeEnvironment row environment) ∧
      ExactTupleProjection row witness ∧
      ExactFixedProjection row witness := by
  have holds :=
    mul_acceptedAir_implies_holds
      row witness relationHolds accepted admission
  exact ⟨holds,
    Opcodes.mul_refines
      (normalize row) (normalizeEnvironment row environment) holds,
    mul_exactTupleProjection row witness,
    mul_exactFixedProjection row witness⟩

theorem mul_exactRetirement
    (row : Row)
    (witness : Witness row)
    (environment : Opcodes.MulEnvironment row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted : Acceptance row witness relationHolds)
    (admission : Admission row) :
    mulRetirement (normalize row) =
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
    SelectorAdmission ∧
      MulHolds (normalize row) ∧
      mulRetirement (normalize row) =
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
