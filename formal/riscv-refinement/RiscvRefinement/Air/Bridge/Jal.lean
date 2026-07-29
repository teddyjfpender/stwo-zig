import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Bridge.DecodeTeamA

/-!
# Production JAL AIR bridge

This module evaluates the exact generated `jal` program.  The J immediate is
kept as its canonical 21-bit two's-complement encoding (with the architectural
low zero bit), so the program tuple and the state-emission target are derived
from the same value that canonical decode recovers.
-/

namespace RiscvRefinement.Air.Bridge.Jal

open RiscvRefinement
open RiscvRefinement.Air.Generated

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

def immediate (encoded : BitVec 20) : BitVec 21 :=
  Decode.jalImmediate encoded

def immediateFieldValue (encoded : BitVec 20) : Nat :=
  let value := immediate encoded
  if value.msb
  then M31.modulus + value.toNat - 2 ^ 21
  else value.toNat

def immediateField (encoded : BitVec 20) : M31 :=
  M31.reduce (immediateFieldValue encoded)

def jumpTarget (pc : Word) (encoded : BitVec 20) : Word :=
  pc + BitVec.signExtend 32 (immediate encoded)

structure Row where
  clock : Nat
  pc : Word
  rd : RegisterIndex
  rdPrevious : WordBytes
  rdPreviousClock : Nat
  rdNext : WordBytes
  immediateEncoded : BitVec 20
  result : WordBytes
  rdNonzero : Bool
deriving DecidableEq, Repr

structure Witness (row : Row) where
  destinationInverse : M31

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
  | 13 => immediateField row.immediateEncoded
  | 14 => bitVecM31 row.result.limb0
  | 15 => bitVecM31 row.result.limb1
  | 16 => bitVecM31 row.result.limb2
  | 17 => bitVecM31 row.result.limb3
  | 18 => boolM31 row.rdNonzero
  | 19 => witness.destinationInverse
  | _ => 0

def evaluation (row : Row) (witness : Witness row) :
    SymbolicEvaluation :=
  Programs.jal.evalSymbolic (columns row witness)

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  linkBound : row.pc.toNat + 4 < M31.modulus
  targetNoWrap :
    if (immediate row.immediateEncoded).msb
    then
      2 ^ 21 - (immediate row.immediateEncoded).toNat ≤
        row.pc.toNat
    else
      row.pc.toNat + (immediate row.immediateEncoded).toNat <
        M31.modulus
  targetAligned :
    (immediate row.immediateEncoded).toNat % 4 = 0

def accessClockField (row : Row) : M31 :=
  TeamACommon.accessClockField row.clock 1

def destinationClockGapField (row : Row) : M31 :=
  TeamACommon.clockGapField
    row.clock 1 row.rdPreviousClock

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 10
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce 33,
    bitVecM31 row.rd,
    immediateField row.immediateEncoded,
    0
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 11
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 12
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc + immediateField row.immediateEncoded,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def resultMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 13
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.result.limb1,
    bitVecM31 row.result.limb2
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def resultM31Lookup (row : Row) : EvaluatedLookup where
  ordinal := 14
  domain := .rangeCheckM31
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.result.limb0,
    bitVecM31 row.result.limb3
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 15
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

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 16
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

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 17
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[destinationClockGapField row]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

macro "reduce_jal" : tactic =>
  `(tactic|
    (simp only [
      evaluation,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.jal,
      Programs.jalSource,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      List.length_cons,
      List.length_nil,
      List.map,
      List.map_toArray,
      Array.map_push,
      Array.map_empty,
      columns,
      programLookup,
      stateConsumeLookup,
      stateEmitLookup,
      resultMiddleLookup,
      resultM31Lookup,
      destinationConsumeLookup,
      destinationEmitLookup,
      destinationClockLookup,
      accessClockField,
      destinationClockGapField,
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      TeamACommon.wordBytesField,
      SymbolicEvaluation.activeSelectorsAccepted,
      M31.ofNat?
    ] <;>
      simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?
      ]))

set_option maxRecDepth 20000 in
theorem selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  simp only [
    evaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    Programs.jal,
    Programs.jalSource,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    SymbolicEvaluation.activeSelectorsAccepted,
    columns,
    M31.ofNat?,
  ]
  rfl

set_option maxRecDepth 20000 in
theorem lookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 10 = some (programLookup row) ∧
      (evaluation row witness).lookup? 11 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 12 =
        some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 13 =
        some (resultMiddleLookup row) ∧
      (evaluation row witness).lookup? 14 =
        some (resultM31Lookup row) ∧
      (evaluation row witness).lookup? 15 =
        some (destinationConsumeLookup row) ∧
      (evaluation row witness).lookup? 16 =
        some (destinationEmitLookup row) ∧
      (evaluation row witness).lookup? 17 =
        some (destinationClockLookup row) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · have selected :
        Programs.jal.source.events[10]? =
          some (.lookup {
            ordinal := 10
            domain := .programAccess
            numerator := 54
            tuple := #[2, 55, 3, 13, 51]
            role := .request
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 10 _ selected,
    ]
    reduce_jal
  · have selected :
        Programs.jal.source.events[11]? =
          some (.lookup {
            ordinal := 11
            domain := .registersState
            numerator := 54
            tuple := #[2, 1]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 11 _ selected,
    ]
    reduce_jal
  · have selected :
        Programs.jal.source.events[12]? =
          some (.lookup {
            ordinal := 12
            domain := .registersState
            numerator := 0
            tuple := #[56, 57]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 12 _ selected,
    ]
    reduce_jal
  · have selected :
        Programs.jal.source.events[13]? =
          some (.lookup {
            ordinal := 13
            domain := .rangeCheck88
            numerator := 54
            tuple := #[15, 16]
            role := .request
            tableId := some .rangeCheck88
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 13 _ selected,
    ]
    reduce_jal
  · have selected :
        Programs.jal.source.events[14]? =
          some (.lookup {
            ordinal := 14
            domain := .rangeCheckM31
            numerator := 54
            tuple := #[14, 17]
            role := .request
            tableId := some .rangeCheckM31
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 14 _ selected,
    ]
    reduce_jal
  · have selected :
        Programs.jal.source.events[15]? =
          some (.lookup {
            ordinal := 15
            domain := .memoryAccess
            numerator := 54
            tuple := #[51, 3, 8, 4, 5, 6, 7]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 15 _ selected,
    ]
    reduce_jal
  · have selected :
        Programs.jal.source.events[16]? =
          some (.lookup {
            ordinal := 16
            domain := .memoryAccess
            numerator := 0
            tuple := #[51, 3, 50, 9, 10, 11, 12]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 16 _ selected,
    ]
    reduce_jal
  · have selected :
        Programs.jal.source.events[17]? =
          some (.lookup {
            ordinal := 17
            domain := .rangeCheck20
            numerator := 54
            tuple := #[53]
            role := .request
            tableId := some .rangeCheck20
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.jal (columns row witness) 17 _ selected,
    ]
    reduce_jal

def ConstraintEquations (row : Row) (witness : Witness row) : Prop :=
  TeamACommon.wordBytesField row.result -
      (bitVecM31 row.pc + M31.reduce 4) = 0 ∧
    bitVecM31 row.rd *
        (1 - boolM31 row.rdNonzero) = 0 ∧
    bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero = 0 ∧
    bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb0 = 0 ∧
    bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb1 = 0 ∧
    bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb2 = 0 ∧
    bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb3 = 0

private theorem constraintsHoldEvents
    (nodes : LocalValues) :
    (Programs.jalSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      #[22, 33, 35, 37, 39, 41, 43, 45, 47, 21].all
        (fun root => nodes.getSymbolic root == 0) := by
  simp [Programs.jalSource, Event.evalSymbolic]

theorem constraintsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      #[22, 33, 35, 37, 39, 41, 43, 45, 47, 21].all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) := by
  exact constraintsHoldEvents (evaluation row witness).nodes

set_option maxRecDepth 20000 in
private theorem node22 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 22 =
      (1 : M31) * (1 - 1) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node33 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 33 =
      (1 : M31) *
        (TeamACommon.wordBytesField row.result -
          (bitVecM31 row.pc + M31.reduce 4)) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node35 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 35 =
      boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node37 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 37 =
      bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) := by
  rfl

set_option maxRecDepth 20000 in
private theorem node39 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 39 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  rfl

set_option maxRecDepth 20000 in
private theorem node41 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 41 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb0 := by
  rfl

set_option maxRecDepth 20000 in
private theorem node43 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 43 =
      bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb1 := by
  rfl

set_option maxRecDepth 20000 in
private theorem node45 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 45 =
      bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb2 := by
  rfl

set_option maxRecDepth 20000 in
private theorem node47 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 47 =
      bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb3 := by
  rfl

set_option maxRecDepth 20000 in
private theorem node21 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 21 =
      (1 : M31) - 1 := by
  rfl

set_option maxRecDepth 20000 in
theorem constraintsHold_iff
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold = true ↔
      ConstraintEquations row witness := by
  rw [constraintsHold_eq]
  cases flag : row.rdNonzero <;>
    simp [
      ConstraintEquations,
      node22,
      node33,
      node35,
      node37,
      node39,
      node41,
      node43,
      node45,
      node47,
      node21,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      flag,
    ]

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  selectors :
    (evaluation row witness).activeSelectorsAccepted = true
  constraints :
    (evaluation row witness).constraintsHold = true
  fixedLookups :
    (evaluation row witness).fixedLookupsHold = true

theorem resultM31RequestHolds
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (resultM31Lookup row).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) 14 (resultM31Lookup row) fixed
    (lookupProjection row witness).2.2.2.2.1

theorem destinationClockRequestHolds
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (destinationClockLookup row).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) 17 (destinationClockLookup row) fixed
    (lookupProjection row witness).2.2.2.2.2.2.2

private theorem byteFieldVal (value : Byte) :
    (bitVecM31 value).val = value.toNat := by
  apply Lui.bitVecM31_val
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

theorem resultM31RequestHolds_iff (row : Row) :
    (resultM31Lookup row).fixedRequestHolds = true ↔
      row.result.limb0.toNat +
          2 ^ 8 * row.result.limb3.toNat <
        2 ^ 15 - 1 := by
  simp only [
    resultM31Lookup,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
  ]
  simp [byteFieldVal]
  have lowBound : row.result.limb0.toNat < 256 := by
    simpa using row.result.limb0.isLt
  constructor
  · intro holds
    rcases holds with impossible | holds
    · have nonzero : (-(1 : M31)) ≠ 0 := by decide
      exact False.elim (nonzero impossible)
    · exact holds.2
  · intro endpointBound
    have highBound : row.result.limb3.toNat < 128 := by
      omega
    exact Or.inr ⟨⟨lowBound, highBound⟩, endpointBound⟩

theorem resultValueBound_of_fixedLookups
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    row.result.value < M31.modulus := by
  have endpoints :=
    (resultM31RequestHolds_iff row).mp
      (resultM31RequestHolds row witness fixed)
  have low := row.result.limb0.isLt
  have middle0 := row.result.limb1.isLt
  have middle1 := row.result.limb2.isLt
  have high := row.result.limb3.isLt
  simp only [Nat.reducePow] at low middle0 middle1 high endpoints
  simp only [WordBytes.value]
  rw [M31.modulus_eq]
  omega

theorem destinationClockGapBound_of_fixedLookups
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (destinationClockGapField row).val < 2 ^ 20 := by
  apply
    (TeamACommon.rangeCheck20RequestHolds_iff
      17 (some 1) (destinationClockGapField row)).mp
  simpa [destinationClockLookup] using
    destinationClockRequestHolds row witness fixed

theorem destinationClock_of_air
    (row : Row)
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
      accessClockField row =
        M31.reduce (accessClock row.clock 1) := by
    apply M31.ext
    change
      (TeamACommon.accessClockField row.clock 1).val =
        (M31.reduce (accessClock row.clock 1)).val
    rw [
      TeamACommon.accessClockField_val
        row.clock 1 admission.clockPositive admission.clockBound (by decide),
      M31.reduce_val_of_lt _ currentModulusBound,
    ]
  have gapBound :=
    destinationClockGapBound_of_fixedLookups row witness fixed
  change
    (accessClockField row -
        M31.reduce row.rdPreviousClock - 1).val < 2 ^ 20 at gapBound
  rw [accessClockFieldEq] at gapBound
  exact
    TeamACommon.validPreviousClock_of_gap
      row.rdPreviousClock
      (accessClock row.clock 1)
      currentPositive
      currentBound
      admission.destinationPreviousBound
      gapBound

theorem immediateToNatBound (encoded : BitVec 20) :
    (immediate encoded).toNat < 2 ^ 21 := by
  exact (immediate encoded).isLt

theorem immediateFieldValueBound (encoded : BitVec 20) :
    immediateFieldValue encoded < M31.modulus := by
  unfold immediateFieldValue
  by_cases sign : (immediate encoded).msb
  · simp only [sign, ↓reduceIte]
    have lower := BitVec.le_toNat_of_msb_true sign
    have upper := immediateToNatBound encoded
    rw [M31.modulus_eq]
    simp only [Nat.reducePow] at lower upper ⊢
    omega
  · simp only [sign]
    have upper := immediateToNatBound encoded
    simp [M31.modulus_eq] at *
    omega

theorem immediateFieldVal (encoded : BitVec 20) :
    (immediateField encoded).val =
      immediateFieldValue encoded := by
  exact
    M31.reduce_val_of_lt
      (immediateFieldValue encoded)
      (immediateFieldValueBound encoded)

theorem jumpTargetToNat
    (row : Row)
    (admission : Admission row) :
    (jumpTarget row.pc row.immediateEncoded).toNat =
      if (immediate row.immediateEncoded).msb
      then
        row.pc.toNat -
          (2 ^ 21 - (immediate row.immediateEncoded).toNat)
      else
        row.pc.toNat +
          (immediate row.immediateEncoded).toNat := by
  let offset := immediate row.immediateEncoded
  change
    (row.pc + BitVec.signExtend 32 offset).toNat =
      if offset.msb
      then row.pc.toNat - (2 ^ 21 - offset.toNat)
      else row.pc.toNat + offset.toNat
  have offsetBound : offset.toNat < 2 ^ 21 :=
    immediateToNatBound row.immediateEncoded
  have offsetWidthBound : offset.toNat < 2 ^ 32 := by
    simp only [Nat.reducePow] at offsetBound ⊢
    omega
  have pcWidthBound : row.pc.toNat < 2 ^ 32 :=
    row.pc.isLt
  by_cases sign : offset.msb
  · have targetBound := admission.targetNoWrap
    change
      (if offset.msb
        then 2 ^ 21 - offset.toNat ≤ row.pc.toNat
        else row.pc.toNat + offset.toNat < M31.modulus) at targetBound
    simp only [sign, ↓reduceIte] at targetBound ⊢
    have arithmetic :
        row.pc.toNat + (offset.toNat + (2 ^ 32 - 2 ^ 21)) =
          2 ^ 32 +
            (row.pc.toNat - (2 ^ 21 - offset.toNat)) := by
      have signedLower := BitVec.le_toNat_of_msb_true sign
      simp only [Nat.reduceSubDiff, Nat.reducePow] at signedLower offsetBound pcWidthBound targetBound
      simp only [Nat.reducePow]
      omega
    have resultBound :
        row.pc.toNat - (2 ^ 21 - offset.toNat) < 2 ^ 32 := by
      omega
    simp only [
      BitVec.toNat_add,
      BitVec.toNat_signExtend,
      BitVec.toNat_setWidth,
      sign,
      ↓reduceIte,
    ]
    rw [Nat.mod_eq_of_lt offsetWidthBound, arithmetic]
    simp [Nat.mod_eq_of_lt resultBound]
  · have targetBound := admission.targetNoWrap
    have signFalse : offset.msb = false := by
      cases value : offset.msb
      · rfl
      · exact False.elim (sign value)
    change
      (if offset.msb
        then 2 ^ 21 - offset.toNat ≤ row.pc.toNat
        else row.pc.toNat + offset.toNat < M31.modulus) at targetBound
    simp only [signFalse, Bool.false_eq_true, ↓reduceIte] at targetBound ⊢
    have sumWidthBound :
        row.pc.toNat + offset.toNat < 2 ^ 32 := by
      have := targetBound
      simp [M31.modulus_eq] at *
      omega
    simp only [
      BitVec.toNat_add,
      BitVec.toNat_signExtend,
      BitVec.toNat_setWidth,
      signFalse,
      Bool.false_eq_true,
      ↓reduceIte,
      Nat.add_zero,
    ]
    rw [
      Nat.mod_eq_of_lt offsetWidthBound,
      Nat.mod_eq_of_lt sumWidthBound,
    ]

theorem targetField
    (row : Row)
    (admission : Admission row) :
    bitVecM31 row.pc + immediateField row.immediateEncoded =
      bitVecM31 (jumpTarget row.pc row.immediateEncoded) := by
  change
    M31.reduce row.pc.toNat +
        M31.reduce (immediateFieldValue row.immediateEncoded) =
      M31.reduce (jumpTarget row.pc row.immediateEncoded).toNat
  rw [TeamACommon.reduceAdd]
  apply M31.ext
  simp only [M31.reduce_val]
  rw [jumpTargetToNat row admission]
  let offset := immediate row.immediateEncoded
  change
    (row.pc.toNat + immediateFieldValue row.immediateEncoded) %
          M31.modulus =
      (if offset.msb
        then row.pc.toNat - (2 ^ 21 - offset.toNat)
        else row.pc.toNat + offset.toNat) %
          M31.modulus
  by_cases sign : offset.msb
  · have targetBound := admission.targetNoWrap
    change
      (if offset.msb
        then 2 ^ 21 - offset.toNat ≤ row.pc.toNat
        else row.pc.toNat + offset.toNat < M31.modulus) at targetBound
    simp only [sign, ↓reduceIte] at targetBound ⊢
    have offsetBound : offset.toNat < 2 ^ 21 :=
      immediateToNatBound row.immediateEncoded
    have arithmetic :
        row.pc.toNat +
            (M31.modulus + offset.toNat - 2 ^ 21) =
          M31.modulus +
            (row.pc.toNat - (2 ^ 21 - offset.toNat)) := by
      rw [M31.modulus_eq]
      simp only [Nat.reducePow] at offsetBound targetBound ⊢
      omega
    have targetLt :
        row.pc.toNat - (2 ^ 21 - offset.toNat) <
          M31.modulus := by
      have := admission.linkBound
      omega
    simp only [immediateFieldValue, offset]
    rw [if_pos sign, arithmetic]
    change
      (M31.modulus +
          (row.pc.toNat - (2 ^ 21 - offset.toNat))) %
            M31.modulus =
        (row.pc.toNat - (2 ^ 21 - offset.toNat)) %
          M31.modulus
    simp
  · have signFalse : offset.msb = false := by
      cases value : offset.msb
      · rfl
      · exact False.elim (sign value)
    have targetBound := admission.targetNoWrap
    change
      (if offset.msb
        then 2 ^ 21 - offset.toNat ≤ row.pc.toNat
        else row.pc.toNat + offset.toNat < M31.modulus) at targetBound
    simp only [signFalse, Bool.false_eq_true, ↓reduceIte] at targetBound ⊢
    simp only [immediateFieldValue, offset]
    rw [if_neg sign]

theorem resultIsLink
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    row.result.word = nextPc row.pc := by
  have equations :
      ConstraintEquations row witness :=
    (constraintsHold_iff row witness).mp accepted.constraints
  have resultEquation :
      TeamACommon.wordBytesField row.result =
        bitVecM31 row.pc + M31.reduce 4 :=
    (M31.sub_eq_zero_iff _ _).mp equations.1
  rw [TeamACommon.nextPcField row.pc admission.linkBound] at resultEquation
  have fieldEquality :
      bitVecM31 row.result.word =
        bitVecM31 (nextPc row.pc) := by
    rw [
      show bitVecM31 row.result.word =
          TeamACommon.wordBytesField row.result by
        simp only [
          bitVecM31,
          Lui.bitVecM31,
          WordBytes.word_toNat,
          TeamACommon.wordBytesField_eq_reduce,
        ],
      resultEquation,
    ]
  apply
    TeamACommon.bitVecM31_injective_of_bounds
      row.result.word (nextPc row.pc)
  · simpa using
      resultValueBound_of_fixedLookups
        row witness accepted.fixedLookups
  · rw [TeamACommon.nextPcToNat row.pc admission.linkBound]
    exact admission.linkBound
  · exact fieldEquality

theorem destinationFlag
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) := by
  have equations :=
    (constraintsHold_iff row witness).mp accepted.constraints
  exact
    TeamACommon.destinationFlag_of_equations
      row.rd row.rdNonzero witness.destinationInverse
      equations.2.1 equations.2.2.1

theorem destinationBytes
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNext =
      if row.rdNonzero then row.result else WordBytes.zero := by
  have equations :=
    (constraintsHold_iff row witness).mp accepted.constraints
  exact
    TeamACommon.destinationBytes_of_equations
      row.rdNext row.result row.rdNonzero
      equations.2.2.2.1
      equations.2.2.2.2.1
      equations.2.2.2.2.2.1
      equations.2.2.2.2.2.2

theorem destinationWord
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    row.rdNext.word =
      architecturalValue row.rd (nextPc row.pc) := by
  have bytes := destinationBytes row witness accepted
  have flag := destinationFlag row witness accepted
  have link := resultIsLink row witness admission accepted
  by_cases zero : row.rd = zeroRegister
  · rw [bytes, flag]
    simp [zero, architecturalValue]
  · rw [bytes, flag]
    simp [zero, architecturalValue, link]

theorem stateEmitFields
    (row : Row)
    (admission : Admission row) :
    (stateEmitLookup row).tuple =
      #[
        bitVecM31 (jumpTarget row.pc row.immediateEncoded),
        M31.reduce (row.clock + 1)
      ] := by
  have clockBound : row.clock + 1 < M31.modulus := by
    have := admission.clockBound
    simp [M31.modulus_eq] at *
    omega
  simp only [stateEmitLookup]
  rw [
    targetField row admission,
    TeamACommon.nextClockField row.clock clockBound,
  ]

structure ProductionRefinement
    (row : Row)
    (witness : Witness row) : Prop where
  selectors :
    (evaluation row witness).activeSelectorsAccepted = true
  constraints :
    (evaluation row witness).constraintsHold = true
  fixedLookups :
    (evaluation row witness).fixedLookupsHold = true
  exactLookups :
    (evaluation row witness).lookup? 10 = some (programLookup row) ∧
      (evaluation row witness).lookup? 11 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 12 =
        some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 13 =
        some (resultMiddleLookup row) ∧
      (evaluation row witness).lookup? 14 =
        some (resultM31Lookup row) ∧
      (evaluation row witness).lookup? 15 =
        some (destinationConsumeLookup row) ∧
      (evaluation row witness).lookup? 16 =
        some (destinationEmitLookup row) ∧
      (evaluation row witness).lookup? 17 =
        some (destinationClockLookup row)
  link :
    row.result.word = nextPc row.pc
  destination :
    row.rdNext.word =
      architecturalValue row.rd (nextPc row.pc)
  destinationClock :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 1)
  stateEmission :
    (stateEmitLookup row).tuple =
      #[
        bitVecM31 (jumpTarget row.pc row.immediateEncoded),
        M31.reduce (row.clock + 1)
      ]
  noSourceProjection :
    Programs.jal.source.projection.sourceEvents = #[]

set_option maxRecDepth 20000 in
theorem noSourceProjection :
    Programs.jal.source.projection.sourceEvents = #[] := by
  decide

theorem sound
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    ProductionRefinement row witness := by
  exact {
    selectors := accepted.selectors
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    exactLookups := lookupProjection row witness
    link := resultIsLink row witness admission accepted
    destination := destinationWord row witness admission accepted
    destinationClock :=
      destinationClock_of_air
        row witness admission accepted.fixedLookups
    stateEmission := stateEmitFields row admission
    noSourceProjection := noSourceProjection
  }

private def resultMiddleLookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 13
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 54
  tuple := #[nodes.getSymbolic 15, nodes.getSymbolic 16]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def resultM31LookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 14
  domain := .rangeCheckM31
  numerator := nodes.getSymbolic 54
  tuple := #[nodes.getSymbolic 14, nodes.getSymbolic 17]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def destinationClockLookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 17
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 54
  tuple := #[nodes.getSymbolic 53]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

private theorem fixedLookupsHoldEvents
    (nodes : LocalValues) :
    (Programs.jalSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((resultMiddleLookupAt nodes).fixedRequestHolds &&
        ((resultM31LookupAt nodes).fixedRequestHolds &&
          (destinationClockLookupAt nodes).fixedRequestHolds)) := by
  simp [
    Programs.jalSource,
    Event.evalSymbolic,
    resultMiddleLookupAt,
    resultM31LookupAt,
    destinationClockLookupAt,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.fixedMembership,
  ]

set_option maxRecDepth 20000 in
private theorem resultMiddleLookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    resultMiddleLookupAt (evaluation row witness).nodes =
      resultMiddleLookup row := by
  simp only [evaluation, resultMiddleLookupAt]
  reduce_jal

set_option maxRecDepth 20000 in
private theorem resultM31LookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    resultM31LookupAt (evaluation row witness).nodes =
      resultM31Lookup row := by
  simp only [evaluation, resultM31LookupAt]
  reduce_jal

set_option maxRecDepth 20000 in
private theorem destinationClockLookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    destinationClockLookupAt (evaluation row witness).nodes =
      destinationClockLookup row := by
  simp only [evaluation, destinationClockLookupAt]
  reduce_jal

theorem fixedLookupsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).fixedLookupsHold =
      ((resultMiddleLookup row).fixedRequestHolds &&
        ((resultM31Lookup row).fixedRequestHolds &&
          (destinationClockLookup row).fixedRequestHolds)) := by
  rw [SymbolicEvaluation.fixedLookupsHold]
  change
    (Programs.jalSource.events.map
      (Event.evalSymbolic (evaluation row witness).nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((resultMiddleLookup row).fixedRequestHolds &&
        ((resultM31Lookup row).fixedRequestHolds &&
          (destinationClockLookup row).fixedRequestHolds))
  rw [fixedLookupsHoldEvents]
  rw [
    resultMiddleLookupAt_evaluation row witness,
    resultM31LookupAt_evaluation row witness,
    destinationClockLookupAt_evaluation row witness,
  ]

def exampleLinkBytes : WordBytes where
  limb0 := BitVec.ofNat 8 4
  limb1 := BitVec.ofNat 8 0
  limb2 := BitVec.ofNat 8 0
  limb3 := BitVec.ofNat 8 0

def exampleRow : Row where
  clock := 7
  pc := BitVec.ofNat 32 0
  rd := BitVec.ofNat 5 1
  rdPrevious := WordBytes.zero
  rdPreviousClock := 0
  rdNext := exampleLinkBytes
  immediateEncoded := BitVec.ofNat 20 8
  result := exampleLinkBytes
  rdNonzero := true

def exampleWitness : Witness exampleRow where
  destinationInverse := 1

theorem exampleAdmission : Admission exampleRow := by
  constructor <;> decide

set_option maxRecDepth 20000 in
theorem exampleAcceptance :
    Acceptance exampleRow exampleWitness := by
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
      exampleLinkBytes,
      bitVecM31,
      boolM31,
      TeamACommon.bitVecM31,
      TeamACommon.boolM31,
      TeamACommon.wordBytesField,
      Lui.bitVecM31,
      Lui.boolM31,
      WordBytes.zero,
    ]
  · rw [fixedLookupsHold_eq]
    decide

theorem acceptanceNonvacuous :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧ Acceptance row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance⟩

theorem exampleRefines :
    ProductionRefinement exampleRow exampleWitness :=
  sound exampleRow exampleWitness exampleAdmission exampleAcceptance

end RiscvRefinement.Air.Bridge.Jal
