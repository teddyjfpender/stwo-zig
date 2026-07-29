import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Bridge.DecodeTeamA

/-!
# Production JALR AIR bridge

The typed row is the canonical runner witness for a successful RV32IM JALR:
the source access is read-only, the signed I-immediate is added modulo `2^32`,
bit zero is cleared, the successful target is four-byte aligned, and `pc + 4`
is written through the destination gadget.
-/

namespace RiscvRefinement.Air.Bridge.Jalr

open RiscvRefinement
open RiscvRefinement.Air.Generated

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

def wordBytes (word : Word) : WordBytes where
  limb0 := BitVec.extractLsb 7 0 word
  limb1 := BitVec.extractLsb 15 8 word
  limb2 := BitVec.extractLsb 23 16 word
  limb3 := BitVec.extractLsb 31 24 word

theorem wordBytes_word (word : Word) :
    (wordBytes word).word = word := by
  rw [WordBytes.word_append]
  simp only [wordBytes]
  bv_decide

def immediateFieldValue (immediate : BitVec 12) : Nat :=
  if immediate.msb
  then M31.modulus + immediate.toNat - 2 ^ 12
  else immediate.toNat

def immediateField (immediate : BitVec 12) : M31 :=
  M31.reduce (immediateFieldValue immediate)

def immediateByte (immediate : BitVec 12) : Byte :=
  BitVec.extractLsb 7 0 immediate

def immediateNibble (immediate : BitVec 12) : BitVec 4 :=
  BitVec.extractLsb 11 8 immediate

def immediateSign (immediate : BitVec 12) : Bool :=
  immediate.msb

def unalignedTarget (source : Word) (immediate : BitVec 12) : Word :=
  source + BitVec.signExtend 32 immediate

def jumpTarget (source : Word) (immediate : BitVec 12) : Word :=
  BitVec.ofNat 32
    ((unalignedTarget source immediate).toNat / 2 * 2)

def targetWord (source : Word) (immediate : BitVec 12) : Nat :=
  (jumpTarget source immediate).toNat / 4

def targetWordLow20 (source : Word) (immediate : BitVec 12) : Nat :=
  targetWord source immediate % 2 ^ 20

def targetWordHigh8 (source : Word) (immediate : BitVec 12) : Nat :=
  targetWord source immediate / 2 ^ 20

def linkValue (pc : Word) : Word :=
  nextPc pc

structure Row where
  clock : Nat
  pc : Word
  rd : RegisterIndex
  rdPrevious : WordBytes
  rdPreviousClock : Nat
  rs1 : RegisterIndex
  rs1Value : WordBytes
  rs1PreviousClock : Nat
  immediate : BitVec 12
deriving DecidableEq, Repr

def result (row : Row) : WordBytes :=
  wordBytes (linkValue row.pc)

def targetBytes (row : Row) : WordBytes :=
  wordBytes (jumpTarget row.rs1Value.word row.immediate)

def rdNonzero (row : Row) : Bool :=
  decide (row.rd ≠ zeroRegister)

def rdNext (row : Row) : WordBytes :=
  if rdNonzero row then result row else WordBytes.zero

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
  | 9 => bitVecM31 (rdNext row).limb0
  | 10 => bitVecM31 (rdNext row).limb1
  | 11 => bitVecM31 (rdNext row).limb2
  | 12 => bitVecM31 (rdNext row).limb3
  | 13 => bitVecM31 row.rs1
  | 14 => bitVecM31 row.rs1Value.limb0
  | 15 => bitVecM31 row.rs1Value.limb1
  | 16 => bitVecM31 row.rs1Value.limb2
  | 17 => bitVecM31 row.rs1Value.limb3
  | 18 => M31.reduce row.rs1PreviousClock
  | 19 => bitVecM31 row.rs1Value.limb0
  | 20 => bitVecM31 row.rs1Value.limb1
  | 21 => bitVecM31 row.rs1Value.limb2
  | 22 => bitVecM31 row.rs1Value.limb3
  | 23 => M31.reduce
      ((jumpTarget row.rs1Value.word row.immediate).toNat / 2)
  | 24 => boolM31
      ((unalignedTarget row.rs1Value.word row.immediate).toNat % 2 = 1)
  | 25 => immediateField row.immediate
  | 26 => bitVecM31 (result row).limb0
  | 27 => bitVecM31 (result row).limb1
  | 28 => bitVecM31 (result row).limb2
  | 29 => bitVecM31 (result row).limb3
  | 30 => boolM31 (rdNonzero row)
  | 31 => witness.destinationInverse
  | 32 => M31.reduce (targetWordLow20 row.rs1Value.word row.immediate)
  | 33 => M31.reduce (targetWordHigh8 row.rs1Value.word row.immediate)
  | 34 => bitVecM31 (targetBytes row).limb0
  | 35 => bitVecM31 (targetBytes row).limb1
  | 36 => bitVecM31 (targetBytes row).limb2
  | 37 => bitVecM31 (targetBytes row).limb3
  | 38 => bitVecM31 (immediateByte row.immediate)
  | 39 => bitVecM31 (immediateNibble row.immediate)
  | 40 => boolM31 (immediateSign row.immediate)
  | _ => 0

def evaluation (row : Row) (witness : Witness row) :
    SymbolicEvaluation :=
  Programs.jalr.evalSymbolic (columns row witness)

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourcePreviousBound : row.rs1PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcProfileBound : row.pc.toNat + 4 < M31.modulus
  targetProfileBound :
    (jumpTarget row.rs1Value.word row.immediate).toNat < 2 ^ 30
  targetAligned :
    (jumpTarget row.rs1Value.word row.immediate).toNat % 4 = 0

def accessClockField (row : Row) (ordinal : Nat) : M31 :=
  TeamACommon.accessClockField row.clock ordinal

def clockGapField (row : Row) (ordinal previous : Nat) : M31 :=
  TeamACommon.clockGapField row.clock ordinal previous

def stateTargetField (row : Row) : M31 :=
  M31.reduce 4 *
    (M31.reduce (targetWordLow20 row.rs1Value.word row.immediate) +
      M31.reduce (targetWordHigh8 row.rs1Value.word row.immediate) *
        M31.reduce (2 ^ 20))

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 23
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce 34, bitVecM31 row.rd,
    bitVecM31 row.rs1, immediateField row.immediate]
  role := .request
  tableId := none
  accessOrdinal := none

def sourceConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 24
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
    bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
    bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3]
  role := .consume
  tableId := none
  accessOrdinal := some 1

def sourceEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 25
  domain := .memoryAccess
  numerator := 1
  tuple := #[0, bitVecM31 row.rs1, accessClockField row 1,
    bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
    bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def sourceClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 26
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row 1 row.rs1PreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

def sourceMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 27
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.rs1Value.limb1,
    bitVecM31 row.rs1Value.limb2]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def sourceOuterLookup (row : Row) : EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.rs1Value.limb0,
    bitVecM31 row.rs1Value.limb3]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def targetLow20Lookup (row : Row) : EvaluatedLookup where
  ordinal := 29
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[M31.reduce
    (targetWordLow20 row.rs1Value.word row.immediate)]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

def targetHigh8Lookup (row : Row) : EvaluatedLookup where
  ordinal := 30
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[M31.reduce
    (targetWordHigh8 row.rs1Value.word row.immediate), 0]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def targetMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 31
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 (targetBytes row).limb1,
    bitVecM31 (targetBytes row).limb2]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def targetM31Lookup (row : Row) : EvaluatedLookup where
  ordinal := 32
  domain := .rangeCheckM31
  numerator := -(1 : M31)
  tuple := #[bitVecM31 (targetBytes row).limb0,
    bitVecM31 (targetBytes row).limb3]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

def immediateRangeLookup (row : Row) : EvaluatedLookup where
  ordinal := 33
  domain := .rangeCheck884
  numerator := -(1 : M31)
  tuple := #[bitVecM31 (immediateByte row.immediate), 0,
    (bitVecM31 (immediateNibble row.immediate) -
      boolM31 (immediateSign row.immediate) * M31.reduce 8) *
        M31.reduce 2]
  role := .request
  tableId := some .rangeCheck884
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 34
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 35
  domain := .registersState
  numerator := 1
  tuple := #[stateTargetField row, M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

def resultMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 36
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 (result row).limb1,
    bitVecM31 (result row).limb2]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def resultM31Lookup (row : Row) : EvaluatedLookup where
  ordinal := 37
  domain := .rangeCheckM31
  numerator := -(1 : M31)
  tuple := #[bitVecM31 (result row).limb0,
    bitVecM31 (result row).limb3]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 38
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[0, bitVecM31 row.rd, M31.reduce row.rdPreviousClock,
    bitVecM31 row.rdPrevious.limb0, bitVecM31 row.rdPrevious.limb1,
    bitVecM31 row.rdPrevious.limb2, bitVecM31 row.rdPrevious.limb3]
  role := .consume
  tableId := none
  accessOrdinal := some 2

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 39
  domain := .memoryAccess
  numerator := 1
  tuple := #[0, bitVecM31 row.rd, accessClockField row 2,
    bitVecM31 (rdNext row).limb0, bitVecM31 (rdNext row).limb1,
    bitVecM31 (rdNext row).limb2, bitVecM31 (rdNext row).limb3]
  role := .emit
  tableId := none
  accessOrdinal := some 2

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 40
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row 2 row.rdPreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

macro "reduce_jalr" : tactic =>
  `(tactic|
    (simp only [
      evaluation,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.jalr,
      Programs.jalrSource,
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
      sourceConsumeLookup,
      sourceEmitLookup,
      sourceClockLookup,
      sourceMiddleLookup,
      sourceOuterLookup,
      targetLow20Lookup,
      targetHigh8Lookup,
      targetMiddleLookup,
      targetM31Lookup,
      immediateRangeLookup,
      stateConsumeLookup,
      stateEmitLookup,
      resultMiddleLookup,
      resultM31Lookup,
      destinationConsumeLookup,
      destinationEmitLookup,
      destinationClockLookup,
      accessClockField,
      clockGapField,
      stateTargetField,
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      SymbolicEvaluation.activeSelectorsAccepted,
      SymbolicEvaluation.lookup?,
      SymbolicEvaluation.constraintsHold,
      SymbolicEvaluation.fixedLookupsHold,
      EvaluatedEvent.lookup?,
      EvaluatedLookup.fixedRequestHolds,
      EvaluatedLookup.fixedMembership,
      EvaluatedLookup.isLive,
      FixedTableId.contains,
      Option.bind,
      M31.ofNat?
    ] <;>
      simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?
      ]))

set_option maxRecDepth 50000 in
theorem selectorAccepted (row : Row) (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  reduce_jalr
  rfl

set_option maxRecDepth 50000 in
theorem lookupProjection (row : Row) (witness : Witness row) :
    (evaluation row witness).lookup? 23 = some (programLookup row) ∧
      (evaluation row witness).lookup? 24 = some (sourceConsumeLookup row) ∧
      (evaluation row witness).lookup? 25 = some (sourceEmitLookup row) ∧
      (evaluation row witness).lookup? 26 = some (sourceClockLookup row) ∧
      (evaluation row witness).lookup? 27 = some (sourceMiddleLookup row) ∧
      (evaluation row witness).lookup? 28 = some (sourceOuterLookup row) ∧
      (evaluation row witness).lookup? 29 = some (targetLow20Lookup row) ∧
      (evaluation row witness).lookup? 30 = some (targetHigh8Lookup row) ∧
      (evaluation row witness).lookup? 31 = some (targetMiddleLookup row) ∧
      (evaluation row witness).lookup? 32 = some (targetM31Lookup row) ∧
      (evaluation row witness).lookup? 33 = some (immediateRangeLookup row) ∧
      (evaluation row witness).lookup? 34 = some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 35 = some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 36 = some (resultMiddleLookup row) ∧
      (evaluation row witness).lookup? 37 = some (resultM31Lookup row) ∧
      (evaluation row witness).lookup? 38 =
        some (destinationConsumeLookup row) ∧
      (evaluation row witness).lookup? 39 =
        some (destinationEmitLookup row) ∧
      (evaluation row witness).lookup? 40 =
        some (destinationClockLookup row) := by
  reduce_jalr
  simp_all [EvaluatedEvent.lookup?]

theorem exactProgramIdentity :
    Programs.jalr.source.contentDigest =
        "f9c886168efb2767e00082083936f5a928725bb3f89da03581e860560b963083" ∧
      Programs.jalr.source.family = .jalr ∧
      Programs.jalr.source.nodes.size = 151 ∧
      Programs.jalr.source.events.size = 41 ∧
      Programs.jalr.source.projection.programEvent = 23 ∧
      Programs.jalr.source.projection.sourceEvents = #[24, 25] ∧
      Programs.jalr.source.projection.destinationEvents = #[38, 39] ∧
      Programs.jalr.source.projection.stateEvents = #[34, 35] ∧
      Programs.jalr.source.projection.nextPc = 65 := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

theorem stateTargetField_eq
    (row : Row)
    (admission : Admission row) :
    stateTargetField row =
      bitVecM31 (jumpTarget row.rs1Value.word row.immediate) := by
  simp only [stateTargetField, bitVecM31,
    TeamACommon.bitVecM31, Lui.bitVecM31]
  rw [
    TeamACommon.reduceMul
      (targetWordHigh8 row.rs1Value.word row.immediate) (2 ^ 20),
    TeamACommon.reduceAdd
      (targetWordLow20 row.rs1Value.word row.immediate)
      (targetWordHigh8 row.rs1Value.word row.immediate * 2 ^ 20),
    TeamACommon.reduceMul 4
      (targetWordLow20 row.rs1Value.word row.immediate +
        targetWordHigh8 row.rs1Value.word row.immediate * 2 ^ 20),
  ]
  congr 1
  have split :
      targetWordLow20 row.rs1Value.word row.immediate +
          targetWordHigh8 row.rs1Value.word row.immediate * 2 ^ 20 =
        targetWord row.rs1Value.word row.immediate := by
    unfold targetWordLow20 targetWordHigh8
    omega
  rw [split]
  unfold targetWord
  have aligned := admission.targetAligned
  omega

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true

structure ProductionRefinement (row : Row) (witness : Witness row) : Prop where
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true
  lookups :
    (evaluation row witness).lookup? 23 = some (programLookup row) ∧
      (evaluation row witness).lookup? 24 = some (sourceConsumeLookup row) ∧
      (evaluation row witness).lookup? 25 = some (sourceEmitLookup row) ∧
      (evaluation row witness).lookup? 26 = some (sourceClockLookup row) ∧
      (evaluation row witness).lookup? 27 = some (sourceMiddleLookup row) ∧
      (evaluation row witness).lookup? 28 = some (sourceOuterLookup row) ∧
      (evaluation row witness).lookup? 29 = some (targetLow20Lookup row) ∧
      (evaluation row witness).lookup? 30 = some (targetHigh8Lookup row) ∧
      (evaluation row witness).lookup? 31 = some (targetMiddleLookup row) ∧
      (evaluation row witness).lookup? 32 = some (targetM31Lookup row) ∧
      (evaluation row witness).lookup? 33 = some (immediateRangeLookup row) ∧
      (evaluation row witness).lookup? 34 = some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 35 = some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 36 = some (resultMiddleLookup row) ∧
      (evaluation row witness).lookup? 37 = some (resultM31Lookup row) ∧
      (evaluation row witness).lookup? 38 =
        some (destinationConsumeLookup row) ∧
      (evaluation row witness).lookup? 39 =
        some (destinationEmitLookup row) ∧
      (evaluation row witness).lookup? 40 =
        some (destinationClockLookup row)
  programIdentity :
    Programs.jalr.source.contentDigest =
        "f9c886168efb2767e00082083936f5a928725bb3f89da03581e860560b963083"
  nextPc :
    (stateEmitLookup row).tuple[0]? =
      some (bitVecM31 (jumpTarget row.rs1Value.word row.immediate))
  nextClock :
    (stateEmitLookup row).tuple[1]? =
      some (M31.reduce (row.clock + 1))
  sourceReadOnly :
    (sourceConsumeLookup row).tuple[3]? =
        (sourceEmitLookup row).tuple[3]? ∧
      (sourceConsumeLookup row).tuple[4]? =
        (sourceEmitLookup row).tuple[4]? ∧
      (sourceConsumeLookup row).tuple[5]? =
        (sourceEmitLookup row).tuple[5]? ∧
      (sourceConsumeLookup row).tuple[6]? =
        (sourceEmitLookup row).tuple[6]?
  link :
    (result row).word = RiscvRefinement.nextPc row.pc
  destination :
    (rdNext row).word =
      architecturalValue row.rd (RiscvRefinement.nextPc row.pc)

theorem destination_word (row : Row) :
    (rdNext row).word =
      architecturalValue row.rd (RiscvRefinement.nextPc row.pc) := by
  unfold rdNext rdNonzero architecturalValue
  by_cases zero : row.rd = zeroRegister
  · simp [zero]
  · simp [zero, result, linkValue, wordBytes_word]

theorem sound
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    ProductionRefinement row witness := by
  refine {
    selectors := selectorAccepted row witness
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    lookups := lookupProjection row witness
    programIdentity := exactProgramIdentity.1
    nextPc := by simp [stateEmitLookup, stateTargetField_eq row admission]
    nextClock := ?_
    sourceReadOnly := by simp [sourceConsumeLookup, sourceEmitLookup]
    link := by simp [result, linkValue, wordBytes_word]
    destination := destination_word row
  }
  simp [
    stateEmitLookup,
    TeamACommon.nextClockField row.clock (by
      have := admission.clockBound
      simp [M31.modulus_eq] at *
      omega),
  ]

def exampleRow : Row where
  clock := 7
  pc := BitVec.ofNat 32 0x1000
  rd := BitVec.ofNat 5 1
  rdPrevious := WordBytes.zero
  rdPreviousClock := 0
  rs1 := BitVec.ofNat 5 2
  rs1Value := wordBytes (BitVec.ofNat 32 101)
  rs1PreviousClock := 1
  immediate := BitVec.ofNat 12 4

def exampleWitness : Witness exampleRow where
  destinationInverse := 1

theorem exampleAdmission : Admission exampleRow := by
  refine {
    clockPositive := by decide
    clockBound := by decide
    sourcePreviousBound := by decide
    destinationPreviousBound := by decide
    pcProfileBound := by decide
    targetProfileBound := by decide
    targetAligned := by decide
  }

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
theorem exampleAcceptance : Acceptance exampleRow exampleWitness := by
  constructor <;>
    simp only [exampleRow, exampleWitness] <;>
    reduce_jalr <;>
    try simp [
      wordBytes,
      result,
      targetBytes,
      rdNext,
      rdNonzero,
      linkValue,
      jumpTarget,
      unalignedTarget,
      targetWord,
      targetWordLow20,
      targetWordHigh8,
      immediateField,
      immediateFieldValue,
      immediateByte,
      immediateNibble,
      immediateSign,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      M31.toNat,
      M31.reduce,
      M31.modulus
    ] <;>
    try decide

theorem acceptanceNonvacuous :
    ∃ row witness,
      Admission row ∧ Acceptance row witness ∧
        ProductionRefinement row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance,
    sound exampleRow exampleWitness exampleAdmission exampleAcceptance⟩

end RiscvRefinement.Air.Bridge.Jalr
