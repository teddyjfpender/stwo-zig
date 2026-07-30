import RiscvRefinement.Air.Bridge.Addi
import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Bridge.DecodeTeamA

/-!
# Production JALR AIR bridge

Every witness and output column below is independent of the architectural
answer.  Accepted production constraints and fixed-table requests are what
bind the raw immediate decomposition, target, link value, preserved source,
and gated destination to RV32IM JALR semantics.
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

def unalignedTarget (source : Word) (immediate : BitVec 12) : Word :=
  source + BitVec.signExtend 32 immediate

def jumpTarget (source : Word) (immediate : BitVec 12) : Word :=
  BitVec.ofNat 32
    ((unalignedTarget source immediate).toNat / 2 * 2)

structure Row where
  enabler : M31
  clock : Nat
  pc : Word
  rd : RegisterIndex
  rdPrevious : WordBytes
  rdPreviousClock : Nat
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1Previous : WordBytes
  rs1PreviousClock : Nat
  rs1Next : WordBytes
  immediate : BitVec 12
  toPcOverTwo : M31
  targetLsb : Bool
  result : WordBytes
  rdNonzero : Bool
  targetWordLow20 : M31
  targetWordHigh8 : M31
  target : WordBytes
  immediateByte : Byte
  immediateNibble : BitVec 4
  immediateSign : Bool
deriving DecidableEq, Repr

structure Witness (row : Row) where
  destinationInverse : M31

def columns (row : Row) (witness : Witness row) : Nat → M31
  | 0 => row.enabler
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
  | 23 => row.toPcOverTwo
  | 24 => boolM31 row.targetLsb
  | 25 => immediateField row.immediate
  | 26 => bitVecM31 row.result.limb0
  | 27 => bitVecM31 row.result.limb1
  | 28 => bitVecM31 row.result.limb2
  | 29 => bitVecM31 row.result.limb3
  | 30 => boolM31 row.rdNonzero
  | 31 => witness.destinationInverse
  | 32 => row.targetWordLow20
  | 33 => row.targetWordHigh8
  | 34 => bitVecM31 row.target.limb0
  | 35 => bitVecM31 row.target.limb1
  | 36 => bitVecM31 row.target.limb2
  | 37 => bitVecM31 row.target.limb3
  | 38 => bitVecM31 row.immediateByte
  | 39 => bitVecM31 row.immediateNibble
  | 40 => boolM31 row.immediateSign
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

def accessClockField (row : Row) (ordinal : Nat) : M31 :=
  TeamACommon.accessClockField row.clock ordinal

def clockGapField (row : Row) (ordinal previous : Nat) : M31 :=
  TeamACommon.clockGapField row.clock ordinal previous

def targetWordField (row : Row) : M31 :=
  row.targetWordLow20 +
    row.targetWordHigh8 * M31.reduce (2 ^ 20)

def stateTargetField (row : Row) : M31 :=
  M31.reduce 4 * targetWordField row

def immediateCompositionField (row : Row) : M31 :=
  bitVecM31 row.immediateByte +
      bitVecM31 row.immediateNibble * M31.reduce 256 -
    boolM31 row.immediateSign * M31.reduce 4096

def immediateSecondByteField (row : Row) : M31 :=
  bitVecM31 row.immediateNibble +
    boolM31 row.immediateSign * M31.reduce 240

def immediateSignByteField (row : Row) : M31 :=
  boolM31 row.immediateSign * M31.reduce 255

def carry1Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb0 +
      bitVecM31 row.immediateByte -
      (bitVecM31 row.target.limb0 + boolM31 row.targetLsb)) *
    M31.reduce 8388608

def carry2Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb1 +
      immediateSecondByteField row +
      carry1Field row -
      bitVecM31 row.target.limb1) *
    M31.reduce 8388608

def carry3Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb2 +
      immediateSignByteField row +
      carry2Field row -
      bitVecM31 row.target.limb2) *
    M31.reduce 8388608

def carry4Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb3 +
      immediateSignByteField row +
      carry3Field row -
      bitVecM31 row.target.limb3) *
    M31.reduce 8388608

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 23
  domain := .programAccess
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce 34,
    bitVecM31 row.rd,
    bitVecM31 row.rs1,
    immediateField row.immediate
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def sourceConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 24
  domain := .memoryAccess
  numerator := -row.enabler
  tuple := #[
    0,
    bitVecM31 row.rs1,
    M31.reduce row.rs1PreviousClock,
    bitVecM31 row.rs1Previous.limb0,
    bitVecM31 row.rs1Previous.limb1,
    bitVecM31 row.rs1Previous.limb2,
    bitVecM31 row.rs1Previous.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 1

def sourceEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 25
  domain := .memoryAccess
  numerator := row.enabler
  tuple := #[
    0,
    bitVecM31 row.rs1,
    accessClockField row 1,
    bitVecM31 row.rs1Next.limb0,
    bitVecM31 row.rs1Next.limb1,
    bitVecM31 row.rs1Next.limb2,
    bitVecM31 row.rs1Next.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def sourceClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 26
  domain := .rangeCheck20
  numerator := -row.enabler
  tuple := #[clockGapField row 1 row.rs1PreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

def sourceMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 27
  domain := .rangeCheck88
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.rs1Next.limb1,
    bitVecM31 row.rs1Next.limb2
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def sourceOuterLookup (row : Row) : EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck88
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.rs1Next.limb0,
    bitVecM31 row.rs1Next.limb3
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def targetLow20Lookup (row : Row) : EvaluatedLookup where
  ordinal := 29
  domain := .rangeCheck20
  numerator := -row.enabler
  tuple := #[row.targetWordLow20]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

def targetHigh8Lookup (row : Row) : EvaluatedLookup where
  ordinal := 30
  domain := .rangeCheck88
  numerator := -row.enabler
  tuple := #[row.targetWordHigh8, 0]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def targetMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 31
  domain := .rangeCheck88
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.target.limb1,
    bitVecM31 row.target.limb2
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def targetM31Lookup (row : Row) : EvaluatedLookup where
  ordinal := 32
  domain := .rangeCheckM31
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.target.limb0,
    bitVecM31 row.target.limb3
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

def immediateRangeLookup (row : Row) : EvaluatedLookup where
  ordinal := 33
  domain := .rangeCheck884
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.immediateByte,
    0,
    (bitVecM31 row.immediateNibble -
      boolM31 row.immediateSign * M31.reduce 8) *
        M31.reduce 2
  ]
  role := .request
  tableId := some .rangeCheck884
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 34
  domain := .registersState
  numerator := -row.enabler
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 35
  domain := .registersState
  numerator := row.enabler
  tuple := #[stateTargetField row, M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

def resultMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 36
  domain := .rangeCheck88
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.result.limb1,
    bitVecM31 row.result.limb2
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def resultM31Lookup (row : Row) : EvaluatedLookup where
  ordinal := 37
  domain := .rangeCheckM31
  numerator := -row.enabler
  tuple := #[
    bitVecM31 row.result.limb0,
    bitVecM31 row.result.limb3
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 38
  domain := .memoryAccess
  numerator := -row.enabler
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
  accessOrdinal := some 2

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 39
  domain := .memoryAccess
  numerator := row.enabler
  tuple := #[
    0,
    bitVecM31 row.rd,
    accessClockField row 2,
    bitVecM31 row.rdNext.limb0,
    bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2,
    bitVecM31 row.rdNext.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 2

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 40
  domain := .rangeCheck20
  numerator := -row.enabler
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
      targetWordField,
      stateTargetField,
      immediateCompositionField,
      immediateSecondByteField,
      immediateSignByteField,
      carry1Field,
      carry2Field,
      carry3Field,
      carry4Field,
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      TeamACommon.wordBytesField,
      SymbolicEvaluation.activeSelectorsAccepted,
      SymbolicEvaluation.lookup?,
      M31.ofNat?
    ] <;>
      simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?
      ]))

set_option maxRecDepth 50000 in
theorem selectorAccepted
    (row : Row)
    (witness : Witness row)
    (enabler : row.enabler = 1) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  change
    (row.enabler == (1 : M31)) &&
      ((M31.reduce 34 : M31) == M31.reduce 34) = true
  simp [enabler]

def expectedLookup? (row : Row) : Nat → Option EvaluatedLookup
  | 23 => some (programLookup row)
  | 24 => some (sourceConsumeLookup row)
  | 25 => some (sourceEmitLookup row)
  | 26 => some (sourceClockLookup row)
  | 27 => some (sourceMiddleLookup row)
  | 28 => some (sourceOuterLookup row)
  | 29 => some (targetLow20Lookup row)
  | 30 => some (targetHigh8Lookup row)
  | 31 => some (targetMiddleLookup row)
  | 32 => some (targetM31Lookup row)
  | 33 => some (immediateRangeLookup row)
  | 34 => some (stateConsumeLookup row)
  | 35 => some (stateEmitLookup row)
  | 36 => some (resultMiddleLookup row)
  | 37 => some (resultM31Lookup row)
  | 38 => some (destinationConsumeLookup row)
  | 39 => some (destinationEmitLookup row)
  | 40 => some (destinationClockLookup row)
  | _ => none

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
theorem lookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 23 = some (programLookup row) ∧
      (evaluation row witness).lookup? 24 =
        some (sourceConsumeLookup row) ∧
      (evaluation row witness).lookup? 25 =
        some (sourceEmitLookup row) ∧
      (evaluation row witness).lookup? 26 =
        some (sourceClockLookup row) ∧
      (evaluation row witness).lookup? 27 =
        some (sourceMiddleLookup row) ∧
      (evaluation row witness).lookup? 28 =
        some (sourceOuterLookup row) ∧
      (evaluation row witness).lookup? 29 =
        some (targetLow20Lookup row) ∧
      (evaluation row witness).lookup? 30 =
        some (targetHigh8Lookup row) ∧
      (evaluation row witness).lookup? 31 =
        some (targetMiddleLookup row) ∧
      (evaluation row witness).lookup? 32 =
        some (targetM31Lookup row) ∧
      (evaluation row witness).lookup? 33 =
        some (immediateRangeLookup row) ∧
      (evaluation row witness).lookup? 34 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 35 =
        some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 36 =
        some (resultMiddleLookup row) ∧
      (evaluation row witness).lookup? 37 =
        some (resultM31Lookup row) ∧
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
        "15309f4ca69cb59fe7889181dd8b6691b11b8e979ac7bbd9528aeb1120497ab4" ∧
      Programs.jalr.source.family = .jalr ∧
      Programs.jalr.source.nodes.size = 151 ∧
      Programs.jalr.source.events.size = 41 ∧
      Programs.jalr.source.projection.programEvent = 23 ∧
      Programs.jalr.source.projection.sourceEvents = #[24, 25] ∧
      Programs.jalr.source.projection.destinationEvents = #[38, 39] ∧
      Programs.jalr.source.projection.stateEvents = #[34, 35] ∧
      Programs.jalr.source.projection.nextPc = 65 := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

private theorem constraintsHoldEvents
    (nodes : LocalValues) :
    (Programs.jalrSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      #[43, 45, 47, 54, 66, 69, 83, 90, 97, 104, 113, 115,
        117, 119, 121, 123, 125, 127, 129, 131, 133, 135, 42].all
        (fun root => nodes.getSymbolic root == 0) := by
  simp [Programs.jalrSource, Event.evalSymbolic]

theorem constraintsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      #[43, 45, 47, 54, 66, 69, 83, 90, 97, 104, 113, 115,
        117, 119, 121, 123, 125, 127, 129, 131, 133, 135, 42].all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) :=
  constraintsHoldEvents (evaluation row witness).nodes

set_option maxRecDepth 50000 in
private theorem node43 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 43 =
      row.enabler * (row.enabler - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node45 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 45 =
      boolM31 row.targetLsb * (boolM31 row.targetLsb - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node47 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 47 =
      boolM31 row.immediateSign * (boolM31 row.immediateSign - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node54 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 54 =
      immediateCompositionField row - immediateField row.immediate := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node66 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 66 =
      TeamACommon.wordBytesField row.target - stateTargetField row := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node69 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 69 =
      row.toPcOverTwo - M31.reduce 2 * targetWordField row := by
  reduce_jalr
  apply congrArg (fun value : M31 => row.toPcOverTwo - value)
  apply M31.ext
  change
    ((targetWordField row).val * (M31.reduce 2).val) %
        M31.modulus =
      ((M31.reduce 2).val * (targetWordField row).val) %
        M31.modulus
  rw [Nat.mul_comm]

set_option maxRecDepth 50000 in
private theorem node83 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 83 =
      carry1Field row * (carry1Field row - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node90 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 90 =
      carry2Field row * (carry2Field row - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node97 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 97 =
      carry3Field row * (carry3Field row - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node104 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 104 =
      carry4Field row * (carry4Field row - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node113 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 113 =
      row.enabler *
        (TeamACommon.wordBytesField row.result -
          (bitVecM31 row.pc + M31.reduce 4)) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node115 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 115 =
      boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node117 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 117 =
      bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node119 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 119 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node121 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 121 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb0 := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node123 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 123 =
      bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb1 := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node125 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 125 =
      bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb2 := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node127 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 127 =
      bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb3 := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node129 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 129 =
      row.enabler *
        (bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node131 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 131 =
      row.enabler *
        (bitVecM31 row.rs1Next.limb1 -
          bitVecM31 row.rs1Previous.limb1) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node133 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 133 =
      row.enabler *
        (bitVecM31 row.rs1Next.limb2 -
          bitVecM31 row.rs1Previous.limb2) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node135 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 135 =
      row.enabler *
        (bitVecM31 row.rs1Next.limb3 -
          bitVecM31 row.rs1Previous.limb3) := by
  reduce_jalr

set_option maxRecDepth 50000 in
private theorem node42 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 42 =
      row.enabler - 1 := by
  reduce_jalr

def ConstraintEquations
    (row : Row)
    (witness : Witness row) : Prop :=
  row.enabler * (row.enabler - 1) = 0 ∧
  boolM31 row.targetLsb * (boolM31 row.targetLsb - 1) = 0 ∧
  boolM31 row.immediateSign * (boolM31 row.immediateSign - 1) = 0 ∧
  immediateCompositionField row - immediateField row.immediate = 0 ∧
  TeamACommon.wordBytesField row.target - stateTargetField row = 0 ∧
  row.toPcOverTwo - M31.reduce 2 * targetWordField row = 0 ∧
  carry1Field row * (carry1Field row - 1) = 0 ∧
  carry2Field row * (carry2Field row - 1) = 0 ∧
  carry3Field row * (carry3Field row - 1) = 0 ∧
  carry4Field row * (carry4Field row - 1) = 0 ∧
  row.enabler *
      (TeamACommon.wordBytesField row.result -
        (bitVecM31 row.pc + M31.reduce 4)) = 0 ∧
  boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) = 0 ∧
  bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) = 0 ∧
  bitVecM31 row.rd * witness.destinationInverse -
      boolM31 row.rdNonzero = 0 ∧
  bitVecM31 row.rdNext.limb0 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb0 = 0 ∧
  bitVecM31 row.rdNext.limb1 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb1 = 0 ∧
  bitVecM31 row.rdNext.limb2 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb2 = 0 ∧
  bitVecM31 row.rdNext.limb3 -
      boolM31 row.rdNonzero * bitVecM31 row.result.limb3 = 0 ∧
  row.enabler *
      (bitVecM31 row.rs1Next.limb0 -
        bitVecM31 row.rs1Previous.limb0) = 0 ∧
  row.enabler *
      (bitVecM31 row.rs1Next.limb1 -
        bitVecM31 row.rs1Previous.limb1) = 0 ∧
  row.enabler *
      (bitVecM31 row.rs1Next.limb2 -
        bitVecM31 row.rs1Previous.limb2) = 0 ∧
  row.enabler *
      (bitVecM31 row.rs1Next.limb3 -
        bitVecM31 row.rs1Previous.limb3) = 0 ∧
  row.enabler - 1 = 0

theorem constraintsHold_iff
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold = true ↔
      ConstraintEquations row witness := by
  rw [constraintsHold_eq]
  cases targetLsb : row.targetLsb <;>
    cases immediateSign : row.immediateSign <;>
      cases destination : row.rdNonzero <;>
        simp [
          ConstraintEquations,
          node43, node45, node47, node54, node66, node69,
          node83, node90, node97, node104, node113, node115,
          node117, node119, node121, node123, node125, node127,
          node129, node131, node133, node135, node42,
          targetLsb, immediateSign, destination,
          boolM31, TeamACommon.boolM31, Lui.boolM31,
        ]

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true

structure ExactLookups (row : Row) (witness : Witness row) : Prop where
  program :
    (evaluation row witness).lookup? 23 = some (programLookup row)
  sourceConsume :
    (evaluation row witness).lookup? 24 = some (sourceConsumeLookup row)
  sourceEmit :
    (evaluation row witness).lookup? 25 = some (sourceEmitLookup row)
  sourceClock :
    (evaluation row witness).lookup? 26 = some (sourceClockLookup row)
  sourceMiddle :
    (evaluation row witness).lookup? 27 = some (sourceMiddleLookup row)
  sourceOuter :
    (evaluation row witness).lookup? 28 = some (sourceOuterLookup row)
  targetLow20 :
    (evaluation row witness).lookup? 29 = some (targetLow20Lookup row)
  targetHigh8 :
    (evaluation row witness).lookup? 30 = some (targetHigh8Lookup row)
  targetMiddle :
    (evaluation row witness).lookup? 31 = some (targetMiddleLookup row)
  targetM31 :
    (evaluation row witness).lookup? 32 = some (targetM31Lookup row)
  immediateRange :
    (evaluation row witness).lookup? 33 = some (immediateRangeLookup row)
  stateConsume :
    (evaluation row witness).lookup? 34 = some (stateConsumeLookup row)
  stateEmit :
    (evaluation row witness).lookup? 35 = some (stateEmitLookup row)
  resultMiddle :
    (evaluation row witness).lookup? 36 = some (resultMiddleLookup row)
  resultM31 :
    (evaluation row witness).lookup? 37 = some (resultM31Lookup row)
  destinationConsume :
    (evaluation row witness).lookup? 38 =
      some (destinationConsumeLookup row)
  destinationEmit :
    (evaluation row witness).lookup? 39 =
      some (destinationEmitLookup row)
  destinationClock :
    (evaluation row witness).lookup? 40 =
      some (destinationClockLookup row)

theorem exactLookups (row : Row) (witness : Witness row) :
    ExactLookups row witness := by
  rcases lookupProjection row witness with
    ⟨program, sourceConsume, sourceEmit, sourceClock,
      sourceMiddle, sourceOuter, targetLow20, targetHigh8,
      targetMiddle, targetM31, immediateRange, stateConsume,
      stateEmit, resultMiddle, resultM31, destinationConsume,
      destinationEmit, destinationClock⟩
  exact {
    program
    sourceConsume
    sourceEmit
    sourceClock
    sourceMiddle
    sourceOuter
    targetLow20
    targetHigh8
    targetMiddle
    targetM31
    immediateRange
    stateConsume
    stateEmit
    resultMiddle
    resultM31
    destinationConsume
    destinationEmit
    destinationClock
  }

structure AirEquations (row : Row) (witness : Witness row) : Prop where
  enablerOne : row.enabler = 1
  immediate :
    immediateCompositionField row = immediateField row.immediate
  targetDecomposition :
    TeamACommon.wordBytesField row.target = stateTargetField row
  targetOverTwo :
    row.toPcOverTwo = M31.reduce 2 * targetWordField row
  carry1 : carry1Field row * (carry1Field row - 1) = 0
  carry2 : carry2Field row * (carry2Field row - 1) = 0
  carry3 : carry3Field row * (carry3Field row - 1) = 0
  carry4 : carry4Field row * (carry4Field row - 1) = 0
  result :
    TeamACommon.wordBytesField row.result =
      bitVecM31 row.pc + M31.reduce 4
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
  source0 :
    bitVecM31 row.rs1Next.limb0 =
      bitVecM31 row.rs1Previous.limb0
  source1 :
    bitVecM31 row.rs1Next.limb1 =
      bitVecM31 row.rs1Previous.limb1
  source2 :
    bitVecM31 row.rs1Next.limb2 =
      bitVecM31 row.rs1Previous.limb2
  source3 :
    bitVecM31 row.rs1Next.limb3 =
      bitVecM31 row.rs1Previous.limb3

theorem airEquations
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    AirEquations row witness := by
  have equations :=
    (constraintsHold_iff row witness).mp accepted.constraints
  rcases equations with
    ⟨_, _, _, immediate, target, overTwo,
      carry1, carry2, carry3, carry4, result, _,
      destinationZero, destinationInverse,
      destination0, destination1, destination2, destination3,
      source0, source1, source2, source3, enablerEquation⟩
  have enablerOne :
      row.enabler = 1 :=
    (M31.sub_eq_zero_iff row.enabler 1).mp enablerEquation
  refine {
    enablerOne
    immediate :=
      (M31.sub_eq_zero_iff
        (immediateCompositionField row)
        (immediateField row.immediate)).mp immediate
    targetDecomposition :=
      (M31.sub_eq_zero_iff
        (TeamACommon.wordBytesField row.target)
        (stateTargetField row)).mp target
    targetOverTwo :=
      (M31.sub_eq_zero_iff
        row.toPcOverTwo
        (M31.reduce 2 * targetWordField row)).mp overTwo
    carry1
    carry2
    carry3
    carry4
    result := ?_
    destinationZero
    destinationInverse
    destination0
    destination1
    destination2
    destination3
    source0 := ?_
    source1 := ?_
    source2 := ?_
    source3 := ?_
  }
  · rw [enablerOne, M31.one_mul] at result
    exact
      (M31.sub_eq_zero_iff
        (TeamACommon.wordBytesField row.result)
        (bitVecM31 row.pc + M31.reduce 4)).mp result
  · rw [enablerOne, M31.one_mul] at source0
    exact
      (M31.sub_eq_zero_iff _ _).mp source0
  · rw [enablerOne, M31.one_mul] at source1
    exact
      (M31.sub_eq_zero_iff _ _).mp source1
  · rw [enablerOne, M31.one_mul] at source2
    exact
      (M31.sub_eq_zero_iff _ _).mp source2
  · rw [enablerOne, M31.one_mul] at source3
    exact
      (M31.sub_eq_zero_iff _ _).mp source3

private theorem byteFieldVal (value : Byte) :
    (bitVecM31 value).val = value.toNat := by
  apply Lui.bitVecM31_val
  have bound := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byte_eq_of_field
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right := by
  apply BitVec.eq_of_toNat_eq
  have values := congrArg M31.val equality
  rw [byteFieldVal left, byteFieldVal right] at values
  exact values

theorem sourceBytes
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rs1Next = row.rs1Previous := by
  have equations := airEquations row witness accepted
  apply WordBytes.eq_of_limbs
  · exact byte_eq_of_field _ _ equations.source0
  · exact byte_eq_of_field _ _ equations.source1
  · exact byte_eq_of_field _ _ equations.source2
  · exact byte_eq_of_field _ _ equations.source3

theorem destinationFlag
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) := by
  have equations := airEquations row witness accepted
  exact
    TeamACommon.destinationFlag_of_equations
      row.rd row.rdNonzero witness.destinationInverse
      equations.destinationZero equations.destinationInverse

theorem destinationBytes
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNext =
      if row.rdNonzero then row.result else WordBytes.zero := by
  have equations := airEquations row witness accepted
  exact
    TeamACommon.destinationBytes_of_equations
      row.rdNext row.result row.rdNonzero
      equations.destination0 equations.destination1
      equations.destination2 equations.destination3

private theorem fixedRequestOfLookup
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness)
    (ordinal : Nat)
    (lookup : EvaluatedLookup)
    (projection :
      (evaluation row witness).lookup? ordinal = some lookup) :
    lookup.fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) ordinal lookup
    accepted.fixedLookups projection

theorem targetLow20Request
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    (targetLow20Lookup row).fixedRequestHolds = true :=
  fixedRequestOfLookup row witness accepted 29 _
    (exactLookups row witness).targetLow20

theorem targetHigh8Request
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    (targetHigh8Lookup row).fixedRequestHolds = true :=
  fixedRequestOfLookup row witness accepted 30 _
    (exactLookups row witness).targetHigh8

theorem targetM31Request
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    (targetM31Lookup row).fixedRequestHolds = true :=
  fixedRequestOfLookup row witness accepted 32 _
    (exactLookups row witness).targetM31

theorem immediateRangeRequest
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    (immediateRangeLookup row).fixedRequestHolds = true :=
  fixedRequestOfLookup row witness accepted 33 _
    (exactLookups row witness).immediateRange

theorem resultM31Request
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    (resultM31Lookup row).fixedRequestHolds = true :=
  fixedRequestOfLookup row witness accepted 37 _
    (exactLookups row witness).resultM31

theorem sourceClockRequest
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    (sourceClockLookup row).fixedRequestHolds = true :=
  fixedRequestOfLookup row witness accepted 26 _
    (exactLookups row witness).sourceClock

theorem destinationClockRequest
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    (destinationClockLookup row).fixedRequestHolds = true :=
  fixedRequestOfLookup row witness accepted 40 _
    (exactLookups row witness).destinationClock

private theorem rangeCheck88FirstBound
    (ordinal : Nat)
    (value : M31)
    (holds :
      (EvaluatedLookup.fixedRequestHolds {
        ordinal
        domain := .rangeCheck88
        numerator := -(1 : M31)
        tuple := #[value, 0]
        role := .request
        tableId := some .rangeCheck88
        accessOrdinal := none
      }) = true) :
    value.val < 256 := by
  have request :
      (-(1 : M31)) = 0 ∨
        FixedTableId.rangeCheck88.contains [value, 0] = true := by
    simpa [
      EvaluatedLookup.fixedRequestHolds,
      EvaluatedLookup.isLive,
      EvaluatedLookup.fixedMembership,
    ] using holds
  rcases request with impossible | membership
  · have nonzero : (-(1 : M31)) ≠ 0 := by decide
    exact False.elim (nonzero impossible)
  · exact
      (FixedTableId.rangeCheck88_contains_iff value 0).mp membership |>.1

private theorem outerM31RequestHolds_iff
    (ordinal : Nat)
    (bytes : WordBytes) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal
      domain := .rangeCheckM31
      numerator := -(1 : M31)
      tuple := #[bitVecM31 bytes.limb0, bitVecM31 bytes.limb3]
      role := .request
      tableId := some .rangeCheckM31
      accessOrdinal := none
    }) = true ↔
      bytes.limb0.toNat + 2 ^ 8 * bytes.limb3.toNat <
        2 ^ 15 - 1 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
  ]
  simp [byteFieldVal]
  have lowBound : bytes.limb0.toNat < 256 := by
    simpa using bytes.limb0.isLt
  constructor
  · intro holds
    rcases holds with impossible | holds
    · have nonzero : (-(1 : M31)) ≠ 0 := by decide
      exact False.elim (nonzero impossible)
    · exact holds.2
  · intro endpointBound
    have highBound : bytes.limb3.toNat < 128 := by omega
    exact Or.inr ⟨⟨lowBound, highBound⟩, endpointBound⟩

theorem targetLow20Bound
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.targetWordLow20.val < 2 ^ 20 := by
  have request := targetLow20Request row witness accepted
  have enabler := (airEquations row witness accepted).enablerOne
  exact
    (TeamACommon.rangeCheck20RequestHolds_iff
      29 none row.targetWordLow20).mp
      (by simpa [targetLow20Lookup, enabler] using request)

theorem targetHigh8Bound
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.targetWordHigh8.val < 256 := by
  have request := targetHigh8Request row witness accepted
  have enabler := (airEquations row witness accepted).enablerOne
  exact
    rangeCheck88FirstBound 30 row.targetWordHigh8
      (by simpa [targetHigh8Lookup, enabler] using request)

theorem targetValueBound
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.target.value < M31.modulus := by
  have request := targetM31Request row witness accepted
  have enabler := (airEquations row witness accepted).enablerOne
  have endpoints :=
    (outerM31RequestHolds_iff 32 row.target).mp
      (by simpa [targetM31Lookup, enabler] using request)
  have limb0 := row.target.limb0.isLt
  have limb1 := row.target.limb1.isLt
  have limb2 := row.target.limb2.isLt
  have limb3 := row.target.limb3.isLt
  simp only [Nat.reducePow] at limb0 limb1 limb2 limb3
  simp only [WordBytes.value]
  rw [M31.modulus_eq]
  omega

theorem resultValueBound
    (row : Row) (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.result.value < M31.modulus := by
  have request := resultM31Request row witness accepted
  have enabler := (airEquations row witness accepted).enablerOne
  have endpoints :=
    (outerM31RequestHolds_iff 37 row.result).mp
      (by simpa [resultM31Lookup, enabler] using request)
  have limb0 := row.result.limb0.isLt
  have limb1 := row.result.limb1.isLt
  have limb2 := row.result.limb2.isLt
  have limb3 := row.result.limb3.isLt
  simp only [Nat.reducePow] at limb0 limb1 limb2 limb3
  simp only [WordBytes.value]
  rw [M31.modulus_eq]
  omega

private theorem accessClockBound
    (row : Row)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 2) :
    accessClock row.clock ordinal < 2 ^ 26 := by
  simp only [accessClock]
  have bound := admission.clockBound
  omega

private theorem accessClockField_eq
    (row : Row)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 2) :
    accessClockField row ordinal =
      M31.reduce (accessClock row.clock ordinal) := by
  apply M31.ext
  rw [
    accessClockField,
    TeamACommon.accessClockField_val
      row.clock ordinal admission.clockPositive admission.clockBound
      (by omega),
    M31.reduce_val_of_lt,
  ]
  have bound := accessClockBound row admission ordinal ordinalBound
  simp [M31.modulus_eq] at *
  omega

theorem sourceClock
    (row : Row) (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    validPreviousClock
      row.rs1PreviousClock (accessClock row.clock 1) := by
  apply TeamACommon.validPreviousClock_of_gap
  · simp only [accessClock]
    omega
  · exact accessClockBound row admission 1 (by decide)
  · exact admission.sourcePreviousBound
  · have request := sourceClockRequest row witness accepted
    have enabler := (airEquations row witness accepted).enablerOne
    have gap :=
      (TeamACommon.rangeCheck20RequestHolds_iff
        26 (some 1) (clockGapField row 1 row.rs1PreviousClock)).mp
        (by simpa [sourceClockLookup, enabler] using request)
    have accessEq := accessClockField_eq row admission 1 (by decide)
    unfold accessClockField at accessEq
    rw [clockGapField, TeamACommon.clockGapField, accessEq] at gap
    exact gap

theorem destinationClock
    (row : Row) (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    validPreviousClock
      row.rdPreviousClock (accessClock row.clock 2) := by
  apply TeamACommon.validPreviousClock_of_gap
  · simp only [accessClock]
    omega
  · exact accessClockBound row admission 2 (by decide)
  · exact admission.destinationPreviousBound
  · have request := destinationClockRequest row witness accepted
    have enabler := (airEquations row witness accepted).enablerOne
    have gap :=
      (TeamACommon.rangeCheck20RequestHolds_iff
        40 (some 2) (clockGapField row 2 row.rdPreviousClock)).mp
        (by simpa [destinationClockLookup, enabler] using request)
    have accessEq := accessClockField_eq row admission 2 (by decide)
    unfold accessClockField at accessEq
    rw [clockGapField, TeamACommon.clockGapField, accessEq] at gap
    exact gap

def rawImmediateUnsigned (row : Row) : Nat :=
  row.immediateByte.toNat + 256 * row.immediateNibble.toNat

def rawImmediateFieldValue (row : Row) : Nat :=
  if row.immediateSign
  then M31.modulus + rawImmediateUnsigned row - 4096
  else rawImmediateUnsigned row

private theorem rawImmediateUnsignedBound (row : Row) :
    rawImmediateUnsigned row < 4096 := by
  have byteBound := row.immediateByte.isLt
  have nibbleBound := row.immediateNibble.isLt
  simp only [Nat.reducePow] at byteBound nibbleBound
  simp only [rawImmediateUnsigned]
  omega

private theorem reduceSelf (value : M31) :
    M31.reduce value.val = value := by
  apply M31.ext
  rw [M31.reduce_val_of_lt value.val value.isLt]

private theorem immediateUnsignedField
    (row : Row) :
    bitVecM31 row.immediateByte +
        bitVecM31 row.immediateNibble * M31.reduce 256 =
      M31.reduce (rawImmediateUnsigned row) := by
  simp only [
    bitVecM31,
    TeamACommon.bitVecM31,
    Lui.bitVecM31,
    rawImmediateUnsigned,
  ]
  rw [
    TeamACommon.reduceMul row.immediateNibble.toNat 256,
    TeamACommon.reduceAdd
      row.immediateByte.toNat
      (row.immediateNibble.toNat * 256),
  ]
  congr 1
  omega

theorem immediateCompositionField_eq
    (row : Row) :
    immediateCompositionField row =
      M31.reduce (rawImmediateFieldValue row) := by
  rw [immediateCompositionField, immediateUnsignedField]
  cases sign : row.immediateSign
  · simp [
      sign,
      rawImmediateFieldValue,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
    ]
  · simp only [
      sign,
      rawImmediateFieldValue,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      M31.one_mul,
      ↓reduceIte,
    ]
    apply M31.ext
    have unsignedBound := rawImmediateUnsignedBound row
    have unsignedField :
        (M31.reduce (rawImmediateUnsigned row)).val =
          rawImmediateUnsigned row :=
      M31.reduce_val_of_lt _ (by
        rw [M31.modulus_eq]
        omega)
    have fourKField :
        (M31.reduce 4096).val = 4096 :=
      M31.reduce_val_of_lt 4096 (by decide)
    have ordered :
        (M31.reduce (rawImmediateUnsigned row)).val <
          (M31.reduce 4096).val := by
      rw [unsignedField, fourKField]
      exact unsignedBound
    have signedBound :
        M31.modulus + rawImmediateUnsigned row - 4096 <
          M31.modulus := by
      rw [M31.modulus_eq]
      omega
    have signedField :
        (M31.reduce
          (M31.modulus + rawImmediateUnsigned row - 4096)).val =
            M31.modulus + rawImmediateUnsigned row - 4096 :=
      M31.reduce_val_of_lt _ signedBound
    rw [
      M31.sub_val_of_lt _ _ ordered,
      unsignedField,
      fourKField,
      signedField,
    ]

private theorem canonicalImmediateFieldValueBound
    (immediate : BitVec 12) :
    immediateFieldValue immediate < M31.modulus := by
  have bound := immediate.isLt
  simp only [Nat.reducePow] at bound
  cases sign : immediate.msb <;>
    simp [immediateFieldValue, sign, M31.modulus_eq] <;>
      omega

private theorem immediateToNatDecomposition
    (immediate : BitVec 12) :
    immediate.toNat =
      (BitVec.extractLsb 7 0 immediate).toNat +
        256 * (BitVec.extractLsb 11 8 immediate).toNat := by
  simp only [
    BitVec.extractLsb_toNat,
    Nat.shiftRight_eq_div_pow,
    Nat.reducePow,
    Nat.div_one,
  ]
  have bound := immediate.isLt
  simp only [Nat.reducePow] at bound
  omega

theorem immediateComponents
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.immediateByte = BitVec.extractLsb 7 0 row.immediate ∧
      row.immediateNibble = BitVec.extractLsb 11 8 row.immediate ∧
      row.immediateSign = row.immediate.msb := by
  have equation := (airEquations row witness accepted).immediate
  rw [immediateCompositionField_eq] at equation
  change
    M31.reduce (rawImmediateFieldValue row) =
      M31.reduce (immediateFieldValue row.immediate) at equation
  have rawBound :
      rawImmediateFieldValue row < M31.modulus := by
    have unsignedBound := rawImmediateUnsignedBound row
    cases sign : row.immediateSign <;>
      simp [rawImmediateFieldValue, sign, M31.modulus_eq] <;>
        omega
  have canonicalBound :=
    canonicalImmediateFieldValueBound row.immediate
  have signedValues := congrArg M31.val equation
  rw [
    M31.reduce_val_of_lt _ rawBound,
    M31.reduce_val_of_lt _ canonicalBound,
  ] at signedValues
  have refined :
      rawImmediateUnsigned row = row.immediate.toNat ∧
        row.immediateSign = row.immediate.msb := by
    have unsignedBound := rawImmediateUnsignedBound row
    have canonicalUnsignedBound := row.immediate.isLt
    simp only [Nat.reducePow] at canonicalUnsignedBound
    cases rawSign : row.immediateSign <;>
      cases canonicalSign : row.immediate.msb <;>
        simp [
          rawImmediateFieldValue,
          immediateFieldValue,
          rawSign,
          canonicalSign,
          M31.modulus_eq,
        ] at signedValues ⊢ <;>
          omega
  have decomposition :=
    immediateToNatDecomposition row.immediate
  have rawByteBound := row.immediateByte.isLt
  have canonicalByteBound :=
    (BitVec.extractLsb 7 0 row.immediate).isLt
  have rawNibbleBound := row.immediateNibble.isLt
  have canonicalNibbleBound :=
    (BitVec.extractLsb 11 8 row.immediate).isLt
  simp only [Nat.reducePow] at rawByteBound canonicalByteBound rawNibbleBound canonicalNibbleBound
  have byteValue :
      row.immediateByte.toNat =
        (BitVec.extractLsb 7 0 row.immediate).toNat := by
    simp only [rawImmediateUnsigned] at refined
    omega
  have nibbleValue :
      row.immediateNibble.toNat =
        (BitVec.extractLsb 11 8 row.immediate).toNat := by
    simp only [rawImmediateUnsigned] at refined
    omega
  exact ⟨
    BitVec.eq_of_toNat_eq byteValue,
    BitVec.eq_of_toNat_eq nibbleValue,
    refined.2
  ⟩

def immediateBytes (row : Row) : WordBytes where
  limb0 := row.immediateByte
  limb1 :=
    BitVec.ofNat 8
      (row.immediateNibble.toNat + 240 * row.immediateSign.toNat)
  limb2 := BitVec.ofNat 8 (255 * row.immediateSign.toNat)
  limb3 := BitVec.ofNat 8 (255 * row.immediateSign.toNat)

theorem immediateBytesWord
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (immediateBytes row).word =
      BitVec.signExtend 32 row.immediate := by
  rcases immediateComponents row witness accepted with
    ⟨byte, nibble, sign⟩
  have decomposition :=
    immediateToNatDecomposition row.immediate
  have immediateBound := row.immediate.isLt
  have nibbleBound :=
    (BitVec.extractLsb 11 8 row.immediate).isLt
  simp only [Nat.reducePow] at immediateBound nibbleBound
  have immediateWordBound :
      row.immediate.toNat < 4294967296 := by
    omega
  have nibbleByteBound :
      (BitVec.extractLsb 11 8 row.immediate).toNat < 256 := by
    omega
  have signedNibbleByteBound :
      (BitVec.extractLsb 11 8 row.immediate).toNat + 240 < 256 := by
    omega
  cases signBit : row.immediate.msb
  · apply BitVec.eq_of_toNat_eq
    simp only [
      WordBytes.word_toNat,
      WordBytes.value,
      immediateBytes,
      byte,
      nibble,
      sign,
      BitVec.toNat_ofNat,
      Nat.reducePow,
      signBit,
      Bool.toNat,
      cond_false,
      BitVec.toNat_signExtend,
      BitVec.toNat_setWidth,
      Bool.false_eq_true,
      ↓reduceIte,
      Nat.mul_zero,
      Nat.add_zero,
      Nat.zero_mod,
    ]
    rw [
      Nat.mod_eq_of_lt nibbleByteBound,
      Nat.mod_eq_of_lt immediateWordBound,
    ]
    omega
  · apply BitVec.eq_of_toNat_eq
    simp only [
      WordBytes.word_toNat,
      WordBytes.value,
      immediateBytes,
      byte,
      nibble,
      sign,
      BitVec.toNat_ofNat,
      Nat.reducePow,
      signBit,
      Bool.toNat,
      cond_true,
      BitVec.toNat_signExtend,
      BitVec.toNat_setWidth,
      ↓reduceIte,
      Nat.mul_one,
      Nat.reduceMul,
      Nat.reduceMod,
      Nat.reduceSub,
    ]
    rw [
      Nat.mod_eq_of_lt signedNibbleByteBound,
      Nat.mod_eq_of_lt immediateWordBound,
    ]
    omega

def targetQuotient (row : Row) : Nat :=
  row.targetWordLow20.val +
    row.targetWordHigh8.val * 2 ^ 20

theorem targetDecomposition
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.target.value = 4 * targetQuotient row := by
  have lowBound := targetLow20Bound row witness accepted
  have highBound := targetHigh8Bound row witness accepted
  have targetBound := targetValueBound row witness accepted
  have quotientBound : targetQuotient row < 2 ^ 28 := by
    simp only [targetQuotient]
    omega
  have productBound :
      4 * targetQuotient row < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have quotientField :
      targetWordField row = M31.reduce (targetQuotient row) := by
    rw [
      targetWordField,
      ← reduceSelf row.targetWordLow20,
      ← reduceSelf row.targetWordHigh8,
      TeamACommon.reduceMul,
      TeamACommon.reduceAdd,
    ]
    rfl
  have fieldEquality :=
    (airEquations row witness accepted).targetDecomposition
  rw [
    TeamACommon.wordBytesField_eq_reduce,
    stateTargetField,
    quotientField,
    TeamACommon.reduceMul,
  ] at fieldEquality
  exact
    (M31.reduce_injective_of_lt targetBound productBound).mp
      fieldEquality

theorem targetAligned
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.target.word.toNat % 4 = 0 := by
  rw [WordBytes.word_toNat,
    targetDecomposition row witness accepted]
  omega

theorem targetOverTwo
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.toPcOverTwo =
      M31.reduce (2 * targetQuotient row) := by
  have lowBound := targetLow20Bound row witness accepted
  have highBound := targetHigh8Bound row witness accepted
  have quotientBound : targetQuotient row < 2 ^ 28 := by
    simp only [targetQuotient]
    omega
  have quotientField :
      targetWordField row = M31.reduce (targetQuotient row) := by
    rw [
      targetWordField,
      ← reduceSelf row.targetWordLow20,
      ← reduceSelf row.targetWordHigh8,
      TeamACommon.reduceMul,
      TeamACommon.reduceAdd,
    ]
    rfl
  rw [
    (airEquations row witness accepted).targetOverTwo,
    quotientField,
    TeamACommon.reduceMul,
  ]

private theorem boolM31_eq_reduce (value : Bool) :
    boolM31 value = M31.reduce value.toNat := by
  cases value <;> rfl

private theorem immediateSecondByteField_eq
    (row : Row) :
    immediateSecondByteField row =
      M31.reduce
        (row.immediateNibble.toNat +
          240 * row.immediateSign.toNat) := by
  rw [
    immediateSecondByteField,
    boolM31_eq_reduce,
  ]
  simp only [
    bitVecM31,
    TeamACommon.bitVecM31,
    Lui.bitVecM31,
  ]
  rw [
    TeamACommon.reduceMul,
    TeamACommon.reduceAdd,
  ]
  congr 1
  omega

private theorem immediateSignByteField_eq
    (row : Row) :
    immediateSignByteField row =
      M31.reduce (255 * row.immediateSign.toNat) := by
  rw [
    immediateSignByteField,
    boolM31_eq_reduce,
    TeamACommon.reduceMul,
  ]
  congr 1
  omega

private theorem targetLowResultField_eq
    (row : Row) :
    bitVecM31 row.target.limb0 + boolM31 row.targetLsb =
      M31.reduce
        (row.target.limb0.toNat + row.targetLsb.toNat) := by
  rw [boolM31_eq_reduce]
  simp only [
    bitVecM31,
    TeamACommon.bitVecM31,
    Lui.bitVecM31,
  ]
  rw [TeamACommon.reduceAdd]

theorem carryRecurrence
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    ∃ carry1 carry2 carry3 carry4 : BitVec 1,
      row.rs1Next.limb0.toNat + row.immediateByte.toNat =
          row.target.limb0.toNat + row.targetLsb.toNat +
            256 * carry1.toNat ∧
      row.rs1Next.limb1.toNat +
            (row.immediateNibble.toNat +
              240 * row.immediateSign.toNat) +
            carry1.toNat =
          row.target.limb1.toNat + 256 * carry2.toNat ∧
      row.rs1Next.limb2.toNat +
            255 * row.immediateSign.toNat +
            carry2.toNat =
          row.target.limb2.toNat + 256 * carry3.toNat ∧
      row.rs1Next.limb3.toNat +
            255 * row.immediateSign.toNat +
            carry3.toNat =
          row.target.limb3.toNat + 256 * carry4.toNat := by
  have equations := airEquations row witness accepted
  have source0Bound := row.rs1Next.limb0.isLt
  have source1Bound := row.rs1Next.limb1.isLt
  have source2Bound := row.rs1Next.limb2.isLt
  have source3Bound := row.rs1Next.limb3.isLt
  have immediate0Bound := row.immediateByte.isLt
  have immediate1RawBound := row.immediateNibble.isLt
  have target0Bound := row.target.limb0.isLt
  have target1Bound := row.target.limb1.isLt
  have target2Bound := row.target.limb2.isLt
  have target3Bound := row.target.limb3.isLt
  simp only [Nat.reducePow] at source0Bound source1Bound source2Bound source3Bound immediate0Bound immediate1RawBound target0Bound target1Bound target2Bound target3Bound
  have signBound := Bool.toNat_lt row.immediateSign
  have targetLsbBound := Bool.toNat_lt row.targetLsb
  have immediate1Bound :
      row.immediateNibble.toNat +
          240 * row.immediateSign.toNat < 256 := by
    omega
  have signByteBound :
      255 * row.immediateSign.toNat < 256 := by
    omega
  have decomposition :=
    targetDecomposition row witness accepted
  have targetLowResultBound :
      row.target.limb0.toNat + row.targetLsb.toNat < 256 := by
    simp only [WordBytes.value, targetQuotient] at decomposition
    omega
  obtain ⟨carry1, carry1Value, recurrence1⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb0.toNat
      row.immediateByte.toNat
      0
      (row.target.limb0.toNat + row.targetLsb.toNat)
      (carry1Field row)
      source0Bound
      immediate0Bound
      (by decide)
      targetLowResultBound
      (by
        rw [
          carry1Field,
          targetLowResultField_eq,
        ]
        simp only [
          bitVecM31,
          TeamACommon.bitVecM31,
          Lui.bitVecM31,
          M31.reduce_zero,
          M31.add_zero,
        ])
      equations.carry1
  have carry1Bound := carry1.isLt
  simp only [Nat.reducePow] at carry1Bound
  obtain ⟨carry2, carry2Value, recurrence2⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb1.toNat
      (row.immediateNibble.toNat +
        240 * row.immediateSign.toNat)
      carry1.toNat
      row.target.limb1.toNat
      (carry2Field row)
      source1Bound
      immediate1Bound
      carry1Bound
      target1Bound
      (by
        rw [
          carry2Field,
          immediateSecondByteField_eq,
          carry1Value,
        ]
        rfl)
      equations.carry2
  have carry2Bound := carry2.isLt
  simp only [Nat.reducePow] at carry2Bound
  obtain ⟨carry3, carry3Value, recurrence3⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb2.toNat
      (255 * row.immediateSign.toNat)
      carry2.toNat
      row.target.limb2.toNat
      (carry3Field row)
      source2Bound
      signByteBound
      carry2Bound
      target2Bound
      (by
        rw [
          carry3Field,
          immediateSignByteField_eq,
          carry2Value,
        ]
        rfl)
      equations.carry3
  have carry3Bound := carry3.isLt
  simp only [Nat.reducePow] at carry3Bound
  obtain ⟨carry4, _, recurrence4⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb3.toNat
      (255 * row.immediateSign.toNat)
      carry3.toNat
      row.target.limb3.toNat
      (carry4Field row)
      source3Bound
      signByteBound
      carry3Bound
      target3Bound
      (by
        rw [
          carry4Field,
          immediateSignByteField_eq,
          carry3Value,
        ]
        rfl)
      equations.carry4
  exact ⟨
    carry1, carry2, carry3, carry4,
    by simpa [Nat.add_assoc] using recurrence1,
    by simpa [Nat.add_assoc] using recurrence2,
    by simpa [Nat.add_assoc] using recurrence3,
    by simpa [Nat.add_assoc] using recurrence4
  ⟩

private theorem immediateBytesValue
    (row : Row) :
    (immediateBytes row).value =
      row.immediateByte.toNat +
        256 *
          (row.immediateNibble.toNat +
            240 * row.immediateSign.toNat) +
        65536 * (255 * row.immediateSign.toNat) +
        16777216 * (255 * row.immediateSign.toNat) := by
  have nibbleBound := row.immediateNibble.isLt
  have signBound := Bool.toNat_lt row.immediateSign
  simp only [Nat.reducePow] at nibbleBound
  simp only [
    immediateBytes,
    WordBytes.value,
    BitVec.toNat_ofNat,
    Nat.reducePow,
  ]
  rw [
    Nat.mod_eq_of_lt (by omega :
      row.immediateNibble.toNat +
        240 * row.immediateSign.toNat < 256),
    Nat.mod_eq_of_lt (by omega :
      255 * row.immediateSign.toNat < 256),
  ]

theorem additionRecurrenceValue
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    ∃ carry4 : BitVec 1,
      row.rs1Next.value + (immediateBytes row).value =
        row.target.value + row.targetLsb.toNat +
          4294967296 * carry4.toNat := by
  rcases carryRecurrence row witness accepted with
    ⟨carry1, carry2, carry3, carry4,
      limb0, limb1, limb2, limb3⟩
  refine ⟨carry4, ?_⟩
  rw [immediateBytesValue]
  simp only [WordBytes.value]
  omega

/-- The four byte recurrences implement RV32 addition modulo `2^32`.
The separate low-bit witness is still present on the right; the following
theorem clears it when deriving the architectural JALR target. -/
theorem unalignedTargetValue
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (unalignedTarget row.rs1Previous.word row.immediate).toNat =
      row.target.value + row.targetLsb.toNat := by
  rcases additionRecurrenceValue row witness accepted with
    ⟨carry4, recurrence⟩
  have source := sourceBytes row witness accepted
  have immediate := immediateBytesWord row witness accepted
  have targetBound := targetValueBound row witness accepted
  have targetLsbBound := Bool.toNat_lt row.targetLsb
  have targetSumBound :
      row.target.value + row.targetLsb.toNat < 4294967296 := by
    rw [M31.modulus_eq] at targetBound
    omega
  rw [
    unalignedTarget,
    ← source,
    ← immediate,
    BitVec.toNat_add,
    WordBytes.word_toNat,
    WordBytes.word_toNat,
  ]
  simp only [Nat.reducePow]
  rw [recurrence]
  omega

theorem u32Addition
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.target.word +
        BitVec.ofNat 32 row.targetLsb.toNat =
      unalignedTarget row.rs1Previous.word row.immediate := by
  apply BitVec.eq_of_toNat_eq
  have targetBound := targetValueBound row witness accepted
  have targetLsbBound := Bool.toNat_lt row.targetLsb
  have targetSumBound :
      row.target.value + row.targetLsb.toNat < 4294967296 := by
    rw [M31.modulus_eq] at targetBound
    omega
  rw [
    BitVec.toNat_add,
    WordBytes.word_toNat,
    BitVec.toNat_ofNat,
  ]
  simp only [Nat.reducePow]
  rw [
    Nat.mod_eq_of_lt (by omega :
      row.targetLsb.toNat < 4294967296),
    Nat.mod_eq_of_lt targetSumBound,
    unalignedTargetValue row witness accepted,
  ]

theorem targetIsJumpTarget
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.target.word =
      jumpTarget row.rs1Previous.word row.immediate := by
  apply BitVec.eq_of_toNat_eq
  have unaligned :=
    unalignedTargetValue row witness accepted
  have decomposition :=
    targetDecomposition row witness accepted
  have targetBound := targetValueBound row witness accepted
  have targetLsbBound := Bool.toNat_lt row.targetLsb
  have jumpBound :
      (unalignedTarget row.rs1Previous.word row.immediate).toNat /
          2 * 2 <
        4294967296 := by
    have bound :=
      (unalignedTarget row.rs1Previous.word row.immediate).isLt
    simp only [Nat.reducePow] at bound
    omega
  rw [
    WordBytes.word_toNat,
    jumpTarget,
    BitVec.toNat_ofNat,
  ]
  simp only [Nat.reducePow]
  rw [
    Nat.mod_eq_of_lt jumpBound,
    unaligned,
  ]
  omega

theorem resultIsLink
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    row.result.word = nextPc row.pc := by
  have resultEquation :=
    (airEquations row witness accepted).result
  rw [
    TeamACommon.nextPcField row.pc admission.pcProfileBound,
  ] at resultEquation
  have fieldEquality :
      bitVecM31 row.result.word =
        bitVecM31 (nextPc row.pc) := by
    rw [
      show bitVecM31 row.result.word =
          TeamACommon.wordBytesField row.result by
        simp only [
          bitVecM31,
          TeamACommon.bitVecM31,
          Lui.bitVecM31,
          WordBytes.word_toNat,
          TeamACommon.wordBytesField_eq_reduce,
        ],
      resultEquation,
    ]
  apply
    TeamACommon.bitVecM31_injective_of_bounds
      row.result.word (nextPc row.pc)
  · simpa [WordBytes.word_toNat] using
      resultValueBound row witness accepted
  · rw [TeamACommon.nextPcToNat row.pc admission.pcProfileBound]
    exact admission.pcProfileBound
  · exact fieldEquality

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
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    (stateEmitLookup row).tuple =
      #[
        bitVecM31
          (jumpTarget row.rs1Previous.word row.immediate),
        M31.reduce (row.clock + 1)
      ] := by
  have target := targetIsJumpTarget row witness accepted
  have targetField :
      stateTargetField row =
        bitVecM31
          (jumpTarget row.rs1Previous.word row.immediate) := by
    rw [← target]
    simp only [
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      WordBytes.word_toNat,
    ]
    rw [
      ← (airEquations row witness accepted).targetDecomposition,
      TeamACommon.wordBytesField_eq_reduce,
    ]
  have clockBound : row.clock + 1 < M31.modulus := by
    have bound := admission.clockBound
    rw [M31.modulus_eq]
    omega
  simp only [stateEmitLookup]
  rw [
    targetField,
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
  program :
    (evaluation row witness).lookup? 23 = some (programLookup row)
  sourceConsume :
    (evaluation row witness).lookup? 24 = some (sourceConsumeLookup row)
  sourceEmit :
    (evaluation row witness).lookup? 25 = some (sourceEmitLookup row)
  sourceClockLookup :
    (evaluation row witness).lookup? 26 = some (sourceClockLookup row)
  sourceMiddle :
    (evaluation row witness).lookup? 27 = some (sourceMiddleLookup row)
  sourceOuter :
    (evaluation row witness).lookup? 28 = some (sourceOuterLookup row)
  targetLow20 :
    (evaluation row witness).lookup? 29 = some (targetLow20Lookup row)
  targetHigh8 :
    (evaluation row witness).lookup? 30 = some (targetHigh8Lookup row)
  targetMiddle :
    (evaluation row witness).lookup? 31 = some (targetMiddleLookup row)
  targetM31 :
    (evaluation row witness).lookup? 32 = some (targetM31Lookup row)
  immediateRange :
    (evaluation row witness).lookup? 33 = some (immediateRangeLookup row)
  stateConsume :
    (evaluation row witness).lookup? 34 = some (stateConsumeLookup row)
  stateEmit :
    (evaluation row witness).lookup? 35 = some (stateEmitLookup row)
  resultMiddle :
    (evaluation row witness).lookup? 36 = some (resultMiddleLookup row)
  resultM31 :
    (evaluation row witness).lookup? 37 = some (resultM31Lookup row)
  destinationConsume :
    (evaluation row witness).lookup? 38 =
      some (destinationConsumeLookup row)
  destinationEmit :
    (evaluation row witness).lookup? 39 =
      some (destinationEmitLookup row)
  destinationClockLookup :
    (evaluation row witness).lookup? 40 =
      some (destinationClockLookup row)
  sourceValue : row.rs1Next = row.rs1Previous
  sourceClock :
    validPreviousClock
      row.rs1PreviousClock (accessClock row.clock 1)
  signedImmediate :
    (immediateBytes row).word =
      BitVec.signExtend 32 row.immediate
  wrappedAddition :
    row.target.word + BitVec.ofNat 32 row.targetLsb.toNat =
      unalignedTarget row.rs1Previous.word row.immediate
  target :
    row.target.word =
      jumpTarget row.rs1Previous.word row.immediate
  targetAligned : row.target.word.toNat % 4 = 0
  targetBound : row.target.value < M31.modulus
  link : row.result.word = nextPc row.pc
  destination :
    row.rdNext.word =
      architecturalValue row.rd (nextPc row.pc)
  destinationClock :
    validPreviousClock
      row.rdPreviousClock (accessClock row.clock 2)
  stateEmission :
    (stateEmitLookup row).tuple =
      #[
        bitVecM31
          (jumpTarget row.rs1Previous.word row.immediate),
        M31.reduce (row.clock + 1)
      ]
  programIdentity :
    Programs.jalr.source.contentDigest =
      "15309f4ca69cb59fe7889181dd8b6691b11b8e979ac7bbd9528aeb1120497ab4"

theorem sound
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    ProductionRefinement row witness := by
  rcases lookupProjection row witness with
    ⟨programProjection, sourceConsumeProjection, sourceEmitProjection,
      sourceClockProjection, sourceMiddleProjection, sourceOuterProjection,
      targetLow20Projection, targetHigh8Projection, targetMiddleProjection,
      targetM31Projection, immediateRangeProjection, stateConsumeProjection,
      stateEmitProjection, resultMiddleProjection, resultM31Projection,
      destinationConsumeProjection, destinationEmitProjection,
      destinationClockProjection⟩
  exact {
    selectors := accepted.selectors
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    program := programProjection
    sourceConsume := sourceConsumeProjection
    sourceEmit := sourceEmitProjection
    sourceClockLookup := sourceClockProjection
    sourceMiddle := sourceMiddleProjection
    sourceOuter := sourceOuterProjection
    targetLow20 := targetLow20Projection
    targetHigh8 := targetHigh8Projection
    targetMiddle := targetMiddleProjection
    targetM31 := targetM31Projection
    immediateRange := immediateRangeProjection
    stateConsume := stateConsumeProjection
    stateEmit := stateEmitProjection
    resultMiddle := resultMiddleProjection
    resultM31 := resultM31Projection
    destinationConsume := destinationConsumeProjection
    destinationEmit := destinationEmitProjection
    destinationClockLookup := destinationClockProjection
    sourceValue := sourceBytes row witness accepted
    sourceClock := sourceClock row witness admission accepted
    signedImmediate := immediateBytesWord row witness accepted
    wrappedAddition := u32Addition row witness accepted
    target := targetIsJumpTarget row witness accepted
    targetAligned := targetAligned row witness accepted
    targetBound := targetValueBound row witness accepted
    link := resultIsLink row witness admission accepted
    destination := destinationWord row witness admission accepted
    destinationClock :=
      destinationClock row witness admission accepted
    stateEmission := stateEmitFields row witness admission accepted
    programIdentity := exactProgramIdentity.1
  }

def exampleSource : WordBytes :=
  wordBytes (BitVec.ofNat 32 101)

def exampleTarget : WordBytes :=
  wordBytes (BitVec.ofNat 32 104)

def exampleLink : WordBytes :=
  wordBytes (BitVec.ofNat 32 0x1004)

def exampleRow : Row where
  enabler := 1
  clock := 7
  pc := BitVec.ofNat 32 0x1000
  rd := BitVec.ofNat 5 1
  rdPrevious := WordBytes.zero
  rdPreviousClock := 0
  rdNext := exampleLink
  rs1 := BitVec.ofNat 5 2
  rs1Previous := exampleSource
  rs1PreviousClock := 1
  rs1Next := exampleSource
  immediate := BitVec.ofNat 12 4
  toPcOverTwo := M31.reduce 52
  targetLsb := true
  result := exampleLink
  rdNonzero := true
  targetWordLow20 := M31.reduce 26
  targetWordHigh8 := 0
  target := exampleTarget
  immediateByte := BitVec.ofNat 8 4
  immediateNibble := BitVec.ofNat 4 0
  immediateSign := false

def exampleWitness : Witness exampleRow where
  destinationInverse := 1

theorem exampleAdmission : Admission exampleRow := by
  exact {
    clockPositive := by decide
    clockBound := by decide
    sourcePreviousBound := by decide
    destinationPreviousBound := by decide
    pcProfileBound := by decide
  }

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
theorem exampleAcceptance :
    Acceptance exampleRow exampleWitness := by
  exact {
    selectors := by decide
    constraints := by
      apply (constraintsHold_iff exampleRow exampleWitness).mpr
      simp [
        ConstraintEquations,
        exampleRow,
        exampleWitness,
        exampleSource,
        exampleTarget,
        exampleLink,
        wordBytes,
        immediateField,
        immediateFieldValue,
        immediateCompositionField,
        immediateSecondByteField,
        immediateSignByteField,
        targetWordField,
        stateTargetField,
        carry1Field,
        carry2Field,
        carry3Field,
        carry4Field,
        bitVecM31,
        boolM31,
        TeamACommon.bitVecM31,
        TeamACommon.boolM31,
        TeamACommon.wordBytesField,
        Lui.bitVecM31,
        Lui.boolM31,
        WordBytes.zero,
      ]
      decide
    fixedLookups := by
      simp only [
        exampleRow,
        exampleWitness,
        exampleSource,
        exampleTarget,
        exampleLink,
      ]
      rw [SymbolicEvaluation.fixedLookupsHold]
      reduce_jalr
      simp [
        wordBytes,
        immediateField,
        immediateFieldValue,
        bitVecM31,
        boolM31,
        TeamACommon.bitVecM31,
        TeamACommon.boolM31,
        Lui.bitVecM31,
        Lui.boolM31,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
        EvaluatedLookup.isLive,
        FixedTableId.contains,
        M31.toNat,
        M31.reduce,
        M31.modulus,
      ]
      decide
  }

def zeroDestinationRow : Row :=
  { exampleRow with
    rd := zeroRegister
    rdNext := WordBytes.zero
    rdNonzero := false
  }

def zeroDestinationWitness : Witness zeroDestinationRow where
  destinationInverse := 0

theorem zeroDestinationAdmission :
    Admission zeroDestinationRow := by
  exact {
    clockPositive := by decide
    clockBound := by decide
    sourcePreviousBound := by decide
    destinationPreviousBound := by decide
    pcProfileBound := by decide
  }

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
theorem zeroDestinationAcceptance :
    Acceptance zeroDestinationRow zeroDestinationWitness := by
  exact {
    selectors := by decide
    constraints := by
      apply
        (constraintsHold_iff
          zeroDestinationRow zeroDestinationWitness).mpr
      simp [
        ConstraintEquations,
        zeroDestinationRow,
        zeroDestinationWitness,
        zeroRegister,
        exampleRow,
        exampleSource,
        exampleTarget,
        exampleLink,
        wordBytes,
        immediateField,
        immediateFieldValue,
        immediateCompositionField,
        immediateSecondByteField,
        immediateSignByteField,
        targetWordField,
        stateTargetField,
        carry1Field,
        carry2Field,
        carry3Field,
        carry4Field,
        bitVecM31,
        boolM31,
        TeamACommon.bitVecM31,
        TeamACommon.boolM31,
        TeamACommon.wordBytesField,
        Lui.bitVecM31,
        Lui.boolM31,
        WordBytes.zero,
      ]
      decide
    fixedLookups := by
      simp only [
        zeroDestinationRow,
        zeroDestinationWitness,
        zeroRegister,
        exampleRow,
        exampleSource,
        exampleTarget,
        exampleLink,
        WordBytes.zero,
      ]
      rw [SymbolicEvaluation.fixedLookupsHold]
      reduce_jalr
      simp [
        wordBytes,
        immediateField,
        immediateFieldValue,
        bitVecM31,
        boolM31,
        TeamACommon.bitVecM31,
        TeamACommon.boolM31,
        Lui.bitVecM31,
        Lui.boolM31,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
        EvaluatedLookup.isLive,
        FixedTableId.contains,
        M31.toNat,
        M31.reduce,
        M31.modulus,
      ]
      decide
  }

def sourceAliasRow : Row :=
  { exampleRow with
    rd := BitVec.ofNat 5 1
    rdPrevious := exampleSource
    rdPreviousClock := accessClock 7 1
    rs1 := BitVec.ofNat 5 1
  }

def sourceAliasWitness : Witness sourceAliasRow where
  destinationInverse := 1

theorem sourceAliasAdmission :
    Admission sourceAliasRow := by
  exact {
    clockPositive := by decide
    clockBound := by decide
    sourcePreviousBound := by decide
    destinationPreviousBound := by decide
    pcProfileBound := by decide
  }

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
theorem sourceAliasAcceptance :
    Acceptance sourceAliasRow sourceAliasWitness := by
  exact {
    selectors := by decide
    constraints := by
      apply
        (constraintsHold_iff sourceAliasRow sourceAliasWitness).mpr
      simp [
        ConstraintEquations,
        sourceAliasRow,
        sourceAliasWitness,
        accessClock,
        exampleRow,
        exampleSource,
        exampleTarget,
        exampleLink,
        wordBytes,
        immediateField,
        immediateFieldValue,
        immediateCompositionField,
        immediateSecondByteField,
        immediateSignByteField,
        targetWordField,
        stateTargetField,
        carry1Field,
        carry2Field,
        carry3Field,
        carry4Field,
        bitVecM31,
        boolM31,
        TeamACommon.bitVecM31,
        TeamACommon.boolM31,
        TeamACommon.wordBytesField,
        Lui.bitVecM31,
        Lui.boolM31,
        WordBytes.zero,
      ]
      decide
    fixedLookups := by
      simp only [
        sourceAliasRow,
        sourceAliasWitness,
        accessClock,
        exampleRow,
        exampleSource,
        exampleTarget,
        exampleLink,
        WordBytes.zero,
      ]
      rw [SymbolicEvaluation.fixedLookupsHold]
      reduce_jalr
      simp [
        wordBytes,
        immediateField,
        immediateFieldValue,
        bitVecM31,
        boolM31,
        TeamACommon.bitVecM31,
        TeamACommon.boolM31,
        Lui.bitVecM31,
        Lui.boolM31,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
        EvaluatedLookup.isLive,
        FixedTableId.contains,
        M31.toNat,
        M31.reduce,
        M31.modulus,
      ]
      decide
  }

theorem acceptanceNonvacuous :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧ Acceptance row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance⟩

theorem exampleRefines :
    ProductionRefinement exampleRow exampleWitness :=
  sound exampleRow exampleWitness exampleAdmission exampleAcceptance

theorem zeroDestinationRefines :
    ProductionRefinement zeroDestinationRow zeroDestinationWitness :=
  sound zeroDestinationRow zeroDestinationWitness
    zeroDestinationAdmission zeroDestinationAcceptance

theorem sourceAliasRefines :
    ProductionRefinement sourceAliasRow sourceAliasWitness :=
  sound sourceAliasRow sourceAliasWitness
    sourceAliasAdmission sourceAliasAcceptance

/-- In the concrete alias witness, the value emitted by the first (`rs1`)
access is exactly the value consumed by the later (`rd`) access.  Together
with ordinals `25 < 38`, this witnesses the production source-before-
destination ordering when `rd = rs1`. -/
theorem sourceAliasReadBeforeWrite :
    (sourceEmitLookup sourceAliasRow).tuple =
        (destinationConsumeLookup sourceAliasRow).tuple ∧
      (sourceEmitLookup sourceAliasRow).ordinal <
        (destinationConsumeLookup sourceAliasRow).ordinal := by
  decide

end RiscvRefinement.Air.Bridge.Jalr
