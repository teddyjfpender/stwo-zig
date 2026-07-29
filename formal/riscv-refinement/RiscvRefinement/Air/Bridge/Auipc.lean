import RiscvRefinement.Air.Bridge.Addi
import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Bridge.DecodeTeamA

/-!
# Production AUIPC AIR bridge

The row below is the exact 29-column production layout.  PC and immediate
decompositions remain explicit witnesses: the bridge must derive their
architectural meaning from the generated constraints and fixed-table requests,
including the low-byte constraint which eliminates the M31 alias.
-/

namespace RiscvRefinement.Air.Bridge.Auipc

open RiscvRefinement
open RiscvRefinement.Air.Generated

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

def immediateWord (encoded : BitVec 20) : Word :=
  Decode.auipcImmediate encoded

theorem immediateWordToNat (encoded : BitVec 20) :
    (immediateWord encoded).toNat =
      4096 * encoded.toNat := by
  simp only [
    immediateWord,
    Decode.auipcImmediate,
    BitVec.append_eq,
    toNat_append_arith,
    BitVec.toNat_ofNat,
    Nat.reducePow,
    Nat.zero_mod,
  ]
  omega

def immediateFieldValue (encoded : BitVec 20) : Nat :=
  let value := immediateWord encoded
  if value.msb then value.toNat - 2 else value.toNat

def immediateField (encoded : BitVec 20) : M31 :=
  M31.reduce (immediateFieldValue encoded)

def pcRelativeValue (pc : Word) (encoded : BitVec 20) : Word :=
  pc + immediateWord encoded

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

structure Row where
  clock : Nat
  pc : Word
  rd : RegisterIndex
  rdPrevious : WordBytes
  rdPreviousClock : Nat
  rdNext : WordBytes
  immediateEncoded : BitVec 20
  immediateFelt : M31
  result : WordBytes
  rdNonzero : Bool
  pcLimbs : WordBytes
  immediateLimbs : WordBytes
  immediateSign : Bool
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
  | 13 => row.immediateFelt
  | 14 => bitVecM31 row.result.limb0
  | 15 => bitVecM31 row.result.limb1
  | 16 => bitVecM31 row.result.limb2
  | 17 => bitVecM31 row.result.limb3
  | 18 => boolM31 row.rdNonzero
  | 19 => witness.destinationInverse
  | 20 => bitVecM31 row.pcLimbs.limb0
  | 21 => bitVecM31 row.pcLimbs.limb1
  | 22 => bitVecM31 row.pcLimbs.limb2
  | 23 => bitVecM31 row.pcLimbs.limb3
  | 24 => bitVecM31 row.immediateLimbs.limb0
  | 25 => bitVecM31 row.immediateLimbs.limb1
  | 26 => bitVecM31 row.immediateLimbs.limb2
  | 27 => bitVecM31 row.immediateLimbs.limb3
  | 28 => boolM31 row.immediateSign
  | _ => 0

def evaluation (row : Row) (witness : Witness row) :
    SymbolicEvaluation :=
  Programs.auipc.evalSymbolic (columns row witness)

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcProfileBound : row.pc.toNat < 2 ^ 30
  immediateFieldBinds :
    row.immediateFelt = immediateField row.immediateEncoded

def accessClockField (row : Row) : M31 :=
  TeamACommon.accessClockField row.clock 1

def destinationClockGapField (row : Row) : M31 :=
  TeamACommon.clockGapField row.clock 1 row.rdPreviousClock

def carry1Field (row : Row) : M31 :=
  (bitVecM31 row.pcLimbs.limb0 +
      bitVecM31 row.immediateLimbs.limb0 -
      bitVecM31 row.result.limb0) *
    M31.reduce 8388608

def carry2Field (row : Row) : M31 :=
  (bitVecM31 row.pcLimbs.limb1 +
      bitVecM31 row.immediateLimbs.limb1 +
      carry1Field row -
      bitVecM31 row.result.limb1) *
    M31.reduce 8388608

def carry3Field (row : Row) : M31 :=
  (bitVecM31 row.pcLimbs.limb2 +
      bitVecM31 row.immediateLimbs.limb2 +
      carry2Field row -
      bitVecM31 row.result.limb2) *
    M31.reduce 8388608

def carry4Field (row : Row) : M31 :=
  (bitVecM31 row.pcLimbs.limb3 +
      bitVecM31 row.immediateLimbs.limb3 +
      carry3Field row -
      bitVecM31 row.result.limb3) *
    M31.reduce 8388608

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 17
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce 36,
    bitVecM31 row.rd, row.immediateFelt, 0]
  role := .request
  tableId := none
  accessOrdinal := none

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
  tuple := #[bitVecM31 row.pc + M31.reduce 4,
    M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

def resultLowLookup (row : Row) : EvaluatedLookup where
  ordinal := 20
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.result.limb0,
    bitVecM31 row.result.limb1]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def resultHighLookup (row : Row) : EvaluatedLookup where
  ordinal := 21
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.result.limb2,
    bitVecM31 row.result.limb3]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def pcMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 22
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pcLimbs.limb1,
    bitVecM31 row.pcLimbs.limb2]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def pcM31Lookup (row : Row) : EvaluatedLookup where
  ordinal := 23
  domain := .rangeCheckM31
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pcLimbs.limb0,
    bitVecM31 row.pcLimbs.limb3]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

def immediateMiddleLookup (row : Row) : EvaluatedLookup where
  ordinal := 24
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.immediateLimbs.limb1,
    bitVecM31 row.immediateLimbs.limb2]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def immediateM31Lookup (row : Row) : EvaluatedLookup where
  ordinal := 25
  domain := .rangeCheckM31
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.immediateLimbs.limb0,
    bitVecM31 row.immediateLimbs.limb3 -
      boolM31 row.immediateSign * M31.reduce 128
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 26
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[0, bitVecM31 row.rd,
    M31.reduce row.rdPreviousClock,
    bitVecM31 row.rdPrevious.limb0,
    bitVecM31 row.rdPrevious.limb1,
    bitVecM31 row.rdPrevious.limb2,
    bitVecM31 row.rdPrevious.limb3]
  role := .consume
  tableId := none
  accessOrdinal := some 1

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 27
  domain := .memoryAccess
  numerator := 1
  tuple := #[0, bitVecM31 row.rd, accessClockField row,
    bitVecM31 row.rdNext.limb0,
    bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2,
    bitVecM31 row.rdNext.limb3]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[destinationClockGapField row]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

macro "reduce_auipc" : tactic =>
  `(tactic|
    (simp only [
      evaluation,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.auipc,
      Programs.auipcSource,
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
      resultLowLookup,
      resultHighLookup,
      pcMiddleLookup,
      pcM31Lookup,
      immediateMiddleLookup,
      immediateM31Lookup,
      destinationConsumeLookup,
      destinationEmitLookup,
      destinationClockLookup,
      accessClockField,
      destinationClockGapField,
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      TeamACommon.wordBytesField,
      carry1Field,
      carry2Field,
      carry3Field,
      carry4Field,
      SymbolicEvaluation.lookup?,
      M31.ofNat?
    ] <;>
      simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?
      ]))

set_option maxRecDepth 30000 in
theorem selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  simp only [
    evaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    Programs.auipc,
    Programs.auipcSource,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    SymbolicEvaluation.activeSelectorsAccepted,
    columns,
    M31.ofNat?,
  ]
  rfl

def expectedLookup? (row : Row) : Nat → Option EvaluatedLookup
  | 17 => some (programLookup row)
  | 18 => some (stateConsumeLookup row)
  | 19 => some (stateEmitLookup row)
  | 20 => some (resultLowLookup row)
  | 21 => some (resultHighLookup row)
  | 22 => some (pcMiddleLookup row)
  | 23 => some (pcM31Lookup row)
  | 24 => some (immediateMiddleLookup row)
  | 25 => some (immediateM31Lookup row)
  | 26 => some (destinationConsumeLookup row)
  | 27 => some (destinationEmitLookup row)
  | 28 => some (destinationClockLookup row)
  | _ => none

set_option maxRecDepth 30000 in
theorem lookupProjection
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (lower : 17 ≤ ordinal)
    (upper : ordinal ≤ 28) :
    (evaluation row witness).lookup? ordinal =
      expectedLookup? row ordinal := by
  have cases :
      ordinal = 17 ∨ ordinal = 18 ∨ ordinal = 19 ∨
      ordinal = 20 ∨ ordinal = 21 ∨ ordinal = 22 ∨
      ordinal = 23 ∨ ordinal = 24 ∨ ordinal = 25 ∨
      ordinal = 26 ∨ ordinal = 27 ∨ ordinal = 28 := by
    omega
  rcases cases with h | h | h | h | h | h | h | h | h | h | h | h <;>
    subst ordinal <;> reduce_auipc <;>
      simp [expectedLookup?, EvaluatedEvent.lookup?] <;> rfl

theorem allLookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 17 = some (programLookup row) ∧
      (evaluation row witness).lookup? 18 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 19 =
        some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 20 =
        some (resultLowLookup row) ∧
      (evaluation row witness).lookup? 21 =
        some (resultHighLookup row) ∧
      (evaluation row witness).lookup? 22 =
        some (pcMiddleLookup row) ∧
      (evaluation row witness).lookup? 23 =
        some (pcM31Lookup row) ∧
      (evaluation row witness).lookup? 24 =
        some (immediateMiddleLookup row) ∧
      (evaluation row witness).lookup? 25 =
        some (immediateM31Lookup row) ∧
      (evaluation row witness).lookup? 26 =
        some (destinationConsumeLookup row) ∧
      (evaluation row witness).lookup? 27 =
        some (destinationEmitLookup row) ∧
      (evaluation row witness).lookup? 28 =
        some (destinationClockLookup row) := by
  exact ⟨
    lookupProjection row witness 17 (by decide) (by decide),
    lookupProjection row witness 18 (by decide) (by decide),
    lookupProjection row witness 19 (by decide) (by decide),
    lookupProjection row witness 20 (by decide) (by decide),
    lookupProjection row witness 21 (by decide) (by decide),
    lookupProjection row witness 22 (by decide) (by decide),
    lookupProjection row witness 23 (by decide) (by decide),
    lookupProjection row witness 24 (by decide) (by decide),
    lookupProjection row witness 25 (by decide) (by decide),
    lookupProjection row witness 26 (by decide) (by decide),
    lookupProjection row witness 27 (by decide) (by decide),
    lookupProjection row witness 28 (by decide) (by decide)
  ⟩

theorem exactProgramIdentity :
    Programs.auipc.source.contentDigest =
        "f39f05e0549d5aec6e814c5cf48797044718597ce6bf54b58baff8568873e4d7" ∧
      Programs.auipc.source.family = .auipc ∧
      Programs.auipc.source.nodes.size = 106 ∧
      Programs.auipc.source.events.size = 29 ∧
      Programs.auipc.source.projection.programEvent = 17 ∧
      Programs.auipc.source.projection.sourceEvents = #[] ∧
      Programs.auipc.source.projection.destinationEvents = #[26, 27] ∧
      Programs.auipc.source.projection.stateEvents = #[18, 19] ∧
      Programs.auipc.source.projection.nextPc = 96 := by
  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩

def ConstraintEquations
    (row : Row)
    (witness : Witness row) : Prop :=
  TeamACommon.wordBytesField row.pcLimbs -
      bitVecM31 row.pc = 0 ∧
    (TeamACommon.wordBytesField row.immediateLimbs -
        row.immediateFelt) -
        boolM31 row.immediateSign * M31.reduce 2 = 0 ∧
    bitVecM31 row.immediateLimbs.limb0 = 0 ∧
    carry1Field row * (carry1Field row - 1) = 0 ∧
    carry2Field row * (carry2Field row - 1) = 0 ∧
    carry3Field row * (carry3Field row - 1) = 0 ∧
    carry4Field row * (carry4Field row - 1) = 0 ∧
    bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) = 0 ∧
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
    (Programs.auipcSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      #[31, 39, 49, 51, 52, 60, 66, 72, 78, 80, 82, 84,
        86, 88, 90, 92, 30].all
        (fun root => nodes.getSymbolic root == 0) := by
  simp [Programs.auipcSource, Event.evalSymbolic]

theorem constraintsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      #[31, 39, 49, 51, 52, 60, 66, 72, 78, 80, 82, 84,
        86, 88, 90, 92, 30].all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) := by
  exact constraintsHoldEvents (evaluation row witness).nodes

set_option maxRecDepth 30000 in
private theorem node31 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 31 =
      (1 : M31) * (1 - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node39 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 39 =
      TeamACommon.wordBytesField row.pcLimbs -
        bitVecM31 row.pc := by
  rfl

set_option maxRecDepth 30000 in
private theorem node49 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 49 =
      (TeamACommon.wordBytesField row.immediateLimbs -
        row.immediateFelt) -
          boolM31 row.immediateSign * M31.reduce 2 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node51 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 51 =
      boolM31 row.immediateSign *
        (boolM31 row.immediateSign - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node52 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 52 =
      (1 : M31) *
        bitVecM31 row.immediateLimbs.limb0 := by
  rfl

private theorem evalAllSymbolic_append
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
      exact
        induction
          (LocalExprNode.evalSymbolic row values node :: values)

private theorem newestValueSymbolic_evalAllSymbolic
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

private theorem getSymbolic_eq_prefix
    (row : Row)
    (witness : Witness row)
    (index : Nat)
    (bound : index < Programs.auipc.nodes.length) :
    (evaluation row witness).nodes.getSymbolic index =
      newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness)
          (Programs.auipc.nodes.take (index + 1))
          [])
        0 := by
  change
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness) Programs.auipc.nodes [])
        (Programs.auipc.nodes.length - index - 1) =
      _
  have offset :
      (Programs.auipc.nodes.take (index + 1) ++
            Programs.auipc.nodes.drop (index + 1)).length -
            index - 1 =
        (Programs.auipc.nodes.drop (index + 1)).length + 0 := by
    simp only [List.length_append, List.length_take, List.length_drop]
    omega
  calc
    newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness) Programs.auipc.nodes [])
          (Programs.auipc.nodes.length - index - 1) =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.auipc.nodes.take (index + 1) ++
              Programs.auipc.nodes.drop (index + 1))
            [])
          ((Programs.auipc.nodes.take (index + 1) ++
              Programs.auipc.nodes.drop (index + 1)).length -
                index - 1) := by
      rw [List.take_append_drop]
    _ =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.auipc.nodes.take (index + 1))
            [])
          0 := by
      rw [
        evalAllSymbolic_append,
        offset,
        newestValueSymbolic_evalAllSymbolic,
      ]

private theorem newestValueSymbolic_take_eq_getSymbolic
    (row : Row)
    (witness : Witness row)
    (count offset : Nat)
    (offsetBound : offset < count)
    (countBound : count ≤ Programs.auipc.nodes.length) :
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness)
          (Programs.auipc.nodes.take count)
          [])
        offset =
      (evaluation row witness).nodes.getSymbolic
        (count - offset - 1) := by
  change
    _ =
      newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness) Programs.auipc.nodes [])
        (Programs.auipc.nodes.length -
            (count - offset - 1) - 1)
  have fullOffset :
      (Programs.auipc.nodes.take count ++
            Programs.auipc.nodes.drop count).length -
            (count - offset - 1) - 1 =
        (Programs.auipc.nodes.drop count).length + offset := by
    simp only [List.length_append, List.length_take, List.length_drop]
    omega
  symm
  calc
    newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness) Programs.auipc.nodes [])
          (Programs.auipc.nodes.length -
              (count - offset - 1) - 1) =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.auipc.nodes.take count ++
              Programs.auipc.nodes.drop count)
            [])
          ((Programs.auipc.nodes.take count ++
              Programs.auipc.nodes.drop count).length -
                (count - offset - 1) - 1) := by
      rw [List.take_append_drop]
    _ =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (columns row witness)
            (Programs.auipc.nodes.take count)
            [])
          offset := by
      rw [
        evalAllSymbolic_append,
        fullOffset,
        newestValueSymbolic_evalAllSymbolic,
      ]

private theorem getSymbolic_of_selected
    (row : Row)
    (witness : Witness row)
    (index : Nat)
    (node : LocalExprNode)
    (bound : index < Programs.auipc.nodes.length)
    (selected : Programs.auipc.nodes[index]? = some node) :
    (evaluation row witness).nodes.getSymbolic index =
      node.evalSymbolic
        (columns row witness)
        (LocalExprNode.evalAllSymbolic
          (columns row witness)
          (Programs.auipc.nodes.take index)
          []) := by
  rw [getSymbolic_eq_prefix row witness index bound]
  rw [List.take_add_one, selected]
  simp only [
    Option.toList_some,
    evalAllSymbolic_append,
    LocalExprNode.evalAllSymbolic,
    newestValueSymbolic,
  ]

private def valuesThrough52
    (row : Row)
    (witness : Witness row) :
    List M31 :=
  LocalExprNode.evalAllSymbolic
    (columns row witness) (Programs.auipc.nodes.take 53) []

set_option maxRecDepth 30000 in
private theorem valuesThrough52_node20
    (row : Row)
    (witness : Witness row) :
    newestValueSymbolic (valuesThrough52 row witness) 32 =
      bitVecM31 row.pcLimbs.limb0 := by
  rfl

set_option maxRecDepth 30000 in
private theorem valuesThrough52_node24
    (row : Row)
    (witness : Witness row) :
    newestValueSymbolic (valuesThrough52 row witness) 28 =
      bitVecM31 row.immediateLimbs.limb0 := by
  rfl

set_option maxRecDepth 30000 in
private theorem valuesThrough52_node14
    (row : Row)
    (witness : Witness row) :
    newestValueSymbolic (valuesThrough52 row witness) 38 =
      bitVecM31 row.result.limb0 := by
  rfl

private def carry1Nodes : List LocalExprNode := [
  .const (M31.reduce 0),
  .add 33 29,
  .add 0 1,
  .sub 0 41,
  .const (M31.reduce 8388608),
  .mul 1 0
]

private theorem nodesThrough58 :
    Programs.auipc.nodes.take 59 =
      Programs.auipc.nodes.take 53 ++ carry1Nodes := by
  decide

set_option maxRecDepth 30000 in
private theorem node58 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 58 =
      carry1Field row := by
  change
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness) Programs.auipc.nodes [])
        (Programs.auipc.nodes.length - 58 - 1) =
      carry1Field row
  rw [
    show Programs.auipc.nodes =
        Programs.auipc.nodes.take 59 ++
          Programs.auipc.nodes.drop 59 by
      exact (List.take_append_drop 59 Programs.auipc.nodes).symm,
    evalAllSymbolic_append,
  ]
  have offset :
      (Programs.auipc.nodes.take 59 ++
            Programs.auipc.nodes.drop 59).length - 58 - 1 =
        (Programs.auipc.nodes.drop 59).length + 0 := by
    decide
  rw [offset, newestValueSymbolic_evalAllSymbolic]
  rw [nodesThrough58, evalAllSymbolic_append]
  change
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (columns row witness) carry1Nodes
          (valuesThrough52 row witness))
        0 =
      carry1Field row
  simp only [
    carry1Nodes,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    newestValueSymbolic,
    valuesThrough52_node20,
    valuesThrough52_node24,
    valuesThrough52_node14,
    carry1Field,
    M31.reduce_zero,
    M31.add_zero,
  ]

set_option maxRecDepth 30000 in
private theorem node29 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 29 = 1 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node60Raw (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 60 =
      (evaluation row witness).nodes.getSymbolic 58 *
        ((evaluation row witness).nodes.getSymbolic 58 - 1) := by
  rw [
    getSymbolic_of_selected row witness 60 (.mul 1 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 60 1 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 60 0 (by decide) (by decide),
    getSymbolic_of_selected row witness 59 (.sub 0 29)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 59 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 59 29 (by decide) (by decide),
    node29,
  ]

set_option maxRecDepth 30000 in
private theorem node60 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 60 =
      carry1Field row * (carry1Field row - 1) := by
  rw [node60Raw, node58]

set_option maxRecDepth 30000 in
private theorem node15 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 15 =
      bitVecM31 row.result.limb1 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node21 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 21 =
      bitVecM31 row.pcLimbs.limb1 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node25 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 25 =
      bitVecM31 row.immediateLimbs.limb1 := by
  rfl

private theorem node57 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 57 =
      M31.reduce 8388608 := by
  rw [
    getSymbolic_of_selected row witness 57
      (.const (M31.reduce 8388608)) (by decide) (by decide),
  ]
  rfl

private theorem node61 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 61 =
      bitVecM31 row.pcLimbs.limb1 +
        bitVecM31 row.immediateLimbs.limb1 := by
  rw [
    getSymbolic_of_selected row witness 61 (.add 39 35)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 61 39 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 61 35 (by decide) (by decide),
    node21,
    node25,
  ]

private theorem node62 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 62 =
      bitVecM31 row.pcLimbs.limb1 +
        bitVecM31 row.immediateLimbs.limb1 +
          carry1Field row := by
  rw [
    getSymbolic_of_selected row witness 62 (.add 0 3)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 62 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 62 3 (by decide) (by decide),
    node61,
    node58,
  ]

private theorem node63 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 63 =
      bitVecM31 row.pcLimbs.limb1 +
        bitVecM31 row.immediateLimbs.limb1 +
          carry1Field row -
            bitVecM31 row.result.limb1 := by
  rw [
    getSymbolic_of_selected row witness 63 (.sub 0 47)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 63 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 63 47 (by decide) (by decide),
    node62,
    node15,
  ]

set_option maxRecDepth 30000 in
private theorem node64 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 64 =
      carry2Field row := by
  rw [
    getSymbolic_of_selected row witness 64 (.mul 0 6)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 64 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 64 6 (by decide) (by decide),
    node63,
    node57,
  ]
  rfl

set_option maxRecDepth 30000 in
private theorem node66Raw (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 66 =
      (evaluation row witness).nodes.getSymbolic 64 *
        ((evaluation row witness).nodes.getSymbolic 64 - 1) := by
  rw [
    getSymbolic_of_selected row witness 66 (.mul 1 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 66 1 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 66 0 (by decide) (by decide),
    getSymbolic_of_selected row witness 65 (.sub 0 35)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 65 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 65 35 (by decide) (by decide),
    node29,
  ]

set_option maxRecDepth 30000 in
private theorem node66 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 66 =
      carry2Field row * (carry2Field row - 1) := by
  rw [node66Raw, node64]

set_option maxRecDepth 30000 in
private theorem node16 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 16 =
      bitVecM31 row.result.limb2 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node22 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 22 =
      bitVecM31 row.pcLimbs.limb2 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node26 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 26 =
      bitVecM31 row.immediateLimbs.limb2 := by
  rfl

private theorem node67 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 67 =
      bitVecM31 row.pcLimbs.limb2 +
        bitVecM31 row.immediateLimbs.limb2 := by
  rw [
    getSymbolic_of_selected row witness 67 (.add 44 40)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 67 44 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 67 40 (by decide) (by decide),
    node22,
    node26,
  ]

private theorem node68 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 68 =
      bitVecM31 row.pcLimbs.limb2 +
        bitVecM31 row.immediateLimbs.limb2 +
          carry2Field row := by
  rw [
    getSymbolic_of_selected row witness 68 (.add 0 3)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 68 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 68 3 (by decide) (by decide),
    node67,
    node64,
  ]

private theorem node69 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 69 =
      bitVecM31 row.pcLimbs.limb2 +
        bitVecM31 row.immediateLimbs.limb2 +
          carry2Field row -
            bitVecM31 row.result.limb2 := by
  rw [
    getSymbolic_of_selected row witness 69 (.sub 0 52)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 69 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 69 52 (by decide) (by decide),
    node68,
    node16,
  ]

set_option maxRecDepth 30000 in
private theorem node70 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 70 =
      carry3Field row := by
  rw [
    getSymbolic_of_selected row witness 70 (.mul 0 12)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 70 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 70 12 (by decide) (by decide),
    node69,
    node57,
  ]
  rfl

set_option maxRecDepth 30000 in
private theorem node72Raw (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 72 =
      (evaluation row witness).nodes.getSymbolic 70 *
        ((evaluation row witness).nodes.getSymbolic 70 - 1) := by
  rw [
    getSymbolic_of_selected row witness 72 (.mul 1 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 72 1 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 72 0 (by decide) (by decide),
    getSymbolic_of_selected row witness 71 (.sub 0 41)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 71 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 71 41 (by decide) (by decide),
    node29,
  ]

set_option maxRecDepth 30000 in
private theorem node72 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 72 =
      carry3Field row * (carry3Field row - 1) := by
  rw [node72Raw, node70]

set_option maxRecDepth 30000 in
private theorem node17 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 17 =
      bitVecM31 row.result.limb3 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node23 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 23 =
      bitVecM31 row.pcLimbs.limb3 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node27 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 27 =
      bitVecM31 row.immediateLimbs.limb3 := by
  rfl

private theorem node73 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 73 =
      bitVecM31 row.pcLimbs.limb3 +
        bitVecM31 row.immediateLimbs.limb3 := by
  rw [
    getSymbolic_of_selected row witness 73 (.add 49 45)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 73 49 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 73 45 (by decide) (by decide),
    node23,
    node27,
  ]

private theorem node74 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 74 =
      bitVecM31 row.pcLimbs.limb3 +
        bitVecM31 row.immediateLimbs.limb3 +
          carry3Field row := by
  rw [
    getSymbolic_of_selected row witness 74 (.add 0 3)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 74 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 74 3 (by decide) (by decide),
    node73,
    node70,
  ]

private theorem node75 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 75 =
      bitVecM31 row.pcLimbs.limb3 +
        bitVecM31 row.immediateLimbs.limb3 +
          carry3Field row -
            bitVecM31 row.result.limb3 := by
  rw [
    getSymbolic_of_selected row witness 75 (.sub 0 57)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 75 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 75 57 (by decide) (by decide),
    node74,
    node17,
  ]

set_option maxRecDepth 30000 in
private theorem node76 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 76 =
      carry4Field row := by
  rw [
    getSymbolic_of_selected row witness 76 (.mul 0 18)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 76 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 76 18 (by decide) (by decide),
    node75,
    node57,
  ]
  rfl

set_option maxRecDepth 30000 in
private theorem node78Raw (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 78 =
      (evaluation row witness).nodes.getSymbolic 76 *
        ((evaluation row witness).nodes.getSymbolic 76 - 1) := by
  rw [
    getSymbolic_of_selected row witness 78 (.mul 1 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 78 1 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 78 0 (by decide) (by decide),
    getSymbolic_of_selected row witness 77 (.sub 0 47)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 77 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 77 47 (by decide) (by decide),
    node29,
  ]

set_option maxRecDepth 30000 in
private theorem node78 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 78 =
      carry4Field row * (carry4Field row - 1) := by
  rw [node78Raw, node76]

set_option maxRecDepth 30000 in
private theorem node3 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 3 =
      bitVecM31 row.rd := by
  rfl

set_option maxRecDepth 30000 in
private theorem node9 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 9 =
      bitVecM31 row.rdNext.limb0 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node10 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 10 =
      bitVecM31 row.rdNext.limb1 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node11 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 11 =
      bitVecM31 row.rdNext.limb2 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node12 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 12 =
      bitVecM31 row.rdNext.limb3 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node14 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 14 =
      bitVecM31 row.result.limb0 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node18 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 18 =
      boolM31 row.rdNonzero := by
  rfl

set_option maxRecDepth 30000 in
private theorem node19 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 19 =
      witness.destinationInverse := by
  rfl

private theorem node79 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 79 =
      boolM31 row.rdNonzero - 1 := by
  rw [
    getSymbolic_of_selected row witness 79 (.sub 60 49)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 79 60 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 79 49 (by decide) (by decide),
    node18,
    node29,
  ]

set_option maxRecDepth 30000 in
private theorem node80 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 80 =
      boolM31 row.rdNonzero *
        (boolM31 row.rdNonzero - 1) := by
  rw [
    getSymbolic_of_selected row witness 80 (.mul 61 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 80 61 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 80 0 (by decide) (by decide),
    node18,
    node79,
  ]

private theorem node81 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 81 =
      1 - boolM31 row.rdNonzero := by
  rw [
    getSymbolic_of_selected row witness 81 (.sub 51 62)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 81 51 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 81 62 (by decide) (by decide),
    node29,
    node18,
  ]

set_option maxRecDepth 30000 in
private theorem node82 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 82 =
      bitVecM31 row.rd *
        (1 - boolM31 row.rdNonzero) := by
  rw [
    getSymbolic_of_selected row witness 82 (.mul 78 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 82 78 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 82 0 (by decide) (by decide),
    node3,
    node81,
  ]

private theorem node83 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 83 =
      bitVecM31 row.rd * witness.destinationInverse := by
  rw [
    getSymbolic_of_selected row witness 83 (.mul 79 63)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 83 79 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 83 63 (by decide) (by decide),
    node3,
    node19,
  ]

set_option maxRecDepth 30000 in
private theorem node84 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 84 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  rw [
    getSymbolic_of_selected row witness 84 (.sub 0 65)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 84 0 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 84 65 (by decide) (by decide),
    node83,
    node18,
  ]

private theorem node85 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 85 =
      boolM31 row.rdNonzero *
        bitVecM31 row.result.limb0 := by
  rw [
    getSymbolic_of_selected row witness 85 (.mul 66 70)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 85 66 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 85 70 (by decide) (by decide),
    node18,
    node14,
  ]

set_option maxRecDepth 30000 in
private theorem node86 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 86 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb0 := by
  rw [
    getSymbolic_of_selected row witness 86 (.sub 76 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 86 76 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 86 0 (by decide) (by decide),
    node9,
    node85,
  ]

private theorem node87 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 87 =
      boolM31 row.rdNonzero *
        bitVecM31 row.result.limb1 := by
  rw [
    getSymbolic_of_selected row witness 87 (.mul 68 71)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 87 68 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 87 71 (by decide) (by decide),
    node18,
    node15,
  ]

set_option maxRecDepth 30000 in
private theorem node88 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 88 =
      bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb1 := by
  rw [
    getSymbolic_of_selected row witness 88 (.sub 77 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 88 77 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 88 0 (by decide) (by decide),
    node10,
    node87,
  ]

private theorem node89 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 89 =
      boolM31 row.rdNonzero *
        bitVecM31 row.result.limb2 := by
  rw [
    getSymbolic_of_selected row witness 89 (.mul 70 72)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 89 70 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 89 72 (by decide) (by decide),
    node18,
    node16,
  ]

set_option maxRecDepth 30000 in
private theorem node90 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 90 =
      bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb2 := by
  rw [
    getSymbolic_of_selected row witness 90 (.sub 78 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 90 78 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 90 0 (by decide) (by decide),
    node11,
    node89,
  ]

private theorem node91 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 91 =
      boolM31 row.rdNonzero *
        bitVecM31 row.result.limb3 := by
  rw [
    getSymbolic_of_selected row witness 91 (.mul 72 73)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 91 72 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 91 73 (by decide) (by decide),
    node18,
    node17,
  ]

set_option maxRecDepth 30000 in
private theorem node92 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 92 =
      bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero *
          bitVecM31 row.result.limb3 := by
  rw [
    getSymbolic_of_selected row witness 92 (.sub 79 0)
      (by decide) (by decide),
  ]
  simp only [LocalExprNode.evalSymbolic]
  rw [
    newestValueSymbolic_take_eq_getSymbolic
      row witness 92 79 (by decide) (by decide),
    newestValueSymbolic_take_eq_getSymbolic
      row witness 92 0 (by decide) (by decide),
    node12,
    node91,
  ]

set_option maxRecDepth 30000 in
private theorem node30 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 30 =
      (1 : M31) - 1 := by
  rfl

theorem constraintsHold_iff
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold = true ↔
      ConstraintEquations row witness := by
  rw [constraintsHold_eq]
  cases sign : row.immediateSign <;>
    cases destination : row.rdNonzero <;>
      simp [
        ConstraintEquations,
        node31,
        node39,
        node49,
        node51,
        node52,
        node60,
        node66,
        node72,
        node78,
        node80,
        node82,
        node84,
        node86,
        node88,
        node90,
        node92,
        node30,
        boolM31,
        TeamACommon.boolM31,
        Lui.boolM31,
        sign,
        destination,
      ]

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  selectors :
    (evaluation row witness).activeSelectorsAccepted = true
  constraints :
    (evaluation row witness).constraintsHold = true
  fixedLookups :
    (evaluation row witness).fixedLookupsHold = true

theorem pcM31RequestHolds
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (pcM31Lookup row).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) 23 (pcM31Lookup row) fixed
    (lookupProjection row witness 23 (by decide) (by decide))

theorem immediateM31RequestHolds
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (immediateM31Lookup row).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) 25 (immediateM31Lookup row) fixed
    (lookupProjection row witness 25 (by decide) (by decide))

theorem destinationClockRequestHolds
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (destinationClockLookup row).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) 28 (destinationClockLookup row) fixed
    (lookupProjection row witness 28 (by decide) (by decide))

private theorem byteFieldVal (value : Byte) :
    (bitVecM31 value).val = value.toNat := by
  apply Lui.bitVecM31_val
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem rangeCheckM31SecondBound
    (ordinal : Nat)
    (accessOrdinal : Option Nat)
    (low high : M31)
    (holds :
      (EvaluatedLookup.fixedRequestHolds {
        ordinal
        domain := .rangeCheckM31
        numerator := -(1 : M31)
        tuple := #[low, high]
        role := .request
        tableId := some .rangeCheckM31
        accessOrdinal
      }) = true) :
    high.val < 128 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
  ] at holds
  simp at holds
  rcases holds with impossible | membership
  · have nonzero : (-(1 : M31)) ≠ 0 := by decide
    exact False.elim (nonzero impossible)
  · exact membership.1.2

theorem immediateHighAdjustedBound_of_request
    (row : Row)
    (holds :
      (immediateM31Lookup row).fixedRequestHolds = true) :
    (bitVecM31 row.immediateLimbs.limb3 -
        boolM31 row.immediateSign * M31.reduce 128).val <
      128 := by
  apply
    rangeCheckM31SecondBound
      25 none
      (bitVecM31 row.immediateLimbs.limb0)
      (bitVecM31 row.immediateLimbs.limb3 -
        boolM31 row.immediateSign * M31.reduce 128)
  simpa [immediateM31Lookup] using holds

theorem immediateTrueImpliesHighLimb
    (row : Row)
    (request :
      (immediateM31Lookup row).fixedRequestHolds = true)
    (sign : row.immediateSign = true) :
    128 ≤ row.immediateLimbs.limb3.toNat := by
  have adjusted :=
    immediateHighAdjustedBound_of_request row request
  rw [sign] at adjusted
  simp only [
    boolM31,
    TeamACommon.boolM31,
    Lui.boolM31,
    M31.one_mul,
  ] at adjusted
  by_cases lower : row.immediateLimbs.limb3.toNat < 128
  · have highFieldLower :
        (bitVecM31 row.immediateLimbs.limb3).val <
          (M31.reduce 128).val := by
      rw [
        byteFieldVal row.immediateLimbs.limb3,
        M31.reduce_val_of_lt 128 (by decide),
      ]
      exact lower
    rw [
      M31.sub_val_of_lt
        (bitVecM31 row.immediateLimbs.limb3)
        (M31.reduce 128)
        highFieldLower,
    ] at adjusted
    have highBound := row.immediateLimbs.limb3.isLt
    simp only [Nat.reducePow] at highBound
    have modulusValue : M31.modulus = 2147483647 :=
      M31.modulus_eq
    rw [
      byteFieldVal row.immediateLimbs.limb3,
      M31.reduce_val_of_lt 128 (by decide),
    ] at adjusted
    omega
  · omega

private theorem m31_eq_add_of_sub_eq
    (left right offset : M31)
    (equation : left - right = offset) :
    left = right + offset := by
  have values := congrArg M31.val equation
  have leftBound : left.val < M31.modulus := by
    simpa [M31.modulus_eq] using left.isLt
  have rightBound : right.val < M31.modulus := by
    simpa [M31.modulus_eq] using right.isLt
  have offsetBound : offset.val < M31.modulus := by
    simpa [M31.modulus_eq] using offset.isLt
  by_cases ordered : right.val ≤ left.val
  · rw [M31.sub_val_of_le left right ordered] at values
    have sumBound : right.val + offset.val < M31.modulus := by
      omega
    apply M31.ext
    rw [M31.add_val_of_lt right offset sumBound]
    omega
  · have reverse : left.val < right.val := Nat.lt_of_not_ge ordered
    rw [M31.sub_val_of_lt left right reverse] at values
    apply M31.ext
    change left.val = (right.val + offset.val) % M31.modulus
    have sum :
        right.val + offset.val = M31.modulus + left.val := by
      omega
    rw [sum, Nat.add_mod_left]
    exact (Nat.mod_eq_of_lt leftBound).symm

private theorem m31_sub_eq_of_eq_add
    (left right offset : M31)
    (equation : left = right + offset) :
    left - offset = right := by
  have values := congrArg M31.val equation
  have leftBound : left.val < M31.modulus := by
    simpa [M31.modulus_eq] using left.isLt
  have rightBound : right.val < M31.modulus := by
    simpa [M31.modulus_eq] using right.isLt
  have offsetBound : offset.val < M31.modulus := by
    simpa [M31.modulus_eq] using offset.isLt
  by_cases sumBound : right.val + offset.val < M31.modulus
  · rw [M31.add_val_of_lt right offset sumBound] at values
    apply M31.ext
    rw [M31.sub_val_of_le left offset (by omega)]
    omega
  · have sumUpper :
        right.val + offset.val < 2 * M31.modulus := by
      omega
    have sumLower : M31.modulus ≤ right.val + offset.val :=
      Nat.le_of_not_gt sumBound
    have addValue :
        (right + offset).val =
          right.val + offset.val - M31.modulus := by
      change
        (right.val + offset.val) % M31.modulus =
          right.val + offset.val - M31.modulus
      rw [Nat.mod_eq_sub_mod sumLower]
      exact
        Nat.mod_eq_of_lt
          (by omega :
            right.val + offset.val - M31.modulus <
              M31.modulus)
    rw [addValue] at values
    have reverse : left.val < offset.val := by
      omega
    apply M31.ext
    rw [M31.sub_val_of_lt left offset reverse]
    omega

private def adjustedImmediateValue (value : Nat) (sign : Bool) : Nat :=
  if sign then value - 2 else value

private theorem reduceAdjustedInjective
    (left right leftFactor rightFactor : Nat)
    (leftSign rightSign : Bool)
    (leftFactorization : left = 256 * leftFactor)
    (rightFactorization : right = 256 * rightFactor)
    (leftLower : leftSign = true → 2 ≤ left)
    (rightLower : rightSign = true → 2 ≤ right)
    (leftBound : left < 2 * M31.modulus)
    (rightBound : right < 2 * M31.modulus)
    (equality :
      M31.reduce (adjustedImmediateValue left leftSign) =
        M31.reduce (adjustedImmediateValue right rightSign)) :
    left = right ∧ leftSign = rightSign := by
  have adjustedLeftBound :
      adjustedImmediateValue left leftSign < 2 * M31.modulus := by
    cases leftSign <;> simp [adjustedImmediateValue] <;> omega
  have adjustedRightBound :
      adjustedImmediateValue right rightSign < 2 * M31.modulus := by
    cases rightSign <;> simp [adjustedImmediateValue] <;> omega
  have values := congrArg M31.val equality
  change
    adjustedImmediateValue left leftSign % M31.modulus =
      adjustedImmediateValue right rightSign % M31.modulus at values
  have reduceOnce
      (value : Nat)
      (bound : value < 2 * M31.modulus) :
      value % M31.modulus =
        if value < M31.modulus
        then value
        else value - M31.modulus := by
    by_cases small : value < M31.modulus
    · simp [small, Nat.mod_eq_of_lt]
    · simp only [small, ↓reduceIte]
      rw [Nat.mod_eq_sub_mod (Nat.le_of_not_gt small)]
      exact Nat.mod_eq_of_lt (by omega)
  rw [
    reduceOnce
      (adjustedImmediateValue left leftSign) adjustedLeftBound,
    reduceOnce
      (adjustedImmediateValue right rightSign) adjustedRightBound,
  ] at values
  have modulusValue : M31.modulus = 2147483647 :=
    M31.modulus_eq
  by_cases leftSmall :
      adjustedImmediateValue left leftSign < M31.modulus
  <;> by_cases rightSmall :
      adjustedImmediateValue right rightSign < M31.modulus
  <;> simp only [leftSmall, rightSmall, ↓reduceIte] at values
  all_goals
    cases leftSign <;> cases rightSign <;>
      simp [adjustedImmediateValue] at leftLower rightLower values leftSmall rightSmall ⊢ <;>
      omega

private theorem reduceSubTwoAligned
    (value factor : Nat)
    (factorization : value = 256 * factor)
    (lower : 2 ≤ value)
    (bound : value < 2 * M31.modulus) :
    M31.reduce value - M31.reduce 2 =
      M31.reduce (value - 2) := by
  have reducedValue
      (input : Nat)
      (inputBound : input < 2 * M31.modulus) :
      (M31.reduce input).val =
        if input < M31.modulus
        then input
        else input - M31.modulus := by
    change
      input % M31.modulus =
        if input < M31.modulus
        then input
        else input - M31.modulus
    by_cases small : input < M31.modulus
    · simp [small, Nat.mod_eq_of_lt]
    · simp only [small, ↓reduceIte]
      rw [Nat.mod_eq_sub_mod (Nat.le_of_not_gt small)]
      exact Nat.mod_eq_of_lt (by omega)
  have twoValue :
      (M31.reduce 2).val = 2 :=
    M31.reduce_val_of_lt 2 (by decide)
  have differenceBound :
      value - 2 < 2 * M31.modulus := by
    omega
  have modulusValue : M31.modulus = 2147483647 :=
    M31.modulus_eq
  by_cases ordered :
      (M31.reduce 2).val ≤ (M31.reduce value).val
  · have orderedField := ordered
    rw [reducedValue value bound, twoValue] at ordered
    apply M31.ext
    rw [
      M31.sub_val_of_le
        (M31.reduce value) (M31.reduce 2) orderedField,
      reducedValue value bound,
      twoValue,
      reducedValue (value - 2) differenceBound,
    ]
    by_cases valueSmall : value < M31.modulus <;>
      by_cases differenceSmall : value - 2 < M31.modulus <;>
        simp [valueSmall, differenceSmall] at ordered ⊢ <;>
        omega
  · have reverse :
        (M31.reduce value).val < (M31.reduce 2).val :=
      Nat.lt_of_not_ge ordered
    have reverseField := reverse
    rw [reducedValue value bound, twoValue] at reverse
    apply M31.ext
    rw [
      M31.sub_val_of_lt
        (M31.reduce value) (M31.reduce 2) reverseField,
      reducedValue value bound,
      twoValue,
      reducedValue (value - 2) differenceBound,
    ]
    by_cases valueSmall : value < M31.modulus <;>
      by_cases differenceSmall : value - 2 < M31.modulus <;>
        simp [valueSmall, differenceSmall] at reverse ⊢ <;>
        omega

theorem pcM31RequestHolds_iff (row : Row) :
    (pcM31Lookup row).fixedRequestHolds = true ↔
      row.pcLimbs.limb0.toNat +
          2 ^ 8 * row.pcLimbs.limb3.toNat <
        2 ^ 15 - 1 := by
  simp only [
    pcM31Lookup,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
  ]
  simp [byteFieldVal]
  have lowBound : row.pcLimbs.limb0.toNat < 256 := by
    simpa using row.pcLimbs.limb0.isLt
  constructor
  · intro holds
    rcases holds with impossible | holds
    · have nonzero : (-(1 : M31)) ≠ 0 := by decide
      exact False.elim (nonzero impossible)
    · exact holds.2
  · intro endpointBound
    have highBound : row.pcLimbs.limb3.toNat < 128 := by
      omega
    exact Or.inr ⟨⟨lowBound, highBound⟩, endpointBound⟩

theorem pcLimbsValueBound_of_fixedLookups
    (row : Row)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    row.pcLimbs.value < M31.modulus := by
  have endpoints :=
    (pcM31RequestHolds_iff row).mp
      (pcM31RequestHolds row witness fixed)
  have low := row.pcLimbs.limb0.isLt
  have middle0 := row.pcLimbs.limb1.isLt
  have middle1 := row.pcLimbs.limb2.isLt
  have high := row.pcLimbs.limb3.isLt
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
      28 (some 1) (destinationClockGapField row)).mp
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

private def resultLowLookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 20
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 94
  tuple := #[nodes.getSymbolic 14, nodes.getSymbolic 15]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def resultHighLookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 21
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 94
  tuple := #[nodes.getSymbolic 16, nodes.getSymbolic 17]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def pcMiddleLookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 22
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 94
  tuple := #[nodes.getSymbolic 21, nodes.getSymbolic 22]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def pcM31LookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 23
  domain := .rangeCheckM31
  numerator := nodes.getSymbolic 94
  tuple := #[nodes.getSymbolic 20, nodes.getSymbolic 23]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def immediateMiddleLookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 24
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 94
  tuple := #[nodes.getSymbolic 25, nodes.getSymbolic 26]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def immediateM31LookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 25
  domain := .rangeCheckM31
  numerator := nodes.getSymbolic 94
  tuple := #[nodes.getSymbolic 24, nodes.getSymbolic 100]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def destinationClockLookupAt
    (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 94
  tuple := #[nodes.getSymbolic 105]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

set_option maxRecDepth 30000 in
private theorem fixedLookupsHoldEvents
    (nodes : LocalValues) :
    (Programs.auipcSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((resultLowLookupAt nodes).fixedRequestHolds &&
        ((resultHighLookupAt nodes).fixedRequestHolds &&
          ((pcMiddleLookupAt nodes).fixedRequestHolds &&
            ((pcM31LookupAt nodes).fixedRequestHolds &&
              ((immediateMiddleLookupAt nodes).fixedRequestHolds &&
                ((immediateM31LookupAt nodes).fixedRequestHolds &&
                  (destinationClockLookupAt nodes).fixedRequestHolds)))))) := by
  simp [
    Programs.auipcSource,
    Event.evalSymbolic,
    resultLowLookupAt,
    resultHighLookupAt,
    pcMiddleLookupAt,
    pcM31LookupAt,
    immediateMiddleLookupAt,
    immediateM31LookupAt,
    destinationClockLookupAt,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.fixedMembership,
  ]

set_option maxRecDepth 30000 in
private theorem resultLowLookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    resultLowLookupAt (evaluation row witness).nodes =
      resultLowLookup row := by
  simp only [evaluation, resultLowLookupAt]
  reduce_auipc

set_option maxRecDepth 30000 in
private theorem resultHighLookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    resultHighLookupAt (evaluation row witness).nodes =
      resultHighLookup row := by
  simp only [evaluation, resultHighLookupAt]
  reduce_auipc

set_option maxRecDepth 30000 in
private theorem pcMiddleLookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    pcMiddleLookupAt (evaluation row witness).nodes =
      pcMiddleLookup row := by
  simp only [evaluation, pcMiddleLookupAt]
  reduce_auipc

set_option maxRecDepth 30000 in
private theorem pcM31LookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    pcM31LookupAt (evaluation row witness).nodes =
      pcM31Lookup row := by
  simp only [evaluation, pcM31LookupAt]
  reduce_auipc

set_option maxRecDepth 30000 in
private theorem immediateMiddleLookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    immediateMiddleLookupAt (evaluation row witness).nodes =
      immediateMiddleLookup row := by
  simp only [evaluation, immediateMiddleLookupAt]
  reduce_auipc

set_option maxRecDepth 30000 in
private theorem immediateM31LookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    immediateM31LookupAt (evaluation row witness).nodes =
      immediateM31Lookup row := by
  simp only [evaluation, immediateM31LookupAt]
  reduce_auipc

set_option maxRecDepth 30000 in
private theorem destinationClockLookupAt_evaluation
    (row : Row)
    (witness : Witness row) :
    destinationClockLookupAt (evaluation row witness).nodes =
      destinationClockLookup row := by
  simp only [evaluation, destinationClockLookupAt]
  reduce_auipc

theorem fixedLookupsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).fixedLookupsHold =
      ((resultLowLookup row).fixedRequestHolds &&
        ((resultHighLookup row).fixedRequestHolds &&
          ((pcMiddleLookup row).fixedRequestHolds &&
            ((pcM31Lookup row).fixedRequestHolds &&
              ((immediateMiddleLookup row).fixedRequestHolds &&
                ((immediateM31Lookup row).fixedRequestHolds &&
                  (destinationClockLookup row).fixedRequestHolds)))))) := by
  rw [SymbolicEvaluation.fixedLookupsHold]
  change
    (Programs.auipcSource.events.map
      (Event.evalSymbolic (evaluation row witness).nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((resultLowLookup row).fixedRequestHolds &&
        ((resultHighLookup row).fixedRequestHolds &&
          ((pcMiddleLookup row).fixedRequestHolds &&
            ((pcM31Lookup row).fixedRequestHolds &&
              ((immediateMiddleLookup row).fixedRequestHolds &&
                ((immediateM31Lookup row).fixedRequestHolds &&
                  (destinationClockLookup row).fixedRequestHolds))))))
  rw [fixedLookupsHoldEvents]
  rw [
    resultLowLookupAt_evaluation row witness,
    resultHighLookupAt_evaluation row witness,
    pcMiddleLookupAt_evaluation row witness,
    pcM31LookupAt_evaluation row witness,
    immediateMiddleLookupAt_evaluation row witness,
    immediateM31LookupAt_evaluation row witness,
    destinationClockLookupAt_evaluation row witness,
  ]

set_option maxRecDepth 30000 in
theorem carryRecurrence_of_constraints
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    ∃ carry1 carry2 carry3 carry4 : BitVec 1,
      row.pcLimbs.limb0.toNat + row.immediateLimbs.limb0.toNat =
          row.result.limb0.toNat + 256 * carry1.toNat ∧
      row.pcLimbs.limb1.toNat + row.immediateLimbs.limb1.toNat +
            carry1.toNat =
          row.result.limb1.toNat + 256 * carry2.toNat ∧
      row.pcLimbs.limb2.toNat + row.immediateLimbs.limb2.toNat +
            carry2.toNat =
          row.result.limb2.toNat + 256 * carry3.toNat ∧
      row.pcLimbs.limb3.toNat + row.immediateLimbs.limb3.toNat +
            carry3.toNat =
          row.result.limb3.toNat + 256 * carry4.toNat := by
  rcases equations with
    ⟨_, _, _, carry1Boolean, carry2Boolean, carry3Boolean,
      carry4Boolean, _⟩
  have pc0Bound := row.pcLimbs.limb0.isLt
  have pc1Bound := row.pcLimbs.limb1.isLt
  have pc2Bound := row.pcLimbs.limb2.isLt
  have pc3Bound := row.pcLimbs.limb3.isLt
  have immediate0Bound := row.immediateLimbs.limb0.isLt
  have immediate1Bound := row.immediateLimbs.limb1.isLt
  have immediate2Bound := row.immediateLimbs.limb2.isLt
  have immediate3Bound := row.immediateLimbs.limb3.isLt
  have result0Bound := row.result.limb0.isLt
  have result1Bound := row.result.limb1.isLt
  have result2Bound := row.result.limb2.isLt
  have result3Bound := row.result.limb3.isLt
  simp only [Nat.reducePow] at pc0Bound pc1Bound pc2Bound pc3Bound
  simp only [Nat.reducePow] at immediate0Bound immediate1Bound immediate2Bound immediate3Bound
  simp only [Nat.reducePow] at result0Bound result1Bound result2Bound result3Bound
  obtain ⟨carry1, carry1Value, recurrence1⟩ :=
    Addi.carryFieldClassified
      row.pcLimbs.limb0.toNat
      row.immediateLimbs.limb0.toNat
      0
      row.result.limb0.toNat
      (carry1Field row)
      pc0Bound immediate0Bound (by omega) result0Bound
      (by
        simp only [
          carry1Field,
          bitVecM31,
          TeamACommon.bitVecM31,
          Lui.bitVecM31,
          M31.reduce_zero,
          M31.add_zero,
        ])
      carry1Boolean
  have carry1Bound := carry1.isLt
  simp only [Nat.reducePow] at carry1Bound
  obtain ⟨carry2, carry2Value, recurrence2⟩ :=
    Addi.carryFieldClassified
      row.pcLimbs.limb1.toNat
      row.immediateLimbs.limb1.toNat
      carry1.toNat
      row.result.limb1.toNat
      (carry2Field row)
      pc1Bound immediate1Bound carry1Bound result1Bound
      (by
        simp only [
          carry2Field,
          carry1Value,
          bitVecM31,
          TeamACommon.bitVecM31,
          Lui.bitVecM31,
        ])
      carry2Boolean
  have carry2Bound := carry2.isLt
  simp only [Nat.reducePow] at carry2Bound
  obtain ⟨carry3, carry3Value, recurrence3⟩ :=
    Addi.carryFieldClassified
      row.pcLimbs.limb2.toNat
      row.immediateLimbs.limb2.toNat
      carry2.toNat
      row.result.limb2.toNat
      (carry3Field row)
      pc2Bound immediate2Bound carry2Bound result2Bound
      (by
        simp only [
          carry3Field,
          carry2Value,
          bitVecM31,
          TeamACommon.bitVecM31,
          Lui.bitVecM31,
        ])
      carry3Boolean
  have carry3Bound := carry3.isLt
  simp only [Nat.reducePow] at carry3Bound
  obtain ⟨carry4, _, recurrence4⟩ :=
    Addi.carryFieldClassified
      row.pcLimbs.limb3.toNat
      row.immediateLimbs.limb3.toNat
      carry3.toNat
      row.result.limb3.toNat
      (carry4Field row)
      pc3Bound immediate3Bound carry3Bound result3Bound
      (by
        simp only [
          carry4Field,
          carry3Value,
          bitVecM31,
          TeamACommon.bitVecM31,
          Lui.bitVecM31,
        ])
      carry4Boolean
  exact ⟨carry1, carry2, carry3, carry4,
    recurrence1, recurrence2, recurrence3, recurrence4⟩

theorem pcLimbsWord
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    row.pcLimbs.word = row.pc := by
  have equations :=
    (constraintsHold_iff row witness).mp accepted.constraints
  have fieldEquation :
      TeamACommon.wordBytesField row.pcLimbs =
        bitVecM31 row.pc :=
    (M31.sub_eq_zero_iff _ _).mp equations.1
  have fieldEquality :
      bitVecM31 row.pcLimbs.word = bitVecM31 row.pc := by
    rw [
      show bitVecM31 row.pcLimbs.word =
          TeamACommon.wordBytesField row.pcLimbs by
        simp only [
          bitVecM31,
          TeamACommon.bitVecM31,
          Lui.bitVecM31,
          WordBytes.word_toNat,
          TeamACommon.wordBytesField_eq_reduce,
        ],
      fieldEquation,
    ]
  apply
    TeamACommon.bitVecM31_injective_of_bounds
      row.pcLimbs.word row.pc
  · simpa [WordBytes.word_toNat] using
      pcLimbsValueBound_of_fixedLookups
        row witness accepted.fixedLookups
  · have profile := admission.pcProfileBound
    simp [M31.modulus_eq] at *
    omega
  · exact fieldEquality

theorem resultWord_of_constraints
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.result.word =
      row.pcLimbs.word + row.immediateLimbs.word := by
  have equations :=
    (constraintsHold_iff row witness).mp accepted.constraints
  rcases carryRecurrence_of_constraints row witness equations with
    ⟨carry1, carry2, carry3, carry4,
      limb0, limb1, limb2, limb3⟩
  apply BitVec.eq_of_toNat_eq
  simp only [
    WordBytes.word_toNat,
    BitVec.toNat_add,
    Nat.reducePow,
  ]
  have total :
      row.pcLimbs.value + row.immediateLimbs.value =
        row.result.value + 4294967296 * carry4.toNat := by
    simp only [WordBytes.value]
    omega
  rw [total]
  have resultBound := row.result.value_lt
  simp only [Nat.reducePow] at resultBound
  omega

theorem immediateWordAndSign
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    row.immediateLimbs.word =
        immediateWord row.immediateEncoded ∧
      row.immediateSign =
        (immediateWord row.immediateEncoded).msb := by
  let raw := row.immediateLimbs.word.toNat
  let canonical := (immediateWord row.immediateEncoded).toNat
  have equations :=
    (constraintsHold_iff row witness).mp accepted.constraints
  have lowField :
      bitVecM31 row.immediateLimbs.limb0 = 0 :=
    equations.2.2.1
  have lowValue := congrArg M31.val lowField
  have lowZero : row.immediateLimbs.limb0.toNat = 0 := by
    rw [byteFieldVal row.immediateLimbs.limb0] at lowValue
    simpa using lowValue
  let rawFactor :=
    (row.immediateLimbs.limb3.toNat * 256 +
        row.immediateLimbs.limb2.toNat) *
      256 + row.immediateLimbs.limb1.toNat
  have rawFactorization :
      raw = 256 * rawFactor := by
    simp only [
      raw,
      rawFactor,
      WordBytes.word_toNat,
      WordBytes.value,
      lowZero,
    ]
    omega
  let canonicalFactor :=
    16 * row.immediateEncoded.toNat
  have canonicalFactorization :
      canonical = 256 * canonicalFactor := by
    rw [show canonical =
      (immediateWord row.immediateEncoded).toNat from rfl]
    rw [immediateWordToNat]
    simp only [canonicalFactor]
    omega
  have rawBound :
      raw < 2 * M31.modulus := by
    have widthBound := row.immediateLimbs.word.isLt
    simp only [Nat.reducePow] at widthBound
    rw [M31.modulus_eq]
    omega
  have canonicalBound :
      canonical < 2 * M31.modulus := by
    have widthBound :=
      (immediateWord row.immediateEncoded).isLt
    simp only [Nat.reducePow] at widthBound
    rw [M31.modulus_eq]
    omega
  have request :=
    immediateM31RequestHolds
      row witness accepted.fixedLookups
  have rawLower :
      row.immediateSign = true → 2 ≤ raw := by
    intro sign
    have high :=
      immediateTrueImpliesHighLimb row request sign
    simp only [
      raw,
      WordBytes.word_toNat,
      WordBytes.value,
    ]
    omega
  have canonicalLower :
      (immediateWord row.immediateEncoded).msb = true →
        2 ≤ canonical := by
    intro sign
    have lower := BitVec.le_toNat_of_msb_true sign
    exact Nat.le_trans (by decide) lower
  have rawAdjustedField :
      M31.reduce
          (adjustedImmediateValue raw row.immediateSign) =
        row.immediateFelt := by
    have fieldEquation := equations.2.1
    rw [TeamACommon.wordBytesField_eq_reduce] at fieldEquation
    have rawValue :
        raw = row.immediateLimbs.value := by
      simp [raw, WordBytes.word_toNat]
    rw [← rawValue] at fieldEquation
    change
      (M31.reduce raw - row.immediateFelt) -
          boolM31 row.immediateSign * M31.reduce 2 = 0
        at fieldEquation
    cases sign : row.immediateSign
    · simpa [
        adjustedImmediateValue,
        sign,
        boolM31,
        TeamACommon.boolM31,
        Lui.boolM31,
      ] using
        (M31.sub_eq_zero_iff
          (M31.reduce raw) row.immediateFelt).mp
          (by simpa [
            sign,
            boolM31,
            TeamACommon.boolM31,
            Lui.boolM31,
          ] using fieldEquation)
    · have difference :
          M31.reduce raw - row.immediateFelt =
            M31.reduce 2 :=
        (M31.sub_eq_zero_iff
          (M31.reduce raw - row.immediateFelt)
          (M31.reduce 2)).mp
          (by simpa [
            sign,
            boolM31,
            TeamACommon.boolM31,
            Lui.boolM31,
          ] using fieldEquation)
      have sum :=
        m31_eq_add_of_sub_eq
          (M31.reduce raw)
          row.immediateFelt
          (M31.reduce 2)
          difference
      have rotated :=
        m31_sub_eq_of_eq_add
          (M31.reduce raw)
          row.immediateFelt
          (M31.reduce 2)
          sum
      rw [
        reduceSubTwoAligned
          raw rawFactor rawFactorization
          (rawLower sign) rawBound
      ] at rotated
      simpa [adjustedImmediateValue, sign] using rotated
  have canonicalAdjustedField :
      M31.reduce
          (adjustedImmediateValue canonical
            (immediateWord row.immediateEncoded).msb) =
        immediateField row.immediateEncoded := by
    simp only [
      canonical,
      adjustedImmediateValue,
      immediateField,
      immediateFieldValue,
    ]
  have adjustedEquality :
      M31.reduce
          (adjustedImmediateValue raw row.immediateSign) =
        M31.reduce
          (adjustedImmediateValue canonical
            (immediateWord row.immediateEncoded).msb) := by
    rw [
      rawAdjustedField,
      admission.immediateFieldBinds,
      canonicalAdjustedField,
    ]
  have refined :=
    reduceAdjustedInjective
      raw canonical rawFactor canonicalFactor
      row.immediateSign
      (immediateWord row.immediateEncoded).msb
      rawFactorization canonicalFactorization
      rawLower canonicalLower
      rawBound canonicalBound
      adjustedEquality
  constructor
  · apply BitVec.eq_of_toNat_eq
    exact refined.1
  · exact refined.2

theorem resultWord
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    row.result.word =
      pcRelativeValue row.pc row.immediateEncoded := by
  rw [
    resultWord_of_constraints row witness accepted,
    pcLimbsWord row witness admission accepted,
    (immediateWordAndSign row witness admission accepted).1,
  ]
  rfl

theorem destinationFlag
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) := by
  rcases
      (constraintsHold_iff row witness).mp accepted.constraints with
    ⟨_, _, _, _, _, _, _, zeroProduct, inverseProduct, _⟩
  exact
    TeamACommon.destinationFlag_of_equations
      row.rd row.rdNonzero witness.destinationInverse
      zeroProduct inverseProduct

theorem destinationBytes
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNext =
      if row.rdNonzero then row.result else WordBytes.zero := by
  rcases
      (constraintsHold_iff row witness).mp accepted.constraints with
    ⟨_, _, _, _, _, _, _, _, _, limb0, limb1, limb2, limb3⟩
  exact
    TeamACommon.destinationBytes_of_equations
      row.rdNext row.result row.rdNonzero
      limb0 limb1 limb2 limb3

theorem destinationWord
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    row.rdNext.word =
      architecturalValue row.rd
        (pcRelativeValue row.pc row.immediateEncoded) := by
  have bytes := destinationBytes row witness accepted
  have flag := destinationFlag row witness accepted
  have result := resultWord row witness admission accepted
  by_cases zero : row.rd = zeroRegister
  · rw [bytes, flag]
    simp [zero, architecturalValue]
  · rw [bytes, flag]
    simp [zero, architecturalValue, result]

theorem stateEmitFields
    (row : Row)
    (admission : Admission row) :
    (stateEmitLookup row).tuple =
      #[
        bitVecM31 (nextPc row.pc),
        M31.reduce (row.clock + 1)
      ] := by
  have pcBound : row.pc.toNat + 4 < M31.modulus := by
    have := admission.pcProfileBound
    simp [M31.modulus_eq] at *
    omega
  have clockBound : row.clock + 1 < M31.modulus := by
    have := admission.clockBound
    simp [M31.modulus_eq] at *
    omega
  simp only [stateEmitLookup]
  rw [
    TeamACommon.nextPcField row.pc pcBound,
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
    (evaluation row witness).lookup? 17 = some (programLookup row) ∧
      (evaluation row witness).lookup? 18 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 19 =
        some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 20 =
        some (resultLowLookup row) ∧
      (evaluation row witness).lookup? 21 =
        some (resultHighLookup row) ∧
      (evaluation row witness).lookup? 22 =
        some (pcMiddleLookup row) ∧
      (evaluation row witness).lookup? 23 =
        some (pcM31Lookup row) ∧
      (evaluation row witness).lookup? 24 =
        some (immediateMiddleLookup row) ∧
      (evaluation row witness).lookup? 25 =
        some (immediateM31Lookup row) ∧
      (evaluation row witness).lookup? 26 =
        some (destinationConsumeLookup row) ∧
      (evaluation row witness).lookup? 27 =
        some (destinationEmitLookup row) ∧
      (evaluation row witness).lookup? 28 =
        some (destinationClockLookup row)
  programIdentity :
    Programs.auipc.source.contentDigest =
      "f39f05e0549d5aec6e814c5cf48797044718597ce6bf54b58baff8568873e4d7"
  exactProgramTuple :
    (programLookup row).tuple = #[
      bitVecM31 row.pc,
      M31.reduce 36,
      bitVecM31 row.rd,
      immediateField row.immediateEncoded,
      0
    ]
  stateEmission :
    (stateEmitLookup row).tuple = #[
      bitVecM31 (nextPc row.pc),
      M31.reduce (row.clock + 1)
    ]
  pcDecomposition : row.pcLimbs.word = row.pc
  immediateDecomposition :
    row.immediateLimbs.word =
      immediateWord row.immediateEncoded
  immediateSign :
    row.immediateSign =
      (immediateWord row.immediateEncoded).msb
  result :
    row.result.word =
      pcRelativeValue row.pc row.immediateEncoded
  destination :
    row.rdNext.word =
      architecturalValue row.rd
        (pcRelativeValue row.pc row.immediateEncoded)
  destinationClock :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 1)
  immediateFixed :
    (immediateM31Lookup row).fixedRequestHolds = true
  noSourceProjection :
    Programs.auipc.source.projection.sourceEvents = #[]

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
    exactLookups := allLookupProjection row witness
    programIdentity := exactProgramIdentity.1
    exactProgramTuple := by
      simp [programLookup, admission.immediateFieldBinds]
    stateEmission := stateEmitFields row admission
    pcDecomposition := pcLimbsWord row witness admission accepted
    immediateDecomposition :=
      (immediateWordAndSign row witness admission accepted).1
    immediateSign :=
      (immediateWordAndSign row witness admission accepted).2
    result := resultWord row witness admission accepted
    destination := destinationWord row witness admission accepted
    destinationClock :=
      destinationClock_of_air
        row witness admission accepted.fixedLookups
    immediateFixed :=
      immediateM31RequestHolds
        row witness accepted.fixedLookups
    noSourceProjection := exactProgramIdentity.2.2.2.2.2.1
  }

def exampleRow : Row where
  clock := 7
  pc := BitVec.ofNat 32 0x1000
  rd := BitVec.ofNat 5 1
  rdPrevious := WordBytes.zero
  rdPreviousClock := 0
  rdNext := wordBytes (BitVec.ofNat 32 0x3000)
  immediateEncoded := BitVec.ofNat 20 2
  immediateFelt := M31.reduce 0x2000
  result := wordBytes (BitVec.ofNat 32 0x3000)
  rdNonzero := true
  pcLimbs := wordBytes (BitVec.ofNat 32 0x1000)
  immediateLimbs := wordBytes (BitVec.ofNat 32 0x2000)
  immediateSign := false

def exampleWitness : Witness exampleRow where
  destinationInverse := 1

theorem exampleAdmission : Admission exampleRow := by
  exact {
    clockPositive := by decide
    clockBound := by decide
    destinationPreviousBound := by decide
    pcProfileBound := by decide
    immediateFieldBinds := by decide
  }

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
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
      wordBytes,
      carry1Field,
      carry2Field,
      carry3Field,
      carry4Field,
      bitVecM31,
      boolM31,
      TeamACommon.bitVecM31,
      TeamACommon.boolM31,
      Lui.bitVecM31,
      Lui.boolM31,
    ]
    decide
  · rw [fixedLookupsHold_eq]
    decide

def x0ExampleRow : Row where
  clock := 7
  pc := BitVec.ofNat 32 0x1000
  rd := zeroRegister
  rdPrevious := WordBytes.zero
  rdPreviousClock := 0
  rdNext := WordBytes.zero
  immediateEncoded := BitVec.ofNat 20 2
  immediateFelt := M31.reduce 0x2000
  result := wordBytes (BitVec.ofNat 32 0x3000)
  rdNonzero := false
  pcLimbs := wordBytes (BitVec.ofNat 32 0x1000)
  immediateLimbs := wordBytes (BitVec.ofNat 32 0x2000)
  immediateSign := false

def x0ExampleWitness : Witness x0ExampleRow where
  destinationInverse := 0

theorem x0ExampleAdmission : Admission x0ExampleRow := by
  exact {
    clockPositive := by decide
    clockBound := by decide
    destinationPreviousBound := by decide
    pcProfileBound := by decide
    immediateFieldBinds := by decide
  }

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
theorem x0ExampleAcceptance :
    Acceptance x0ExampleRow x0ExampleWitness := by
  refine {
    selectors := selectorAccepted x0ExampleRow x0ExampleWitness
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff x0ExampleRow x0ExampleWitness).mpr
    simp [
      ConstraintEquations,
      x0ExampleRow,
      x0ExampleWitness,
      wordBytes,
      carry1Field,
      carry2Field,
      carry3Field,
      carry4Field,
      bitVecM31,
      boolM31,
      TeamACommon.bitVecM31,
      TeamACommon.boolM31,
      Lui.bitVecM31,
      Lui.boolM31,
      zeroRegister,
      WordBytes.zero,
    ]
    decide
  · rw [fixedLookupsHold_eq]
    decide

theorem acceptanceNonvacuous :
    ∃ row witness,
      Admission row ∧ Acceptance row witness ∧
        ProductionRefinement row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance,
    sound exampleRow exampleWitness
      exampleAdmission exampleAcceptance⟩

theorem x0AcceptanceNonvacuous :
    ∃ row witness,
      row.rd = zeroRegister ∧
        Admission row ∧ Acceptance row witness ∧
          ProductionRefinement row witness :=
  ⟨x0ExampleRow, x0ExampleWitness, rfl,
    x0ExampleAdmission, x0ExampleAcceptance,
    sound x0ExampleRow x0ExampleWitness
      x0ExampleAdmission x0ExampleAcceptance⟩

end RiscvRefinement.Air.Bridge.Auipc
