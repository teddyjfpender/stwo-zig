import RiscvRefinement.Air.Bridge.Lui

/-!
# Production ADDI AIR bridge

This module projects the typed normalized `AddiRow` into the exact columns of
the generated production program.  It evaluates `Generated.Programs.addi`
directly and derives the normalized carry recurrence from the production
boolean carry constraints.
-/

namespace RiscvRefinement.Air.Bridge

open RiscvRefinement
open RiscvRefinement.Air.Generated

namespace Addi

abbrev boolM31 : Bool → M31 := Lui.boolM31

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  Lui.bitVecM31 value

private def encodedDifferenceField (encoded : Fin 767) : M31 :=
  if encoded.val < 255 then
    0 - M31.reduce (255 - encoded.val)
  else
    M31.reduce (encoded.val - 255)

private def encodedCarryField (encoded : Fin 767) : M31 :=
  encodedDifferenceField encoded * M31.reduce 8388608

set_option maxRecDepth 20000 in
private theorem encodedCarryField_boolean
    (encoded : Fin 767)
    (boolean :
      encodedCarryField encoded *
          (encodedCarryField encoded - 1) =
        0) :
    encoded.val = 255 ∨ encoded.val = 511 := by
  revert encoded
  decide

structure Witness (row : AddiRow) where
  destinationInverse : M31

def columns
    (row : AddiRow)
    (witness : Witness row) :
    Nat → M31
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
  | 22 => bitVecM31 row.imm0
  | 23 => bitVecM31 row.imm1
  | 24 => bitVecM31 row.immSign
  | 25 => 1
  | 26 => 0
  | 27 => 0
  | 28 => 0
  | 29 => bitVecM31 row.result.limb0
  | 30 => bitVecM31 row.result.limb1
  | 31 => bitVecM31 row.result.limb2
  | 32 => bitVecM31 row.result.limb3
  | 33 => boolM31 row.rdNonzero
  | 34 => witness.destinationInverse
  | _ => 0

def evaluation
    (row : AddiRow)
    (witness : Witness row) :
    SymbolicEvaluation :=
  Programs.addi.evalSymbolic (columns row witness)

structure Admission (row : AddiRow) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourcePreviousBound : row.rs1PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26

def accessClockField (row : AddiRow) (ordinal : Nat) : M31 :=
  (M31.reduce row.clock - 1) * M31.reduce 4 + M31.reduce ordinal

def sourceClockGapField (row : AddiRow) : M31 :=
  accessClockField row 1 - M31.reduce row.rs1PreviousClock - 1

def destinationClockGapField (row : AddiRow) : M31 :=
  accessClockField row 2 - M31.reduce row.rdPreviousClock - 1

def immediateLimb1Field (row : AddiRow) : M31 :=
  bitVecM31 row.imm1 + bitVecM31 row.immSign * M31.reduce 248

def signLimbField (row : AddiRow) : M31 :=
  bitVecM31 row.immSign * M31.reduce 255

def programLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 22
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce 10,
    bitVecM31 row.rd,
    bitVecM31 row.rs1,
    bitVecM31 row.imm0 +
      bitVecM31 row.imm1 * M31.reduce 256 +
      bitVecM31 row.immSign * M31.reduce 2048
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def immediateLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 23
  domain := .rangeCheck811
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.imm0,
    bitVecM31 row.imm1 * M31.reduce 256
  ]
  role := .request
  tableId := some .rangeCheck811
  accessOrdinal := none

def stateConsumeLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 24
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 25
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc + M31.reduce 4,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def sourceConsumeLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 26
  domain := .memoryAccess
  numerator := -(1 : M31)
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

def sourceEmitLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 27
  domain := .memoryAccess
  numerator := 1
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

def sourceClockLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[sourceClockGapField row]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

def bitwiseLookup
    (ordinal : Nat)
    (source immediate result : M31) :
    EvaluatedLookup where
  ordinal := ordinal
  domain := .bitwise
  numerator := 0
  tuple := #[source, immediate, result, 0]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

def bitwiseLookup0 (row : AddiRow) : EvaluatedLookup :=
  bitwiseLookup 29
    (bitVecM31 row.rs1Next.limb0)
    (bitVecM31 row.imm0)
    (bitVecM31 row.result.limb0)

def bitwiseLookup1 (row : AddiRow) : EvaluatedLookup :=
  bitwiseLookup 30
    (bitVecM31 row.rs1Next.limb1)
    (immediateLimb1Field row)
    (bitVecM31 row.result.limb1)

def bitwiseLookup2 (row : AddiRow) : EvaluatedLookup :=
  bitwiseLookup 31
    (bitVecM31 row.rs1Next.limb2)
    (signLimbField row)
    (bitVecM31 row.result.limb2)

def bitwiseLookup3 (row : AddiRow) : EvaluatedLookup :=
  bitwiseLookup 32
    (bitVecM31 row.rs1Next.limb3)
    (signLimbField row)
    (bitVecM31 row.result.limb3)

def resultLowLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 33
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.result.limb0,
    bitVecM31 row.result.limb1
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def resultHighLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 34
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.result.limb2,
    bitVecM31 row.result.limb3
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def destinationConsumeLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 35
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
  accessOrdinal := some 2

def destinationEmitLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 36
  domain := .memoryAccess
  numerator := 1
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

def destinationClockLookup (row : AddiRow) : EvaluatedLookup where
  ordinal := 37
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[destinationClockGapField row]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

macro "reduce_addi_lookup" : tactic =>
  `(tactic|
    (simp only [
      LocalProgram.evalNodesSymbolic,
      Programs.addi,
      Programs.addiSource,
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
      immediateLookup,
      stateConsumeLookup,
      stateEmitLookup,
      sourceConsumeLookup,
      sourceEmitLookup,
      sourceClockLookup,
      bitwiseLookup,
      bitwiseLookup0,
      bitwiseLookup1,
      bitwiseLookup2,
      bitwiseLookup3,
      resultLowLookup,
      resultHighLookup,
      destinationConsumeLookup,
      destinationEmitLookup,
      destinationClockLookup,
      accessClockField,
      sourceClockGapField,
      destinationClockGapField,
      immediateLimb1Field,
      signLimbField,
      M31.add_zero,
      M31.zero_add,
      M31.mul_zero,
      M31.zero_mul,
      M31.one_mul,
      M31.mul_one,
      M31.sub_zero
    ] <;> rfl))

set_option maxRecDepth 30000 in
private theorem programLookup_projection
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).lookup? 22 = some (programLookup row) := by
  rw [evaluation]
  have selected :
      Programs.addi.source.events[22]? =
        some (.lookup {
          ordinal := 22
          domain := .programAccess
          numerator := 118
          tuple := #[1, 129, 2, 12, 135]
          role := .request
          tableId := none
          liveness := .nonzeroNumerator
          accessOrdinal := none
        }) := by decide
  rw [
    LocalProgram.lookup?_evalSymbolic_of_event
      Programs.addi (columns row witness) 22 _ selected,
  ]
  reduce_addi_lookup

set_option maxRecDepth 30000 in
theorem lookup_projection
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).lookup? 22 = some (programLookup row) ∧
    (evaluation row witness).lookup? 23 = some (immediateLookup row) ∧
    (evaluation row witness).lookup? 24 = some (stateConsumeLookup row) ∧
    (evaluation row witness).lookup? 25 = some (stateEmitLookup row) ∧
    (evaluation row witness).lookup? 26 = some (sourceConsumeLookup row) ∧
    (evaluation row witness).lookup? 27 = some (sourceEmitLookup row) ∧
    (evaluation row witness).lookup? 28 = some (sourceClockLookup row) ∧
    (evaluation row witness).lookup? 29 = some (bitwiseLookup0 row) ∧
    (evaluation row witness).lookup? 30 = some (bitwiseLookup1 row) ∧
    (evaluation row witness).lookup? 31 = some (bitwiseLookup2 row) ∧
    (evaluation row witness).lookup? 32 = some (bitwiseLookup3 row) ∧
    (evaluation row witness).lookup? 33 = some (resultLowLookup row) ∧
    (evaluation row witness).lookup? 34 = some (resultHighLookup row) ∧
    (evaluation row witness).lookup? 35 =
      some (destinationConsumeLookup row) ∧
    (evaluation row witness).lookup? 36 =
      some (destinationEmitLookup row) ∧
    (evaluation row witness).lookup? 37 =
      some (destinationClockLookup row) := by
  refine ⟨programLookup_projection row witness, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[23]? =
          some (.lookup {
            ordinal := 23
            domain := .rangeCheck811
            numerator := 118
            tuple := #[22, 131]
            role := .request
            tableId := some .rangeCheck811
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 23 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[24]? =
          some (.lookup {
            ordinal := 24
            domain := .registersState
            numerator := 118
            tuple := #[1, 0]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 24 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[25]? =
          some (.lookup {
            ordinal := 25
            domain := .registersState
            numerator := 38
            tuple := #[136, 137]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 25 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[26]? =
          some (.lookup {
            ordinal := 26
            domain := .memoryAccess
            numerator := 118
            tuple := #[56, 12, 17, 13, 14, 15, 16]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 26 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[27]? =
          some (.lookup {
            ordinal := 27
            domain := .memoryAccess
            numerator := 38
            tuple := #[56, 12, 115, 18, 19, 20, 21]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 27 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[28]? =
          some (.lookup {
            ordinal := 28
            domain := .rangeCheck20
            numerator := 118
            tuple := #[117]
            role := .request
            tableId := some .rangeCheck20
            liveness := .nonzeroNumerator
            accessOrdinal := some 1
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 28 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[29]? =
          some (.lookup {
            ordinal := 29
            domain := .bitwise
            numerator := 142
            tuple := #[18, 22, 29, 141]
            role := .request
            tableId := some .bitwise
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 29 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[30]? =
          some (.lookup {
            ordinal := 30
            domain := .bitwise
            numerator := 142
            tuple := #[19, 53, 30, 141]
            role := .request
            tableId := some .bitwise
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 30 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[31]? =
          some (.lookup {
            ordinal := 31
            domain := .bitwise
            numerator := 142
            tuple := #[20, 55, 31, 141]
            role := .request
            tableId := some .bitwise
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 31 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[32]? =
          some (.lookup {
            ordinal := 32
            domain := .bitwise
            numerator := 142
            tuple := #[21, 55, 32, 141]
            role := .request
            tableId := some .bitwise
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 32 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[33]? =
          some (.lookup {
            ordinal := 33
            domain := .rangeCheck88
            numerator := 118
            tuple := #[29, 30]
            role := .request
            tableId := some .rangeCheck88
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 33 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[34]? =
          some (.lookup {
            ordinal := 34
            domain := .rangeCheck88
            numerator := 118
            tuple := #[31, 32]
            role := .request
            tableId := some .rangeCheck88
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 34 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[35]? =
          some (.lookup {
            ordinal := 35
            domain := .memoryAccess
            numerator := 118
            tuple := #[56, 2, 7, 3, 4, 5, 6]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 2
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 35 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[36]? =
          some (.lookup {
            ordinal := 36
            domain := .memoryAccess
            numerator := 38
            tuple := #[56, 2, 112, 8, 9, 10, 11]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := some 2
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 36 _ selected,
    ]
    reduce_addi_lookup
  · rw [evaluation]
    have selected :
        Programs.addi.source.events[37]? =
          some (.lookup {
            ordinal := 37
            domain := .rangeCheck20
            numerator := 118
            tuple := #[114]
            role := .request
            tableId := some .rangeCheck20
            liveness := .nonzeroNumerator
            accessOrdinal := some 2
          }) := by decide
    rw [
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.addi (columns row witness) 37 _ selected,
    ]
    reduce_addi_lookup

set_option maxRecDepth 30000 in
theorem selectorAccepted
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  simp only [
    evaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    Programs.addi,
    Programs.addiSource,
    LocalExprNode.evalAllSymbolic,
    LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic,
    newestValueSymbolic,
    SymbolicEvaluation.activeSelectorsAccepted,
    columns,
    M31.ofNat?,
  ]
  rfl

def carry1Field (row : AddiRow) : M31 :=
  (bitVecM31 row.rs1Next.limb0 + bitVecM31 row.imm0 + 0 -
      bitVecM31 row.result.limb0) *
    M31.reduce 8388608

def carry2Field (row : AddiRow) : M31 :=
  (bitVecM31 row.rs1Next.limb1 + immediateLimb1Field row +
      carry1Field row - bitVecM31 row.result.limb1) *
    M31.reduce 8388608

def carry3Field (row : AddiRow) : M31 :=
  (bitVecM31 row.rs1Next.limb2 + signLimbField row +
      carry2Field row - bitVecM31 row.result.limb2) *
    M31.reduce 8388608

def carry4Field (row : AddiRow) : M31 :=
  (bitVecM31 row.rs1Next.limb3 + signLimbField row +
      carry3Field row - bitVecM31 row.result.limb3) *
    M31.reduce 8388608

private theorem bitVecOneBoolean
    (value : BitVec 1) :
    bitVecM31 value * (bitVecM31 value - 1) = 0 := by
  have bound := value.isLt
  simp only [Nat.reducePow] at bound
  have cases : value.toNat = 0 ∨ value.toNat = 1 := by omega
  rcases cases with zero | one
  · have valueZero : value = BitVec.ofNat 1 0 :=
      BitVec.eq_of_toNat_eq (by simp [zero])
    rw [valueZero]
    decide
  · have valueOne : value = BitVec.ofNat 1 1 :=
      BitVec.eq_of_toNat_eq (by simp [one])
    rw [valueOne]
    decide

private theorem reduceAddThree
    (left middle right : Nat)
    (leftBound : left < M31.modulus)
    (middleBound : middle < M31.modulus)
    (rightBound : right < M31.modulus)
    (totalBound : left + middle + right < M31.modulus) :
    M31.reduce left + M31.reduce middle + M31.reduce right =
      M31.reduce (left + middle + right) := by
  apply M31.ext
  have pairBound : left + middle < M31.modulus := by omega
  have pairValue :
      (M31.reduce left + M31.reduce middle).val =
        left + middle := by
    calc
      (M31.reduce left + M31.reduce middle).val =
          (M31.reduce left).val + (M31.reduce middle).val := by
        apply M31.add_val_of_lt
        rw [
          M31.reduce_val_of_lt left leftBound,
          M31.reduce_val_of_lt middle middleBound,
        ]
        exact pairBound
      _ = left + middle := by
        rw [
          M31.reduce_val_of_lt left leftBound,
          M31.reduce_val_of_lt middle middleBound,
        ]
  calc
    ((M31.reduce left + M31.reduce middle) + M31.reduce right).val =
        (M31.reduce left + M31.reduce middle).val +
          (M31.reduce right).val := by
      apply M31.add_val_of_lt
      rw [pairValue, M31.reduce_val_of_lt right rightBound]
      exact totalBound
    _ = left + middle + right := by
      rw [
        pairValue,
        M31.reduce_val_of_lt right rightBound,
      ]
    _ = (M31.reduce (left + middle + right)).val := by
      symm
      exact M31.reduce_val_of_lt _ totalBound

private theorem encodedDifferenceField_eq
    (source immediate carryIn result : Nat)
    (encoded : Fin 767)
    (encodedValue :
      encoded.val =
        source + immediate + carryIn + 255 - result)
    (sourceBound : source < 256)
    (immediateBound : immediate < 256)
    (carryBound : carryIn < 2)
    (resultBound : result < 256) :
    encodedDifferenceField encoded =
      M31.reduce source + M31.reduce immediate +
        M31.reduce carryIn - M31.reduce result := by
  have sourceFieldBound : source < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have immediateFieldBound : immediate < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have carryFieldBound : carryIn < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have resultFieldBound : result < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have totalFieldBound :
      source + immediate + carryIn < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  rw [
    reduceAddThree source immediate carryIn
      sourceFieldBound immediateFieldBound carryFieldBound totalFieldBound,
  ]
  by_cases less : source + immediate + carryIn < result
  · have encodedSmall : encoded.val < 255 := by omega
    have differencePositive :
        0 < 255 - encoded.val := by omega
    have differenceBound :
        255 - encoded.val < M31.modulus := by
      rw [M31.modulus_eq]
      omega
    rw [encodedDifferenceField]
    simp only [encodedSmall, ↓reduceIte]
    apply M31.ext
    rw [
      M31.sub_val_of_lt
        0 (M31.reduce (255 - encoded.val))
        (by
          change 0 < (M31.reduce (255 - encoded.val)).val
          rw [M31.reduce_val_of_lt _ differenceBound]
          exact differencePositive),
      M31.sub_val_of_lt
        (M31.reduce (source + immediate + carryIn))
        (M31.reduce result)
        (by
          rw [
            M31.reduce_val_of_lt _ totalFieldBound,
            M31.reduce_val_of_lt _ resultFieldBound,
          ]
          exact less),
      M31.reduce_val_of_lt _ differenceBound,
      M31.reduce_val_of_lt _ totalFieldBound,
      M31.reduce_val_of_lt _ resultFieldBound,
    ]
    change
      M31.modulus + 0 - (255 - encoded.val) =
        M31.modulus + (source + immediate + carryIn) - result
    omega
  · have ordered : result ≤ source + immediate + carryIn :=
      Nat.le_of_not_gt less
    have encodedLarge : ¬ encoded.val < 255 := by omega
    have differenceBound :
        encoded.val - 255 < M31.modulus := by
      rw [M31.modulus_eq]
      omega
    rw [encodedDifferenceField]
    simp only [encodedLarge, ↓reduceIte]
    apply M31.ext
    rw [
      M31.reduce_val_of_lt _ differenceBound,
      M31.sub_val_of_le
        (M31.reduce (source + immediate + carryIn))
        (M31.reduce result)
        (by
          rw [
            M31.reduce_val_of_lt _ resultFieldBound,
            M31.reduce_val_of_lt _ totalFieldBound,
          ]
          exact ordered),
      M31.reduce_val_of_lt _ totalFieldBound,
      M31.reduce_val_of_lt _ resultFieldBound,
    ]
    omega

private theorem carryFieldClassified
    (source immediate carryIn result : Nat)
    (field : M31)
    (sourceBound : source < 256)
    (immediateBound : immediate < 256)
    (carryBound : carryIn < 2)
    (resultBound : result < 256)
    (fieldEquation :
      field =
        (M31.reduce source + M31.reduce immediate +
          M31.reduce carryIn - M31.reduce result) *
            M31.reduce 8388608)
    (boolean : field * (field - 1) = 0) :
    ∃ carry : BitVec 1,
      field = bitVecM31 carry ∧
      source + immediate + carryIn =
        result + 256 * carry.toNat := by
  let encoded : Fin 767 := {
    val := source + immediate + carryIn + 255 - result
    isLt := by omega
  }
  have encodedValue :
      encoded.val =
        source + immediate + carryIn + 255 - result := rfl
  have differenceEquation :
      encodedDifferenceField encoded =
        M31.reduce source + M31.reduce immediate +
          M31.reduce carryIn - M31.reduce result :=
    encodedDifferenceField_eq
      source immediate carryIn result encoded encodedValue
      sourceBound immediateBound carryBound resultBound
  have fieldEncoded : field = encodedCarryField encoded := by
    rw [fieldEquation, encodedCarryField, differenceEquation]
  have encodedBoolean :
      encodedCarryField encoded *
          (encodedCarryField encoded - 1) =
        0 := by
    rw [← fieldEncoded]
    exact boolean
  rcases encodedCarryField_boolean encoded encodedBoolean with
    noCarry | hasCarry
  · refine ⟨BitVec.ofNat 1 0, ?_, ?_⟩
    · rw [fieldEncoded]
      simp [
        encodedCarryField,
        encodedDifferenceField,
        noCarry,
        bitVecM31,
        Lui.bitVecM31,
      ]
    · simp only [BitVec.toNat_ofNat]
      omega
  · refine ⟨BitVec.ofNat 1 1, ?_, ?_⟩
    · rw [fieldEncoded]
      have inverseIdentity :
          M31.reduce 256 * M31.reduce 8388608 = 1 := by
        decide
      simpa [
        encodedCarryField,
        encodedDifferenceField,
        hasCarry,
        bitVecM31,
        Lui.bitVecM31,
      ] using inverseIdentity
    · simp only [BitVec.toNat_ofNat]
      omega

private theorem immediateLimb1Field_eq
    (row : AddiRow) :
    immediateLimb1Field row =
      M31.reduce
        (row.imm1.toNat + 248 * row.immSign.toNat) := by
  have immBound := row.imm1.isLt
  have signBound := row.immSign.isLt
  simp only [Nat.reducePow] at immBound signBound
  apply M31.ext
  have signProductBound :
      (bitVecM31 row.immSign).val * (M31.reduce 248).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val row.immSign (by
        rw [M31.modulus_eq]
        omega),
      M31.reduce_val_of_lt 248 (by
        rw [M31.modulus_eq]
        omega),
      M31.modulus_eq,
    ]
    omega
  have productValue :
      (bitVecM31 row.immSign * M31.reduce 248).val =
        row.immSign.toNat * 248 := by
    rw [
      M31.mul_val_of_lt _ _ signProductBound,
      Lui.bitVecM31_val row.immSign (by
        rw [M31.modulus_eq]
        omega),
      M31.reduce_val_of_lt 248 (by
        rw [M31.modulus_eq]
        omega),
    ]
  have sumBound :
      (bitVecM31 row.imm1).val +
          (bitVecM31 row.immSign * M31.reduce 248).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val row.imm1 (by
        rw [M31.modulus_eq]
        omega),
      productValue,
      M31.modulus_eq,
    ]
    omega
  rw [immediateLimb1Field, M31.add_val_of_lt _ _ sumBound]
  rw [
    Lui.bitVecM31_val row.imm1 (by
      rw [M31.modulus_eq]
      omega),
    productValue,
    M31.reduce_val_of_lt _ (by
      rw [M31.modulus_eq]
      omega),
  ]
  omega

private theorem signLimbField_eq
    (row : AddiRow) :
    signLimbField row =
      M31.reduce (255 * row.immSign.toNat) := by
  have signBound := row.immSign.isLt
  simp only [Nat.reducePow] at signBound
  apply M31.ext
  have productBound :
      (bitVecM31 row.immSign).val * (M31.reduce 255).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val row.immSign (by
        rw [M31.modulus_eq]
        omega),
      M31.reduce_val_of_lt 255 (by
        rw [M31.modulus_eq]
        omega),
      M31.modulus_eq,
    ]
    omega
  rw [signLimbField, M31.mul_val_of_lt _ _ productBound]
  rw [
    Lui.bitVecM31_val row.immSign (by
      rw [M31.modulus_eq]
      omega),
    M31.reduce_val_of_lt 255 (by
      rw [M31.modulus_eq]
      omega),
    M31.reduce_val_of_lt _ (by
      rw [M31.modulus_eq]
      omega),
  ]
  omega

private theorem constraintsHoldEvents
    (nodes : LocalValues) :
    (Programs.addiSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      #[40, 42, 44, 46, 48, 50, 64, 71, 78, 85, 87, 89, 91,
        93, 95, 97, 99, 101, 103, 105, 107, 39].all
        (fun root => nodes.getSymbolic root == 0) := by
  simp [Programs.addiSource, Event.evalSymbolic]

theorem constraintsHold_eq
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      #[40, 42, 44, 46, 48, 50, 64, 71, 78, 85, 87, 89, 91,
        93, 95, 97, 99, 101, 103, 105, 107, 39].all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) := by
  exact constraintsHoldEvents (evaluation row witness).nodes

set_option maxRecDepth 30000 in
private theorem node40
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 40 =
      (1 + 0 + 0 + 0 : M31) * ((1 + 0 + 0 + 0 : M31) - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node42
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 42 =
      (1 : M31) * (1 - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node44
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 44 =
      (0 : M31) * (0 - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node46
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 46 =
      (0 : M31) * (0 - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node48
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 48 =
      (0 : M31) * (0 - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node50
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 50 =
      bitVecM31 row.immSign * (bitVecM31 row.immSign - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node64
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 64 =
      (1 : M31) * (carry1Field row * (carry1Field row - 1)) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node71
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 71 =
      (1 : M31) * (carry2Field row * (carry2Field row - 1)) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node78
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 78 =
      (1 : M31) * (carry3Field row * (carry3Field row - 1)) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node85
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 85 =
      (1 : M31) * (carry4Field row * (carry4Field row - 1)) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node87
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 87 =
      boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node89
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 89 =
      bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node91
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 91 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  rfl

set_option maxRecDepth 30000 in
private theorem node93
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 93 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb0 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node95
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 95 =
      bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb1 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node97
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 97 =
      bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb2 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node99
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 99 =
      bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb3 := by
  rfl

set_option maxRecDepth 30000 in
private theorem node101
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 101 =
      (1 + 0 + 0 + 0 : M31) *
        (bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node103
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 103 =
      (1 + 0 + 0 + 0 : M31) *
        (bitVecM31 row.rs1Next.limb1 -
          bitVecM31 row.rs1Previous.limb1) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node105
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 105 =
      (1 + 0 + 0 + 0 : M31) *
        (bitVecM31 row.rs1Next.limb2 -
          bitVecM31 row.rs1Previous.limb2) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node107
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 107 =
      (1 + 0 + 0 + 0 : M31) *
        (bitVecM31 row.rs1Next.limb3 -
          bitVecM31 row.rs1Previous.limb3) := by
  rfl

set_option maxRecDepth 30000 in
private theorem node39
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 39 =
      (1 + 0 + 0 + 0 : M31) - 1 := by
  rfl

def ConstraintEquations
    (row : AddiRow)
    (witness : Witness row) :
    Prop :=
  carry1Field row * (carry1Field row - 1) = 0 ∧
  carry2Field row * (carry2Field row - 1) = 0 ∧
  carry3Field row * (carry3Field row - 1) = 0 ∧
  carry4Field row * (carry4Field row - 1) = 0 ∧
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
  bitVecM31 row.rs1Next.limb0 -
      bitVecM31 row.rs1Previous.limb0 = 0 ∧
  bitVecM31 row.rs1Next.limb1 -
      bitVecM31 row.rs1Previous.limb1 = 0 ∧
  bitVecM31 row.rs1Next.limb2 -
      bitVecM31 row.rs1Previous.limb2 = 0 ∧
  bitVecM31 row.rs1Next.limb3 -
      bitVecM31 row.rs1Previous.limb3 = 0

theorem constraintsHold_iff
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold = true ↔
      ConstraintEquations row witness := by
  rw [constraintsHold_eq]
  cases flag : row.rdNonzero <;>
    simp [
      flag,
      ConstraintEquations,
      node40,
      node42,
      node44,
      node46,
      node48,
      node50,
      node64,
      node71,
      node78,
      node85,
      node87,
      node89,
      node91,
      node93,
      node95,
      node97,
      node99,
      node101,
      node103,
      node105,
      node107,
      node39,
      boolM31,
      Lui.boolM31,
      bitVecOneBoolean,
    ]

theorem carryRecurrence_of_constraints
    (row : AddiRow)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    ∃ carry1 carry2 carry3 carry4 : BitVec 1,
      row.rs1Next.limb0.toNat + row.imm0.toNat =
          row.result.limb0.toNat + 256 * carry1.toNat ∧
      row.rs1Next.limb1.toNat +
            (row.imm1.toNat + 248 * row.immSign.toNat) +
            carry1.toNat =
          row.result.limb1.toNat + 256 * carry2.toNat ∧
      row.rs1Next.limb2.toNat +
            255 * row.immSign.toNat +
            carry2.toNat =
          row.result.limb2.toNat + 256 * carry3.toNat ∧
      row.rs1Next.limb3.toNat +
            255 * row.immSign.toNat +
            carry3.toNat =
          row.result.limb3.toNat + 256 * carry4.toNat := by
  have source0Bound := row.rs1Next.limb0.isLt
  have source1Bound := row.rs1Next.limb1.isLt
  have source2Bound := row.rs1Next.limb2.isLt
  have source3Bound := row.rs1Next.limb3.isLt
  have immediate0Bound := row.imm0.isLt
  have immediate1RawBound := row.imm1.isLt
  have signBound := row.immSign.isLt
  have result0Bound := row.result.limb0.isLt
  have result1Bound := row.result.limb1.isLt
  have result2Bound := row.result.limb2.isLt
  have result3Bound := row.result.limb3.isLt
  simp only [Nat.reducePow] at source0Bound source1Bound source2Bound source3Bound
  simp only [Nat.reducePow] at immediate0Bound immediate1RawBound signBound
  simp only [Nat.reducePow] at result0Bound result1Bound result2Bound result3Bound
  have immediate1Bound :
      row.imm1.toNat + 248 * row.immSign.toNat < 256 := by
    omega
  have signLimbBound :
      255 * row.immSign.toNat < 256 := by
    omega
  obtain ⟨carry1, carry1Value, recurrence1⟩ :=
    carryFieldClassified
      row.rs1Next.limb0.toNat
      row.imm0.toNat
      0
      row.result.limb0.toNat
      (carry1Field row)
      source0Bound
      immediate0Bound
      (by decide)
      result0Bound
      (by rfl)
      equations.1
  have carry1Bound := carry1.isLt
  simp only [Nat.reducePow] at carry1Bound
  obtain ⟨carry2, carry2Value, recurrence2⟩ :=
    carryFieldClassified
      row.rs1Next.limb1.toNat
      (row.imm1.toNat + 248 * row.immSign.toNat)
      carry1.toNat
      row.result.limb1.toNat
      (carry2Field row)
      source1Bound
      immediate1Bound
      carry1Bound
      result1Bound
      (by
        rw [
          carry2Field,
          immediateLimb1Field_eq,
          carry1Value,
        ]
        rfl)
      equations.2.1
  have carry2Bound := carry2.isLt
  simp only [Nat.reducePow] at carry2Bound
  obtain ⟨carry3, carry3Value, recurrence3⟩ :=
    carryFieldClassified
      row.rs1Next.limb2.toNat
      (255 * row.immSign.toNat)
      carry2.toNat
      row.result.limb2.toNat
      (carry3Field row)
      source2Bound
      signLimbBound
      carry2Bound
      result2Bound
      (by
        rw [
          carry3Field,
          signLimbField_eq,
          carry2Value,
        ]
        rfl)
      equations.2.2.1
  have carry3Bound := carry3.isLt
  simp only [Nat.reducePow] at carry3Bound
  obtain ⟨carry4, _, recurrence4⟩ :=
    carryFieldClassified
      row.rs1Next.limb3.toNat
      (255 * row.immSign.toNat)
      carry3.toNat
      row.result.limb3.toNat
      (carry4Field row)
      source3Bound
      signLimbBound
      carry3Bound
      result3Bound
      (by
        rw [
          carry4Field,
          signLimbField_eq,
          carry3Value,
        ]
        rfl)
      equations.2.2.2.1
  refine ⟨carry1, carry2, carry3, carry4, ?_, ?_, ?_, ?_⟩
  · simpa using recurrence1
  · simpa [Nat.add_assoc] using recurrence2
  · simpa [Nat.add_assoc] using recurrence3
  · simpa [Nat.add_assoc] using recurrence4

private theorem negOneLive :
    ((-(1 : M31)) != 0) = true := by
  decide

theorem sourceClockRequestHolds
    (row : AddiRow)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (sourceClockLookup row).fixedRequestHolds = true := by
  have projection :
      (evaluation row witness).lookup? 28 =
        some (sourceClockLookup row) := by
    rcases lookup_projection row witness with
      ⟨_, _, _, _, _, _, projection, _⟩
    exact projection
  exact
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation row witness) 28 (sourceClockLookup row) fixed projection

theorem destinationClockRequestHolds
    (row : AddiRow)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (destinationClockLookup row).fixedRequestHolds = true := by
  have projection :
      (evaluation row witness).lookup? 37 =
        some (destinationClockLookup row) := by
    rcases lookup_projection row witness with
      ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, projection⟩
    exact projection
  exact
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation row witness) 37 (destinationClockLookup row) fixed projection

private theorem rangeCheck20RequestHolds_iff
    (ordinal accessOrdinal : Nat)
    (value : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal := ordinal
      domain := .rangeCheck20
      numerator := -(1 : M31)
      tuple := #[value]
      role := .request
      tableId := some .rangeCheck20
      accessOrdinal := some accessOrdinal
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

theorem sourceClockRequestHolds_iff
    (row : AddiRow) :
    (sourceClockLookup row).fixedRequestHolds = true ↔
      (sourceClockGapField row).val < 2 ^ 20 :=
  rangeCheck20RequestHolds_iff 28 1 (sourceClockGapField row)

theorem destinationClockRequestHolds_iff
    (row : AddiRow) :
    (destinationClockLookup row).fixedRequestHolds = true ↔
      (destinationClockGapField row).val < 2 ^ 20 :=
  rangeCheck20RequestHolds_iff 37 2 (destinationClockGapField row)

theorem sourceClockGapBound_of_fixedLookups
    (row : AddiRow)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (sourceClockGapField row).val < 2 ^ 20 :=
  (sourceClockRequestHolds_iff row).mp
    (sourceClockRequestHolds row witness fixed)

theorem destinationClockGapBound_of_fixedLookups
    (row : AddiRow)
    (witness : Witness row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    (destinationClockGapField row).val < 2 ^ 20 :=
  (destinationClockRequestHolds_iff row).mp
    (destinationClockRequestHolds row witness fixed)

private theorem clock_lt_modulus
    (row : AddiRow)
    (admission : Admission row) :
    row.clock < M31.modulus := by
  have := admission.clockBound
  simp [M31.modulus_eq] at *
  omega

private theorem clockSubOne_val
    (row : AddiRow)
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
    (row : AddiRow)
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

private theorem accessClockField_val
    (row : AddiRow)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 2) :
    (accessClockField row ordinal).val =
      accessClock row.clock ordinal := by
  have productVal := accessClockProduct_val row admission
  have ordinalModulusBound : ordinal < M31.modulus := by
    simp [M31.modulus_eq]
    omega
  have ordinalVal :
      (M31.reduce ordinal).val = ordinal :=
    M31.reduce_val_of_lt ordinal ordinalModulusBound
  have sumBound :
      ((M31.reduce row.clock - 1) * M31.reduce 4).val +
          (M31.reduce ordinal).val < M31.modulus := by
    rw [productVal, ordinalVal]
    have := admission.clockBound
    simp [M31.modulus_eq] at *
    omega
  change
    (((M31.reduce row.clock - 1) * M31.reduce 4) +
        M31.reduce ordinal).val =
      (row.clock - 1) * 4 + ordinal
  rw [
    M31.add_val_of_lt
      ((M31.reduce row.clock - 1) * M31.reduce 4)
      (M31.reduce ordinal)
      sumBound,
    productVal,
    ordinalVal,
  ]

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
            change 1 ≤
              (M31.reduce current - M31.reduce previous).val
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

private theorem accessClockPositive
    (row : AddiRow)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalPositive : 0 < ordinal) :
    0 < accessClock row.clock ordinal := by
  simp only [accessClock]
  have := admission.clockPositive
  omega

private theorem accessClockBound
    (row : AddiRow)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 2) :
    accessClock row.clock ordinal < 2 ^ 26 := by
  simp only [accessClock]
  have := admission.clockBound
  omega

private theorem accessClockField_eq
    (row : AddiRow)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 2) :
    accessClockField row ordinal =
      M31.reduce (accessClock row.clock ordinal) := by
  apply M31.ext
  rw [
    accessClockField_val row admission ordinal ordinalBound,
    M31.reduce_val_of_lt,
  ]
  have currentBound :=
    accessClockBound row admission ordinal ordinalBound
  simp [M31.modulus_eq] at *
  omega

theorem sourceClock_of_air
    (row : AddiRow)
    (witness : Witness row)
    (admission : Admission row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    validPreviousClock
      row.rs1PreviousClock
      (accessClock row.clock 1) := by
  have fieldEquality := accessClockField_eq row admission 1 (by omega)
  have gapBound := sourceClockGapBound_of_fixedLookups row witness fixed
  rw [sourceClockGapField, fieldEquality] at gapBound
  exact
    validPreviousClock_of_gap
      row.rs1PreviousClock
      (accessClock row.clock 1)
      (accessClockPositive row admission 1 (by omega))
      (accessClockBound row admission 1 (by omega))
      admission.sourcePreviousBound
      gapBound

theorem destinationClock_of_air
    (row : AddiRow)
    (witness : Witness row)
    (admission : Admission row)
    (fixed :
      (evaluation row witness).fixedLookupsHold = true) :
    validPreviousClock
      row.rdPreviousClock
      (accessClock row.clock 2) := by
  have fieldEquality := accessClockField_eq row admission 2 (by omega)
  have gapBound :=
    destinationClockGapBound_of_fixedLookups row witness fixed
  rw [destinationClockGapField, fieldEquality] at gapBound
  exact
    validPreviousClock_of_gap
      row.rdPreviousClock
      (accessClock row.clock 2)
      (accessClockPositive row admission 2 (by omega))
      (accessClockBound row admission 2 (by omega))
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
    Lui.bitVecM31_val left leftBound,
    Lui.bitVecM31_val right rightBound,
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
  simpa [bitVecM31, Lui.bitVecM31] using equality

private theorem byteM31Bound
    (value : Byte) :
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

theorem sourceLimbs_of_constraints
    (row : AddiRow)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rs1Next.limb0 = row.rs1Previous.limb0 ∧
    row.rs1Next.limb1 = row.rs1Previous.limb1 ∧
    row.rs1Next.limb2 = row.rs1Previous.limb2 ∧
    row.rs1Next.limb3 = row.rs1Previous.limb3 := by
  rcases equations with
    ⟨_, _, _, _, _, _, _, _, _, _,
      limb0Equation, limb1Equation, limb2Equation, limb3Equation⟩
  refine ⟨?_, ?_, ?_, ?_⟩
  · apply byte_eq_of_bitVecM31_eq
    exact (M31.sub_eq_zero_iff _ _).mp limb0Equation
  · apply byte_eq_of_bitVecM31_eq
    exact (M31.sub_eq_zero_iff _ _).mp limb1Equation
  · apply byte_eq_of_bitVecM31_eq
    exact (M31.sub_eq_zero_iff _ _).mp limb2Equation
  · apply byte_eq_of_bitVecM31_eq
    exact (M31.sub_eq_zero_iff _ _).mp limb3Equation

theorem destinationFlag_of_constraints
    (row : AddiRow)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) := by
  rcases equations with
    ⟨_, _, _, _, zeroProduct, inverseProduct, _⟩
  cases flag : row.rdNonzero
  · have rdFieldZero : bitVecM31 row.rd = 0 := by
      simpa [flag, boolM31, Lui.boolM31] using zeroProduct
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
        simpa [flag, boolM31, Lui.boolM31] using inverseProduct)
    have rdNonzero : row.rd ≠ zeroRegister := by
      intro rdZero
      rw [rdZero, zeroRegister] at inverseEquality
      have impossible : (0 : M31) = 1 := by
        simpa [bitVecM31, Lui.bitVecM31] using inverseEquality
      cases impossible
    simp [rdNonzero]

theorem destinationLimbs_of_constraints
    (row : AddiRow)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rdNext.limb0 =
        (if row.rdNonzero then row.result.limb0 else WordBytes.zero.limb0) ∧
    row.rdNext.limb1 =
        (if row.rdNonzero then row.result.limb1 else WordBytes.zero.limb1) ∧
    row.rdNext.limb2 =
        (if row.rdNonzero then row.result.limb2 else WordBytes.zero.limb2) ∧
    row.rdNext.limb3 =
        (if row.rdNonzero then row.result.limb3 else WordBytes.zero.limb3) := by
  rcases equations with
    ⟨_, _, _, _, _, _, limb0Equation, limb1Equation,
      limb2Equation, limb3Equation, _⟩
  refine ⟨?_, ?_, ?_, ?_⟩
  · cases flag : row.rdNonzero
    · have fieldZero : bitVecM31 row.rdNext.limb0 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb0Equation
      have valueZero :=
        byte_eq_zero_of_bitVecM31 row.rdNext.limb0 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 row.rdNext.limb0 =
            bitVecM31 row.result.limb0 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb0Equation)
      have valueEquality :=
        byte_eq_of_bitVecM31_eq
          row.rdNext.limb0 row.result.limb0 fieldEquality
      simpa [flag] using valueEquality
  · cases flag : row.rdNonzero
    · have fieldZero : bitVecM31 row.rdNext.limb1 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb1Equation
      have valueZero :=
        byte_eq_zero_of_bitVecM31 row.rdNext.limb1 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 row.rdNext.limb1 =
            bitVecM31 row.result.limb1 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb1Equation)
      have valueEquality :=
        byte_eq_of_bitVecM31_eq
          row.rdNext.limb1 row.result.limb1 fieldEquality
      simpa [flag] using valueEquality
  · cases flag : row.rdNonzero
    · have fieldZero : bitVecM31 row.rdNext.limb2 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb2Equation
      have valueZero :=
        byte_eq_zero_of_bitVecM31 row.rdNext.limb2 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 row.rdNext.limb2 =
            bitVecM31 row.result.limb2 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb2Equation)
      have valueEquality :=
        byte_eq_of_bitVecM31_eq
          row.rdNext.limb2 row.result.limb2 fieldEquality
      simpa [flag] using valueEquality
  · cases flag : row.rdNonzero
    · have fieldZero : bitVecM31 row.rdNext.limb3 = 0 := by
        simpa [flag, boolM31, Lui.boolM31] using limb3Equation
      have valueZero :=
        byte_eq_zero_of_bitVecM31 row.rdNext.limb3 fieldZero
      simpa [flag, WordBytes.zero] using valueZero
    · have fieldEquality :
          bitVecM31 row.rdNext.limb3 =
            bitVecM31 row.result.limb3 :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [flag, boolM31, Lui.boolM31] using limb3Equation)
      have valueEquality :=
        byte_eq_of_bitVecM31_eq
          row.rdNext.limb3 row.result.limb3 fieldEquality
      simpa [flag] using valueEquality

structure Acceptance
    (row : AddiRow)
    (witness : Witness row) : Prop where
  selectors :
    (evaluation row witness).activeSelectorsAccepted = true
  constraints :
    (evaluation row witness).constraintsHold = true
  fixedLookups :
    (evaluation row witness).fixedLookupsHold = true

def interpretedRow (row : AddiRow) : AddiRow :=
  { row with claimedNextPc := nextPc row.pc }

theorem sound
    (row : AddiRow)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    AddiHolds (interpretedRow row) := by
  have equations :
      ConstraintEquations row witness :=
    (constraintsHold_iff row witness).mp accepted.constraints
  rcases sourceLimbs_of_constraints row witness equations with
    ⟨source0, source1, source2, source3⟩
  have recurrence :=
    carryRecurrence_of_constraints row witness equations
  have destinationFlag :=
    destinationFlag_of_constraints row witness equations
  rcases destinationLimbs_of_constraints row witness equations with
    ⟨destination0, destination1, destination2, destination3⟩
  refine {
    clockPositive := ?_
    sourceClock := ?_
    destinationClock := ?_
    sourceLimb0 := ?_
    sourceLimb1 := ?_
    sourceLimb2 := ?_
    sourceLimb3 := ?_
    carryRecurrence := ?_
    destinationFlag := ?_
    destinationLimb0 := ?_
    destinationLimb1 := ?_
    destinationLimb2 := ?_
    destinationLimb3 := ?_
    nextPcResult := ?_
  }
  · simpa [interpretedRow] using admission.clockPositive
  · simpa [interpretedRow] using
      sourceClock_of_air row witness admission accepted.fixedLookups
  · simpa [interpretedRow] using
      destinationClock_of_air row witness admission accepted.fixedLookups
  · simpa [interpretedRow] using source0
  · simpa [interpretedRow] using source1
  · simpa [interpretedRow] using source2
  · simpa [interpretedRow] using source3
  · simpa [interpretedRow] using recurrence
  · simpa [interpretedRow] using destinationFlag
  · simpa [interpretedRow] using destination0
  · simpa [interpretedRow] using destination1
  · simpa [interpretedRow] using destination2
  · simpa [interpretedRow] using destination3
  · rfl

private def immediateLookupAt
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 23
  domain := .rangeCheck811
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 22, nodes.getSymbolic 131]
  role := .request
  tableId := some .rangeCheck811
  accessOrdinal := none

private def sourceClockLookupAt
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 117]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

private def bitwiseLookup0At
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 29
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 18,
    nodes.getSymbolic 22,
    nodes.getSymbolic 29,
    nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup1At
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 30
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 19,
    nodes.getSymbolic 53,
    nodes.getSymbolic 30,
    nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup2At
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 31
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 20,
    nodes.getSymbolic 55,
    nodes.getSymbolic 31,
    nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup3At
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 32
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 21,
    nodes.getSymbolic 55,
    nodes.getSymbolic 32,
    nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def resultLowLookupAt
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 33
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 29, nodes.getSymbolic 30]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def resultHighLookupAt
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 34
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 31, nodes.getSymbolic 32]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def destinationClockLookupAt
    (nodes : LocalValues) :
    EvaluatedLookup where
  ordinal := 37
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 114]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

set_option maxRecDepth 30000 in
private theorem fixedLookupsHoldEvents
    (nodes : LocalValues) :
    (Programs.addiSource.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((immediateLookupAt nodes).fixedRequestHolds &&
        ((sourceClockLookupAt nodes).fixedRequestHolds &&
          ((bitwiseLookup0At nodes).fixedRequestHolds &&
            ((bitwiseLookup1At nodes).fixedRequestHolds &&
              ((bitwiseLookup2At nodes).fixedRequestHolds &&
                ((bitwiseLookup3At nodes).fixedRequestHolds &&
                  ((resultLowLookupAt nodes).fixedRequestHolds &&
                    ((resultHighLookupAt nodes).fixedRequestHolds &&
                      (destinationClockLookupAt nodes).fixedRequestHolds)))))))) := by
  simp [
    Programs.addiSource,
    Event.evalSymbolic,
    immediateLookupAt,
    sourceClockLookupAt,
    bitwiseLookup0At,
    bitwiseLookup1At,
    bitwiseLookup2At,
    bitwiseLookup3At,
    resultLowLookupAt,
    resultHighLookupAt,
    destinationClockLookupAt,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.fixedMembership,
  ]

set_option maxRecDepth 30000 in
private theorem immediateLookupAt_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    immediateLookupAt (evaluation row witness).nodes =
      immediateLookup row := by
  simp only [evaluation]
  unfold immediateLookupAt
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem sourceClockLookupAt_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    sourceClockLookupAt (evaluation row witness).nodes =
      sourceClockLookup row := by
  simp only [evaluation]
  unfold sourceClockLookupAt
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem bitwiseLookup0At_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    bitwiseLookup0At (evaluation row witness).nodes =
      bitwiseLookup0 row := by
  simp only [evaluation]
  unfold bitwiseLookup0At
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem bitwiseLookup1At_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    bitwiseLookup1At (evaluation row witness).nodes =
      bitwiseLookup1 row := by
  simp only [evaluation]
  unfold bitwiseLookup1At
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem bitwiseLookup2At_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    bitwiseLookup2At (evaluation row witness).nodes =
      bitwiseLookup2 row := by
  simp only [evaluation]
  unfold bitwiseLookup2At
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem bitwiseLookup3At_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    bitwiseLookup3At (evaluation row witness).nodes =
      bitwiseLookup3 row := by
  simp only [evaluation]
  unfold bitwiseLookup3At
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem resultLowLookupAt_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    resultLowLookupAt (evaluation row witness).nodes =
      resultLowLookup row := by
  simp only [evaluation]
  unfold resultLowLookupAt
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem resultHighLookupAt_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    resultHighLookupAt (evaluation row witness).nodes =
      resultHighLookup row := by
  simp only [evaluation]
  unfold resultHighLookupAt
  reduce_addi_lookup

set_option maxRecDepth 30000 in
private theorem destinationClockLookupAt_evaluation
    (row : AddiRow)
    (witness : Witness row) :
    destinationClockLookupAt (evaluation row witness).nodes =
      destinationClockLookup row := by
  simp only [evaluation]
  unfold destinationClockLookupAt
  reduce_addi_lookup

theorem fixedLookupsHold_eq
    (row : AddiRow)
    (witness : Witness row) :
    (evaluation row witness).fixedLookupsHold =
      ((immediateLookup row).fixedRequestHolds &&
        ((sourceClockLookup row).fixedRequestHolds &&
          ((resultLowLookup row).fixedRequestHolds &&
            ((resultHighLookup row).fixedRequestHolds &&
              (destinationClockLookup row).fixedRequestHolds)))) := by
  rw [SymbolicEvaluation.fixedLookupsHold]
  change
    (Programs.addiSource.events.map
      (Event.evalSymbolic (evaluation row witness).nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((immediateLookup row).fixedRequestHolds &&
        ((sourceClockLookup row).fixedRequestHolds &&
          ((resultLowLookup row).fixedRequestHolds &&
            ((resultHighLookup row).fixedRequestHolds &&
              (destinationClockLookup row).fixedRequestHolds))))
  rw [fixedLookupsHoldEvents]
  rw [
    immediateLookupAt_evaluation row witness,
    sourceClockLookupAt_evaluation row witness,
    bitwiseLookup0At_evaluation row witness,
    bitwiseLookup1At_evaluation row witness,
    bitwiseLookup2At_evaluation row witness,
    bitwiseLookup3At_evaluation row witness,
    resultLowLookupAt_evaluation row witness,
    resultHighLookupAt_evaluation row witness,
    destinationClockLookupAt_evaluation row witness,
  ]
  simp [
    bitwiseLookup0,
    bitwiseLookup1,
    bitwiseLookup2,
    bitwiseLookup3,
    bitwiseLookup,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
  ]

def exampleRow : AddiRow where
  pc := BitVec.ofNat 32 0x1000
  clock := 1
  rd := BitVec.ofNat 5 1
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := WordBytes.zero
  rs1 := BitVec.ofNat 5 2
  rs1PreviousClock := 0
  rs1Previous := WordBytes.zero
  rs1Next := WordBytes.zero
  imm0 := BitVec.ofNat 8 0
  imm1 := BitVec.ofNat 3 0
  immSign := BitVec.ofNat 1 0
  result := WordBytes.zero
  rdNonzero := true
  claimedNextPc := nextPc (BitVec.ofNat 32 0x1000)

def exampleWitness : Witness exampleRow where
  destinationInverse := 1

theorem exampleAdmission : Admission exampleRow := by
  constructor <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem exampleAcceptance : Acceptance exampleRow exampleWitness := by
  refine {
    selectors := selectorAccepted exampleRow exampleWitness
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff exampleRow exampleWitness).mpr
    simp [
      ConstraintEquations,
      carry1Field,
      carry2Field,
      carry3Field,
      carry4Field,
      immediateLimb1Field,
      signLimbField,
      exampleRow,
      exampleWitness,
      boolM31,
      Lui.boolM31,
      bitVecM31,
      Lui.bitVecM31,
      WordBytes.zero,
    ]
  · rw [fixedLookupsHold_eq]
    decide

theorem acceptance_nonvacuous :
    ∃ (row : AddiRow) (witness : Witness row),
      Admission row ∧ Acceptance row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance⟩

end Addi

end RiscvRefinement.Air.Bridge
