import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Air.Generated.Programs
import RiscvRefinement.Bridge.DecodeBaseAlu

/-!
# Production base-ALU-immediate AIR bridge

This module binds XORI, ORI, and ANDI to their exact committed production AIR
programs.  The three selectors have one column layout and one constraint DAG;
the parameter below changes only the one-hot selector and the exact generated
program whose manifest ID is checked.
-/

namespace RiscvRefinement.Air.Bridge.BaseAluImm

open RiscvRefinement
open RiscvRefinement.Air.Generated
open RiscvRefinement.Decode

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

abbrev Op := BaseAluImmOp

def manifestId : Op → Nat
  | .xori => 13
  | .ori => 14
  | .andi => 15

def bitwiseOperationId : Op → Nat
  | .xori => 2
  | .ori => 1
  | .andi => 0

def program : Op → LocalProgram
  | .xori => Programs.xori
  | .ori => Programs.ori
  | .andi => Programs.andi

structure Row where
  clock : Nat
  pc : Word
  rd : RegisterIndex
  rdPreviousClock : Nat
  rdPrevious : WordBytes
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1PreviousClock : Nat
  rs1Previous : WordBytes
  rs1Next : WordBytes
  imm0 : BitVec 8
  imm1 : BitVec 3
  immSign : BitVec 1
  result : WordBytes
  rdNonzero : Bool
deriving DecidableEq, Repr

structure Witness (row : Row) where
  destinationInverse : M31

def flagAddi (_ : Op) : M31 := 0
def flagXori : Op → M31
  | .xori => 1
  | _ => 0
def flagOri : Op → M31
  | .ori => 1
  | _ => 0
def flagAndi : Op → M31
  | .andi => 1
  | _ => 0

def columns
    (op : Op)
    (row : Row)
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
  | 25 => flagAddi op
  | 26 => flagXori op
  | 27 => flagOri op
  | 28 => flagAndi op
  | 29 => bitVecM31 row.result.limb0
  | 30 => bitVecM31 row.result.limb1
  | 31 => bitVecM31 row.result.limb2
  | 32 => bitVecM31 row.result.limb3
  | 33 => boolM31 row.rdNonzero
  | 34 => witness.destinationInverse
  | _ => 0

def evaluation
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    SymbolicEvaluation :=
  (program op).evalSymbolic (columns op row witness)

def immediateLimb1Field (row : Row) : M31 :=
  bitVecM31 row.imm1 + bitVecM31 row.immSign * M31.reduce 248

def signLimbField (row : Row) : M31 :=
  bitVecM31 row.immSign * M31.reduce 255

def immediateUnsignedField (row : Row) : M31 :=
  bitVecM31 row.imm0 +
    bitVecM31 row.imm1 * M31.reduce 256 +
    bitVecM31 row.immSign * M31.reduce 2048

def accessClockField (row : Row) (ordinal : Nat) : M31 :=
  TeamACommon.accessClockField row.clock ordinal

def clockGapField (row : Row) (ordinal previous : Nat) : M31 :=
  TeamACommon.clockGapField row.clock ordinal previous

def programLookup (op : Op) (row : Row) : EvaluatedLookup where
  ordinal := 22
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce (manifestId op),
    bitVecM31 row.rd,
    bitVecM31 row.rs1,
    immediateUnsignedField row
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def immediateLookup (row : Row) : EvaluatedLookup where
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

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 24
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
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

def sourceConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 26
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
    bitVecM31 row.rs1Previous.limb0,
    bitVecM31 row.rs1Previous.limb1,
    bitVecM31 row.rs1Previous.limb2,
    bitVecM31 row.rs1Previous.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 1

def sourceEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 27
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rs1, accessClockField row 1,
    bitVecM31 row.rs1Next.limb0,
    bitVecM31 row.rs1Next.limb1,
    bitVecM31 row.rs1Next.limb2,
    bitVecM31 row.rs1Next.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def sourceClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row 1 row.rs1PreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

def bitwiseLookupFields
    (op : Op)
    (ordinal : Nat)
    (source immediate result : M31) :
    EvaluatedLookup where
  ordinal := ordinal
  domain := .bitwise
  numerator := -(1 : M31)
  tuple := #[source, immediate, result, M31.reduce (bitwiseOperationId op)]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

def bitwiseLookup0 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 29
    (bitVecM31 row.rs1Next.limb0)
    (bitVecM31 row.imm0)
    (bitVecM31 row.result.limb0)

def bitwiseLookup1 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 30
    (bitVecM31 row.rs1Next.limb1)
    (immediateLimb1Field row)
    (bitVecM31 row.result.limb1)

def bitwiseLookup2 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 31
    (bitVecM31 row.rs1Next.limb2)
    (signLimbField row)
    (bitVecM31 row.result.limb2)

def bitwiseLookup3 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 32
    (bitVecM31 row.rs1Next.limb3)
    (signLimbField row)
    (bitVecM31 row.result.limb3)

def resultLowLookup (row : Row) : EvaluatedLookup where
  ordinal := 33
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.result.limb0, bitVecM31 row.result.limb1]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def resultHighLookup (row : Row) : EvaluatedLookup where
  ordinal := 34
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.result.limb2, bitVecM31 row.result.limb3]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 35
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rd, M31.reduce row.rdPreviousClock,
    bitVecM31 row.rdPrevious.limb0,
    bitVecM31 row.rdPrevious.limb1,
    bitVecM31 row.rdPrevious.limb2,
    bitVecM31 row.rdPrevious.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 2

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 36
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rd, accessClockField row 2,
    bitVecM31 row.rdNext.limb0,
    bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2,
    bitVecM31 row.rdNext.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 2

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 37
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row 2 row.rdPreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

macro "reduce_base_alu_imm" : tactic =>
  `(tactic|
    (simp only [
      program,
      evaluation,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.xori,
      Programs.xoriSource,
      Programs.ori,
      Programs.oriSource,
      Programs.andi,
      Programs.andiSource,
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
      flagAddi,
      flagXori,
      flagOri,
      flagAndi,
      manifestId,
      bitwiseOperationId,
      programLookup,
      immediateLookup,
      stateConsumeLookup,
      stateEmitLookup,
      sourceConsumeLookup,
      sourceEmitLookup,
      sourceClockLookup,
      bitwiseLookupFields,
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
      clockGapField,
      immediateLimb1Field,
      signLimbField,
      immediateUnsignedField,
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      SymbolicEvaluation.activeSelectorsAccepted,
      M31.ofNat?,
      M31.add_zero,
      M31.zero_add,
      M31.mul_zero,
      M31.zero_mul,
      M31.one_mul,
      M31.mul_one,
      M31.sub_zero
    ] <;> rfl))

set_option maxRecDepth 30000 in
theorem selectorAccepted
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).activeSelectorsAccepted = true := by
  cases op <;>
    simp only [
      evaluation,
      program,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.xori,
      Programs.xoriSource,
      Programs.ori,
      Programs.oriSource,
      Programs.andi,
      Programs.andiSource,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      List.length_cons,
      List.length_nil,
      SymbolicEvaluation.activeSelectorsAccepted,
      columns,
      flagAddi,
      flagXori,
      flagOri,
      flagAndi,
      M31.ofNat?,
    ] <;> rfl

private theorem lookupEvent22 (op : Op) :
    (program op).source.events[22]? =
      some (.lookup {
        ordinal := 22
        domain := .programAccess
        numerator := 118
        tuple := #[1, 129, 2, 12, 135]
        role := .request
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent23 (op : Op) :
    (program op).source.events[23]? =
      some (.lookup {
        ordinal := 23
        domain := .rangeCheck811
        numerator := 118
        tuple := #[22, 131]
        role := .request
        tableId := some .rangeCheck811
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent24 (op : Op) :
    (program op).source.events[24]? =
      some (.lookup {
        ordinal := 24
        domain := .registersState
        numerator := 118
        tuple := #[1, 0]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent25 (op : Op) :
    (program op).source.events[25]? =
      some (.lookup {
        ordinal := 25
        domain := .registersState
        numerator := 38
        tuple := #[136, 137]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent26 (op : Op) :
    (program op).source.events[26]? =
      some (.lookup {
        ordinal := 26
        domain := .memoryAccess
        numerator := 118
        tuple := #[56, 12, 17, 13, 14, 15, 16]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 1
      }) := by
  cases op <;> decide

private theorem lookupEvent27 (op : Op) :
    (program op).source.events[27]? =
      some (.lookup {
        ordinal := 27
        domain := .memoryAccess
        numerator := 38
        tuple := #[56, 12, 115, 18, 19, 20, 21]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 1
      }) := by
  cases op <;> decide

private theorem lookupEvent28 (op : Op) :
    (program op).source.events[28]? =
      some (.lookup {
        ordinal := 28
        domain := .rangeCheck20
        numerator := 118
        tuple := #[117]
        role := .request
        tableId := some .rangeCheck20
        liveness := .nonzeroNumerator
        accessOrdinal := some 1
      }) := by
  cases op <;> decide

private theorem lookupEvent29 (op : Op) :
    (program op).source.events[29]? =
      some (.lookup {
        ordinal := 29
        domain := .bitwise
        numerator := 142
        tuple := #[18, 22, 29, 141]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent30 (op : Op) :
    (program op).source.events[30]? =
      some (.lookup {
        ordinal := 30
        domain := .bitwise
        numerator := 142
        tuple := #[19, 53, 30, 141]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent31 (op : Op) :
    (program op).source.events[31]? =
      some (.lookup {
        ordinal := 31
        domain := .bitwise
        numerator := 142
        tuple := #[20, 55, 31, 141]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent32 (op : Op) :
    (program op).source.events[32]? =
      some (.lookup {
        ordinal := 32
        domain := .bitwise
        numerator := 142
        tuple := #[21, 55, 32, 141]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent33 (op : Op) :
    (program op).source.events[33]? =
      some (.lookup {
        ordinal := 33
        domain := .rangeCheck88
        numerator := 118
        tuple := #[29, 30]
        role := .request
        tableId := some .rangeCheck88
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent34 (op : Op) :
    (program op).source.events[34]? =
      some (.lookup {
        ordinal := 34
        domain := .rangeCheck88
        numerator := 118
        tuple := #[31, 32]
        role := .request
        tableId := some .rangeCheck88
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent35 (op : Op) :
    (program op).source.events[35]? =
      some (.lookup {
        ordinal := 35
        domain := .memoryAccess
        numerator := 118
        tuple := #[56, 2, 7, 3, 4, 5, 6]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 2
      }) := by
  cases op <;> decide

private theorem lookupEvent36 (op : Op) :
    (program op).source.events[36]? =
      some (.lookup {
        ordinal := 36
        domain := .memoryAccess
        numerator := 38
        tuple := #[56, 2, 112, 8, 9, 10, 11]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 2
      }) := by
  cases op <;> decide

private theorem lookupEvent37 (op : Op) :
    (program op).source.events[37]? =
      some (.lookup {
        ordinal := 37
        domain := .rangeCheck20
        numerator := 118
        tuple := #[114]
        role := .request
        tableId := some .rangeCheck20
        liveness := .nonzeroNumerator
        accessOrdinal := some 2
      }) := by
  cases op <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem lookupProjection
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).lookup? 22 = some (programLookup op row) ∧
    (evaluation op row witness).lookup? 23 = some (immediateLookup row) ∧
    (evaluation op row witness).lookup? 24 = some (stateConsumeLookup row) ∧
    (evaluation op row witness).lookup? 25 = some (stateEmitLookup row) ∧
    (evaluation op row witness).lookup? 26 = some (sourceConsumeLookup row) ∧
    (evaluation op row witness).lookup? 27 = some (sourceEmitLookup row) ∧
    (evaluation op row witness).lookup? 28 = some (sourceClockLookup row) ∧
    (evaluation op row witness).lookup? 29 = some (bitwiseLookup0 op row) ∧
    (evaluation op row witness).lookup? 30 = some (bitwiseLookup1 op row) ∧
    (evaluation op row witness).lookup? 31 = some (bitwiseLookup2 op row) ∧
    (evaluation op row witness).lookup? 32 = some (bitwiseLookup3 op row) ∧
    (evaluation op row witness).lookup? 33 = some (resultLowLookup row) ∧
    (evaluation op row witness).lookup? 34 = some (resultHighLookup row) ∧
    (evaluation op row witness).lookup? 35 =
      some (destinationConsumeLookup row) ∧
    (evaluation op row witness).lookup? 36 =
      some (destinationEmitLookup row) ∧
    (evaluation op row witness).lookup? 37 =
      some (destinationClockLookup row) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 22 _ (lookupEvent22 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 23 _ (lookupEvent23 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 24 _ (lookupEvent24 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 25 _ (lookupEvent25 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 26 _ (lookupEvent26 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 27 _ (lookupEvent27 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 28 _ (lookupEvent28 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 29 _ (lookupEvent29 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 30 _ (lookupEvent30 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 31 _ (lookupEvent31 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 32 _ (lookupEvent32 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 33 _ (lookupEvent33 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 34 _ (lookupEvent34 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 35 _ (lookupEvent35 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 36 _ (lookupEvent36 op),
    ]
    cases op <;> reduce_base_alu_imm
  · rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 37 _ (lookupEvent37 op),
    ]
    cases op <;> reduce_base_alu_imm

theorem projectionOrdinals (op : Op) :
    (program op).source.projection.programEvent = 22 ∧
      (program op).source.projection.stateEvents = #[24, 25] ∧
      (program op).source.projection.sourceEvents = #[26, 27] ∧
      (program op).source.projection.destinationEvents = #[35, 36] ∧
      (program op).source.projection.nextPc = 136 := by
  cases op <;> decide

private theorem constraintsHoldEvents
    (op : Op)
    (nodes : LocalValues) :
    ((program op).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      #[40, 42, 44, 46, 48, 50, 64, 71, 78, 85, 87, 89, 91,
        93, 95, 97, 99, 101, 103, 105, 107, 39].all
        (fun root => nodes.getSymbolic root == 0) := by
  cases op <;>
    simp [program, Programs.xori, Programs.xoriSource, Programs.ori,
      Programs.oriSource, Programs.andi, Programs.andiSource,
      Event.evalSymbolic]

theorem constraintsHold_eq
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).constraintsHold =
      #[40, 42, 44, 46, 48, 50, 64, 71, 78, 85, 87, 89, 91,
        93, 95, 97, 99, 101, 103, 105, 107, 39].all
        (fun root =>
          (evaluation op row witness).nodes.getSymbolic root == 0) :=
  constraintsHoldEvents op (evaluation op row witness).nodes

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

set_option maxRecDepth 30000 in
private theorem node40 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 40 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node42 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 42 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node44 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 44 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node46 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 46 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node48 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 48 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node50 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 50 =
      bitVecM31 row.immSign * (bitVecM31 row.immSign - 1) := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node64 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 64 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node71 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 71 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node78 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 78 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node85 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 85 = 0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node87 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 87 =
      boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node89 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 89 =
      bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node91 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 91 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node93 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 93 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node95 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 95 =
      bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb1 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node97 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 97 =
      bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb2 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node99 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 99 =
      bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb3 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node101 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 101 =
      bitVecM31 row.rs1Next.limb0 - bitVecM31 row.rs1Previous.limb0 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node103 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 103 =
      bitVecM31 row.rs1Next.limb1 - bitVecM31 row.rs1Previous.limb1 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node105 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 105 =
      bitVecM31 row.rs1Next.limb2 - bitVecM31 row.rs1Previous.limb2 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node107 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 107 =
      bitVecM31 row.rs1Next.limb3 - bitVecM31 row.rs1Previous.limb3 := by
  cases op <;> reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem node39 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 39 = 0 := by
  cases op <;> reduce_base_alu_imm

def ConstraintEquations
    (row : Row)
    (witness : Witness row) :
    Prop :=
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
  bitVecM31 row.rs1Next.limb0 - bitVecM31 row.rs1Previous.limb0 = 0 ∧
  bitVecM31 row.rs1Next.limb1 - bitVecM31 row.rs1Previous.limb1 = 0 ∧
  bitVecM31 row.rs1Next.limb2 - bitVecM31 row.rs1Previous.limb2 = 0 ∧
  bitVecM31 row.rs1Next.limb3 - bitVecM31 row.rs1Previous.limb3 = 0

theorem constraintsHold_iff
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).constraintsHold = true ↔
      ConstraintEquations row witness := by
  rw [constraintsHold_eq]
  cases flag : row.rdNonzero <;>
    simp [
      ConstraintEquations,
      node40, node42, node44, node46, node48, node50,
      node64, node71, node78, node85, node87, node89, node91,
      node93, node95, node97, node99,
      node101, node103, node105, node107, node39,
      flag, boolM31, TeamACommon.boolM31, Lui.boolM31,
      bitVecOneBoolean,
    ]

structure Acceptance
    (op : Op)
    (row : Row)
    (witness : Witness row) : Prop where
  selectors :
    (evaluation op row witness).activeSelectorsAccepted = true
  constraints :
    (evaluation op row witness).constraintsHold = true
  fixedLookups :
    (evaluation op row witness).fixedLookupsHold = true

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourcePreviousBound : row.rs1PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcBound : row.pc.toNat + 4 < M31.modulus

private theorem byteBound (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem fieldByteEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

theorem sourcePreserved
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rs1Next = row.rs1Previous := by
  apply WordBytes.eq_of_limbs
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp equations.2.2.2.2.2.2.1
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp equations.2.2.2.2.2.2.2.1
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp equations.2.2.2.2.2.2.2.2.1
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp equations.2.2.2.2.2.2.2.2.2

theorem destinationFlag
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) :=
  TeamACommon.destinationFlag_of_equations
    row.rd row.rdNonzero witness.destinationInverse
    equations.1 equations.2.1

theorem destinationBytes
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rdNext =
      if row.rdNonzero then row.result else WordBytes.zero :=
  TeamACommon.destinationBytes_of_equations
    row.rdNext row.result row.rdNonzero
    equations.2.2.1
    equations.2.2.2.1
    equations.2.2.2.2.1
    equations.2.2.2.2.2.1

private theorem fixedRequestOfLookup
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true)
    (ordinal : Nat)
    (lookup : EvaluatedLookup)
    (projection : (evaluation op row witness).lookup? ordinal = some lookup) :
    lookup.fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation op row witness) ordinal lookup fixed projection

theorem bitwiseRequestsHold
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    (bitwiseLookup0 op row).fixedRequestHolds = true ∧
      (bitwiseLookup1 op row).fixedRequestHolds = true ∧
      (bitwiseLookup2 op row).fixedRequestHolds = true ∧
      (bitwiseLookup3 op row).fixedRequestHolds = true := by
  rcases lookupProjection op row witness with
    ⟨_, _, _, _, _, _, _, lookup0, lookup1, lookup2, lookup3, _⟩
  exact ⟨
    fixedRequestOfLookup op row witness fixed 29 _ lookup0,
    fixedRequestOfLookup op row witness fixed 30 _ lookup1,
    fixedRequestOfLookup op row witness fixed 31 _ lookup2,
    fixedRequestOfLookup op row witness fixed 32 _ lookup3
  ⟩

def immediateBytes (row : Row) : WordBytes where
  limb0 := row.imm0
  limb1 := BitVec.ofNat 8
    (row.imm1.toNat + 248 * row.immSign.toNat)
  limb2 := BitVec.ofNat 8 (255 * row.immSign.toNat)
  limb3 := BitVec.ofNat 8 (255 * row.immSign.toNat)

def bitwiseByte (op : Op) (left right : Byte) : Byte :=
  match op with
  | .xori => left ^^^ right
  | .ori => left ||| right
  | .andi => left &&& right

def bitwiseBytes (op : Op) (left right : WordBytes) : WordBytes where
  limb0 := bitwiseByte op left.limb0 right.limb0
  limb1 := bitwiseByte op left.limb1 right.limb1
  limb2 := bitwiseByte op left.limb2 right.limb2
  limb3 := bitwiseByte op left.limb3 right.limb3

private theorem byteFieldVal (value : Byte) :
    (bitVecM31 value).val = value.toNat :=
  Lui.bitVecM31_val value (byteBound value)

private theorem immediateLimb1Field_val (row : Row) :
    (immediateLimb1Field row).val =
      (immediateBytes row).limb1.toNat := by
  have immBound := row.imm1.isLt
  have signBound := row.immSign.isLt
  simp only [Nat.reducePow] at immBound signBound
  have rawBound :
      row.imm1.toNat + 248 * row.immSign.toNat < 256 := by omega
  have signProductBound :
      (bitVecM31 row.immSign).val * (M31.reduce 248).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val row.immSign (by simp [M31.modulus_eq]; omega),
      M31.reduce_val_of_lt 248 (by decide),
      M31.modulus_eq,
    ]
    omega
  have productValue :
      (bitVecM31 row.immSign * M31.reduce 248).val =
        row.immSign.toNat * 248 := by
    rw [
      M31.mul_val_of_lt _ _ signProductBound,
      Lui.bitVecM31_val row.immSign (by simp [M31.modulus_eq]; omega),
      M31.reduce_val_of_lt 248 (by decide),
    ]
  have sumBound :
      (bitVecM31 row.imm1).val +
          (bitVecM31 row.immSign * M31.reduce 248).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val row.imm1 (by simp [M31.modulus_eq]; omega),
      productValue,
      M31.modulus_eq,
    ]
    omega
  rw [immediateLimb1Field, M31.add_val_of_lt _ _ sumBound]
  rw [
    Lui.bitVecM31_val row.imm1 (by simp [M31.modulus_eq]; omega),
    productValue,
  ]
  simp only [immediateBytes, BitVec.toNat_ofNat]
  rw [Nat.mod_eq_of_lt (by simpa [Nat.mul_comm] using rawBound)]
  omega

private theorem signLimbField_val (row : Row) :
    (signLimbField row).val =
      (immediateBytes row).limb2.toNat := by
  have signBound := row.immSign.isLt
  simp only [Nat.reducePow] at signBound
  have rawBound : 255 * row.immSign.toNat < 256 := by omega
  have productBound :
      (bitVecM31 row.immSign).val * (M31.reduce 255).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val row.immSign (by simp [M31.modulus_eq]; omega),
      M31.reduce_val_of_lt 255 (by decide),
      M31.modulus_eq,
    ]
    omega
  rw [signLimbField, M31.mul_val_of_lt _ _ productBound]
  rw [
    Lui.bitVecM31_val row.immSign (by simp [M31.modulus_eq]; omega),
    M31.reduce_val_of_lt 255 (by decide),
  ]
  simp only [immediateBytes, BitVec.toNat_ofNat]
  rw [Nat.mod_eq_of_lt rawBound]
  omega

private theorem operationFieldVal (op : Op) :
    (M31.reduce (bitwiseOperationId op)).val =
      bitwiseOperationId op := by
  cases op <;> decide

private theorem bitwiseMembership
    (op : Op)
    (ordinal : Nat)
    (source immediate result : M31)
    (holds :
      (bitwiseLookupFields op ordinal source immediate result).fixedRequestHolds =
        true) :
    FixedTableId.bitwise.contains
      [source, immediate, result, M31.reduce (bitwiseOperationId op)] = true := by
  have nonzero : (-(1 : M31)) ≠ 0 := by decide
  simpa [
    bitwiseLookupFields,
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    nonzero,
  ] using holds

private theorem bitwiseByte_of_membership
    (op : Op)
    (source immediate result : Byte)
    (membership :
      FixedTableId.bitwise.contains
        [bitVecM31 source, bitVecM31 immediate, bitVecM31 result,
          M31.reduce (bitwiseOperationId op)] = true) :
    result = bitwiseByte op source immediate := by
  apply BitVec.eq_of_toNat_eq
  cases op with
  | xori =>
      have meaning :=
        (FixedTableId.bitwise_contains_xor_iff
          (bitVecM31 source) (bitVecM31 immediate) (bitVecM31 result)).mp
          (by simpa [bitwiseOperationId] using membership)
      simpa [bitwiseByte, M31.toNat, byteFieldVal] using meaning.2.2.symm
  | ori =>
      have meaning :=
        (FixedTableId.bitwise_contains_or_iff
          (bitVecM31 source) (bitVecM31 immediate) (bitVecM31 result)).mp
          (by simpa [bitwiseOperationId] using membership)
      simpa [bitwiseByte, M31.toNat, byteFieldVal] using meaning.2.2.symm
  | andi =>
      have meaning :=
        (FixedTableId.bitwise_contains_and_iff
          (bitVecM31 source) (bitVecM31 immediate) (bitVecM31 result)).mp
          (by simpa [bitwiseOperationId] using membership)
      simpa [bitwiseByte, M31.toNat, byteFieldVal] using meaning.2.2.symm

theorem resultBytes_of_fixed
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    row.result = bitwiseBytes op row.rs1Next (immediateBytes row) := by
  rcases bitwiseRequestsHold op row witness fixed with
    ⟨request0, request1, request2, request3⟩
  apply WordBytes.eq_of_limbs
  · apply bitwiseByte_of_membership
    exact bitwiseMembership op 29
      (bitVecM31 row.rs1Next.limb0)
      (bitVecM31 row.imm0)
      (bitVecM31 row.result.limb0)
      request0
  · apply bitwiseByte_of_membership
    have membership := bitwiseMembership op 30
      (bitVecM31 row.rs1Next.limb1)
      (immediateLimb1Field row)
      (bitVecM31 row.result.limb1)
      request1
    have immediateEq :
        immediateLimb1Field row =
          bitVecM31 (immediateBytes row).limb1 := by
      apply M31.ext
      rw [
        immediateLimb1Field_val row,
        byteFieldVal (immediateBytes row).limb1,
      ]
    rw [immediateEq] at membership
    exact membership
  · apply bitwiseByte_of_membership
    have membership := bitwiseMembership op 31
      (bitVecM31 row.rs1Next.limb2)
      (signLimbField row)
      (bitVecM31 row.result.limb2)
      request2
    have immediateEq :
        signLimbField row =
          bitVecM31 (immediateBytes row).limb2 := by
      apply M31.ext
      rw [
        signLimbField_val row,
        byteFieldVal (immediateBytes row).limb2,
      ]
    rw [immediateEq] at membership
    exact membership
  · apply bitwiseByte_of_membership
    have membership := bitwiseMembership op 32
      (bitVecM31 row.rs1Next.limb3)
      (signLimbField row)
      (bitVecM31 row.result.limb3)
      request3
    have limb3 :
        (immediateBytes row).limb3 = (immediateBytes row).limb2 := by
      rfl
    have immediateEq :
        signLimbField row =
          bitVecM31 (immediateBytes row).limb3 := by
      apply M31.ext
      rw [
        limb3,
        signLimbField_val row,
        byteFieldVal (immediateBytes row).limb2,
      ]
    rw [immediateEq] at membership
    exact membership

theorem sourceClockGapBound
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    (clockGapField row 1 row.rs1PreviousClock).val < 2 ^ 20 := by
  rcases lookupProjection op row witness with
    ⟨_, _, _, _, _, _, projection, _⟩
  have request :=
    fixedRequestOfLookup op row witness fixed 28 _ projection
  exact
    (TeamACommon.rangeCheck20RequestHolds_iff
      28 (some 1) (clockGapField row 1 row.rs1PreviousClock)).mp request

theorem destinationClockGapBound
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    (clockGapField row 2 row.rdPreviousClock).val < 2 ^ 20 := by
  rcases lookupProjection op row witness with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, projection⟩
  have request :=
    fixedRequestOfLookup op row witness fixed 37 _ projection
  exact
    (TeamACommon.rangeCheck20RequestHolds_iff
      37 (some 2) (clockGapField row 2 row.rdPreviousClock)).mp request

private theorem accessClockBound
    (row : Row)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 2) :
    accessClock row.clock ordinal < 2 ^ 26 := by
  simp only [accessClock]
  have clockBound := admission.clockBound
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
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1) := by
  apply TeamACommon.validPreviousClock_of_gap
  · simp only [accessClock]
    have positive := admission.clockPositive
    omega
  · exact accessClockBound row admission 1 (by decide)
  · exact admission.sourcePreviousBound
  · have gap := sourceClockGapBound op row witness fixed
    have accessEq :=
      accessClockField_eq row admission 1 (by decide)
    unfold accessClockField at accessEq
    rw [
      clockGapField,
      TeamACommon.clockGapField,
      accessEq,
    ] at gap
    exact gap

theorem destinationClock
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2) := by
  apply TeamACommon.validPreviousClock_of_gap
  · simp only [accessClock]
    have positive := admission.clockPositive
    omega
  · exact accessClockBound row admission 2 (by decide)
  · exact admission.destinationPreviousBound
  · have gap := destinationClockGapBound op row witness fixed
    have accessEq :=
      accessClockField_eq row admission 2 (by decide)
    unfold accessClockField at accessEq
    rw [
      clockGapField,
      TeamACommon.clockGapField,
      accessEq,
    ] at gap
    exact gap

theorem destinationWord
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations row witness) :
    row.rdNext.word = architecturalValue row.rd row.result.word := by
  have bytes := destinationBytes row witness equations
  have flag := destinationFlag row witness equations
  by_cases zero : row.rd = zeroRegister
  · have flagFalse : row.rdNonzero = false := by
      rw [flag]
      simp [zero]
    rw [zero, architecturalValue_zero]
    rw [bytes, flagFalse]
    rfl
  · have flagTrue : row.rdNonzero = true := by
      rw [flag]
      simp [zero]
    rw [architecturalValue]
    simp only [zero, ↓reduceIte]
    rw [bytes, flagTrue]
    rfl

structure ProductionRefinement
    (op : Op)
    (row : Row)
    (witness : Witness row) : Prop where
  selectors :
    (evaluation op row witness).activeSelectorsAccepted = true
  constraints :
    (evaluation op row witness).constraintsHold = true
  fixedLookups :
    (evaluation op row witness).fixedLookupsHold = true
  program :
    (evaluation op row witness).lookup? 22 = some (programLookup op row)
  immediateRange :
    (evaluation op row witness).lookup? 23 = some (immediateLookup row)
  stateConsume :
    (evaluation op row witness).lookup? 24 = some (stateConsumeLookup row)
  stateEmit :
    (evaluation op row witness).lookup? 25 = some (stateEmitLookup row)
  sourceConsume :
    (evaluation op row witness).lookup? 26 = some (sourceConsumeLookup row)
  sourceEmit :
    (evaluation op row witness).lookup? 27 = some (sourceEmitLookup row)
  sourceClockLookup :
    (evaluation op row witness).lookup? 28 = some (sourceClockLookup row)
  bitwise0 :
    (evaluation op row witness).lookup? 29 = some (bitwiseLookup0 op row)
  bitwise1 :
    (evaluation op row witness).lookup? 30 = some (bitwiseLookup1 op row)
  bitwise2 :
    (evaluation op row witness).lookup? 31 = some (bitwiseLookup2 op row)
  bitwise3 :
    (evaluation op row witness).lookup? 32 = some (bitwiseLookup3 op row)
  resultLow :
    (evaluation op row witness).lookup? 33 = some (resultLowLookup row)
  resultHigh :
    (evaluation op row witness).lookup? 34 = some (resultHighLookup row)
  destinationConsume :
    (evaluation op row witness).lookup? 35 =
      some (destinationConsumeLookup row)
  destinationEmit :
    (evaluation op row witness).lookup? 36 =
      some (destinationEmitLookup row)
  destinationClockLookup :
    (evaluation op row witness).lookup? 37 =
      some (destinationClockLookup row)
  sourceValue : row.rs1Next = row.rs1Previous
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  resultValue :
    row.result = bitwiseBytes op row.rs1Next (immediateBytes row)
  destinationValue :
    row.rdNext.word = architecturalValue row.rd row.result.word
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2)
  nextPc :
    (stateEmitLookup row).tuple[0]? = some (bitVecM31 (nextPc row.pc))
  nextClock :
    (stateEmitLookup row).tuple[1]? = some (M31.reduce (row.clock + 1))

theorem sound
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance op row witness) :
    ProductionRefinement op row witness := by
  have equations :=
    (constraintsHold_iff op row witness).mp accepted.constraints
  rcases lookupProjection op row witness with
    ⟨programProjection, immediateProjection, stateConsumeProjection,
      stateEmitProjection, sourceConsumeProjection, sourceEmitProjection,
      sourceClockProjection, bitwise0Projection, bitwise1Projection,
      bitwise2Projection, bitwise3Projection, resultLowProjection,
      resultHighProjection, destinationConsumeProjection,
      destinationEmitProjection, destinationClockProjection⟩
  refine {
    selectors := accepted.selectors
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    program := programProjection
    immediateRange := immediateProjection
    stateConsume := stateConsumeProjection
    stateEmit := stateEmitProjection
    sourceConsume := sourceConsumeProjection
    sourceEmit := sourceEmitProjection
    sourceClockLookup := sourceClockProjection
    bitwise0 := bitwise0Projection
    bitwise1 := bitwise1Projection
    bitwise2 := bitwise2Projection
    bitwise3 := bitwise3Projection
    resultLow := resultLowProjection
    resultHigh := resultHighProjection
    destinationConsume := destinationConsumeProjection
    destinationEmit := destinationEmitProjection
    destinationClockLookup := destinationClockProjection
    sourceValue := sourcePreserved row witness equations
    sourceClock :=
      sourceClock op row witness admission accepted.fixedLookups
    resultValue :=
      resultBytes_of_fixed op row witness accepted.fixedLookups
    destinationValue := destinationWord row witness equations
    destinationClock :=
      destinationClock op row witness admission accepted.fixedLookups
    nextPc := ?_
    nextClock := ?_
  }
  · simp [
      stateEmitLookup,
      TeamACommon.nextPcField row.pc admission.pcBound,
    ]
  · apply congrArg some
    simp only [stateEmitLookup]
    apply TeamACommon.nextClockField
    have bound := admission.clockBound
    simp [M31.modulus_eq] at *
    omega

private def immediateLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 23
  domain := .rangeCheck811
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 22, nodes.getSymbolic 131]
  role := .request
  tableId := some .rangeCheck811
  accessOrdinal := none

private def sourceClockLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 28
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 117]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

private def bitwiseLookup0At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 29
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 18, nodes.getSymbolic 22,
    nodes.getSymbolic 29, nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup1At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 30
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 19, nodes.getSymbolic 53,
    nodes.getSymbolic 30, nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup2At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 31
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 20, nodes.getSymbolic 55,
    nodes.getSymbolic 31, nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup3At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 32
  domain := .bitwise
  numerator := nodes.getSymbolic 142
  tuple := #[
    nodes.getSymbolic 21, nodes.getSymbolic 55,
    nodes.getSymbolic 32, nodes.getSymbolic 141
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def resultLowLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 33
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 29, nodes.getSymbolic 30]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def resultHighLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 34
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 31, nodes.getSymbolic 32]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def destinationClockLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 37
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 118
  tuple := #[nodes.getSymbolic 114]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

set_option maxRecDepth 30000 in
private theorem fixedLookupsHoldEvents
    (op : Op)
    (nodes : LocalValues) :
    ((program op).source.events.map (Event.evalSymbolic nodes)).all
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
  cases op <;>
    simp [
      program,
      Programs.xori,
      Programs.xoriSource,
      Programs.ori,
      Programs.oriSource,
      Programs.andi,
      Programs.andiSource,
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
    (op : Op) (row : Row) (witness : Witness row) :
    immediateLookupAt (evaluation op row witness).nodes =
      immediateLookup row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold immediateLookupAt <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem sourceClockLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    sourceClockLookupAt (evaluation op row witness).nodes =
      sourceClockLookup row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold sourceClockLookupAt <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem bitwiseLookup0At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup0At (evaluation op row witness).nodes =
      bitwiseLookup0 op row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold bitwiseLookup0At <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem bitwiseLookup1At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup1At (evaluation op row witness).nodes =
      bitwiseLookup1 op row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold bitwiseLookup1At <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem bitwiseLookup2At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup2At (evaluation op row witness).nodes =
      bitwiseLookup2 op row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold bitwiseLookup2At <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem bitwiseLookup3At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup3At (evaluation op row witness).nodes =
      bitwiseLookup3 op row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold bitwiseLookup3At <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem resultLowLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    resultLowLookupAt (evaluation op row witness).nodes =
      resultLowLookup row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold resultLowLookupAt <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem resultHighLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    resultHighLookupAt (evaluation op row witness).nodes =
      resultHighLookup row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold resultHighLookupAt <;>
    reduce_base_alu_imm

set_option maxRecDepth 30000 in
private theorem destinationClockLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    destinationClockLookupAt (evaluation op row witness).nodes =
      destinationClockLookup row := by
  cases op <;>
    simp only [evaluation] <;>
    unfold destinationClockLookupAt <;>
    reduce_base_alu_imm

theorem fixedLookupsHold_eq
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).fixedLookupsHold =
      ((immediateLookup row).fixedRequestHolds &&
        ((sourceClockLookup row).fixedRequestHolds &&
          ((bitwiseLookup0 op row).fixedRequestHolds &&
            ((bitwiseLookup1 op row).fixedRequestHolds &&
              ((bitwiseLookup2 op row).fixedRequestHolds &&
                ((bitwiseLookup3 op row).fixedRequestHolds &&
                  ((resultLowLookup row).fixedRequestHolds &&
                    ((resultHighLookup row).fixedRequestHolds &&
                      (destinationClockLookup row).fixedRequestHolds)))))))) := by
  rw [SymbolicEvaluation.fixedLookupsHold]
  change
    ((program op).source.events.map
      (Event.evalSymbolic (evaluation op row witness).nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((immediateLookup row).fixedRequestHolds &&
        ((sourceClockLookup row).fixedRequestHolds &&
          ((bitwiseLookup0 op row).fixedRequestHolds &&
            ((bitwiseLookup1 op row).fixedRequestHolds &&
              ((bitwiseLookup2 op row).fixedRequestHolds &&
                ((bitwiseLookup3 op row).fixedRequestHolds &&
                  ((resultLowLookup row).fixedRequestHolds &&
                    ((resultHighLookup row).fixedRequestHolds &&
                      (destinationClockLookup row).fixedRequestHolds))))))))
  rw [fixedLookupsHoldEvents]
  rw [
    immediateLookupAt_evaluation,
    sourceClockLookupAt_evaluation,
    bitwiseLookup0At_evaluation,
    bitwiseLookup1At_evaluation,
    bitwiseLookup2At_evaluation,
    bitwiseLookup3At_evaluation,
    resultLowLookupAt_evaluation,
    resultHighLookupAt_evaluation,
    destinationClockLookupAt_evaluation,
  ]

def exampleRow : Row where
  clock := 1
  pc := BitVec.ofNat 32 0x1000
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

def exampleWitness : Witness exampleRow where
  destinationInverse := 1

theorem exampleAdmission : Admission exampleRow := by
  constructor <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem exampleAcceptance (op : Op) :
    Acceptance op exampleRow exampleWitness := by
  refine {
    selectors := selectorAccepted op exampleRow exampleWitness
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff op exampleRow exampleWitness).mpr
    simp [
      ConstraintEquations,
      exampleRow,
      exampleWitness,
      WordBytes.zero,
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
    ]
  · rw [fixedLookupsHold_eq]
    cases op <;>
      simp [
        immediateLookup,
        sourceClockLookup,
        bitwiseLookup0,
        bitwiseLookup1,
        bitwiseLookup2,
        bitwiseLookup3,
        bitwiseLookupFields,
        resultLowLookup,
        resultHighLookup,
        destinationClockLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
        EvaluatedLookup.isLive,
        FixedTableId.contains,
        FixedTableId.bitwiseResult,
        immediateLimb1Field,
        signLimbField,
        clockGapField,
        TeamACommon.clockGapField,
        TeamACommon.accessClockField,
        exampleRow,
        WordBytes.zero,
        bitVecM31,
        TeamACommon.bitVecM31,
        Lui.bitVecM31,
        M31.toNat,
        M31.reduce_val,
        M31.modulus_eq,
      ] <;> decide

theorem acceptanceNonvacuous :
    ∀ op : Op,
      ∃ (row : Row) (witness : Witness row),
        Admission row ∧ Acceptance op row witness := by
  intro op
  exact ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance op⟩

def zeroRow
    (zeroDestination : Bool)
    (rs1 : RegisterIndex) : Row where
  clock := 1
  pc := BitVec.ofNat 32 0x1000
  rd := if zeroDestination then zeroRegister else BitVec.ofNat 5 1
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := WordBytes.zero
  rs1 := rs1
  rs1PreviousClock := 0
  rs1Previous := WordBytes.zero
  rs1Next := WordBytes.zero
  imm0 := BitVec.ofNat 8 0
  imm1 := BitVec.ofNat 3 0
  immSign := BitVec.ofNat 1 0
  result := WordBytes.zero
  rdNonzero := !zeroDestination

def zeroWitness
    (zeroDestination : Bool)
    (rs1 : RegisterIndex) :
    Witness (zeroRow zeroDestination rs1) where
  destinationInverse := if zeroDestination then 0 else 1

theorem zeroAdmission
    (zeroDestination : Bool)
    (rs1 : RegisterIndex) :
    Admission (zeroRow zeroDestination rs1) := by
  constructor <;> simp [zeroRow, M31.modulus_eq]

set_option maxHeartbeats 0 in
theorem zeroAcceptance
    (op : Op)
    (zeroDestination : Bool)
    (rs1 : RegisterIndex) :
    Acceptance op
      (zeroRow zeroDestination rs1)
      (zeroWitness zeroDestination rs1) := by
  refine {
    selectors := selectorAccepted op _ _
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff op _ _).mpr
    cases zeroDestination <;> cases op <;>
      simp [
        ConstraintEquations,
        zeroRow,
        zeroWitness,
        zeroRegister,
        WordBytes.zero,
        bitVecM31,
        TeamACommon.bitVecM31,
        Lui.bitVecM31,
        boolM31,
        TeamACommon.boolM31,
        Lui.boolM31,
      ]
  · rw [fixedLookupsHold_eq]
    cases op <;>
      simp [
        immediateLookup,
        sourceClockLookup,
        bitwiseLookup0,
        bitwiseLookup1,
        bitwiseLookup2,
        bitwiseLookup3,
        bitwiseLookupFields,
        resultLowLookup,
        resultHighLookup,
        destinationClockLookup,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.fixedMembership,
        EvaluatedLookup.isLive,
        FixedTableId.contains,
        FixedTableId.bitwiseResult,
        immediateLimb1Field,
        signLimbField,
        clockGapField,
        TeamACommon.clockGapField,
        TeamACommon.accessClockField,
        zeroRow,
        WordBytes.zero,
        bitVecM31,
        TeamACommon.bitVecM31,
        Lui.bitVecM31,
        M31.toNat,
        M31.reduce_val,
        M31.modulus_eq,
      ] <;> decide

theorem zeroDestinationNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧ Acceptance op row witness ∧ row.rd = zeroRegister := by
  exact ⟨
    zeroRow true (BitVec.ofNat 5 2),
    zeroWitness true (BitVec.ofNat 5 2),
    zeroAdmission true (BitVec.ofNat 5 2),
    zeroAcceptance op true (BitVec.ofNat 5 2),
    by rfl
  ⟩

theorem sourceAliasNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧ Acceptance op row witness ∧ row.rd = row.rs1 := by
  exact ⟨
    zeroRow false (BitVec.ofNat 5 1),
    zeroWitness false (BitVec.ofNat 5 1),
    zeroAdmission false (BitVec.ofNat 5 1),
    zeroAcceptance op false (BitVec.ofNat 5 1),
    by rfl
  ⟩

end RiscvRefinement.Air.Bridge.BaseAluImm
