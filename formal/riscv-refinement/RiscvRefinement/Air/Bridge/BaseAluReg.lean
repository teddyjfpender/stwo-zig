import RiscvRefinement.Air.Bridge.Addi
import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Air.Generated.Programs
import RiscvRefinement.Bridge.DecodeBaseAlu

/-!
# Production base-ALU-register AIR bridge

This bridge evaluates the exact committed ADD, SUB, XOR, OR, and AND programs.
It exposes their ordered lookup topology and derives register preservation,
byte-wise/arithmetic result semantics, destination gating, access-clock
validity, and the `pc + 4` state transition from accepted generated AIR rows.
-/

namespace RiscvRefinement.Air.Bridge.BaseAluReg

open RiscvRefinement
open RiscvRefinement.Air.Generated
open RiscvRefinement.Decode

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

abbrev Op := BaseAluRegOp

def manifestId : Op → Nat
  | .add => 0
  | .sub => 1
  | .xor => 5
  | .or => 8
  | .and => 9

def program : Op → LocalProgram
  | .add => Programs.add
  | .sub => Programs.sub
  | .xor => Programs.xor
  | .or => Programs.or
  | .and => Programs.and

def bitwiseOperationId : Op → Nat
  | .xor => 2
  | .or => 1
  | _ => 0

def isBitwise : Op → Bool
  | .xor | .or | .and => true
  | _ => false

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
  rs2 : RegisterIndex
  rs2PreviousClock : Nat
  rs2Previous : WordBytes
  rs2Next : WordBytes
  result : WordBytes
  rdNonzero : Bool
deriving DecidableEq, Repr

structure Witness (row : Row) where
  destinationInverse : M31

def flagAdd : Op → M31
  | .add => 1
  | _ => 0

def flagSub : Op → M31
  | .sub => 1
  | _ => 0

def flagXor : Op → M31
  | .xor => 1
  | _ => 0

def flagOr : Op → M31
  | .or => 1
  | _ => 0

def flagAnd : Op → M31
  | .and => 1
  | _ => 0

def bitwiseFlag (op : Op) : M31 :=
  flagXor op + flagOr op + flagAnd op

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
  | 32 => flagAdd op
  | 33 => flagSub op
  | 34 => flagXor op
  | 35 => flagOr op
  | 36 => flagAnd op
  | 37 => bitVecM31 row.result.limb0
  | 38 => bitVecM31 row.result.limb1
  | 39 => bitVecM31 row.result.limb2
  | 40 => bitVecM31 row.result.limb3
  | 41 => boolM31 row.rdNonzero
  | 42 => witness.destinationInverse
  | _ => 0

def evaluation
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    SymbolicEvaluation :=
  (program op).evalSymbolic (columns op row witness)

def accessClockField (row : Row) (ordinal : Nat) : M31 :=
  TeamACommon.accessClockField row.clock ordinal

def clockGapField (row : Row) (ordinal previous : Nat) : M31 :=
  TeamACommon.clockGapField row.clock ordinal previous

def programLookup (op : Op) (row : Row) : EvaluatedLookup where
  ordinal := 30
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce (manifestId op),
    bitVecM31 row.rd,
    bitVecM31 row.rs1,
    bitVecM31 row.rs2
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 31
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 32
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc + M31.reduce 4,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def source1ConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 33
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

def source1EmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 34
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

def source1ClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 35
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row 1 row.rs1PreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

def source2ConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 36
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rs2, M31.reduce row.rs2PreviousClock,
    bitVecM31 row.rs2Previous.limb0,
    bitVecM31 row.rs2Previous.limb1,
    bitVecM31 row.rs2Previous.limb2,
    bitVecM31 row.rs2Previous.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 2

def source2EmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 37
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rs2, accessClockField row 2,
    bitVecM31 row.rs2Next.limb0,
    bitVecM31 row.rs2Next.limb1,
    bitVecM31 row.rs2Next.limb2,
    bitVecM31 row.rs2Next.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 2

def source2ClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 38
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row 2 row.rs2PreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

def bitwiseLookupFields
    (op : Op)
    (ordinal : Nat)
    (source1 source2 result : M31) :
    EvaluatedLookup where
  ordinal := ordinal
  domain := .bitwise
  numerator := -bitwiseFlag op
  tuple := #[source1, source2, result, M31.reduce (bitwiseOperationId op)]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

def bitwiseLookup0 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 39
    (bitVecM31 row.rs1Next.limb0)
    (bitVecM31 row.rs2Next.limb0)
    (bitVecM31 row.result.limb0)

def bitwiseLookup1 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 40
    (bitVecM31 row.rs1Next.limb1)
    (bitVecM31 row.rs2Next.limb1)
    (bitVecM31 row.result.limb1)

def bitwiseLookup2 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 41
    (bitVecM31 row.rs1Next.limb2)
    (bitVecM31 row.rs2Next.limb2)
    (bitVecM31 row.result.limb2)

def bitwiseLookup3 (op : Op) (row : Row) : EvaluatedLookup :=
  bitwiseLookupFields op 42
    (bitVecM31 row.rs1Next.limb3)
    (bitVecM31 row.rs2Next.limb3)
    (bitVecM31 row.result.limb3)

def resultLowLookup (row : Row) : EvaluatedLookup where
  ordinal := 43
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.result.limb0, bitVecM31 row.result.limb1]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def resultHighLookup (row : Row) : EvaluatedLookup where
  ordinal := 44
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.result.limb2, bitVecM31 row.result.limb3]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 45
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
  accessOrdinal := some 3

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 46
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rd, accessClockField row 3,
    bitVecM31 row.rdNext.limb0,
    bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2,
    bitVecM31 row.rdNext.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 3

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 47
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField row 3 row.rdPreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 3

macro "reduce_base_alu_reg" : tactic =>
  `(tactic|
    (simp only [
      program,
      evaluation,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.add,
      Programs.addSource,
      Programs.sub,
      Programs.subSource,
      Programs.xor,
      Programs.xorSource,
      Programs.or,
      Programs.orSource,
      Programs.and,
      Programs.andSource,
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
      flagAdd,
      flagSub,
      flagXor,
      flagOr,
      flagAnd,
      bitwiseFlag,
      manifestId,
      bitwiseOperationId,
      programLookup,
      stateConsumeLookup,
      stateEmitLookup,
      source1ConsumeLookup,
      source1EmitLookup,
      source1ClockLookup,
      source2ConsumeLookup,
      source2EmitLookup,
      source2ClockLookup,
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
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      SymbolicEvaluation.activeSelectorsAccepted,
      SymbolicEvaluation.lookup?,
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
  cases op <;> reduce_base_alu_reg

private theorem lookupEvent30 (op : Op) :
    (program op).source.events[30]? =
      some (.lookup {
        ordinal := 30
        domain := .programAccess
        numerator := 162
        tuple := #[1, 174, 2, 12, 22]
        role := .request
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent31 (op : Op) :
    (program op).source.events[31]? =
      some (.lookup {
        ordinal := 31
        domain := .registersState
        numerator := 162
        tuple := #[1, 0]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent32 (op : Op) :
    (program op).source.events[32]? =
      some (.lookup {
        ordinal := 32
        domain := .registersState
        numerator := 47
        tuple := #[175, 176]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent33 (op : Op) :
    (program op).source.events[33]? =
      some (.lookup {
        ordinal := 33
        domain := .memoryAccess
        numerator := 162
        tuple := #[60, 12, 17, 13, 14, 15, 16]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 1
      }) := by
  cases op <;> decide

private theorem lookupEvent34 (op : Op) :
    (program op).source.events[34]? =
      some (.lookup {
        ordinal := 34
        domain := .memoryAccess
        numerator := 47
        tuple := #[60, 12, 155, 18, 19, 20, 21]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 1
      }) := by
  cases op <;> decide

private theorem lookupEvent35 (op : Op) :
    (program op).source.events[35]? =
      some (.lookup {
        ordinal := 35
        domain := .rangeCheck20
        numerator := 162
        tuple := #[157]
        role := .request
        tableId := some .rangeCheck20
        liveness := .nonzeroNumerator
        accessOrdinal := some 1
      }) := by
  cases op <;> decide

private theorem lookupEvent36 (op : Op) :
    (program op).source.events[36]? =
      some (.lookup {
        ordinal := 36
        domain := .memoryAccess
        numerator := 162
        tuple := #[60, 22, 27, 23, 24, 25, 26]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 2
      }) := by
  cases op <;> decide

private theorem lookupEvent37 (op : Op) :
    (program op).source.events[37]? =
      some (.lookup {
        ordinal := 37
        domain := .memoryAccess
        numerator := 47
        tuple := #[60, 22, 159, 28, 29, 30, 31]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 2
      }) := by
  cases op <;> decide

private theorem lookupEvent38 (op : Op) :
    (program op).source.events[38]? =
      some (.lookup {
        ordinal := 38
        domain := .rangeCheck20
        numerator := 162
        tuple := #[161]
        role := .request
        tableId := some .rangeCheck20
        liveness := .nonzeroNumerator
        accessOrdinal := some 2
      }) := by
  cases op <;> decide

private theorem lookupEvent39 (op : Op) :
    (program op).source.events[39]? =
      some (.lookup {
        ordinal := 39
        domain := .bitwise
        numerator := 181
        tuple := #[18, 28, 37, 180]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent40 (op : Op) :
    (program op).source.events[40]? =
      some (.lookup {
        ordinal := 40
        domain := .bitwise
        numerator := 181
        tuple := #[19, 29, 38, 180]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent41 (op : Op) :
    (program op).source.events[41]? =
      some (.lookup {
        ordinal := 41
        domain := .bitwise
        numerator := 181
        tuple := #[20, 30, 39, 180]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent42 (op : Op) :
    (program op).source.events[42]? =
      some (.lookup {
        ordinal := 42
        domain := .bitwise
        numerator := 181
        tuple := #[21, 31, 40, 180]
        role := .request
        tableId := some .bitwise
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent43 (op : Op) :
    (program op).source.events[43]? =
      some (.lookup {
        ordinal := 43
        domain := .rangeCheck88
        numerator := 162
        tuple := #[37, 38]
        role := .request
        tableId := some .rangeCheck88
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent44 (op : Op) :
    (program op).source.events[44]? =
      some (.lookup {
        ordinal := 44
        domain := .rangeCheck88
        numerator := 162
        tuple := #[39, 40]
        role := .request
        tableId := some .rangeCheck88
        liveness := .nonzeroNumerator
        accessOrdinal := none
      }) := by
  cases op <;> decide

private theorem lookupEvent45 (op : Op) :
    (program op).source.events[45]? =
      some (.lookup {
        ordinal := 45
        domain := .memoryAccess
        numerator := 162
        tuple := #[60, 2, 7, 3, 4, 5, 6]
        role := .consume
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 3
      }) := by
  cases op <;> decide

private theorem lookupEvent46 (op : Op) :
    (program op).source.events[46]? =
      some (.lookup {
        ordinal := 46
        domain := .memoryAccess
        numerator := 47
        tuple := #[60, 2, 152, 8, 9, 10, 11]
        role := .emit
        tableId := none
        liveness := .nonzeroNumerator
        accessOrdinal := some 3
      }) := by
  cases op <;> decide

private theorem lookupEvent47 (op : Op) :
    (program op).source.events[47]? =
      some (.lookup {
        ordinal := 47
        domain := .rangeCheck20
        numerator := 162
        tuple := #[154]
        role := .request
        tableId := some .rangeCheck20
        liveness := .nonzeroNumerator
        accessOrdinal := some 3
      }) := by
  cases op <;> decide

set_option maxHeartbeats 0 in
set_option maxRecDepth 30000 in
theorem lookupProjection
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).lookup? 30 = some (programLookup op row) ∧
      (evaluation op row witness).lookup? 31 =
        some (stateConsumeLookup row) ∧
      (evaluation op row witness).lookup? 32 = some (stateEmitLookup row) ∧
      (evaluation op row witness).lookup? 33 =
        some (source1ConsumeLookup row) ∧
      (evaluation op row witness).lookup? 34 =
        some (source1EmitLookup row) ∧
      (evaluation op row witness).lookup? 35 =
        some (source1ClockLookup row) ∧
      (evaluation op row witness).lookup? 36 =
        some (source2ConsumeLookup row) ∧
      (evaluation op row witness).lookup? 37 =
        some (source2EmitLookup row) ∧
      (evaluation op row witness).lookup? 38 =
        some (source2ClockLookup row) ∧
      (evaluation op row witness).lookup? 39 =
        some (bitwiseLookup0 op row) ∧
      (evaluation op row witness).lookup? 40 =
        some (bitwiseLookup1 op row) ∧
      (evaluation op row witness).lookup? 41 =
        some (bitwiseLookup2 op row) ∧
      (evaluation op row witness).lookup? 42 =
        some (bitwiseLookup3 op row) ∧
      (evaluation op row witness).lookup? 43 =
        some (resultLowLookup row) ∧
      (evaluation op row witness).lookup? 44 =
        some (resultHighLookup row) ∧
      (evaluation op row witness).lookup? 45 =
        some (destinationConsumeLookup row) ∧
      (evaluation op row witness).lookup? 46 =
        some (destinationEmitLookup row) ∧
      (evaluation op row witness).lookup? 47 =
        some (destinationClockLookup row) := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_,
    ?_, ?_, ?_⟩
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 30 _ (lookupEvent30 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 31 _ (lookupEvent31 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 32 _ (lookupEvent32 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 33 _ (lookupEvent33 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 34 _ (lookupEvent34 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 35 _ (lookupEvent35 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 36 _ (lookupEvent36 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 37 _ (lookupEvent37 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 38 _ (lookupEvent38 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 39 _ (lookupEvent39 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 40 _ (lookupEvent40 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 41 _ (lookupEvent41 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 42 _ (lookupEvent42 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 43 _ (lookupEvent43 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 44 _ (lookupEvent44 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 45 _ (lookupEvent45 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 46 _ (lookupEvent46 op)]
    cases op <;> reduce_base_alu_reg
  · rw [evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        (program op) (columns op row witness) 47 _ (lookupEvent47 op)]
    cases op <;> reduce_base_alu_reg

theorem projectionOrdinals (op : Op) :
    (program op).source.projection.programEvent = 30 ∧
      (program op).source.projection.stateEvents = #[31, 32] ∧
      (program op).source.projection.sourceEvents = #[33, 34, 36, 37] ∧
      (program op).source.projection.destinationEvents = #[45, 46] ∧
      (program op).source.projection.nextPc = 175 := by
  cases op <;> decide

def addCarry1Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb0 + bitVecM31 row.rs2Next.limb0 + 0 -
      bitVecM31 row.result.limb0) *
    M31.reduce 8388608

def addCarry2Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb1 + bitVecM31 row.rs2Next.limb1 +
      addCarry1Field row - bitVecM31 row.result.limb1) *
    M31.reduce 8388608

def addCarry3Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb2 + bitVecM31 row.rs2Next.limb2 +
      addCarry2Field row - bitVecM31 row.result.limb2) *
    M31.reduce 8388608

def addCarry4Field (row : Row) : M31 :=
  (bitVecM31 row.rs1Next.limb3 + bitVecM31 row.rs2Next.limb3 +
      addCarry3Field row - bitVecM31 row.result.limb3) *
    M31.reduce 8388608

def subCarry1Field (row : Row) : M31 :=
  (bitVecM31 row.result.limb0 + bitVecM31 row.rs2Next.limb0 + 0 -
      bitVecM31 row.rs1Next.limb0) *
    M31.reduce 8388608

def subCarry2Field (row : Row) : M31 :=
  (bitVecM31 row.result.limb1 + bitVecM31 row.rs2Next.limb1 +
      subCarry1Field row - bitVecM31 row.rs1Next.limb1) *
    M31.reduce 8388608

def subCarry3Field (row : Row) : M31 :=
  (bitVecM31 row.result.limb2 + bitVecM31 row.rs2Next.limb2 +
      subCarry2Field row - bitVecM31 row.rs1Next.limb2) *
    M31.reduce 8388608

def subCarry4Field (row : Row) : M31 :=
  (bitVecM31 row.result.limb3 + bitVecM31 row.rs2Next.limb3 +
      subCarry3Field row - bitVecM31 row.rs1Next.limb3) *
    M31.reduce 8388608

private theorem constraintsHoldEvents
    (op : Op)
    (nodes : LocalValues) :
    ((program op).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      #[49, 51, 53, 55, 57, 59, 68, 75, 82, 89, 96, 103, 110,
        117, 119, 121, 123, 125, 127, 129, 131, 133, 135, 137, 139,
        141, 143, 145, 147, 48].all
        (fun root => nodes.getSymbolic root == 0) := by
  cases op <;>
    simp [
      program,
      Programs.add,
      Programs.addSource,
      Programs.sub,
      Programs.subSource,
      Programs.xor,
      Programs.xorSource,
      Programs.or,
      Programs.orSource,
      Programs.and,
      Programs.andSource,
      Event.evalSymbolic,
    ]

theorem constraintsHold_eq
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).constraintsHold =
      #[49, 51, 53, 55, 57, 59, 68, 75, 82, 89, 96, 103, 110,
        117, 119, 121, 123, 125, 127, 129, 131, 133, 135, 137, 139,
        141, 143, 145, 147, 48].all
        (fun root =>
          (evaluation op row witness).nodes.getSymbolic root == 0) :=
  constraintsHoldEvents op (evaluation op row witness).nodes

private theorem bitVecOneBoolean (value : BitVec 1) :
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
private theorem node49 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 49 = 0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node51 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 51 = 0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node53 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 53 = 0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node55 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 55 = 0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node57 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 57 = 0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node59 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 59 = 0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node68 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 68 =
      flagAdd op *
        (addCarry1Field row * (addCarry1Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node75 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 75 =
      flagAdd op *
        (addCarry2Field row * (addCarry2Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node82 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 82 =
      flagAdd op *
        (addCarry3Field row * (addCarry3Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node89 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 89 =
      flagAdd op *
        (addCarry4Field row * (addCarry4Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node96 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 96 =
      flagSub op *
        (subCarry1Field row * (subCarry1Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node103 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 103 =
      flagSub op *
        (subCarry2Field row * (subCarry2Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node110 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 110 =
      flagSub op *
        (subCarry3Field row * (subCarry3Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node117 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 117 =
      flagSub op *
        (subCarry4Field row * (subCarry4Field row - 1)) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node119 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 119 =
      boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node121 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 121 =
      bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node123 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 123 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node125 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 125 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node127 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 127 =
      bitVecM31 row.rdNext.limb1 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb1 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node129 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 129 =
      bitVecM31 row.rdNext.limb2 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb2 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node131 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 131 =
      bitVecM31 row.rdNext.limb3 -
        boolM31 row.rdNonzero * bitVecM31 row.result.limb3 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node133 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 133 =
      bitVecM31 row.rs1Next.limb0 - bitVecM31 row.rs1Previous.limb0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node135 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 135 =
      bitVecM31 row.rs1Next.limb1 - bitVecM31 row.rs1Previous.limb1 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node137 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 137 =
      bitVecM31 row.rs1Next.limb2 - bitVecM31 row.rs1Previous.limb2 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node139 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 139 =
      bitVecM31 row.rs1Next.limb3 - bitVecM31 row.rs1Previous.limb3 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node141 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 141 =
      bitVecM31 row.rs2Next.limb0 - bitVecM31 row.rs2Previous.limb0 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node143 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 143 =
      bitVecM31 row.rs2Next.limb1 - bitVecM31 row.rs2Previous.limb1 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node145 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 145 =
      bitVecM31 row.rs2Next.limb2 - bitVecM31 row.rs2Previous.limb2 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node147 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 147 =
      bitVecM31 row.rs2Next.limb3 - bitVecM31 row.rs2Previous.limb3 := by
  cases op <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem node48 (op : Op) (row : Row) (witness : Witness row) :
    (evaluation op row witness).nodes.getSymbolic 48 = 0 := by
  cases op <;> reduce_base_alu_reg

def ArithmeticEquations (op : Op) (row : Row) : Prop :=
  match op with
  | .add =>
      addCarry1Field row * (addCarry1Field row - 1) = 0 ∧
      addCarry2Field row * (addCarry2Field row - 1) = 0 ∧
      addCarry3Field row * (addCarry3Field row - 1) = 0 ∧
      addCarry4Field row * (addCarry4Field row - 1) = 0
  | .sub =>
      subCarry1Field row * (subCarry1Field row - 1) = 0 ∧
      subCarry2Field row * (subCarry2Field row - 1) = 0 ∧
      subCarry3Field row * (subCarry3Field row - 1) = 0 ∧
      subCarry4Field row * (subCarry4Field row - 1) = 0
  | _ => True

def ConstraintEquations
    (op : Op)
    (row : Row)
    (witness : Witness row) : Prop :=
  ArithmeticEquations op row ∧
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
  bitVecM31 row.rs1Next.limb3 - bitVecM31 row.rs1Previous.limb3 = 0 ∧
  bitVecM31 row.rs2Next.limb0 - bitVecM31 row.rs2Previous.limb0 = 0 ∧
  bitVecM31 row.rs2Next.limb1 - bitVecM31 row.rs2Previous.limb1 = 0 ∧
  bitVecM31 row.rs2Next.limb2 - bitVecM31 row.rs2Previous.limb2 = 0 ∧
  bitVecM31 row.rs2Next.limb3 - bitVecM31 row.rs2Previous.limb3 = 0

set_option maxHeartbeats 0 in
theorem constraintsHold_iff
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).constraintsHold = true ↔
      ConstraintEquations op row witness := by
  rw [constraintsHold_eq]
  cases op <;> cases flag : row.rdNonzero <;>
    simp [
      ConstraintEquations,
      ArithmeticEquations,
      node49, node51, node53, node55, node57, node59,
      node68, node75, node82, node89,
      node96, node103, node110, node117,
      node119, node121, node123, node125, node127, node129, node131,
      node133, node135, node137, node139,
      node141, node143, node145, node147, node48,
      flag,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      flagAdd,
      flagSub,
      and_assoc,
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
  source1PreviousBound : row.rs1PreviousClock < 2 ^ 26
  source2PreviousBound : row.rs2PreviousClock < 2 ^ 26
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

theorem sourcesPreserved
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations op row witness) :
    row.rs1Next = row.rs1Previous ∧
      row.rs2Next = row.rs2Previous := by
  rcases equations with
    ⟨_, _, _, _, _, _, _, source10, source11, source12, source13,
      source20, source21, source22, source23⟩
  constructor <;> apply WordBytes.eq_of_limbs
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source10
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source11
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source12
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source13
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source20
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source21
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source22
  · apply fieldByteEq
    exact (M31.sub_eq_zero_iff _ _).mp source23

theorem destinationFlag
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations op row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) :=
  TeamACommon.destinationFlag_of_equations
    row.rd row.rdNonzero witness.destinationInverse
    equations.2.1 equations.2.2.1

theorem destinationBytes
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations op row witness) :
    row.rdNext =
      if row.rdNonzero then row.result else WordBytes.zero :=
  TeamACommon.destinationBytes_of_equations
    row.rdNext row.result row.rdNonzero
    equations.2.2.2.1
    equations.2.2.2.2.1
    equations.2.2.2.2.2.1
    equations.2.2.2.2.2.2.1

theorem destinationWord
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations op row witness) :
    row.rdNext.word = architecturalValue row.rd row.result.word := by
  have bytes := destinationBytes op row witness equations
  have flag := destinationFlag op row witness equations
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

theorem addCarryRecurrence
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations .add row witness) :
    ∃ carry1 carry2 carry3 carry4 : BitVec 1,
      row.rs1Next.limb0.toNat + row.rs2Next.limb0.toNat =
          row.result.limb0.toNat + 256 * carry1.toNat ∧
      row.rs1Next.limb1.toNat + row.rs2Next.limb1.toNat + carry1.toNat =
          row.result.limb1.toNat + 256 * carry2.toNat ∧
      row.rs1Next.limb2.toNat + row.rs2Next.limb2.toNat + carry2.toNat =
          row.result.limb2.toNat + 256 * carry3.toNat ∧
      row.rs1Next.limb3.toNat + row.rs2Next.limb3.toNat + carry3.toNat =
          row.result.limb3.toNat + 256 * carry4.toNat := by
  have source10 := row.rs1Next.limb0.isLt
  have source11 := row.rs1Next.limb1.isLt
  have source12 := row.rs1Next.limb2.isLt
  have source13 := row.rs1Next.limb3.isLt
  have source20 := row.rs2Next.limb0.isLt
  have source21 := row.rs2Next.limb1.isLt
  have source22 := row.rs2Next.limb2.isLt
  have source23 := row.rs2Next.limb3.isLt
  have result0 := row.result.limb0.isLt
  have result1 := row.result.limb1.isLt
  have result2 := row.result.limb2.isLt
  have result3 := row.result.limb3.isLt
  simp only [Nat.reducePow] at source10 source11 source12 source13
  simp only [Nat.reducePow] at source20 source21 source22 source23
  simp only [Nat.reducePow] at result0 result1 result2 result3
  obtain ⟨carry1, carry1Value, recurrence1⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb0.toNat row.rs2Next.limb0.toNat 0
      row.result.limb0.toNat (addCarry1Field row)
      source10 source20 (by decide) result0 (by rfl) equations.1.1
  have carry1Bound := carry1.isLt
  simp only [Nat.reducePow] at carry1Bound
  obtain ⟨carry2, carry2Value, recurrence2⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb1.toNat row.rs2Next.limb1.toNat carry1.toNat
      row.result.limb1.toNat (addCarry2Field row)
      source11 source21 carry1Bound result1
      (by rw [addCarry2Field, carry1Value]; rfl) equations.1.2.1
  have carry2Bound := carry2.isLt
  simp only [Nat.reducePow] at carry2Bound
  obtain ⟨carry3, carry3Value, recurrence3⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb2.toNat row.rs2Next.limb2.toNat carry2.toNat
      row.result.limb2.toNat (addCarry3Field row)
      source12 source22 carry2Bound result2
      (by rw [addCarry3Field, carry2Value]; rfl) equations.1.2.2.1
  have carry3Bound := carry3.isLt
  simp only [Nat.reducePow] at carry3Bound
  obtain ⟨carry4, _, recurrence4⟩ :=
    Addi.carryFieldClassified
      row.rs1Next.limb3.toNat row.rs2Next.limb3.toNat carry3.toNat
      row.result.limb3.toNat (addCarry4Field row)
      source13 source23 carry3Bound result3
      (by rw [addCarry4Field, carry3Value]; rfl) equations.1.2.2.2
  exact ⟨carry1, carry2, carry3, carry4,
    by simpa using recurrence1,
    by simpa [Nat.add_assoc] using recurrence2,
    by simpa [Nat.add_assoc] using recurrence3,
    by simpa [Nat.add_assoc] using recurrence4⟩

theorem subCarryRecurrence
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations .sub row witness) :
    ∃ carry1 carry2 carry3 carry4 : BitVec 1,
      row.result.limb0.toNat + row.rs2Next.limb0.toNat =
          row.rs1Next.limb0.toNat + 256 * carry1.toNat ∧
      row.result.limb1.toNat + row.rs2Next.limb1.toNat + carry1.toNat =
          row.rs1Next.limb1.toNat + 256 * carry2.toNat ∧
      row.result.limb2.toNat + row.rs2Next.limb2.toNat + carry2.toNat =
          row.rs1Next.limb2.toNat + 256 * carry3.toNat ∧
      row.result.limb3.toNat + row.rs2Next.limb3.toNat + carry3.toNat =
          row.rs1Next.limb3.toNat + 256 * carry4.toNat := by
  have result0 := row.result.limb0.isLt
  have result1 := row.result.limb1.isLt
  have result2 := row.result.limb2.isLt
  have result3 := row.result.limb3.isLt
  have source20 := row.rs2Next.limb0.isLt
  have source21 := row.rs2Next.limb1.isLt
  have source22 := row.rs2Next.limb2.isLt
  have source23 := row.rs2Next.limb3.isLt
  have source10 := row.rs1Next.limb0.isLt
  have source11 := row.rs1Next.limb1.isLt
  have source12 := row.rs1Next.limb2.isLt
  have source13 := row.rs1Next.limb3.isLt
  simp only [Nat.reducePow] at result0 result1 result2 result3
  simp only [Nat.reducePow] at source20 source21 source22 source23
  simp only [Nat.reducePow] at source10 source11 source12 source13
  obtain ⟨carry1, carry1Value, recurrence1⟩ :=
    Addi.carryFieldClassified
      row.result.limb0.toNat row.rs2Next.limb0.toNat 0
      row.rs1Next.limb0.toNat (subCarry1Field row)
      result0 source20 (by decide) source10 (by rfl) equations.1.1
  have carry1Bound := carry1.isLt
  simp only [Nat.reducePow] at carry1Bound
  obtain ⟨carry2, carry2Value, recurrence2⟩ :=
    Addi.carryFieldClassified
      row.result.limb1.toNat row.rs2Next.limb1.toNat carry1.toNat
      row.rs1Next.limb1.toNat (subCarry2Field row)
      result1 source21 carry1Bound source11
      (by rw [subCarry2Field, carry1Value]; rfl) equations.1.2.1
  have carry2Bound := carry2.isLt
  simp only [Nat.reducePow] at carry2Bound
  obtain ⟨carry3, carry3Value, recurrence3⟩ :=
    Addi.carryFieldClassified
      row.result.limb2.toNat row.rs2Next.limb2.toNat carry2.toNat
      row.rs1Next.limb2.toNat (subCarry3Field row)
      result2 source22 carry2Bound source12
      (by rw [subCarry3Field, carry2Value]; rfl) equations.1.2.2.1
  have carry3Bound := carry3.isLt
  simp only [Nat.reducePow] at carry3Bound
  obtain ⟨carry4, _, recurrence4⟩ :=
    Addi.carryFieldClassified
      row.result.limb3.toNat row.rs2Next.limb3.toNat carry3.toNat
      row.rs1Next.limb3.toNat (subCarry4Field row)
      result3 source23 carry3Bound source13
      (by rw [subCarry4Field, carry3Value]; rfl) equations.1.2.2.2
  exact ⟨carry1, carry2, carry3, carry4,
    by simpa using recurrence1,
    by simpa [Nat.add_assoc] using recurrence2,
    by simpa [Nat.add_assoc] using recurrence3,
    by simpa [Nat.add_assoc] using recurrence4⟩

theorem addResultWord
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations .add row witness) :
    row.result.word = row.rs1Next.word + row.rs2Next.word := by
  rcases addCarryRecurrence row witness equations with
    ⟨carry1, carry2, carry3, carry4, limb0, limb1, limb2, limb3⟩
  apply BitVec.eq_of_toNat_eq
  simp only [WordBytes.word_toNat, BitVec.toNat_add, Nat.reducePow]
  have total :
      row.rs1Next.value + row.rs2Next.value =
        row.result.value + 4294967296 * carry4.toNat := by
    simp only [WordBytes.value]
    omega
  rw [total]
  have resultBound := row.result.value_lt
  simp only [Nat.reducePow] at resultBound
  omega

theorem subResultWord
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations .sub row witness) :
    row.result.word = row.rs1Next.word - row.rs2Next.word := by
  apply BitVec.eq_sub_iff_add_eq.mpr
  rcases subCarryRecurrence row witness equations with
    ⟨carry1, carry2, carry3, carry4, limb0, limb1, limb2, limb3⟩
  apply BitVec.eq_of_toNat_eq
  simp only [WordBytes.word_toNat, BitVec.toNat_add, Nat.reducePow]
  have total :
      row.result.value + row.rs2Next.value =
        row.rs1Next.value + 4294967296 * carry4.toNat := by
    simp only [WordBytes.value]
    omega
  rw [total]
  have sourceBound := row.rs1Next.value_lt
  simp only [Nat.reducePow] at sourceBound
  omega

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
    ⟨_, _, _, _, _, _, _, _, _, lookup0, lookup1, lookup2, lookup3, _⟩
  exact ⟨
    fixedRequestOfLookup op row witness fixed 39 _ lookup0,
    fixedRequestOfLookup op row witness fixed 40 _ lookup1,
    fixedRequestOfLookup op row witness fixed 41 _ lookup2,
    fixedRequestOfLookup op row witness fixed 42 _ lookup3
  ⟩

def bitwiseByte (op : Op) (left right : Byte) : Byte :=
  match op with
  | .xor => left ^^^ right
  | .or => left ||| right
  | .and => left &&& right
  | _ => 0

def bitwiseBytes (op : Op) (left right : WordBytes) : WordBytes where
  limb0 := bitwiseByte op left.limb0 right.limb0
  limb1 := bitwiseByte op left.limb1 right.limb1
  limb2 := bitwiseByte op left.limb2 right.limb2
  limb3 := bitwiseByte op left.limb3 right.limb3

private theorem byteFieldVal (value : Byte) :
    (bitVecM31 value).val = value.toNat :=
  Lui.bitVecM31_val value (byteBound value)

private theorem bitwiseByte_of_request
    (op : Op)
    (bitwise : isBitwise op = true)
    (ordinal : Nat)
    (source1 source2 result : Byte)
    (request :
      (bitwiseLookupFields op ordinal
        (bitVecM31 source1) (bitVecM31 source2)
        (bitVecM31 result)).fixedRequestHolds = true) :
    result = bitwiseByte op source1 source2 := by
  have membership :
      FixedTableId.bitwise.contains
        [bitVecM31 source1, bitVecM31 source2, bitVecM31 result,
          M31.reduce (bitwiseOperationId op)] = true := by
    have nonzero : (-(1 : M31)) ≠ 0 := by decide
    cases op <;>
      simp [isBitwise] at bitwise
    all_goals
      simpa [
        bitwiseLookupFields,
        bitwiseFlag,
        flagXor,
        flagOr,
        flagAnd,
        EvaluatedLookup.fixedRequestHolds,
        EvaluatedLookup.isLive,
        EvaluatedLookup.fixedMembership,
        nonzero,
      ] using request
  apply BitVec.eq_of_toNat_eq
  cases op with
  | add => simp [isBitwise] at bitwise
  | sub => simp [isBitwise] at bitwise
  | xor =>
      have meaning :=
        (FixedTableId.bitwise_contains_xor_iff
          (bitVecM31 source1) (bitVecM31 source2) (bitVecM31 result)).mp
          (by simpa [bitwiseOperationId] using membership)
      simpa [bitwiseByte, M31.toNat, byteFieldVal] using meaning.2.2.symm
  | or =>
      have meaning :=
        (FixedTableId.bitwise_contains_or_iff
          (bitVecM31 source1) (bitVecM31 source2) (bitVecM31 result)).mp
          (by simpa [bitwiseOperationId] using membership)
      simpa [bitwiseByte, M31.toNat, byteFieldVal] using meaning.2.2.symm
  | and =>
      have meaning :=
        (FixedTableId.bitwise_contains_and_iff
          (bitVecM31 source1) (bitVecM31 source2) (bitVecM31 result)).mp
          (by simpa [bitwiseOperationId] using membership)
      simpa [bitwiseByte, M31.toNat, byteFieldVal] using meaning.2.2.symm

theorem bitwiseResultBytes
    (op : Op)
    (bitwise : isBitwise op = true)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    row.result = bitwiseBytes op row.rs1Next row.rs2Next := by
  rcases bitwiseRequestsHold op row witness fixed with
    ⟨request0, request1, request2, request3⟩
  apply WordBytes.eq_of_limbs
  · exact bitwiseByte_of_request op bitwise 39
      row.rs1Next.limb0 row.rs2Next.limb0 row.result.limb0 request0
  · exact bitwiseByte_of_request op bitwise 40
      row.rs1Next.limb1 row.rs2Next.limb1 row.result.limb1 request1
  · exact bitwiseByte_of_request op bitwise 41
      row.rs1Next.limb2 row.rs2Next.limb2 row.result.limb2 request2
  · exact bitwiseByte_of_request op bitwise 42
      row.rs1Next.limb3 row.rs2Next.limb3 row.result.limb3 request3

theorem bitwiseBytesWord
    (op : Op)
    (bitwise : isBitwise op = true)
    (left right : WordBytes) :
    (bitwiseBytes op left right).word =
      match op with
      | .xor => left.word ^^^ right.word
      | .or => left.word ||| right.word
      | .and => left.word &&& right.word
      | _ => 0 := by
  cases op <;> simp [isBitwise] at bitwise
  · simp only [bitwiseBytes, bitwiseByte, WordBytes.word_append,
      BitVec.append_eq]
    rw [BitVec.xor_append, BitVec.xor_append, BitVec.xor_append]
  · simp only [bitwiseBytes, bitwiseByte, WordBytes.word_append,
      BitVec.append_eq]
    rw [BitVec.or_append, BitVec.or_append, BitVec.or_append]
  · simp only [bitwiseBytes, bitwiseByte, WordBytes.word_append,
      BitVec.append_eq]
    rw [BitVec.and_append, BitVec.and_append, BitVec.and_append]

def executeValue (op : Op) (left right : Word) : Word :=
  match op with
  | .add => left + right
  | .sub => left - right
  | .xor => left ^^^ right
  | .or => left ||| right
  | .and => left &&& right

theorem resultWord
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (equations : ConstraintEquations op row witness)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    row.result.word =
      executeValue op row.rs1Next.word row.rs2Next.word := by
  cases op with
  | add => simpa [executeValue] using addResultWord row witness equations
  | sub => simpa [executeValue] using subResultWord row witness equations
  | xor =>
      rw [bitwiseResultBytes .xor (by rfl) row witness fixed,
        bitwiseBytesWord .xor (by rfl)]
      rfl
  | or =>
      rw [bitwiseResultBytes .or (by rfl) row witness fixed,
        bitwiseBytesWord .or (by rfl)]
      rfl
  | and =>
      rw [bitwiseResultBytes .and (by rfl) row witness fixed,
        bitwiseBytesWord .and (by rfl)]
      rfl

theorem source1ClockGapBound
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    (clockGapField row 1 row.rs1PreviousClock).val < 2 ^ 20 := by
  rcases lookupProjection op row witness with
    ⟨_, _, _, _, _, projection, _⟩
  have request :=
    fixedRequestOfLookup op row witness fixed 35 _ projection
  exact
    (TeamACommon.rangeCheck20RequestHolds_iff
      35 (some 1) (clockGapField row 1 row.rs1PreviousClock)).mp request

theorem source2ClockGapBound
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    (clockGapField row 2 row.rs2PreviousClock).val < 2 ^ 20 := by
  rcases lookupProjection op row witness with
    ⟨_, _, _, _, _, _, _, _, projection, _⟩
  have request :=
    fixedRequestOfLookup op row witness fixed 38 _ projection
  exact
    (TeamACommon.rangeCheck20RequestHolds_iff
      38 (some 2) (clockGapField row 2 row.rs2PreviousClock)).mp request

theorem destinationClockGapBound
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    (clockGapField row 3 row.rdPreviousClock).val < 2 ^ 20 := by
  rcases lookupProjection op row witness with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, projection⟩
  have request :=
    fixedRequestOfLookup op row witness fixed 47 _ projection
  exact
    (TeamACommon.rangeCheck20RequestHolds_iff
      47 (some 3) (clockGapField row 3 row.rdPreviousClock)).mp request

private theorem accessClockBound
    (row : Row)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 3) :
    accessClock row.clock ordinal < 2 ^ 26 := by
  simp only [accessClock]
  have clockBound := admission.clockBound
  omega

private theorem accessClockField_eq
    (row : Row)
    (admission : Admission row)
    (ordinal : Nat)
    (ordinalBound : ordinal ≤ 3) :
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

theorem source1Clock
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
  · exact admission.source1PreviousBound
  · have gap := source1ClockGapBound op row witness fixed
    have accessEq := accessClockField_eq row admission 1 (by decide)
    unfold accessClockField at accessEq
    rw [clockGapField, TeamACommon.clockGapField, accessEq] at gap
    exact gap

theorem source2Clock
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2) := by
  apply TeamACommon.validPreviousClock_of_gap
  · simp only [accessClock]
    have positive := admission.clockPositive
    omega
  · exact accessClockBound row admission 2 (by decide)
  · exact admission.source2PreviousBound
  · have gap := source2ClockGapBound op row witness fixed
    have accessEq := accessClockField_eq row admission 2 (by decide)
    unfold accessClockField at accessEq
    rw [clockGapField, TeamACommon.clockGapField, accessEq] at gap
    exact gap

theorem destinationClock
    (op : Op)
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (fixed : (evaluation op row witness).fixedLookupsHold = true) :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3) := by
  apply TeamACommon.validPreviousClock_of_gap
  · simp only [accessClock]
    have positive := admission.clockPositive
    omega
  · exact accessClockBound row admission 3 (by decide)
  · exact admission.destinationPreviousBound
  · have gap := destinationClockGapBound op row witness fixed
    have accessEq := accessClockField_eq row admission 3 (by decide)
    unfold accessClockField at accessEq
    rw [clockGapField, TeamACommon.clockGapField, accessEq] at gap
    exact gap

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
    (evaluation op row witness).lookup? 30 = some (programLookup op row)
  stateConsume :
    (evaluation op row witness).lookup? 31 = some (stateConsumeLookup row)
  stateEmit :
    (evaluation op row witness).lookup? 32 = some (stateEmitLookup row)
  source1Consume :
    (evaluation op row witness).lookup? 33 = some (source1ConsumeLookup row)
  source1Emit :
    (evaluation op row witness).lookup? 34 = some (source1EmitLookup row)
  source1ClockLookup :
    (evaluation op row witness).lookup? 35 = some (source1ClockLookup row)
  source2Consume :
    (evaluation op row witness).lookup? 36 = some (source2ConsumeLookup row)
  source2Emit :
    (evaluation op row witness).lookup? 37 = some (source2EmitLookup row)
  source2ClockLookup :
    (evaluation op row witness).lookup? 38 = some (source2ClockLookup row)
  bitwise0 :
    (evaluation op row witness).lookup? 39 = some (bitwiseLookup0 op row)
  bitwise1 :
    (evaluation op row witness).lookup? 40 = some (bitwiseLookup1 op row)
  bitwise2 :
    (evaluation op row witness).lookup? 41 = some (bitwiseLookup2 op row)
  bitwise3 :
    (evaluation op row witness).lookup? 42 = some (bitwiseLookup3 op row)
  resultLow :
    (evaluation op row witness).lookup? 43 = some (resultLowLookup row)
  resultHigh :
    (evaluation op row witness).lookup? 44 = some (resultHighLookup row)
  destinationConsume :
    (evaluation op row witness).lookup? 45 =
      some (destinationConsumeLookup row)
  destinationEmit :
    (evaluation op row witness).lookup? 46 =
      some (destinationEmitLookup row)
  destinationClockLookup :
    (evaluation op row witness).lookup? 47 =
      some (destinationClockLookup row)
  source1Value : row.rs1Next = row.rs1Previous
  source2Value : row.rs2Next = row.rs2Previous
  source1Clock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  source2Clock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  resultValue :
    row.result.word =
      executeValue op row.rs1Previous.word row.rs2Previous.word
  destinationValue :
    row.rdNext.word = architecturalValue row.rd row.result.word
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
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
  have sources := sourcesPreserved op row witness equations
  rcases lookupProjection op row witness with
    ⟨programProjection, stateConsumeProjection, stateEmitProjection,
      source1ConsumeProjection, source1EmitProjection, source1ClockProjection,
      source2ConsumeProjection, source2EmitProjection, source2ClockProjection,
      bitwise0Projection, bitwise1Projection, bitwise2Projection,
      bitwise3Projection, resultLowProjection, resultHighProjection,
      destinationConsumeProjection, destinationEmitProjection,
      destinationClockProjection⟩
  refine {
    selectors := accepted.selectors
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    program := programProjection
    stateConsume := stateConsumeProjection
    stateEmit := stateEmitProjection
    source1Consume := source1ConsumeProjection
    source1Emit := source1EmitProjection
    source1ClockLookup := source1ClockProjection
    source2Consume := source2ConsumeProjection
    source2Emit := source2EmitProjection
    source2ClockLookup := source2ClockProjection
    bitwise0 := bitwise0Projection
    bitwise1 := bitwise1Projection
    bitwise2 := bitwise2Projection
    bitwise3 := bitwise3Projection
    resultLow := resultLowProjection
    resultHigh := resultHighProjection
    destinationConsume := destinationConsumeProjection
    destinationEmit := destinationEmitProjection
    destinationClockLookup := destinationClockProjection
    source1Value := sources.1
    source2Value := sources.2
    source1Clock :=
      source1Clock op row witness admission accepted.fixedLookups
    source2Clock :=
      source2Clock op row witness admission accepted.fixedLookups
    resultValue := ?_
    destinationValue := destinationWord op row witness equations
    destinationClock :=
      destinationClock op row witness admission accepted.fixedLookups
    nextPc := ?_
    nextClock := ?_
  }
  · have result :=
      resultWord op row witness equations accepted.fixedLookups
    rw [sources.1, sources.2] at result
    exact result
  · simp [stateEmitLookup,
      TeamACommon.nextPcField row.pc admission.pcBound]
  · apply congrArg some
    simp only [stateEmitLookup]
    apply TeamACommon.nextClockField
    have bound := admission.clockBound
    simp [M31.modulus_eq] at *
    omega

private def source1ClockLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 35
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 162
  tuple := #[nodes.getSymbolic 157]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

private def source2ClockLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 38
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 162
  tuple := #[nodes.getSymbolic 161]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

private def bitwiseLookup0At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 39
  domain := .bitwise
  numerator := nodes.getSymbolic 181
  tuple := #[
    nodes.getSymbolic 18, nodes.getSymbolic 28,
    nodes.getSymbolic 37, nodes.getSymbolic 180
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup1At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 40
  domain := .bitwise
  numerator := nodes.getSymbolic 181
  tuple := #[
    nodes.getSymbolic 19, nodes.getSymbolic 29,
    nodes.getSymbolic 38, nodes.getSymbolic 180
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup2At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 41
  domain := .bitwise
  numerator := nodes.getSymbolic 181
  tuple := #[
    nodes.getSymbolic 20, nodes.getSymbolic 30,
    nodes.getSymbolic 39, nodes.getSymbolic 180
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def bitwiseLookup3At (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 42
  domain := .bitwise
  numerator := nodes.getSymbolic 181
  tuple := #[
    nodes.getSymbolic 21, nodes.getSymbolic 31,
    nodes.getSymbolic 40, nodes.getSymbolic 180
  ]
  role := .request
  tableId := some .bitwise
  accessOrdinal := none

private def resultLowLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 43
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 162
  tuple := #[nodes.getSymbolic 37, nodes.getSymbolic 38]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def resultHighLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 44
  domain := .rangeCheck88
  numerator := nodes.getSymbolic 162
  tuple := #[nodes.getSymbolic 39, nodes.getSymbolic 40]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def destinationClockLookupAt (nodes : LocalValues) : EvaluatedLookup where
  ordinal := 47
  domain := .rangeCheck20
  numerator := nodes.getSymbolic 162
  tuple := #[nodes.getSymbolic 154]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 3

set_option maxRecDepth 30000 in
private theorem fixedLookupsHoldEvents
    (op : Op)
    (nodes : LocalValues) :
    ((program op).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint _ => true
          | .lookup event => event.fixedRequestHolds) =
      ((source1ClockLookupAt nodes).fixedRequestHolds &&
        ((source2ClockLookupAt nodes).fixedRequestHolds &&
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
      Programs.add,
      Programs.addSource,
      Programs.sub,
      Programs.subSource,
      Programs.xor,
      Programs.xorSource,
      Programs.or,
      Programs.orSource,
      Programs.and,
      Programs.andSource,
      Event.evalSymbolic,
      source1ClockLookupAt,
      source2ClockLookupAt,
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
private theorem source1ClockLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    source1ClockLookupAt (evaluation op row witness).nodes =
      source1ClockLookup row := by
  cases op <;> simp only [evaluation] <;>
    unfold source1ClockLookupAt <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem source2ClockLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    source2ClockLookupAt (evaluation op row witness).nodes =
      source2ClockLookup row := by
  cases op <;> simp only [evaluation] <;>
    unfold source2ClockLookupAt <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem bitwiseLookup0At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup0At (evaluation op row witness).nodes =
      bitwiseLookup0 op row := by
  cases op <;> simp only [evaluation] <;>
    unfold bitwiseLookup0At <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem bitwiseLookup1At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup1At (evaluation op row witness).nodes =
      bitwiseLookup1 op row := by
  cases op <;> simp only [evaluation] <;>
    unfold bitwiseLookup1At <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem bitwiseLookup2At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup2At (evaluation op row witness).nodes =
      bitwiseLookup2 op row := by
  cases op <;> simp only [evaluation] <;>
    unfold bitwiseLookup2At <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem bitwiseLookup3At_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    bitwiseLookup3At (evaluation op row witness).nodes =
      bitwiseLookup3 op row := by
  cases op <;> simp only [evaluation] <;>
    unfold bitwiseLookup3At <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem resultLowLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    resultLowLookupAt (evaluation op row witness).nodes =
      resultLowLookup row := by
  cases op <;> simp only [evaluation] <;>
    unfold resultLowLookupAt <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem resultHighLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    resultHighLookupAt (evaluation op row witness).nodes =
      resultHighLookup row := by
  cases op <;> simp only [evaluation] <;>
    unfold resultHighLookupAt <;> reduce_base_alu_reg

set_option maxRecDepth 30000 in
private theorem destinationClockLookupAt_evaluation
    (op : Op) (row : Row) (witness : Witness row) :
    destinationClockLookupAt (evaluation op row witness).nodes =
      destinationClockLookup row := by
  cases op <;> simp only [evaluation] <;>
    unfold destinationClockLookupAt <;> reduce_base_alu_reg

theorem fixedLookupsHold_eq
    (op : Op)
    (row : Row)
    (witness : Witness row) :
    (evaluation op row witness).fixedLookupsHold =
      ((source1ClockLookup row).fixedRequestHolds &&
        ((source2ClockLookup row).fixedRequestHolds &&
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
      ((source1ClockLookup row).fixedRequestHolds &&
        ((source2ClockLookup row).fixedRequestHolds &&
          ((bitwiseLookup0 op row).fixedRequestHolds &&
            ((bitwiseLookup1 op row).fixedRequestHolds &&
              ((bitwiseLookup2 op row).fixedRequestHolds &&
                ((bitwiseLookup3 op row).fixedRequestHolds &&
                  ((resultLowLookup row).fixedRequestHolds &&
                    ((resultHighLookup row).fixedRequestHolds &&
                      (destinationClockLookup row).fixedRequestHolds))))))))
  rw [fixedLookupsHoldEvents]
  rw [
    source1ClockLookupAt_evaluation,
    source2ClockLookupAt_evaluation,
    bitwiseLookup0At_evaluation,
    bitwiseLookup1At_evaluation,
    bitwiseLookup2At_evaluation,
    bitwiseLookup3At_evaluation,
    resultLowLookupAt_evaluation,
    resultHighLookupAt_evaluation,
    destinationClockLookupAt_evaluation,
  ]

def zeroRow
    (zeroDestination : Bool)
    (rs1 rs2 : RegisterIndex) : Row where
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
  rs2 := rs2
  rs2PreviousClock := 0
  rs2Previous := WordBytes.zero
  rs2Next := WordBytes.zero
  result := WordBytes.zero
  rdNonzero := !zeroDestination

def zeroWitness
    (zeroDestination : Bool)
    (rs1 rs2 : RegisterIndex) :
    Witness (zeroRow zeroDestination rs1 rs2) where
  destinationInverse := if zeroDestination then 0 else 1

theorem zeroAdmission
    (zeroDestination : Bool)
    (rs1 rs2 : RegisterIndex) :
    Admission (zeroRow zeroDestination rs1 rs2) := by
  constructor <;> simp [zeroRow, M31.modulus_eq]

set_option maxHeartbeats 0 in
theorem zeroAcceptance
    (op : Op)
    (zeroDestination : Bool)
    (rs1 rs2 : RegisterIndex) :
    Acceptance op
      (zeroRow zeroDestination rs1 rs2)
      (zeroWitness zeroDestination rs1 rs2) := by
  refine {
    selectors :=
      selectorAccepted op
        (zeroRow zeroDestination rs1 rs2)
        (zeroWitness zeroDestination rs1 rs2)
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff op _ _).mpr
    cases zeroDestination <;> cases op <;>
      simp [
        ConstraintEquations,
        ArithmeticEquations,
        addCarry1Field,
        addCarry2Field,
        addCarry3Field,
        addCarry4Field,
        subCarry1Field,
        subCarry2Field,
        subCarry3Field,
        subCarry4Field,
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
        source1ClockLookup,
        source2ClockLookup,
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
        clockGapField,
        TeamACommon.clockGapField,
        TeamACommon.accessClockField,
        bitwiseFlag,
        flagXor,
        flagOr,
        flagAnd,
        bitwiseOperationId,
        zeroRow,
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
  exact ⟨
    zeroRow false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3),
    zeroWitness false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3),
    zeroAdmission false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3),
    zeroAcceptance op false (BitVec.ofNat 5 2) (BitVec.ofNat 5 3)
  ⟩

theorem zeroDestinationNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧ Acceptance op row witness ∧ row.rd = zeroRegister := by
  exact ⟨
    zeroRow true (BitVec.ofNat 5 2) (BitVec.ofNat 5 3),
    zeroWitness true (BitVec.ofNat 5 2) (BitVec.ofNat 5 3),
    zeroAdmission true (BitVec.ofNat 5 2) (BitVec.ofNat 5 3),
    zeroAcceptance op true (BitVec.ofNat 5 2) (BitVec.ofNat 5 3),
    by rfl
  ⟩

theorem source1AliasNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧ Acceptance op row witness ∧ row.rd = row.rs1 := by
  exact ⟨
    zeroRow false (BitVec.ofNat 5 1) (BitVec.ofNat 5 2),
    zeroWitness false (BitVec.ofNat 5 1) (BitVec.ofNat 5 2),
    zeroAdmission false (BitVec.ofNat 5 1) (BitVec.ofNat 5 2),
    zeroAcceptance op false (BitVec.ofNat 5 1) (BitVec.ofNat 5 2),
    by rfl
  ⟩

theorem source2AliasNonvacuous (op : Op) :
    ∃ (row : Row) (witness : Witness row),
      Admission row ∧ Acceptance op row witness ∧ row.rd = row.rs2 := by
  exact ⟨
    zeroRow false (BitVec.ofNat 5 2) (BitVec.ofNat 5 1),
    zeroWitness false (BitVec.ofNat 5 2) (BitVec.ofNat 5 1),
    zeroAdmission false (BitVec.ofNat 5 2) (BitVec.ofNat 5 1),
    zeroAcceptance op false (BitVec.ofNat 5 2) (BitVec.ofNat 5 1),
    by rfl
  ⟩

def maxWordBytes : WordBytes where
  limb0 := BitVec.ofNat 8 255
  limb1 := BitVec.ofNat 8 255
  limb2 := BitVec.ofNat 8 255
  limb3 := BitVec.ofNat 8 255

def oneWordBytes : WordBytes where
  limb0 := BitVec.ofNat 8 1
  limb1 := BitVec.ofNat 8 0
  limb2 := BitVec.ofNat 8 0
  limb3 := BitVec.ofNat 8 0

def addOverflowRow : Row where
  clock := 1
  pc := BitVec.ofNat 32 0x1000
  rd := BitVec.ofNat 5 1
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := WordBytes.zero
  rs1 := BitVec.ofNat 5 2
  rs1PreviousClock := 0
  rs1Previous := maxWordBytes
  rs1Next := maxWordBytes
  rs2 := BitVec.ofNat 5 3
  rs2PreviousClock := 0
  rs2Previous := oneWordBytes
  rs2Next := oneWordBytes
  result := WordBytes.zero
  rdNonzero := true

def addOverflowWitness : Witness addOverflowRow where
  destinationInverse := 1

theorem addOverflowAdmission : Admission addOverflowRow := by
  constructor <;> decide

set_option maxRecDepth 30000 in
theorem addOverflowAcceptance :
    Acceptance .add addOverflowRow addOverflowWitness := by
  refine {
    selectors := selectorAccepted .add addOverflowRow addOverflowWitness
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff .add _ _).mpr
    simp [
      ConstraintEquations,
      ArithmeticEquations,
      addCarry1Field,
      addCarry2Field,
      addCarry3Field,
      addCarry4Field,
      addOverflowRow,
      addOverflowWitness,
      maxWordBytes,
      oneWordBytes,
      WordBytes.zero,
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
    ] <;> decide
  · rw [fixedLookupsHold_eq]
    simp [
      source1ClockLookup,
      source2ClockLookup,
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
      clockGapField,
      TeamACommon.clockGapField,
      TeamACommon.accessClockField,
      bitwiseFlag,
      flagXor,
      flagOr,
      flagAnd,
      addOverflowRow,
      maxWordBytes,
      oneWordBytes,
      WordBytes.zero,
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      M31.toNat,
      M31.reduce_val,
      M31.modulus_eq,
    ] <;> decide

theorem addOverflowNonvacuous :
    Admission addOverflowRow ∧
      Acceptance .add addOverflowRow addOverflowWitness ∧
      addOverflowRow.rs1Previous.word +
          addOverflowRow.rs2Previous.word = 0 := by
  exact ⟨addOverflowAdmission, addOverflowAcceptance, by decide⟩

def subBorrowRow : Row where
  clock := 1
  pc := BitVec.ofNat 32 0x1000
  rd := BitVec.ofNat 5 1
  rdPreviousClock := 0
  rdPrevious := WordBytes.zero
  rdNext := maxWordBytes
  rs1 := BitVec.ofNat 5 2
  rs1PreviousClock := 0
  rs1Previous := WordBytes.zero
  rs1Next := WordBytes.zero
  rs2 := BitVec.ofNat 5 3
  rs2PreviousClock := 0
  rs2Previous := oneWordBytes
  rs2Next := oneWordBytes
  result := maxWordBytes
  rdNonzero := true

def subBorrowWitness : Witness subBorrowRow where
  destinationInverse := 1

theorem subBorrowAdmission : Admission subBorrowRow := by
  constructor <;> decide

set_option maxRecDepth 30000 in
theorem subBorrowAcceptance :
    Acceptance .sub subBorrowRow subBorrowWitness := by
  refine {
    selectors := selectorAccepted .sub subBorrowRow subBorrowWitness
    constraints := ?_
    fixedLookups := ?_
  }
  · apply (constraintsHold_iff .sub _ _).mpr
    simp [
      ConstraintEquations,
      ArithmeticEquations,
      subCarry1Field,
      subCarry2Field,
      subCarry3Field,
      subCarry4Field,
      subBorrowRow,
      subBorrowWitness,
      maxWordBytes,
      oneWordBytes,
      WordBytes.zero,
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
    ] <;> decide
  · rw [fixedLookupsHold_eq]
    simp [
      source1ClockLookup,
      source2ClockLookup,
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
      clockGapField,
      TeamACommon.clockGapField,
      TeamACommon.accessClockField,
      bitwiseFlag,
      flagXor,
      flagOr,
      flagAnd,
      subBorrowRow,
      maxWordBytes,
      oneWordBytes,
      WordBytes.zero,
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      M31.toNat,
      M31.reduce_val,
      M31.modulus_eq,
    ] <;> decide

theorem subBorrowNonvacuous :
    Admission subBorrowRow ∧
      Acceptance .sub subBorrowRow subBorrowWitness ∧
      subBorrowRow.rs1Previous.word -
          subBorrowRow.rs2Previous.word = BitVec.ofNat 32 0xffffffff := by
  exact ⟨subBorrowAdmission, subBorrowAcceptance, by decide⟩

end RiscvRefinement.Air.Bridge.BaseAluReg
