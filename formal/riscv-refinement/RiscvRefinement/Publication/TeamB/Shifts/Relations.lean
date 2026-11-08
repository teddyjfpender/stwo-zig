import RiscvRefinement.Publication.TeamB.Shifts.Acceptance

/-! Bounded shift publication proof owner: Relations. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

def programRelationLookup
    (ordinal manifestId : Nat)
    (pc : Word)
    (rd rs1 operand : RegisterIndex) :
    EvaluatedLookup where
  ordinal
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 pc,
    M31.reduce manifestId,
    bitVecM31 rd,
    bitVecM31 rs1,
    bitVecM31 operand
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def immediateProgramRelationLookup
    (ordinal manifestId : Nat)
    (row : ShiftsImmRow) :
    EvaluatedLookup where
  ordinal
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce manifestId,
    bitVecM31 row.semantic.rd,
    bitVecM31 row.rs1,
    M31.reduce row.immTruncated
  ]
  role := .request
  tableId := none
  accessOrdinal := none

private def stateRelationLookup
    (ordinal : Nat)
    (role : LookupRole)
    (numerator pc clock : M31) :
    EvaluatedLookup where
  ordinal
  domain := .registersState
  numerator
  tuple := #[pc, clock]
  role
  tableId := none
  accessOrdinal := none

private def registerRelationLookup
    (ordinal accessOrdinal : Nat)
    (role : LookupRole)
    (numerator : M31)
    (addr : RegisterIndex)
    (clock : M31)
    (value : WordBytes) :
    EvaluatedLookup where
  ordinal
  domain := .memoryAccess
  numerator
  tuple := #[
    0,
    bitVecM31 addr,
    clock,
    bitVecM31 value.limb0,
    bitVecM31 value.limb1,
    bitVecM31 value.limb2,
    bitVecM31 value.limb3
  ]
  role
  tableId := none
  accessOrdinal := some accessOrdinal

structure ImmExactRelationProjection
    (row : ShiftsImmRow) (witness : ImmWitness row) : Prop where
  program :
    (immEvaluation row witness).lookup? 67 =
      some
        (immediateProgramRelationLookup 67
          (shiftsImmOpcodeId row.semantic.kind) row)
  stateConsume :
    (immEvaluation row witness).lookup? 68 =
      some
        (stateRelationLookup 68 .consume (-(1 : M31))
          (bitVecM31 row.pc) (M31.reduce row.clock))
  stateEmit :
    (immEvaluation row witness).lookup? 69 =
      some
        (stateRelationLookup 69 .emit 1
          (bitVecM31 row.pc + M31.reduce 4)
          (M31.reduce row.clock + 1))
  sourceConsume :
    (immEvaluation row witness).lookup? 70 =
      some
        (registerRelationLookup 70 1 .consume (-(1 : M31))
          row.rs1 (M31.reduce row.rs1PreviousClock)
          row.semantic.rs1Previous)
  sourceEmit :
    (immEvaluation row witness).lookup? 71 =
      some
        (registerRelationLookup 71 1 .emit 1
          row.rs1 (accessClockField row.clock 1)
          row.semantic.rs1Next)
  destinationConsume :
    (immEvaluation row witness).lookup? 79 =
      some
        (registerRelationLookup 79 2 .consume (-(1 : M31))
          row.semantic.rd (M31.reduce row.rdPreviousClock)
          row.semantic.rdPrevious)
  destinationEmit :
    (immEvaluation row witness).lookup? 80 =
      some
        (registerRelationLookup 80 2 .emit 1
          row.semantic.rd (accessClockField row.clock 2)
          row.semantic.rdNext)

structure RegExactRelationProjection
    (row : ShiftsRegRow) (witness : RegWitness row) : Prop where
  program :
    (regEvaluation row witness).lookup? 70 =
      some
        (programRelationLookup 70
          (shiftsRegOpcodeId row.semantic.kind)
          row.pc row.semantic.rd row.rs1 row.rs2)
  stateConsume :
    (regEvaluation row witness).lookup? 71 =
      some
        (stateRelationLookup 71 .consume (-(1 : M31))
          (bitVecM31 row.pc) (M31.reduce row.clock))
  stateEmit :
    (regEvaluation row witness).lookup? 72 =
      some
        (stateRelationLookup 72 .emit 1
          (bitVecM31 row.pc + M31.reduce 4)
          (M31.reduce row.clock + 1))
  sourceConsume :
    (regEvaluation row witness).lookup? 73 =
      some
        (registerRelationLookup 73 1 .consume (-(1 : M31))
          row.rs1 (M31.reduce row.rs1PreviousClock)
          row.semantic.rs1Previous)
  sourceEmit :
    (regEvaluation row witness).lookup? 74 =
      some
        (registerRelationLookup 74 1 .emit 1
          row.rs1 (accessClockField row.clock 1)
          row.semantic.rs1Next)
  secondSourceConsume :
    (regEvaluation row witness).lookup? 76 =
      some
        (registerRelationLookup 76 2 .consume (-(1 : M31))
          row.rs2 (M31.reduce row.rs2PreviousClock)
          row.rs2Previous)
  secondSourceEmit :
    (regEvaluation row witness).lookup? 77 =
      some
        (registerRelationLookup 77 2 .emit 1
          row.rs2 (accessClockField row.clock 2)
          row.rs2Next)
  destinationConsume :
    (regEvaluation row witness).lookup? 86 =
      some
        (registerRelationLookup 86 3 .consume (-(1 : M31))
          row.semantic.rd (M31.reduce row.rdPreviousClock)
          row.semantic.rdPrevious)
  destinationEmit :
    (regEvaluation row witness).lookup? 87 =
      some
        (registerRelationLookup 87 3 .emit 1
          row.semantic.rd (accessClockField row.clock 3)
          row.semantic.rdNext)

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem imm_exactRelationProjection
    (row : ShiftsImmRow)
    (witness : ImmWitness row) :
    ImmExactRelationProjection row witness := by
  refine {
    program := ?_
    stateConsume := ?_
    stateEmit := ?_
    sourceConsume := ?_
    sourceEmit := ?_
    destinationConsume := ?_
    destinationEmit := ?_
  } <;>
  cases kind : row.semantic.kind <;>
  simp [
    immEvaluation, immProgram, kind,
    Programs.slli, Programs.srli, Programs.srai,
    Programs.slliSource, Programs.srliSource, Programs.sraiSource,
    LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic,
    SymbolicEvaluation.lookup?, Event.evalSymbolic,
    EvaluatedEvent.lookup?, immColumns, kindIs, boolM31,
    immediateProgramRelationLookup, stateRelationLookup,
    registerRelationLookup, shiftsImmOpcodeId,
    accessClockField,
  ]

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem reg_exactRelationProjection
    (row : ShiftsRegRow)
    (witness : RegWitness row) :
    RegExactRelationProjection row witness := by
  refine {
    program := ?_
    stateConsume := ?_
    stateEmit := ?_
    sourceConsume := ?_
    sourceEmit := ?_
    secondSourceConsume := ?_
    secondSourceEmit := ?_
    destinationConsume := ?_
    destinationEmit := ?_
  } <;>
  cases kind : row.semantic.kind <;>
  simp [
    regEvaluation, regProgram, kind,
    Programs.sll, Programs.srl, Programs.sra,
    Programs.sllSource, Programs.srlSource, Programs.sraSource,
    LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic,
    SymbolicEvaluation.lookup?, Event.evalSymbolic,
    EvaluatedEvent.lookup?, regColumns, kindIs, boolM31,
    programRelationLookup, stateRelationLookup,
    registerRelationLookup, shiftsRegOpcodeId,
    accessClockField,
  ]

end RiscvRefinement.Publication.TeamB.Shifts
