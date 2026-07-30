import RiscvRefinement.Air.Bridge.Lui
import RiscvRefinement.Air.Generated.Programs

/-!
# Production FENCE AIR bridge

The theorem-facing row below is projected into the exact six columns of the
generated production `fence` program. No constraint, lookup, or event ordinal
is supplied as a parallel premise.
-/

namespace RiscvRefinement.Air.Bridge.Fence

open RiscvRefinement
open RiscvRefinement.Air.Generated

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  Lui.bitVecM31 value

structure Row where
  clock : Nat
  pc : Word
  rd : RegisterIndex
  rs1 : RegisterIndex
  immediate : BitVec 12
deriving DecidableEq, Repr

def columns (row : Row) : Nat → M31
  | 0 => 1
  | 1 => M31.reduce row.clock
  | 2 => bitVecM31 row.pc
  | 3 => bitVecM31 row.rd
  | 4 => bitVecM31 row.rs1
  | 5 => bitVecM31 row.immediate
  | _ => 0

def evaluation (row : Row) : SymbolicEvaluation :=
  Programs.fence.evalSymbolic (columns row)

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 2
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce 45,
    bitVecM31 row.rd,
    bitVecM31 row.rs1,
    bitVecM31 row.immediate
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 3
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 4
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc + M31.reduce 4,
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

macro "reduce_fence" : tactic =>
  `(tactic|
    (simp only [
      evaluation,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.fence,
      Programs.fenceSource,
      LocalExprNode.evalAllSymbolic,
      LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic,
      newestValueSymbolic,
      List.length_cons,
      List.length_nil,
      List.map_toArray,
      Array.map_push,
      Array.map_empty,
      columns,
      programLookup,
      stateConsumeLookup,
      stateEmitLookup,
      SymbolicEvaluation.activeSelectorsAccepted,
      SymbolicEvaluation.constraintsHold,
      SymbolicEvaluation.fixedLookupsHold,
      M31.ofNat?,
      EvaluatedLookup.fixedRequestHolds,
      EvaluatedLookup.fixedMembership,
      EvaluatedLookup.isLive
    ] <;>
      simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?,
        M31.modulus_eq
      ]))

set_option maxRecDepth 20000 in
theorem selectorAccepted (row : Row) :
    (evaluation row).activeSelectorsAccepted = true := by
  reduce_fence
  apply M31.ext
  rfl

set_option maxRecDepth 20000 in
theorem constraintsHold (row : Row) :
    (evaluation row).constraintsHold = true := by
  reduce_fence

set_option maxRecDepth 20000 in
theorem fixedLookupsHold (row : Row) :
    (evaluation row).fixedLookupsHold = true := by
  reduce_fence

set_option maxRecDepth 20000 in
theorem lookupProjection (row : Row) :
    (evaluation row).lookup? 2 = some (programLookup row) ∧
      (evaluation row).lookup? 3 = some (stateConsumeLookup row) ∧
      (evaluation row).lookup? 4 = some (stateEmitLookup row) := by
  constructor
  · have selected :
        Programs.fence.source.events[2]? =
          some (.lookup {
            ordinal := 2
            domain := .programAccess
            numerator := 10
            tuple := #[2, 9, 3, 4, 5]
            role := .request
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.fence (columns row) 2 _ selected,
    ]
    reduce_fence
  constructor
  · have selected :
        Programs.fence.source.events[3]? =
          some (.lookup {
            ordinal := 3
            domain := .registersState
            numerator := 10
            tuple := #[2, 1]
            role := .consume
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.fence (columns row) 3 _ selected,
    ]
    reduce_fence
  · have selected :
        Programs.fence.source.events[4]? =
          some (.lookup {
            ordinal := 4
            domain := .registersState
            numerator := 0
            tuple := #[12, 13]
            role := .emit
            tableId := none
            liveness := .nonzeroNumerator
            accessOrdinal := none
          }) := by decide
    rw [
      evaluation,
      LocalProgram.lookup?_evalSymbolic_of_event
        Programs.fence (columns row) 4 _ selected,
    ]
    reduce_fence

theorem sourceAndDestinationProjectionEmpty :
    Programs.fence.source.projection.sourceEvents = #[] ∧
      Programs.fence.source.projection.destinationEvents = #[] := by
  decide

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock + 1 < M31.modulus
  pcBound : row.pc.toNat + 4 < M31.modulus

private theorem nextPcToNat
    (row : Row)
    (admission : Admission row) :
    (nextPc row.pc).toNat = row.pc.toNat + 4 := by
  simp only [nextPc, BitVec.toNat_add, BitVec.toNat_ofNat, Nat.reducePow]
  rw [Nat.mod_eq_of_lt]
  have bound := admission.pcBound
  rw [M31.modulus_eq] at bound
  omega

theorem nextPcField
    (row : Row)
    (admission : Admission row) :
    bitVecM31 row.pc + M31.reduce 4 =
      bitVecM31 (nextPc row.pc) := by
  apply M31.ext
  have pcBound : row.pc.toNat < M31.modulus := by
    have bound := admission.pcBound
    omega
  have nextBound : (nextPc row.pc).toNat < M31.modulus := by
    rw [nextPcToNat row admission]
    exact admission.pcBound
  have sumBound :
      (bitVecM31 row.pc).val + (M31.reduce 4).val <
        M31.modulus := by
    rw [
      Lui.bitVecM31_val row.pc pcBound,
      M31.reduce_val_of_lt 4 (by decide),
    ]
    exact admission.pcBound
  have sumValue :=
    M31.add_val_of_lt
      (bitVecM31 row.pc) (M31.reduce 4) sumBound
  rw [
    sumValue,
    Lui.bitVecM31_val row.pc pcBound,
    M31.reduce_val_of_lt 4 (by decide),
    Lui.bitVecM31_val (nextPc row.pc) nextBound,
    nextPcToNat row admission,
  ]

theorem nextClockField
    (row : Row)
    (admission : Admission row) :
    M31.reduce row.clock + 1 = M31.reduce (row.clock + 1) := by
  apply M31.ext
  have clockBound : row.clock < M31.modulus := by
    have bound := admission.clockBound
    omega
  have sumBound :
      (M31.reduce row.clock).val + (1 : M31).val <
        M31.modulus := by
    rw [M31.reduce_val_of_lt row.clock clockBound]
    exact admission.clockBound
  rw [
    M31.add_val_of_lt (M31.reduce row.clock) 1 sumBound,
    M31.reduce_val_of_lt row.clock clockBound,
    M31.reduce_val_of_lt (row.clock + 1) admission.clockBound,
  ]
  rfl

structure ProductionRefinement (row : Row) : Prop where
  selectors : (evaluation row).activeSelectorsAccepted = true
  constraints : (evaluation row).constraintsHold = true
  fixedLookups : (evaluation row).fixedLookupsHold = true
  program :
    (evaluation row).lookup? 2 = some (programLookup row)
  stateConsume :
    (evaluation row).lookup? 3 = some (stateConsumeLookup row)
  stateEmit :
    (evaluation row).lookup? 4 = some (stateEmitLookup row)
  noRegisterAccessProjection :
    Programs.fence.source.projection.sourceEvents = #[] ∧
      Programs.fence.source.projection.destinationEvents = #[]
  nextPc :
    (stateEmitLookup row).tuple[0]? =
      some (bitVecM31 (RiscvRefinement.nextPc row.pc))
  nextClock :
    (stateEmitLookup row).tuple[1]? =
      some (M31.reduce (row.clock + 1))

theorem sound
    (row : Row)
    (admission : Admission row) :
    ProductionRefinement row := by
  rcases lookupProjection row with ⟨program, consume, emit⟩
  refine {
    selectors := selectorAccepted row
    constraints := constraintsHold row
    fixedLookups := fixedLookupsHold row
    program := program
    stateConsume := consume
    stateEmit := emit
    noRegisterAccessProjection := sourceAndDestinationProjectionEmpty
    nextPc := ?_
    nextClock := ?_
  }
  · simp [stateEmitLookup, nextPcField row admission]
  · simp [stateEmitLookup, nextClockField row admission]

def exampleRow : Row where
  clock := 7
  pc := BitVec.ofNat 32 0x1000
  rd := BitVec.ofNat 5 31
  rs1 := BitVec.ofNat 5 17
  immediate := BitVec.ofNat 12 0xf53

theorem exampleAdmission : Admission exampleRow := by
  refine {
    clockPositive := by decide
    clockBound := by decide
    pcBound := by decide
  }

theorem acceptanceNonvacuous :
    ∃ row, Admission row ∧ ProductionRefinement row :=
  ⟨exampleRow, exampleAdmission, sound exampleRow exampleAdmission⟩

end RiscvRefinement.Air.Bridge.Fence
