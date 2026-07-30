import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Air.Bridge.LtComparator
import RiscvRefinement.Bridge.DecodeBranches

/-!
# Production branch AIR bridges

This module evaluates the six exact generated branch programs.  The canonical
rows retained below provide small executable non-vacuity witnesses.  The raw
production rows mirror every generated input and output column independently;
their universal soundness theorems derive source preservation, comparison, and
the branch decision from the generated constraints and fixed-table requests.
-/

namespace RiscvRefinement.Air.Bridge.Branches

open RiscvRefinement
open RiscvRefinement.Air.Generated

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

def immediate (encoded : BitVec 12) : BitVec 13 :=
  Decode.branchImmediate encoded

def immediateFieldValue (encoded : BitVec 12) : Nat :=
  if (immediate encoded).msb
  then M31.modulus + (immediate encoded).toNat - 2 ^ 13
  else (immediate encoded).toNat

def immediateField (encoded : BitVec 12) : M31 :=
  M31.reduce (immediateFieldValue encoded)

def branchTarget (pc : Word) (encoded : BitVec 12) : Word :=
  if (immediate encoded).msb
  then BitVec.ofNat 32
    (pc.toNat - (2 ^ 13 - (immediate encoded).toNat))
  else BitVec.ofNat 32 (pc.toNat + (immediate encoded).toNat)

def selectedPc (pc : Word) (encoded : BitVec 12) (taken : Bool) : Word :=
  if taken then branchTarget pc encoded else nextPc pc

structure Admission
    (clock rs1PreviousClock rs2PreviousClock : Nat)
    (pc : Word)
    (encoded : BitVec 12) : Prop where
  clockPositive : 0 < clock
  clockBound : clock ≤ 2 ^ 24
  rs1PreviousBound : rs1PreviousClock < 2 ^ 26
  rs2PreviousBound : rs2PreviousClock < 2 ^ 26
  fallthroughBound : pc.toNat + 4 < M31.modulus
  targetNoWrap :
    if (immediate encoded).msb
    then 2 ^ 13 - (immediate encoded).toNat ≤ pc.toNat
    else pc.toNat + (immediate encoded).toNat < M31.modulus
  targetAligned : (immediate encoded).toNat % 4 = 0

def accessClockField (clock ordinal : Nat) : M31 :=
  TeamACommon.accessClockField clock ordinal

def clockGapField (clock ordinal previous : Nat) : M31 :=
  TeamACommon.clockGapField clock ordinal previous

private theorem immediate_toNat_lt (encoded : BitVec 12) :
    (immediate encoded).toNat < 2 ^ 13 := by
  exact (immediate encoded).isLt

theorem immediateFieldValue_lt (encoded : BitVec 12) :
    immediateFieldValue encoded < M31.modulus := by
  have rawBound := immediate_toNat_lt encoded
  simp only [immediateFieldValue]
  split
  · simp [M31.modulus_eq] at *
    omega
  · simp [M31.modulus_eq] at *
    omega

theorem branchTargetField
    (clock rs1PreviousClock rs2PreviousClock : Nat)
    (pc : Word)
    (encoded : BitVec 12)
    (admission :
      Admission clock rs1PreviousClock rs2PreviousClock pc encoded) :
    bitVecM31 pc + immediateField encoded =
      bitVecM31 (branchTarget pc encoded) := by
  have rawBound := immediate_toNat_lt encoded
  have pcBound : pc.toNat < M31.modulus := by
    have := admission.fallthroughBound
    omega
  simp only [immediateField, immediateFieldValue, branchTarget]
  split <;> rename_i sign
  · have noWrap := admission.targetNoWrap
    rw [if_pos sign] at noWrap
    simp only [bitVecM31, TeamACommon.bitVecM31, Lui.bitVecM31]
    rw [TeamACommon.reduceAdd]
    apply M31.ext
    simp only [M31.reduce_val, BitVec.toNat_ofNat, Nat.reducePow]
    have targetBound :
        pc.toNat - (8192 - (immediate encoded).toNat) < 4294967296 := by
      omega
    rw [Nat.mod_eq_of_lt targetBound]
    have rearrange :
        pc.toNat +
              (M31.modulus + (immediate encoded).toNat - 8192) =
            M31.modulus +
              (pc.toNat - (8192 - (immediate encoded).toNat)) := by
      simp [M31.modulus_eq] at *
      omega
    rw [rearrange, Nat.add_mod_left]
  · have noWrap := admission.targetNoWrap
    rw [if_neg sign] at noWrap
    simp only [bitVecM31, TeamACommon.bitVecM31, Lui.bitVecM31]
    rw [TeamACommon.reduceAdd]
    apply M31.ext
    simp only [M31.reduce_val, BitVec.toNat_ofNat, Nat.reducePow]
    have wordBound :
        pc.toNat + (immediate encoded).toNat < 4294967296 := by
      have := noWrap
      simp [M31.modulus_eq] at *
      omega
    rw [
      Nat.mod_eq_of_lt wordBound,
      Nat.mod_eq_of_lt noWrap,
    ]

theorem selectedPcField
    (clock rs1PreviousClock rs2PreviousClock : Nat)
    (pc : Word)
    (encoded : BitVec 12)
    (taken : Bool)
    (admission :
      Admission clock rs1PreviousClock rs2PreviousClock pc encoded) :
    bitVecM31 pc +
          immediateField encoded * boolM31 taken +
          M31.reduce 4 * (1 - boolM31 taken) =
      bitVecM31 (selectedPc pc encoded taken) := by
  cases taken
  · simpa [
      selectedPc,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      M31.add_zero,
      M31.mul_zero,
      M31.mul_one,
    ] using
      TeamACommon.nextPcField pc admission.fallthroughBound
  · simpa [
      selectedPc,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      M31.add_zero,
      M31.mul_zero,
      M31.mul_one,
    ] using
      branchTargetField
        clock rs1PreviousClock rs2PreviousClock pc encoded admission

/-! ## BEQ / BNE -/

namespace Eq

inductive Kind where
  | beq
  | bne
deriving DecidableEq, Repr

def Kind.decode : Kind → Decode.BranchKind
  | .beq => .beq
  | .bne => .bne

def Kind.program : Kind → LocalProgram
  | .beq => Programs.beq
  | .bne => Programs.bne

def Kind.manifestId : Kind → Nat
  | .beq => 27
  | .bne => 28

def Kind.contentDigest : Kind → String
  | .beq => "0d48f529a978d7e20cb0c4f160061c9ff2fb4e7057bb3feb7237e529d6df4bb6"
  | .bne => "b69c3387aa57782e83d164e39ea749be7a31e532ab947bcab41dace6036e1347"

structure Row where
  kind : Kind
  clock : Nat
  pc : Word
  rs1 : RegisterIndex
  rs1Value : WordBytes
  rs1PreviousClock : Nat
  rs2 : RegisterIndex
  rs2Value : WordBytes
  rs2PreviousClock : Nat
  immediateEncoded : BitVec 12
deriving DecidableEq, Repr

def equal (row : Row) : Bool :=
  decide (row.rs1Value.word = row.rs2Value.word)

def taken (row : Row) : Bool :=
  match row.kind with
  | .beq => equal row
  | .bne => !equal row

structure Witness (row : Row) where
  marker0 : M31
  marker1 : M31
  marker2 : M31
  marker3 : M31

/--
Canonical/example rows precompute this column.  Universal production claims
use `RawRow.branchTaken` below and derive it from accepted constraints.
-/
private def canonicalTakenColumn (row : Row) : Bool :=
  taken row

def columns (row : Row) (witness : Witness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.rs1
  | 3 => bitVecM31 row.rs1Value.limb0
  | 4 => bitVecM31 row.rs1Value.limb1
  | 5 => bitVecM31 row.rs1Value.limb2
  | 6 => bitVecM31 row.rs1Value.limb3
  | 7 => M31.reduce row.rs1PreviousClock
  | 8 => bitVecM31 row.rs1Value.limb0
  | 9 => bitVecM31 row.rs1Value.limb1
  | 10 => bitVecM31 row.rs1Value.limb2
  | 11 => bitVecM31 row.rs1Value.limb3
  | 12 => bitVecM31 row.rs2
  | 13 => bitVecM31 row.rs2Value.limb0
  | 14 => bitVecM31 row.rs2Value.limb1
  | 15 => bitVecM31 row.rs2Value.limb2
  | 16 => bitVecM31 row.rs2Value.limb3
  | 17 => M31.reduce row.rs2PreviousClock
  | 18 => bitVecM31 row.rs2Value.limb0
  | 19 => bitVecM31 row.rs2Value.limb1
  | 20 => bitVecM31 row.rs2Value.limb2
  | 21 => bitVecM31 row.rs2Value.limb3
  | 22 => immediateField row.immediateEncoded
  | 23 => boolM31 (canonicalTakenColumn row)
  | 24 => witness.marker0
  | 25 => witness.marker1
  | 26 => witness.marker2
  | 27 => witness.marker3
  | 28 => if row.kind = .beq then 1 else 0
  | 29 => if row.kind = .bne then 1 else 0
  | _ => 0

def evaluation (row : Row) (witness : Witness row) :
    SymbolicEvaluation :=
  row.kind.program.evalSymbolic (columns row witness)

def admission (row : Row) : Prop :=
  Admission row.clock row.rs1PreviousClock row.rs2PreviousClock
    row.pc row.immediateEncoded

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 18
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce row.kind.manifestId,
    bitVecM31 row.rs1,
    bitVecM31 row.rs2,
    immediateField row.immediateEncoded
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def sourceConsumeLookup
    (row : Row) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 19 else 22
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
      bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
      bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3
    ] else #[
      0, bitVecM31 row.rs2, M31.reduce row.rs2PreviousClock,
      bitVecM31 row.rs2Value.limb0, bitVecM31 row.rs2Value.limb1,
      bitVecM31 row.rs2Value.limb2, bitVecM31 row.rs2Value.limb3
    ]
  role := .consume
  tableId := none
  accessOrdinal := some (source.val + 1)

def sourceEmitLookup
    (row : Row) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 20 else 23
  domain := .memoryAccess
  numerator := 1
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, accessClockField row.clock 1,
      bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
      bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3
    ] else #[
      0, bitVecM31 row.rs2, accessClockField row.clock 2,
      bitVecM31 row.rs2Value.limb0, bitVecM31 row.rs2Value.limb1,
      bitVecM31 row.rs2Value.limb2, bitVecM31 row.rs2Value.limb3
    ]
  role := .emit
  tableId := none
  accessOrdinal := some (source.val + 1)

def sourceClockLookup
    (row : Row) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 21 else 24
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[
    if source = 0
    then clockGapField row.clock 1 row.rs1PreviousClock
    else clockGapField row.clock 2 row.rs2PreviousClock
  ]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some (source.val + 1)

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 25
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 26
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc +
      immediateField row.immediateEncoded * boolM31 (taken row) +
      M31.reduce 4 * (1 - boolM31 (taken row)),
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

macro "reduce_branch_eq" : tactic =>
  `(tactic|
    (simp only [
      evaluation,
      Kind.program,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.beq,
      Programs.beqSource,
      Programs.bne,
      Programs.bneSource,
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
      canonicalTakenColumn,
      programLookup,
      sourceConsumeLookup,
      sourceEmitLookup,
      sourceClockLookup,
      stateConsumeLookup,
      stateEmitLookup,
      accessClockField,
      clockGapField,
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

set_option maxRecDepth 30000 in
theorem selectorAccepted (row : Row) (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  cases kindCase : row.kind <;>
    simp only [evaluation, kindCase, Kind.program] <;>
    reduce_branch_eq <;>
    simp_all <;>
    rfl

set_option maxRecDepth 30000 in
theorem lookupProjection (row : Row) (witness : Witness row) :
    (evaluation row witness).lookup? 18 = some (programLookup row) ∧
      (evaluation row witness).lookup? 19 =
        some (sourceConsumeLookup row 0) ∧
      (evaluation row witness).lookup? 20 =
        some (sourceEmitLookup row 0) ∧
      (evaluation row witness).lookup? 21 =
        some (sourceClockLookup row 0) ∧
      (evaluation row witness).lookup? 22 =
        some (sourceConsumeLookup row 1) ∧
      (evaluation row witness).lookup? 23 =
        some (sourceEmitLookup row 1) ∧
      (evaluation row witness).lookup? 24 =
        some (sourceClockLookup row 1) ∧
      (evaluation row witness).lookup? 25 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 26 =
        some (stateEmitLookup row) := by
  cases kindCase : row.kind <;>
    simp only [evaluation, kindCase, Kind.program] <;>
    reduce_branch_eq <;>
    simp_all [EvaluatedEvent.lookup?, Kind.manifestId]

theorem exactProjectionMetadata (kind : Kind) :
    kind.program.source.projection.programEvent = 18 ∧
      kind.program.source.projection.sourceEvents = #[19, 20, 22, 23] ∧
      kind.program.source.projection.destinationEvents = #[] ∧
      kind.program.source.projection.stateEvents = #[25, 26] ∧
      kind.program.source.projection.nextPc = 98 := by
  cases kind <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem exactProgramIdentity (kind : Kind) :
    kind.program.source.contentDigest = kind.contentDigest ∧
      kind.program.source.family = .branchEq ∧
      kind.program.source.nodes.size = 100 ∧
      kind.program.source.events.size = 27 := by
  cases kind <;> exact ⟨rfl, rfl, rfl, rfl⟩

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true

structure ProductionRefinement
    (row : Row) (witness : Witness row) : Prop where
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true
  lookups :
    (evaluation row witness).lookup? 18 = some (programLookup row) ∧
      (evaluation row witness).lookup? 19 =
        some (sourceConsumeLookup row 0) ∧
      (evaluation row witness).lookup? 20 =
        some (sourceEmitLookup row 0) ∧
      (evaluation row witness).lookup? 21 =
        some (sourceClockLookup row 0) ∧
      (evaluation row witness).lookup? 22 =
        some (sourceConsumeLookup row 1) ∧
      (evaluation row witness).lookup? 23 =
        some (sourceEmitLookup row 1) ∧
      (evaluation row witness).lookup? 24 =
        some (sourceClockLookup row 1) ∧
      (evaluation row witness).lookup? 25 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 26 =
        some (stateEmitLookup row)
  projection :
    row.kind.program.source.projection.programEvent = 18 ∧
      row.kind.program.source.projection.sourceEvents = #[19, 20, 22, 23] ∧
      row.kind.program.source.projection.destinationEvents = #[] ∧
      row.kind.program.source.projection.stateEvents = #[25, 26] ∧
      row.kind.program.source.projection.nextPc = 98
  programIdentity :
    row.kind.program.source.contentDigest = row.kind.contentDigest ∧
      row.kind.program.source.family = .branchEq ∧
      row.kind.program.source.nodes.size = 100 ∧
      row.kind.program.source.events.size = 27
  nextPc :
    (stateEmitLookup row).tuple[0]? =
      some (bitVecM31
        (selectedPc row.pc row.immediateEncoded (taken row)))
  nextClock :
    (stateEmitLookup row).tuple[1]? =
      some (M31.reduce (row.clock + 1))
  sourceReadOnly :
    (sourceConsumeLookup row 0).tuple[3]? =
        (sourceEmitLookup row 0).tuple[3]? ∧
      (sourceConsumeLookup row 0).tuple[4]? =
        (sourceEmitLookup row 0).tuple[4]? ∧
      (sourceConsumeLookup row 0).tuple[5]? =
        (sourceEmitLookup row 0).tuple[5]? ∧
      (sourceConsumeLookup row 0).tuple[6]? =
        (sourceEmitLookup row 0).tuple[6]? ∧
      (sourceConsumeLookup row 1).tuple[3]? =
        (sourceEmitLookup row 1).tuple[3]? ∧
      (sourceConsumeLookup row 1).tuple[4]? =
        (sourceEmitLookup row 1).tuple[4]? ∧
      (sourceConsumeLookup row 1).tuple[5]? =
        (sourceEmitLookup row 1).tuple[5]? ∧
      (sourceConsumeLookup row 1).tuple[6]? =
        (sourceEmitLookup row 1).tuple[6]?

theorem sound
    (row : Row)
    (witness : Witness row)
    (admissionProof : admission row)
    (accepted : Acceptance row witness) :
    ProductionRefinement row witness := by
  refine {
    selectors := selectorAccepted row witness
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    lookups := lookupProjection row witness
    projection := exactProjectionMetadata row.kind
    programIdentity := exactProgramIdentity row.kind
    nextPc := ?_
    nextClock := ?_
    sourceReadOnly := by
      simp [sourceConsumeLookup, sourceEmitLookup]
  }
  · simp [
      stateEmitLookup,
      selectedPcField
        row.clock row.rs1PreviousClock row.rs2PreviousClock
        row.pc row.immediateEncoded (taken row) admissionProof,
    ]
  · simp [
      stateEmitLookup,
      TeamACommon.nextClockField row.clock (by
        have := admissionProof.clockBound
        simp [M31.modulus_eq] at *
        omega),
    ]

/-!
### Universal raw-column refinement

`Row` above is a convenient canonical witness model.  `RawRow` is the
production contract: previous and next source bytes, the immediate field, and
the comparison result are independent columns.  No architectural relationship
between them is admitted below.
-/

structure RawRow where
  kind : Kind
  clock : Nat
  pc : Word
  rs1 : RegisterIndex
  rs1Previous : WordBytes
  rs1PreviousClock : Nat
  rs1Next : WordBytes
  rs2 : RegisterIndex
  rs2Previous : WordBytes
  rs2PreviousClock : Nat
  rs2Next : WordBytes
  immediateEncoded : BitVec 12
  immediateFelt : M31
  branchTaken : Bool
deriving DecidableEq, Repr

structure RawWitness (row : RawRow) where
  marker0 : M31
  marker1 : M31
  marker2 : M31
  marker3 : M31

def rawEqual (row : RawRow) : Bool :=
  decide (row.rs1Next.word = row.rs2Next.word)

def rawTaken (row : RawRow) : Bool :=
  match row.kind with
  | .beq => rawEqual row
  | .bne => !rawEqual row

def equalityFlag (row : RawRow) : Bool :=
  match row.kind with
  | .beq => row.branchTaken
  | .bne => !row.branchTaken

def rawSelectorSum (row : RawRow) : M31 :=
  (if row.kind = .beq then 1 else 0) +
    (if row.kind = .bne then 1 else 0)

def rawEqualityAccumulator
    (row : RawRow) (witness : RawWitness row) : M31 :=
  boolM31 row.branchTaken *
      (if row.kind = .beq then 1 else 0) +
    (1 - boolM31 row.branchTaken) *
      (if row.kind = .bne then 1 else 0) +
    (bitVecM31 row.rs1Next.limb0 -
        bitVecM31 row.rs2Next.limb0) * witness.marker0 +
    (bitVecM31 row.rs1Next.limb1 -
        bitVecM31 row.rs2Next.limb1) * witness.marker1 +
    (bitVecM31 row.rs1Next.limb2 -
        bitVecM31 row.rs2Next.limb2) * witness.marker2 +
    (bitVecM31 row.rs1Next.limb3 -
        bitVecM31 row.rs2Next.limb3) * witness.marker3

def rawColumns (row : RawRow) (witness : RawWitness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.rs1
  | 3 => bitVecM31 row.rs1Previous.limb0
  | 4 => bitVecM31 row.rs1Previous.limb1
  | 5 => bitVecM31 row.rs1Previous.limb2
  | 6 => bitVecM31 row.rs1Previous.limb3
  | 7 => M31.reduce row.rs1PreviousClock
  | 8 => bitVecM31 row.rs1Next.limb0
  | 9 => bitVecM31 row.rs1Next.limb1
  | 10 => bitVecM31 row.rs1Next.limb2
  | 11 => bitVecM31 row.rs1Next.limb3
  | 12 => bitVecM31 row.rs2
  | 13 => bitVecM31 row.rs2Previous.limb0
  | 14 => bitVecM31 row.rs2Previous.limb1
  | 15 => bitVecM31 row.rs2Previous.limb2
  | 16 => bitVecM31 row.rs2Previous.limb3
  | 17 => M31.reduce row.rs2PreviousClock
  | 18 => bitVecM31 row.rs2Next.limb0
  | 19 => bitVecM31 row.rs2Next.limb1
  | 20 => bitVecM31 row.rs2Next.limb2
  | 21 => bitVecM31 row.rs2Next.limb3
  | 22 => row.immediateFelt
  | 23 => boolM31 row.branchTaken
  | 24 => witness.marker0
  | 25 => witness.marker1
  | 26 => witness.marker2
  | 27 => witness.marker3
  | 28 => if row.kind = .beq then 1 else 0
  | 29 => if row.kind = .bne then 1 else 0
  | _ => 0

def rawEvaluation (row : RawRow) (witness : RawWitness row) :
    SymbolicEvaluation :=
  row.kind.program.evalSymbolic (rawColumns row witness)

structure RawAdmission (row : RawRow) : Prop where
  control :
    Admission row.clock row.rs1PreviousClock row.rs2PreviousClock
      row.pc row.immediateEncoded
  immediateFieldBinds :
    row.immediateFelt = immediateField row.immediateEncoded

def rawProgramLookup (row : RawRow) : EvaluatedLookup where
  ordinal := 18
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce row.kind.manifestId,
    bitVecM31 row.rs1,
    bitVecM31 row.rs2,
    row.immediateFelt
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def rawSourceConsumeLookup
    (row : RawRow) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 19 else 22
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
      bitVecM31 row.rs1Previous.limb0, bitVecM31 row.rs1Previous.limb1,
      bitVecM31 row.rs1Previous.limb2, bitVecM31 row.rs1Previous.limb3
    ] else #[
      0, bitVecM31 row.rs2, M31.reduce row.rs2PreviousClock,
      bitVecM31 row.rs2Previous.limb0, bitVecM31 row.rs2Previous.limb1,
      bitVecM31 row.rs2Previous.limb2, bitVecM31 row.rs2Previous.limb3
    ]
  role := .consume
  tableId := none
  accessOrdinal := some (source.val + 1)

def rawSourceEmitLookup
    (row : RawRow) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 20 else 23
  domain := .memoryAccess
  numerator := 1
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, accessClockField row.clock 1,
      bitVecM31 row.rs1Next.limb0, bitVecM31 row.rs1Next.limb1,
      bitVecM31 row.rs1Next.limb2, bitVecM31 row.rs1Next.limb3
    ] else #[
      0, bitVecM31 row.rs2, accessClockField row.clock 2,
      bitVecM31 row.rs2Next.limb0, bitVecM31 row.rs2Next.limb1,
      bitVecM31 row.rs2Next.limb2, bitVecM31 row.rs2Next.limb3
    ]
  role := .emit
  tableId := none
  accessOrdinal := some (source.val + 1)

def rawSourceClockLookup
    (row : RawRow) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 21 else 24
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[
    if source = 0
    then clockGapField row.clock 1 row.rs1PreviousClock
    else clockGapField row.clock 2 row.rs2PreviousClock
  ]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some (source.val + 1)

def rawStateConsumeLookup (row : RawRow) : EvaluatedLookup where
  ordinal := 25
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def rawStateEmitLookup (row : RawRow) : EvaluatedLookup where
  ordinal := 26
  domain := .registersState
  numerator := 1
  tuple := #[
    bitVecM31 row.pc +
      row.immediateFelt * boolM31 row.branchTaken +
      M31.reduce 4 * (1 - boolM31 row.branchTaken),
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

macro "reduce_branch_eq_raw" : tactic =>
  `(tactic|
    (simp only [
      rawEvaluation,
      Kind.program,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.beq,
      Programs.beqSource,
      Programs.bne,
      Programs.bneSource,
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
      rawColumns,
      rawProgramLookup,
      rawSourceConsumeLookup,
      rawSourceEmitLookup,
      rawSourceClockLookup,
      rawStateConsumeLookup,
      rawStateEmitLookup,
      accessClockField,
      clockGapField,
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
      try simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?
      ] <;>
      try rfl))

set_option maxRecDepth 30000 in
theorem rawSelectorAccepted (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).activeSelectorsAccepted = true := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program] <;>
    reduce_branch_eq_raw <;>
    simp_all <;>
    rfl

set_option maxRecDepth 30000 in
theorem rawLookupProjection (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).lookup? 18 = some (rawProgramLookup row) ∧
      (rawEvaluation row witness).lookup? 19 =
        some (rawSourceConsumeLookup row 0) ∧
      (rawEvaluation row witness).lookup? 20 =
        some (rawSourceEmitLookup row 0) ∧
      (rawEvaluation row witness).lookup? 21 =
        some (rawSourceClockLookup row 0) ∧
      (rawEvaluation row witness).lookup? 22 =
        some (rawSourceConsumeLookup row 1) ∧
      (rawEvaluation row witness).lookup? 23 =
        some (rawSourceEmitLookup row 1) ∧
      (rawEvaluation row witness).lookup? 24 =
        some (rawSourceClockLookup row 1) ∧
      (rawEvaluation row witness).lookup? 25 =
        some (rawStateConsumeLookup row) ∧
      (rawEvaluation row witness).lookup? 26 =
        some (rawStateEmitLookup row) := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program] <;>
    reduce_branch_eq_raw <;>
    simp_all [EvaluatedEvent.lookup?, Kind.manifestId]

def rawConstraintRoots : Array Nat :=
  #[33, 35, 37, 39, 45, 47, 49, 51, 61, 63, 65, 67, 69,
    71, 73, 75, 77, 32]

set_option maxHeartbeats 800000 in
private theorem rawConstraintsHoldEvents
    (kind : Kind)
    (nodes : LocalValues) :
    ((kind.program).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      rawConstraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  cases kind
  · simpa [Kind.program, Programs.beq, Programs.beqSource,
      rawConstraintRoots, Event.evalSymbolic]
  · simpa [Kind.program, Programs.bne, Programs.bneSource,
      rawConstraintRoots, Event.evalSymbolic]

theorem rawConstraintsHold_eq
    (row : RawRow)
    (witness : RawWitness row) :
    (rawEvaluation row witness).constraintsHold =
      rawConstraintRoots.all
        (fun root =>
          (rawEvaluation row witness).nodes.getSymbolic root == 0) := by
  exact
    rawConstraintsHoldEvents row.kind (rawEvaluation row witness).nodes

theorem rawConstraintRootZero
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : (rawEvaluation row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ rawConstraintRoots) :
    (rawEvaluation row witness).nodes.getSymbolic root = 0 := by
  rw [rawConstraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

set_option maxRecDepth 30000 in
private theorem rawNode45 (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 45 =
      boolM31 (equalityFlag row) *
        (bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs2Next.limb0) := by
  cases kindCase : row.kind <;> cases takenCase : row.branchTaken <;>
    simp only [rawEvaluation, kindCase, takenCase, Kind.program] <;>
    reduce_branch_eq_raw <;>
    simp [equalityFlag, kindCase, takenCase, boolM31,
      TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 30000 in
private theorem rawNode47 (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 47 =
      boolM31 (equalityFlag row) *
        (bitVecM31 row.rs1Next.limb1 -
          bitVecM31 row.rs2Next.limb1) := by
  cases kindCase : row.kind <;> cases takenCase : row.branchTaken <;>
    simp only [rawEvaluation, kindCase, takenCase, Kind.program] <;>
    reduce_branch_eq_raw <;>
    simp [equalityFlag, kindCase, takenCase, boolM31,
      TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 30000 in
private theorem rawNode49 (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 49 =
      boolM31 (equalityFlag row) *
        (bitVecM31 row.rs1Next.limb2 -
          bitVecM31 row.rs2Next.limb2) := by
  cases kindCase : row.kind <;> cases takenCase : row.branchTaken <;>
    simp only [rawEvaluation, kindCase, takenCase, Kind.program] <;>
    reduce_branch_eq_raw <;>
    simp [equalityFlag, kindCase, takenCase, boolM31,
      TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 30000 in
private theorem rawNode51 (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 51 =
      boolM31 (equalityFlag row) *
        (bitVecM31 row.rs1Next.limb3 -
          bitVecM31 row.rs2Next.limb3) := by
  cases kindCase : row.kind <;> cases takenCase : row.branchTaken <;>
    simp only [rawEvaluation, kindCase, takenCase, Kind.program] <;>
    reduce_branch_eq_raw <;>
    simp [equalityFlag, kindCase, takenCase, boolM31,
      TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 30000 in
private theorem rawNode61 (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 61 =
      rawSelectorSum row *
        (1 - rawEqualityAccumulator row witness) := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program] <;>
    reduce_branch_eq_raw <;>
    simp [rawSelectorSum, rawEqualityAccumulator, kindCase]

set_option maxRecDepth 30000 in
private theorem rawSourceNodes
    (row : RawRow)
    (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 63 =
        bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0 ∧
    (rawEvaluation row witness).nodes.getSymbolic 65 =
        bitVecM31 row.rs1Next.limb1 -
          bitVecM31 row.rs1Previous.limb1 ∧
    (rawEvaluation row witness).nodes.getSymbolic 67 =
        bitVecM31 row.rs1Next.limb2 -
          bitVecM31 row.rs1Previous.limb2 ∧
    (rawEvaluation row witness).nodes.getSymbolic 69 =
        bitVecM31 row.rs1Next.limb3 -
          bitVecM31 row.rs1Previous.limb3 ∧
    (rawEvaluation row witness).nodes.getSymbolic 71 =
        bitVecM31 row.rs2Next.limb0 -
          bitVecM31 row.rs2Previous.limb0 ∧
    (rawEvaluation row witness).nodes.getSymbolic 73 =
        bitVecM31 row.rs2Next.limb1 -
          bitVecM31 row.rs2Previous.limb1 ∧
    (rawEvaluation row witness).nodes.getSymbolic 75 =
        bitVecM31 row.rs2Next.limb2 -
          bitVecM31 row.rs2Previous.limb2 ∧
    (rawEvaluation row witness).nodes.getSymbolic 77 =
        bitVecM31 row.rs2Next.limb3 -
          bitVecM31 row.rs2Previous.limb3 := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program]
  all_goals
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals reduce_branch_eq_raw
  all_goals simp_all

private theorem rawByteEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right := by
  apply TeamACommon.bitVecM31_injective_of_bounds left right
  · have := left.isLt
    simp [M31.modulus_eq] at *
    omega
  · have := right.isLt
    simp [M31.modulus_eq] at *
    omega
  · exact equality

private theorem wordBytesWord_injective
    {left right : WordBytes}
    (equality : left.word = right.word) :
    left = right := by
  have values := congrArg BitVec.toNat equality
  simp only [WordBytes.word_toNat, WordBytes.value] at values
  have l0 := left.limb0.isLt
  have l1 := left.limb1.isLt
  have l2 := left.limb2.isLt
  have l3 := left.limb3.isLt
  have r0 := right.limb0.isLt
  have r1 := right.limb1.isLt
  have r2 := right.limb2.isLt
  have r3 := right.limb3.isLt
  simp only [Nat.reducePow] at l0 l1 l2 l3 r0 r1 r2 r3
  apply WordBytes.eq_of_limbs <;> apply BitVec.eq_of_toNat_eq <;> omega

theorem rawSourceReadOnly
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : (rawEvaluation row witness).constraintsHold = true) :
    row.rs1Next = row.rs1Previous ∧
      row.rs2Next = row.rs2Previous := by
  have zero (root : Nat) (member : root ∈ rawConstraintRoots) :=
    rawConstraintRootZero row witness accepted root member
  have nodes := rawSourceNodes row witness
  apply And.intro <;> apply WordBytes.eq_of_limbs <;> apply rawByteEq
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.1] using zero 63 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.1] using zero 65 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.1] using zero 67 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.1] using zero 69 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.1] using zero 71 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.2.1] using zero 73 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.2.2.1] using zero 75 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.2.2.2] using zero 77 (by simp [rawConstraintRoots]))

theorem rawDecisionCorrect
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : (rawEvaluation row witness).constraintsHold = true) :
    row.branchTaken = rawTaken row := by
  have zero (root : Nat) (member : root ∈ rawConstraintRoots) :=
    rawConstraintRootZero row witness accepted root member
  have equalityCorrect :
      equalityFlag row =
        decide (row.rs1Next.word = row.rs2Next.word) := by
    cases flagCase : equalityFlag row
    · have notEqual :
          row.rs1Next.word ≠ row.rs2Next.word := by
        intro wordEquality
        have bytesEquality := wordBytesWord_injective wordEquality
        have equation := zero 61 (by simp [rawConstraintRoots])
        rw [rawNode61] at equation
        simp only [rawEqualityAccumulator] at equation
        rw [bytesEquality] at equation
        have distinct : (1 : M31) ≠ 0 := by decide
        cases kindCase : row.kind <;>
          cases takenCase : row.branchTaken <;>
          simp_all [
            equalityFlag,
            rawSelectorSum,
            rawEqualityAccumulator,
            boolM31,
            TeamACommon.boolM31,
            Lui.boolM31
          ]
      simp [flagCase, notEqual]
    · have limb0 : row.rs1Next.limb0 = row.rs2Next.limb0 := by
        apply rawByteEq
        have equation := zero 45 (by simp [rawConstraintRoots])
        rw [rawNode45, flagCase] at equation
        simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
        exact (M31.sub_eq_zero_iff _ _).mp equation
      have limb1 : row.rs1Next.limb1 = row.rs2Next.limb1 := by
        apply rawByteEq
        have equation := zero 47 (by simp [rawConstraintRoots])
        rw [rawNode47, flagCase] at equation
        simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
        exact (M31.sub_eq_zero_iff _ _).mp equation
      have limb2 : row.rs1Next.limb2 = row.rs2Next.limb2 := by
        apply rawByteEq
        have equation := zero 49 (by simp [rawConstraintRoots])
        rw [rawNode49, flagCase] at equation
        simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
        exact (M31.sub_eq_zero_iff _ _).mp equation
      have limb3 : row.rs1Next.limb3 = row.rs2Next.limb3 := by
        apply rawByteEq
        have equation := zero 51 (by simp [rawConstraintRoots])
        rw [rawNode51, flagCase] at equation
        simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
        exact (M31.sub_eq_zero_iff _ _).mp equation
      have bytesEquality :=
        WordBytes.eq_of_limbs _ _ limb0 limb1 limb2 limb3
      have wordEquality := congrArg WordBytes.word bytesEquality
      simp [flagCase, wordEquality]
  cases kindCase : row.kind <;> cases takenCase : row.branchTaken <;>
    simp_all [equalityFlag, rawTaken, rawEqual]

structure RawAcceptance
    (row : RawRow) (witness : RawWitness row) : Prop where
  constraints : (rawEvaluation row witness).constraintsHold = true
  fixedLookups : (rawEvaluation row witness).fixedLookupsHold = true

structure RawProductionRefinement
    (row : RawRow) (witness : RawWitness row) : Prop where
  selectors : (rawEvaluation row witness).activeSelectorsAccepted = true
  constraints : (rawEvaluation row witness).constraintsHold = true
  fixedLookups : (rawEvaluation row witness).fixedLookupsHold = true
  lookups :
    (rawEvaluation row witness).lookup? 18 = some (rawProgramLookup row) ∧
      (rawEvaluation row witness).lookup? 19 =
        some (rawSourceConsumeLookup row 0) ∧
      (rawEvaluation row witness).lookup? 20 =
        some (rawSourceEmitLookup row 0) ∧
      (rawEvaluation row witness).lookup? 21 =
        some (rawSourceClockLookup row 0) ∧
      (rawEvaluation row witness).lookup? 22 =
        some (rawSourceConsumeLookup row 1) ∧
      (rawEvaluation row witness).lookup? 23 =
        some (rawSourceEmitLookup row 1) ∧
      (rawEvaluation row witness).lookup? 24 =
        some (rawSourceClockLookup row 1) ∧
      (rawEvaluation row witness).lookup? 25 =
        some (rawStateConsumeLookup row) ∧
      (rawEvaluation row witness).lookup? 26 =
        some (rawStateEmitLookup row)
  projection :
    row.kind.program.source.projection.programEvent = 18 ∧
      row.kind.program.source.projection.sourceEvents = #[19, 20, 22, 23] ∧
      row.kind.program.source.projection.destinationEvents = #[] ∧
      row.kind.program.source.projection.stateEvents = #[25, 26] ∧
      row.kind.program.source.projection.nextPc = 98
  programIdentity :
    row.kind.program.source.contentDigest = row.kind.contentDigest ∧
      row.kind.program.source.family = .branchEq ∧
      row.kind.program.source.nodes.size = 100 ∧
      row.kind.program.source.events.size = 27
  immediate :
    row.immediateFelt = immediateField row.immediateEncoded
  sourceReadOnly :
    row.rs1Next = row.rs1Previous ∧ row.rs2Next = row.rs2Previous
  decision :
    row.branchTaken = rawTaken row
  nextPc :
    (rawStateEmitLookup row).tuple[0]? =
      some (bitVecM31
        (selectedPc row.pc row.immediateEncoded (rawTaken row)))
  nextClock :
    (rawStateEmitLookup row).tuple[1]? =
      some (M31.reduce (row.clock + 1))

theorem rawSound
    (row : RawRow)
    (witness : RawWitness row)
    (admissionProof : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawProductionRefinement row witness := by
  have decision := rawDecisionCorrect row witness accepted.constraints
  refine {
    selectors := rawSelectorAccepted row witness
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    lookups := rawLookupProjection row witness
    projection := exactProjectionMetadata row.kind
    programIdentity := exactProgramIdentity row.kind
    immediate := admissionProof.immediateFieldBinds
    sourceReadOnly := rawSourceReadOnly row witness accepted.constraints
    decision := decision
    nextPc := ?_
    nextClock := ?_
  }
  · simp [
      rawStateEmitLookup,
      admissionProof.immediateFieldBinds,
      decision,
      selectedPcField
        row.clock row.rs1PreviousClock row.rs2PreviousClock
        row.pc row.immediateEncoded (rawTaken row) admissionProof.control,
    ]
  · simp [
      rawStateEmitLookup,
      TeamACommon.nextClockField row.clock (by
        have := admissionProof.control.clockBound
        simp [M31.modulus_eq] at *
        omega),
    ]

def exampleValue (value : Nat) : WordBytes where
  limb0 := BitVec.ofNat 8 value
  limb1 := BitVec.ofNat 8 0
  limb2 := BitVec.ofNat 8 0
  limb3 := BitVec.ofNat 8 0

def exampleRow (kind : Kind) (requestedTaken : Bool) : Row where
  kind := kind
  clock := 7
  pc := BitVec.ofNat 32 0x1000
  rs1 := BitVec.ofNat 5 3
  rs1Value := exampleValue 1
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 4
  rs2Value :=
    exampleValue
      (if kind = .beq then
        if requestedTaken then 1 else 0
      else
        if requestedTaken then 0 else 1)
  rs2PreviousClock := 1
  immediateEncoded := BitVec.ofNat 12 8

def exampleWitness
    (kind : Kind) (requestedTaken : Bool) :
    Witness (exampleRow kind requestedTaken) where
  marker0 :=
    if (exampleRow kind requestedTaken).rs1Value.word =
        (exampleRow kind requestedTaken).rs2Value.word
    then 0
    else 1
  marker1 := 0
  marker2 := 0
  marker3 := 0

theorem exampleTaken (kind : Kind) (requestedTaken : Bool) :
    taken (exampleRow kind requestedTaken) = requestedTaken := by
  cases kind <;> cases requestedTaken <;> decide

theorem exampleAdmission (kind : Kind) (requestedTaken : Bool) :
    admission (exampleRow kind requestedTaken) := by
  cases kind <;> cases requestedTaken <;>
  refine {
    clockPositive := by decide
    clockBound := by decide
    rs1PreviousBound := by decide
    rs2PreviousBound := by decide
    fallthroughBound := by decide
    targetNoWrap := by decide
    targetAligned := by decide
  }

set_option maxRecDepth 30000 in
theorem exampleAcceptance (kind : Kind) (requestedTaken : Bool) :
    Acceptance (exampleRow kind requestedTaken)
      (exampleWitness kind requestedTaken) := by
  cases kind <;> cases requestedTaken <;>
    constructor <;>
    simp only [
      exampleRow,
      exampleWitness,
      exampleValue
    ] <;>
    reduce_branch_eq <;>
    try simp [
      taken,
      equal,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      M31.toNat,
      M31.reduce,
      M31.modulus
    ] <;>
    try decide

theorem takenAndFallthroughNonvacuous (kind : Kind) :
    (∃ row witness,
      admission row ∧
        Acceptance row witness ∧
        ProductionRefinement row witness ∧
        taken row = true) ∧
    (∃ row witness,
      admission row ∧
        Acceptance row witness ∧
        ProductionRefinement row witness ∧
        taken row = false) := by
  constructor
  · refine ⟨exampleRow kind true, exampleWitness kind true,
      exampleAdmission kind true, exampleAcceptance kind true, ?_,
      exampleTaken kind true⟩
    exact sound _ _ (exampleAdmission kind true) (exampleAcceptance kind true)
  · refine ⟨exampleRow kind false, exampleWitness kind false,
      exampleAdmission kind false, exampleAcceptance kind false, ?_,
      exampleTaken kind false⟩
    exact sound _ _ (exampleAdmission kind false) (exampleAcceptance kind false)

end Eq

/-! ## BLT / BGE / BLTU / BGEU -/

namespace Lt

inductive Kind where
  | blt
  | bge
  | bltu
  | bgeu
deriving DecidableEq, Repr

def Kind.decode : Kind → Decode.BranchKind
  | .blt => .blt
  | .bge => .bge
  | .bltu => .bltu
  | .bgeu => .bgeu

def Kind.program : Kind → LocalProgram
  | .blt => Programs.blt
  | .bge => Programs.bge
  | .bltu => Programs.bltu
  | .bgeu => Programs.bgeu

def Kind.manifestId : Kind → Nat
  | .blt => 29
  | .bge => 30
  | .bltu => 31
  | .bgeu => 32

def Kind.contentDigest : Kind → String
  | .blt => "56664799a5df1d05f70fb30b8090b93978053bc1e1b124bb5a8f6cb2fe005659"
  | .bge => "962c6e7126784b6b1ff4d3ce5c9e8062690c95370ccaa75811e19bf9bd0ab37a"
  | .bltu => "55cdb7210b32950bc6cdbc1770c761d978442ef5d351faf18189ba534acf503a"
  | .bgeu => "774ee6ee481bef7600752b1322ee11ef8d6563d8874d1dd4e894a100e595f53e"

def Kind.signed : Kind → Bool
  | .blt | .bge => true
  | .bltu | .bgeu => false

def Kind.lessOpcode : Kind → Bool
  | .blt | .bltu => true
  | .bge | .bgeu => false

structure Row where
  kind : Kind
  clock : Nat
  pc : Word
  rs1 : RegisterIndex
  rs1Value : WordBytes
  rs1PreviousClock : Nat
  rs2 : RegisterIndex
  rs2Value : WordBytes
  rs2PreviousClock : Nat
  immediateEncoded : BitVec 12
deriving DecidableEq, Repr

def signedLess (left right : Word) : Bool :=
  if left.msb = right.msb
  then decide (left.toNat < right.toNat)
  else left.msb

def less (row : Row) : Bool :=
  if row.kind.signed
  then signedLess row.rs1Value.word row.rs2Value.word
  else decide (row.rs1Value.word.toNat < row.rs2Value.word.toNat)

def taken (row : Row) : Bool :=
  if row.kind.lessOpcode then less row else !less row

def signedByteField (value : Byte) : M31 :=
  if value.msb
  then M31.reduce (M31.modulus + value.toNat - 256)
  else bitVecM31 value

def mostSignificantField (signed : Bool) (value : WordBytes) : M31 :=
  if signed then signedByteField value.limb3 else bitVecM31 value.limb3

structure Witness (row : Row) where
  marker0 : Bool
  marker1 : Bool
  marker2 : Bool
  marker3 : Bool
  difference : M31

def markerSum (witness : Witness row) : M31 :=
  boolM31 witness.marker0 +
    boolM31 witness.marker1 +
    boolM31 witness.marker2 +
    boolM31 witness.marker3

/--
These helpers belong only to the canonical non-vacuity model.  The universal
production bridge below has independent raw MSL, comparison, decision, and
selected-PC columns and proves their values from `RawAcceptance`.
-/
private def canonicalMostSignificantColumn
    (row : Row) (value : WordBytes) : M31 :=
  mostSignificantField row.kind.signed value

private def canonicalLessColumn (row : Row) : Bool :=
  less row

private def canonicalTakenColumn (row : Row) : Bool :=
  taken row

def columns (row : Row) (witness : Witness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.rs1
  | 3 => bitVecM31 row.rs1Value.limb0
  | 4 => bitVecM31 row.rs1Value.limb1
  | 5 => bitVecM31 row.rs1Value.limb2
  | 6 => bitVecM31 row.rs1Value.limb3
  | 7 => M31.reduce row.rs1PreviousClock
  | 8 => bitVecM31 row.rs1Value.limb0
  | 9 => bitVecM31 row.rs1Value.limb1
  | 10 => bitVecM31 row.rs1Value.limb2
  | 11 => bitVecM31 row.rs1Value.limb3
  | 12 => bitVecM31 row.rs2
  | 13 => bitVecM31 row.rs2Value.limb0
  | 14 => bitVecM31 row.rs2Value.limb1
  | 15 => bitVecM31 row.rs2Value.limb2
  | 16 => bitVecM31 row.rs2Value.limb3
  | 17 => M31.reduce row.rs2PreviousClock
  | 18 => bitVecM31 row.rs2Value.limb0
  | 19 => bitVecM31 row.rs2Value.limb1
  | 20 => bitVecM31 row.rs2Value.limb2
  | 21 => bitVecM31 row.rs2Value.limb3
  | 22 => canonicalMostSignificantColumn row row.rs1Value
  | 23 => canonicalMostSignificantColumn row row.rs2Value
  | 24 => immediateField row.immediateEncoded
  | 25 => boolM31 (canonicalTakenColumn row)
  | 26 => boolM31 (canonicalLessColumn row)
  | 27 => boolM31 witness.marker0
  | 28 => boolM31 witness.marker1
  | 29 => boolM31 witness.marker2
  | 30 => boolM31 witness.marker3
  | 31 => witness.difference
  | 32 => bitVecM31
      (selectedPc row.pc row.immediateEncoded (canonicalTakenColumn row))
  | 33 => if row.kind = .blt then 1 else 0
  | 34 => if row.kind = .bltu then 1 else 0
  | 35 => if row.kind = .bge then 1 else 0
  | 36 => if row.kind = .bgeu then 1 else 0
  | _ => 0

def evaluation (row : Row) (witness : Witness row) :
    SymbolicEvaluation :=
  row.kind.program.evalSymbolic (columns row witness)

def admission (row : Row) : Prop :=
  Admission row.clock row.rs1PreviousClock row.rs2PreviousClock
    row.pc row.immediateEncoded

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 33
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce row.kind.manifestId,
    bitVecM31 row.rs1,
    bitVecM31 row.rs2,
    immediateField row.immediateEncoded
  ]
  role := .request
  tableId := none
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
  tuple := #[
    bitVecM31 (selectedPc row.pc row.immediateEncoded (taken row)),
    M31.reduce row.clock + 1
  ]
  role := .emit
  tableId := none
  accessOrdinal := none

def sourceConsumeLookup
    (row : Row) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 36 else 39
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
      bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
      bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3
    ] else #[
      0, bitVecM31 row.rs2, M31.reduce row.rs2PreviousClock,
      bitVecM31 row.rs2Value.limb0, bitVecM31 row.rs2Value.limb1,
      bitVecM31 row.rs2Value.limb2, bitVecM31 row.rs2Value.limb3
    ]
  role := .consume
  tableId := none
  accessOrdinal := some (source.val + 1)

def sourceEmitLookup
    (row : Row) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 37 else 40
  domain := .memoryAccess
  numerator := 1
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, accessClockField row.clock 1,
      bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
      bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3
    ] else #[
      0, bitVecM31 row.rs2, accessClockField row.clock 2,
      bitVecM31 row.rs2Value.limb0, bitVecM31 row.rs2Value.limb1,
      bitVecM31 row.rs2Value.limb2, bitVecM31 row.rs2Value.limb3
    ]
  role := .emit
  tableId := none
  accessOrdinal := some (source.val + 1)

def sourceClockLookup
    (row : Row) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 38 else 41
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[
    if source = 0
    then clockGapField row.clock 1 row.rs1PreviousClock
    else clockGapField row.clock 2 row.rs2PreviousClock
  ]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some (source.val + 1)

def shiftedMostSignificantLookup (row : Row) : EvaluatedLookup where
  ordinal := 42
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    mostSignificantField row.kind.signed row.rs1Value +
      boolM31 row.kind.signed * M31.reduce 128,
    mostSignificantField row.kind.signed row.rs2Value +
      boolM31 row.kind.signed * M31.reduce 128
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def positiveDifferenceLookup
    (row : Row) (witness : Witness row) : EvaluatedLookup where
  ordinal := 43
  domain := .rangeCheck20
  numerator := -markerSum witness
  tuple := #[witness.difference - 1]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

macro "reduce_branch_lt" : tactic =>
  `(tactic|
    (simp only [
      evaluation,
      Kind.program,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.blt,
      Programs.bltSource,
      Programs.bge,
      Programs.bgeSource,
      Programs.bltu,
      Programs.bltuSource,
      Programs.bgeu,
      Programs.bgeuSource,
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
      canonicalMostSignificantColumn,
      canonicalTakenColumn,
      canonicalLessColumn,
      programLookup,
      stateConsumeLookup,
      stateEmitLookup,
      sourceConsumeLookup,
      sourceEmitLookup,
      sourceClockLookup,
      shiftedMostSignificantLookup,
      positiveDifferenceLookup,
      markerSum,
      accessClockField,
      clockGapField,
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

set_option maxRecDepth 40000 in
theorem selectorAccepted (row : Row) (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  cases kindCase : row.kind <;>
    simp only [evaluation, kindCase, Kind.program] <;>
    reduce_branch_lt <;>
    simp_all <;>
    rfl

set_option maxRecDepth 40000 in
theorem lookupProjection (row : Row) (witness : Witness row) :
    (evaluation row witness).lookup? 33 = some (programLookup row) ∧
      (evaluation row witness).lookup? 34 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 35 =
        some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 36 =
        some (sourceConsumeLookup row 0) ∧
      (evaluation row witness).lookup? 37 =
        some (sourceEmitLookup row 0) ∧
      (evaluation row witness).lookup? 38 =
        some (sourceClockLookup row 0) ∧
      (evaluation row witness).lookup? 39 =
        some (sourceConsumeLookup row 1) ∧
      (evaluation row witness).lookup? 40 =
        some (sourceEmitLookup row 1) ∧
      (evaluation row witness).lookup? 41 =
        some (sourceClockLookup row 1) ∧
      (evaluation row witness).lookup? 42 =
        some (shiftedMostSignificantLookup row) ∧
      (evaluation row witness).lookup? 43 =
        some (positiveDifferenceLookup row witness) := by
  cases kindCase : row.kind <;>
    simp only [evaluation, kindCase, Kind.program] <;>
    reduce_branch_lt <;>
    simp_all [
      EvaluatedEvent.lookup?,
      Kind.manifestId,
      Kind.signed,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      M31.add_zero
    ]

theorem exactProjectionMetadata (kind : Kind) :
    kind.program.source.projection.programEvent = 33 ∧
      kind.program.source.projection.sourceEvents = #[36, 37, 39, 40] ∧
      kind.program.source.projection.destinationEvents = #[] ∧
      kind.program.source.projection.stateEvents = #[34, 35] ∧
      kind.program.source.projection.nextPc = 32 := by
  cases kind <;> decide

theorem exactProgramIdentity (kind : Kind) :
    kind.program.source.contentDigest = kind.contentDigest ∧
      kind.program.source.family = .branchLt ∧
      kind.program.source.nodes.size = 159 ∧
      kind.program.source.events.size = 44 := by
  cases kind <;> exact ⟨rfl, rfl, rfl, rfl⟩

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true

structure ProductionRefinement
    (row : Row) (witness : Witness row) : Prop where
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true
  lookups :
    (evaluation row witness).lookup? 33 = some (programLookup row) ∧
      (evaluation row witness).lookup? 34 =
        some (stateConsumeLookup row) ∧
      (evaluation row witness).lookup? 35 =
        some (stateEmitLookup row) ∧
      (evaluation row witness).lookup? 36 =
        some (sourceConsumeLookup row 0) ∧
      (evaluation row witness).lookup? 37 =
        some (sourceEmitLookup row 0) ∧
      (evaluation row witness).lookup? 38 =
        some (sourceClockLookup row 0) ∧
      (evaluation row witness).lookup? 39 =
        some (sourceConsumeLookup row 1) ∧
      (evaluation row witness).lookup? 40 =
        some (sourceEmitLookup row 1) ∧
      (evaluation row witness).lookup? 41 =
        some (sourceClockLookup row 1) ∧
      (evaluation row witness).lookup? 42 =
        some (shiftedMostSignificantLookup row) ∧
      (evaluation row witness).lookup? 43 =
        some (positiveDifferenceLookup row witness)
  projection :
    row.kind.program.source.projection.programEvent = 33 ∧
      row.kind.program.source.projection.sourceEvents = #[36, 37, 39, 40] ∧
      row.kind.program.source.projection.destinationEvents = #[] ∧
      row.kind.program.source.projection.stateEvents = #[34, 35] ∧
      row.kind.program.source.projection.nextPc = 32
  programIdentity :
    row.kind.program.source.contentDigest = row.kind.contentDigest ∧
      row.kind.program.source.family = .branchLt ∧
      row.kind.program.source.nodes.size = 159 ∧
      row.kind.program.source.events.size = 44
  nextPc :
    (stateEmitLookup row).tuple[0]? =
      some (bitVecM31
        (selectedPc row.pc row.immediateEncoded (taken row)))
  nextClock :
    (stateEmitLookup row).tuple[1]? =
      some (M31.reduce (row.clock + 1))
  sourceReadOnly :
    (sourceConsumeLookup row 0).tuple[3]? =
        (sourceEmitLookup row 0).tuple[3]? ∧
      (sourceConsumeLookup row 0).tuple[4]? =
        (sourceEmitLookup row 0).tuple[4]? ∧
      (sourceConsumeLookup row 0).tuple[5]? =
        (sourceEmitLookup row 0).tuple[5]? ∧
      (sourceConsumeLookup row 0).tuple[6]? =
        (sourceEmitLookup row 0).tuple[6]? ∧
      (sourceConsumeLookup row 1).tuple[3]? =
        (sourceEmitLookup row 1).tuple[3]? ∧
      (sourceConsumeLookup row 1).tuple[4]? =
        (sourceEmitLookup row 1).tuple[4]? ∧
      (sourceConsumeLookup row 1).tuple[5]? =
        (sourceEmitLookup row 1).tuple[5]? ∧
      (sourceConsumeLookup row 1).tuple[6]? =
        (sourceEmitLookup row 1).tuple[6]?

theorem sound
    (row : Row)
    (witness : Witness row)
    (admissionProof : admission row)
    (accepted : Acceptance row witness) :
    ProductionRefinement row witness := by
  refine {
    selectors := selectorAccepted row witness
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    lookups := lookupProjection row witness
    projection := exactProjectionMetadata row.kind
    programIdentity := exactProgramIdentity row.kind
    nextPc := by simp [stateEmitLookup]
    nextClock := ?_
    sourceReadOnly := by
      simp [sourceConsumeLookup, sourceEmitLookup]
  }
  simp [
    stateEmitLookup,
    TeamACommon.nextClockField row.clock (by
      have := admissionProof.clockBound
      simp [M31.modulus_eq] at *
      omega),
  ]

/-!
### Universal raw-column refinement

As for equality branches, the production row keeps each generated witness and
output independent.  In particular neither MSL normalization, the less-than
bit, the taken bit, source preservation, nor the selected PC is precomputed.
-/

structure RawRow where
  kind : Kind
  clock : Nat
  pc : Word
  rs1 : RegisterIndex
  rs1Previous : WordBytes
  rs1PreviousClock : Nat
  rs1Next : WordBytes
  rs2 : RegisterIndex
  rs2Previous : WordBytes
  rs2PreviousClock : Nat
  rs2Next : WordBytes
  immediateEncoded : BitVec 12
  immediateFelt : M31
  branchTaken : Bool
  comparisonLess : Bool
  selectedPcFelt : M31
deriving DecidableEq, Repr

structure RawWitness (row : RawRow) where
  rs1MostSignificant : M31
  rs2MostSignificant : M31
  marker0 : Bool
  marker1 : Bool
  marker2 : Bool
  marker3 : Bool
  difference : M31

def rawTopKey (row : RawRow) (bytes : WordBytes) : Nat :=
  LtComparator.byteKey row.kind.signed bytes.limb3

def rawTopField (row : RawRow) (bytes : WordBytes) : M31 :=
  M31.reduce (rawTopKey row bytes)

def rawLess (row : RawRow) : Bool :=
  if rawTopField row row.rs1Next = rawTopField row row.rs2Next then
    if bitVecM31 row.rs1Next.limb2 = bitVecM31 row.rs2Next.limb2 then
      if bitVecM31 row.rs1Next.limb1 = bitVecM31 row.rs2Next.limb1 then
        if bitVecM31 row.rs1Next.limb0 = bitVecM31 row.rs2Next.limb0 then
          false
        else
          decide (
            (bitVecM31 row.rs1Next.limb0).val <
              (bitVecM31 row.rs2Next.limb0).val)
      else
        decide (
          (bitVecM31 row.rs1Next.limb1).val <
            (bitVecM31 row.rs2Next.limb1).val)
    else
      decide (
        (bitVecM31 row.rs1Next.limb2).val <
          (bitVecM31 row.rs2Next.limb2).val)
  else
    decide (
      (rawTopField row row.rs1Next).val <
        (rawTopField row row.rs2Next).val)

private theorem wordMsbEqHighByteMsb (bytes : WordBytes) :
    bytes.word.msb = bytes.limb3.msb := by
  rw [WordBytes.word_append]
  bv_decide

private theorem byteMsbEqThreshold (byte : Byte) :
    byte.msb = decide (128 ≤ byte.toNat) := by
  revert byte
  decide

/--
The natural-number key whose ordinary ordering is unsigned word ordering when
`signed = false`, and two's-complement signed word ordering when
`signed = true`.
-/
private def rawOrderedValue (signed : Bool) (bytes : WordBytes) : Nat :=
  bytes.limb0.toNat +
    256 * bytes.limb1.toNat +
    65536 * bytes.limb2.toNat +
    16777216 * LtComparator.byteKey signed bytes.limb3

private def rawOrderedLess
    (signed : Bool) (left right : WordBytes) : Bool :=
  decide (rawOrderedValue signed left < rawOrderedValue signed right)

private theorem rawOrderedLessEqArchitectural
    (signed : Bool) (left right : WordBytes) :
    rawOrderedLess signed left right =
      if signed
      then signedLess left.word right.word
      else decide (left.word.toNat < right.word.toNat) := by
  cases signed
  · simp only [
      rawOrderedLess,
      rawOrderedValue,
      LtComparator.byteKey,
      Bool.false_eq_true,
      ↓reduceIte,
      WordBytes.word_toNat,
      WordBytes.value,
    ]
  · simp only [
      rawOrderedLess,
      rawOrderedValue,
      LtComparator.byteKey,
      ↓reduceIte,
      signedLess,
    ]
    rw [
      wordMsbEqHighByteMsb left,
      wordMsbEqHighByteMsb right,
      byteMsbEqThreshold left.limb3,
      byteMsbEqThreshold right.limb3,
    ]
    simp only [WordBytes.word_toNat, WordBytes.value]
    have left0Bound := left.limb0.isLt
    have left1Bound := left.limb1.isLt
    have left2Bound := left.limb2.isLt
    have left3Bound := left.limb3.isLt
    have right0Bound := right.limb0.isLt
    have right1Bound := right.limb1.isLt
    have right2Bound := right.limb2.isLt
    have right3Bound := right.limb3.isLt
    simp only [Nat.reducePow] at left0Bound left1Bound left2Bound left3Bound right0Bound right1Bound right2Bound right3Bound
    by_cases leftSigned : 128 ≤ left.limb3.toNat <;>
      by_cases rightSigned : 128 ≤ right.limb3.toNat <;>
      simp [leftSigned, rightSigned] <;>
      omega

private theorem rawByteKeyLtModulus
    (signed : Bool) (byte : Byte) :
    LtComparator.byteKey signed byte < M31.modulus := by
  have bound := byte.isLt
  simp only [Nat.reducePow] at bound
  cases signed <;>
    simp [LtComparator.byteKey, M31.modulus_eq] <;>
    omega

private theorem rawLessEqOrdered (row : RawRow) :
    rawLess row =
      rawOrderedLess row.kind.signed row.rs1Next row.rs2Next := by
  let left := row.rs1Next
  let right := row.rs2Next
  have topLeftBound :=
    rawByteKeyLtModulus row.kind.signed left.limb3
  have topRightBound :=
    rawByteKeyLtModulus row.kind.signed right.limb3
  have topEq :
      rawTopField row left = rawTopField row right ↔
        rawTopKey row left = rawTopKey row right := by
    exact M31.reduce_injective_of_lt topLeftBound topRightBound
  have limbEq (leftByte rightByte : Byte) :
      bitVecM31 leftByte = bitVecM31 rightByte ↔
        leftByte.toNat = rightByte.toNat := by
    exact M31.reduce_injective_of_lt
      (by
        have := leftByte.isLt
        simp [M31.modulus_eq] at *
        omega)
      (by
        have := rightByte.isLt
        simp [M31.modulus_eq] at *
        omega)
  have limbVal (byte : Byte) :
      (bitVecM31 byte).val = byte.toNat := by
    exact M31.reduce_val_of_lt _ (by
      have := byte.isLt
      simp [M31.modulus_eq] at *
      omega)
  have topLeftVal :
      (rawTopField row left).val = rawTopKey row left :=
    M31.reduce_val_of_lt _ topLeftBound
  have topRightVal :
      (rawTopField row right).val = rawTopKey row right :=
    M31.reduce_val_of_lt _ topRightBound
  rw [
    rawLess,
    show row.rs1Next = left from rfl,
    show row.rs2Next = right from rfl,
  ]
  simp only [
    topEq,
    limbEq,
    topLeftVal,
    topRightVal,
    limbVal,
  ]
  simp only [rawOrderedLess, rawOrderedValue, rawTopKey]
  have left0Bound := left.limb0.isLt
  have left1Bound := left.limb1.isLt
  have left2Bound := left.limb2.isLt
  have left3Bound :=
    rawByteKeyLtModulus row.kind.signed left.limb3
  have right0Bound := right.limb0.isLt
  have right1Bound := right.limb1.isLt
  have right2Bound := right.limb2.isLt
  have right3Bound :=
    rawByteKeyLtModulus row.kind.signed right.limb3
  simp only [Nat.reducePow] at left0Bound left1Bound left2Bound right0Bound right1Bound right2Bound
  by_cases topEqual :
      LtComparator.byteKey row.kind.signed left.limb3 =
        LtComparator.byteKey row.kind.signed right.limb3
  · by_cases limb2Equal : left.limb2.toNat = right.limb2.toNat
    · by_cases limb1Equal : left.limb1.toNat = right.limb1.toNat
      · by_cases limb0Equal : left.limb0.toNat = right.limb0.toNat
        · simp [topEqual, limb2Equal, limb1Equal, limb0Equal]
        · simp [topEqual, limb2Equal, limb1Equal, limb0Equal]
      · simp [topEqual, limb2Equal, limb1Equal]
        omega
    · simp [topEqual, limb2Equal]
      omega
  · simp [topEqual]
    omega

/--
The raw production comparator is exactly the RV32 signed or unsigned
comparison selected by the opcode.  This closes the byte-lexicographic bridge
from the generated comparator columns back to architectural words.
-/
theorem rawLessEqArchitectural (row : RawRow) :
    rawLess row =
      if row.kind.signed
      then signedLess row.rs1Next.word row.rs2Next.word
      else decide (row.rs1Next.word.toNat < row.rs2Next.word.toNat) := by
  rw [rawLessEqOrdered, rawOrderedLessEqArchitectural]

def rawTaken (row : RawRow) : Bool :=
  if row.kind.lessOpcode then rawLess row else !rawLess row

def rawMarkerSum (witness : RawWitness row) : M31 :=
  boolM31 witness.marker0 +
    boolM31 witness.marker1 +
    boolM31 witness.marker2 +
    boolM31 witness.marker3

def rawSignedOffset (kind : Kind) : M31 :=
  boolM31 kind.signed * M31.reduce 128

def rawSourceOneKey (row : RawRow) (witness : RawWitness row) : M31 :=
  witness.rs1MostSignificant + rawSignedOffset row.kind

def rawSourceTwoKey (row : RawRow) (witness : RawWitness row) : M31 :=
  witness.rs2MostSignificant + rawSignedOffset row.kind

def rawColumns (row : RawRow) (witness : RawWitness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.rs1
  | 3 => bitVecM31 row.rs1Previous.limb0
  | 4 => bitVecM31 row.rs1Previous.limb1
  | 5 => bitVecM31 row.rs1Previous.limb2
  | 6 => bitVecM31 row.rs1Previous.limb3
  | 7 => M31.reduce row.rs1PreviousClock
  | 8 => bitVecM31 row.rs1Next.limb0
  | 9 => bitVecM31 row.rs1Next.limb1
  | 10 => bitVecM31 row.rs1Next.limb2
  | 11 => bitVecM31 row.rs1Next.limb3
  | 12 => bitVecM31 row.rs2
  | 13 => bitVecM31 row.rs2Previous.limb0
  | 14 => bitVecM31 row.rs2Previous.limb1
  | 15 => bitVecM31 row.rs2Previous.limb2
  | 16 => bitVecM31 row.rs2Previous.limb3
  | 17 => M31.reduce row.rs2PreviousClock
  | 18 => bitVecM31 row.rs2Next.limb0
  | 19 => bitVecM31 row.rs2Next.limb1
  | 20 => bitVecM31 row.rs2Next.limb2
  | 21 => bitVecM31 row.rs2Next.limb3
  | 22 => witness.rs1MostSignificant
  | 23 => witness.rs2MostSignificant
  | 24 => row.immediateFelt
  | 25 => boolM31 row.branchTaken
  | 26 => boolM31 row.comparisonLess
  | 27 => boolM31 witness.marker0
  | 28 => boolM31 witness.marker1
  | 29 => boolM31 witness.marker2
  | 30 => boolM31 witness.marker3
  | 31 => witness.difference
  | 32 => row.selectedPcFelt
  | 33 => if row.kind = .blt then 1 else 0
  | 34 => if row.kind = .bltu then 1 else 0
  | 35 => if row.kind = .bge then 1 else 0
  | 36 => if row.kind = .bgeu then 1 else 0
  | _ => 0

def rawEvaluation (row : RawRow) (witness : RawWitness row) :
    SymbolicEvaluation :=
  row.kind.program.evalSymbolic (rawColumns row witness)

structure RawAdmission (row : RawRow) : Prop where
  control :
    Admission row.clock row.rs1PreviousClock row.rs2PreviousClock
      row.pc row.immediateEncoded
  immediateFieldBinds :
    row.immediateFelt = immediateField row.immediateEncoded

def rawProgramLookup (row : RawRow) : EvaluatedLookup where
  ordinal := 33
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce row.kind.manifestId,
    bitVecM31 row.rs1,
    bitVecM31 row.rs2,
    row.immediateFelt
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def rawStateConsumeLookup (row : RawRow) : EvaluatedLookup where
  ordinal := 34
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def rawStateEmitLookup (row : RawRow) : EvaluatedLookup where
  ordinal := 35
  domain := .registersState
  numerator := 1
  tuple := #[row.selectedPcFelt, M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

def rawSourceConsumeLookup
    (row : RawRow) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 36 else 39
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
      bitVecM31 row.rs1Previous.limb0, bitVecM31 row.rs1Previous.limb1,
      bitVecM31 row.rs1Previous.limb2, bitVecM31 row.rs1Previous.limb3
    ] else #[
      0, bitVecM31 row.rs2, M31.reduce row.rs2PreviousClock,
      bitVecM31 row.rs2Previous.limb0, bitVecM31 row.rs2Previous.limb1,
      bitVecM31 row.rs2Previous.limb2, bitVecM31 row.rs2Previous.limb3
    ]
  role := .consume
  tableId := none
  accessOrdinal := some (source.val + 1)

def rawSourceEmitLookup
    (row : RawRow) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 37 else 40
  domain := .memoryAccess
  numerator := 1
  tuple :=
    if source = 0 then #[
      0, bitVecM31 row.rs1, accessClockField row.clock 1,
      bitVecM31 row.rs1Next.limb0, bitVecM31 row.rs1Next.limb1,
      bitVecM31 row.rs1Next.limb2, bitVecM31 row.rs1Next.limb3
    ] else #[
      0, bitVecM31 row.rs2, accessClockField row.clock 2,
      bitVecM31 row.rs2Next.limb0, bitVecM31 row.rs2Next.limb1,
      bitVecM31 row.rs2Next.limb2, bitVecM31 row.rs2Next.limb3
    ]
  role := .emit
  tableId := none
  accessOrdinal := some (source.val + 1)

def rawSourceClockLookup
    (row : RawRow) (source : Fin 2) : EvaluatedLookup where
  ordinal := if source = 0 then 38 else 41
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[
    if source = 0
    then clockGapField row.clock 1 row.rs1PreviousClock
    else clockGapField row.clock 2 row.rs2PreviousClock
  ]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some (source.val + 1)

def rawShiftedMostSignificantLookup
    (row : RawRow) (witness : RawWitness row) : EvaluatedLookup where
  ordinal := 42
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    rawSourceOneKey row witness,
    rawSourceTwoKey row witness
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def rawPositiveDifferenceLookup
    (row : RawRow) (witness : RawWitness row) : EvaluatedLookup where
  ordinal := 43
  domain := .rangeCheck20
  numerator := -rawMarkerSum witness
  tuple := #[witness.difference - 1]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

macro "reduce_branch_lt_raw" : tactic =>
  `(tactic|
    (simp only [
      rawEvaluation,
      Kind.program,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.blt,
      Programs.bltSource,
      Programs.bge,
      Programs.bgeSource,
      Programs.bltu,
      Programs.bltuSource,
      Programs.bgeu,
      Programs.bgeuSource,
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
      rawColumns,
      rawProgramLookup,
      rawStateConsumeLookup,
      rawStateEmitLookup,
      rawSourceConsumeLookup,
      rawSourceEmitLookup,
      rawSourceClockLookup,
      rawShiftedMostSignificantLookup,
      rawPositiveDifferenceLookup,
      rawMarkerSum,
      accessClockField,
      clockGapField,
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
      try simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?
      ] <;>
      try rfl))

set_option maxRecDepth 30000 in
theorem rawSelectorAccepted (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).activeSelectorsAccepted = true := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program] <;>
    reduce_branch_lt_raw <;>
    simp_all <;>
    rfl

set_option maxRecDepth 30000 in
theorem rawLookupProjection (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).lookup? 33 = some (rawProgramLookup row) ∧
      (rawEvaluation row witness).lookup? 34 =
        some (rawStateConsumeLookup row) ∧
      (rawEvaluation row witness).lookup? 35 =
        some (rawStateEmitLookup row) ∧
      (rawEvaluation row witness).lookup? 36 =
        some (rawSourceConsumeLookup row 0) ∧
      (rawEvaluation row witness).lookup? 37 =
        some (rawSourceEmitLookup row 0) ∧
      (rawEvaluation row witness).lookup? 38 =
        some (rawSourceClockLookup row 0) ∧
      (rawEvaluation row witness).lookup? 39 =
        some (rawSourceConsumeLookup row 1) ∧
      (rawEvaluation row witness).lookup? 40 =
        some (rawSourceEmitLookup row 1) ∧
      (rawEvaluation row witness).lookup? 41 =
        some (rawSourceClockLookup row 1) ∧
      (rawEvaluation row witness).lookup? 42 =
        some (rawShiftedMostSignificantLookup row witness) ∧
      (rawEvaluation row witness).lookup? 43 =
        some (rawPositiveDifferenceLookup row witness) := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program] <;>
    reduce_branch_lt_raw <;>
    simp_all [
      EvaluatedEvent.lookup?,
      Kind.manifestId,
      Kind.signed,
      rawSourceOneKey,
      rawSourceTwoKey,
      rawSignedOffset,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      M31.add_zero
    ]

def rawConstraintRoots : Array Nat :=
  #[42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 68, 73, 75,
    91, 93, 95, 97, 99, 101, 103, 105, 107, 108, 113,
    115, 117, 119, 121, 123, 125, 127, 129, 41]

set_option maxHeartbeats 1200000 in
private theorem rawConstraintsHoldEvents
    (kind : Kind)
    (nodes : LocalValues) :
    ((kind.program).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      rawConstraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  cases kind
  · simpa [Kind.program, Programs.blt, Programs.bltSource,
      rawConstraintRoots, Event.evalSymbolic]
  · simpa [Kind.program, Programs.bge, Programs.bgeSource,
      rawConstraintRoots, Event.evalSymbolic]
  · simpa [Kind.program, Programs.bltu, Programs.bltuSource,
      rawConstraintRoots, Event.evalSymbolic]
  · simpa [Kind.program, Programs.bgeu, Programs.bgeuSource,
      rawConstraintRoots, Event.evalSymbolic]

theorem rawConstraintsHold_eq
    (row : RawRow)
    (witness : RawWitness row) :
    (rawEvaluation row witness).constraintsHold =
      rawConstraintRoots.all
        (fun root =>
          (rawEvaluation row witness).nodes.getSymbolic root == 0) := by
  exact
    rawConstraintsHoldEvents row.kind (rawEvaluation row witness).nodes

theorem rawConstraintRootZero
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : (rawEvaluation row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ rawConstraintRoots) :
    (rawEvaluation row witness).nodes.getSymbolic root = 0 := by
  rw [rawConstraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

set_option maxRecDepth 30000 in
set_option maxHeartbeats 1000000 in
private theorem rawSourceNodes
    (row : RawRow)
    (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 115 =
        bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0 ∧
    (rawEvaluation row witness).nodes.getSymbolic 117 =
        bitVecM31 row.rs1Next.limb1 -
          bitVecM31 row.rs1Previous.limb1 ∧
    (rawEvaluation row witness).nodes.getSymbolic 119 =
        bitVecM31 row.rs1Next.limb2 -
          bitVecM31 row.rs1Previous.limb2 ∧
    (rawEvaluation row witness).nodes.getSymbolic 121 =
        bitVecM31 row.rs1Next.limb3 -
          bitVecM31 row.rs1Previous.limb3 ∧
    (rawEvaluation row witness).nodes.getSymbolic 123 =
        bitVecM31 row.rs2Next.limb0 -
          bitVecM31 row.rs2Previous.limb0 ∧
    (rawEvaluation row witness).nodes.getSymbolic 125 =
        bitVecM31 row.rs2Next.limb1 -
          bitVecM31 row.rs2Previous.limb1 ∧
    (rawEvaluation row witness).nodes.getSymbolic 127 =
        bitVecM31 row.rs2Next.limb2 -
          bitVecM31 row.rs2Previous.limb2 ∧
    (rawEvaluation row witness).nodes.getSymbolic 129 =
        bitVecM31 row.rs2Next.limb3 -
          bitVecM31 row.rs2Previous.limb3 := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program]
  all_goals
    refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  all_goals reduce_branch_lt_raw
  all_goals simp [kindCase]

private theorem rawByteEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  TeamACommon.bitVecM31_injective_of_bounds
    left right
    (by have := left.isLt; simp [M31.modulus_eq] at *; omega)
    (by have := right.isLt; simp [M31.modulus_eq] at *; omega)
    equality

theorem rawSourceReadOnly
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : (rawEvaluation row witness).constraintsHold = true) :
    row.rs1Next = row.rs1Previous ∧
      row.rs2Next = row.rs2Previous := by
  have zero (root : Nat) (member : root ∈ rawConstraintRoots) :=
    rawConstraintRootZero row witness accepted root member
  have nodes := rawSourceNodes row witness
  apply And.intro <;> apply WordBytes.eq_of_limbs <;> apply rawByteEq
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.1] using zero 115 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.1] using zero 117 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.1] using zero 119 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.1] using zero 121 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.1] using zero 123 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.2.1] using zero 125 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.2.2.1] using zero 127 (by simp [rawConstraintRoots]))
  · exact (M31.sub_eq_zero_iff _ _).mp
      (by simpa [nodes.2.2.2.2.2.2.2] using zero 129 (by simp [rawConstraintRoots]))

private theorem rawEvalAllSymbolic_append
    (rowValues : Nat → M31)
    (left right : List LocalExprNode)
    (values : List M31) :
    LocalExprNode.evalAllSymbolic rowValues (left ++ right) values =
      LocalExprNode.evalAllSymbolic rowValues right
        (LocalExprNode.evalAllSymbolic rowValues left values) := by
  induction left generalizing values with
  | nil => rfl
  | cons node tail induction =>
      simp only [List.cons_append, LocalExprNode.evalAllSymbolic]
      exact
        induction
          (LocalExprNode.evalSymbolic rowValues values node :: values)

private theorem rawNewestValueSymbolic_evalAllSymbolic
    (rowValues : Nat → M31)
    (nodes : List LocalExprNode)
    (values : List M31)
    (offset : Nat) :
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic rowValues nodes values)
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

private theorem rawGetSymbolic_eq_prefix
    (row : RawRow)
    (witness : RawWitness row)
    (index : Nat)
    (bound : index < row.kind.program.nodes.length) :
    (rawEvaluation row witness).nodes.getSymbolic index =
      newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (rawColumns row witness)
          (row.kind.program.nodes.take (index + 1))
          [])
        0 := by
  change
    newestValueSymbolic
        (LocalExprNode.evalAllSymbolic
          (rawColumns row witness) row.kind.program.nodes [])
        (row.kind.program.nodes.length - index - 1) =
      _
  have offset :
      (row.kind.program.nodes.take (index + 1) ++
            row.kind.program.nodes.drop (index + 1)).length -
            index - 1 =
        (row.kind.program.nodes.drop (index + 1)).length + 0 := by
    simp only [List.length_append, List.length_take, List.length_drop]
    omega
  calc
    newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (rawColumns row witness) row.kind.program.nodes [])
          (row.kind.program.nodes.length - index - 1) =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (rawColumns row witness)
            (row.kind.program.nodes.take (index + 1) ++
              row.kind.program.nodes.drop (index + 1))
            [])
          ((row.kind.program.nodes.take (index + 1) ++
              row.kind.program.nodes.drop (index + 1)).length -
                index - 1) := by
      rw [List.take_append_drop]
    _ =
        newestValueSymbolic
          (LocalExprNode.evalAllSymbolic
            (rawColumns row witness)
            (row.kind.program.nodes.take (index + 1))
            [])
          0 := by
      rw [
        rawEvalAllSymbolic_append,
        offset,
        rawNewestValueSymbolic_evalAllSymbolic,
      ]

private def rawComparisonSign (result : Bool) : M31 :=
  M31.reduce 2 * boolM31 result - 1

private theorem rawComparisonSign_eq (result : Bool) :
    rawComparisonSign result = LtComparator.comparisonSign result := by
  cases result <;> decide

set_option maxRecDepth 34000 in
set_option maxHeartbeats 1200000 in
private theorem rawComparatorNodes
    (row : RawRow)
    (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 73 =
        (bitVecM31 row.rs1Next.limb3 - witness.rs1MostSignificant) *
          (M31.reduce 256 -
            (bitVecM31 row.rs1Next.limb3 -
              witness.rs1MostSignificant)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 75 =
        (bitVecM31 row.rs2Next.limb3 - witness.rs2MostSignificant) *
          (M31.reduce 256 -
            (bitVecM31 row.rs2Next.limb3 -
              witness.rs2MostSignificant)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 91 =
        (1 - boolM31 witness.marker3) *
          (rawComparisonSign row.comparisonLess *
            (witness.rs2MostSignificant -
              witness.rs1MostSignificant)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 93 =
        boolM31 witness.marker3 *
          (witness.difference -
            rawComparisonSign row.comparisonLess *
              (witness.rs2MostSignificant -
                witness.rs1MostSignificant)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 95 =
        (1 - boolM31 witness.marker3 - boolM31 witness.marker2) *
          (rawComparisonSign row.comparisonLess *
            (bitVecM31 row.rs2Next.limb2 -
              bitVecM31 row.rs1Next.limb2)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 97 =
        boolM31 witness.marker2 *
          (witness.difference -
            rawComparisonSign row.comparisonLess *
              (bitVecM31 row.rs2Next.limb2 -
                bitVecM31 row.rs1Next.limb2)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 99 =
        (1 - boolM31 witness.marker3 - boolM31 witness.marker2 -
            boolM31 witness.marker1) *
          (rawComparisonSign row.comparisonLess *
            (bitVecM31 row.rs2Next.limb1 -
              bitVecM31 row.rs1Next.limb1)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 101 =
        boolM31 witness.marker1 *
          (witness.difference -
            rawComparisonSign row.comparisonLess *
              (bitVecM31 row.rs2Next.limb1 -
                bitVecM31 row.rs1Next.limb1)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 103 =
        (1 - rawMarkerSum witness) *
          (rawComparisonSign row.comparisonLess *
            (bitVecM31 row.rs2Next.limb0 -
              bitVecM31 row.rs1Next.limb0)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 105 =
        boolM31 witness.marker0 *
          (witness.difference -
            rawComparisonSign row.comparisonLess *
              (bitVecM31 row.rs2Next.limb0 -
                bitVecM31 row.rs1Next.limb0)) ∧
    (rawEvaluation row witness).nodes.getSymbolic 108 =
        (1 - rawMarkerSum witness) *
          boolM31 row.comparisonLess := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program] <;>
    reduce_branch_lt_raw <;>
    simp [
      kindCase,
      rawMarkerSum,
      rawComparisonSign,
      LtComparator.boolM31,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
    ]

set_option maxRecDepth 34000 in
private theorem rawNode113 (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 113 =
      boolM31 row.comparisonLess -
        (boolM31 row.branchTaken *
            ((if row.kind = .blt then 1 else 0) +
              (if row.kind = .bltu then 1 else 0)) +
          (1 - boolM31 row.branchTaken) *
            ((if row.kind = .bge then 1 else 0) +
              (if row.kind = .bgeu then 1 else 0))) := by
  have programBound (kind : Kind) :
      113 < kind.program.nodes.length := by
    cases kind <;> decide
  cases row with
  | mk kind clock pc rs1 rs1Previous rs1PreviousClock rs1Next rs2
      rs2Previous rs2PreviousClock rs2Next immediateEncoded immediateFelt
      branchTaken comparisonLess selectedPcFelt =>
      cases kind <;>
        rw [rawGetSymbolic_eq_prefix _ witness 113 (programBound _)] <;>
        rfl

theorem rawDecisionFromComparison
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : (rawEvaluation row witness).constraintsHold = true) :
    row.branchTaken =
      if row.kind.lessOpcode
      then row.comparisonLess
      else !row.comparisonLess := by
  have equation :=
    rawConstraintRootZero row witness accepted 113
      (by simp [rawConstraintRoots])
  rw [rawNode113] at equation
  cases kindCase : row.kind <;>
    cases takenCase : row.branchTaken <;>
    cases lessCase : row.comparisonLess <;>
    simp_all [
      Kind.lessOpcode,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31
    ]
  all_goals
    first
    | exact (show (1 : M31) ≠ 0 by decide) equation
    | exact (show (0 : M31) - 1 ≠ 0 by decide) equation

set_option maxRecDepth 30000 in
private theorem rawNode68 (row : RawRow) (witness : RawWitness row) :
    (rawEvaluation row witness).nodes.getSymbolic 68 =
      row.selectedPcFelt -
        (bitVecM31 row.pc +
          row.immediateFelt * boolM31 row.branchTaken +
          M31.reduce 4 * (1 - boolM31 row.branchTaken)) := by
  cases kindCase : row.kind <;>
    simp only [rawEvaluation, kindCase, Kind.program] <;>
    reduce_branch_lt_raw <;>
    simp [kindCase]

theorem rawSelectedPc
    (row : RawRow)
    (witness : RawWitness row)
    (admissionProof : RawAdmission row)
    (accepted : (rawEvaluation row witness).constraintsHold = true) :
    row.selectedPcFelt =
      bitVecM31
        (selectedPc row.pc row.immediateEncoded row.branchTaken) := by
  have equation :=
    rawConstraintRootZero row witness accepted 68
      (by simp [rawConstraintRoots])
  rw [rawNode68] at equation
  have selected :=
    selectedPcField
      row.clock row.rs1PreviousClock row.rs2PreviousClock
      row.pc row.immediateEncoded row.branchTaken admissionProof.control
  rw [admissionProof.immediateFieldBinds, selected] at equation
  exact (M31.sub_eq_zero_iff _ _).mp equation

structure RawAcceptance
    (row : RawRow) (witness : RawWitness row) : Prop where
  constraints : (rawEvaluation row witness).constraintsHold = true
  fixedLookups : (rawEvaluation row witness).fixedLookupsHold = true

private theorem rawMslLookupProjection
    (row : RawRow)
    (witness : RawWitness row) :
    (rawEvaluation row witness).lookup? 42 =
      some (rawShiftedMostSignificantLookup row witness) := by
  rcases rawLookupProjection row witness with
    ⟨_, _, _, _, _, _, _, _, _, selected, _⟩
  exact selected

private theorem rawDifferenceLookupProjection
    (row : RawRow)
    (witness : RawWitness row) :
    (rawEvaluation row witness).lookup? 43 =
      some (rawPositiveDifferenceLookup row witness) := by
  rcases rawLookupProjection row witness with
    ⟨_, _, _, _, _, _, _, _, _, _, selected⟩
  exact selected

theorem rawMslRangeBounds
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness) :
    (rawSourceOneKey row witness).val < 256 ∧
      (rawSourceTwoKey row witness).val < 256 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (rawEvaluation row witness) 42
      (rawShiftedMostSignificantLookup row witness)
      accepted.fixedLookups (rawMslLookupProjection row witness)
  have live :
      (rawShiftedMostSignificantLookup row witness).isLive = true := by
    simp [
      rawShiftedMostSignificantLookup,
      EvaluatedLookup.isLive,
    ]
    decide
  rw [EvaluatedLookup.fixedRequestHolds, live] at request
  have membership :
      FixedTableId.rangeCheck88.contains
        [rawSourceOneKey row witness,
          rawSourceTwoKey row witness] = true := by
    simpa [
      rawShiftedMostSignificantLookup,
      EvaluatedLookup.fixedMembership,
    ] using request
  exact (FixedTableId.rangeCheck88_contains_iff _ _).mp membership

set_option maxRecDepth 30000 in
private theorem rawNegMarkerSumLive
    (marker0 marker1 marker2 marker3 : Bool)
    (anyMarker :
      marker0 = true ∨ marker1 = true ∨
        marker2 = true ∨ marker3 = true) :
    (-(boolM31 marker0 + boolM31 marker1 +
        boolM31 marker2 + boolM31 marker3) != (0 : M31)) = true := by
  cases marker0Case : marker0 <;>
    cases marker1Case : marker1 <;>
    cases marker2Case : marker2 <;>
    cases marker3Case : marker3 <;>
    simp_all [
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
    ] <;>
    decide

private theorem rawPositiveDifferenceLive
    (row : RawRow)
    (witness : RawWitness row)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    (rawPositiveDifferenceLookup row witness).isLive = true := by
  change (-rawMarkerSum witness != (0 : M31)) = true
  exact rawNegMarkerSumLive
    witness.marker0 witness.marker1 witness.marker2 witness.marker3 anyMarker

private theorem rawPositiveDifferenceRequestHolds
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness) :
    (rawPositiveDifferenceLookup row witness).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (rawEvaluation row witness) 43
    (rawPositiveDifferenceLookup row witness)
    accepted.fixedLookups (rawDifferenceLookupProjection row witness)

private theorem rawFixedMembershipOfLiveRequest
    (lookup : EvaluatedLookup)
    (request : lookup.fixedRequestHolds = true)
    (live : lookup.isLive = true) :
    lookup.fixedMembership.getD true = true := by
  rw [EvaluatedLookup.fixedRequestHolds, live] at request
  exact request

private theorem rawFixedMembershipEqOfTableId
    (lookup : EvaluatedLookup)
    (table : FixedTableId)
    (tableId : lookup.tableId = some table) :
    lookup.fixedMembership.getD true =
      table.contains lookup.tuple.toList := by
  simp only [
    EvaluatedLookup.fixedMembership,
    tableId,
    Option.map,
    Option.getD
  ]

private theorem rawPositiveDifferenceMembership
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    FixedTableId.rangeCheck20.contains
      (#[witness.difference - 1]).toList = true := by
  have request :=
    rawPositiveDifferenceRequestHolds row witness accepted
  have live := rawPositiveDifferenceLive row witness anyMarker
  have membership :=
    rawFixedMembershipOfLiveRequest
      (rawPositiveDifferenceLookup row witness) request live
  have tableId :
      (rawPositiveDifferenceLookup row witness).tableId =
        some .rangeCheck20 := rfl
  rw [rawFixedMembershipEqOfTableId
    (rawPositiveDifferenceLookup row witness) .rangeCheck20 tableId] at membership
  change FixedTableId.rangeCheck20.contains
    (#[witness.difference - 1]).toList = true at membership
  exact membership

private theorem rawRangeCheck20BoundOfSingletonMembership
    (value : M31)
    (membership :
      FixedTableId.rangeCheck20.contains (#[value]).toList = true) :
    value.val < 2 ^ 20 := by
  have listMembership :
      FixedTableId.rangeCheck20.contains [value] = true := by
    simpa only [Array.toList] using membership
  exact (FixedTableId.rangeCheck20_contains_iff _).mp listMembership

theorem rawDifferenceGapBound
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    (witness.difference - 1).val < 2 ^ 20 :=
  rawRangeCheck20BoundOfSingletonMembership _
    (rawPositiveDifferenceMembership row witness accepted anyMarker)

theorem rawDifferencePositive
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    0 < witness.difference.val := by
  have gapBound :=
    rawDifferenceGapBound row witness accepted anyMarker
  by_cases positive : 0 < witness.difference.val
  · exact positive
  · have zeroValue : witness.difference.val = 0 := by omega
    have differenceZero : witness.difference = 0 :=
      M31.ext zeroValue
    rw [differenceZero] at gapBound
    have impossible : M31.modulus - 1 < 2 ^ 20 := by
      simpa [M31.sub_val_of_lt] using gapBound
    simp [M31.modulus_eq] at impossible

theorem rawDifferenceBound
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    witness.difference.val ≤ 2 ^ 20 := by
  have positive :=
    rawDifferencePositive row witness accepted anyMarker
  have gapBound :=
    rawDifferenceGapBound row witness accepted anyMarker
  have oneValue : (1 : M31).val = 1 := by decide
  have differenceSub :
      (witness.difference - 1).val =
        witness.difference.val - 1 := by
    rw [M31.sub_val_of_le]
    · rfl
    · simpa [oneValue] using positive
  rw [differenceSub] at gapBound
  omega

theorem rawTopKeyBound
    (row : RawRow) (bytes : WordBytes) :
    rawTopKey row bytes < 256 := by
  simp only [rawTopKey, LtComparator.byteKey]
  split
  · exact Nat.mod_lt _ (by decide)
  · simpa using bytes.limb3.isLt

@[simp]
theorem rawTopField_val
    (row : RawRow) (bytes : WordBytes) :
    (rawTopField row bytes).val = rawTopKey row bytes := by
  apply M31.reduce_val_of_lt
  have bound := rawTopKeyBound row bytes
  simp only [M31.modulus_eq]
  omega

private theorem rawByteFieldVal (byte : Byte) :
    (bitVecM31 byte).val = byte.toNat :=
  Lui.bitVecM31_val byte (by
    have bound := byte.isLt
    simp only [Nat.reducePow] at bound
    simp only [M31.modulus_eq]
    omega)

private theorem rawByteFieldBound (byte : Byte) :
    (bitVecM31 byte).val < 256 := by
  rw [rawByteFieldVal]
  simpa using byte.isLt

theorem rawNormalizedKeys
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness) :
    (rawSourceOneKey row witness).val =
        LtComparator.byteKey row.kind.signed row.rs1Next.limb3 ∧
      (rawSourceTwoKey row witness).val =
        LtComparator.byteKey row.kind.signed row.rs2Next.limb3 := by
  have bounds := rawMslRangeBounds row witness accepted
  rcases rawComparatorNodes row witness with
    ⟨node73, node75, _, _, _, _, _, _, _, _, _⟩
  have firstRoot :=
    rawConstraintRootZero row witness accepted.constraints 73
      (by simp [rawConstraintRoots])
  have secondRoot :=
    rawConstraintRootZero row witness accepted.constraints 75
      (by simp [rawConstraintRoots])
  rw [node73] at firstRoot
  rw [node75] at secondRoot
  exact ⟨
    by
      simpa [rawSourceOneKey, rawSignedOffset] using
        LtComparator.normalizedKey row.kind.signed row.rs1Next.limb3
          witness.rs1MostSignificant bounds.1 firstRoot,
    by
      simpa [rawSourceTwoKey, rawSignedOffset] using
        LtComparator.normalizedKey row.kind.signed row.rs2Next.limb3
          witness.rs2MostSignificant bounds.2 secondRoot
  ⟩

private theorem rawTopDifference
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness) :
    witness.rs2MostSignificant - witness.rs1MostSignificant =
      rawTopField row row.rs2Next -
        rawTopField row row.rs1Next := by
  have keys := rawNormalizedKeys row witness accepted
  have leftTop :
      rawSourceOneKey row witness =
        rawTopField row row.rs1Next := by
    apply M31.ext
    simpa [rawTopKey] using keys.1
  have rightTop :
      rawSourceTwoKey row witness =
        rawTopField row row.rs2Next := by
    apply M31.ext
    simpa [rawTopKey] using keys.2
  calc
    witness.rs2MostSignificant - witness.rs1MostSignificant =
        rawSourceTwoKey row witness -
          rawSourceOneKey row witness := by
      simpa [rawSourceOneKey, rawSourceTwoKey] using
        LtComparator.translatedSub
          witness.rs1MostSignificant witness.rs2MostSignificant
            (rawSignedOffset row.kind)
    _ = rawTopField row row.rs2Next -
          rawTopField row row.rs1Next := by
      rw [leftTop, rightTop]

def rawComparatorContract
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness) :
    LtComparator.ComparatorContract := by
  refine {
    result := row.comparisonLess
    leftTop := rawTopField row row.rs1Next
    rightTop := rawTopField row row.rs2Next
    left2 := bitVecM31 row.rs1Next.limb2
    right2 := bitVecM31 row.rs2Next.limb2
    left1 := bitVecM31 row.rs1Next.limb1
    right1 := bitVecM31 row.rs2Next.limb1
    left0 := bitVecM31 row.rs1Next.limb0
    right0 := bitVecM31 row.rs2Next.limb0
    marker0 := witness.marker0
    marker1 := witness.marker1
    marker2 := witness.marker2
    marker3 := witness.marker3
    difference := witness.difference
    leftTopBound := by simpa using rawTopKeyBound row row.rs1Next
    rightTopBound := by simpa using rawTopKeyBound row row.rs2Next
    left2Bound := rawByteFieldBound _
    right2Bound := rawByteFieldBound _
    left1Bound := rawByteFieldBound _
    right1Bound := rawByteFieldBound _
    left0Bound := rawByteFieldBound _
    right0Bound := rawByteFieldBound _
    differencePositive := rawDifferencePositive row witness accepted
    differenceBound := rawDifferenceBound row witness accepted
    topEqual := ?_
    topSelected := ?_
    limb2Equal := ?_
    limb2Selected := ?_
    limb1Equal := ?_
    limb1Selected := ?_
    limb0Equal := ?_
    limb0Selected := ?_
    noMarkerResult := ?_
  }
  · intro markerOff
    rcases rawComparatorNodes row witness with
      ⟨_, _, node91, _, _, _, _, _, _, _, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 91
        (by simp [rawConstraintRoots])
    rw [node91, markerOff] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    rw [rawComparisonSign_eq,
      rawTopDifference row witness accepted] at equation
    exact equation
  · intro markerOn
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, node93, _, _, _, _, _, _, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 93
        (by simp [rawConstraintRoots])
    rw [node93, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected := (M31.sub_eq_zero_iff _ _).mp equation
    rw [rawComparisonSign_eq,
      rawTopDifference row witness accepted] at selected
    exact selected
  · intro marker3Off marker2Off
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, _, node95, _, _, _, _, _, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 95
        (by simp [rawConstraintRoots])
    rw [node95, marker3Off, marker2Off] at equation
    simpa [boolM31, TeamACommon.boolM31, Lui.boolM31,
      rawComparisonSign_eq] using equation
  · intro markerOn
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, _, _, node97, _, _, _, _, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 97
        (by simp [rawConstraintRoots])
    rw [node97, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected := (M31.sub_eq_zero_iff _ _).mp equation
    simpa [rawComparisonSign_eq] using selected
  · intro marker3Off marker2Off marker1Off
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, _, _, _, node99, _, _, _, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 99
        (by simp [rawConstraintRoots])
    rw [node99, marker3Off, marker2Off, marker1Off] at equation
    simpa [boolM31, TeamACommon.boolM31, Lui.boolM31,
      rawComparisonSign_eq] using equation
  · intro markerOn
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, _, _, _, _, node101, _, _, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 101
        (by simp [rawConstraintRoots])
    rw [node101, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected := (M31.sub_eq_zero_iff _ _).mp equation
    simpa [rawComparisonSign_eq] using selected
  · intro marker3Off marker2Off marker1Off marker0Off
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, _, _, _, _, _, node103, _, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 103
        (by simp [rawConstraintRoots])
    rw [node103] at equation
    simpa [rawMarkerSum, boolM31, TeamACommon.boolM31,
      Lui.boolM31, rawComparisonSign_eq, marker3Off, marker2Off,
      marker1Off, marker0Off] using equation
  · intro markerOn
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, _, _, _, _, _, _, node105, _⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 105
        (by simp [rawConstraintRoots])
    rw [node105, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected := (M31.sub_eq_zero_iff _ _).mp equation
    simpa [rawComparisonSign_eq] using selected
  · intro marker3Off marker2Off marker1Off marker0Off
    rcases rawComparatorNodes row witness with
      ⟨_, _, _, _, _, _, _, _, _, _, node108⟩
    have equation :=
      rawConstraintRootZero row witness accepted.constraints 108
        (by simp [rawConstraintRoots])
    rw [node108] at equation
    simp [rawMarkerSum, boolM31, TeamACommon.boolM31,
      Lui.boolM31, marker3Off, marker2Off, marker1Off,
      marker0Off] at equation
    cases resultCase : row.comparisonLess
    · rfl
    · have impossible : (1 : M31) = 0 := by
        simpa [resultCase, boolM31, TeamACommon.boolM31,
          Lui.boolM31] using equation
      exact False.elim ((by decide : (1 : M31) ≠ 0) impossible)

theorem rawComparisonCorrect
    (row : RawRow)
    (witness : RawWitness row)
    (accepted : RawAcceptance row witness) :
    row.comparisonLess = rawLess row := by
  simpa [
    rawComparatorContract,
    LtComparator.ComparatorContract.lexicographicLess,
    rawLess,
  ] using
    LtComparator.comparisonCorrectOfContract
      (rawComparatorContract row witness accepted)

structure RawProductionRefinement
    (row : RawRow) (witness : RawWitness row) : Prop where
  selectors : (rawEvaluation row witness).activeSelectorsAccepted = true
  constraints : (rawEvaluation row witness).constraintsHold = true
  fixedLookups : (rawEvaluation row witness).fixedLookupsHold = true
  lookups :
    (rawEvaluation row witness).lookup? 33 = some (rawProgramLookup row) ∧
      (rawEvaluation row witness).lookup? 34 =
        some (rawStateConsumeLookup row) ∧
      (rawEvaluation row witness).lookup? 35 =
        some (rawStateEmitLookup row) ∧
      (rawEvaluation row witness).lookup? 36 =
        some (rawSourceConsumeLookup row 0) ∧
      (rawEvaluation row witness).lookup? 37 =
        some (rawSourceEmitLookup row 0) ∧
      (rawEvaluation row witness).lookup? 38 =
        some (rawSourceClockLookup row 0) ∧
      (rawEvaluation row witness).lookup? 39 =
        some (rawSourceConsumeLookup row 1) ∧
      (rawEvaluation row witness).lookup? 40 =
        some (rawSourceEmitLookup row 1) ∧
      (rawEvaluation row witness).lookup? 41 =
        some (rawSourceClockLookup row 1) ∧
      (rawEvaluation row witness).lookup? 42 =
        some (rawShiftedMostSignificantLookup row witness) ∧
      (rawEvaluation row witness).lookup? 43 =
        some (rawPositiveDifferenceLookup row witness)
  projection :
    row.kind.program.source.projection.programEvent = 33 ∧
      row.kind.program.source.projection.sourceEvents = #[36, 37, 39, 40] ∧
      row.kind.program.source.projection.destinationEvents = #[] ∧
      row.kind.program.source.projection.stateEvents = #[34, 35] ∧
      row.kind.program.source.projection.nextPc = 32
  programIdentity :
    row.kind.program.source.contentDigest = row.kind.contentDigest ∧
      row.kind.program.source.family = .branchLt ∧
      row.kind.program.source.nodes.size = 159 ∧
      row.kind.program.source.events.size = 44
  immediate :
    row.immediateFelt = immediateField row.immediateEncoded
  sourceReadOnly :
    row.rs1Next = row.rs1Previous ∧ row.rs2Next = row.rs2Previous
  comparison :
    row.comparisonLess = rawLess row
  decision :
    row.branchTaken = rawTaken row
  nextPc :
    (rawStateEmitLookup row).tuple[0]? =
      some (bitVecM31
        (selectedPc row.pc row.immediateEncoded (rawTaken row)))
  nextClock :
    (rawStateEmitLookup row).tuple[1]? =
      some (M31.reduce (row.clock + 1))

theorem rawSound
    (row : RawRow)
    (witness : RawWitness row)
    (admissionProof : RawAdmission row)
    (accepted : RawAcceptance row witness) :
    RawProductionRefinement row witness := by
  have comparison := rawComparisonCorrect row witness accepted
  have decision :
      row.branchTaken = rawTaken row := by
    rw [rawTaken, ← comparison]
    exact rawDecisionFromComparison row witness accepted.constraints
  refine {
    selectors := rawSelectorAccepted row witness
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    lookups := rawLookupProjection row witness
    projection := exactProjectionMetadata row.kind
    programIdentity := exactProgramIdentity row.kind
    immediate := admissionProof.immediateFieldBinds
    sourceReadOnly :=
      rawSourceReadOnly row witness accepted.constraints
    comparison := comparison
    decision := decision
    nextPc := ?_
    nextClock := ?_
  }
  · simp [
      rawStateEmitLookup,
      rawSelectedPc row witness admissionProof accepted.constraints,
      decision,
    ]
  · simp [
      rawStateEmitLookup,
      TeamACommon.nextClockField row.clock (by
        have := admissionProof.control.clockBound
        simp [M31.modulus_eq] at *
        omega),
    ]

def exampleValue (value : Nat) : WordBytes where
  limb0 := BitVec.ofNat 8 value
  limb1 := BitVec.ofNat 8 0
  limb2 := BitVec.ofNat 8 0
  limb3 := BitVec.ofNat 8 0

def exampleLess (kind : Kind) (requestedTaken : Bool) : Bool :=
  if kind.lessOpcode then requestedTaken else !requestedTaken

def exampleRow (kind : Kind) (requestedTaken : Bool) : Row where
  kind := kind
  clock := 7
  pc := BitVec.ofNat 32 0x1000
  rs1 := BitVec.ofNat 5 3
  rs1Value := exampleValue (if exampleLess kind requestedTaken then 0 else 1)
  rs1PreviousClock := 0
  rs2 := BitVec.ofNat 5 4
  rs2Value := exampleValue (if exampleLess kind requestedTaken then 1 else 0)
  rs2PreviousClock := 1
  immediateEncoded := BitVec.ofNat 12 8

def exampleWitness
    (kind : Kind) (requestedTaken : Bool) :
    Witness (exampleRow kind requestedTaken) where
  marker0 := true
  marker1 := false
  marker2 := false
  marker3 := false
  difference := 1

theorem exampleTaken (kind : Kind) (requestedTaken : Bool) :
    taken (exampleRow kind requestedTaken) = requestedTaken := by
  cases kind <;> cases requestedTaken <;> decide

theorem exampleAdmission (kind : Kind) (requestedTaken : Bool) :
    admission (exampleRow kind requestedTaken) := by
  cases kind <;> cases requestedTaken <;>
  refine {
    clockPositive := by decide
    clockBound := by decide
    rs1PreviousBound := by decide
    rs2PreviousBound := by decide
    fallthroughBound := by decide
    targetNoWrap := by decide
    targetAligned := by decide
  }

set_option maxRecDepth 50000 in
set_option maxHeartbeats 2000000 in
theorem exampleAcceptance (kind : Kind) (requestedTaken : Bool) :
    Acceptance (exampleRow kind requestedTaken)
      (exampleWitness kind requestedTaken) := by
  cases kind <;> cases requestedTaken <;>
    constructor <;>
    simp only [
      exampleRow,
      exampleWitness,
      exampleValue,
      exampleLess,
      Kind.lessOpcode
    ] <;>
    reduce_branch_lt <;>
    try simp [
      taken,
      less,
      signedLess,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      Kind.signed,
      Kind.lessOpcode,
      mostSignificantField,
      signedByteField,
      M31.toNat,
      M31.reduce,
      M31.modulus
    ] <;>
    try decide

theorem takenAndFallthroughNonvacuous (kind : Kind) :
    (∃ row witness,
      admission row ∧
        Acceptance row witness ∧
        ProductionRefinement row witness ∧
        taken row = true) ∧
    (∃ row witness,
      admission row ∧
        Acceptance row witness ∧
        ProductionRefinement row witness ∧
        taken row = false) := by
  constructor
  · refine ⟨exampleRow kind true, exampleWitness kind true,
      exampleAdmission kind true, exampleAcceptance kind true, ?_,
      exampleTaken kind true⟩
    exact sound _ _ (exampleAdmission kind true) (exampleAcceptance kind true)
  · refine ⟨exampleRow kind false, exampleWitness kind false,
      exampleAdmission kind false, exampleAcceptance kind false, ?_,
      exampleTaken kind false⟩
    exact sound _ _ (exampleAdmission kind false) (exampleAcceptance kind false)

end Lt

end RiscvRefinement.Air.Bridge.Branches
