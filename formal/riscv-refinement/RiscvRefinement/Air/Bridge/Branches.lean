import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Bridge.DecodeBranches

/-!
# Production branch AIR bridges

This module evaluates the six exact generated branch programs.  The typed rows
are the canonical runner rows: source emissions repeat source consumptions,
the branch decision is computed from the two source words, and the generated
comparison witnesses remain explicit.  Thus the refinement does not assume a
prover-supplied branch decision.
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
  | .beq => "fb2353552d0fbba572e0d7017f418505aedb9b5b715ff97a565b74cc7103d2bd"
  | .bne => "9b3d05be9b95c41f0797825ac535dd426461d74e9ff9914d58f28dd27339c6b5"

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
  | 23 => boolM31 (taken row)
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
  | .blt => "573e558380032a31fdbebeab96de9c302ff33aeaabdb261e432e572b37911fc7"
  | .bge => "f395e8d96e972262428a89129eb5d119642d8a13d2692bbc2564305d388350aa"
  | .bltu => "c757852363ba430f104c45b15f669bd2f57c6df6b97b645420ebbd332c9bc2c4"
  | .bgeu => "7e57913c67680548a90fd90661f52a36e6dc9ba93a26dd097bc106706114e54d"

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
  | 22 => mostSignificantField row.kind.signed row.rs1Value
  | 23 => mostSignificantField row.kind.signed row.rs2Value
  | 24 => immediateField row.immediateEncoded
  | 25 => boolM31 (taken row)
  | 26 => boolM31 (less row)
  | 27 => boolM31 witness.marker0
  | 28 => boolM31 witness.marker1
  | 29 => boolM31 witness.marker2
  | 30 => boolM31 witness.marker3
  | 31 => witness.difference
  | 32 => bitVecM31
      (selectedPc row.pc row.immediateEncoded (taken row))
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
