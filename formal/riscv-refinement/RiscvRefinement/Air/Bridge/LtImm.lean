import RiscvRefinement.Air.Bridge.LtReg

/-!
# Production SLTI/SLTIU AIR bridge

The typed row is the canonical runner row: the source emission is the value
consumed, the comparison bit and destination bytes are architectural
functions, and only the first-difference and inverse columns remain explicit
witnesses.  Both exact 37-column generated programs are evaluated directly.
-/

namespace RiscvRefinement.Air.Bridge.LtImm

open RiscvRefinement
open RiscvRefinement.Air.Generated

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

abbrev Kind := LtReg.Kind

def manifestId : Kind → Nat
  | .signed => 11
  | .unsigned => 12

def contentDigest : Kind → String
  | .signed =>
      "f94708caa7efc55cc42107fda4d38a82f386d3ca239da3e51dd9dc5d0630adba"
  | .unsigned =>
      "912355ff223a0b48c5684ec22c05d8ab304468e16c7ec5030f8f41b4d1484e42"

def program : Kind → LocalProgram
  | .signed => Programs.slti
  | .unsigned => Programs.sltiu

theorem programContentDigest (kind : Kind) :
    (program kind).source.contentDigest = contentDigest kind := by
  cases kind <;> decide

def isSigned : Kind → Bool := LtReg.isSigned

def imm0 (immediate : BitVec 12) : Byte :=
  BitVec.extractLsb 7 0 immediate

def imm1 (immediate : BitVec 12) : BitVec 3 :=
  BitVec.extractLsb 10 8 immediate

def immMsb (immediate : BitVec 12) : BitVec 1 :=
  BitVec.extractLsb 11 11 immediate

def immSign (immediate : BitVec 12) : Bool :=
  (immMsb immediate).toNat = 1

def immediateBytes (immediate : BitVec 12) : WordBytes :=
  let sign := immSign immediate
  {
    limb0 := imm0 immediate
    limb1 := BitVec.ofNat 8
      ((imm1 immediate).toNat + if sign then 248 else 0)
    limb2 := BitVec.ofNat 8 (if sign then 255 else 0)
    limb3 := BitVec.ofNat 8 (if sign then 255 else 0)
  }

def comparison
    (kind : Kind)
    (source : WordBytes)
    (immediate : BitVec 12) :
    Bool :=
  LtReg.semanticLess kind source (immediateBytes immediate)

def resultBytes (result : Bool) : WordBytes :=
  LtReg.comparisonBytes result

def destinationNonzero (rd : RegisterIndex) : Bool :=
  decide (rd ≠ zeroRegister)

def destinationBytes
    (rd : RegisterIndex)
    (result : Bool) :
    WordBytes :=
  if destinationNonzero rd then resultBytes result else WordBytes.zero

structure Row where
  kind : Kind
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

structure Witness (row : Row) where
  marker0 : Bool
  marker1 : Bool
  marker2 : Bool
  marker3 : Bool
  difference : Byte
  destinationInverse : M31

def markerPrefix (witness : Witness row) : M31 :=
  ((boolM31 witness.marker0 + boolM31 witness.marker1) +
      boolM31 witness.marker2) +
    boolM31 witness.marker3

def accessClock (row : Row) (ordinal : Nat) : M31 :=
  TeamACommon.accessClockField row.clock ordinal

def clockGap (row : Row) (ordinal previous : Nat) : M31 :=
  TeamACommon.clockGapField row.clock ordinal previous

def columns (row : Row) (witness : Witness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.rd
  | 3 => bitVecM31 row.rdPrevious.limb0
  | 4 => bitVecM31 row.rdPrevious.limb1
  | 5 => bitVecM31 row.rdPrevious.limb2
  | 6 => bitVecM31 row.rdPrevious.limb3
  | 7 => M31.reduce row.rdPreviousClock
  | 8 =>
      bitVecM31
        (destinationBytes row.rd
          (comparison row.kind row.rs1Value row.immediate)).limb0
  | 9 =>
      bitVecM31
        (destinationBytes row.rd
          (comparison row.kind row.rs1Value row.immediate)).limb1
  | 10 =>
      bitVecM31
        (destinationBytes row.rd
          (comparison row.kind row.rs1Value row.immediate)).limb2
  | 11 =>
      bitVecM31
        (destinationBytes row.rd
          (comparison row.kind row.rs1Value row.immediate)).limb3
  | 12 => bitVecM31 row.rs1
  | 13 => bitVecM31 row.rs1Value.limb0
  | 14 => bitVecM31 row.rs1Value.limb1
  | 15 => bitVecM31 row.rs1Value.limb2
  | 16 => bitVecM31 row.rs1Value.limb3
  | 17 => M31.reduce row.rs1PreviousClock
  | 18 => bitVecM31 row.rs1Value.limb0
  | 19 => bitVecM31 row.rs1Value.limb1
  | 20 => bitVecM31 row.rs1Value.limb2
  | 21 => bitVecM31 row.rs1Value.limb3
  | 22 => boolM31 (comparison row.kind row.rs1Value row.immediate)
  | 23 => LtReg.mslField row.kind row.rs1Value
  | 24 => bitVecM31 (imm0 row.immediate)
  | 25 => bitVecM31 (imm1 row.immediate)
  | 26 => bitVecM31 (immMsb row.immediate)
  | 27 => boolM31 (isSigned row.kind)
  | 28 => boolM31 (!(isSigned row.kind))
  | 29 => boolM31 witness.marker0
  | 30 => boolM31 witness.marker1
  | 31 => boolM31 witness.marker2
  | 32 => boolM31 witness.marker3
  | 33 => bitVecM31 witness.difference
  | 34 => boolM31 (destinationNonzero row.rd)
  | 35 => witness.destinationInverse
  | 36 => LtReg.mslField row.kind (immediateBytes row.immediate)
  | _ => 0

def evaluation (row : Row) (witness : Witness row) : SymbolicEvaluation :=
  (program row.kind).evalSymbolic (columns row witness)

def immediateField (row : Row) : M31 :=
  bitVecM31 (imm0 row.immediate) +
    bitVecM31 (imm1 row.immediate) * M31.reduce 256 +
    bitVecM31 (immMsb row.immediate) * M31.reduce 2048

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 33
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc, M31.reduce (manifestId row.kind),
    bitVecM31 row.rd, bitVecM31 row.rs1, immediateField row
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def immediateRangeLookup (row : Row) : EvaluatedLookup where
  ordinal := 34
  domain := .rangeCheck884
  numerator := -(1 : M31)
  tuple := #[
    LtReg.mslField row.kind row.rs1Value +
      boolM31 (isSigned row.kind) * M31.reduce 128,
    bitVecM31 (imm0 row.immediate),
    bitVecM31 (imm1 row.immediate) * M31.reduce 2
  ]
  role := .request
  tableId := some .rangeCheck884
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 35
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 36
  domain := .registersState
  numerator := 1
  tuple := #[bitVecM31 row.pc + M31.reduce 4, M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

def sourceConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 37
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rs1, M31.reduce row.rs1PreviousClock,
    bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
    bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 1

def sourceEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 38
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rs1, accessClock row 1,
    bitVecM31 row.rs1Value.limb0, bitVecM31 row.rs1Value.limb1,
    bitVecM31 row.rs1Value.limb2, bitVecM31 row.rs1Value.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 1

def sourceClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 39
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGap row 1 row.rs1PreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 1

def positiveDifferenceLookup
    (row : Row)
    (witness : Witness row) :
    EvaluatedLookup where
  ordinal := 40
  domain := .rangeCheck20
  numerator := -markerPrefix witness
  tuple := #[bitVecM31 witness.difference - 1]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 41
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rd, M31.reduce row.rdPreviousClock,
    bitVecM31 row.rdPrevious.limb0, bitVecM31 row.rdPrevious.limb1,
    bitVecM31 row.rdPrevious.limb2, bitVecM31 row.rdPrevious.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 2

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 42
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rd, accessClock row 2,
    bitVecM31
      (destinationBytes row.rd
        (comparison row.kind row.rs1Value row.immediate)).limb0,
    bitVecM31
      (destinationBytes row.rd
        (comparison row.kind row.rs1Value row.immediate)).limb1,
    bitVecM31
      (destinationBytes row.rd
        (comparison row.kind row.rs1Value row.immediate)).limb2,
    bitVecM31
      (destinationBytes row.rd
        (comparison row.kind row.rs1Value row.immediate)).limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 2

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 43
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGap row 2 row.rdPreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 2

macro "reduce_ltimm" : tactic =>
  `(tactic|
    (simp_all only [
      program,
      evaluation,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.slti,
      Programs.sltiSource,
      Programs.sltiu,
      Programs.sltiuSource,
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
      manifestId,
      isSigned,
      LtReg.isSigned,
      imm0,
      imm1,
      immMsb,
      immSign,
      immediateBytes,
      comparison,
      LtReg.semanticLess,
      LtReg.topKey,
      resultBytes,
      LtReg.comparisonBytes,
      destinationNonzero,
      destinationBytes,
      markerPrefix,
      accessClock,
      clockGap,
      immediateField,
      programLookup,
      immediateRangeLookup,
      stateConsumeLookup,
      stateEmitLookup,
      sourceConsumeLookup,
      sourceEmitLookup,
      sourceClockLookup,
      positiveDifferenceLookup,
      destinationConsumeLookup,
      destinationEmitLookup,
      destinationClockLookup,
      LtReg.mslField,
      LtReg.signedMsl,
      boolM31,
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      TeamACommon.boolM31,
      Lui.boolM31,
      SymbolicEvaluation.activeSelectorsAccepted,
      SymbolicEvaluation.constraintsHold,
      SymbolicEvaluation.fixedLookupsHold,
      SymbolicEvaluation.lookup?,
      M31.ofNat?,
      M31.add_zero,
      M31.zero_add,
      M31.mul_zero,
      M31.zero_mul,
      M31.one_mul,
      M31.mul_one,
      M31.sub_zero
    ] <;>
      simp [
        LocalValues.getSymbolic,
        newestValueSymbolic,
        Event.evalSymbolic,
        M31.ofNat?,
        FixedTableId.contains,
        M31.modulus_eq
      ]))

set_option maxRecDepth 30000 in
theorem selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals constructor <;> apply M31.ext <;> rfl

def expectedLookup? (row : Row) (witness : Witness row) :
    Nat → Option EvaluatedLookup
  | 33 => some (programLookup row)
  | 34 => some (immediateRangeLookup row)
  | 35 => some (stateConsumeLookup row)
  | 36 => some (stateEmitLookup row)
  | 37 => some (sourceConsumeLookup row)
  | 38 => some (sourceEmitLookup row)
  | 39 => some (sourceClockLookup row)
  | 40 => some (positiveDifferenceLookup row witness)
  | 41 => some (destinationConsumeLookup row)
  | 42 => some (destinationEmitLookup row)
  | 43 => some (destinationClockLookup row)
  | _ => none

theorem generatedEventOrder (kind : Kind) :
    ((program kind).source.events[33]?).map Event.ordinal = some 33 ∧
      ((program kind).source.events[34]?).map Event.ordinal = some 34 ∧
      ((program kind).source.events[35]?).map Event.ordinal = some 35 ∧
      ((program kind).source.events[36]?).map Event.ordinal = some 36 ∧
      ((program kind).source.events[37]?).map Event.ordinal = some 37 ∧
      ((program kind).source.events[38]?).map Event.ordinal = some 38 ∧
      ((program kind).source.events[39]?).map Event.ordinal = some 39 ∧
      ((program kind).source.events[40]?).map Event.ordinal = some 40 ∧
      ((program kind).source.events[41]?).map Event.ordinal = some 41 ∧
      ((program kind).source.events[42]?).map Event.ordinal = some 42 ∧
      ((program kind).source.events[43]?).map Event.ordinal = some 43 := by
  cases kind <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem lookupProjection
    (row : Row)
    (witness : Witness row)
    (ordinal : Nat)
    (lower : 33 ≤ ordinal)
    (upper : ordinal ≤ 43) :
    (evaluation row witness).lookup? ordinal =
      expectedLookup? row witness ordinal := by
  have cases :
      ordinal = 33 ∨ ordinal = 34 ∨ ordinal = 35 ∨ ordinal = 36 ∨
      ordinal = 37 ∨ ordinal = 38 ∨ ordinal = 39 ∨ ordinal = 40 ∨
      ordinal = 41 ∨ ordinal = 42 ∨ ordinal = 43 := by
    omega
  rcases cases with h | h | h | h | h | h | h | h | h | h | h <;>
    subst ordinal <;> cases kind : row.kind
  all_goals simp only [expectedLookup?]
  all_goals reduce_ltimm
  all_goals simp [EvaluatedEvent.lookup?]

theorem projectionMetadata (kind : Kind) :
    (program kind).source.projection.programEvent = 33 ∧
      (program kind).source.projection.stateEvents = #[35, 36] ∧
      (program kind).source.projection.sourceEvents = #[37, 38] ∧
      (program kind).source.projection.destinationEvents = #[41, 42] ∧
      (program kind).source.projection.nextPc = 157 := by
  cases kind <;> decide

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  pcBound : row.pc.toNat + 4 < M31.modulus
  sourcePreviousBound : row.rs1PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true

structure ProductionRefinement (row : Row) (witness : Witness row) : Prop where
  sourceDigest :
    (program row.kind).source.contentDigest = contentDigest row.kind
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true
  exactLookups :
    ∀ ordinal, 33 ≤ ordinal → ordinal ≤ 43 →
      (evaluation row witness).lookup? ordinal =
        expectedLookup? row witness ordinal
  eventOrder :
    ((program row.kind).source.events[33]?).map Event.ordinal = some 33 ∧
      ((program row.kind).source.events[34]?).map Event.ordinal = some 34 ∧
      ((program row.kind).source.events[35]?).map Event.ordinal = some 35 ∧
      ((program row.kind).source.events[36]?).map Event.ordinal = some 36 ∧
      ((program row.kind).source.events[37]?).map Event.ordinal = some 37 ∧
      ((program row.kind).source.events[38]?).map Event.ordinal = some 38 ∧
      ((program row.kind).source.events[39]?).map Event.ordinal = some 39 ∧
      ((program row.kind).source.events[40]?).map Event.ordinal = some 40 ∧
      ((program row.kind).source.events[41]?).map Event.ordinal = some 41 ∧
      ((program row.kind).source.events[42]?).map Event.ordinal = some 42 ∧
      ((program row.kind).source.events[43]?).map Event.ordinal = some 43
  projection :
    (program row.kind).source.projection.programEvent = 33 ∧
      (program row.kind).source.projection.stateEvents = #[35, 36] ∧
      (program row.kind).source.projection.sourceEvents = #[37, 38] ∧
      (program row.kind).source.projection.destinationEvents = #[41, 42] ∧
      (program row.kind).source.projection.nextPc = 157
  comparisonIsArchitectural :
    columns row witness 22 =
      boolM31 (comparison row.kind row.rs1Value row.immediate)
  sourceReadOnly :
    (sourceEmitLookup row).tuple[3]? =
        (sourceConsumeLookup row).tuple[3]? ∧
      (sourceEmitLookup row).tuple[4]? =
        (sourceConsumeLookup row).tuple[4]? ∧
      (sourceEmitLookup row).tuple[5]? =
        (sourceConsumeLookup row).tuple[5]? ∧
      (sourceEmitLookup row).tuple[6]? =
        (sourceConsumeLookup row).tuple[6]?
  destinationIsArchitectural :
    (destinationEmitLookup row).tuple[3]? =
        some (bitVecM31
          (destinationBytes row.rd
            (comparison row.kind row.rs1Value row.immediate)).limb0) ∧
      (destinationEmitLookup row).tuple[4]? =
        some (bitVecM31
          (destinationBytes row.rd
            (comparison row.kind row.rs1Value row.immediate)).limb1) ∧
      (destinationEmitLookup row).tuple[5]? =
        some (bitVecM31
          (destinationBytes row.rd
            (comparison row.kind row.rs1Value row.immediate)).limb2) ∧
      (destinationEmitLookup row).tuple[6]? =
        some (bitVecM31
          (destinationBytes row.rd
            (comparison row.kind row.rs1Value row.immediate)).limb3)
  nextPc :
    (stateEmitLookup row).tuple[0]? =
      some (bitVecM31 (RiscvRefinement.nextPc row.pc))
  nextClock :
    (stateEmitLookup row).tuple[1]? =
      some (M31.reduce (row.clock + 1))

theorem sound
    (row : Row)
    (witness : Witness row)
    (admission : Admission row)
    (accepted : Acceptance row witness) :
    ProductionRefinement row witness := by
  refine {
    sourceDigest := programContentDigest row.kind
    selectors := accepted.selectors
    constraints := accepted.constraints
    fixedLookups := accepted.fixedLookups
    exactLookups := fun ordinal lower upper =>
      lookupProjection row witness ordinal lower upper
    eventOrder := generatedEventOrder row.kind
    projection := projectionMetadata row.kind
    comparisonIsArchitectural := rfl
    sourceReadOnly := by simp [sourceConsumeLookup, sourceEmitLookup]
    destinationIsArchitectural := by
      simp [destinationEmitLookup]
    nextPc := ?_
    nextClock := ?_
  }
  · simp [stateEmitLookup, TeamACommon.nextPcField row.pc admission.pcBound]
  · have bound : row.clock + 1 < M31.modulus := by
      have clockBound : row.clock ≤ 16777216 := by
        simpa using admission.clockBound
      rw [M31.modulus_eq]
      omega
    simp [stateEmitLookup, TeamACommon.nextClockField row.clock bound]

def exampleRow : Row where
  kind := .unsigned
  clock := 1
  pc := BitVec.ofNat 32 0x1000
  rd := BitVec.ofNat 5 1
  rdPrevious := WordBytes.zero
  rdPreviousClock := 0
  rs1 := BitVec.ofNat 5 2
  rs1Value := { WordBytes.zero with limb0 := BitVec.ofNat 8 1 }
  rs1PreviousClock := 0
  immediate := BitVec.ofNat 12 2

def exampleWitness : Witness exampleRow where
  marker0 := true
  marker1 := false
  marker2 := false
  marker3 := false
  difference := BitVec.ofNat 8 1
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
  · simp only [exampleRow, exampleWitness]
    reduce_ltimm <;> decide
  · simp only [exampleRow, exampleWitness]
    reduce_ltimm <;> decide

theorem acceptanceNonvacuous :
    ∃ row witness, Admission row ∧ Acceptance row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance⟩

/- Signed SLTI sees `0x80000000 < 0`; SLTIU does not.  As in the
register form, the signed witness aliases `rd = rs1` and the unsigned witness
targets x0. -/
def highBitRow (kind : Kind) : Row where
  kind := kind
  clock := 1
  pc := BitVec.ofNat 32 0x1000
  rd := match kind with
    | .signed => BitVec.ofNat 5 1
    | .unsigned => zeroRegister
  rdPrevious := match kind with
    | .signed => LtReg.highBitBytes
    | .unsigned => WordBytes.zero
  rdPreviousClock := match kind with
    | .signed => 1
    | .unsigned => 0
  rs1 := BitVec.ofNat 5 1
  rs1Value := LtReg.highBitBytes
  rs1PreviousClock := 0
  immediate := BitVec.ofNat 12 0

def highBitWitness (kind : Kind) : Witness (highBitRow kind) where
  marker0 := false
  marker1 := false
  marker2 := false
  marker3 := true
  difference := BitVec.ofNat 8 128
  destinationInverse := match kind with
    | .signed => 1
    | .unsigned => 0

theorem highBitAdmission (kind : Kind) :
    Admission (highBitRow kind) := by
  cases kind <;> constructor <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem highBitAcceptance (kind : Kind) :
    Acceptance (highBitRow kind) (highBitWitness kind) := by
  refine {
    selectors := selectorAccepted _ _
    constraints := ?_
    fixedLookups := ?_
  }
  · cases kind <;>
      simp only [highBitRow, highBitWitness, LtReg.highBitBytes] <;>
      reduce_ltimm <;> decide
  · cases kind <;>
      simp only [highBitRow, highBitWitness, LtReg.highBitBytes] <;>
      reduce_ltimm <;> decide

theorem signedHighBitResult :
    comparison .signed LtReg.highBitBytes (BitVec.ofNat 12 0) = true := by
  decide

theorem unsignedHighBitResult :
    comparison .unsigned LtReg.highBitBytes (BitVec.ofNat 12 0) = false := by
  decide

theorem signedAliasNonvacuous :
    ∃ row witness,
      row.kind = .signed ∧ row.rd = row.rs1 ∧
        Admission row ∧ Acceptance row witness :=
  ⟨highBitRow .signed, highBitWitness .signed, rfl, rfl,
    highBitAdmission .signed, highBitAcceptance .signed⟩

theorem unsignedX0Nonvacuous :
    ∃ row witness,
      row.kind = .unsigned ∧ row.rd = zeroRegister ∧
        Admission row ∧ Acceptance row witness :=
  ⟨highBitRow .unsigned, highBitWitness .unsigned, rfl, rfl,
    highBitAdmission .unsigned, highBitAcceptance .unsigned⟩

end RiscvRefinement.Air.Bridge.LtImm
