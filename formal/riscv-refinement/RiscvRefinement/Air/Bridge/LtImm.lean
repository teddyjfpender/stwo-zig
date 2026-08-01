import RiscvRefinement.Air.Bridge.LtReg
import RiscvRefinement.Air.Bridge.LtComparator

/-!
# Production SLTI/SLTIU AIR bridge

The typed row and witness model every generated input, output, and witness
column independently.  The universal refinement theorem derives source
preservation, the comparison bit, and the destination bytes from accepted
production constraints and live fixed-table lookups.
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
      "f749061d1b4f84ae1990707debed715c7386d5dc4116ad4a53e6cb52036b0794"
  | .unsigned =>
      "bbed2f63b6d08c8b25bdadf11c4be6b1441e61c6901e6f833cfbd2468552b5b8"

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
  rdNext : WordBytes
  rs1 : RegisterIndex
  rs1Previous : WordBytes
  rs1PreviousClock : Nat
  rs1Next : WordBytes
  immediate : BitVec 12
deriving DecidableEq, Repr

structure Witness (row : Row) where
  /-- Raw production column 22 (`cmp_result`). -/
  comparisonResult : Bool
  /-- Raw production column 23 (`rs1_msl_felt`). -/
  sourceMsl : M31
  marker0 : Bool
  marker1 : Bool
  marker2 : Bool
  marker3 : Bool
  difference : Byte
  /-- Raw production column 34 (`destination_nonzero`). -/
  destinationNonzero : Bool
  destinationInverse : M31
  /-- Raw production column 36 (`imm_msl_felt`). -/
  immediateMsl : M31

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
  | 22 => boolM31 witness.comparisonResult
  | 23 => witness.sourceMsl
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
  | 34 => boolM31 witness.destinationNonzero
  | 35 => witness.destinationInverse
  | 36 => witness.immediateMsl
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

def immediateRangeLookup (row : Row) (witness : Witness row) :
    EvaluatedLookup where
  ordinal := 34
  domain := .rangeCheck884
  numerator := -(1 : M31)
  tuple := #[
    witness.sourceMsl +
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
    bitVecM31 row.rs1Previous.limb0, bitVecM31 row.rs1Previous.limb1,
    bitVecM31 row.rs1Previous.limb2, bitVecM31 row.rs1Previous.limb3
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
    bitVecM31 row.rs1Next.limb0, bitVecM31 row.rs1Next.limb1,
    bitVecM31 row.rs1Next.limb2, bitVecM31 row.rs1Next.limb3
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
    bitVecM31 row.rdNext.limb0,
    bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2,
    bitVecM31 row.rdNext.limb3
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
  | 34 => some (immediateRangeLookup row witness)
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

def constraintRoots : Array Nat :=
  #[67, 69, 71, 73, 74, 76, 78, 80, 82, 84, 89, 91, 97, 99,
    105, 107, 113, 115, 117, 118, 120, 122, 124, 126, 128, 130,
    131, 132, 134, 136, 138, 140, 66]

set_option maxHeartbeats 800000 in
private theorem constraintsHoldEvents
    (kind : Kind)
    (nodes : LocalValues) :
    ((program kind).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      constraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  cases kind
  · simpa [program, Programs.slti, Programs.sltiSource, constraintRoots,
      Event.evalSymbolic]
  · simpa [program, Programs.sltiu, Programs.sltiuSource, constraintRoots,
      Event.evalSymbolic]

theorem constraintsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      constraintRoots.all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) := by
  exact constraintsHoldEvents row.kind (evaluation row witness).nodes

def expectedFixedChecks (row : Row) (witness : Witness row) : Bool :=
  #[
    programLookup row,
    immediateRangeLookup row witness,
    stateConsumeLookup row,
    stateEmitLookup row,
    sourceConsumeLookup row,
    sourceEmitLookup row,
    sourceClockLookup row,
    positiveDifferenceLookup row witness,
    destinationConsumeLookup row,
    destinationEmitLookup row,
    destinationClockLookup row
  ].all EvaluatedLookup.fixedRequestHolds

set_option maxHeartbeats 800000 in
set_option maxRecDepth 30000 in
theorem fixedLookupsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).fixedLookupsHold =
      expectedFixedChecks row witness := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program, expectedFixedChecks]
  all_goals reduce_ltimm

theorem constraintRootZero
    (row : Row)
    (witness : Witness row)
    (accepted : (evaluation row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ constraintRoots) :
    (evaluation row witness).nodes.getSymbolic root = 0 := by
  rw [constraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

def comparisonSign (result : Bool) : M31 :=
  boolM31 result * M31.reduce 2 - 1

def signedOffset (kind : Kind) : M31 :=
  boolM31 (isSigned kind) * M31.reduce 128

def sourceKey (row : Row) (witness : Witness row) : M31 :=
  witness.sourceMsl + signedOffset row.kind

def immediateKey (row : Row) (witness : Witness row) : M31 :=
  witness.immediateMsl + signedOffset row.kind

def expectedImmediateMsl
    (kind : Kind) (immediate : BitVec 12) : M31 :=
  boolM31 (!(isSigned kind)) *
      (bitVecM31 (immMsb immediate) * M31.reduce 255) -
    boolM31 (isSigned kind) * bitVecM31 (immMsb immediate)

def immediateLimb2Field (immediate : BitVec 12) : M31 :=
  bitVecM31 (immMsb immediate) * M31.reduce 255

def immediateLimb1Field (immediate : BitVec 12) : M31 :=
  bitVecM31 (imm1 immediate) +
    bitVecM31 (immMsb immediate) * M31.reduce 248

def selectorSum (kind : Kind) : M31 :=
  boolM31 (isSigned kind) + boolM31 (!(isSigned kind))

set_option maxRecDepth 20000 in
private theorem node66 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 66 =
      selectorSum row.kind - 1 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [selectorSum, kind, isSigned, LtReg.isSigned, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node67 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 67 =
      selectorSum row.kind * (selectorSum row.kind - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [selectorSum, kind, isSigned, LtReg.isSigned, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node69 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 69 =
      boolM31 (isSigned row.kind) *
        (boolM31 (isSigned row.kind) - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [kind, isSigned, LtReg.isSigned, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node71 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 71 =
      boolM31 (!(isSigned row.kind)) *
        (boolM31 (!(isSigned row.kind)) - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [kind, isSigned, LtReg.isSigned, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node73 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 73 =
      bitVecM31 (immMsb row.immediate) *
        (bitVecM31 (immMsb row.immediate) - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node78 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 78 =
      boolM31 witness.marker0 * (boolM31 witness.marker0 - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node80 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 80 =
      boolM31 witness.marker1 * (boolM31 witness.marker1 - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node82 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 82 =
      boolM31 witness.marker2 * (boolM31 witness.marker2 - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node84 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 84 =
      boolM31 witness.marker3 * (boolM31 witness.marker3 - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node74 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 74 =
      witness.immediateMsl -
        expectedImmediateMsl row.kind row.immediate := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [expectedImmediateMsl, kind, isSigned, LtReg.isSigned,
    immMsb, boolM31, TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node76 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 76 =
      (bitVecM31 row.rs1Next.limb3 - witness.sourceMsl) *
        (M31.reduce 256 -
          (bitVecM31 row.rs1Next.limb3 - witness.sourceMsl)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node89 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 89 =
      (1 - boolM31 witness.marker3) *
        (comparisonSign witness.comparisonResult *
          (witness.immediateMsl - witness.sourceMsl)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, boolM31, TeamACommon.boolM31,
    Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node91 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 91 =
      boolM31 witness.marker3 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (witness.immediateMsl - witness.sourceMsl)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, boolM31, TeamACommon.boolM31,
    Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node97 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 97 =
      (1 - boolM31 witness.marker3 - boolM31 witness.marker2) *
        (comparisonSign witness.comparisonResult *
          (immediateLimb2Field row.immediate -
            bitVecM31 row.rs1Next.limb2)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, immediateLimb2Field, immMsb, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node99 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 99 =
      boolM31 witness.marker2 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (immediateLimb2Field row.immediate -
              bitVecM31 row.rs1Next.limb2)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, immediateLimb2Field, immMsb, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node105 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 105 =
      (1 - (boolM31 witness.marker3 + boolM31 witness.marker2) -
          boolM31 witness.marker1) *
        (comparisonSign witness.comparisonResult *
          (immediateLimb1Field row.immediate -
            bitVecM31 row.rs1Next.limb1)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, immediateLimb1Field, imm1, immMsb,
    boolM31, TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node107 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 107 =
      boolM31 witness.marker1 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (immediateLimb1Field row.immediate -
              bitVecM31 row.rs1Next.limb1)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, immediateLimb1Field, imm1, immMsb,
    boolM31, TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node113 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 113 =
      (1 -
          ((boolM31 witness.marker3 + boolM31 witness.marker2) +
            boolM31 witness.marker1) -
          boolM31 witness.marker0) *
        (comparisonSign witness.comparisonResult *
          (bitVecM31 (immediateBytes row.immediate).limb0 -
            bitVecM31 row.rs1Next.limb0)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, immediateBytes, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node115 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 115 =
      boolM31 witness.marker0 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (bitVecM31 (immediateBytes row.immediate).limb0 -
              bitVecM31 row.rs1Next.limb0)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm
  all_goals simp [comparisonSign, immediateBytes, boolM31,
    TeamACommon.boolM31, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node117 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 117 =
      markerPrefix witness * (1 - markerPrefix witness) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node118 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 118 =
      (1 - markerPrefix witness) *
        boolM31 witness.comparisonResult := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node120 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 120 =
      boolM31 witness.comparisonResult *
        (boolM31 witness.comparisonResult - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node122 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 122 =
      boolM31 witness.destinationNonzero *
        (boolM31 witness.destinationNonzero - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node124 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 124 =
      bitVecM31 row.rd * (1 - boolM31 witness.destinationNonzero) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node126 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 126 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 witness.destinationNonzero := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node128 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 128 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 witness.destinationNonzero *
          boolM31 witness.comparisonResult := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node130 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 130 =
      bitVecM31 row.rdNext.limb1 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node131 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 131 =
      bitVecM31 row.rdNext.limb2 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem node132 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 132 =
      bitVecM31 row.rdNext.limb3 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltimm

set_option maxRecDepth 20000 in
private theorem sourceNodes (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 134 =
        bitVecM31 row.rs1Next.limb0 -
          bitVecM31 row.rs1Previous.limb0 ∧
      (evaluation row witness).nodes.getSymbolic 136 =
        bitVecM31 row.rs1Next.limb1 -
          bitVecM31 row.rs1Previous.limb1 ∧
      (evaluation row witness).nodes.getSymbolic 138 =
        bitVecM31 row.rs1Next.limb2 -
          bitVecM31 row.rs1Previous.limb2 ∧
      (evaluation row witness).nodes.getSymbolic 140 =
        bitVecM31 row.rs1Next.limb3 -
          bitVecM31 row.rs1Previous.limb3 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals constructor
  all_goals try constructor
  all_goals reduce_ltimm

private theorem node134 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 134 =
      bitVecM31 row.rs1Next.limb0 -
        bitVecM31 row.rs1Previous.limb0 :=
  (sourceNodes row witness).1

private theorem node136 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 136 =
      bitVecM31 row.rs1Next.limb1 -
        bitVecM31 row.rs1Previous.limb1 :=
  (sourceNodes row witness).2.1

private theorem node138 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 138 =
      bitVecM31 row.rs1Next.limb2 -
        bitVecM31 row.rs1Previous.limb2 :=
  (sourceNodes row witness).2.2.1

private theorem node140 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 140 =
      bitVecM31 row.rs1Next.limb3 -
        bitVecM31 row.rs1Previous.limb3 :=
  (sourceNodes row witness).2.2.2

theorem immediateLimbFields
    (immediate : BitVec 12) :
    immediateLimb2Field immediate =
        bitVecM31 (immediateBytes immediate).limb2 ∧
      immediateLimb1Field immediate =
        bitVecM31 (immediateBytes immediate).limb1 := by
  have bound : (immMsb immediate).toNat < 2 := by
    simpa using (immMsb immediate).isLt
  have middleBound : (imm1 immediate).toNat < 8 := by
    simpa using (imm1 immediate).isLt
  have modEq (value : Nat) (small : value < 256) :
      value % 2147483647 =
        value % 256 % 2147483647 := by
    rw [
      Nat.mod_eq_of_lt (by omega),
      Nat.mod_eq_of_lt small,
      Nat.mod_eq_of_lt (by omega),
    ]
  have values :
      (immMsb immediate).toNat = 0 ∨
        (immMsb immediate).toNat = 1 := by omega
  rcases values with value | value <;>
    constructor <;>
    apply M31.ext <;>
    simp [
      immediateLimb2Field,
      immediateLimb1Field,
      immediateBytes,
      immSign,
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      TeamACommon.reduceAdd,
      TeamACommon.reduceMul,
      value,
      M31.modulus_eq
    ]
  all_goals apply modEq <;> omega

theorem expectedImmediateKey
    (kind : Kind)
    (immediate : BitVec 12) :
    (expectedImmediateMsl kind immediate + signedOffset kind).val =
        LtComparator.byteKey (isSigned kind)
          (immediateBytes immediate).limb3 ∧
      (expectedImmediateMsl kind immediate + signedOffset kind).val < 256 := by
  have bound : (immMsb immediate).toNat < 2 := by
    simpa using (immMsb immediate).isLt
  have signedOneValue :
      ((0 : M31) - 1 + M31.reduce 128).val = 127 := by decide
  have zeroValue : (0 : M31).val = 0 := rfl
  have values :
      (immMsb immediate).toNat = 0 ∨
        (immMsb immediate).toNat = 1 := by omega
  cases kind <;>
    rcases values with value | value <;>
    constructor <;>
    simp [
      expectedImmediateMsl,
      signedOffset,
      isSigned,
      LtReg.isSigned,
      LtComparator.byteKey,
      immediateBytes,
      immSign,
      bitVecM31,
      TeamACommon.bitVecM31,
      Lui.bitVecM31,
      boolM31,
      TeamACommon.boolM31,
      Lui.boolM31,
      TeamACommon.reduceAdd,
      TeamACommon.reduceMul,
      value,
      signedOneValue,
      zeroValue,
      M31.modulus_eq
    ]

private theorem byteBound (byte : Byte) :
    byte.toNat < M31.modulus := by
  have := byte.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byteEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

private theorem fieldValue (byte : Byte) :
    (bitVecM31 byte).val = byte.toNat :=
  Lui.bitVecM31_val byte (byteBound byte)

private theorem fieldBound (byte : Byte) :
    (bitVecM31 byte).val < 256 := by
  rw [fieldValue]
  simpa using byte.isLt

private theorem immediateLookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 34 =
      some (immediateRangeLookup row witness) := by
  simpa [expectedLookup?] using
    lookupProjection row witness 34 (by omega) (by omega)

private theorem differenceLookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 40 =
      some (positiveDifferenceLookup row witness) := by
  simpa [expectedLookup?] using
    lookupProjection row witness 40 (by omega) (by omega)

theorem sourceKeyBound
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (sourceKey row witness).val < 256 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation row witness) 34 (immediateRangeLookup row witness)
      accepted.fixedLookups (immediateLookupProjection row witness)
  have live :
      (immediateRangeLookup row witness).isLive = true := by
    simp [immediateRangeLookup, EvaluatedLookup.isLive]
    decide
  rw [EvaluatedLookup.fixedRequestHolds, live] at request
  have membership :
      FixedTableId.rangeCheck884.contains
        [sourceKey row witness,
          bitVecM31 (imm0 row.immediate),
          bitVecM31 (imm1 row.immediate) * M31.reduce 2] = true := by
    simpa [immediateRangeLookup, sourceKey, signedOffset,
      EvaluatedLookup.fixedMembership] using request
  exact
    (FixedTableId.rangeCheck884_contains_iff _ _ _).mp membership |>.1

private theorem negMarkerPrefixLive
    (marker0 marker1 marker2 marker3 : Bool)
    (anyMarker :
      marker0 = true ∨ marker1 = true ∨
        marker2 = true ∨ marker3 = true) :
    ((-(((boolM31 marker0 + boolM31 marker1) +
          boolM31 marker2) + boolM31 marker3)) != (0 : M31)) = true := by
  cases marker0 <;>
    cases marker1 <;>
    cases marker2 <;>
    cases marker3 <;>
    simp_all [boolM31, TeamACommon.boolM31, Lui.boolM31] <;>
    decide

private theorem differenceLive
    (row : Row)
    (witness : Witness row)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    (positiveDifferenceLookup row witness).isLive = true := by
  change (-markerPrefix witness != (0 : M31)) = true
  exact
    negMarkerPrefixLive witness.marker0 witness.marker1
      witness.marker2 witness.marker3 anyMarker

private theorem rangeCheck20RequestHolds_iff
    (numerator value : M31)
    (live : (numerator != (0 : M31)) = true) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal := 40
      domain := .rangeCheck20
      numerator
      tuple := #[value]
      role := .request
      tableId := some .rangeCheck20
      accessOrdinal := none
    }) = true ↔ value.val < 2 ^ 20 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    live,
    ↓reduceIte,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
    decide_eq_true_eq,
  ]

private theorem positiveDifferenceBound
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    (bitVecM31 witness.difference - 1).val < 2 ^ 20 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation row witness) 40
      (positiveDifferenceLookup row witness)
      accepted.fixedLookups (differenceLookupProjection row witness)
  have liveLookup := differenceLive row witness anyMarker
  have live :
      (-markerPrefix witness != (0 : M31)) = true := by
    simpa [positiveDifferenceLookup, EvaluatedLookup.isLive] using
      liveLookup
  apply
    (rangeCheck20RequestHolds_iff
      (-markerPrefix witness)
      (bitVecM31 witness.difference - 1) live).mp
  simpa only [positiveDifferenceLookup] using request

theorem differencePositive
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    0 < (bitVecM31 witness.difference).val := by
  have bound := positiveDifferenceBound row witness accepted anyMarker
  rw [fieldValue]
  by_cases positive : 0 < witness.difference.toNat
  · exact positive
  · have zero : witness.difference.toNat = 0 := by omega
    have byteZero :
        witness.difference = BitVec.ofNat 8 0 :=
      BitVec.eq_of_toNat_eq (by simpa using zero)
    rw [byteZero] at bound
    have impossible :
        M31.modulus - 1 < 2 ^ 20 := by
      simpa [
        bitVecM31,
        TeamACommon.bitVecM31,
        Lui.bitVecM31,
        M31.sub_val_of_lt
      ] using bound
    simp [M31.modulus_eq] at impossible

theorem byteKey_eq
    (kind : Kind)
    (byte : Byte) :
    LtComparator.byteKey (isSigned kind) byte =
      LtReg.byteKey kind byte := by
  cases kind <;> revert byte <;> decide

theorem sourceKeyCorrect
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (sourceKey row witness).val =
      LtReg.byteKey row.kind row.rs1Next.limb3 := by
  have root :=
    constraintRootZero row witness accepted.constraints 76
      (by simp [constraintRoots])
  rw [node76] at root
  have normalized :=
    LtComparator.normalizedKey
      (isSigned row.kind) row.rs1Next.limb3 witness.sourceMsl
      (sourceKeyBound row witness accepted)
      (by simpa using root)
  simpa [sourceKey, signedOffset, byteKey_eq] using normalized

theorem immediateKeyCorrect
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (immediateKey row witness).val =
        LtReg.byteKey row.kind (immediateBytes row.immediate).limb3 ∧
      (immediateKey row witness).val < 256 := by
  have root :=
    constraintRootZero row witness accepted.constraints 74
      (by simp [constraintRoots])
  rw [node74] at root
  have msl :
      witness.immediateMsl =
        expectedImmediateMsl row.kind row.immediate :=
    (M31.sub_eq_zero_iff _ _).mp root
  rw [immediateKey, msl]
  have expected := expectedImmediateKey row.kind row.immediate
  simpa [signedOffset, byteKey_eq] using expected

def comparatorContract
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    LtComparator.ComparatorContract := by
  have zero (root : Nat) (member : root ∈ constraintRoots) :=
    constraintRootZero row witness accepted.constraints root member
  have immediateFields := immediateLimbFields row.immediate
  have immediateTop := immediateKeyCorrect row witness accepted
  refine {
    result := witness.comparisonResult
    leftTop := sourceKey row witness
    rightTop := immediateKey row witness
    left2 := bitVecM31 row.rs1Next.limb2
    right2 := immediateLimb2Field row.immediate
    left1 := bitVecM31 row.rs1Next.limb1
    right1 := immediateLimb1Field row.immediate
    left0 := bitVecM31 row.rs1Next.limb0
    right0 := bitVecM31 (imm0 row.immediate)
    marker0 := witness.marker0
    marker1 := witness.marker1
    marker2 := witness.marker2
    marker3 := witness.marker3
    difference := bitVecM31 witness.difference
    leftTopBound := sourceKeyBound row witness accepted
    rightTopBound := immediateTop.2
    left2Bound := fieldBound _
    right2Bound := by rw [immediateFields.1]; exact fieldBound _
    left1Bound := fieldBound _
    right1Bound := by rw [immediateFields.2]; exact fieldBound _
    left0Bound := fieldBound _
    right0Bound := fieldBound _
    differencePositive := fun anyMarker =>
      differencePositive row witness accepted anyMarker
    differenceBound := fun _ => by
      have := fieldBound witness.difference
      omega
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
    have equation := zero 89 (by simp [constraintRoots])
    rw [node89, markerOff] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    rw [LtComparator.translatedSub
      witness.sourceMsl witness.immediateMsl
      (signedOffset row.kind)] at equation
    simpa [sourceKey, immediateKey, comparisonSign,
      LtComparator.comparisonSign] using equation
  · intro markerOn
    have equation := zero 91 (by simp [constraintRoots])
    rw [node91, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected :
        bitVecM31 witness.difference =
          comparisonSign witness.comparisonResult *
            (witness.immediateMsl - witness.sourceMsl) :=
      (M31.sub_eq_zero_iff _ _).mp equation
    rw [LtComparator.translatedSub
      witness.sourceMsl witness.immediateMsl
      (signedOffset row.kind)] at selected
    simpa [sourceKey, immediateKey, comparisonSign,
      LtComparator.comparisonSign] using selected
  · intro marker3Off marker2Off
    have equation := zero 97 (by simp [constraintRoots])
    rw [node97, marker3Off, marker2Off] at equation
    simpa [boolM31, TeamACommon.boolM31, Lui.boolM31, comparisonSign,
      LtComparator.comparisonSign] using equation
  · intro markerOn
    have equation := zero 99 (by simp [constraintRoots])
    rw [node99, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    simpa [comparisonSign, LtComparator.comparisonSign] using
      (M31.sub_eq_zero_iff _ _).mp equation
  · intro marker3Off marker2Off marker1Off
    have equation := zero 105 (by simp [constraintRoots])
    rw [node105, marker3Off, marker2Off, marker1Off] at equation
    simpa [boolM31, TeamACommon.boolM31, Lui.boolM31, comparisonSign,
      LtComparator.comparisonSign] using equation
  · intro markerOn
    have equation := zero 107 (by simp [constraintRoots])
    rw [node107, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    simpa [comparisonSign, LtComparator.comparisonSign] using
      (M31.sub_eq_zero_iff _ _).mp equation
  · intro marker3Off marker2Off marker1Off marker0Off
    have equation := zero 113 (by simp [constraintRoots])
    rw [node113, marker3Off, marker2Off, marker1Off, marker0Off] at equation
    simpa [boolM31, TeamACommon.boolM31, Lui.boolM31, comparisonSign,
      LtComparator.comparisonSign] using equation
  · intro markerOn
    have equation := zero 115 (by simp [constraintRoots])
    rw [node115, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    simpa [comparisonSign, LtComparator.comparisonSign] using
      (M31.sub_eq_zero_iff _ _).mp equation
  · intro marker3Off marker2Off marker1Off marker0Off
    have equation := zero 118 (by simp [constraintRoots])
    rw [node118] at equation
    simp [markerPrefix, marker3Off, marker2Off, marker1Off, marker0Off,
      boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    cases resultCase : witness.comparisonResult
    · rfl
    · exfalso
      apply (show (1 : M31) ≠ 0 by decide)
      simpa [resultCase, boolM31, TeamACommon.boolM31, Lui.boolM31] using
        equation

theorem comparisonCorrect
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    witness.comparisonResult =
      comparison row.kind row.rs1Next row.immediate := by
  have raw :=
    LtComparator.comparisonCorrectOfContract
      (comparatorContract row witness accepted)
  have sourceTop := sourceKeyCorrect row witness accepted
  have immediateTop := (immediateKeyCorrect row witness accepted).1
  have immediateFields := immediateLimbFields row.immediate
  have topEq :
      sourceKey row witness = immediateKey row witness ↔
        LtReg.topKey row.kind row.rs1Next =
          LtReg.topKey row.kind (immediateBytes row.immediate) := by
    constructor
    · intro equal
      rw [LtReg.topKey_eq_byteKey, LtReg.topKey_eq_byteKey]
      calc
        LtReg.byteKey row.kind row.rs1Next.limb3 =
            (sourceKey row witness).val := sourceTop.symm
        _ = (immediateKey row witness).val := congrArg M31.val equal
        _ = LtReg.byteKey row.kind
              (immediateBytes row.immediate).limb3 := immediateTop
    · intro equal
      apply M31.ext
      rw [sourceTop, immediateTop]
      simpa [LtReg.topKey_eq_byteKey] using equal
  have fieldEqIff (left right : Byte) :
      bitVecM31 left = bitVecM31 right ↔ left = right := by
    exact ⟨byteEq left right, congrArg bitVecM31⟩
  have rawResult :
      witness.comparisonResult =
        if sourceKey row witness = immediateKey row witness then
          if bitVecM31 row.rs1Next.limb2 =
              immediateLimb2Field row.immediate then
            if bitVecM31 row.rs1Next.limb1 =
                immediateLimb1Field row.immediate then
              if bitVecM31 row.rs1Next.limb0 =
                  bitVecM31 (imm0 row.immediate) then
                false
              else
                decide (row.rs1Next.limb0.toNat <
                  (imm0 row.immediate).toNat)
            else
              decide (row.rs1Next.limb1.toNat <
                (immediateBytes row.immediate).limb1.toNat)
          else
            decide (row.rs1Next.limb2.toNat <
              (immediateBytes row.immediate).limb2.toNat)
        else
          decide (LtReg.topKey row.kind row.rs1Next <
            LtReg.topKey row.kind (immediateBytes row.immediate)) := by
    simpa [
      LtComparator.ComparatorContract.lexicographicLess,
      comparatorContract,
      fieldValue,
      sourceTop,
      immediateTop,
      immediateFields.1,
      immediateFields.2
    ] using raw
  rw [rawResult]
  simp only [comparison]
  by_cases top : sourceKey row witness = immediateKey row witness
  · have topArchitectural := topEq.mp top
    rw [if_pos top]
    by_cases limb2 :
        bitVecM31 row.rs1Next.limb2 =
          immediateLimb2Field row.immediate
    · have limb2Architectural :
          row.rs1Next.limb2 =
            (immediateBytes row.immediate).limb2 :=
        (fieldEqIff _ _).mp (by simpa [immediateFields.1] using limb2)
      rw [if_pos limb2]
      by_cases limb1 :
          bitVecM31 row.rs1Next.limb1 =
            immediateLimb1Field row.immediate
      · have limb1Architectural :
            row.rs1Next.limb1 =
              (immediateBytes row.immediate).limb1 :=
          (fieldEqIff _ _).mp (by simpa [immediateFields.2] using limb1)
        rw [if_pos limb1]
        by_cases limb0 :
            bitVecM31 row.rs1Next.limb0 =
              bitVecM31 (imm0 row.immediate)
        · have limb0Architectural :
              row.rs1Next.limb0 =
                (immediateBytes row.immediate).limb0 := by
            exact (fieldEqIff _ _).mp (by
              simpa [immediateBytes] using limb0)
          rw [if_pos limb0]
          simp [LtReg.semanticLess, topArchitectural, limb2Architectural,
            limb1Architectural, limb0Architectural]
        · have limb0Architectural :
              row.rs1Next.limb0 ≠
                (immediateBytes row.immediate).limb0 := by
            intro equal
            apply limb0
            simpa [immediateBytes] using congrArg bitVecM31 equal
          rw [if_neg limb0]
          simp [LtReg.semanticLess, topArchitectural, limb2Architectural,
            limb1Architectural, limb0Architectural, immediateBytes]
      · have limb1Architectural :
            row.rs1Next.limb1 ≠
              (immediateBytes row.immediate).limb1 := by
          intro equal
          apply limb1
          simpa [immediateFields.2] using congrArg bitVecM31 equal
        rw [if_neg limb1]
        simp [LtReg.semanticLess, topArchitectural, limb2Architectural,
          limb1Architectural]
    · have limb2Architectural :
          row.rs1Next.limb2 ≠
            (immediateBytes row.immediate).limb2 := by
        intro equal
        apply limb2
        simpa [immediateFields.1] using congrArg bitVecM31 equal
      rw [if_neg limb2]
      simp [LtReg.semanticLess, topArchitectural, limb2Architectural]
  · have topArchitectural :
        LtReg.topKey row.kind row.rs1Next ≠
          LtReg.topKey row.kind (immediateBytes row.immediate) :=
      fun equal => top (topEq.mpr equal)
    rw [if_neg top]
    simp [LtReg.semanticLess, topArchitectural]

private theorem sourceLimb0
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rs1Next.limb0 = row.rs1Previous.limb0 := by
  have nodes := sourceNodes row witness
  have root :=
    constraintRootZero row witness accepted.constraints 134
      (by simp [constraintRoots])
  apply byteEq
  exact (M31.sub_eq_zero_iff _ _).mp
    (by simpa [nodes.1] using root)

private theorem sourceLimb1
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rs1Next.limb1 = row.rs1Previous.limb1 := by
  have nodes := sourceNodes row witness
  have root :=
    constraintRootZero row witness accepted.constraints 136
      (by simp [constraintRoots])
  apply byteEq
  exact (M31.sub_eq_zero_iff _ _).mp
    (by simpa [nodes.2.1] using root)

private theorem sourceLimb2
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rs1Next.limb2 = row.rs1Previous.limb2 := by
  have nodes := sourceNodes row witness
  have root :=
    constraintRootZero row witness accepted.constraints 138
      (by simp [constraintRoots])
  apply byteEq
  exact (M31.sub_eq_zero_iff _ _).mp
    (by simpa [nodes.2.2.1] using root)

private theorem sourceLimb3
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rs1Next.limb3 = row.rs1Previous.limb3 := by
  have nodes := sourceNodes row witness
  have root :=
    constraintRootZero row witness accepted.constraints 140
      (by simp [constraintRoots])
  apply byteEq
  exact (M31.sub_eq_zero_iff _ _).mp
    (by simpa [nodes.2.2.2] using root)

set_option maxHeartbeats 100000 in
theorem sourceReadOnly
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rs1Next = row.rs1Previous :=
  WordBytes.eq_of_limbs row.rs1Next row.rs1Previous
    (sourceLimb0 row witness accepted)
    (sourceLimb1 row witness accepted)
    (sourceLimb2 row witness accepted)
    (sourceLimb3 row witness accepted)

private theorem destinationResultOfZeroFlag
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness)
    (flag : witness.destinationNonzero = false) :
    row.rdNext =
      destinationBytes row.rd witness.comparisonResult := by
  have zero (root : Nat) (member : root ∈ constraintRoots) :=
    constraintRootZero row witness accepted.constraints root member
  have addressRoot := zero 124 (by simp [constraintRoots])
  rw [node124, flag] at addressRoot
  simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at addressRoot
  have rdZero : row.rd = zeroRegister := by
    apply TeamACommon.bitVecM31_injective_of_bounds
      row.rd zeroRegister
    · have := row.rd.isLt
      simp [M31.modulus_eq] at *
      omega
    · decide
    · simpa using addressRoot
  have limb0Root := zero 128 (by simp [constraintRoots])
  have limb1Root := zero 130 (by simp [constraintRoots])
  have limb2Root := zero 131 (by simp [constraintRoots])
  have limb3Root := zero 132 (by simp [constraintRoots])
  rw [node128, flag] at limb0Root
  rw [node130] at limb1Root
  rw [node131] at limb2Root
  rw [node132] at limb3Root
  have rdNextZero : row.rdNext = WordBytes.zero := by
    apply WordBytes.eq_of_limbs <;> apply byteEq
    · simpa [boolM31, TeamACommon.boolM31, Lui.boolM31] using
        limb0Root
    · simpa using limb1Root
    · simpa using limb2Root
    · simpa using limb3Root
  rw [rdNextZero, rdZero]
  simp [destinationBytes, destinationNonzero]

private theorem destinationResultOfNonzeroFlag
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness)
    (flag : witness.destinationNonzero = true) :
    row.rdNext =
      destinationBytes row.rd witness.comparisonResult := by
  have zero (root : Nat) (member : root ∈ constraintRoots) :=
    constraintRootZero row witness accepted.constraints root member
  have inverseRoot := zero 126 (by simp [constraintRoots])
  rw [node126, flag] at inverseRoot
  change
    bitVecM31 row.rd * witness.destinationInverse - 1 = 0 at inverseRoot
  have rdNonzero : row.rd ≠ zeroRegister := by
    intro rdZero
    rw [rdZero] at inverseRoot
    have rdField : bitVecM31 zeroRegister = 0 := by decide
    rw [rdField, M31.zero_mul] at inverseRoot
    have impossible : (0 : M31) - 1 = 0 := inverseRoot
    exact (by decide : (0 : M31) - 1 ≠ 0) impossible
  have limb0Root := zero 128 (by simp [constraintRoots])
  have limb1Root := zero 130 (by simp [constraintRoots])
  have limb2Root := zero 131 (by simp [constraintRoots])
  have limb3Root := zero 132 (by simp [constraintRoots])
  rw [node128, flag] at limb0Root
  rw [node130] at limb1Root
  rw [node131] at limb2Root
  rw [node132] at limb3Root
  have rdNextResult :
      row.rdNext = resultBytes witness.comparisonResult := by
    apply WordBytes.eq_of_limbs <;> apply byteEq
    · have equality :=
        (M31.sub_eq_zero_iff _ _).mp (by
          simpa [boolM31, TeamACommon.boolM31, Lui.boolM31] using
            limb0Root)
      simpa [resultBytes] using
        equality.trans
          (LtReg.comparisonBytes_limb0_field
            witness.comparisonResult).symm
    · simpa [resultBytes] using limb1Root
    · simpa [resultBytes] using limb2Root
    · simpa [resultBytes] using limb3Root
  rw [rdNextResult]
  have nonzeroFlag : destinationNonzero row.rd = true := by
    simp [destinationNonzero, rdNonzero]
  simp [destinationBytes, nonzeroFlag]

theorem destinationResult
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNext =
      destinationBytes row.rd witness.comparisonResult := by
  cases flag : witness.destinationNonzero
  · exact destinationResultOfZeroFlag row witness accepted flag
  · exact destinationResultOfNonzeroFlag row witness accepted flag

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
    witness.comparisonResult =
      comparison row.kind row.rs1Next row.immediate
  sourceReadOnly :
    row.rs1Next = row.rs1Previous
  destinationIsArchitectural :
    row.rdNext =
      destinationBytes row.rd
        (comparison row.kind row.rs1Next row.immediate)
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
    comparisonIsArchitectural :=
      comparisonCorrect row witness accepted
    sourceReadOnly := sourceReadOnly row witness accepted
    destinationIsArchitectural := by
      have result := destinationResult row witness accepted
      rw [comparisonCorrect row witness accepted] at result
      exact result
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
  rdNext := resultBytes true
  rs1 := BitVec.ofNat 5 2
  rs1Previous := { WordBytes.zero with limb0 := BitVec.ofNat 8 1 }
  rs1PreviousClock := 0
  rs1Next := { WordBytes.zero with limb0 := BitVec.ofNat 8 1 }
  immediate := BitVec.ofNat 12 2

def exampleWitness : Witness exampleRow where
  comparisonResult := true
  sourceMsl := 0
  marker0 := true
  marker1 := false
  marker2 := false
  marker3 := false
  difference := BitVec.ofNat 8 1
  destinationNonzero := true
  destinationInverse := 1
  immediateMsl := 0

theorem exampleAdmission : Admission exampleRow := by
  constructor <;> decide

private theorem exampleConstraints :
    (evaluation exampleRow exampleWitness).constraintsHold = true := by
  rw [constraintsHold_eq]
  simp [
    constraintRoots,
    node66, node67, node69, node71, node73, node74, node76,
    node78, node80, node82, node84, node89, node91, node97, node99,
    node105, node107, node113, node115, node117, node118, node120,
    node122, node124, node126, node128, node130, node131, node132,
    node134, node136, node138, node140,
    exampleRow, exampleWitness, selectorSum, expectedImmediateMsl,
    comparisonSign, immediateLimb2Field, immediateLimb1Field,
    immediateBytes, markerPrefix, resultBytes, LtReg.comparisonBytes,
    bitVecM31, TeamACommon.bitVecM31, Lui.bitVecM31,
    boolM31, TeamACommon.boolM31, Lui.boolM31
  ]
  decide

set_option maxRecDepth 30000 in
private theorem exampleFixedLookups :
    (evaluation exampleRow exampleWitness).fixedLookupsHold = true := by
  rw [fixedLookupsHold_eq]
  simp only [expectedFixedChecks, exampleRow, exampleWitness]
  reduce_ltimm <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem exampleAcceptance : Acceptance exampleRow exampleWitness := by
  exact {
    selectors := selectorAccepted exampleRow exampleWitness
    constraints := exampleConstraints
    fixedLookups := exampleFixedLookups
  }

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
  rdNext := match kind with
    | .signed => resultBytes true
    | .unsigned => WordBytes.zero
  rs1 := BitVec.ofNat 5 1
  rs1Previous := LtReg.highBitBytes
  rs1PreviousClock := 0
  rs1Next := LtReg.highBitBytes
  immediate := BitVec.ofNat 12 0

def highBitWitness (kind : Kind) : Witness (highBitRow kind) where
  comparisonResult := match kind with
    | .signed => true
    | .unsigned => false
  sourceMsl := LtReg.mslField kind LtReg.highBitBytes
  marker0 := false
  marker1 := false
  marker2 := false
  marker3 := true
  difference := BitVec.ofNat 8 128
  destinationNonzero := match kind with
    | .signed => true
    | .unsigned => false
  destinationInverse := match kind with
    | .signed => 1
    | .unsigned => 0
  immediateMsl := 0

theorem highBitAdmission (kind : Kind) :
    Admission (highBitRow kind) := by
  cases kind <;> constructor <;> decide

private theorem highBitConstraints (kind : Kind) :
    (evaluation (highBitRow kind) (highBitWitness kind)).constraintsHold =
      true := by
  cases kind <;> rw [constraintsHold_eq]
  all_goals simp [
    constraintRoots,
    node66, node67, node69, node71, node73, node74, node76,
    node78, node80, node82, node84, node89, node91, node97, node99,
    node105, node107, node113, node115, node117, node118, node120,
    node122, node124, node126, node128, node130, node131, node132,
    node134, node136, node138, node140,
    highBitRow, highBitWitness, LtReg.highBitBytes,
    selectorSum, expectedImmediateMsl, comparisonSign,
    immediateLimb2Field, immediateLimb1Field, immediateBytes,
    markerPrefix, resultBytes, LtReg.comparisonBytes,
    bitVecM31, TeamACommon.bitVecM31, Lui.bitVecM31,
    boolM31, TeamACommon.boolM31, Lui.boolM31
  ]
  all_goals decide

set_option maxRecDepth 30000 in
private theorem highBitFixedLookups (kind : Kind) :
    (evaluation (highBitRow kind) (highBitWitness kind)).fixedLookupsHold =
      true := by
  cases kind <;> rw [fixedLookupsHold_eq]
  all_goals simp only [
    expectedFixedChecks, highBitRow, highBitWitness, LtReg.highBitBytes
  ]
  all_goals reduce_ltimm <;> decide

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem highBitAcceptance (kind : Kind) :
    Acceptance (highBitRow kind) (highBitWitness kind) := by
  exact {
    selectors := selectorAccepted _ _
    constraints := highBitConstraints kind
    fixedLookups := highBitFixedLookups kind
  }

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
