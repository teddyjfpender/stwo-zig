import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Air.Generated.Programs

/-!
# Production SLT/SLTU AIR bridge

This module evaluates the two committed `lt_reg` programs directly.  The row
projection follows the 44 production columns, including the signed-most-
significant-limb and first-difference witnesses.  Lookup ordinals 36--49 are
the exact generated event order.
-/

namespace RiscvRefinement.Air.Bridge.LtReg

open RiscvRefinement
open RiscvRefinement.Air.Generated

abbrev bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  TeamACommon.bitVecM31 value

abbrev boolM31 : Bool → M31 :=
  TeamACommon.boolM31

inductive Kind where
  | signed
  | unsigned
deriving DecidableEq, Repr

def manifestId : Kind → Nat
  | .signed => 3
  | .unsigned => 4

def program : Kind → LocalProgram
  | .signed => Programs.slt
  | .unsigned => Programs.sltu

def contentDigest : Kind → String
  | .signed =>
      "801ad0322cbabc01b301ba9a85000ee3eea6c8cf4c4ba178d9c917a0fe50a1d8"
  | .unsigned =>
      "63f345598eb53045513ddf150afa0e3635dd423ac2600cfdb3d8214a3731a881"

theorem programContentDigest (kind : Kind) :
    (program kind).source.contentDigest = contentDigest kind := by
  cases kind <;> decide

def isSigned : Kind → Bool
  | .signed => true
  | .unsigned => false

def signedMsl (byte : Byte) : M31 :=
  if byte.toNat < 128 then
    bitVecM31 byte
  else
    0 - M31.reduce (256 - byte.toNat)

def mslField (kind : Kind) (bytes : WordBytes) : M31 :=
  match kind with
  | .signed => signedMsl bytes.limb3
  | .unsigned => bitVecM31 bytes.limb3

def topKey (kind : Kind) (bytes : WordBytes) : Nat :=
  match kind with
  | .signed =>
      if bytes.limb3.toNat < 128
      then bytes.limb3.toNat + 128
      else bytes.limb3.toNat - 128
  | .unsigned => bytes.limb3.toNat

def byteKey (kind : Kind) (byte : Byte) : Nat :=
  match kind with
  | .signed =>
      if byte.toNat < 128
      then byte.toNat + 128
      else byte.toNat - 128
  | .unsigned => byte.toNat

theorem topKey_eq_byteKey (kind : Kind) (bytes : WordBytes) :
    topKey kind bytes = byteKey kind bytes.limb3 := by
  cases kind <;> rfl

def semanticLess
    (kind : Kind)
    (left right : WordBytes) :
    Bool :=
  decide (
    topKey kind left < topKey kind right ∨
    (topKey kind left = topKey kind right ∧
      (left.limb2.toNat < right.limb2.toNat ∨
      (left.limb2 = right.limb2 ∧
        (left.limb1.toNat < right.limb1.toNat ∨
        (left.limb1 = right.limb1 ∧
          left.limb0.toNat < right.limb0.toNat))))))

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
  rs2 : RegisterIndex
  rs2Previous : WordBytes
  rs2PreviousClock : Nat
  rs2Next : WordBytes
  rdNonzero : Bool
deriving DecidableEq, Repr

structure Witness (row : Row) where
  /-- Raw production column 32 (`cmp_result`). -/
  comparisonResult : Bool
  /-- Raw production columns 33 and 34 (`rs{1,2}_msl_felt`). -/
  sourceOneMsl : M31
  sourceTwoMsl : M31
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

def comparisonSign (result : Bool) : M31 :=
  boolM31 result * M31.reduce 2 - 1

def signedOffset (kind : Kind) : M31 :=
  boolM31 (isSigned kind) * M31.reduce 128

def sourceOneKey (row : Row) (witness : Witness row) : M31 :=
  witness.sourceOneMsl + signedOffset row.kind

def sourceTwoKey (row : Row) (witness : Witness row) : M31 :=
  witness.sourceTwoMsl + signedOffset row.kind

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
  | 32 => boolM31 witness.comparisonResult
  | 33 => witness.sourceOneMsl
  | 34 => witness.sourceTwoMsl
  | 35 => boolM31 (isSigned row.kind)
  | 36 => boolM31 (!(isSigned row.kind))
  | 37 => boolM31 witness.marker0
  | 38 => boolM31 witness.marker1
  | 39 => boolM31 witness.marker2
  | 40 => boolM31 witness.marker3
  | 41 => bitVecM31 witness.difference
  | 42 => boolM31 row.rdNonzero
  | 43 => witness.destinationInverse
  | _ => 0

def evaluation (row : Row) (witness : Witness row) : SymbolicEvaluation :=
  (program row.kind).evalSymbolic (columns row witness)

def accessClock (row : Row) (ordinal : Nat) : M31 :=
  TeamACommon.accessClockField row.clock ordinal

def clockGap (row : Row) (ordinal previous : Nat) : M31 :=
  TeamACommon.clockGapField row.clock ordinal previous

def programLookup (row : Row) : EvaluatedLookup where
  ordinal := 36
  domain := .programAccess
  numerator := -(1 : M31)
  tuple := #[
    bitVecM31 row.pc,
    M31.reduce (manifestId row.kind),
    bitVecM31 row.rd,
    bitVecM31 row.rs1,
    bitVecM31 row.rs2
  ]
  role := .request
  tableId := none
  accessOrdinal := none

def stateConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 37
  domain := .registersState
  numerator := -(1 : M31)
  tuple := #[bitVecM31 row.pc, M31.reduce row.clock]
  role := .consume
  tableId := none
  accessOrdinal := none

def stateEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 38
  domain := .registersState
  numerator := 1
  tuple := #[bitVecM31 row.pc + M31.reduce 4, M31.reduce row.clock + 1]
  role := .emit
  tableId := none
  accessOrdinal := none

def sourceConsumeLookup
    (row : Row)
    (which : Bool) :
    EvaluatedLookup :=
  let address := if which then row.rs2 else row.rs1
  let previousClock :=
    if which then row.rs2PreviousClock else row.rs1PreviousClock
  let previous := if which then row.rs2Previous else row.rs1Previous
  {
    ordinal := if which then 42 else 39
    domain := .memoryAccess
    numerator := -(1 : M31)
    tuple := #[
      0, bitVecM31 address, M31.reduce previousClock,
      bitVecM31 previous.limb0, bitVecM31 previous.limb1,
      bitVecM31 previous.limb2, bitVecM31 previous.limb3
    ]
    role := .consume
    tableId := none
    accessOrdinal := some (if which then 2 else 1)
  }

def sourceEmitLookup
    (row : Row)
    (which : Bool) :
    EvaluatedLookup :=
  let address := if which then row.rs2 else row.rs1
  let next := if which then row.rs2Next else row.rs1Next
  let ordinal := if which then 2 else 1
  {
    ordinal := if which then 43 else 40
    domain := .memoryAccess
    numerator := 1
    tuple := #[
      0, bitVecM31 address, accessClock row ordinal,
      bitVecM31 next.limb0, bitVecM31 next.limb1,
      bitVecM31 next.limb2, bitVecM31 next.limb3
    ]
    role := .emit
    tableId := none
    accessOrdinal := some ordinal
  }

def sourceClockLookup
    (row : Row)
    (which : Bool) :
    EvaluatedLookup :=
  let ordinal := if which then 2 else 1
  let previous :=
    if which then row.rs2PreviousClock else row.rs1PreviousClock
  {
    ordinal := if which then 44 else 41
    domain := .rangeCheck20
    numerator := -(1 : M31)
    tuple := #[clockGap row ordinal previous]
    role := .request
    tableId := some .rangeCheck20
    accessOrdinal := some ordinal
  }

def mslRangeLookup (row : Row) (witness : Witness row) : EvaluatedLookup where
  ordinal := 45
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    sourceOneKey row witness,
    sourceTwoKey row witness
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

def positiveDifferenceLookup
    (row : Row)
    (witness : Witness row) :
    EvaluatedLookup where
  ordinal := 46
  domain := .rangeCheck20
  numerator := -markerPrefix witness
  tuple := #[bitVecM31 witness.difference - 1]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

def destinationConsumeLookup (row : Row) : EvaluatedLookup where
  ordinal := 47
  domain := .memoryAccess
  numerator := -(1 : M31)
  tuple := #[
    0, bitVecM31 row.rd, M31.reduce row.rdPreviousClock,
    bitVecM31 row.rdPrevious.limb0, bitVecM31 row.rdPrevious.limb1,
    bitVecM31 row.rdPrevious.limb2, bitVecM31 row.rdPrevious.limb3
  ]
  role := .consume
  tableId := none
  accessOrdinal := some 3

def destinationEmitLookup (row : Row) : EvaluatedLookup where
  ordinal := 48
  domain := .memoryAccess
  numerator := 1
  tuple := #[
    0, bitVecM31 row.rd, accessClock row 3,
    bitVecM31 row.rdNext.limb0, bitVecM31 row.rdNext.limb1,
    bitVecM31 row.rdNext.limb2, bitVecM31 row.rdNext.limb3
  ]
  role := .emit
  tableId := none
  accessOrdinal := some 3

def destinationClockLookup (row : Row) : EvaluatedLookup where
  ordinal := 49
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGap row 3 row.rdPreviousClock]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some 3

macro "reduce_ltreg" : tactic =>
  `(tactic|
    (simp_all only [
      evaluation,
      program,
      LocalProgram.evalSymbolic,
      LocalProgram.evalNodesSymbolic,
      Programs.slt,
      Programs.sltu,
      Programs.sltSource,
      Programs.sltuSource,
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
      mslField,
      signedMsl,
      boolM31,
      TeamACommon.boolM31,
      programLookup,
      stateConsumeLookup,
      stateEmitLookup,
      sourceConsumeLookup,
      sourceEmitLookup,
      sourceClockLookup,
      mslRangeLookup,
      positiveDifferenceLookup,
      destinationConsumeLookup,
      destinationEmitLookup,
      destinationClockLookup,
      accessClock,
      clockGap,
      markerPrefix,
      comparisonSign,
      signedOffset,
      sourceOneKey,
      sourceTwoKey,
      semanticLess,
      topKey,
      TeamACommon.accessClockField,
      TeamACommon.clockGapField,
      Lui.boolM31,
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
theorem selectorAccepted
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).activeSelectorsAccepted = true := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals apply M31.ext <;> rfl

/- The explicit event proofs below deliberately spell out every generated
lookup.  This makes an ordinal or tuple-order drift a compile-time failure. -/
set_option maxHeartbeats 1000000 in
set_option maxRecDepth 20000 in
theorem lookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 36 = some (programLookup row) ∧
    (evaluation row witness).lookup? 37 = some (stateConsumeLookup row) ∧
    (evaluation row witness).lookup? 38 = some (stateEmitLookup row) ∧
    (evaluation row witness).lookup? 39 = some (sourceConsumeLookup row false) ∧
    (evaluation row witness).lookup? 40 = some (sourceEmitLookup row false) ∧
    (evaluation row witness).lookup? 41 = some (sourceClockLookup row false) ∧
    (evaluation row witness).lookup? 42 = some (sourceConsumeLookup row true) ∧
    (evaluation row witness).lookup? 43 = some (sourceEmitLookup row true) ∧
    (evaluation row witness).lookup? 44 = some (sourceClockLookup row true) ∧
    (evaluation row witness).lookup? 45 =
      some (mslRangeLookup row witness) ∧
    (evaluation row witness).lookup? 46 =
      some (positiveDifferenceLookup row witness) ∧
    (evaluation row witness).lookup? 47 = some (destinationConsumeLookup row) ∧
    (evaluation row witness).lookup? 48 = some (destinationEmitLookup row) ∧
    (evaluation row witness).lookup? 49 = some (destinationClockLookup row) := by
  cases kind : row.kind <;>
    repeat' apply And.intro
  all_goals
    first
    | have selected :
          (program row.kind).source.events[36]? =
            some (.lookup {
              ordinal := 36
              domain := .programAccess
              numerator := 157
              tuple := #[1, 160, 2, 12, 22]
              role := .request
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := none
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 36 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[37]? =
            some (.lookup {
              ordinal := 37
              domain := .registersState
              numerator := 157
              tuple := #[1, 0]
              role := .consume
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := none
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 37 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[38]? =
            some (.lookup {
              ordinal := 38
              domain := .registersState
              numerator := 59
              tuple := #[161, 162]
              role := .emit
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := none
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 38 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[39]? =
            some (.lookup {
              ordinal := 39
              domain := .memoryAccess
              numerator := 157
              tuple := #[45, 12, 17, 13, 14, 15, 16]
              role := .consume
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := some 1
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 39 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[40]? =
            some (.lookup {
              ordinal := 40
              domain := .memoryAccess
              numerator := 59
              tuple := #[45, 12, 150, 18, 19, 20, 21]
              role := .emit
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := some 1
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 40 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[41]? =
            some (.lookup {
              ordinal := 41
              domain := .rangeCheck20
              numerator := 157
              tuple := #[152]
              role := .request
              tableId := some .rangeCheck20
              liveness := .nonzeroNumerator
              accessOrdinal := some 1
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 41 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[42]? =
            some (.lookup {
              ordinal := 42
              domain := .memoryAccess
              numerator := 157
              tuple := #[45, 22, 27, 23, 24, 25, 26]
              role := .consume
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := some 2
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 42 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[43]? =
            some (.lookup {
              ordinal := 43
              domain := .memoryAccess
              numerator := 59
              tuple := #[45, 22, 153, 28, 29, 30, 31]
              role := .emit
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := some 2
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 43 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[44]? =
            some (.lookup {
              ordinal := 44
              domain := .rangeCheck20
              numerator := 157
              tuple := #[155]
              role := .request
              tableId := some .rangeCheck20
              liveness := .nonzeroNumerator
              accessOrdinal := some 2
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 44 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[45]? =
            some (.lookup {
              ordinal := 45
              domain := .rangeCheck88
              numerator := 157
              tuple := #[54, 55]
              role := .request
              tableId := some .rangeCheck88
              liveness := .nonzeroNumerator
              accessOrdinal := none
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 45 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[46]? =
            some (.lookup {
              ordinal := 46
              domain := .rangeCheck20
              numerator := 163
              tuple := #[156]
              role := .request
              tableId := some .rangeCheck20
              liveness := .nonzeroNumerator
              accessOrdinal := none
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 46 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[47]? =
            some (.lookup {
              ordinal := 47
              domain := .memoryAccess
              numerator := 157
              tuple := #[45, 2, 7, 3, 4, 5, 6]
              role := .consume
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := some 3
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 47 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[48]? =
            some (.lookup {
              ordinal := 48
              domain := .memoryAccess
              numerator := 59
              tuple := #[45, 2, 147, 8, 9, 10, 11]
              role := .emit
              tableId := none
              liveness := .nonzeroNumerator
              accessOrdinal := some 3
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 48 _ selected]
      reduce_ltreg
    | have selected :
          (program row.kind).source.events[49]? =
            some (.lookup {
              ordinal := 49
              domain := .rangeCheck20
              numerator := 157
              tuple := #[149]
              role := .request
              tableId := some .rangeCheck20
              liveness := .nonzeroNumerator
              accessOrdinal := some 3
            }) := by simp [program, kind, Programs.slt, Programs.sltu,
              Programs.sltSource, Programs.sltuSource]
      rw [evaluation,
        LocalProgram.lookup?_evalSymbolic_of_event
          (program row.kind) (columns row witness) 49 _ selected]
      reduce_ltreg

def constraintRoots : Array Nat :=
  #[61, 63, 65, 67, 69, 71, 73, 75, 78, 80, 85, 87, 93, 95,
    101, 103, 109, 111, 113, 114, 116, 118, 120, 122, 124, 125,
    126, 128, 130, 132, 134, 136, 138, 140, 142, 60]

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
  · simpa [program, Programs.slt, Programs.sltSource, constraintRoots,
      Event.evalSymbolic]
  · simpa [program, Programs.sltu, Programs.sltuSource, constraintRoots,
      Event.evalSymbolic]

theorem constraintsHold_eq
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).constraintsHold =
      constraintRoots.all
        (fun root =>
          (evaluation row witness).nodes.getSymbolic root == 0) := by
  exact constraintsHoldEvents row.kind (evaluation row witness).nodes

theorem constraintRootZero
    (row : Row)
    (witness : Witness row)
    (accepted : (evaluation row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ constraintRoots) :
    (evaluation row witness).nodes.getSymbolic root = 0 := by
  rw [constraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ :=
    Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

set_option maxRecDepth 20000 in
private theorem node78 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 78 =
      (bitVecM31 row.rs1Next.limb3 - witness.sourceOneMsl) *
        (M31.reduce 256 -
          (bitVecM31 row.rs1Next.limb3 - witness.sourceOneMsl)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node80 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 80 =
      (bitVecM31 row.rs2Next.limb3 - witness.sourceTwoMsl) *
        (M31.reduce 256 -
          (bitVecM31 row.rs2Next.limb3 - witness.sourceTwoMsl)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node85 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 85 =
      (1 - boolM31 witness.marker3) *
        (comparisonSign witness.comparisonResult *
          (witness.sourceTwoMsl - witness.sourceOneMsl)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals simp [kind, isSigned, comparisonSign, boolM31,
    TeamACommon.boolM31]

set_option maxRecDepth 20000 in
private theorem node87 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 87 =
      boolM31 witness.marker3 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (witness.sourceTwoMsl - witness.sourceOneMsl)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals simp [kind, comparisonSign, mslField, isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node93 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 93 =
      (1 - boolM31 witness.marker3 - boolM31 witness.marker2) *
        (comparisonSign witness.comparisonResult *
          (bitVecM31 row.rs2Next.limb2 - bitVecM31 row.rs1Next.limb2)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node95 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 95 =
      boolM31 witness.marker2 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (bitVecM31 row.rs2Next.limb2 -
              bitVecM31 row.rs1Next.limb2)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node101 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 101 =
      (1 -
          (boolM31 witness.marker3 + boolM31 witness.marker2) -
          boolM31 witness.marker1) *
        (comparisonSign witness.comparisonResult *
          (bitVecM31 row.rs2Next.limb1 - bitVecM31 row.rs1Next.limb1)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node103 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 103 =
      boolM31 witness.marker1 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (bitVecM31 row.rs2Next.limb1 -
              bitVecM31 row.rs1Next.limb1)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node109 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 109 =
      (1 -
          ((boolM31 witness.marker3 + boolM31 witness.marker2) +
            boolM31 witness.marker1) -
          boolM31 witness.marker0) *
        (comparisonSign witness.comparisonResult *
          (bitVecM31 row.rs2Next.limb0 - bitVecM31 row.rs1Next.limb0)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node111 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 111 =
      boolM31 witness.marker0 *
        (bitVecM31 witness.difference -
          comparisonSign witness.comparisonResult *
            (bitVecM31 row.rs2Next.limb0 -
              bitVecM31 row.rs1Next.limb0)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node113 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 113 =
      markerPrefix witness * (1 - markerPrefix witness) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node114 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 114 =
      (1 - markerPrefix witness) *
        boolM31 witness.comparisonResult := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node116 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 116 =
      boolM31 row.rdNonzero * (boolM31 row.rdNonzero - 1) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node118 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 118 =
      bitVecM31 row.rd * (1 - boolM31 row.rdNonzero) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node120 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 120 =
      bitVecM31 row.rd * witness.destinationInverse -
        boolM31 row.rdNonzero := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node122 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 122 =
      bitVecM31 row.rdNext.limb0 -
        boolM31 row.rdNonzero *
          boolM31 witness.comparisonResult := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node124 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 124 =
      bitVecM31 row.rdNext.limb1 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node125 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 125 =
      bitVecM31 row.rdNext.limb2 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node126 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 126 =
      bitVecM31 row.rdNext.limb3 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals try simp [kind, comparisonSign, markerPrefix, mslField,
    isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node128 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 128 =
      bitVecM31 row.rs1Next.limb0 - bitVecM31 row.rs1Previous.limb0 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node130 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 130 =
      bitVecM31 row.rs1Next.limb1 - bitVecM31 row.rs1Previous.limb1 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node132 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 132 =
      bitVecM31 row.rs1Next.limb2 - bitVecM31 row.rs1Previous.limb2 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node134 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 134 =
      bitVecM31 row.rs1Next.limb3 - bitVecM31 row.rs1Previous.limb3 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node136 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 136 =
      bitVecM31 row.rs2Next.limb0 - bitVecM31 row.rs2Previous.limb0 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node138 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 138 =
      bitVecM31 row.rs2Next.limb1 - bitVecM31 row.rs2Previous.limb1 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node140 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 140 =
      bitVecM31 row.rs2Next.limb2 - bitVecM31 row.rs2Previous.limb2 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

set_option maxRecDepth 20000 in
private theorem node142 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 142 =
      bitVecM31 row.rs2Next.limb3 - bitVecM31 row.rs2Previous.limb3 := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg

structure Acceptance (row : Row) (witness : Witness row) : Prop where
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true

structure Admission (row : Row) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  pcBound : row.pc.toNat + 4 < M31.modulus
  sourceOnePreviousBound : row.rs1PreviousClock < 2 ^ 26
  sourceTwoPreviousBound : row.rs2PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26

def comparisonBytes (result : Bool) : WordBytes where
  limb0 := BitVec.ofNat 8 (if result then 1 else 0)
  limb1 := BitVec.ofNat 8 0
  limb2 := BitVec.ofNat 8 0
  limb3 := BitVec.ofNat 8 0

@[simp]
theorem comparisonBytes_limb0_field (result : Bool) :
    bitVecM31 (comparisonBytes result).limb0 = boolM31 result := by
  cases result <;> rfl

@[simp]
theorem comparisonBytes_upper_fields (result : Bool) :
    bitVecM31 (comparisonBytes result).limb1 = 0 ∧
      bitVecM31 (comparisonBytes result).limb2 = 0 ∧
      bitVecM31 (comparisonBytes result).limb3 = 0 := by
  cases result <;> decide

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

private theorem m31SubEqOfEqAdd
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
      exact Nat.mod_eq_of_lt (by omega)
    rw [addValue] at values
    have reverse : left.val < offset.val := by omega
    apply M31.ext
    rw [M31.sub_val_of_lt left offset reverse]
    omega

private def keyMslField (signed : Bool) (key : Byte) : M31 :=
  bitVecM31 key - boolM31 signed * M31.reduce 128

private def keyByte (value : M31) : Byte :=
  BitVec.ofNat 8 value.val

private theorem keyByteField
    (value : M31)
    (bound : value.val < 256) :
    bitVecM31 (keyByte value) = value := by
  change M31.reduce (BitVec.ofNat 8 value.val).toNat = value
  have toNat : (BitVec.ofNat 8 value.val).toNat = value.val := by
    simp [Nat.mod_eq_of_lt bound]
  rw [toNat]
  exact M31.reduce_toNat value

set_option maxHeartbeats 0 in
set_option maxRecDepth 100000 in
private theorem keyPolynomialUnique
    (signed : Bool)
    (byte key : Byte)
    (polynomial :
      let difference := bitVecM31 byte - keyMslField signed key
      difference * (M31.reduce 256 - difference) = 0) :
    key.toNat =
      if signed then (byte.toNat + 128) % 256 else byte.toNat := by
  cases signed <;> revert byte key <;> decide

private theorem signedKeyModulo (byte : Byte) :
    (byte.toNat + 128) % 256 = byteKey .signed byte := by
  have byteBound := byte.isLt
  simp only [Nat.reducePow] at byteBound
  by_cases low : byte.toNat < 128
  · rw [Nat.mod_eq_of_lt (by omega)]
    simp [byteKey, low]
  · rw [Nat.mod_eq_sub_mod (by omega)]
    rw [Nat.mod_eq_of_lt (by omega)]
    simp [byteKey, low]

private theorem normalizedKey
    (kind : Kind)
    (byte : Byte)
    (rawMsl : M31)
    (keyBound :
      (rawMsl +
        boolM31 (isSigned kind) * M31.reduce 128).val < 256)
    (polynomial :
      (bitVecM31 byte - rawMsl) *
        (M31.reduce 256 - (bitVecM31 byte - rawMsl)) = 0) :
    (rawMsl +
      boolM31 (isSigned kind) * M31.reduce 128).val =
        byteKey kind byte := by
  let key :=
    rawMsl + boolM31 (isSigned kind) * M31.reduce 128
  let encodedKey := keyByte key
  have encodedKeyField : bitVecM31 encodedKey = key :=
    keyByteField key keyBound
  have rawFromKey :
      rawMsl =
        key - boolM31 (isSigned kind) * M31.reduce 128 := by
    symm
    apply m31SubEqOfEqAdd
    rfl
  have normalizedPolynomial :
      let difference :=
        bitVecM31 byte - keyMslField (isSigned kind) encodedKey
      difference * (M31.reduce 256 - difference) = 0 := by
    simpa [keyMslField, encodedKeyField, rawFromKey] using polynomial
  have finite :=
    keyPolynomialUnique
      (isSigned kind) byte encodedKey normalizedPolynomial
  have encodedKeyValue : encodedKey.toNat = key.val := by
    simp [encodedKey, keyByte]
    exact keyBound
  cases kind
  · simpa [key, isSigned, encodedKeyValue, signedKeyModulo] using finite
  · simpa [key, isSigned, encodedKeyValue, byteKey] using finite

private theorem reduceCongr {left right : Nat}
    (congruent : left % M31.modulus = right % M31.modulus) :
    M31.reduce left = M31.reduce right := by
  apply M31.ext
  simpa only [M31.reduce_val] using congruent

private theorem negOneMulPositive
    (value : Nat)
    (positive : 0 < value)
    (bound : value < M31.modulus) :
    M31.reduce (M31.modulus - 1) * M31.reduce value =
      M31.reduce (M31.modulus - value) := by
  rw [TeamACommon.reduceMul]
  apply reduceCongr
  have expand :
      (M31.modulus - 1) * value =
        M31.modulus * (value - 1) + (M31.modulus - value) := by
    simp only [M31.modulus_eq] at positive bound ⊢
    omega
  rw [expand, Nat.mul_add_mod]

private theorem negOneMulNegative
    (value : Nat)
    (bound : value < M31.modulus) :
    M31.reduce (M31.modulus - 1) *
        M31.reduce (M31.modulus - value) =
      M31.reduce value := by
  rw [TeamACommon.reduceMul]
  apply reduceCongr
  have expand :
      (M31.modulus - 1) * (M31.modulus - value) =
        M31.modulus * (M31.modulus - value - 1) + value := by
    simp only [M31.modulus_eq] at bound ⊢
    omega
  rw [expand, Nat.mul_add_mod]

private theorem negOneMulSub (left right : M31) :
    ((0 : M31) - 1) * (right - left) = left - right := by
  have negOne : (0 : M31) - 1 =
      M31.reduce (M31.modulus - 1) := by decide
  rw [negOne]
  rcases Nat.lt_trichotomy left.val right.val with order | equal | order
  · have differenceBound : right.val - left.val < M31.modulus := by
      have rightBound : right.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using right.isLt
      exact Nat.lt_of_le_of_lt (Nat.sub_le _ _) rightBound
    have rightSubLeft :
        right - left = M31.reduce (right.val - left.val) := by
      apply M31.ext
      calc
        (right - left).val = right.val - left.val :=
          M31.sub_val_of_le right left (Nat.le_of_lt order)
        _ = (M31.reduce (right.val - left.val)).val :=
          (M31.reduce_val_of_lt _ differenceBound).symm
    have leftSubRight :
        left - right =
          M31.reduce (M31.modulus - (right.val - left.val)) := by
      apply M31.ext
      have rightBound : right.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using right.isLt
      have reducedBound :
          M31.modulus - (right.val - left.val) < M31.modulus := by
        omega
      calc
        (left - right).val = M31.modulus + left.val - right.val :=
          M31.sub_val_of_lt left right order
        _ = M31.modulus - (right.val - left.val) := by omega
        _ = (M31.reduce
              (M31.modulus - (right.val - left.val))).val :=
          (M31.reduce_val_of_lt _ reducedBound).symm
    rw [rightSubLeft, leftSubRight]
    exact negOneMulPositive _ (by omega) differenceBound
  · have fieldEqual : left = right := M31.ext equal
    subst right
    simp
  · have differenceBound : left.val - right.val < M31.modulus := by
      have leftBound : left.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using left.isLt
      exact Nat.lt_of_le_of_lt (Nat.sub_le _ _) leftBound
    have rightSubLeft :
        right - left =
          M31.reduce (M31.modulus - (left.val - right.val)) := by
      apply M31.ext
      have leftBound : left.val < M31.modulus := by
        simpa [M31.modulus, M31.modulus_eq] using left.isLt
      have reducedBound :
          M31.modulus - (left.val - right.val) < M31.modulus := by
        omega
      calc
        (right - left).val = M31.modulus + right.val - left.val :=
          M31.sub_val_of_lt right left order
        _ = M31.modulus - (left.val - right.val) := by omega
        _ = (M31.reduce
              (M31.modulus - (left.val - right.val))).val :=
          (M31.reduce_val_of_lt _ reducedBound).symm
    have leftSubRight :
        left - right = M31.reduce (left.val - right.val) := by
      apply M31.ext
      calc
        (left - right).val = left.val - right.val :=
          M31.sub_val_of_le left right (Nat.le_of_lt order)
        _ = (M31.reduce (left.val - right.val)).val :=
          (M31.reduce_val_of_lt _ differenceBound).symm
    rw [rightSubLeft, leftSubRight]
    exact negOneMulNegative _ differenceBound

private theorem positiveSubImpliesLt
    (left right : M31)
    (leftBound : left.val < 256)
    (rightBound : right.val < 256)
    (difference : Byte)
    (positive : 0 < difference.toNat)
    (equation : bitVecM31 difference = right - left) :
    left.val < right.val := by
  have differenceBound : difference.toNat < 256 := by
    simpa using difference.isLt
  have values := congrArg M31.val equation
  have differenceValue :
      (bitVecM31 difference).val = difference.toNat :=
    Lui.bitVecM31_val difference (byteBound difference)
  rw [differenceValue] at values
  rcases Nat.lt_trichotomy left.val right.val with less | equal | reverse
  · exact less
  · have fieldsEqual : left = right := M31.ext equal
    rw [fieldsEqual, M31.sub_self] at equation
    have impossible := congrArg M31.val equation
    rw [differenceValue] at impossible
    change difference.toNat = 0 at impossible
    omega
  · rw [M31.sub_val_of_lt right left reverse] at values
    have modulusValue : M31.modulus = 2147483647 := M31.modulus_eq
    omega

@[simp]
private theorem comparisonSignFalse :
    comparisonSign false = (0 : M31) - 1 := by rfl

@[simp]
private theorem comparisonSignTrue :
    comparisonSign true = 1 := by decide

theorem orientedZero
    (result : Bool)
    (left right : M31)
    (equation : comparisonSign result * (right - left) = 0) :
    left = right := by
  cases result
  · have reversed : left - right = 0 := by
      rw [comparisonSignFalse, negOneMulSub] at equation
      exact equation
    exact (M31.sub_eq_zero_iff _ _).mp reversed
  · have forward : right - left = 0 := by
      rw [comparisonSignTrue, M31.one_mul] at equation
      exact equation
    exact (M31.sub_eq_zero_iff _ _).mp forward |>.symm

private theorem positiveFieldSubImpliesLt
    (left right difference : M31)
    (leftBound : left.val < 256)
    (rightBound : right.val < 256)
    (differencePositive : 0 < difference.val)
    (differenceBound : difference.val ≤ 2 ^ 20)
    (equation : difference = right - left) :
    left.val < right.val := by
  have values := congrArg M31.val equation
  rcases Nat.lt_trichotomy left.val right.val with less | equal | reverse
  · exact less
  · have fieldsEqual : left = right := M31.ext equal
    rw [fieldsEqual, M31.sub_self] at equation
    have impossible := congrArg M31.val equation
    change difference.val = 0 at impossible
    omega
  · rw [M31.sub_val_of_lt right left reverse] at values
    simp only [M31.modulus_eq] at values
    omega

/--
Pure comparator orientation contract shared by the LT and branch bridges.
The range-check hypothesis rules out a wrapped M31 subtraction.
-/
theorem orientedPositiveField
    (result : Bool)
    (left right difference : M31)
    (leftBound : left.val < 256)
    (rightBound : right.val < 256)
    (differencePositive : 0 < difference.val)
    (differenceBound : difference.val ≤ 2 ^ 20)
    (equation :
      difference = comparisonSign result * (right - left)) :
    result = decide (left.val < right.val) ∧ left ≠ right := by
  cases result
  · have reversed : difference = left - right := by
      rw [comparisonSignFalse, negOneMulSub] at equation
      exact equation
    have order :=
      positiveFieldSubImpliesLt right left difference
        rightBound leftBound differencePositive differenceBound reversed
    refine ⟨by simp [show ¬ left.val < right.val by omega], ?_⟩
    intro equal
    have := congrArg M31.val equal
    omega
  · have forward : difference = right - left := by
      rw [comparisonSignTrue, M31.one_mul] at equation
      exact equation
    have order :=
      positiveFieldSubImpliesLt left right difference
        leftBound rightBound differencePositive differenceBound forward
    refine ⟨by simp [order], ?_⟩
    intro equal
    have := congrArg M31.val equal
    omega

/--
The pure four-limb comparator contract implemented by the production LT and
branch AIR gadgets.  All fields remain raw; callers obtain these equations and
bounds from their own accepted constraint roots and live fixed-table requests.
-/
structure ComparatorContract where
  result : Bool
  leftTop : M31
  rightTop : M31
  left2 : M31
  right2 : M31
  left1 : M31
  right1 : M31
  left0 : M31
  right0 : M31
  marker0 : Bool
  marker1 : Bool
  marker2 : Bool
  marker3 : Bool
  difference : M31
  leftTopBound : leftTop.val < 256
  rightTopBound : rightTop.val < 256
  left2Bound : left2.val < 256
  right2Bound : right2.val < 256
  left1Bound : left1.val < 256
  right1Bound : right1.val < 256
  left0Bound : left0.val < 256
  right0Bound : right0.val < 256
  differencePositive :
    marker0 = true ∨ marker1 = true ∨
      marker2 = true ∨ marker3 = true →
        0 < difference.val
  differenceBound :
    marker0 = true ∨ marker1 = true ∨
      marker2 = true ∨ marker3 = true →
        difference.val ≤ 2 ^ 20
  topEqual :
    marker3 = false →
      comparisonSign result * (rightTop - leftTop) = 0
  topSelected :
    marker3 = true →
      difference =
        comparisonSign result * (rightTop - leftTop)
  limb2Equal :
    marker3 = false → marker2 = false →
      comparisonSign result * (right2 - left2) = 0
  limb2Selected :
    marker2 = true →
      difference =
        comparisonSign result * (right2 - left2)
  limb1Equal :
    marker3 = false → marker2 = false → marker1 = false →
      comparisonSign result * (right1 - left1) = 0
  limb1Selected :
    marker1 = true →
      difference =
        comparisonSign result * (right1 - left1)
  limb0Equal :
    marker3 = false → marker2 = false → marker1 = false →
      marker0 = false →
        comparisonSign result * (right0 - left0) = 0
  limb0Selected :
    marker0 = true →
      difference =
        comparisonSign result * (right0 - left0)
  noMarkerResult :
    marker3 = false → marker2 = false → marker1 = false →
      marker0 = false → result = false

def ComparatorContract.lexicographicLess
    (contract : ComparatorContract) : Bool :=
  if contract.leftTop = contract.rightTop then
    if contract.left2 = contract.right2 then
      if contract.left1 = contract.right1 then
        if contract.left0 = contract.right0 then
          false
        else
          decide (contract.left0.val < contract.right0.val)
      else
        decide (contract.left1.val < contract.right1.val)
    else
      decide (contract.left2.val < contract.right2.val)
  else
    decide (contract.leftTop.val < contract.rightTop.val)

/--
Any raw fields satisfying `ComparatorContract` compute the lexicographic
less-than bit.  This theorem is independent of a generated program.
-/
theorem comparisonCorrectOfContract
    (contract : ComparatorContract) :
    contract.result = contract.lexicographicLess := by
  cases marker3Case : contract.marker3
  · have top :=
      orientedZero contract.result contract.leftTop contract.rightTop
        (contract.topEqual marker3Case)
    cases marker2Case : contract.marker2
    · have limb2 :=
        orientedZero contract.result contract.left2 contract.right2
          (contract.limb2Equal marker3Case marker2Case)
      cases marker1Case : contract.marker1
      · have limb1 :=
          orientedZero contract.result contract.left1 contract.right1
            (contract.limb1Equal marker3Case marker2Case marker1Case)
        cases marker0Case : contract.marker0
        · have limb0 :=
            orientedZero contract.result contract.left0 contract.right0
              (contract.limb0Equal marker3Case marker2Case marker1Case
                marker0Case)
          simpa [ComparatorContract.lexicographicLess, top, limb2, limb1,
            limb0] using
            contract.noMarkerResult marker3Case marker2Case marker1Case
              marker0Case
        · have selected :=
            orientedPositiveField contract.result contract.left0
              contract.right0 contract.difference contract.left0Bound
              contract.right0Bound
              (contract.differencePositive (Or.inl marker0Case))
              (contract.differenceBound (Or.inl marker0Case))
              (contract.limb0Selected marker0Case)
          simpa [ComparatorContract.lexicographicLess, top, limb2, limb1,
            selected.2] using selected.1
      · have selected :=
          orientedPositiveField contract.result contract.left1
            contract.right1 contract.difference contract.left1Bound
            contract.right1Bound
            (contract.differencePositive (Or.inr (Or.inl marker1Case)))
            (contract.differenceBound (Or.inr (Or.inl marker1Case)))
            (contract.limb1Selected marker1Case)
        simpa [ComparatorContract.lexicographicLess, top, limb2,
          selected.2] using selected.1
    · have selected :=
        orientedPositiveField contract.result contract.left2
          contract.right2 contract.difference contract.left2Bound
          contract.right2Bound
          (contract.differencePositive
            (Or.inr (Or.inr (Or.inl marker2Case))))
          (contract.differenceBound
            (Or.inr (Or.inr (Or.inl marker2Case))))
          (contract.limb2Selected marker2Case)
      simpa [ComparatorContract.lexicographicLess, top, selected.2] using
        selected.1
  · have selected :=
      orientedPositiveField contract.result contract.leftTop
        contract.rightTop contract.difference contract.leftTopBound
        contract.rightTopBound
        (contract.differencePositive
          (Or.inr (Or.inr (Or.inr marker3Case))))
        (contract.differenceBound
          (Or.inr (Or.inr (Or.inr marker3Case))))
        (contract.topSelected marker3Case)
    simpa [ComparatorContract.lexicographicLess, selected.2] using selected.1

private theorem orientedPositive
    (result : Bool)
    (left right : M31)
    (leftBound : left.val < 256)
    (rightBound : right.val < 256)
    (difference : Byte)
    (positive : 0 < difference.toNat)
    (equation :
      bitVecM31 difference =
        comparisonSign result * (right - left)) :
    result = decide (left.val < right.val) ∧ left ≠ right := by
  cases result
  · have reversed :
        bitVecM31 difference = left - right := by
      rw [comparisonSignFalse, negOneMulSub] at equation
      exact equation
    have order :=
      positiveSubImpliesLt right left rightBound leftBound
        difference positive reversed
    refine ⟨by simp [show ¬ left.val < right.val by omega], ?_⟩
    intro equal
    have := congrArg M31.val equal
    omega
  · have forward :
        bitVecM31 difference = right - left := by
      rw [comparisonSignTrue, M31.one_mul] at equation
      exact equation
    have order :=
      positiveSubImpliesLt left right leftBound rightBound
        difference positive forward
    refine ⟨by simp [order], ?_⟩
    intro equal
    have := congrArg M31.val equal
    omega

private theorem mslLookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 45 =
      some (mslRangeLookup row witness) := by
  rcases lookupProjection row witness with
    ⟨_, _, _, _, _, _, _, _, _, selected, _⟩
  exact selected

private theorem differenceLookupProjection
    (row : Row)
    (witness : Witness row) :
    (evaluation row witness).lookup? 46 =
      some (positiveDifferenceLookup row witness) := by
  rcases lookupProjection row witness with
    ⟨_, _, _, _, _, _, _, _, _, _, selected, _⟩
  exact selected

theorem mslRangeBounds
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (sourceOneKey row witness).val < 256 ∧
      (sourceTwoKey row witness).val < 256 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation row witness) 45 (mslRangeLookup row witness)
      accepted.fixedLookups (mslLookupProjection row witness)
  have live :
      (mslRangeLookup row witness).isLive = true := by
    simp [mslRangeLookup, EvaluatedLookup.isLive]
    decide
  rw [EvaluatedLookup.fixedRequestHolds, live] at request
  have membership :
      FixedTableId.rangeCheck88.contains
        [sourceOneKey row witness, sourceTwoKey row witness] = true := by
    simpa [mslRangeLookup, EvaluatedLookup.fixedMembership] using request
  exact (FixedTableId.rangeCheck88_contains_iff _ _).mp membership

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

private theorem positiveDifferenceLive
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

private theorem positiveDifferenceRequestHolds
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (positiveDifferenceLookup row witness).fixedRequestHolds = true :=
  SymbolicEvaluation.fixedRequestHolds_of_lookup
    (evaluation row witness) 46
    (positiveDifferenceLookup row witness)
    accepted.fixedLookups (differenceLookupProjection row witness)

private theorem rangeCheck20RequestHolds_iff
    (numerator value : M31)
    (live : (numerator != (0 : M31)) = true) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal := 46
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
  have live :
      (-markerPrefix witness != (0 : M31)) = true := by
    simpa [positiveDifferenceLookup, EvaluatedLookup.isLive] using
      positiveDifferenceLive row witness anyMarker
  apply
    (rangeCheck20RequestHolds_iff
      (-markerPrefix witness)
      (bitVecM31 witness.difference - 1) live).mp
  simpa only [positiveDifferenceLookup] using
    positiveDifferenceRequestHolds row witness accepted

private theorem bytePositiveOfDifferenceBound
    (difference : Byte)
    (bound : (bitVecM31 difference - 1).val < 2 ^ 20) :
    0 < difference.toNat := by
  by_cases positive : 0 < difference.toNat
  · exact positive
  · have zero : difference.toNat = 0 := by omega
    have byteZero :
        difference = BitVec.ofNat 8 0 :=
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

theorem differencePositive
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness)
    (anyMarker :
      witness.marker0 = true ∨ witness.marker1 = true ∨
        witness.marker2 = true ∨ witness.marker3 = true) :
    0 < witness.difference.toNat :=
  bytePositiveOfDifferenceBound witness.difference
    (positiveDifferenceBound row witness accepted anyMarker)

theorem normalizedKeys
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    (sourceOneKey row witness).val =
        byteKey row.kind row.rs1Next.limb3 ∧
      (sourceTwoKey row witness).val =
        byteKey row.kind row.rs2Next.limb3 := by
  have bounds := mslRangeBounds row witness accepted
  have firstRoot :=
    constraintRootZero row witness accepted.constraints 78
      (by simp [constraintRoots])
  have secondRoot :=
    constraintRootZero row witness accepted.constraints 80
      (by simp [constraintRoots])
  rw [node78] at firstRoot
  rw [node80] at secondRoot
  exact ⟨
    normalizedKey row.kind row.rs1Next.limb3 witness.sourceOneMsl
      bounds.1 firstRoot,
    normalizedKey row.kind row.rs2Next.limb3 witness.sourceTwoMsl
      bounds.2 secondRoot
  ⟩

private theorem m31EqAddOfSubEq
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
    have sumBound : right.val + offset.val < M31.modulus := by omega
    apply M31.ext
    rw [M31.add_val_of_lt right offset sumBound]
    omega
  · have reverse : left.val < right.val := Nat.lt_of_not_ge ordered
    rw [M31.sub_val_of_lt left right reverse] at values
    apply M31.ext
    change left.val = (right.val + offset.val) % M31.modulus
    have sum :
        right.val + offset.val = M31.modulus + left.val := by omega
    rw [sum, Nat.add_mod_left]
    exact (Nat.mod_eq_of_lt leftBound).symm

private theorem m31AddComm (left right : M31) :
    left + right = right + left := by
  apply M31.ext
  change
    (left.val + right.val) % M31.modulus =
      (right.val + left.val) % M31.modulus
  rw [Nat.add_comm]

private theorem m31AddAssoc (first second third : M31) :
    (first + second) + third = first + (second + third) := by
  rw [
    ← M31.reduce_toNat first,
    ← M31.reduce_toNat second,
    ← M31.reduce_toNat third,
    TeamACommon.reduceAdd,
    TeamACommon.reduceAdd,
    TeamACommon.reduceAdd,
    TeamACommon.reduceAdd,
  ]
  congr 1
  omega

private theorem translatedSub
    (left right offset : M31) :
    right - left = (right + offset) - (left + offset) := by
  let difference := right - left
  have rightEquation : right = left + difference :=
    m31EqAddOfSubEq right left difference rfl
  have shifted :
      right + offset = difference + (left + offset) := by
    calc
      right + offset = (left + difference) + offset := by
        rw [rightEquation]
      _ = left + (difference + offset) :=
        m31AddAssoc left difference offset
      _ = left + (offset + difference) := by
        rw [m31AddComm difference offset]
      _ = (left + offset) + difference :=
        (m31AddAssoc left offset difference).symm
      _ = difference + (left + offset) :=
        m31AddComm (left + offset) difference
  exact
    (m31SubEqOfEqAdd
      (right + offset) difference (left + offset) shifted).symm

private theorem signedMslSubEqKeySub
    (leftMsl rightMsl : M31) :
    rightMsl - leftMsl =
      (rightMsl + M31.reduce 128) -
        (leftMsl + M31.reduce 128) := by
  exact translatedSub leftMsl rightMsl (M31.reduce 128)

private theorem mslSubEqKeySub
    (kind : Kind)
    (leftMsl rightMsl : M31) :
    rightMsl - leftMsl =
      (rightMsl + signedOffset kind) -
        (leftMsl + signedOffset kind) := by
  cases kind
  · simpa [signedOffset, isSigned, boolM31,
      TeamACommon.boolM31, Lui.boolM31] using
      signedMslSubEqKeySub leftMsl rightMsl
  · simp [signedOffset, isSigned, boolM31,
      TeamACommon.boolM31, Lui.boolM31]

theorem comparisonCorrect
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    witness.comparisonResult =
      semanticLess row.kind row.rs1Next row.rs2Next := by
  have zero (root : Nat) (member : root ∈ constraintRoots) :=
    constraintRootZero row witness accepted.constraints root member
  have keys := normalizedKeys row witness accepted
  have keyBounds := mslRangeBounds row witness accepted
  have fieldValue (byte : Byte) :
      (bitVecM31 byte).val = byte.toNat :=
    Lui.bitVecM31_val byte (byteBound byte)
  have fieldBound (byte : Byte) :
      (bitVecM31 byte).val < 256 := by
    rw [fieldValue]
    simpa using byte.isLt
  have topEqual
      (markerOff : witness.marker3 = false) :
      sourceOneKey row witness = sourceTwoKey row witness := by
    have equation := zero 85 (by simp [constraintRoots])
    rw [node85, markerOff] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    rw [mslSubEqKeySub row.kind] at equation
    exact
      orientedZero witness.comparisonResult
        (sourceOneKey row witness) (sourceTwoKey row witness) equation
  have topSelected
      (markerOn : witness.marker3 = true) :
      witness.comparisonResult =
          decide ((sourceOneKey row witness).val <
            (sourceTwoKey row witness).val) ∧
        sourceOneKey row witness ≠ sourceTwoKey row witness := by
    have equation := zero 87 (by simp [constraintRoots])
    rw [node87, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected :
        bitVecM31 witness.difference =
          comparisonSign witness.comparisonResult *
            (witness.sourceTwoMsl - witness.sourceOneMsl) :=
      (M31.sub_eq_zero_iff _ _).mp equation
    rw [mslSubEqKeySub row.kind] at selected
    exact
      orientedPositive witness.comparisonResult
        (sourceOneKey row witness) (sourceTwoKey row witness)
        keyBounds.1 keyBounds.2 witness.difference
        (differencePositive row witness accepted
          (Or.inr (Or.inr (Or.inr markerOn))))
        selected
  have limb2Equal
      (marker3Off : witness.marker3 = false)
      (marker2Off : witness.marker2 = false) :
      row.rs1Next.limb2 = row.rs2Next.limb2 := by
    have equation := zero 93 (by simp [constraintRoots])
    rw [node93, marker3Off, marker2Off] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    exact byteEq _ _ (orientedZero witness.comparisonResult _ _ equation)
  have limb2Selected
      (markerOn : witness.marker2 = true) :
      witness.comparisonResult =
          decide (row.rs1Next.limb2.toNat < row.rs2Next.limb2.toNat) ∧
        row.rs1Next.limb2 ≠ row.rs2Next.limb2 := by
    have equation := zero 95 (by simp [constraintRoots])
    rw [node95, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected :
        bitVecM31 witness.difference =
          comparisonSign witness.comparisonResult *
            (bitVecM31 row.rs2Next.limb2 -
              bitVecM31 row.rs1Next.limb2) :=
      (M31.sub_eq_zero_iff _ _).mp equation
    have result :=
      orientedPositive witness.comparisonResult
        (bitVecM31 row.rs1Next.limb2)
        (bitVecM31 row.rs2Next.limb2)
        (fieldBound _) (fieldBound _) witness.difference
        (differencePositive row witness accepted
          (Or.inr (Or.inr (Or.inl markerOn))))
        selected
    refine ⟨?_, ?_⟩
    · simpa [fieldValue] using result.1
    · intro equal
      exact result.2 (congrArg bitVecM31 equal)
  have limb1Equal
      (marker3Off : witness.marker3 = false)
      (marker2Off : witness.marker2 = false)
      (marker1Off : witness.marker1 = false) :
      row.rs1Next.limb1 = row.rs2Next.limb1 := by
    have equation := zero 101 (by simp [constraintRoots])
    rw [node101, marker3Off, marker2Off, marker1Off] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    exact byteEq _ _ (orientedZero witness.comparisonResult _ _ equation)
  have limb1Selected
      (markerOn : witness.marker1 = true) :
      witness.comparisonResult =
          decide (row.rs1Next.limb1.toNat < row.rs2Next.limb1.toNat) ∧
        row.rs1Next.limb1 ≠ row.rs2Next.limb1 := by
    have equation := zero 103 (by simp [constraintRoots])
    rw [node103, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected :
        bitVecM31 witness.difference =
          comparisonSign witness.comparisonResult *
            (bitVecM31 row.rs2Next.limb1 -
              bitVecM31 row.rs1Next.limb1) :=
      (M31.sub_eq_zero_iff _ _).mp equation
    have result :=
      orientedPositive witness.comparisonResult
        (bitVecM31 row.rs1Next.limb1)
        (bitVecM31 row.rs2Next.limb1)
        (fieldBound _) (fieldBound _) witness.difference
        (differencePositive row witness accepted
          (Or.inr (Or.inl markerOn)))
        selected
    refine ⟨?_, ?_⟩
    · simpa [fieldValue] using result.1
    · intro equal
      exact result.2 (congrArg bitVecM31 equal)
  have limb0Equal
      (marker3Off : witness.marker3 = false)
      (marker2Off : witness.marker2 = false)
      (marker1Off : witness.marker1 = false)
      (marker0Off : witness.marker0 = false) :
      row.rs1Next.limb0 = row.rs2Next.limb0 := by
    have equation := zero 109 (by simp [constraintRoots])
    rw [node109, marker3Off, marker2Off, marker1Off, marker0Off] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    exact byteEq _ _ (orientedZero witness.comparisonResult _ _ equation)
  have limb0Selected
      (markerOn : witness.marker0 = true) :
      witness.comparisonResult =
          decide (row.rs1Next.limb0.toNat < row.rs2Next.limb0.toNat) ∧
        row.rs1Next.limb0 ≠ row.rs2Next.limb0 := by
    have equation := zero 111 (by simp [constraintRoots])
    rw [node111, markerOn] at equation
    simp [boolM31, TeamACommon.boolM31, Lui.boolM31] at equation
    have selected :
        bitVecM31 witness.difference =
          comparisonSign witness.comparisonResult *
            (bitVecM31 row.rs2Next.limb0 -
              bitVecM31 row.rs1Next.limb0) :=
      (M31.sub_eq_zero_iff _ _).mp equation
    have result :=
      orientedPositive witness.comparisonResult
        (bitVecM31 row.rs1Next.limb0)
        (bitVecM31 row.rs2Next.limb0)
        (fieldBound _) (fieldBound _) witness.difference
        (differencePositive row witness accepted (Or.inl markerOn))
        selected
    refine ⟨?_, ?_⟩
    · simpa [fieldValue] using result.1
    · intro equal
      exact result.2 (congrArg bitVecM31 equal)
  cases marker3Case : witness.marker3
  · have top := topEqual marker3Case
    have topArchitectural :
        topKey row.kind row.rs1Next = topKey row.kind row.rs2Next := by
      calc
        topKey row.kind row.rs1Next =
            byteKey row.kind row.rs1Next.limb3 :=
          topKey_eq_byteKey _ _
        _ = (sourceOneKey row witness).val := keys.1.symm
        _ = (sourceTwoKey row witness).val := congrArg M31.val top
        _ = byteKey row.kind row.rs2Next.limb3 := keys.2
        _ = topKey row.kind row.rs2Next :=
          (topKey_eq_byteKey _ _).symm
    cases marker2Case : witness.marker2
    · have limb2 := limb2Equal marker3Case marker2Case
      cases marker1Case : witness.marker1
      · have limb1 := limb1Equal marker3Case marker2Case marker1Case
        cases marker0Case : witness.marker0
        · have limb0 :=
            limb0Equal marker3Case marker2Case marker1Case marker0Case
          have equation := zero 114 (by simp [constraintRoots])
          rw [node114] at equation
          simp [markerPrefix, marker3Case, marker2Case, marker1Case,
            marker0Case, boolM31, TeamACommon.boolM31,
            Lui.boolM31] at equation
          have resultFalse : witness.comparisonResult = false := by
            cases resultCase : witness.comparisonResult
            · rfl
            · have impossible : (1 : M31) = 0 := by
                simpa [resultCase, boolM31, TeamACommon.boolM31,
                  Lui.boolM31] using equation
              exact False.elim ((by decide : (1 : M31) ≠ 0) impossible)
          simp [semanticLess, topArchitectural, limb2, limb1, limb0,
            resultFalse]
        · have selected := limb0Selected marker0Case
          simpa [semanticLess, topArchitectural, limb2, limb1,
            selected.2] using selected.1
      · have selected := limb1Selected marker1Case
        simpa [semanticLess, topArchitectural, limb2, selected.2] using
          selected.1
    · have selected := limb2Selected marker2Case
      simpa [semanticLess, topArchitectural, selected.2] using selected.1
  · have selected := topSelected marker3Case
    have keyValuesNe :
        (sourceOneKey row witness).val ≠
          (sourceTwoKey row witness).val := by
      intro equal
      exact selected.2 (M31.ext equal)
    have firstTop :
        topKey row.kind row.rs1Next =
          (sourceOneKey row witness).val := by
      rw [topKey_eq_byteKey]
      exact keys.1.symm
    have secondTop :
        topKey row.kind row.rs2Next =
          (sourceTwoKey row witness).val := by
      rw [topKey_eq_byteKey]
      exact keys.2.symm
    simpa [semanticLess, firstTop, secondTop, keyValuesNe] using selected.1

theorem sourceReadOnly
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rs1Next = row.rs1Previous ∧
      row.rs2Next = row.rs2Previous := by
  have zero (root : Nat) (member : root ∈ constraintRoots) :=
    constraintRootZero row witness accepted.constraints root member
  apply And.intro <;> apply WordBytes.eq_of_limbs
  · apply byteEq
    have h := zero 128 (by simp [constraintRoots])
    rw [node128] at h
    exact (M31.sub_eq_zero_iff _ _).mp h
  · apply byteEq
    have h := zero 130 (by simp [constraintRoots])
    rw [node130] at h
    exact (M31.sub_eq_zero_iff _ _).mp h
  · apply byteEq
    have h := zero 132 (by simp [constraintRoots])
    rw [node132] at h
    exact (M31.sub_eq_zero_iff _ _).mp h
  · apply byteEq
    have h := zero 134 (by simp [constraintRoots])
    rw [node134] at h
    exact (M31.sub_eq_zero_iff _ _).mp h
  · apply byteEq
    have h := zero 136 (by simp [constraintRoots])
    rw [node136] at h
    exact (M31.sub_eq_zero_iff _ _).mp h
  · apply byteEq
    have h := zero 138 (by simp [constraintRoots])
    rw [node138] at h
    exact (M31.sub_eq_zero_iff _ _).mp h
  · apply byteEq
    have h := zero 140 (by simp [constraintRoots])
    rw [node140] at h
    exact (M31.sub_eq_zero_iff _ _).mp h
  · apply byteEq
    have h := zero 142 (by simp [constraintRoots])
    rw [node142] at h
    exact (M31.sub_eq_zero_iff _ _).mp h

theorem destinationResult
    (row : Row)
    (witness : Witness row)
    (accepted : Acceptance row witness) :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) ∧
      row.rdNext =
        if row.rdNonzero
        then comparisonBytes witness.comparisonResult
        else WordBytes.zero := by
  have zero (root : Nat) (member : root ∈ constraintRoots) :=
    constraintRootZero row witness accepted.constraints root member
  have flagZero := zero 118 (by simp [constraintRoots])
  have flagInv := zero 120 (by simp [constraintRoots])
  rw [node118] at flagZero
  rw [node120] at flagInv
  refine ⟨TeamACommon.destinationFlag_of_equations
      row.rd row.rdNonzero witness.destinationInverse flagZero flagInv, ?_⟩
  apply TeamACommon.destinationBytes_of_equations
  · simpa using (by
      have h := zero 122 (by simp [constraintRoots])
      rw [node122] at h
      exact h)
  · simpa using (by
      have h := zero 124 (by simp [constraintRoots])
      rw [node124] at h
      exact h)
  · simpa using (by
      have h := zero 125 (by simp [constraintRoots])
      rw [node125] at h
      exact h)
  · simpa using (by
      have h := zero 126 (by simp [constraintRoots])
      rw [node126] at h
      exact h)

structure ProductionRefinement (row : Row) (witness : Witness row) : Prop where
  sourceDigest :
    (program row.kind).source.contentDigest = contentDigest row.kind
  selectors : (evaluation row witness).activeSelectorsAccepted = true
  constraints : (evaluation row witness).constraintsHold = true
  fixedLookups : (evaluation row witness).fixedLookupsHold = true
  exactLookups :
    (evaluation row witness).lookup? 36 = some (programLookup row) ∧
    (evaluation row witness).lookup? 37 = some (stateConsumeLookup row) ∧
    (evaluation row witness).lookup? 38 = some (stateEmitLookup row) ∧
    (evaluation row witness).lookup? 39 = some (sourceConsumeLookup row false) ∧
    (evaluation row witness).lookup? 40 = some (sourceEmitLookup row false) ∧
    (evaluation row witness).lookup? 41 = some (sourceClockLookup row false) ∧
    (evaluation row witness).lookup? 42 = some (sourceConsumeLookup row true) ∧
    (evaluation row witness).lookup? 43 = some (sourceEmitLookup row true) ∧
    (evaluation row witness).lookup? 44 = some (sourceClockLookup row true) ∧
    (evaluation row witness).lookup? 45 =
      some (mslRangeLookup row witness) ∧
    (evaluation row witness).lookup? 46 =
      some (positiveDifferenceLookup row witness) ∧
    (evaluation row witness).lookup? 47 = some (destinationConsumeLookup row) ∧
    (evaluation row witness).lookup? 48 = some (destinationEmitLookup row) ∧
    (evaluation row witness).lookup? 49 = some (destinationClockLookup row)
  projection :
    (program row.kind).source.projection.programEvent = 36 ∧
      (program row.kind).source.projection.stateEvents = #[37, 38] ∧
      (program row.kind).source.projection.sourceEvents = #[39, 40, 42, 43] ∧
      (program row.kind).source.projection.destinationEvents = #[47, 48] ∧
      (program row.kind).source.projection.nextPc = 161
  sourcesReadOnly :
    row.rs1Next = row.rs1Previous ∧ row.rs2Next = row.rs2Previous
  comparison :
    witness.comparisonResult =
      semanticLess row.kind row.rs1Next row.rs2Next
  destination :
    row.rdNonzero = decide (row.rd ≠ zeroRegister) ∧
      row.rdNext =
        if row.rdNonzero
        then comparisonBytes
          (semanticLess row.kind row.rs1Next row.rs2Next)
        else WordBytes.zero
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
    exactLookups := lookupProjection row witness
    projection := ?_
    sourcesReadOnly := sourceReadOnly row witness accepted
    comparison := comparisonCorrect row witness accepted
    destination := ?_
    nextPc := ?_
    nextClock := ?_
  }
  · cases row.kind <;> decide
  · have destination := destinationResult row witness accepted
    rw [comparisonCorrect row witness accepted] at destination
    exact destination
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
  rdNext := { WordBytes.zero with limb0 := BitVec.ofNat 8 1 }
  rs1 := BitVec.ofNat 5 2
  rs1Previous := { WordBytes.zero with limb0 := BitVec.ofNat 8 1 }
  rs1PreviousClock := 0
  rs1Next := { WordBytes.zero with limb0 := BitVec.ofNat 8 1 }
  rs2 := BitVec.ofNat 5 3
  rs2Previous := { WordBytes.zero with limb0 := BitVec.ofNat 8 2 }
  rs2PreviousClock := 0
  rs2Next := { WordBytes.zero with limb0 := BitVec.ofNat 8 2 }
  rdNonzero := true

def exampleWitness : Witness exampleRow where
  comparisonResult := true
  sourceOneMsl := 0
  sourceTwoMsl := 0
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
    reduce_ltreg <;> decide
  · simp only [exampleRow, exampleWitness]
    reduce_ltreg <;> decide

theorem acceptanceNonvacuous :
    ∃ row witness, Admission row ∧ Acceptance row witness :=
  ⟨exampleRow, exampleWitness, exampleAdmission, exampleAcceptance⟩

/- The high-bit pair distinguishes signed from unsigned comparison.  The
signed row also exercises `rd = rs1`; the unsigned row writes x0. -/
def highBitBytes : WordBytes :=
  { WordBytes.zero with limb3 := BitVec.ofNat 8 128 }

def highBitRow (kind : Kind) : Row where
  kind := kind
  clock := 1
  pc := BitVec.ofNat 32 0x1000
  rd := match kind with
    | .signed => BitVec.ofNat 5 1
    | .unsigned => zeroRegister
  rdPrevious := match kind with
    | .signed => highBitBytes
    | .unsigned => WordBytes.zero
  rdPreviousClock := match kind with
    | .signed => 1
    | .unsigned => 0
  rdNext := match kind with
    | .signed => comparisonBytes true
    | .unsigned => WordBytes.zero
  rs1 := BitVec.ofNat 5 1
  rs1Previous := highBitBytes
  rs1PreviousClock := 0
  rs1Next := highBitBytes
  rs2 := BitVec.ofNat 5 2
  rs2Previous := WordBytes.zero
  rs2PreviousClock := 0
  rs2Next := WordBytes.zero
  rdNonzero := match kind with
    | .signed => true
    | .unsigned => false

def highBitWitness (kind : Kind) : Witness (highBitRow kind) where
  comparisonResult := match kind with
    | .signed => true
    | .unsigned => false
  sourceOneMsl := match kind with
    | .signed => 0 - M31.reduce 128
    | .unsigned => M31.reduce 128
  sourceTwoMsl := 0
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
      simp only [highBitRow, highBitWitness, highBitBytes] <;>
      reduce_ltreg <;> decide
  · cases kind <;>
      simp only [highBitRow, highBitWitness, highBitBytes] <;>
      reduce_ltreg <;> decide

theorem signedHighBitResult :
    semanticLess .signed highBitBytes WordBytes.zero = true := by
  decide

theorem unsignedHighBitResult :
    semanticLess .unsigned highBitBytes WordBytes.zero = false := by
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

end RiscvRefinement.Air.Bridge.LtReg
