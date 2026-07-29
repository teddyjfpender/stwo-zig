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
      "9428afb3998e1bb4710ec0af937de55039b8bd6e6de6cf6a8ba98b9b506661a8"
  | .unsigned =>
      "7be3d65864cfd73580221d5e86a52a7e171595913fa740270f82d62e27d4f328"

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

def comparisonSign (row : Row) : M31 :=
  boolM31 (semanticLess row.kind row.rs1Next row.rs2Next) *
      M31.reduce 2 -
    1

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
  | 32 => boolM31 (semanticLess row.kind row.rs1Next row.rs2Next)
  | 33 => mslField row.kind row.rs1Next
  | 34 => mslField row.kind row.rs2Next
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

def mslRangeLookup (row : Row) : EvaluatedLookup where
  ordinal := 45
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    mslField row.kind row.rs1Next +
      boolM31 (isSigned row.kind) * M31.reduce 128,
    mslField row.kind row.rs2Next +
      boolM31 (isSigned row.kind) * M31.reduce 128
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
    (evaluation row witness).lookup? 45 = some (mslRangeLookup row) ∧
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
private theorem node85 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 85 =
      (1 - boolM31 witness.marker3) *
        (comparisonSign row *
          (mslField row.kind row.rs2Next - mslField row.kind row.rs1Next)) := by
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
          comparisonSign row *
            (mslField row.kind row.rs2Next - mslField row.kind row.rs1Next)) := by
  cases kind : row.kind
  all_goals simp only [evaluation, kind, program]
  all_goals reduce_ltreg
  all_goals simp [kind, comparisonSign, mslField, isSigned, Lui.boolM31]

set_option maxRecDepth 20000 in
private theorem node93 (row : Row) (witness : Witness row) :
    (evaluation row witness).nodes.getSymbolic 93 =
      (1 - boolM31 witness.marker3 - boolM31 witness.marker2) *
        (comparisonSign row *
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
          comparisonSign row *
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
        (comparisonSign row *
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
          comparisonSign row *
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
        (comparisonSign row *
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
          comparisonSign row *
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
        boolM31 (semanticLess row.kind row.rs1Next row.rs2Next) := by
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
          boolM31 (semanticLess row.kind row.rs1Next row.rs2Next) := by
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
        then comparisonBytes
          (semanticLess row.kind row.rs1Next row.rs2Next)
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
    (evaluation row witness).lookup? 45 = some (mslRangeLookup row) ∧
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
    destination := destinationResult row witness accepted
    nextPc := ?_
    nextClock := ?_
  }
  · cases row.kind <;> decide
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
