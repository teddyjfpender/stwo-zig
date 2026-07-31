import RiscvRefinement.Air.Generated.Programs
import RiscvRefinement.Air.Bridge.MulBridge
import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Opcodes.LoadStore
import RiscvRefinement.Publication.Acceptance
import RiscvRefinement.Publication.TeamB.Common
import RiscvRefinement.Publication.Universal

/-!
# Publication bridge for the eight load/store instructions

The public theorems in this module start from acceptance of an exact generated
`LocalProgram`.  `LoadStoreHolds`, the architectural refinement, and the exact
ordered relation tuples are conclusions.

The current generated family has 56 columns, 325 localized nodes, 71 direct
constraints, and 16 lookups.  The eight programs share the same nodes and
events; their committed manifest identity is the only evaluator metadata that
differs.
-/

namespace RiscvRefinement.Publication.TeamB.LoadStore

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

private def bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  M31.reduce value.toNat

private def boolM31 : Bool → M31
  | false => 0
  | true => 1

inductive Kind where
  | lb
  | lh
  | lw
  | lbu
  | lhu
  | sb
  | sh
  | sw
deriving DecidableEq, Repr

def program : Kind → LocalProgram
  | .lb => Programs.lb
  | .lh => Programs.lh
  | .lw => Programs.lw
  | .lbu => Programs.lbu
  | .lhu => Programs.lhu
  | .sb => Programs.sb
  | .sh => Programs.sh
  | .sw => Programs.sw

def manifestId : Kind → Nat
  | .lb => 19
  | .lh => 20
  | .lw => 21
  | .lbu => 22
  | .lhu => 23
  | .sb => 24
  | .sh => 25
  | .sw => 26

def selected (kind : Kind) (row : LoadStoreRow) : Bool :=
  match kind with
  | .lb => row.isLb
  | .lh => row.isLh
  | .lw => row.isLw
  | .lbu => row.isLbu
  | .lhu => row.isLhu
  | .sb => row.isSb
  | .sh => row.isSh
  | .sw => row.isSw

structure Witness (row : LoadStoreRow) where
  /-- The two generated address columns are witness-role columns and remain
  absent from every constraint and lookup. -/
  destinationAddress : M31
  sourceAddress : M31
  destinationInverse : M31

/-- Exact 56-column order shared by all eight generated programs. -/
def columns (row : LoadStoreRow) (witness : Witness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => witness.destinationAddress
  | 3 => bitVecM31 row.dstPrevious.limb0
  | 4 => bitVecM31 row.dstPrevious.limb1
  | 5 => bitVecM31 row.dstPrevious.limb2
  | 6 => bitVecM31 row.dstPrevious.limb3
  | 7 => M31.reduce row.dstPreviousClock
  | 8 => bitVecM31 row.dstNext.limb0
  | 9 => bitVecM31 row.dstNext.limb1
  | 10 => bitVecM31 row.dstNext.limb2
  | 11 => bitVecM31 row.dstNext.limb3
  | 12 => bitVecM31 row.rs1Addr
  | 13 => bitVecM31 row.rs1Previous.limb0
  | 14 => bitVecM31 row.rs1Previous.limb1
  | 15 => bitVecM31 row.rs1Previous.limb2
  | 16 => bitVecM31 row.rs1Previous.limb3
  | 17 => M31.reduce row.rs1PreviousClock
  | 18 => bitVecM31 row.rs1Next.limb0
  | 19 => bitVecM31 row.rs1Next.limb1
  | 20 => bitVecM31 row.rs1Next.limb2
  | 21 => bitVecM31 row.rs1Next.limb3
  | 22 => witness.sourceAddress
  | 23 => bitVecM31 row.srcPrevious.limb0
  | 24 => bitVecM31 row.srcPrevious.limb1
  | 25 => bitVecM31 row.srcPrevious.limb2
  | 26 => bitVecM31 row.srcPrevious.limb3
  | 27 => M31.reduce row.srcPreviousClock
  | 28 => bitVecM31 row.srcNext.limb0
  | 29 => bitVecM31 row.srcNext.limb1
  | 30 => bitVecM31 row.srcNext.limb2
  | 31 => bitVecM31 row.srcNext.limb3
  | 32 => bitVecM31 row.r2Idx
  | 33 => M31.reduce row.immFelt
  | 34 => boolM31 row.srcMsb
  | 35 => M31.reduce row.shiftAmount
  | 36 => M31.reduce row.sourceSelector
  | 37 => M31.reduce row.destinationSelector
  | 38 => boolM31 row.marker0
  | 39 => boolM31 row.marker1
  | 40 => boolM31 row.marker2
  | 41 => boolM31 row.marker3
  | 42 => boolM31 row.isLb
  | 43 => boolM31 row.isLh
  | 44 => boolM31 row.isLbu
  | 45 => boolM31 row.isLhu
  | 46 => boolM31 row.isLw
  | 47 => boolM31 row.isSb
  | 48 => boolM31 row.isSh
  | 49 => boolM31 row.isSw
  | 50 => bitVecM31 row.result.limb0
  | 51 => bitVecM31 row.result.limb1
  | 52 => bitVecM31 row.result.limb2
  | 53 => bitVecM31 row.result.limb3
  | 54 => boolM31 row.destinationNonzero
  | 55 => witness.destinationInverse
  | _ => 0

def evaluation
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    SymbolicEvaluation :=
  (program kind).evalSymbolic (columns row witness)

/-- A representative evaluator for the shared load/store node/event graph.
The eight generated programs differ in committed selector metadata, not in
their localized evaluator graph. -/
def baseEvaluation
    (row : LoadStoreRow)
    (witness : Witness row) :
    SymbolicEvaluation :=
  Programs.lb.evalSymbolic (columns row witness)

private theorem programNodesShared (kind : Kind) :
    (program kind).nodes = Programs.lb.nodes := by
  cases kind <;> rfl

private theorem programEventsShared (kind : Kind) :
    (program kind).source.events = Programs.lbSource.events := by
  cases kind <;> rfl

private theorem evaluationNodesShared
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    (evaluation kind row witness).nodes =
      (baseEvaluation row witness).nodes := by
  simp only [
    evaluation, baseEvaluation, LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic, programNodesShared,
  ]

/-- Facts supplied by the frontend profile rather than one AIR row.  They are
only canonical-representative and access-clock bounds; no load/store semantic
equation is admitted here. -/
structure Admission (row : LoadStoreRow) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  basePreviousBound : row.rs1PreviousClock < 2 ^ 26
  sourcePreviousBound : row.srcPreviousClock < 2 ^ 26
  destinationPreviousBound : row.dstPreviousClock < 2 ^ 26
  pcBound : row.pc.toNat + 4 < M31.modulus
  claimedNextPcCanonical : row.claimedNextPc.toNat < M31.modulus
  immediateCanonical : row.immFelt < M31.modulus
  shiftAmountCanonical : row.shiftAmount < M31.modulus
  alignedQuarterCanonical : row.alignedQuarter < M31.modulus

/-- `claimedNextPc` is no longer an oracle column.  It is bound explicitly to
the exact generated next-PC projection node. -/
structure Bindings
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) : Prop where
  nextPcProjection :
    bitVecM31 row.claimedNextPc =
      (evaluation kind row witness).nodes.getSymbolic 317

abbrev Acceptance
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  RiscvRefinement.Publication.AcceptedProductionEvaluation
    (evaluation kind row witness) relationHolds

/-! ## Exact direct-constraint extraction -/

def constraintRoots : Array Nat :=
  #[104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126,
    128, 130, 132, 139, 144, 148, 150, 152, 157, 159, 161, 163,
    166, 169, 172, 175, 178, 181, 184, 187, 188, 189, 193, 195,
    197, 199, 201, 203, 205, 207, 210, 213, 218, 223, 225, 227,
    229, 231, 233, 235, 237, 239, 243, 247, 251, 255, 257, 259,
    261, 270, 271, 272, 273, 275, 276, 277, 278, 279, 103]

set_option maxHeartbeats 800000 in
set_option maxRecDepth 30000 in
private theorem constraintsHoldEvents
    (kind : Kind)
    (nodes : LocalValues) :
    ((program kind).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      constraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  rw [programEventsShared]
  simp [
    Programs.lbSource, constraintRoots, Event.evalSymbolic,
  ]

theorem constraintsHold_eq
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    (evaluation kind row witness).constraintsHold =
      constraintRoots.all
        (fun root =>
          (evaluation kind row witness).nodes.getSymbolic root == 0) :=
  constraintsHoldEvents kind (evaluation kind row witness).nodes

theorem constraintRootZero
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (accepted : (evaluation kind row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ constraintRoots) :
    (evaluation kind row witness).nodes.getSymbolic root = 0 := by
  rw [constraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selectedRoot := accepted index bound
  rw [value] at selectedRoot
  simpa only [beq_iff_eq] using selectedRoot

theorem baseConstraintRootZero
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (accepted : (evaluation kind row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ constraintRoots) :
    (baseEvaluation row witness).nodes.getSymbolic root = 0 := by
  rw [← evaluationNodesShared kind row witness]
  exact constraintRootZero kind row witness accepted root member

private theorem byteBound (value : Byte) :
    value.toNat < M31.modulus := by
  have bound := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byteEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

private theorem registerBound (value : RegisterIndex) :
    value.toNat < M31.modulus := by
  have bound := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem boolEq
    (left right : Bool)
    (equality : boolM31 left = boolM31 right) :
    left = right := by
  cases left <;> cases right
  · rfl
  · have values := congrArg M31.toNat equality
    simp [boolM31] at values
  · have values := congrArg M31.toNat equality
    simp [boolM31] at values
  · rfl

private theorem byteZero
    (value : Byte)
    (equality : bitVecM31 value = 0) :
    value = 0 := by
  apply byteEq value 0
  simpa [bitVecM31] using equality

private theorem wordBytesEq
    (left right : WordBytes)
    (limb0 : bitVecM31 left.limb0 = bitVecM31 right.limb0)
    (limb1 : bitVecM31 left.limb1 = bitVecM31 right.limb1)
    (limb2 : bitVecM31 left.limb2 = bitVecM31 right.limb2)
    (limb3 : bitVecM31 left.limb3 = bitVecM31 right.limb3) :
    left = right := by
  apply WordBytes.eq_of_limbs
  · exact byteEq left.limb0 right.limb0 limb0
  · exact byteEq left.limb1 right.limb1 limb1
  · exact byteEq left.limb2 right.limb2 limb2
  · exact byteEq left.limb3 right.limb3 limb3

private theorem m31EqOfSubZero
    {left right : M31}
    (equation : left - right = 0) :
    left = right :=
  (M31.sub_eq_zero_iff left right).mp equation

private theorem m31EqZeroOfMulOne
    {value : M31}
    (equation : (1 : M31) * value = 0) :
    value = 0 := by
  simpa only [M31.one_mul] using equation

private theorem reduceNatEq
    {left right : Nat}
    (leftBound : left < M31.modulus)
    (rightBound : right < M31.modulus)
    (equality : M31.reduce left = M31.reduce right) :
    left = right :=
  (M31.reduce_injective_of_lt leftBound rightBound).mp equality

private theorem registerOpcodeBound (row : LoadStoreRow) :
    row.opcodeId < M31.modulus := by
  simp only [LoadStoreRow.opcodeId]
  have lb : bitValue row.isLb ≤ 1 := by cases row.isLb <;> decide
  have lh : bitValue row.isLh ≤ 1 := by cases row.isLh <;> decide
  have lw : bitValue row.isLw ≤ 1 := by cases row.isLw <;> decide
  have lbu : bitValue row.isLbu ≤ 1 := by cases row.isLbu <;> decide
  have lhu : bitValue row.isLhu ≤ 1 := by cases row.isLhu <;> decide
  have sb : bitValue row.isSb ≤ 1 := by cases row.isSb <;> decide
  have sh : bitValue row.isSh ≤ 1 := by cases row.isSh <;> decide
  have sw : bitValue row.isSw ≤ 1 := by cases row.isSw <;> decide
  rw [M31.modulus_eq]
  omega

private theorem manifestIdBound (kind : Kind) :
    manifestId kind < M31.modulus := by
  cases kind <;> decide

/-! ## Exact selector recovery -/

private theorem bitValueInjective :
    Function.Injective bitValue := by
  intro left right equality
  cases left <;> cases right <;>
    simp_all [bitValue] <;>
    omega

private theorem bitValueLeOne (flag : Bool) :
    bitValue flag ≤ 1 := by
  cases flag <;> decide

private theorem boolM31_eq_reduce_bitValue (flag : Bool) :
    boolM31 flag = M31.reduce (bitValue flag) := by
  cases flag <;> rfl

private theorem selectorSumBound (row : LoadStoreRow) :
    row.selectorSum < M31.modulus := by
  have lb := bitValueLeOne row.isLb
  have lh := bitValueLeOne row.isLh
  have lw := bitValueLeOne row.isLw
  have lbu := bitValueLeOne row.isLbu
  have lhu := bitValueLeOne row.isLhu
  have sb := bitValueLeOne row.isSb
  have sh := bitValueLeOne row.isSh
  have sw := bitValueLeOne row.isSw
  simp only [LoadStoreRow.selectorSum]
  rw [M31.modulus_eq]
  omega

/-- All eight flags are recovered from the active one-hot equation and the
exact manifest-selected opcode expression; no caller supplies a selector. -/
def FlagFacts (kind : Kind) (row : LoadStoreRow) : Prop :=
  match kind with
  | .lb =>
      row.isLb = true ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false
  | .lh =>
      row.isLb = false ∧ row.isLh = true ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false
  | .lw =>
      row.isLb = false ∧ row.isLh = false ∧ row.isLw = true ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false
  | .lbu =>
      row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = true ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false
  | .lhu =>
      row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = true ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false
  | .sb =>
      row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = true ∧
        row.isSh = false ∧ row.isSw = false
  | .sh =>
      row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = true ∧ row.isSw = false
  | .sw =>
      row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = true

/-
The earlier disjunctive one-hot proof is retained temporarily as review
history, but excluded from elaboration.  Direct selector recovery below avoids
building its enormous eight-level tactic snapshot.

private theorem selectorCasesOfSum
    (row : LoadStoreRow)
    (sum : row.selectorSum = 1) :
    (row.isLb = true ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = true ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLw = true ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = true ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = true ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = true ∧
        row.isSh = false ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = true ∧ row.isSw = false) ∨
      (row.isLb = false ∧ row.isLh = false ∧ row.isLw = false ∧
        row.isLbu = false ∧ row.isLhu = false ∧ row.isSb = false ∧
        row.isSh = false ∧ row.isSw = true) := by
  by_cases lb : row.isLb = true
  · left
    refine ⟨lb, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
    all_goals
      apply bitValueInjective
      simp only [bitValue_false]
      have equation := sum
      simp only [
        LoadStoreRow.selectorSum, lb, bitValue_true,
      ] at equation
      omega
  have lbFalse : row.isLb = false := by
    cases row.isLb <;> simp_all
  by_cases lh : row.isLh = true
  · right
    left
    refine ⟨lbFalse, lh, ?_, ?_, ?_, ?_, ?_, ?_⟩
    all_goals
      apply bitValueInjective
      simp only [bitValue_false]
      have equation := sum
      simp only [
        LoadStoreRow.selectorSum, lh, bitValue_true,
      ] at equation
      omega
  have lhFalse : row.isLh = false := by
    cases row.isLh <;> simp_all
  by_cases lw : row.isLw = true
  · right
    right
    left
    refine ⟨lbFalse, lhFalse, lw, ?_, ?_, ?_, ?_, ?_⟩
    all_goals
      apply bitValueInjective
      simp only [bitValue_false]
      have equation := sum
      simp only [
        LoadStoreRow.selectorSum, lw, bitValue_true,
      ] at equation
      omega
  have lwFalse : row.isLw = false := by
    cases row.isLw <;> simp_all
  by_cases lbu : row.isLbu = true
  · right
    right
    right
    left
    refine ⟨lbFalse, lhFalse, lwFalse, lbu, ?_, ?_, ?_, ?_⟩
    all_goals
      apply bitValueInjective
      simp only [bitValue_false]
      have equation := sum
      simp only [
        LoadStoreRow.selectorSum, lbu, bitValue_true,
      ] at equation
      omega
  have lbuFalse : row.isLbu = false := by
    cases row.isLbu <;> simp_all
  by_cases lhu : row.isLhu = true
  · right
    right
    right
    right
    left
    refine
      ⟨lbFalse, lhFalse, lwFalse, lbuFalse, lhu, ?_, ?_, ?_⟩
    all_goals
      apply bitValueInjective
      simp only [bitValue_false]
      have equation := sum
      simp only [
        LoadStoreRow.selectorSum, lhu, bitValue_true,
      ] at equation
      omega
  have lhuFalse : row.isLhu = false := by
    cases row.isLhu <;> simp_all
  by_cases sb : row.isSb = true
  · right
    right
    right
    right
    right
    left
    refine
      ⟨lbFalse, lhFalse, lwFalse, lbuFalse, lhuFalse, sb, ?_, ?_⟩
    all_goals
      apply bitValueInjective
      simp only [bitValue_false]
      have equation := sum
      simp only [
        LoadStoreRow.selectorSum, sb, bitValue_true,
      ] at equation
      omega
  have sbFalse : row.isSb = false := by
    cases row.isSb <;> simp_all
  by_cases sh : row.isSh = true
  · right
    right
    right
    right
    right
    right
    left
    refine
      ⟨lbFalse, lhFalse, lwFalse, lbuFalse, lhuFalse, sbFalse,
        sh, ?_⟩
    apply bitValueInjective
    simp only [bitValue_false]
    have equation := sum
    simp only [
      LoadStoreRow.selectorSum, sh, bitValue_true,
    ] at equation
    omega
  have shFalse : row.isSh = false := by
    cases row.isSh <;> simp_all
  right
  right
  right
  right
  right
  right
  right
  refine
    ⟨lbFalse, lhFalse, lwFalse, lbuFalse, lhuFalse, sbFalse,
      shFalse, ?_⟩
  apply bitValueInjective
  simp only [bitValue_true]
  have equation := sum
  simp only [
    LoadStoreRow.selectorSum, lbFalse, lhFalse, lwFalse, lbuFalse,
    lhuFalse, sbFalse, shFalse, bitValue_false,
  ] at equation
  exact equation
-/

set_option maxHeartbeats 1000000 in
private theorem flagFactsOfSelectorAndOpcode
    (kind : Kind)
    (row : LoadStoreRow)
    (sum : row.selectorSum = 1)
    (opcode : row.opcodeId = manifestId kind) :
    FlagFacts kind row := by
  have lbBound := bitValueLeOne row.isLb
  have lhBound := bitValueLeOne row.isLh
  have lwBound := bitValueLeOne row.isLw
  have lbuBound := bitValueLeOne row.isLbu
  have lhuBound := bitValueLeOne row.isLhu
  have sbBound := bitValueLeOne row.isSb
  have shBound := bitValueLeOne row.isSh
  have swBound := bitValueLeOne row.isSw
  have sumEquation := sum
  simp only [LoadStoreRow.selectorSum] at sumEquation
  have opcodeEquation := opcode
  simp only [LoadStoreRow.opcodeId] at opcodeEquation
  have trueOfOne
      (flag : Bool)
      (value : bitValue flag = 1) :
      flag = true := by
    apply bitValueInjective
    simpa only [bitValue_true] using value
  have falseOfZero
      (flag : Bool)
      (value : bitValue flag = 0) :
      flag = false := by
    apply bitValueInjective
    simpa only [bitValue_false] using value
  cases kind with
  | lb =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 1 := by omega
      have lhValue : bitValue row.isLh = 0 := by omega
      have lwValue : bitValue row.isLw = 0 := by omega
      have lbuValue : bitValue row.isLbu = 0 := by omega
      have lhuValue : bitValue row.isLhu = 0 := by omega
      have sbValue : bitValue row.isSb = 0 := by omega
      have shValue : bitValue row.isSh = 0 := by omega
      have swValue : bitValue row.isSw = 0 := by omega
      exact
        ⟨trueOfOne row.isLb lbValue,
          falseOfZero row.isLh lhValue,
          falseOfZero row.isLw lwValue,
          falseOfZero row.isLbu lbuValue,
          falseOfZero row.isLhu lhuValue,
          falseOfZero row.isSb sbValue,
          falseOfZero row.isSh shValue,
          falseOfZero row.isSw swValue⟩
  | lh =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 0 := by omega
      have lhValue : bitValue row.isLh = 1 := by omega
      have lwValue : bitValue row.isLw = 0 := by omega
      have lbuValue : bitValue row.isLbu = 0 := by omega
      have lhuValue : bitValue row.isLhu = 0 := by omega
      have sbValue : bitValue row.isSb = 0 := by omega
      have shValue : bitValue row.isSh = 0 := by omega
      have swValue : bitValue row.isSw = 0 := by omega
      exact
        ⟨falseOfZero row.isLb lbValue,
          trueOfOne row.isLh lhValue,
          falseOfZero row.isLw lwValue,
          falseOfZero row.isLbu lbuValue,
          falseOfZero row.isLhu lhuValue,
          falseOfZero row.isSb sbValue,
          falseOfZero row.isSh shValue,
          falseOfZero row.isSw swValue⟩
  | lw =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 0 := by omega
      have lhValue : bitValue row.isLh = 0 := by omega
      have lwValue : bitValue row.isLw = 1 := by omega
      have lbuValue : bitValue row.isLbu = 0 := by omega
      have lhuValue : bitValue row.isLhu = 0 := by omega
      have sbValue : bitValue row.isSb = 0 := by omega
      have shValue : bitValue row.isSh = 0 := by omega
      have swValue : bitValue row.isSw = 0 := by omega
      exact
        ⟨falseOfZero row.isLb lbValue,
          falseOfZero row.isLh lhValue,
          trueOfOne row.isLw lwValue,
          falseOfZero row.isLbu lbuValue,
          falseOfZero row.isLhu lhuValue,
          falseOfZero row.isSb sbValue,
          falseOfZero row.isSh shValue,
          falseOfZero row.isSw swValue⟩
  | lbu =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 0 := by omega
      have lhValue : bitValue row.isLh = 0 := by omega
      have lwValue : bitValue row.isLw = 0 := by omega
      have lbuValue : bitValue row.isLbu = 1 := by omega
      have lhuValue : bitValue row.isLhu = 0 := by omega
      have sbValue : bitValue row.isSb = 0 := by omega
      have shValue : bitValue row.isSh = 0 := by omega
      have swValue : bitValue row.isSw = 0 := by omega
      exact
        ⟨falseOfZero row.isLb lbValue,
          falseOfZero row.isLh lhValue,
          falseOfZero row.isLw lwValue,
          trueOfOne row.isLbu lbuValue,
          falseOfZero row.isLhu lhuValue,
          falseOfZero row.isSb sbValue,
          falseOfZero row.isSh shValue,
          falseOfZero row.isSw swValue⟩
  | lhu =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 0 := by omega
      have lhValue : bitValue row.isLh = 0 := by omega
      have lwValue : bitValue row.isLw = 0 := by omega
      have lbuValue : bitValue row.isLbu = 0 := by omega
      have lhuValue : bitValue row.isLhu = 1 := by omega
      have sbValue : bitValue row.isSb = 0 := by omega
      have shValue : bitValue row.isSh = 0 := by omega
      have swValue : bitValue row.isSw = 0 := by omega
      exact
        ⟨falseOfZero row.isLb lbValue,
          falseOfZero row.isLh lhValue,
          falseOfZero row.isLw lwValue,
          falseOfZero row.isLbu lbuValue,
          trueOfOne row.isLhu lhuValue,
          falseOfZero row.isSb sbValue,
          falseOfZero row.isSh shValue,
          falseOfZero row.isSw swValue⟩
  | sb =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 0 := by omega
      have lhValue : bitValue row.isLh = 0 := by omega
      have lwValue : bitValue row.isLw = 0 := by omega
      have lbuValue : bitValue row.isLbu = 0 := by omega
      have lhuValue : bitValue row.isLhu = 0 := by omega
      have sbValue : bitValue row.isSb = 1 := by omega
      have shValue : bitValue row.isSh = 0 := by omega
      have swValue : bitValue row.isSw = 0 := by omega
      exact
        ⟨falseOfZero row.isLb lbValue,
          falseOfZero row.isLh lhValue,
          falseOfZero row.isLw lwValue,
          falseOfZero row.isLbu lbuValue,
          falseOfZero row.isLhu lhuValue,
          trueOfOne row.isSb sbValue,
          falseOfZero row.isSh shValue,
          falseOfZero row.isSw swValue⟩
  | sh =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 0 := by omega
      have lhValue : bitValue row.isLh = 0 := by omega
      have lwValue : bitValue row.isLw = 0 := by omega
      have lbuValue : bitValue row.isLbu = 0 := by omega
      have lhuValue : bitValue row.isLhu = 0 := by omega
      have sbValue : bitValue row.isSb = 0 := by omega
      have shValue : bitValue row.isSh = 1 := by omega
      have swValue : bitValue row.isSw = 0 := by omega
      exact
        ⟨falseOfZero row.isLb lbValue,
          falseOfZero row.isLh lhValue,
          falseOfZero row.isLw lwValue,
          falseOfZero row.isLbu lbuValue,
          falseOfZero row.isLhu lhuValue,
          falseOfZero row.isSb sbValue,
          trueOfOne row.isSh shValue,
          falseOfZero row.isSw swValue⟩
  | sw =>
      simp only [manifestId] at opcodeEquation
      have lbValue : bitValue row.isLb = 0 := by omega
      have lhValue : bitValue row.isLh = 0 := by omega
      have lwValue : bitValue row.isLw = 0 := by omega
      have lbuValue : bitValue row.isLbu = 0 := by omega
      have lhuValue : bitValue row.isLhu = 0 := by omega
      have sbValue : bitValue row.isSb = 0 := by omega
      have shValue : bitValue row.isSh = 0 := by omega
      have swValue : bitValue row.isSw = 1 := by omega
      exact
        ⟨falseOfZero row.isLb lbValue,
          falseOfZero row.isLh lhValue,
          falseOfZero row.isLw lwValue,
          falseOfZero row.isLbu lbuValue,
          falseOfZero row.isLhu lhuValue,
          falseOfZero row.isSb sbValue,
          falseOfZero row.isSh shValue,
          trueOfOne row.isSw swValue⟩

private theorem selectedOfFlagFacts
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    selected kind row = true := by
  cases kind <;>
    simp_all [selected, FlagFacts]

private def activeField (row : LoadStoreRow) : M31 :=
  (((((((boolM31 row.isLb + boolM31 row.isLh) +
      boolM31 row.isLbu) + boolM31 row.isLhu) +
      boolM31 row.isLw) + boolM31 row.isSb) +
      boolM31 row.isSh) + boolM31 row.isSw)

private theorem activeFieldImage (row : LoadStoreRow) :
    activeField row = M31.reduce row.selectorSum := by
  simp [
    activeField, LoadStoreRow.selectorSum,
    boolM31_eq_reduce_bitValue,
    Air.Bridge.TeamACommon.reduceAdd,
  ]

set_option maxRecDepth 30000 in
private theorem baseActiveNodeProjection
    (row : LoadStoreRow)
    (witness : Witness row) :
    (baseEvaluation row witness).activeRow =
      activeField row := by
  rfl

set_option maxRecDepth 30000 in
private theorem baseActiveNode
    (row : LoadStoreRow)
    (witness : Witness row) :
    (baseEvaluation row witness).activeRow =
      M31.reduce row.selectorSum := by
  rw [
    baseActiveNodeProjection row witness,
    activeFieldImage row,
  ]

private def opcodeField (row : LoadStoreRow) : M31 :=
  (((((((boolM31 row.isLb * M31.reduce 19 +
      boolM31 row.isLh * M31.reduce 20) +
      boolM31 row.isLw * M31.reduce 21) +
      boolM31 row.isLbu * M31.reduce 22) +
      boolM31 row.isLhu * M31.reduce 23) +
      boolM31 row.isSb * M31.reduce 24) +
      boolM31 row.isSh * M31.reduce 25) +
      boolM31 row.isSw * M31.reduce 26)

private theorem opcodeFieldImage (row : LoadStoreRow) :
    opcodeField row = M31.reduce row.opcodeId := by
  simp [
    opcodeField, LoadStoreRow.opcodeId,
    boolM31_eq_reduce_bitValue,
    Air.Bridge.TeamACommon.reduceMul,
    Air.Bridge.TeamACommon.reduceAdd,
    Nat.mul_comm,
  ]

set_option maxRecDepth 30000 in
private theorem baseSelectorNodeProjection
    (row : LoadStoreRow)
    (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 316 =
      opcodeField row := by
  rfl

set_option maxRecDepth 30000 in
private theorem baseSelectorNode
    (row : LoadStoreRow)
    (witness : Witness row) :
    (baseEvaluation row witness).nodes.getSymbolic 316 =
      M31.reduce row.opcodeId := by
  rw [
    baseSelectorNodeProjection row witness,
    opcodeFieldImage row,
  ]

set_option maxRecDepth 30000 in
private theorem evaluationManifestId
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    (evaluation kind row witness).manifestId = manifestId kind := by
  cases kind <;> rfl

set_option maxRecDepth 30000 in
private theorem manifestIdOfNat (kind : Kind) :
    M31.ofNat? (manifestId kind) =
      some (M31.reduce (manifestId kind)) := by
  cases kind <;> rfl

set_option maxRecDepth 30000 in
private theorem evaluationOpcodeSelectorNode
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    (evaluation kind row witness).opcodeSelector =
      (evaluation kind row witness).nodes.getSymbolic 316 := by
  cases kind <;> rfl

set_option maxRecDepth 30000 in
private theorem evaluationActiveRowEqBase
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    (evaluation kind row witness).activeRow =
      (baseEvaluation row witness).activeRow := by
  cases kind <;> rfl

set_option maxRecDepth 30000 in
private theorem acceptedSelectorNode
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (active :
      (evaluation kind row witness).activeSelectorsAccepted = true) :
    (baseEvaluation row witness).nodes.getSymbolic 316 =
      M31.reduce (manifestId kind) := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have opcodeAccepted := selectorsAccepted.2
  rw [evaluationManifestId kind row witness] at opcodeAccepted
  rw [manifestIdOfNat kind] at opcodeAccepted
  have selectorEquality :
      (evaluation kind row witness).opcodeSelector =
        M31.reduce (manifestId kind) := by
    simpa only [beq_iff_eq] using opcodeAccepted
  calc
    (baseEvaluation row witness).nodes.getSymbolic 316 =
        (evaluation kind row witness).nodes.getSymbolic 316 := by
      rw [evaluationNodesShared kind row witness]
    _ = (evaluation kind row witness).opcodeSelector :=
      (evaluationOpcodeSelectorNode kind row witness).symm
    _ = M31.reduce (manifestId kind) :=
      selectorEquality

set_option maxRecDepth 30000 in
private theorem selectorSumOfExactActive
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (active :
      (evaluation kind row witness).activeSelectorsAccepted = true) :
    row.selectorSum = 1 := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have rowAccepted := selectorsAccepted.1
  have exactActive :
      (baseEvaluation row witness).activeRow = 1 := by
    have sourceActive :
        (evaluation kind row witness).activeRow = 1 := by
      simpa only [beq_iff_eq] using rowAccepted
    rw [evaluationActiveRowEqBase kind row witness] at sourceActive
    exact sourceActive
  apply
    (M31.reduce_injective_of_lt
      (selectorSumBound row) (by decide : 1 < M31.modulus)).mp
  rw [← baseActiveNode row witness]
  simpa using exactActive

private theorem opcodeIdOfExactActive
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (active :
      (evaluation kind row witness).activeSelectorsAccepted = true) :
    row.opcodeId = manifestId kind := by
  apply
    (M31.reduce_injective_of_lt
      (registerOpcodeBound row) (manifestIdBound kind)).mp
  rw [← baseSelectorNode row witness]
  exact acceptedSelectorNode kind row witness active

/-! ## Direct-root equations -/

private def storeField (row : LoadStoreRow) : M31 :=
  (boolM31 row.isSb + boolM31 row.isSh) + boolM31 row.isSw

private def loadField (row : LoadStoreRow) : M31 :=
  activeField row - storeField row

private def byteField (row : LoadStoreRow) : M31 :=
  (boolM31 row.isLbu + boolM31 row.isLb) + boolM31 row.isSb

private def halfField (row : LoadStoreRow) : M31 :=
  (boolM31 row.isLhu + boolM31 row.isLh) + boolM31 row.isSh

private def byteLoadField (row : LoadStoreRow) : M31 :=
  boolM31 row.isLb + boolM31 row.isLbu

private def halfLoadField (row : LoadStoreRow) : M31 :=
  boolM31 row.isLh + boolM31 row.isLhu

private def signedField (row : LoadStoreRow) : M31 :=
  boolM31 row.isLb + boolM31 row.isLh

private def markerSumField (row : LoadStoreRow) : M31 :=
  (((0 + boolM31 row.marker0) + boolM31 row.marker1) +
      boolM31 row.marker2) + boolM31 row.marker3

private def shiftIdField (row : LoadStoreRow) : M31 :=
  (((0 + boolM31 row.marker0 * M31.reduce 0) +
      boolM31 row.marker1 * M31.reduce 1) +
      boolM31 row.marker2 * M31.reduce 2) +
      boolM31 row.marker3 * M31.reduce 3

private def signMaskField (row : LoadStoreRow) : M31 :=
  signedField row * boolM31 row.srcMsb * M31.reduce 255

private def baseValueField (row : LoadStoreRow) : M31 :=
  Air.Bridge.TeamACommon.wordBytesField row.rs1Next

private def effectiveMinusShiftField (row : LoadStoreRow) : M31 :=
  baseValueField row + M31.reduce row.immFelt -
    M31.reduce row.shiftAmount

private theorem baseConstraintsOfAccepted
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (direct : (evaluation kind row witness).constraintsHold = true) :
    (baseEvaluation row witness).constraintsHold = true := by
  change (evaluation .lb row witness).constraintsHold = true
  rw [constraintsHold_eq .lb row witness]
  rw [constraintsHold_eq kind row witness] at direct
  rw [evaluationNodesShared kind row witness] at direct
  simpa [evaluation, baseEvaluation, program] using direct

/-- The exact 71-root evaluation, projected onto the 55 non-typing equations
used by the semantic reverse bridge. -/
structure DirectEquations
    (row : LoadStoreRow)
    (witness : Witness row) : Prop where
  signCanonical :
    (1 - signedField row) * boolM31 row.srcMsb = 0
  shiftAmount :
    M31.reduce row.shiftAmount -
      (byteField row * shiftIdField row +
        halfField row *
          (shiftIdField row - 1) * M31.reduce 1073741824) = 0
  sourceSelector :
    M31.reduce row.sourceSelector -
      (loadField row * effectiveMinusShiftField row +
        storeField row * bitVecM31 row.r2Idx) = 0
  destinationSelector :
    M31.reduce row.destinationSelector -
      (loadField row * bitVecM31 row.r2Idx +
        storeField row * effectiveMinusShiftField row) = 0
  byteMarker :
    byteField row * (1 - markerSumField row) = 0
  halfMarker :
    halfField row * (M31.reduce 2 - markerSumField row) = 0
  halfShift :
    halfField row * (1 - shiftIdField row) *
      (M31.reduce 5 - shiftIdField row) = 0
  byteExtension1 :
    byteLoadField row *
      (signMaskField row - bitVecM31 row.result.limb1) = 0
  byteExtension2 :
    byteLoadField row *
      (signMaskField row - bitVecM31 row.result.limb2) = 0
  byteExtension3 :
    byteLoadField row *
      (signMaskField row - bitVecM31 row.result.limb3) = 0
  byteLoad0 :
    byteLoadField row *
      (bitVecM31 row.result.limb0 - bitVecM31 row.srcNext.limb0) *
        boolM31 row.marker0 = 0
  byteStore0 :
    boolM31 row.isSb *
      (bitVecM31 row.dstNext.limb0 - bitVecM31 row.srcNext.limb0) *
        boolM31 row.marker0 = 0
  byteLoad1 :
    byteLoadField row *
      (bitVecM31 row.result.limb0 - bitVecM31 row.srcNext.limb1) *
        boolM31 row.marker1 = 0
  byteStore1 :
    boolM31 row.isSb *
      (bitVecM31 row.dstNext.limb1 - bitVecM31 row.srcNext.limb0) *
        boolM31 row.marker1 = 0
  byteLoad2 :
    byteLoadField row *
      (bitVecM31 row.result.limb0 - bitVecM31 row.srcNext.limb2) *
        boolM31 row.marker2 = 0
  byteStore2 :
    boolM31 row.isSb *
      (bitVecM31 row.dstNext.limb2 - bitVecM31 row.srcNext.limb0) *
        boolM31 row.marker2 = 0
  byteLoad3 :
    byteLoadField row *
      (bitVecM31 row.result.limb0 - bitVecM31 row.srcNext.limb3) *
        boolM31 row.marker3 = 0
  byteStore3 :
    boolM31 row.isSb *
      (bitVecM31 row.dstNext.limb3 - bitVecM31 row.srcNext.limb0) *
        boolM31 row.marker3 = 0
  halfExtension2 :
    halfLoadField row *
      (signMaskField row - bitVecM31 row.result.limb2) = 0
  halfExtension3 :
    halfLoadField row *
      (signMaskField row - bitVecM31 row.result.limb3) = 0
  halfLoadLow0 :
    halfLoadField row *
      ((M31.reduce 5 - shiftIdField row) * M31.reduce 536870912) *
        (bitVecM31 row.result.limb0 - bitVecM31 row.srcNext.limb0) = 0
  halfLoadLow1 :
    halfLoadField row *
      ((M31.reduce 5 - shiftIdField row) * M31.reduce 536870912) *
        (bitVecM31 row.result.limb1 - bitVecM31 row.srcNext.limb1) = 0
  halfLoadHigh0 :
    halfLoadField row *
      ((shiftIdField row - 1) * M31.reduce 536870912) *
        (bitVecM31 row.result.limb0 - bitVecM31 row.srcNext.limb2) = 0
  halfLoadHigh1 :
    halfLoadField row *
      ((shiftIdField row - 1) * M31.reduce 536870912) *
        (bitVecM31 row.result.limb1 - bitVecM31 row.srcNext.limb3) = 0
  halfStoreLow0 :
    boolM31 row.isSh *
      ((M31.reduce 5 - shiftIdField row) * M31.reduce 536870912) *
        (bitVecM31 row.dstNext.limb0 - bitVecM31 row.srcNext.limb0) = 0
  halfStoreLow1 :
    boolM31 row.isSh *
      ((M31.reduce 5 - shiftIdField row) * M31.reduce 536870912) *
        (bitVecM31 row.dstNext.limb1 - bitVecM31 row.srcNext.limb1) = 0
  halfStoreHigh2 :
    boolM31 row.isSh *
      ((shiftIdField row - 1) * M31.reduce 536870912) *
        (bitVecM31 row.dstNext.limb2 - bitVecM31 row.srcNext.limb0) = 0
  halfStoreHigh3 :
    boolM31 row.isSh *
      ((shiftIdField row - 1) * M31.reduce 536870912) *
        (bitVecM31 row.dstNext.limb3 - bitVecM31 row.srcNext.limb1) = 0
  word0 :
    boolM31 row.isLw *
        (bitVecM31 row.result.limb0 - bitVecM31 row.srcNext.limb0) +
      boolM31 row.isSw *
        (bitVecM31 row.dstNext.limb0 - bitVecM31 row.srcNext.limb0) = 0
  word1 :
    boolM31 row.isLw *
        (bitVecM31 row.result.limb1 - bitVecM31 row.srcNext.limb1) +
      boolM31 row.isSw *
        (bitVecM31 row.dstNext.limb1 - bitVecM31 row.srcNext.limb1) = 0
  word2 :
    boolM31 row.isLw *
        (bitVecM31 row.result.limb2 - bitVecM31 row.srcNext.limb2) +
      boolM31 row.isSw *
        (bitVecM31 row.dstNext.limb2 - bitVecM31 row.srcNext.limb2) = 0
  word3 :
    boolM31 row.isLw *
        (bitVecM31 row.result.limb3 - bitVecM31 row.srcNext.limb3) +
      boolM31 row.isSw *
        (bitVecM31 row.dstNext.limb3 - bitVecM31 row.srcNext.limb3) = 0
  base0 :
    activeField row *
      (bitVecM31 row.rs1Next.limb0 -
        bitVecM31 row.rs1Previous.limb0) = 0
  base1 :
    activeField row *
      (bitVecM31 row.rs1Next.limb1 -
        bitVecM31 row.rs1Previous.limb1) = 0
  base2 :
    activeField row *
      (bitVecM31 row.rs1Next.limb2 -
        bitVecM31 row.rs1Previous.limb2) = 0
  base3 :
    activeField row *
      (bitVecM31 row.rs1Next.limb3 -
        bitVecM31 row.rs1Previous.limb3) = 0
  source0 :
    activeField row *
      (bitVecM31 row.srcNext.limb0 -
        bitVecM31 row.srcPrevious.limb0) = 0
  source1 :
    activeField row *
      (bitVecM31 row.srcNext.limb1 -
        bitVecM31 row.srcPrevious.limb1) = 0
  source2 :
    activeField row *
      (bitVecM31 row.srcNext.limb2 -
        bitVecM31 row.srcPrevious.limb2) = 0
  source3 :
    activeField row *
      (bitVecM31 row.srcNext.limb3 -
        bitVecM31 row.srcPrevious.limb3) = 0
  preserve0 :
    (boolM31 row.isSb + boolM31 row.isSh) *
      (1 - boolM31 row.marker0) *
        (bitVecM31 row.dstNext.limb0 -
          bitVecM31 row.dstPrevious.limb0) = 0
  preserve1 :
    (boolM31 row.isSb + boolM31 row.isSh) *
      (1 - boolM31 row.marker1) *
        (bitVecM31 row.dstNext.limb1 -
          bitVecM31 row.dstPrevious.limb1) = 0
  preserve2 :
    (boolM31 row.isSb + boolM31 row.isSh) *
      (1 - boolM31 row.marker2) *
        (bitVecM31 row.dstNext.limb2 -
          bitVecM31 row.dstPrevious.limb2) = 0
  preserve3 :
    (boolM31 row.isSb + boolM31 row.isSh) *
      (1 - boolM31 row.marker3) *
        (bitVecM31 row.dstNext.limb3 -
          bitVecM31 row.dstPrevious.limb3) = 0
  destinationZero :
    bitVecM31 row.r2Idx *
      (1 - boolM31 row.destinationNonzero) = 0
  destinationInverse :
    bitVecM31 row.r2Idx * witness.destinationInverse -
      boolM31 row.destinationNonzero = 0
  loadDestination0 :
    loadField row *
      (bitVecM31 row.dstNext.limb0 -
        boolM31 row.destinationNonzero *
          bitVecM31 row.result.limb0) = 0
  loadDestination1 :
    loadField row *
      (bitVecM31 row.dstNext.limb1 -
        boolM31 row.destinationNonzero *
          bitVecM31 row.result.limb1) = 0
  loadDestination2 :
    loadField row *
      (bitVecM31 row.dstNext.limb2 -
        boolM31 row.destinationNonzero *
          bitVecM31 row.result.limb2) = 0
  loadDestination3 :
    loadField row *
      (bitVecM31 row.dstNext.limb3 -
        boolM31 row.destinationNonzero *
          bitVecM31 row.result.limb3) = 0
  storeResult0 :
    (1 - loadField row) * bitVecM31 row.result.limb0 = 0
  storeResult1 :
    (1 - loadField row) * bitVecM31 row.result.limb1 = 0
  storeResult2 :
    (1 - loadField row) * bitVecM31 row.result.limb2 = 0
  storeResult3 :
    (1 - loadField row) * bitVecM31 row.result.limb3 = 0
  baseHigh :
    activeField row * bitVecM31 row.rs1Next.limb3 = 0
  selector : activeField row - 1 = 0

macro "load_store_root " kind:term ", " row:term ", " witness:term ", "
    direct:term ", " root:term : tactic =>
  `(tactic|
    exact
      (show
        (baseEvaluation $row $witness).nodes.getSymbolic $root = 0
        from
          baseConstraintRootZero $kind $row $witness $direct $root
            (by simp [constraintRoots])))

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem directEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (direct : (evaluation kind row witness).constraintsHold = true) :
    DirectEquations row witness := by
  exact {
    signCanonical := by
      load_store_root kind, row, witness, direct, 124
    shiftAmount := by
      load_store_root kind, row, witness, direct, 139
    sourceSelector := by
      load_store_root kind, row, witness, direct, 144
    destinationSelector := by
      load_store_root kind, row, witness, direct, 148
    byteMarker := by
      load_store_root kind, row, witness, direct, 150
    halfMarker := by
      load_store_root kind, row, witness, direct, 152
    halfShift := by
      load_store_root kind, row, witness, direct, 157
    byteExtension1 := by
      load_store_root kind, row, witness, direct, 159
    byteExtension2 := by
      load_store_root kind, row, witness, direct, 161
    byteExtension3 := by
      load_store_root kind, row, witness, direct, 163
    byteLoad0 := by
      load_store_root kind, row, witness, direct, 166
    byteStore0 := by
      load_store_root kind, row, witness, direct, 169
    byteLoad1 := by
      load_store_root kind, row, witness, direct, 172
    byteStore1 := by
      load_store_root kind, row, witness, direct, 175
    byteLoad2 := by
      load_store_root kind, row, witness, direct, 178
    byteStore2 := by
      load_store_root kind, row, witness, direct, 181
    byteLoad3 := by
      load_store_root kind, row, witness, direct, 184
    byteStore3 := by
      load_store_root kind, row, witness, direct, 187
    halfExtension2 := by
      load_store_root kind, row, witness, direct, 188
    halfExtension3 := by
      load_store_root kind, row, witness, direct, 189
    halfLoadLow0 := by
      load_store_root kind, row, witness, direct, 193
    halfLoadLow1 := by
      load_store_root kind, row, witness, direct, 195
    halfLoadHigh0 := by
      load_store_root kind, row, witness, direct, 197
    halfLoadHigh1 := by
      load_store_root kind, row, witness, direct, 199
    halfStoreLow0 := by
      load_store_root kind, row, witness, direct, 201
    halfStoreLow1 := by
      load_store_root kind, row, witness, direct, 203
    halfStoreHigh2 := by
      load_store_root kind, row, witness, direct, 205
    halfStoreHigh3 := by
      load_store_root kind, row, witness, direct, 207
    word0 := by
      load_store_root kind, row, witness, direct, 210
    word1 := by
      load_store_root kind, row, witness, direct, 213
    word2 := by
      load_store_root kind, row, witness, direct, 218
    word3 := by
      load_store_root kind, row, witness, direct, 223
    base0 := by
      load_store_root kind, row, witness, direct, 225
    base1 := by
      load_store_root kind, row, witness, direct, 227
    base2 := by
      load_store_root kind, row, witness, direct, 229
    base3 := by
      load_store_root kind, row, witness, direct, 231
    source0 := by
      load_store_root kind, row, witness, direct, 233
    source1 := by
      load_store_root kind, row, witness, direct, 235
    source2 := by
      load_store_root kind, row, witness, direct, 237
    source3 := by
      load_store_root kind, row, witness, direct, 239
    preserve0 := by
      load_store_root kind, row, witness, direct, 243
    preserve1 := by
      load_store_root kind, row, witness, direct, 247
    preserve2 := by
      load_store_root kind, row, witness, direct, 251
    preserve3 := by
      load_store_root kind, row, witness, direct, 255
    destinationZero := by
      load_store_root kind, row, witness, direct, 259
    destinationInverse := by
      load_store_root kind, row, witness, direct, 261
    loadDestination0 := by
      load_store_root kind, row, witness, direct, 270
    loadDestination1 := by
      load_store_root kind, row, witness, direct, 271
    loadDestination2 := by
      load_store_root kind, row, witness, direct, 272
    loadDestination3 := by
      load_store_root kind, row, witness, direct, 273
    storeResult0 := by
      load_store_root kind, row, witness, direct, 275
    storeResult1 := by
      load_store_root kind, row, witness, direct, 276
    storeResult2 := by
      load_store_root kind, row, witness, direct, 277
    storeResult3 := by
      load_store_root kind, row, witness, direct, 278
    baseHigh := by
      load_store_root kind, row, witness, direct, 279
    selector := by
      load_store_root kind, row, witness, direct, 103
  }

/-! ## Direct semantic consequences -/

private theorem activeFieldOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    activeField row = 1 := by
  cases kind <;>
    simp_all [FlagFacts, activeField, boolM31]

private theorem storeFieldOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    storeField row =
      if kind = .sb ∨ kind = .sh ∨ kind = .sw then 1 else 0 := by
  cases kind <;>
    simp_all [FlagFacts, storeField, boolM31]

private theorem loadFieldOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    loadField row =
      if kind = .lb ∨ kind = .lh ∨ kind = .lw ∨
          kind = .lbu ∨ kind = .lhu then 1 else 0 := by
  cases kind <;>
    simp_all [
      FlagFacts, loadField, activeField, storeField, boolM31,
    ]

private theorem storeFieldImageOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    storeField row = boolM31 row.isStore := by
  cases kind <;>
    simp_all [
      FlagFacts, storeField, LoadStoreRow.isStore, boolM31,
    ]

private theorem loadFieldImageOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    loadField row = boolM31 row.isLoad := by
  cases kind <;>
    simp_all [
      FlagFacts, loadField, activeField, storeField,
      LoadStoreRow.isLoad, LoadStoreRow.isStore, boolM31,
    ]

/-!
Keep the selector reductions in small lemmas whose contexts do not contain
the 55-field `DirectEquations` structure.  Downstream proofs can then rewrite
one multiplier at a time instead of asking `simp` to inspect the whole
generated-AIR consequence context.
-/
private theorem signedFieldImageOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    signedField row = boolM31 row.isSigned := by
  cases kind <;>
    simp_all [
      FlagFacts, signedField, LoadStoreRow.isSigned, boolM31,
    ]

private theorem byteLoadFieldImageOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    byteLoadField row = boolM31 row.isByteLoad := by
  cases kind <;>
    simp_all [
      FlagFacts, byteLoadField, LoadStoreRow.isByteLoad, boolM31,
    ]

private theorem halfLoadFieldImageOfFlags
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    halfLoadField row = boolM31 row.isHalfLoad := by
  cases kind <;>
    simp_all [
      FlagFacts, halfLoadField, LoadStoreRow.isHalfLoad, boolM31,
    ]

private theorem byteWidthFieldReductions
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row)
    (width : row.isByte = true) :
    byteField row = 1 ∧ halfField row = 0 := by
  cases kind <;>
    simp_all [
      FlagFacts, byteField, halfField, LoadStoreRow.isByte, boolM31,
    ]

private theorem halfWidthFieldReductions
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row)
    (width : row.isHalf = true) :
    byteField row = 0 ∧ halfField row = 1 := by
  cases kind <;>
    simp_all [
      FlagFacts, byteField, halfField, LoadStoreRow.isHalf, boolM31,
    ]

private theorem wordWidthFieldReductions
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row)
    (width : row.isWord = true) :
    byteField row = 0 ∧ halfField row = 0 := by
  cases kind <;>
    simp_all [
      FlagFacts, byteField, halfField, LoadStoreRow.isWord, boolM31,
    ]

private theorem markerSumBound (row : LoadStoreRow) :
    row.markerSum < M31.modulus := by
  have m0 := bitValueLeOne row.marker0
  have m1 := bitValueLeOne row.marker1
  have m2 := bitValueLeOne row.marker2
  have m3 := bitValueLeOne row.marker3
  simp only [LoadStoreRow.markerSum]
  rw [M31.modulus_eq]
  omega

private theorem shiftIdBound (row : LoadStoreRow) :
    row.shiftId < M31.modulus := by
  have m1 := bitValueLeOne row.marker1
  have m2 := bitValueLeOne row.marker2
  have m3 := bitValueLeOne row.marker3
  simp only [LoadStoreRow.shiftId]
  rw [M31.modulus_eq]
  omega

private theorem markerSumFieldImage (row : LoadStoreRow) :
    markerSumField row = M31.reduce row.markerSum := by
  simp [
    markerSumField, LoadStoreRow.markerSum,
    boolM31_eq_reduce_bitValue,
    Air.Bridge.TeamACommon.reduceAdd,
  ]

private theorem shiftIdFieldImage (row : LoadStoreRow) :
    shiftIdField row = M31.reduce row.shiftId := by
  simp [
    shiftIdField, LoadStoreRow.shiftId,
    boolM31_eq_reduce_bitValue,
    Air.Bridge.TeamACommon.reduceMul,
    Air.Bridge.TeamACommon.reduceAdd,
    Nat.mul_comm,
  ]

private theorem signMaskFieldImage
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row) :
    signMaskField row = bitVecM31 row.signMask := by
  cases kind <;> cases sign : row.srcMsb <;>
    simp_all [
      FlagFacts, signMaskField, signedField, boolM31,
      LoadStoreRow.signMask, LoadStoreRow.isSigned,
      bitVecM31, bitValue,
    ]

private theorem baseReadOnlyOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.rs1Next = row.rs1Previous := by
  have active := activeFieldOfFlags kind row flags
  apply wordBytesEq
  · apply m31EqOfSubZero
    simpa [active] using equations.base0
  · apply m31EqOfSubZero
    simpa [active] using equations.base1
  · apply m31EqOfSubZero
    simpa [active] using equations.base2
  · apply m31EqOfSubZero
    simpa [active] using equations.base3

private theorem sourceReadOnlyOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.srcNext = row.srcPrevious := by
  have active := activeFieldOfFlags kind row flags
  apply wordBytesEq
  · apply m31EqOfSubZero
    simpa [active] using equations.source0
  · apply m31EqOfSubZero
    simpa [active] using equations.source1
  · apply m31EqOfSubZero
    simpa [active] using equations.source2
  · apply m31EqOfSubZero
    simpa [active] using equations.source3

private theorem baseHighZeroOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.rs1Next.limb3 = 0 := by
  have active := activeFieldOfFlags kind row flags
  apply byteZero
  simpa [active] using equations.baseHigh

private theorem destinationFlagOfEquations
    (row : LoadStoreRow)
    (witness : Witness row)
    (equations : DirectEquations row witness) :
    row.destinationNonzero = decide (row.r2Idx ≠ zeroRegister) := by
  exact
    Air.Bridge.TeamACommon.destinationFlag_of_equations
      row.r2Idx row.destinationNonzero witness.destinationInverse
      (by
        simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using equations.destinationZero)
      (by
        simpa [
          bitVecM31, boolM31,
          Air.Bridge.TeamACommon.bitVecM31,
          Air.Bridge.TeamACommon.boolM31,
          Air.Bridge.Lui.bitVecM31,
          Air.Bridge.Lui.boolM31,
        ] using equations.destinationInverse)

private theorem loadDestinationOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness)
    (isLoad : row.isLoad = true) :
    row.dstNext =
      if row.destinationNonzero then row.result else WordBytes.zero := by
  have load : loadField row = 1 := by
    cases kind <;>
      simp_all [
        FlagFacts, loadField, activeField, storeField, boolM31,
        LoadStoreRow.isLoad, LoadStoreRow.isStore,
      ]
  exact
    Air.Bridge.TeamACommon.destinationBytes_of_equations
      row.dstNext row.result row.destinationNonzero
      (by simpa [load] using equations.loadDestination0)
      (by simpa [load] using equations.loadDestination1)
      (by simpa [load] using equations.loadDestination2)
      (by simpa [load] using equations.loadDestination3)

private theorem storeResultZeroOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness)
    (isStore : row.isStore = true) :
    row.result = WordBytes.zero := by
  have load : loadField row = 0 := by
    cases kind <;>
      simp_all [
        FlagFacts, loadField, activeField, storeField, boolM31,
        LoadStoreRow.isStore,
      ]
  apply WordBytes.eq_of_limbs
  · have field : bitVecM31 row.result.limb0 = 0 := by
      simpa [load] using equations.storeResult0
    simpa [WordBytes.zero] using byteZero row.result.limb0 field
  · have field : bitVecM31 row.result.limb1 = 0 := by
      simpa [load] using equations.storeResult1
    simpa [WordBytes.zero] using byteZero row.result.limb1 field
  · have field : bitVecM31 row.result.limb2 = 0 := by
      simpa [load] using equations.storeResult2
    simpa [WordBytes.zero] using byteZero row.result.limb2 field
  · have field : bitVecM31 row.result.limb3 = 0 := by
      simpa [load] using equations.storeResult3
    simpa [WordBytes.zero] using byteZero row.result.limb3 field

private theorem boolFalseOfFieldZero
    (value : Bool)
    (zero : boolM31 value = 0) :
    value = false := by
  apply boolEq value false
  simpa [boolM31] using zero

private theorem signWitnessCanonicalOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isSigned = false → row.srcMsb = false := by
  intro unsigned
  have signedZero : signedField row = 0 := by
    rw [signedFieldImageOfFlags kind row flags, unsigned]
    rfl
  apply boolFalseOfFieldZero
  simpa only [
    signedZero, M31.sub_zero, M31.one_mul,
  ] using equations.signCanonical

private theorem markerSumOneOfField
    (row : LoadStoreRow)
    (equation : 1 - markerSumField row = 0) :
    row.markerSum = 1 := by
  have field : markerSumField row = 1 :=
    (m31EqOfSubZero equation).symm
  apply
    reduceNatEq (markerSumBound row) (by decide : 1 < M31.modulus)
  calc
    M31.reduce row.markerSum = markerSumField row :=
      (markerSumFieldImage row).symm
    _ = 1 := field
    _ = M31.reduce 1 := rfl

private theorem markerSumTwoOfField
    (row : LoadStoreRow)
    (equation : M31.reduce 2 - markerSumField row = 0) :
    row.markerSum = 2 := by
  have field : markerSumField row = M31.reduce 2 :=
    (m31EqOfSubZero equation).symm
  apply
    reduceNatEq (markerSumBound row) (by decide : 2 < M31.modulus)
  calc
    M31.reduce row.markerSum = markerSumField row :=
      (markerSumFieldImage row).symm
    _ = M31.reduce 2 := field

private theorem byteMarkerSumOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isByte = true → row.markerSum = 1 := by
  intro width
  have byte :=
    (byteWidthFieldReductions kind row flags width).1
  apply markerSumOneOfField
  simpa only [byte, M31.one_mul] using equations.byteMarker

private theorem halfMarkerSumOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isHalf = true → row.markerSum = 2 := by
  intro width
  have half :=
    (halfWidthFieldReductions kind row flags width).2
  apply markerSumTwoOfField
  simpa only [half, M31.one_mul] using equations.halfMarker

private theorem halfShiftPolynomialNonzero
    (value : Nat)
    (bound : value ≤ 6)
    (notOne : value ≠ 1)
    (notFive : value ≠ 5) :
    (1 - M31.reduce value) *
        (M31.reduce 5 - M31.reduce value) ≠ 0 := by
  have values :
      value = 0 ∨ value = 1 ∨ value = 2 ∨ value = 3 ∨
        value = 4 ∨ value = 5 ∨ value = 6 := by
    omega
  rcases values with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · decide
  · exact (notOne rfl).elim
  · decide
  · decide
  · decide
  · exact (notFive rfl).elim
  · decide

private theorem halfShiftIdOfField
    (row : LoadStoreRow)
    (equation :
      (1 - shiftIdField row) *
        (M31.reduce 5 - shiftIdField row) = 0) :
    row.shiftId = 1 ∨ row.shiftId = 5 := by
  have m1 := bitValueLeOne row.marker1
  have m2 := bitValueLeOne row.marker2
  have m3 := bitValueLeOne row.marker3
  have bound : row.shiftId ≤ 6 := by
    simp only [LoadStoreRow.shiftId]
    omega
  rw [shiftIdFieldImage row] at equation
  by_cases one : row.shiftId = 1
  · exact Or.inl one
  by_cases five : row.shiftId = 5
  · exact Or.inr five
  exact
    (halfShiftPolynomialNonzero
      row.shiftId bound one five equation).elim

private theorem halfShiftIdOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isHalf = true → row.shiftId = 1 ∨ row.shiftId = 5 := by
  intro width
  have half :=
    (halfWidthFieldReductions kind row flags width).2
  apply halfShiftIdOfField
  simpa only [half, M31.one_mul] using equations.halfShift

private theorem byteShiftAmountOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (admission : Admission row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isByte = true → row.shiftAmount = row.shiftId := by
  intro width
  have widthFields :=
    byteWidthFieldReductions kind row flags width
  have solve
      (field :
        M31.reduce row.shiftAmount - shiftIdField row = 0) :
      row.shiftAmount = row.shiftId := by
    apply
      reduceNatEq admission.shiftAmountCanonical (shiftIdBound row)
    calc
      M31.reduce row.shiftAmount = shiftIdField row :=
        m31EqOfSubZero field
      _ = M31.reduce row.shiftId := shiftIdFieldImage row
  apply solve
  simpa only [
    widthFields.1, widthFields.2, M31.one_mul, M31.zero_mul,
    M31.add_zero,
  ] using equations.shiftAmount

private theorem halfShiftAmountOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (admission : Admission row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isHalf = true → 2 * row.shiftAmount + 1 = row.shiftId := by
  intro width
  have widthFields :=
    halfWidthFieldReductions kind row flags width
  have identifier :=
    halfShiftIdOfEquations kind row witness flags equations width
  rcases identifier with id | id
  · have field : M31.reduce row.shiftAmount = 0 := by
      have root := equations.shiftAmount
      rw [
        widthFields.1, widthFields.2,
        shiftIdFieldImage row, id,
      ] at root
      simpa using m31EqOfSubZero root
    have amount : row.shiftAmount = 0 := by
      apply
        reduceNatEq admission.shiftAmountCanonical
          (by decide : 0 < M31.modulus)
      simpa using field
    omega
  · have field : M31.reduce row.shiftAmount = M31.reduce 2 := by
      have root := equations.shiftAmount
      rw [
        widthFields.1, widthFields.2,
        shiftIdFieldImage row, id,
      ] at root
      simpa using m31EqOfSubZero root
    have amount : row.shiftAmount = 2 :=
      reduceNatEq admission.shiftAmountCanonical
        (by decide : 2 < M31.modulus) field
    omega

private theorem wordShiftAmountOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (admission : Admission row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isWord = true → row.shiftAmount = 0 := by
  intro width
  have widthFields :=
    wordWidthFieldReductions kind row flags width
  have solve
      (field : M31.reduce row.shiftAmount = 0) :
      row.shiftAmount = 0 := by
    apply
      reduceNatEq admission.shiftAmountCanonical
        (by decide : 0 < M31.modulus)
    simpa using field
  apply solve
  have root := equations.shiftAmount
  rw [widthFields.1, widthFields.2] at root
  simpa using m31EqOfSubZero root

private theorem extensionByteOfField
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row)
    (result : Byte)
    (equation :
      signMaskField row - bitVecM31 result = 0) :
    result = row.signMask := by
  have field :
      bitVecM31 row.signMask = bitVecM31 result := by
    rw [← signMaskFieldImage kind row flags]
    exact m31EqOfSubZero equation
  exact (byteEq row.signMask result field).symm

private theorem byteLoadExtensionOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isByteLoad = true →
      row.result.limb1 = row.signMask ∧
        row.result.limb2 = row.signMask ∧
        row.result.limb3 = row.signMask := by
  intro load
  have loadField : byteLoadField row = 1 := by
    rw [byteLoadFieldImageOfFlags kind row flags, load]
    rfl
  refine ⟨?_, ?_, ?_⟩
  · apply extensionByteOfField kind row flags
    simpa only [loadField, M31.one_mul] using
      equations.byteExtension1
  · apply extensionByteOfField kind row flags
    simpa only [loadField, M31.one_mul] using
      equations.byteExtension2
  · apply extensionByteOfField kind row flags
    simpa only [loadField, M31.one_mul] using
      equations.byteExtension3

private theorem byteLoadSelectOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isByteLoad = true →
      (row.marker0 = true →
          row.result.limb0 = row.srcNext.limb0) ∧
        (row.marker1 = true →
          row.result.limb0 = row.srcNext.limb1) ∧
        (row.marker2 = true →
          row.result.limb0 = row.srcNext.limb2) ∧
        (row.marker3 = true →
          row.result.limb0 = row.srcNext.limb3) := by
  intro load
  have loadField : byteLoadField row = 1 := by
    rw [byteLoadFieldImageOfFlags kind row flags, load]
    rfl
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, marker, boolM31, M31.one_mul, M31.mul_one,
    ] using equations.byteLoad0
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, marker, boolM31, M31.one_mul, M31.mul_one,
    ] using equations.byteLoad1
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, marker, boolM31, M31.one_mul, M31.mul_one,
    ] using equations.byteLoad2
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, marker, boolM31, M31.one_mul, M31.mul_one,
    ] using equations.byteLoad3

private theorem byteStoreSelectOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isSb = true →
      (row.marker0 = true →
          row.dstNext.limb0 = row.srcNext.limb0) ∧
        (row.marker1 = true →
          row.dstNext.limb1 = row.srcNext.limb0) ∧
        (row.marker2 = true →
          row.dstNext.limb2 = row.srcNext.limb0) ∧
        (row.marker3 = true →
          row.dstNext.limb3 = row.srcNext.limb0) := by
  intro store
  have storeField : boolM31 row.isSb = 1 := by
    rw [store]
    rfl
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.byteStore0
    rw [storeField] at root
    simpa only [
      marker, boolM31, M31.one_mul, M31.mul_one,
    ] using root
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.byteStore1
    rw [storeField] at root
    simpa only [
      marker, boolM31, M31.one_mul, M31.mul_one,
    ] using root
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.byteStore2
    rw [storeField] at root
    simpa only [
      marker, boolM31, M31.one_mul, M31.mul_one,
    ] using root
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.byteStore3
    rw [storeField] at root
    simpa only [
      marker, boolM31, M31.one_mul, M31.mul_one,
    ] using root

private theorem halfLoadExtensionOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isHalfLoad = true →
      row.result.limb2 = row.signMask ∧
        row.result.limb3 = row.signMask := by
  intro load
  have loadField : halfLoadField row = 1 := by
    rw [halfLoadFieldImageOfFlags kind row flags, load]
    rfl
  constructor
  · apply extensionByteOfField kind row flags
    simpa only [loadField, M31.one_mul] using
      equations.halfExtension2
  · apply extensionByteOfField kind row flags
    simpa only [loadField, M31.one_mul] using
      equations.halfExtension3

private theorem halfLowSelectionCoefficient :
    (M31.reduce 5 - M31.reduce 1) * M31.reduce 536870912 = 1 := by
  decide

private theorem halfHighSelectionCoefficient :
    (M31.reduce 5 - 1) * M31.reduce 536870912 = 1 := by
  decide

private theorem halfLoadLowOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isHalfLoad = true → row.shiftId = 1 →
      row.result.limb0 = row.srcNext.limb0 ∧
        row.result.limb1 = row.srcNext.limb1 := by
  intro load identifier
  have loadField : halfLoadField row = 1 := by
    rw [halfLoadFieldImageOfFlags kind row flags, load]
    rfl
  constructor
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, shiftIdFieldImage row, identifier,
      halfLowSelectionCoefficient, M31.one_mul,
    ] using equations.halfLoadLow0
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, shiftIdFieldImage row, identifier,
      halfLowSelectionCoefficient, M31.one_mul,
    ] using equations.halfLoadLow1

private theorem halfLoadHighOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isHalfLoad = true → row.shiftId = 5 →
      row.result.limb0 = row.srcNext.limb2 ∧
        row.result.limb1 = row.srcNext.limb3 := by
  intro load identifier
  have loadField : halfLoadField row = 1 := by
    rw [halfLoadFieldImageOfFlags kind row flags, load]
    rfl
  constructor
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, shiftIdFieldImage row, identifier,
      halfHighSelectionCoefficient, M31.one_mul,
    ] using equations.halfLoadHigh0
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      loadField, shiftIdFieldImage row, identifier,
      halfHighSelectionCoefficient, M31.one_mul,
    ] using equations.halfLoadHigh1

private theorem halfStoreLowOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isSh = true → row.shiftId = 1 →
      row.dstNext.limb0 = row.srcNext.limb0 ∧
        row.dstNext.limb1 = row.srcNext.limb1 := by
  intro store identifier
  have storeField : boolM31 row.isSh = 1 := by
    rw [store]
    rfl
  constructor
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      storeField, shiftIdFieldImage row, identifier,
      halfLowSelectionCoefficient, M31.one_mul,
    ] using equations.halfStoreLow0
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      storeField, shiftIdFieldImage row, identifier,
      halfLowSelectionCoefficient, M31.one_mul,
    ] using equations.halfStoreLow1

private theorem halfStoreHighOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isSh = true → row.shiftId = 5 →
      row.dstNext.limb2 = row.srcNext.limb0 ∧
        row.dstNext.limb3 = row.srcNext.limb1 := by
  intro store identifier
  have storeField : boolM31 row.isSh = 1 := by
    rw [store]
    rfl
  constructor
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      storeField, shiftIdFieldImage row, identifier,
      halfHighSelectionCoefficient, M31.one_mul,
    ] using equations.halfStoreHigh2
  · apply byteEq
    apply m31EqOfSubZero
    simpa only [
      storeField, shiftIdFieldImage row, identifier,
      halfHighSelectionCoefficient, M31.one_mul,
    ] using equations.halfStoreHigh3

private theorem wordLoadSelectorFields
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row)
    (load : row.isLw = true) :
    boolM31 row.isLw = 1 ∧ boolM31 row.isSw = 0 := by
  cases kind <;>
    simp_all [FlagFacts, boolM31]

private theorem wordStoreSelectorFields
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row)
    (store : row.isSw = true) :
    boolM31 row.isLw = 0 ∧ boolM31 row.isSw = 1 := by
  cases kind <;>
    simp_all [FlagFacts, boolM31]

private theorem partialStoreSelectorField
    (kind : Kind)
    (row : LoadStoreRow)
    (flags : FlagFacts kind row)
    (narrow : row.isSb = true ∨ row.isSh = true) :
    boolM31 row.isSb + boolM31 row.isSh = 1 := by
  cases kind <;>
    simp_all [FlagFacts, boolM31]

private theorem wordLoadOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isLw = true → row.result = row.srcNext := by
  intro load
  have selectors :=
    wordLoadSelectorFields kind row flags load
  apply wordBytesEq
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.add_zero,
    ] using equations.word0
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.add_zero,
    ] using equations.word1
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.add_zero,
    ] using equations.word2
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.add_zero,
    ] using equations.word3

private theorem wordStoreOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isSw = true → row.dstNext = row.srcNext := by
  intro store
  have selectors :=
    wordStoreSelectorFields kind row flags store
  apply wordBytesEq
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.zero_add,
    ] using equations.word0
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.zero_add,
    ] using equations.word1
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.zero_add,
    ] using equations.word2
  · apply m31EqOfSubZero
    simpa only [
      selectors.1, selectors.2, M31.one_mul, M31.zero_mul,
      M31.zero_add,
    ] using equations.word3

private theorem partialStorePreserveOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.isSb = true ∨ row.isSh = true →
      (row.marker0 = false →
          row.dstNext.limb0 = row.dstPrevious.limb0) ∧
        (row.marker1 = false →
          row.dstNext.limb1 = row.dstPrevious.limb1) ∧
        (row.marker2 = false →
          row.dstNext.limb2 = row.dstPrevious.limb2) ∧
        (row.marker3 = false →
          row.dstNext.limb3 = row.dstPrevious.limb3) := by
  intro narrow
  have selector :=
    partialStoreSelectorField kind row flags narrow
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.preserve0
    rw [selector] at root
    simpa only [
      marker, boolM31, M31.sub_zero, M31.one_mul,
    ] using root
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.preserve1
    rw [selector] at root
    simpa only [
      marker, boolM31, M31.sub_zero, M31.one_mul,
    ] using root
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.preserve2
    rw [selector] at root
    simpa only [
      marker, boolM31, M31.sub_zero, M31.one_mul,
    ] using root
  · intro marker
    apply byteEq
    apply m31EqOfSubZero
    have root := equations.preserve3
    rw [selector] at root
    simpa only [
      marker, boolM31, M31.sub_zero, M31.one_mul,
    ] using root

private theorem shiftAmountLtFourOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (admission : Admission row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    row.shiftAmount < 4 := by
  have byteBranch :
      row.isByte = true → row.shiftAmount < 4 := by
    intro width
    have sum :=
      byteMarkerSumOfEquations kind row witness flags equations width
    have amount :=
      byteShiftAmountOfEquations
        kind row witness admission flags equations width
    simp only [LoadStoreRow.markerSum] at sum
    simp only [LoadStoreRow.shiftId] at amount
    rcases
        Opcodes.byte_marker_cases
          row.marker0 row.marker1 row.marker2 row.marker3 sum with
      ⟨_, _, _, _, identifier⟩ |
      ⟨_, _, _, _, identifier⟩ |
      ⟨_, _, _, _, identifier⟩ |
      ⟨_, _, _, _, identifier⟩ <;>
        omega
  have halfBranch :
      row.isHalf = true → row.shiftAmount < 4 := by
    intro width
    have amount :=
      halfShiftAmountOfEquations
        kind row witness admission flags equations width
    rcases
        halfShiftIdOfEquations kind row witness flags equations width with
      identifier | identifier <;>
        omega
  have wordBranch :
      row.isWord = true → row.shiftAmount < 4 := by
    intro width
    rw [
      wordShiftAmountOfEquations
        kind row witness admission flags equations width,
    ]
    decide
  cases kind with
  | lb =>
      exact byteBranch (by simp_all [FlagFacts, LoadStoreRow.isByte])
  | lh =>
      exact halfBranch (by simp_all [FlagFacts, LoadStoreRow.isHalf])
  | lw =>
      exact wordBranch (by simp_all [FlagFacts, LoadStoreRow.isWord])
  | lbu =>
      exact byteBranch (by simp_all [FlagFacts, LoadStoreRow.isByte])
  | lhu =>
      exact halfBranch (by simp_all [FlagFacts, LoadStoreRow.isHalf])
  | sb =>
      exact byteBranch (by simp_all [FlagFacts, LoadStoreRow.isByte])
  | sh =>
      exact halfBranch (by simp_all [FlagFacts, LoadStoreRow.isHalf])
  | sw =>
      exact wordBranch (by simp_all [FlagFacts, LoadStoreRow.isWord])

private theorem alignedAddressFieldOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness) :
    M31.reduce row.alignedAddress =
      effectiveMinusShiftField row := by
  have loadImage :=
    loadFieldImageOfFlags kind row flags
  have storeImage :=
    storeFieldImageOfFlags kind row flags
  cases store : row.isStore with
  | false =>
      have loadOne : loadField row = 1 := by
        rw [loadImage, LoadStoreRow.isLoad, store]
        rfl
      have storeZero : storeField row = 0 := by
        rw [storeImage, store]
        rfl
      have source :
          M31.reduce row.sourceSelector =
            M31.reduce row.alignedAddress := by
        simp [LoadStoreRow.sourceSelector, store]
      have root := m31EqOfSubZero equations.sourceSelector
      rw [source, loadOne, storeZero] at root
      simpa only [
        M31.one_mul, M31.zero_mul, M31.add_zero,
      ] using root
  | true =>
      have loadZero : loadField row = 0 := by
        rw [loadImage, LoadStoreRow.isLoad, store]
        rfl
      have storeOne : storeField row = 1 := by
        rw [storeImage, store]
        rfl
      have destination :
          M31.reduce row.destinationSelector =
            M31.reduce row.alignedAddress := by
        simp only [
          LoadStoreRow.destinationSelector, store, ↓reduceIte,
        ]
      have root := m31EqOfSubZero equations.destinationSelector
      rw [destination, loadZero, storeOne] at root
      simpa only [
        M31.zero_mul, M31.one_mul, M31.zero_add,
      ] using root

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
    have sumBound : right.val + offset.val < M31.modulus := by
      omega
    apply M31.ext
    rw [M31.add_val_of_lt right offset sumBound]
    omega
  · have reverse : left.val < right.val := Nat.lt_of_not_ge ordered
    rw [M31.sub_val_of_lt left right reverse] at values
    apply M31.ext
    change left.val = (right.val + offset.val) % M31.modulus
    have sum :
        right.val + offset.val = M31.modulus + left.val := by
      omega
    rw [sum, Nat.add_mod_left, Nat.mod_eq_of_lt leftBound]

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
      exact
        Nat.mod_eq_of_lt
          (by omega :
            right.val + offset.val - M31.modulus <
              M31.modulus)
    rw [addValue] at values
    have reverse : left.val < offset.val := by
      omega
    apply M31.ext
    rw [M31.sub_val_of_lt left offset reverse]
    omega

private theorem memoryAddressOfEquations
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (admission : Admission row)
    (flags : FlagFacts kind row)
    (equations : DirectEquations row witness)
    (alignedQuarterRange : row.alignedQuarter < 2 ^ 20) :
    (row.rs1Next.value + row.immFelt) % m31Modulus =
      row.alignedAddress + row.shiftAmount := by
  have alignedField :=
    alignedAddressFieldOfEquations kind row witness flags equations
  have sumField :
      baseValueField row + M31.reduce row.immFelt =
        M31.reduce row.shiftAmount + M31.reduce row.alignedAddress :=
    m31EqAddOfSubEq
      (baseValueField row + M31.reduce row.immFelt)
      (M31.reduce row.shiftAmount)
      (M31.reduce row.alignedAddress)
      alignedField.symm
  have normalized :
      M31.reduce (row.rs1Next.value + row.immFelt) =
        M31.reduce (row.alignedAddress + row.shiftAmount) := by
    calc
      M31.reduce (row.rs1Next.value + row.immFelt) =
          M31.reduce row.rs1Next.value + M31.reduce row.immFelt :=
        (Air.Bridge.TeamACommon.reduceAdd _ _).symm
      _ = baseValueField row + M31.reduce row.immFelt := by
        rw [
          baseValueField,
          Air.Bridge.TeamACommon.wordBytesField_eq_reduce row.rs1Next,
        ]
      _ = M31.reduce row.shiftAmount +
          M31.reduce row.alignedAddress :=
        sumField
      _ = M31.reduce (row.shiftAmount + row.alignedAddress) :=
        Air.Bridge.TeamACommon.reduceAdd _ _
      _ = M31.reduce (row.alignedAddress + row.shiftAmount) := by
        congr 1
        omega
  have shiftRange :=
    shiftAmountLtFourOfEquations
      kind row witness admission flags equations
  have addressRange :
      row.alignedAddress + row.shiftAmount < M31.modulus := by
    simp only [LoadStoreRow.alignedAddress]
    rw [M31.modulus_eq]
    simp only [Nat.reducePow] at alignedQuarterRange
    omega
  have values := congrArg M31.val normalized
  simp only [M31.reduce_val] at values
  rw [Nat.mod_eq_of_lt addressRange] at values
  simpa [m31Modulus, M31.modulus_eq] using values

/-! ## Exact fixed-table projection -/

private def accessClockField
    (row : LoadStoreRow)
    (ordinal : Nat) : M31 :=
  Air.Bridge.TeamACommon.accessClockField row.clock ordinal

private def clockGapField
    (row : LoadStoreRow)
    (ordinal previous : Nat) : M31 :=
  accessClockField row ordinal - M31.reduce previous - 1

private def sourceAccessClockField (row : LoadStoreRow) : M31 :=
  accessClockField row 2 + loadField row

private def destinationAccessClockField (row : LoadStoreRow) : M31 :=
  accessClockField row 2 + storeField row

private def sourceClockGapField (row : LoadStoreRow) : M31 :=
  sourceAccessClockField row - M31.reduce row.srcPreviousClock - 1

private def destinationClockGapField (row : LoadStoreRow) : M31 :=
  destinationAccessClockField row -
    M31.reduce row.dstPreviousClock - 1

private def alignedQuarterField (row : LoadStoreRow) : M31 :=
  (M31.reduce row.sourceSelector +
      M31.reduce row.destinationSelector -
      bitVecM31 row.r2Idx) *
    M31.reduce 536870912

private def range20Lookup
    (ordinal : Nat)
    (accessOrdinal : Option Nat)
    (numerator value : M31) :
    EvaluatedLookup where
  ordinal := ordinal
  domain := .rangeCheck20
  numerator := numerator
  tuple := #[value]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := accessOrdinal

private def rangeM31Lookup
    (ordinal : Nat)
    (numerator low high : M31) :
    EvaluatedLookup where
  ordinal := ordinal
  domain := .rangeCheckM31
  numerator := numerator
  tuple := #[low, high]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def fixedLookupOrdinals : Array Nat :=
  #[76, 77, 78, 81, 84, 85, 86]

private def fixedRawLookup : Nat → LookupEvent
  | 76 => {
      ordinal := 76
      domain := .rangeCheck20
      numerator := 293
      tuple := #[286]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := some 1
    }
  | 77 => {
      ordinal := 77
      domain := .rangeCheck20
      numerator := 293
      tuple := #[102]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 78 => {
      ordinal := 78
      domain := .rangeCheckM31
      numerator := 293
      tuple := #[18, 21]
      role := .request
      tableId := some .rangeCheckM31
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 81 => {
      ordinal := 81
      domain := .rangeCheck20
      numerator := 293
      tuple := #[289]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := some 2
    }
  | 84 => {
      ordinal := 84
      domain := .rangeCheck20
      numerator := 293
      tuple := #[292]
      role := .request
      tableId := some .rangeCheck20
      liveness := .nonzeroNumerator
      accessOrdinal := some 3
    }
  | 85 => {
      ordinal := 85
      domain := .rangeCheckM31
      numerator := 323
      tuple := #[70, 321]
      role := .request
      tableId := some .rangeCheckM31
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | 86 => {
      ordinal := 86
      domain := .rangeCheckM31
      numerator := 324
      tuple := #[70, 322]
      role := .request
      tableId := some .rangeCheckM31
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }
  | ordinal => {
      ordinal := ordinal
      domain := .programAccess
      numerator := 0
      tuple := #[]
      role := .request
      tableId := none
      liveness := .nonzeroNumerator
      accessOrdinal := none
    }

private def expectedFixedLookup
    (row : LoadStoreRow) : Nat → EvaluatedLookup
  | 76 =>
      range20Lookup 76 (some 1) (-activeField row)
        (clockGapField row 1 row.rs1PreviousClock)
  | 77 =>
      range20Lookup 77 none (-activeField row)
        (alignedQuarterField row)
  | 78 =>
      rangeM31Lookup 78 (-activeField row)
        (bitVecM31 row.rs1Next.limb0)
        (bitVecM31 row.rs1Next.limb3)
  | 81 =>
      range20Lookup 81 (some 2) (-activeField row)
        (sourceClockGapField row)
  | 84 =>
      range20Lookup 84 (some 3) (-activeField row)
        (destinationClockGapField row)
  | 85 =>
      rangeM31Lookup 85 (-(boolM31 row.isLb))
        0
        (bitVecM31 row.result.limb0 -
          boolM31 row.srcMsb * M31.reduce 128)
  | 86 =>
      rangeM31Lookup 86 (-(boolM31 row.isLh))
        0
        (bitVecM31 row.result.limb1 -
          boolM31 row.srcMsb * M31.reduce 128)
  | ordinal =>
      range20Lookup ordinal none 0 0

private def evaluatedSelectedLookup
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (event : LookupEvent) : EvaluatedLookup where
  ordinal := event.ordinal
  domain := event.domain
  numerator :=
    ((program kind).evalNodesSymbolic
      (columns row witness)).getSymbolic event.numerator
  tuple :=
    event.tuple.map
      ((program kind).evalNodesSymbolic
        (columns row witness)).getSymbolic
  role := event.role
  tableId := event.tableId
  accessOrdinal := event.accessOrdinal

set_option maxRecDepth 30000 in
private theorem fixedRawLookupSelected
    (kind : Kind)
    (ordinal : Nat)
    (member : ordinal ∈ fixedLookupOrdinals) :
    (program kind).source.events[ordinal]? =
      some (.lookup (fixedRawLookup ordinal)) := by
  have choices := member
  simp [fixedLookupOrdinals] at choices
  rcases choices with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl
  all_goals
    rw [programEventsShared]
    rfl

private theorem selectedFixedLookupProjection
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ fixedLookupOrdinals) :
    (evaluation kind row witness).lookup? ordinal =
      some
        (evaluatedSelectedLookup kind row witness
          (fixedRawLookup ordinal)) := by
  unfold evaluation evaluatedSelectedLookup
  exact
    LocalProgram.lookup?_evalSymbolic_of_event
      (program kind) (columns row witness) ordinal
      (fixedRawLookup ordinal)
      (fixedRawLookupSelected kind ordinal member)

set_option maxRecDepth 30000 in
private theorem evaluatedFixedLookupsA
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    evaluatedSelectedLookup kind row witness (fixedRawLookup 76) =
        expectedFixedLookup row 76 ∧
      evaluatedSelectedLookup kind row witness (fixedRawLookup 77) =
        expectedFixedLookup row 77 ∧
      evaluatedSelectedLookup kind row witness (fixedRawLookup 78) =
        expectedFixedLookup row 78 ∧
      evaluatedSelectedLookup kind row witness (fixedRawLookup 81) =
        expectedFixedLookup row 81 := by
  simp [
    evaluatedSelectedLookup, fixedRawLookup, expectedFixedLookup,
    LocalProgram.evalNodesSymbolic, programNodesShared, Programs.lb,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic, columns,
    range20Lookup, rangeM31Lookup,
    accessClockField, Air.Bridge.TeamACommon.accessClockField,
    clockGapField, sourceAccessClockField,
    sourceClockGapField, alignedQuarterField,
    activeField, loadField, storeField, bitVecM31, boolM31,
  ]

set_option maxRecDepth 30000 in
private theorem evaluatedFixedLookupsB
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    evaluatedSelectedLookup kind row witness (fixedRawLookup 84) =
        expectedFixedLookup row 84 ∧
      evaluatedSelectedLookup kind row witness (fixedRawLookup 85) =
        expectedFixedLookup row 85 ∧
      evaluatedSelectedLookup kind row witness (fixedRawLookup 86) =
        expectedFixedLookup row 86 := by
  simp [
    evaluatedSelectedLookup, fixedRawLookup, expectedFixedLookup,
    LocalProgram.evalNodesSymbolic, programNodesShared, Programs.lb,
    LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
    LocalValues.getSymbolic, newestValueSymbolic, columns,
    range20Lookup, rangeM31Lookup,
    accessClockField, Air.Bridge.TeamACommon.accessClockField,
    destinationAccessClockField,
    destinationClockGapField,
    activeField, loadField, storeField, bitVecM31, boolM31,
  ]

private theorem fixedProjectionAt
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (ordinal : Nat)
    (member : ordinal ∈ fixedLookupOrdinals) :
    (evaluation kind row witness).lookup? ordinal =
      some (expectedFixedLookup row ordinal) := by
  obtain ⟨h76, h77, h78, h81⟩ :=
    evaluatedFixedLookupsA kind row witness
  obtain ⟨h84, h85, h86⟩ :=
    evaluatedFixedLookupsB kind row witness
  have evaluated :
      evaluatedSelectedLookup kind row witness
          (fixedRawLookup ordinal) =
        expectedFixedLookup row ordinal := by
    have choices := member
    simp [fixedLookupOrdinals] at choices
    rcases choices with
      rfl | rfl | rfl | rfl | rfl | rfl | rfl
    all_goals assumption
  exact
    (selectedFixedLookupProjection
      kind row witness ordinal member).trans
      (congrArg some evaluated)

structure ExactFixedProjection
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) : Prop where
  baseClock :
    (evaluation kind row witness).lookup? 76 =
      some
        (range20Lookup 76 (some 1) (-activeField row)
          (clockGapField row 1 row.rs1PreviousClock))
  alignedQuarter :
    (evaluation kind row witness).lookup? 77 =
      some
        (range20Lookup 77 none (-activeField row)
          (alignedQuarterField row))
  baseRange :
    (evaluation kind row witness).lookup? 78 =
      some
        (rangeM31Lookup 78 (-activeField row)
          (bitVecM31 row.rs1Next.limb0)
          (bitVecM31 row.rs1Next.limb3))
  sourceClock :
    (evaluation kind row witness).lookup? 81 =
      some
        (range20Lookup 81 (some 2) (-activeField row)
          (sourceClockGapField row))
  destinationClock :
    (evaluation kind row witness).lookup? 84 =
      some
        (range20Lookup 84 (some 3) (-activeField row)
          (destinationClockGapField row))
  byteSign :
    (evaluation kind row witness).lookup? 85 =
      some
        (rangeM31Lookup 85 (-(boolM31 row.isLb))
          0
          (bitVecM31 row.result.limb0 -
            boolM31 row.srcMsb * M31.reduce 128))
  halfSign :
    (evaluation kind row witness).lookup? 86 =
      some
        (rangeM31Lookup 86 (-(boolM31 row.isLh))
          0
          (bitVecM31 row.result.limb1 -
            boolM31 row.srcMsb * M31.reduce 128))

private theorem evaluationLookupShared
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (ordinal : Nat) :
    (evaluation kind row witness).lookup? ordinal =
      (baseEvaluation row witness).lookup? ordinal := by
  cases kind <;> rfl

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem exactFixedProjection
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row) :
    ExactFixedProjection kind row witness := by
  have members :
      76 ∈ fixedLookupOrdinals ∧
        77 ∈ fixedLookupOrdinals ∧
        78 ∈ fixedLookupOrdinals ∧
        81 ∈ fixedLookupOrdinals ∧
        84 ∈ fixedLookupOrdinals ∧
        85 ∈ fixedLookupOrdinals ∧
        86 ∈ fixedLookupOrdinals := by
    simp [fixedLookupOrdinals]
  obtain ⟨h76, h77, h78, h81, h84, h85, h86⟩ := members
  exact {
    baseClock :=
      fixedProjectionAt kind row witness 76 h76
    alignedQuarter :=
      fixedProjectionAt kind row witness 77 h77
    baseRange :=
      fixedProjectionAt kind row witness 78 h78
    sourceClock :=
      fixedProjectionAt kind row witness 81 h81
    destinationClock :=
      fixedProjectionAt kind row witness 84 h84
    byteSign :=
      fixedProjectionAt kind row witness 85 h85
    halfSign :=
      fixedProjectionAt kind row witness 86 h86
  }

private theorem negOneLive :
    ((-(1 : M31)) != 0) = true := by
  decide

private theorem rangeCheckM31RequestHolds_iff
    (ordinal : Nat)
    (low high : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal := ordinal
      domain := .rangeCheckM31
      numerator := -(1 : M31)
      tuple := #[low, high]
      role := .request
      tableId := some .rangeCheckM31
      accessOrdinal := none
    }) = true ↔
      low.val < 256 ∧ high.val < 128 ∧
        low.val + 256 * high.val < 32767 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    negOneLive,
    ↓reduceIte,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
    decide_eq_true_eq,
    Bool.and_eq_true,
    Nat.reducePow,
    Nat.reduceSub,
    and_assoc,
  ]

private theorem range20BoundOfLookup
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (ordinal : Nat)
    (accessOrdinal : Option Nat)
    (value : M31)
    (fixed : (evaluation kind row witness).fixedLookupsHold = true)
    (selected :
      (evaluation kind row witness).lookup? ordinal =
        some
          (range20Lookup ordinal accessOrdinal (-activeField row) value)) :
    value.val < 2 ^ 20 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation kind row witness) ordinal
      (range20Lookup ordinal accessOrdinal (-activeField row) value)
      fixed selected
  have active := activeFieldOfFlags kind row flags
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      ordinal accessOrdinal value).mp
      (by simpa [range20Lookup, active] using request)

private theorem rangeM31BoundsOfLookup
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (flags : FlagFacts kind row)
    (ordinal : Nat)
    (low high : M31)
    (fixed : (evaluation kind row witness).fixedLookupsHold = true)
    (selected :
      (evaluation kind row witness).lookup? ordinal =
        some
          (rangeM31Lookup ordinal (-activeField row) low high)) :
    low.val < 256 ∧ high.val < 128 ∧
      low.val + 256 * high.val < 32767 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation kind row witness) ordinal
      (rangeM31Lookup ordinal (-activeField row) low high)
      fixed selected
  have active := activeFieldOfFlags kind row flags
  exact
    (rangeCheckM31RequestHolds_iff ordinal low high).mp
      (by simpa [rangeM31Lookup, active] using request)

private theorem signResidualBoundOfLookup
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (ordinal : Nat)
    (selector : Bool)
    (high : M31)
    (selectorOn : selector = true)
    (fixed : (evaluation kind row witness).fixedLookupsHold = true)
    (selected :
      (evaluation kind row witness).lookup? ordinal =
        some
          (rangeM31Lookup ordinal (-(boolM31 selector)) 0 high)) :
    high.val < 128 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (evaluation kind row witness) ordinal
      (rangeM31Lookup ordinal (-(boolM31 selector)) 0 high)
      fixed selected
  have normalized :
      EvaluatedLookup.fixedRequestHolds {
        ordinal := ordinal
        domain := .rangeCheckM31
        numerator := -(1 : M31)
        tuple := #[0, high]
        role := .request
        tableId := some .rangeCheckM31
        accessOrdinal := none
      } = true := by
    simpa [rangeM31Lookup, selectorOn, boolM31] using request
  exact
    ((rangeCheckM31RequestHolds_iff ordinal 0 high).mp normalized).2.1

private theorem byteGetLsbDSevenEqThreshold (byte : Byte) :
    byte.getLsbD 7 = decide (128 ≤ byte.toNat) := by
  revert byte
  decide

private theorem byteMsbOfResidual
    (byte : Byte)
    (sign : Bool)
    (residual :
      (bitVecM31 byte - boolM31 sign * M31.reduce 128).val < 128) :
    sign = byte.getLsbD 7 := by
  have byteImage :
      (bitVecM31 byte).val = byte.toNat :=
    M31.reduce_val_of_lt byte.toNat (byteBound byte)
  rw [byteGetLsbDSevenEqThreshold byte]
  cases sign with
  | false =>
      have below : byte.toNat < 128 := by
        simpa [boolM31, byteImage] using residual
      simp [below]
  | true =>
      have high : 128 ≤ byte.toNat := by
        by_cases below : byte.toNat < 128
        · have wrapped :=
            M31.sub_val_of_lt
              (bitVecM31 byte) (M31.reduce 128)
              (by
                rw [
                  byteImage,
                  M31.reduce_val_of_lt 128 (by decide),
                ]
                exact below)
          rw [show boolM31 true = 1 by rfl, M31.one_mul] at residual
          rw [
            wrapped, byteImage,
            M31.reduce_val_of_lt 128 (by decide),
          ] at residual
          simp [M31.modulus_eq] at residual
          omega
        · omega
      simp [high]

private theorem byteSignWitnessOfLookup
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (fixed : (evaluation kind row witness).fixedLookupsHold = true) :
    row.isLb = true →
      row.srcMsb = row.result.limb0.getLsbD 7 := by
  intro selector
  have projection := exactFixedProjection kind row witness
  apply byteMsbOfResidual
  exact
    signResidualBoundOfLookup kind row witness 85 row.isLb
      (bitVecM31 row.result.limb0 -
        boolM31 row.srcMsb * M31.reduce 128)
      selector fixed projection.byteSign

private theorem halfSignWitnessOfLookup
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (fixed : (evaluation kind row witness).fixedLookupsHold = true) :
    row.isLh = true →
      row.srcMsb = row.result.limb1.getLsbD 7 := by
  intro selector
  have projection := exactFixedProjection kind row witness
  apply byteMsbOfResidual
  exact
    signResidualBoundOfLookup kind row witness 86 row.isLh
      (bitVecM31 row.result.limb1 -
        boolM31 row.srcMsb * M31.reduce 128)
      selector fixed projection.halfSign

private theorem reduceQuarter (value : Nat) :
    M31.reduce (4 * value) * M31.reduce 536870912 =
      M31.reduce value := by
  rw [Air.Bridge.TeamACommon.reduceMul]
  apply M31.ext
  simp only [M31.reduce_val]
  have expand :
      4 * value * 536870912 =
        value + M31.modulus * value := by
    rw [M31.modulus_eq]
    omega
  rw [expand, Nat.add_mul_mod_self_left]

private theorem alignedQuarterFieldImage (row : LoadStoreRow) :
    alignedQuarterField row = M31.reduce row.alignedQuarter := by
  have selectors :
      row.sourceSelector + row.destinationSelector =
        row.alignedAddress + row.r2Idx.toNat := by
    cases store : row.isStore <;>
      simp [
        LoadStoreRow.sourceSelector,
        LoadStoreRow.destinationSelector, store,
      ] <;>
      omega
  have selectorDifference :
      M31.reduce row.sourceSelector +
          M31.reduce row.destinationSelector -
        bitVecM31 row.r2Idx =
      M31.reduce row.alignedAddress := by
    apply m31SubEqOfEqAdd
    simp only [bitVecM31]
    calc
      M31.reduce row.sourceSelector +
          M31.reduce row.destinationSelector =
          M31.reduce
            (row.sourceSelector + row.destinationSelector) :=
        Air.Bridge.TeamACommon.reduceAdd _ _
      _ = M31.reduce
          (row.alignedAddress + row.r2Idx.toNat) := by
        rw [selectors]
      _ = M31.reduce row.alignedAddress +
          M31.reduce row.r2Idx.toNat :=
        (Air.Bridge.TeamACommon.reduceAdd _ _).symm
  simp only [alignedQuarterField]
  rw [selectorDifference, LoadStoreRow.alignedAddress]
  exact reduceQuarter row.alignedQuarter

private theorem byteFieldValue (value : Byte) :
    (bitVecM31 value).val = value.toNat := by
  exact M31.reduce_val_of_lt value.toNat (byteBound value)

structure FixedConsequences (row : LoadStoreRow) : Prop where
  baseGap :
    (clockGapField row 1 row.rs1PreviousClock).val < 2 ^ 20
  alignedQuarterRange : row.alignedQuarter < 2 ^ 20
  baseHighLimbRange : row.rs1Next.limb3.toNat < 128
  baseLimbsCanonical :
    row.rs1Next.limb0.toNat ≠ 255 ∨
      row.rs1Next.limb3.toNat ≠ 127
  sourceGap : (sourceClockGapField row).val < 2 ^ 20
  destinationGap : (destinationClockGapField row).val < 2 ^ 20

private theorem fixedConsequences
    (kind : Kind)
    (row : LoadStoreRow)
    (witness : Witness row)
    (admission : Admission row)
    (flags : FlagFacts kind row)
    (fixed : (evaluation kind row witness).fixedLookupsHold = true) :
    FixedConsequences row := by
  have projection := exactFixedProjection kind row witness
  have baseBounds :=
    rangeM31BoundsOfLookup kind row witness flags 78
      (bitVecM31 row.rs1Next.limb0)
      (bitVecM31 row.rs1Next.limb3)
      fixed projection.baseRange
  refine {
    baseGap :=
      range20BoundOfLookup kind row witness flags 76 (some 1)
        (clockGapField row 1 row.rs1PreviousClock)
        fixed projection.baseClock
    alignedQuarterRange := ?_
    baseHighLimbRange := ?_
    baseLimbsCanonical := ?_
    sourceGap :=
      range20BoundOfLookup kind row witness flags 81 (some 2)
        (sourceClockGapField row)
        fixed projection.sourceClock
    destinationGap :=
      range20BoundOfLookup kind row witness flags 84 (some 3)
        (destinationClockGapField row)
        fixed projection.destinationClock
  }
  · have range :=
      range20BoundOfLookup kind row witness flags 77 none
        (alignedQuarterField row)
        fixed projection.alignedQuarter
    rw [alignedQuarterFieldImage row,
      M31.reduce_val_of_lt row.alignedQuarter
        admission.alignedQuarterCanonical] at range
    exact range
  · simpa [byteFieldValue] using baseBounds.2.1
  · by_cases low : row.rs1Next.limb0.toNat = 255
    · apply Or.inr
      intro high
      have sumBound := baseBounds.2.2
      rw [byteFieldValue, byteFieldValue, low, high] at sumBound
      omega
    · exact Or.inl low

end RiscvRefinement.Publication.TeamB.LoadStore
