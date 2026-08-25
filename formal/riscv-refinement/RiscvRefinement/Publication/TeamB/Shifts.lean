import RiscvRefinement.Air.Generated.Programs
import RiscvRefinement.Air.Bridge.TeamACommon
import RiscvRefinement.Opcodes.Shifts
import RiscvRefinement.Publication.Acceptance
import RiscvRefinement.Publication.Universal

/-!
# Publication bridge for the six shift instructions

The evaluator in this file is the decoded `LocalProgram` generated from each
committed AIR IR v2 document.  The typed rows are only a convenient column
binding: acceptance is stated in terms of the generated evaluator and the
semantic predicates are conclusions.
-/

namespace RiscvRefinement.Publication.TeamB.Shifts

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

private def kindIs (expected actual : ShiftKind) : Bool :=
  decide (actual = expected)

private def marker (index expected : Nat) : M31 :=
  if index = expected then 1 else 0

private def leftMultiplier (row : ShiftRow) : M31 :=
  if row.kind = .sll then M31.reduce row.multiplier else 0

private def rightMultiplier (row : ShiftRow) : M31 :=
  if row.kind = .sll then 0 else M31.reduce row.multiplier

structure ImmWitness (row : ShiftsImmRow) where
  destinationInverse : M31

structure RegWitness (row : ShiftsRegRow) where
  destinationInverse : M31

/-- Exact 51-column order shared by the three generated `shifts_imm` programs. -/
def immColumns (row : ShiftsImmRow) (witness : ImmWitness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.semantic.rd
  | 3 => bitVecM31 row.semantic.rdPrevious.limb0
  | 4 => bitVecM31 row.semantic.rdPrevious.limb1
  | 5 => bitVecM31 row.semantic.rdPrevious.limb2
  | 6 => bitVecM31 row.semantic.rdPrevious.limb3
  | 7 => M31.reduce row.rdPreviousClock
  | 8 => bitVecM31 row.semantic.rdNext.limb0
  | 9 => bitVecM31 row.semantic.rdNext.limb1
  | 10 => bitVecM31 row.semantic.rdNext.limb2
  | 11 => bitVecM31 row.semantic.rdNext.limb3
  | 12 => bitVecM31 row.rs1
  | 13 => bitVecM31 row.semantic.rs1Previous.limb0
  | 14 => bitVecM31 row.semantic.rs1Previous.limb1
  | 15 => bitVecM31 row.semantic.rs1Previous.limb2
  | 16 => bitVecM31 row.semantic.rs1Previous.limb3
  | 17 => M31.reduce row.rs1PreviousClock
  | 18 => bitVecM31 row.semantic.rs1Next.limb0
  | 19 => bitVecM31 row.semantic.rs1Next.limb1
  | 20 => bitVecM31 row.semantic.rs1Next.limb2
  | 21 => bitVecM31 row.semantic.rs1Next.limb3
  | 22 => boolM31 row.semantic.rs1Sign
  | 23 => M31.reduce row.immTruncated
  | 24 => boolM31 (kindIs .sll row.semantic.kind)
  | 25 => boolM31 (kindIs .srl row.semantic.kind)
  | 26 => boolM31 (kindIs .sra row.semantic.kind)
  | 27 => leftMultiplier row.semantic
  | 28 => rightMultiplier row.semantic
  | 29 => marker row.semantic.bitIndex 0
  | 30 => marker row.semantic.bitIndex 1
  | 31 => marker row.semantic.bitIndex 2
  | 32 => marker row.semantic.bitIndex 3
  | 33 => marker row.semantic.bitIndex 4
  | 34 => marker row.semantic.bitIndex 5
  | 35 => marker row.semantic.bitIndex 6
  | 36 => marker row.semantic.bitIndex 7
  | 37 => marker row.semantic.limbIndex 0
  | 38 => marker row.semantic.limbIndex 1
  | 39 => marker row.semantic.limbIndex 2
  | 40 => marker row.semantic.limbIndex 3
  | 41 => M31.reduce row.semantic.carry0
  | 42 => M31.reduce row.semantic.carry1
  | 43 => M31.reduce row.semantic.carry2
  | 44 => M31.reduce row.semantic.carry3
  | 45 => bitVecM31 row.semantic.result.limb0
  | 46 => bitVecM31 row.semantic.result.limb1
  | 47 => bitVecM31 row.semantic.result.limb2
  | 48 => bitVecM31 row.semantic.result.limb3
  | 49 => boolM31 row.semantic.rdNonzero
  | 50 => witness.destinationInverse
  | _ => 0

/-- Exact 60-column order shared by the three generated `shifts_reg` programs. -/
def regColumns (row : ShiftsRegRow) (witness : RegWitness row) : Nat → M31
  | 0 => M31.reduce row.clock
  | 1 => bitVecM31 row.pc
  | 2 => bitVecM31 row.semantic.rd
  | 3 => bitVecM31 row.semantic.rdPrevious.limb0
  | 4 => bitVecM31 row.semantic.rdPrevious.limb1
  | 5 => bitVecM31 row.semantic.rdPrevious.limb2
  | 6 => bitVecM31 row.semantic.rdPrevious.limb3
  | 7 => M31.reduce row.rdPreviousClock
  | 8 => bitVecM31 row.semantic.rdNext.limb0
  | 9 => bitVecM31 row.semantic.rdNext.limb1
  | 10 => bitVecM31 row.semantic.rdNext.limb2
  | 11 => bitVecM31 row.semantic.rdNext.limb3
  | 12 => bitVecM31 row.rs1
  | 13 => bitVecM31 row.semantic.rs1Previous.limb0
  | 14 => bitVecM31 row.semantic.rs1Previous.limb1
  | 15 => bitVecM31 row.semantic.rs1Previous.limb2
  | 16 => bitVecM31 row.semantic.rs1Previous.limb3
  | 17 => M31.reduce row.rs1PreviousClock
  | 18 => bitVecM31 row.semantic.rs1Next.limb0
  | 19 => bitVecM31 row.semantic.rs1Next.limb1
  | 20 => bitVecM31 row.semantic.rs1Next.limb2
  | 21 => bitVecM31 row.semantic.rs1Next.limb3
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
  | 32 => boolM31 row.semantic.rs1Sign
  | 33 => boolM31 (kindIs .sll row.semantic.kind)
  | 34 => boolM31 (kindIs .srl row.semantic.kind)
  | 35 => boolM31 (kindIs .sra row.semantic.kind)
  | 36 => leftMultiplier row.semantic
  | 37 => rightMultiplier row.semantic
  | 38 => marker row.semantic.bitIndex 0
  | 39 => marker row.semantic.bitIndex 1
  | 40 => marker row.semantic.bitIndex 2
  | 41 => marker row.semantic.bitIndex 3
  | 42 => marker row.semantic.bitIndex 4
  | 43 => marker row.semantic.bitIndex 5
  | 44 => marker row.semantic.bitIndex 6
  | 45 => marker row.semantic.bitIndex 7
  | 46 => marker row.semantic.limbIndex 0
  | 47 => marker row.semantic.limbIndex 1
  | 48 => marker row.semantic.limbIndex 2
  | 49 => marker row.semantic.limbIndex 3
  | 50 => M31.reduce row.semantic.carry0
  | 51 => M31.reduce row.semantic.carry1
  | 52 => M31.reduce row.semantic.carry2
  | 53 => M31.reduce row.semantic.carry3
  | 54 => bitVecM31 row.semantic.result.limb0
  | 55 => bitVecM31 row.semantic.result.limb1
  | 56 => bitVecM31 row.semantic.result.limb2
  | 57 => bitVecM31 row.semantic.result.limb3
  | 58 => boolM31 row.semantic.rdNonzero
  | 59 => witness.destinationInverse
  | _ => 0

def immProgram : ShiftKind → LocalProgram
  | .sll => Programs.slli
  | .srl => Programs.srli
  | .sra => Programs.srai

def regProgram : ShiftKind → LocalProgram
  | .sll => Programs.sll
  | .srl => Programs.srl
  | .sra => Programs.sra

def immEvaluation
    (row : ShiftsImmRow) (witness : ImmWitness row) : SymbolicEvaluation :=
  (immProgram row.semantic.kind).evalSymbolic (immColumns row witness)

def regEvaluation
    (row : ShiftsRegRow) (witness : RegWitness row) : SymbolicEvaluation :=
  (regProgram row.semantic.kind).evalSymbolic (regColumns row witness)

/-- Facts supplied by the frontend profile rather than a single AIR row. -/
structure ImmAdmission (row : ShiftsImmRow) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourcePreviousBound : row.rs1PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcBound : row.pc.toNat + 4 < M31.modulus
  claimedNextPcCanonical : row.claimedNextPc.toNat < M31.modulus
  immediateCanonical : row.immTruncated < M31.modulus
  carry0Canonical : row.semantic.carry0 < M31.modulus
  carry1Canonical : row.semantic.carry1 < M31.modulus
  carry2Canonical : row.semantic.carry2 < M31.modulus
  carry3Canonical : row.semantic.carry3 < M31.modulus

/-- Facts supplied by the frontend profile rather than a single AIR row. -/
structure RegAdmission (row : ShiftsRegRow) : Prop where
  clockPositive : 0 < row.clock
  clockBound : row.clock ≤ 2 ^ 24
  sourcePreviousBound : row.rs1PreviousClock < 2 ^ 26
  secondSourcePreviousBound : row.rs2PreviousClock < 2 ^ 26
  destinationPreviousBound : row.rdPreviousClock < 2 ^ 26
  pcBound : row.pc.toNat + 4 < M31.modulus
  claimedNextPcCanonical : row.claimedNextPc.toNat < M31.modulus
  carry0Canonical : row.semantic.carry0 < M31.modulus
  carry1Canonical : row.semantic.carry1 < M31.modulus
  carry2Canonical : row.semantic.carry2 < M31.modulus
  carry3Canonical : row.semantic.carry3 < M31.modulus

/--
The only extra frontend binding not already represented by a typed AIR column
is the architectural `claimedNextPc`.  It is tied to the exact generated
projection node, not assumed equal to the semantic `nextPc`.
-/
structure ImmBindings
    (row : ShiftsImmRow) (witness : ImmWitness row) : Prop where
  nextPcProjection :
    bitVecM31 row.claimedNextPc =
      (immEvaluation row witness).nodes.getSymbolic 329

structure RegBindings
    (row : ShiftsRegRow) (witness : RegWitness row) : Prop where
  nextPcProjection :
    bitVecM31 row.claimedNextPc =
      (regEvaluation row witness).nodes.getSymbolic 346

abbrev ImmAcceptance
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  RiscvRefinement.Publication.AcceptedProductionEvaluation
    (immEvaluation row witness) relationHolds

abbrev RegAcceptance
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop) : Prop :=
  RiscvRefinement.Publication.AcceptedProductionEvaluation
    (regEvaluation row witness) relationHolds

/-! The reverse evaluator lemmas and publication wrappers follow below. -/

def immConstraintRoots : Array Nat :=
  #[122, 124, 126, 128, 130, 132, 134, 136, 138, 140, 142, 144, 146,
    148, 150, 152, 154, 156, 157, 158, 160, 162, 170, 177, 184, 191,
    193, 198, 203, 208, 210, 211, 216, 221, 223, 224, 225, 230, 238,
    246, 254, 263, 265, 267, 269, 274, 276, 278, 281, 282, 284, 287,
    288, 289, 291, 293, 295, 297, 299, 301, 303, 305, 307, 309, 311,
    312, 121]

def regConstraintRoots : Array Nat :=
  #[131, 133, 135, 137, 139, 141, 143, 145, 147, 149, 151, 153, 155,
    157, 159, 161, 163, 165, 166, 167, 169, 171, 179, 186, 193, 200,
    202, 207, 212, 217, 219, 220, 225, 230, 232, 233, 234, 239, 247,
    255, 263, 272, 274, 276, 278, 283, 285, 287, 290, 291, 293, 296,
    297, 298, 300, 302, 304, 306, 308, 310, 312, 314, 316, 318, 320,
    322, 324, 326, 328, 130]

set_option maxHeartbeats 800000 in
set_option maxRecDepth 30000 in
private theorem immConstraintsHoldEvents
    (kind : ShiftKind)
    (nodes : LocalValues) :
    ((immProgram kind).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      immConstraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  cases kind
  · simpa [immProgram, Programs.slli, Programs.slliSource, immConstraintRoots,
      Event.evalSymbolic]
  · simpa [immProgram, Programs.srli, Programs.srliSource, immConstraintRoots,
      Event.evalSymbolic]
  · simpa [immProgram, Programs.srai, Programs.sraiSource, immConstraintRoots,
      Event.evalSymbolic]

set_option maxHeartbeats 800000 in
set_option maxRecDepth 30000 in
private theorem regConstraintsHoldEvents
    (kind : ShiftKind)
    (nodes : LocalValues) :
    ((regProgram kind).source.events.map (Event.evalSymbolic nodes)).all
        (fun
          | .constraint event => event.value == 0
          | .lookup _ => true) =
      regConstraintRoots.all (fun root => nodes.getSymbolic root == 0) := by
  cases kind
  · simpa [regProgram, Programs.sll, Programs.sllSource, regConstraintRoots,
      Event.evalSymbolic]
  · simpa [regProgram, Programs.srl, Programs.srlSource, regConstraintRoots,
      Event.evalSymbolic]
  · simpa [regProgram, Programs.sra, Programs.sraSource, regConstraintRoots,
      Event.evalSymbolic]

theorem immConstraintsHold_eq
    (row : ShiftsImmRow)
    (witness : ImmWitness row) :
    (immEvaluation row witness).constraintsHold =
      immConstraintRoots.all
        (fun root =>
          (immEvaluation row witness).nodes.getSymbolic root == 0) :=
  immConstraintsHoldEvents row.semantic.kind
    (immEvaluation row witness).nodes

theorem regConstraintsHold_eq
    (row : ShiftsRegRow)
    (witness : RegWitness row) :
    (regEvaluation row witness).constraintsHold =
      regConstraintRoots.all
        (fun root =>
          (regEvaluation row witness).nodes.getSymbolic root == 0) :=
  regConstraintsHoldEvents row.semantic.kind
    (regEvaluation row witness).nodes

theorem immConstraintRootZero
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (accepted : (immEvaluation row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ immConstraintRoots) :
    (immEvaluation row witness).nodes.getSymbolic root = 0 := by
  rw [immConstraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

theorem regConstraintRootZero
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (accepted : (regEvaluation row witness).constraintsHold = true)
    (root : Nat)
    (member : root ∈ regConstraintRoots) :
    (regEvaluation row witness).nodes.getSymbolic root = 0 := by
  rw [regConstraintsHold_eq, Array.all_eq_true] at accepted
  obtain ⟨index, bound, value⟩ := Array.mem_iff_getElem.mp member
  have selected := accepted index bound
  rw [value] at selected
  simpa only [beq_iff_eq] using selected

private theorem byteBound (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

private theorem byteNatBound (value : Byte) :
    value.toNat < 256 := by
  simpa only [Nat.reducePow] using value.isLt

private theorem byteEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

private theorem byteNatZero
    (value : Byte)
    (equation : bitVecM31 value = 0) :
    value.toNat = 0 := by
  have values := congrArg M31.val equation
  rw [show (bitVecM31 value).val = value.toNat by
    exact M31.reduce_val_of_lt _ (byteBound value)] at values
  exact values

private theorem byteNatSignFill
    (value : Byte)
    (sign : Bool)
    (equation :
      bitVecM31 value - boolM31 sign * M31.reduce 255 = 0) :
    value.toNat = 255 * (if sign then 1 else 0) := by
  have field :=
    (M31.sub_eq_zero_iff _ _).mp equation
  cases sign
  · have zero : bitVecM31 value = 0 := by
      simpa [boolM31] using field
    simpa using byteNatZero value zero
  · have valueField :
        bitVecM31 value = M31.reduce 255 := by
      simpa [boolM31] using field
    have image := congrArg M31.val valueField
    rw [
      show (bitVecM31 value).val = value.toNat by
        exact M31.reduce_val_of_lt _ (byteBound value),
      M31.reduce_val_of_lt 255 (by decide),
    ] at image
    simpa using image

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem immSourceLimb0
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.rs1Next.limb0 = row.semantic.rs1Previous.limb0 := by
  have root :=
    immConstraintRootZero row witness direct 305
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    apply byteEq
    apply (M31.sub_eq_zero_iff _ _).mp
    simpa [
      immEvaluation, immProgram, kind,
      Programs.slli, Programs.srli, Programs.srai,
      Programs.slliSource, Programs.srliSource, Programs.sraiSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, immColumns,
      kindIs, boolM31,
    ] using root

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem immSourceReadOnly
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.rs1Next = row.semantic.rs1Previous := by
  apply WordBytes.eq_of_limbs
  · exact immSourceLimb0 row witness direct
  all_goals
    apply byteEq
    apply (M31.sub_eq_zero_iff _ _).mp
  · have root :=
      immConstraintRootZero row witness direct 307
        (by simp [immConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      immConstraintRootZero row witness direct 309
        (by simp [immConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      immConstraintRootZero row witness direct 311
        (by simp [immConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using root

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem regSourceReadOnly
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.semantic.rs1Next = row.semantic.rs1Previous := by
  apply WordBytes.eq_of_limbs <;> apply byteEq <;>
    apply (M31.sub_eq_zero_iff _ _).mp
  · have root :=
      regConstraintRootZero row witness direct 314
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 316
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 318
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 320
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem regSecondSourceReadOnly
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.rs2Next = row.rs2Previous := by
  apply WordBytes.eq_of_limbs <;> apply byteEq <;>
    apply (M31.sub_eq_zero_iff _ _).mp
  · have root :=
      regConstraintRootZero row witness direct 322
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 324
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 326
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root
  · have root :=
      regConstraintRootZero row witness direct 328
        (by simp [regConstraintRoots])
    cases kind : row.semantic.kind <;>
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using root

structure DestinationConsequences (row : ShiftRow) : Prop where
  flag : row.rdNonzero = decide (row.rd ≠ zeroRegister)
  bytes : row.rdNext = if row.rdNonzero then row.result else WordBytes.zero

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem immDestinationConsequences
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    DestinationConsequences row.semantic := by
  have zeroRoot :=
    immConstraintRootZero row witness direct 293
      (by simp [immConstraintRoots])
  have inverseRoot :=
    immConstraintRootZero row witness direct 295
      (by simp [immConstraintRoots])
  have limb0 :=
    immConstraintRootZero row witness direct 297
      (by simp [immConstraintRoots])
  have limb1 :=
    immConstraintRootZero row witness direct 299
      (by simp [immConstraintRoots])
  have limb2 :=
    immConstraintRootZero row witness direct 301
      (by simp [immConstraintRoots])
  have limb3 :=
    immConstraintRootZero row witness direct 303
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have zeroEquation :
        bitVecM31 row.semantic.rd *
            (1 - boolM31 row.semantic.rdNonzero) = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using zeroRoot
    have inverseEquation :
        bitVecM31 row.semantic.rd * witness.destinationInverse -
            boolM31 row.semantic.rdNonzero = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using inverseRoot
    have e0 :
        bitVecM31 row.semantic.rdNext.limb0 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb0 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb0
    have e1 :
        bitVecM31 row.semantic.rdNext.limb1 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb1 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb1
    have e2 :
        bitVecM31 row.semantic.rdNext.limb2 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb2 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb2
    have e3 :
        bitVecM31 row.semantic.rdNext.limb3 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb3 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limb3
    exact {
      flag :=
        Air.Bridge.TeamACommon.destinationFlag_of_equations
          row.semantic.rd row.semantic.rdNonzero witness.destinationInverse
          zeroEquation inverseEquation
      bytes :=
        Air.Bridge.TeamACommon.destinationBytes_of_equations
          row.semantic.rdNext row.semantic.result row.semantic.rdNonzero
          e0 e1 e2 e3
    }

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem regDestinationConsequences
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    DestinationConsequences row.semantic := by
  have zeroRoot :=
    regConstraintRootZero row witness direct 302
      (by simp [regConstraintRoots])
  have inverseRoot :=
    regConstraintRootZero row witness direct 304
      (by simp [regConstraintRoots])
  have limb0 :=
    regConstraintRootZero row witness direct 306
      (by simp [regConstraintRoots])
  have limb1 :=
    regConstraintRootZero row witness direct 308
      (by simp [regConstraintRoots])
  have limb2 :=
    regConstraintRootZero row witness direct 310
      (by simp [regConstraintRoots])
  have limb3 :=
    regConstraintRootZero row witness direct 312
      (by simp [regConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have zeroEquation :
        bitVecM31 row.semantic.rd *
            (1 - boolM31 row.semantic.rdNonzero) = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using zeroRoot
    have inverseEquation :
        bitVecM31 row.semantic.rd * witness.destinationInverse -
            boolM31 row.semantic.rdNonzero = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using inverseRoot
    have e0 :
        bitVecM31 row.semantic.rdNext.limb0 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb0 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb0
    have e1 :
        bitVecM31 row.semantic.rdNext.limb1 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb1 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb1
    have e2 :
        bitVecM31 row.semantic.rdNext.limb2 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb2 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb2
    have e3 :
        bitVecM31 row.semantic.rdNext.limb3 -
            boolM31 row.semantic.rdNonzero *
              bitVecM31 row.semantic.result.limb3 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limb3
    exact {
      flag :=
        Air.Bridge.TeamACommon.destinationFlag_of_equations
          row.semantic.rd row.semantic.rdNonzero witness.destinationInverse
          zeroEquation inverseEquation
      bytes :=
        Air.Bridge.TeamACommon.destinationBytes_of_equations
          row.semantic.rdNext row.semantic.result row.semantic.rdNonzero
          e0 e1 e2 e3
    }

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem immIndexRanges
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4 := by
  have bitRoot :=
    immConstraintRootZero row witness direct 157
      (by simp [immConstraintRoots])
  have limbRoot :=
    immConstraintRootZero row witness direct 158
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have bitEquation :
        marker row.semantic.bitIndex 0 +
            marker row.semantic.bitIndex 1 +
            marker row.semantic.bitIndex 2 +
            marker row.semantic.bitIndex 3 +
            marker row.semantic.bitIndex 4 +
            marker row.semantic.bitIndex 5 +
            marker row.semantic.bitIndex 6 +
            marker row.semantic.bitIndex 7 -
          1 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using bitRoot
    have limbEquation :
        marker row.semantic.limbIndex 0 +
            marker row.semantic.limbIndex 1 +
            marker row.semantic.limbIndex 2 +
            marker row.semantic.limbIndex 3 -
          1 = 0 := by
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31,
      ] using limbRoot
    constructor
    · by_cases inside : row.semantic.bitIndex < 8
      · exact inside
      · exfalso
        have h0 : row.semantic.bitIndex ≠ 0 := by omega
        have h1 : row.semantic.bitIndex ≠ 1 := by omega
        have h2 : row.semantic.bitIndex ≠ 2 := by omega
        have h3 : row.semantic.bitIndex ≠ 3 := by omega
        have h4 : row.semantic.bitIndex ≠ 4 := by omega
        have h5 : row.semantic.bitIndex ≠ 5 := by omega
        have h6 : row.semantic.bitIndex ≠ 6 := by omega
        have h7 : row.semantic.bitIndex ≠ 7 := by omega
        simp [marker, h0, h1, h2, h3, h4, h5, h6, h7] at bitEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) bitEquation
    · by_cases inside : row.semantic.limbIndex < 4
      · exact inside
      · exfalso
        have h0 : row.semantic.limbIndex ≠ 0 := by omega
        have h1 : row.semantic.limbIndex ≠ 1 := by omega
        have h2 : row.semantic.limbIndex ≠ 2 := by omega
        have h3 : row.semantic.limbIndex ≠ 3 := by omega
        simp [marker, h0, h1, h2, h3] at limbEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) limbEquation

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem regIndexRanges
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4 := by
  have bitRoot :=
    regConstraintRootZero row witness direct 166
      (by simp [regConstraintRoots])
  have limbRoot :=
    regConstraintRootZero row witness direct 167
      (by simp [regConstraintRoots])
  cases kind : row.semantic.kind
  all_goals
    have bitEquation :
        marker row.semantic.bitIndex 0 +
            marker row.semantic.bitIndex 1 +
            marker row.semantic.bitIndex 2 +
            marker row.semantic.bitIndex 3 +
            marker row.semantic.bitIndex 4 +
            marker row.semantic.bitIndex 5 +
            marker row.semantic.bitIndex 6 +
            marker row.semantic.bitIndex 7 -
          1 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using bitRoot
    have limbEquation :
        marker row.semantic.limbIndex 0 +
            marker row.semantic.limbIndex 1 +
            marker row.semantic.limbIndex 2 +
            marker row.semantic.limbIndex 3 -
          1 = 0 := by
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.srl, Programs.sra,
        Programs.sllSource, Programs.srlSource, Programs.sraSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31,
      ] using limbRoot
    constructor
    · by_cases inside : row.semantic.bitIndex < 8
      · exact inside
      · exfalso
        have h0 : row.semantic.bitIndex ≠ 0 := by omega
        have h1 : row.semantic.bitIndex ≠ 1 := by omega
        have h2 : row.semantic.bitIndex ≠ 2 := by omega
        have h3 : row.semantic.bitIndex ≠ 3 := by omega
        have h4 : row.semantic.bitIndex ≠ 4 := by omega
        have h5 : row.semantic.bitIndex ≠ 5 := by omega
        have h6 : row.semantic.bitIndex ≠ 6 := by omega
        have h7 : row.semantic.bitIndex ≠ 7 := by omega
        simp [marker, h0, h1, h2, h3, h4, h5, h6, h7] at bitEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) bitEquation
    · by_cases inside : row.semantic.limbIndex < 4
      · exact inside
      · exfalso
        have h0 : row.semantic.limbIndex ≠ 0 := by omega
        have h1 : row.semantic.limbIndex ≠ 1 := by omega
        have h2 : row.semantic.limbIndex ≠ 2 := by omega
        have h3 : row.semantic.limbIndex ≠ 3 := by omega
        simp [marker, h0, h1, h2, h3] at limbEquation
        exact (by decide : (0 : M31) - 1 ≠ 0) limbEquation

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem immSignIsLogicalZero
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.semantic.kind ≠ ShiftKind.sra → row.semantic.rs1Sign = false := by
  have root :=
    immConstraintRootZero row witness direct 132
      (by simp [immConstraintRoots])
  cases kind : row.semantic.kind
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          immEvaluation, immProgram, kind, sign,
          Programs.slli, Programs.srli, Programs.srai,
          Programs.slliSource, Programs.srliSource, Programs.sraiSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          immEvaluation, immProgram, kind, sign,
          Programs.slli, Programs.srli, Programs.srai,
          Programs.slliSource, Programs.srliSource, Programs.sraiSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro notSra
    exact False.elim (notSra rfl)

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem regSignIsLogicalZero
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true) :
    row.semantic.kind ≠ ShiftKind.sra → row.semantic.rs1Sign = false := by
  have root :=
    regConstraintRootZero row witness direct 141
      (by simp [regConstraintRoots])
  cases kind : row.semantic.kind
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          regEvaluation, regProgram, kind, sign,
          Programs.sll, Programs.srl, Programs.sra,
          Programs.sllSource, Programs.srlSource, Programs.sraSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro _
    cases sign : row.semantic.rs1Sign
    · rfl
    · exfalso
      have impossible : (1 : M31) = 0 := by
        simpa [
          regEvaluation, regProgram, kind, sign,
          Programs.sll, Programs.srl, Programs.sra,
          Programs.sllSource, Programs.srlSource, Programs.sraSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31,
        ] using root
      exact (by decide : (1 : M31) ≠ 0) impossible
  · intro notSra
    exact False.elim (notSra rfl)

private theorem bitIndexCases {index : Nat} (bound : index < 8) :
    index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 ∨
      index = 4 ∨ index = 5 ∨ index = 6 ∨ index = 7 := by
  omega

private theorem limbIndexCases {index : Nat} (bound : index < 4) :
    index = 0 ∨ index = 1 ∨ index = 2 ∨ index = 3 := by
  omega

private theorem bitMarkerMultiplier
    (index : Nat)
    (bound : index < 8) :
    marker index 0 +
          marker index 1 * M31.reduce 2 +
          marker index 2 * M31.reduce 4 +
          marker index 3 * M31.reduce 8 +
          marker index 4 * M31.reduce 16 +
          marker index 5 * M31.reduce 32 +
          marker index 6 * M31.reduce 64 +
          marker index 7 * M31.reduce 128 =
      M31.reduce (2 ^ index) := by
  rcases bitIndexCases bound with h | h | h | h | h | h | h | h <;>
    subst index <;> decide

private theorem bitMarkerIndex
    (index : Nat)
    (bound : index < 8) :
    marker index 0 * M31.reduce 0 +
          marker index 1 * M31.reduce 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 +
          marker index 4 * M31.reduce 4 +
          marker index 5 * M31.reduce 5 +
          marker index 6 * M31.reduce 6 +
          marker index 7 * M31.reduce 7 =
      M31.reduce index := by
  rcases bitIndexCases bound with h | h | h | h | h | h | h | h <;>
    subst index <;> decide

private theorem limbMarkerIndex
    (index : Nat)
    (bound : index < 4) :
    marker index 0 * M31.reduce 0 +
          marker index 1 * M31.reduce 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 =
      M31.reduce index := by
  rcases limbIndexCases bound with h | h | h | h <;>
    subst index <;> decide

private theorem bitMarkerIndex'
    (index : Nat)
    (bound : index < 8) :
    marker index 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 +
          marker index 4 * M31.reduce 4 +
          marker index 5 * M31.reduce 5 +
          marker index 6 * M31.reduce 6 +
          marker index 7 * M31.reduce 7 =
      M31.reduce index := by
  simpa using bitMarkerIndex index bound

private theorem limbMarkerIndex'
    (index : Nat)
    (bound : index < 4) :
    marker index 1 +
          marker index 2 * M31.reduce 2 +
          marker index 3 * M31.reduce 3 =
      M31.reduce index := by
  simpa using limbMarkerIndex index bound

set_option maxRecDepth 20000 in
set_option maxHeartbeats 0 in
private theorem immImmediateBinds
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (admission : ImmAdmission row)
    (direct : (immEvaluation row witness).constraintsHold = true) :
    row.immTruncated = row.semantic.shiftAmount := by
  have ranges := immIndexRanges row witness direct
  have root :=
    immConstraintRootZero row witness direct 312
      (by simp [immConstraintRoots])
  have fieldEquation :
      M31.reduce row.immTruncated -
          M31.reduce row.semantic.shiftAmount = 0 := by
    cases kind : row.semantic.kind
    all_goals
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.srli, Programs.srai,
        Programs.slliSource, Programs.srliSource, Programs.sraiSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, ShiftRow.shiftAmount,
        limbMarkerIndex' row.semantic.limbIndex ranges.2,
        bitMarkerIndex' row.semantic.bitIndex ranges.1,
        Air.Bridge.TeamACommon.reduceMul,
        Air.Bridge.TeamACommon.reduceAdd,
        Nat.mul_comm,
      ] using root
  apply
    (M31.reduce_injective_of_lt
      admission.immediateCanonical
      (by
        have h := ranges
        simp only [ShiftRow.shiftAmount]
        simp [M31.modulus_eq]
        omega)).mp
  exact (M31.sub_eq_zero_iff _ _).mp fieldEquation

private def accessClockField (clock ordinal : Nat) : M31 :=
  (M31.reduce clock - 1) * M31.reduce 4 + M31.reduce ordinal

private def clockGapField (clock ordinal previous : Nat) : M31 :=
  accessClockField clock ordinal - M31.reduce previous - 1

private def clockLookup
    (eventOrdinal accessOrdinal clock previous : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[clockGapField clock accessOrdinal previous]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := some accessOrdinal

private def carryLookup
    (eventOrdinal carry multiplier : Nat) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheck88
  numerator := -(1 : M31)
  tuple := #[
    M31.reduce carry,
    M31.reduce multiplier - 1 - M31.reduce carry
  ]
  role := .request
  tableId := some .rangeCheck88
  accessOrdinal := none

private def signLookup
    (eventOrdinal : Nat) (row : ShiftRow) : EvaluatedLookup where
  ordinal := eventOrdinal
  domain := .rangeCheckM31
  numerator := -(boolM31 (kindIs .sra row.kind))
  tuple := #[
    0,
    bitVecM31 row.rs1Next.limb3 -
      boolM31 row.rs1Sign * M31.reduce 128
  ]
  role := .request
  tableId := some .rangeCheckM31
  accessOrdinal := none

private def amountMaskLookup
    (row : ShiftsRegRow) : EvaluatedLookup where
  ordinal := 79
  domain := .rangeCheck20
  numerator := -(1 : M31)
  tuple := #[
    M31.reduce 7 -
      (bitVecM31 row.rs2Next.limb0 -
          M31.reduce row.semantic.shiftAmount) *
        M31.reduce 67108864
  ]
  role := .request
  tableId := some .rangeCheck20
  accessOrdinal := none

private theorem negOneLive :
    ((-(1 : M31)) != 0) = true := by
  decide

private theorem rangeCheck88RequestHolds_iff
    (ordinal : Nat)
    (low high : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal
      domain := .rangeCheck88
      numerator := -(1 : M31)
      tuple := #[low, high]
      role := .request
      tableId := some .rangeCheck88
      accessOrdinal := none
    }) = true ↔ low.val < 256 ∧ high.val < 256 := by
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

private theorem rangeCheckM31RequestHolds_iff
    (ordinal : Nat)
    (low high : M31) :
    (EvaluatedLookup.fixedRequestHolds {
      ordinal
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

structure ImmExactFixedProjection
    (row : ShiftsImmRow) (witness : ImmWitness row) : Prop where
  sourceClock :
    (immEvaluation row witness).lookup? 72 =
      some (clockLookup 72 1 row.clock row.rs1PreviousClock)
  carry0 :
    (immEvaluation row witness).lookup? 73 =
      some (carryLookup 73 row.semantic.carry0 row.semantic.multiplier)
  carry1 :
    (immEvaluation row witness).lookup? 74 =
      some (carryLookup 74 row.semantic.carry1 row.semantic.multiplier)
  carry2 :
    (immEvaluation row witness).lookup? 75 =
      some (carryLookup 75 row.semantic.carry2 row.semantic.multiplier)
  carry3 :
    (immEvaluation row witness).lookup? 76 =
      some (carryLookup 76 row.semantic.carry3 row.semantic.multiplier)
  destinationClock :
    (immEvaluation row witness).lookup? 81 =
      some (clockLookup 81 2 row.clock row.rdPreviousClock)
  sign :
    (immEvaluation row witness).lookup? 82 =
      some (signLookup 82 row.semantic)

structure RegExactFixedProjection
    (row : ShiftsRegRow) (witness : RegWitness row) : Prop where
  sourceClock :
    (regEvaluation row witness).lookup? 75 =
      some (clockLookup 75 1 row.clock row.rs1PreviousClock)
  secondSourceClock :
    (regEvaluation row witness).lookup? 78 =
      some (clockLookup 78 2 row.clock row.rs2PreviousClock)
  amountMask :
    (regEvaluation row witness).lookup? 79 =
      some (amountMaskLookup row)
  carry0 :
    (regEvaluation row witness).lookup? 80 =
      some (carryLookup 80 row.semantic.carry0 row.semantic.multiplier)
  carry1 :
    (regEvaluation row witness).lookup? 81 =
      some (carryLookup 81 row.semantic.carry1 row.semantic.multiplier)
  carry2 :
    (regEvaluation row witness).lookup? 82 =
      some (carryLookup 82 row.semantic.carry2 row.semantic.multiplier)
  carry3 :
    (regEvaluation row witness).lookup? 83 =
      some (carryLookup 83 row.semantic.carry3 row.semantic.multiplier)
  destinationClock :
    (regEvaluation row witness).lookup? 88 =
      some (clockLookup 88 3 row.clock row.rdPreviousClock)
  sign :
    (regEvaluation row witness).lookup? 89 =
      some (signLookup 89 row.semantic)

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem imm_exactFixedProjection
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (bitRange : row.semantic.bitIndex < 8) :
    ImmExactFixedProjection row witness := by
  refine {
    sourceClock := ?_
    carry0 := ?_
    carry1 := ?_
    carry2 := ?_
    carry3 := ?_
    destinationClock := ?_
    sign := ?_
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
    bitMarkerMultiplier row.semantic.bitIndex bitRange,
    ShiftRow.multiplier,
    leftMultiplier, rightMultiplier,
    clockLookup, carryLookup, signLookup, clockGapField, accessClockField,
  ]

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
theorem reg_exactFixedProjection
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (bitRange : row.semantic.bitIndex < 8)
    (limbRange : row.semantic.limbIndex < 4) :
    RegExactFixedProjection row witness := by
  refine {
    sourceClock := ?_
    secondSourceClock := ?_
    amountMask := ?_
    carry0 := ?_
    carry1 := ?_
    carry2 := ?_
    carry3 := ?_
    destinationClock := ?_
    sign := ?_
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
    bitMarkerMultiplier row.semantic.bitIndex bitRange,
    bitMarkerIndex' row.semantic.bitIndex bitRange,
    limbMarkerIndex' row.semantic.limbIndex limbRange,
    ShiftRow.shiftAmount,
    ShiftRow.multiplier,
    Air.Bridge.TeamACommon.reduceMul,
    Air.Bridge.TeamACommon.reduceAdd,
    Nat.mul_comm,
    leftMultiplier, rightMultiplier,
    clockLookup, carryLookup, signLookup, amountMaskLookup,
    clockGapField, accessClockField,
  ]

private theorem clockGapBoundOfLookup
    (evaluation : SymbolicEvaluation)
    (eventOrdinal accessOrdinal clock previous : Nat)
    (fixed : evaluation.fixedLookupsHold = true)
    (selected :
      evaluation.lookup? eventOrdinal =
        some (clockLookup eventOrdinal accessOrdinal clock previous)) :
    (clockGapField clock accessOrdinal previous).val < 2 ^ 20 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      evaluation eventOrdinal
      (clockLookup eventOrdinal accessOrdinal clock previous) fixed selected
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      eventOrdinal (some accessOrdinal)
      (clockGapField clock accessOrdinal previous)).mp
      (by simpa [clockLookup] using request)

private theorem amountMaskBoundOfLookup
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (fixed : (regEvaluation row witness).fixedLookupsHold = true)
    (selected :
      (regEvaluation row witness).lookup? 79 =
        some (amountMaskLookup row)) :
    (M31.reduce 7 -
        (bitVecM31 row.rs2Next.limb0 -
            M31.reduce row.semantic.shiftAmount) *
          M31.reduce 67108864).val < 2 ^ 20 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      (regEvaluation row witness) 79 (amountMaskLookup row)
      fixed selected
  exact
    (Air.Bridge.TeamACommon.rangeCheck20RequestHolds_iff
      79 none
      (M31.reduce 7 -
        (bitVecM31 row.rs2Next.limb0 -
            M31.reduce row.semantic.shiftAmount) *
          M31.reduce 67108864)).mp
      (by simpa [amountMaskLookup] using request)

/-!
`rs2_next_0` is a byte and the normalized shift amount is five bits.  This
finite theorem checks the exact production inverse-of-32 encoding, including
the field wrap, rather than replacing it with an integer division axiom.
-/
set_option maxRecDepth 100000 in
set_option maxHeartbeats 0 in
private theorem amountMaskUnique :
    ∀ (byte : Byte) (shift : Fin 32),
      (M31.reduce 7 -
          (bitVecM31 byte - M31.reduce shift.val) *
            M31.reduce 67108864).val < 2 ^ 20 →
        ∃ high : Fin 8,
          byte.toNat = 32 * high.val + shift.val := by
  decide

private theorem carryBoundsOfLookup
    (evaluation : SymbolicEvaluation)
    (ordinal carry multiplier : Nat)
    (fixed : evaluation.fixedLookupsHold = true)
    (selected :
      evaluation.lookup? ordinal =
        some (carryLookup ordinal carry multiplier)) :
    (M31.reduce carry).val < 256 ∧
      (M31.reduce multiplier - 1 - M31.reduce carry).val < 256 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      evaluation ordinal (carryLookup ordinal carry multiplier)
      fixed selected
  exact
    (rangeCheck88RequestHolds_iff ordinal
      (M31.reduce carry)
      (M31.reduce multiplier - 1 - M31.reduce carry)).mp
      (by simpa [carryLookup] using request)

private theorem carryLtMultiplier
    (carry multiplier : Nat)
    (carryCanonical : carry < M31.modulus)
    (multiplierPositive : 0 < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (bounds :
      (M31.reduce carry).val < 256 ∧
        (M31.reduce multiplier - 1 - M31.reduce carry).val < 256) :
    carry < multiplier := by
  have carryImage :
      (M31.reduce carry).val = carry :=
    M31.reduce_val_of_lt carry carryCanonical
  have multiplierCanonical : multiplier < M31.modulus := by
    rw [M31.modulus_eq]
    omega
  have multiplierImage :
      (M31.reduce multiplier).val = multiplier :=
    M31.reduce_val_of_lt multiplier multiplierCanonical
  have predecessorImage :
      (M31.reduce multiplier - 1).val = multiplier - 1 := by
    have ordered :
        (1 : M31).val ≤ (M31.reduce multiplier).val := by
      rw [multiplierImage]
      change 1 ≤ multiplier
      omega
    rw [M31.sub_val_of_le _ _ ordered, multiplierImage]
    change multiplier - 1 = multiplier - 1
    rfl
  have carryByte : carry < 256 := by
    rw [carryImage] at bounds
    exact bounds.1
  by_cases desired : carry < multiplier
  · exact desired
  · have wrapped :=
      M31.sub_val_of_lt
        (M31.reduce multiplier - 1) (M31.reduce carry)
        (by rw [predecessorImage, carryImage]; omega)
    rw [predecessorImage, carryImage] at wrapped
    rw [wrapped] at bounds
    simp [M31.modulus_eq] at bounds
    omega

private theorem signBoundsOfLookup
    (evaluation : SymbolicEvaluation)
    (ordinal : Nat)
    (row : ShiftRow)
    (kind : row.kind = .sra)
    (fixed : evaluation.fixedLookupsHold = true)
    (selected :
      evaluation.lookup? ordinal = some (signLookup ordinal row)) :
    128 * row.signNat ≤ row.rs1Next.limb3.toNat ∧
      row.rs1Next.limb3.toNat < 128 * row.signNat + 128 := by
  have request :=
    SymbolicEvaluation.fixedRequestHolds_of_lookup
      evaluation ordinal (signLookup ordinal row) fixed selected
  have residueBound :
      (bitVecM31 row.rs1Next.limb3 -
          boolM31 row.rs1Sign * M31.reduce 128).val < 128 := by
    have normalized :
        EvaluatedLookup.fixedRequestHolds {
          ordinal
          domain := .rangeCheckM31
          numerator := -(1 : M31)
          tuple := #[
            0,
            bitVecM31 row.rs1Next.limb3 -
              boolM31 row.rs1Sign * M31.reduce 128
          ]
          role := .request
          tableId := some .rangeCheckM31
          accessOrdinal := none
        } = true := by
      simpa [signLookup, kind, kindIs, boolM31] using request
    have bounds :=
      (rangeCheckM31RequestHolds_iff ordinal 0
        (bitVecM31 row.rs1Next.limb3 -
          boolM31 row.rs1Sign * M31.reduce 128)).mp normalized
    exact bounds.2.1
  have byteImage :
      (bitVecM31 row.rs1Next.limb3).val =
        row.rs1Next.limb3.toNat := by
    exact M31.reduce_val_of_lt _ (byteBound row.rs1Next.limb3)
  cases sign : row.rs1Sign
  · simp only [ShiftRow.signNat, sign, ↓reduceIte, Nat.zero_mul,
      Nat.zero_add]
    have upper := residueBound
    simpa [sign, boolM31, byteImage] using upper
  · simp only [ShiftRow.signNat, sign, ↓reduceIte, Nat.one_mul]
    rw [sign] at residueBound
    simp only [boolM31, M31.one_mul] at residueBound
    have highAtLeast : 128 ≤ row.rs1Next.limb3.toNat := by
      by_cases below : row.rs1Next.limb3.toNat < 128
      · have wrapped :=
          M31.sub_val_of_lt
            (bitVecM31 row.rs1Next.limb3) (M31.reduce 128)
            (by
              rw [byteImage,
                M31.reduce_val_of_lt 128 (by decide)]
              exact below)
        rw [wrapped, byteImage,
          M31.reduce_val_of_lt 128 (by decide)] at residueBound
        simp [M31.modulus_eq] at residueBound
        omega
      · omega
    constructor
    · exact highAtLeast
    · have := row.rs1Next.limb3.isLt
      simp only [Nat.reducePow] at this
      omega

private theorem validClockOfGap
    (clock ordinal previous : Nat)
    (clockPositive : 0 < clock)
    (clockBound : clock ≤ 2 ^ 24)
    (ordinalPositive : 0 < ordinal)
    (ordinalBound : ordinal ≤ 3)
    (previousBound : previous < 2 ^ 26)
    (gapBound : (clockGapField clock ordinal previous).val < 2 ^ 20) :
    validPreviousClock previous (accessClock clock ordinal) := by
  have currentBound : accessClock clock ordinal < 2 ^ 26 := by
    simp only [accessClock]
    omega
  have currentPositive : 0 < accessClock clock ordinal := by
    simp only [accessClock]
    omega
  have accessImage :
      (accessClockField clock ordinal).val = accessClock clock ordinal := by
    simpa [accessClockField,
      Air.Bridge.TeamACommon.accessClockField] using
      Air.Bridge.TeamACommon.accessClockField_val
        clock ordinal clockPositive clockBound (by omega)
  have accessEquality :
      accessClockField clock ordinal =
        M31.reduce (accessClock clock ordinal) := by
    apply M31.ext
    rw [accessImage,
      M31.reduce_val_of_lt _ (by
        rw [M31.modulus_eq]
        omega)]
  apply Air.Bridge.TeamACommon.validPreviousClock_of_gap
    previous (accessClock clock ordinal) currentPositive currentBound
    previousBound
  simpa [clockGapField, accessEquality] using gapBound

private theorem multiplierLe128
    (row : ShiftRow)
    (bitRange : row.bitIndex < 8) :
    row.multiplier ≤ 128 := by
  simp only [ShiftRow.multiplier]
  have := Nat.pow_le_pow_right (by omega : 0 < (2 : Nat))
    (show row.bitIndex ≤ 7 by omega)
  simpa using this

/-!
The movement roots are field equations.  These small cancellation lemmas keep
the reverse bridge honest about subtraction wrap: no natural-number
subtraction is substituted for field subtraction until both sides have been
rearranged into non-negative, canonically bounded sums.
-/

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
        right.val + offset.val = M31.modulus + left.val := by
      omega
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
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceAdd,
  ]
  congr 1
  omega

private theorem leftContinuationRearrange
    (result previousCarry shiftedCarry scaledSource : M31)
    (equation :
      (result - (previousCarry - shiftedCarry)) - scaledSource = 0) :
    result + shiftedCarry = scaledSource + previousCarry := by
  have first :
      result - (previousCarry - shiftedCarry) = scaledSource :=
    (M31.sub_eq_zero_iff _ _).mp equation
  have resultExpansion :
      result = (previousCarry - shiftedCarry) + scaledSource :=
    m31EqAddOfSubEq _ _ _ first
  have previousExpansion :
      previousCarry = shiftedCarry + (previousCarry - shiftedCarry) :=
    m31EqAddOfSubEq _ _ _ rfl
  calc
    result + shiftedCarry =
        ((previousCarry - shiftedCarry) + scaledSource) + shiftedCarry := by
          rw [resultExpansion]
    _ = (previousCarry - shiftedCarry) +
        (scaledSource + shiftedCarry) :=
      m31AddAssoc _ _ _
    _ = (previousCarry - shiftedCarry) +
        (shiftedCarry + scaledSource) := by
      rw [m31AddComm scaledSource shiftedCarry]
    _ = ((previousCarry - shiftedCarry) + shiftedCarry) +
        scaledSource :=
      (m31AddAssoc _ _ _).symm
    _ = (shiftedCarry + (previousCarry - shiftedCarry)) +
        scaledSource := by
      rw [m31AddComm (previousCarry - shiftedCarry) shiftedCarry]
    _ = previousCarry + scaledSource := by
      rw [← previousExpansion]
    _ = scaledSource + previousCarry :=
      m31AddComm _ _

private theorem rightMovementRearrange
    (shiftedCarry source carry scaledResult : M31)
    (equation :
      (shiftedCarry + (source - carry)) - scaledResult = 0) :
    scaledResult + carry = source + shiftedCarry := by
  have resultExpansion :
      shiftedCarry + (source - carry) = scaledResult :=
    (M31.sub_eq_zero_iff _ _).mp equation
  have sourceExpansion :
      source = carry + (source - carry) :=
    m31EqAddOfSubEq _ _ _ rfl
  calc
    scaledResult + carry =
        (shiftedCarry + (source - carry)) + carry := by
          rw [← resultExpansion]
    _ = shiftedCarry + ((source - carry) + carry) :=
      m31AddAssoc _ _ _
    _ = shiftedCarry + (carry + (source - carry)) := by
      rw [m31AddComm (source - carry) carry]
    _ = shiftedCarry + source := by
      rw [← sourceExpansion]
    _ = source + shiftedCarry :=
      m31AddComm _ _

private theorem rightTopRearrange
    (fill source carry scaledResult baseFill : M31)
    (equation : (fill + (source - carry)) - scaledResult = 0) :
    (scaledResult + carry) + baseFill =
      source + (fill + baseFill) := by
  have base :=
    rightMovementRearrange fill source carry scaledResult equation
  calc
    (scaledResult + carry) + baseFill =
        (source + fill) + baseFill := by rw [base]
    _ = source + (fill + baseFill) :=
      m31AddAssoc _ _ _

private theorem naturalEqualityOfReduced
    (left right : Nat)
    (leftBound : left < M31.modulus)
    (rightBound : right < M31.modulus)
    (equation : M31.reduce left = M31.reduce right) :
    left = right :=
  (M31.reduce_injective_of_lt leftBound rightBound).mp equation

private theorem leftStartNatural
    (result carry multiplier source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (equation :
      M31.reduce result + M31.reduce 256 * M31.reduce carry =
        M31.reduce source * M31.reduce multiplier) :
    result + 256 * carry = multiplier * source := by
  have productBound :
      multiplier * source < M31.modulus := by
    have productLe :
        multiplier * source ≤ 128 * 255 :=
      Nat.mul_le_mul multiplierBound (by omega)
    rw [M31.modulus_eq]
    omega
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    omega
  · exact productBound
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
  ] using equation

private theorem leftContinuationNatural
    (result carry previousCarry multiplier source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < multiplier)
    (previousCarryBound : previousCarry < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (equation :
      (M31.reduce result -
          (M31.reduce previousCarry -
            M31.reduce 256 * M31.reduce carry)) -
        M31.reduce source * M31.reduce multiplier = 0) :
    result + 256 * carry =
      multiplier * source + previousCarry := by
  have productLe :
      multiplier * source ≤ 128 * 255 :=
    Nat.mul_le_mul multiplierBound (by omega)
  have rearranged :=
    leftContinuationRearrange
      (M31.reduce result)
      (M31.reduce previousCarry)
      (M31.reduce 256 * M31.reduce carry)
      (M31.reduce source * M31.reduce multiplier)
      equation
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    omega
  · rw [M31.modulus_eq]
    omega
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
  ] using rearranged

private theorem rightMovementNatural
    (result carry nextCarry multiplier source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < multiplier)
    (nextCarryBound : nextCarry < multiplier)
    (multiplierBound : multiplier ≤ 128)
    (equation :
      (M31.reduce nextCarry * M31.reduce 256 +
          (M31.reduce source - M31.reduce carry)) -
        M31.reduce result * M31.reduce multiplier = 0) :
    multiplier * result + carry = source + 256 * nextCarry := by
  have productLe :
      multiplier * result ≤ 128 * 255 :=
    Nat.mul_le_mul multiplierBound (by omega)
  have rearranged :=
    rightMovementRearrange
      (M31.reduce nextCarry * M31.reduce 256)
      (M31.reduce source)
      (M31.reduce carry)
      (M31.reduce result * M31.reduce multiplier)
      equation
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    omega
  · rw [M31.modulus_eq]
    omega
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
  ] using rearranged

private theorem boolM31SignNat (row : ShiftRow) :
    boolM31 row.rs1Sign = M31.reduce row.signNat := by
  cases sign : row.rs1Sign <;>
    simp [boolM31, ShiftRow.signNat, sign]

private theorem reduceSubOne
    (value : Nat)
    (positive : 0 < value)
    (canonical : value < M31.modulus) :
    M31.reduce value - M31.reduce 1 = M31.reduce (value - 1) := by
  have ordered :
      (M31.reduce 1).val ≤ (M31.reduce value).val := by
    rw [
      M31.reduce_val_of_lt 1 (by decide),
      M31.reduce_val_of_lt value canonical,
    ]
    omega
  apply M31.ext
  rw [
    M31.sub_val_of_le _ _ ordered,
    M31.reduce_val_of_lt 1 (by decide),
    M31.reduce_val_of_lt value canonical,
    M31.reduce_val_of_lt (value - 1) (by omega),
  ]

private theorem signFillIdentity
    (row : ShiftRow)
    (multiplierBound : row.multiplier ≤ 128) :
    let multiplier := row.multiplier
    boolM31 row.rs1Sign * (M31.reduce multiplier - 1) * M31.reduce 256 +
        boolM31 row.rs1Sign * M31.reduce 256 =
      M31.reduce (256 * row.signNat * multiplier) := by
  cases sign : row.rs1Sign
  · simp [boolM31, ShiftRow.signNat, sign]
  · have positive := row.multiplier_pos
    have canonical : row.multiplier < M31.modulus := by
      rw [M31.modulus_eq]
      omega
    simp only [sign, boolM31, ShiftRow.signNat, ↓reduceIte, M31.one_mul]
    change
      (M31.reduce row.multiplier - M31.reduce 1) * M31.reduce 256 +
          M31.reduce 256 =
        M31.reduce (256 * 1 * row.multiplier)
    rw [
      reduceSubOne row.multiplier positive canonical,
      Air.Bridge.TeamACommon.reduceMul,
      Air.Bridge.TeamACommon.reduceAdd,
    ]
    congr 1
    omega

private theorem rightTopNatural
    (row : ShiftRow)
    (result carry source : Nat)
    (resultBound : result < 256)
    (sourceBound : source < 256)
    (carryBound : carry < row.multiplier)
    (multiplierBound : row.multiplier ≤ 128)
    (equation :
      (boolM31 row.rs1Sign *
            (M31.reduce row.multiplier - 1) *
            M31.reduce 256 +
          (M31.reduce source - M31.reduce carry)) -
        M31.reduce result * M31.reduce row.multiplier = 0) :
    row.multiplier * result + carry + 256 * row.signNat =
      source + 256 * row.signNat * row.multiplier := by
  have productLe :
      row.multiplier * result ≤ 128 * 255 :=
    Nat.mul_le_mul multiplierBound (by omega)
  have fillProductLe :
      256 * row.signNat * row.multiplier ≤ 256 * 1 * 128 := by
    have signBound : row.signNat ≤ 1 := by
      unfold ShiftRow.signNat
      split <;> omega
    exact
      Nat.mul_le_mul
        (Nat.mul_le_mul (Nat.le_refl 256) signBound)
        multiplierBound
  have rearranged :=
    rightTopRearrange
      (boolM31 row.rs1Sign *
        (M31.reduce row.multiplier - 1) *
        M31.reduce 256)
      (M31.reduce source)
      (M31.reduce carry)
      (M31.reduce result * M31.reduce row.multiplier)
      (boolM31 row.rs1Sign * M31.reduce 256)
      equation
  rw [signFillIdentity row multiplierBound] at rearranged
  rw [boolM31SignNat row] at rearranged
  apply naturalEqualityOfReduced
  · rw [M31.modulus_eq]
    have signBound : row.signNat ≤ 1 := by
      unfold ShiftRow.signNat
      split <;> omega
    omega
  · rw [M31.modulus_eq]
    have signBound : row.signNat ≤ 1 := by
      unfold ShiftRow.signNat
      split <;> omega
    omega
  simpa [
    Air.Bridge.TeamACommon.reduceAdd,
    Air.Bridge.TeamACommon.reduceMul,
    Nat.mul_comm,
    Nat.mul_left_comm,
    Nat.mul_assoc,
  ] using rearranged

structure ImmFixedConsequences (row : ShiftsImmRow) : Prop where
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 2)
  carry0 : row.semantic.carry0 < row.semantic.multiplier
  carry1 : row.semantic.carry1 < row.semantic.multiplier
  carry2 : row.semantic.carry2 < row.semantic.multiplier
  carry3 : row.semantic.carry3 < row.semantic.multiplier
  signLower :
    row.semantic.kind = .sra →
      128 * row.semantic.signNat ≤ row.semantic.rs1Next.limb3.toNat
  signUpper :
    row.semantic.kind = .sra →
      row.semantic.rs1Next.limb3.toNat <
        128 * row.semantic.signNat + 128

structure RegFixedConsequences (row : ShiftsRegRow) : Prop where
  sourceClock :
    validPreviousClock row.rs1PreviousClock (accessClock row.clock 1)
  secondSourceClock :
    validPreviousClock row.rs2PreviousClock (accessClock row.clock 2)
  destinationClock :
    validPreviousClock row.rdPreviousClock (accessClock row.clock 3)
  carry0 : row.semantic.carry0 < row.semantic.multiplier
  carry1 : row.semantic.carry1 < row.semantic.multiplier
  carry2 : row.semantic.carry2 < row.semantic.multiplier
  carry3 : row.semantic.carry3 < row.semantic.multiplier
  shiftAmountBinds :
    ∃ high,
      high ≤ 7 ∧
        row.rs2Next.limb0.toNat =
          32 * high + row.semantic.shiftAmount
  signLower :
    row.semantic.kind = .sra →
      128 * row.semantic.signNat ≤ row.semantic.rs1Next.limb3.toNat
  signUpper :
    row.semantic.kind = .sra →
      row.semantic.rs1Next.limb3.toNat <
        128 * row.semantic.signNat + 128

private theorem immFixedConsequences
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (admission : ImmAdmission row)
    (direct : (immEvaluation row witness).constraintsHold = true)
    (fixed : (immEvaluation row witness).fixedLookupsHold = true) :
    ImmFixedConsequences row := by
  have ranges := immIndexRanges row witness direct
  have projection := imm_exactFixedProjection row witness ranges.1
  have multiplierPositive := row.semantic.multiplier_pos
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  refine {
    sourceClock :=
      validClockOfGap row.clock 1 row.rs1PreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.sourcePreviousBound
        (clockGapBoundOfLookup
          (immEvaluation row witness) 72 1 row.clock row.rs1PreviousClock
          fixed projection.sourceClock)
    destinationClock :=
      validClockOfGap row.clock 2 row.rdPreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.destinationPreviousBound
        (clockGapBoundOfLookup
          (immEvaluation row witness) 81 2 row.clock row.rdPreviousClock
          fixed projection.destinationClock)
    carry0 :=
      carryLtMultiplier row.semantic.carry0 row.semantic.multiplier
        admission.carry0Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 73 row.semantic.carry0
          row.semantic.multiplier fixed projection.carry0)
    carry1 :=
      carryLtMultiplier row.semantic.carry1 row.semantic.multiplier
        admission.carry1Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 74 row.semantic.carry1
          row.semantic.multiplier fixed projection.carry1)
    carry2 :=
      carryLtMultiplier row.semantic.carry2 row.semantic.multiplier
        admission.carry2Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 75 row.semantic.carry2
          row.semantic.multiplier fixed projection.carry2)
    carry3 :=
      carryLtMultiplier row.semantic.carry3 row.semantic.multiplier
        admission.carry3Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (immEvaluation row witness) 76 row.semantic.carry3
          row.semantic.multiplier fixed projection.carry3)
    signLower := ?_
    signUpper := ?_
  }
  · intro kind
    exact
      (signBoundsOfLookup (immEvaluation row witness) 82 row.semantic
        kind fixed projection.sign).1
  · intro kind
    exact
      (signBoundsOfLookup (immEvaluation row witness) 82 row.semantic
        kind fixed projection.sign).2

private theorem regFixedConsequences
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (admission : RegAdmission row)
    (direct : (regEvaluation row witness).constraintsHold = true)
    (fixed : (regEvaluation row witness).fixedLookupsHold = true) :
    RegFixedConsequences row := by
  have ranges := regIndexRanges row witness direct
  have projection :=
    reg_exactFixedProjection row witness ranges.1 ranges.2
  have multiplierPositive := row.semantic.multiplier_pos
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  refine {
    sourceClock :=
      validClockOfGap row.clock 1 row.rs1PreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.sourcePreviousBound
        (clockGapBoundOfLookup
          (regEvaluation row witness) 75 1 row.clock row.rs1PreviousClock
          fixed projection.sourceClock)
    secondSourceClock :=
      validClockOfGap row.clock 2 row.rs2PreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.secondSourcePreviousBound
        (clockGapBoundOfLookup
          (regEvaluation row witness) 78 2 row.clock row.rs2PreviousClock
          fixed projection.secondSourceClock)
    destinationClock :=
      validClockOfGap row.clock 3 row.rdPreviousClock
        admission.clockPositive admission.clockBound (by omega) (by omega)
        admission.destinationPreviousBound
        (clockGapBoundOfLookup
          (regEvaluation row witness) 88 3 row.clock row.rdPreviousClock
          fixed projection.destinationClock)
    carry0 :=
      carryLtMultiplier row.semantic.carry0 row.semantic.multiplier
        admission.carry0Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 80 row.semantic.carry0
          row.semantic.multiplier fixed projection.carry0)
    carry1 :=
      carryLtMultiplier row.semantic.carry1 row.semantic.multiplier
        admission.carry1Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 81 row.semantic.carry1
          row.semantic.multiplier fixed projection.carry1)
    carry2 :=
      carryLtMultiplier row.semantic.carry2 row.semantic.multiplier
        admission.carry2Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 82 row.semantic.carry2
          row.semantic.multiplier fixed projection.carry2)
    carry3 :=
      carryLtMultiplier row.semantic.carry3 row.semantic.multiplier
        admission.carry3Canonical multiplierPositive multiplierBound
        (carryBoundsOfLookup
          (regEvaluation row witness) 83 row.semantic.carry3
          row.semantic.multiplier fixed projection.carry3)
    shiftAmountBinds := ?_
    signLower := ?_
    signUpper := ?_
  }
  · let shift : Fin 32 := {
      val := row.semantic.shiftAmount
      isLt := by
        simp only [ShiftRow.shiftAmount]
        omega
    }
    obtain ⟨high, equality⟩ :=
      amountMaskUnique row.rs2Next.limb0 shift
        (amountMaskBoundOfLookup row witness fixed projection.amountMask)
    exact ⟨high.val, by omega, by simpa [shift] using equality⟩
  · intro kind
    exact
      (signBoundsOfLookup (regEvaluation row witness) 89 row.semantic
        kind fixed projection.sign).1
  · intro kind
    exact
      (signBoundsOfLookup (regEvaluation row witness) 89 row.semantic
        kind fixed projection.sign).2

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem immLeftMovement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : ImmFixedConsequences row)
    (kind : row.semantic.kind = .sll) :
    shiftLeftEquations row.semantic.limbIndex row.semantic.multiplier
      row.semantic.rs1Next row.semantic.result
      row.semantic.carry0 row.semantic.carry1
      row.semantic.carry2 row.semantic.carry3 := by
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  rcases limbIndexCases ranges.2 with limb | limb | limb | limb
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 170
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb0.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have root :=
        immConstraintRootZero row witness direct 177
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb1.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 184
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 191
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry2 -
                M31.reduce 256 * M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.rs1Next.limb3.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 fixed.carry2 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 193
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb0
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 198
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb1.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have root :=
        immConstraintRootZero row witness direct 203
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 208
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 210
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb0
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 211
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb1
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 216
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb2.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have root :=
        immConstraintRootZero row witness direct 221
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 223
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb0
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 224
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb1
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 225
          (by simp [immConstraintRoots])
      apply byteNatZero row.semantic.result.limb2
      simpa [
        immEvaluation, immProgram, kind,
        Programs.slli, Programs.slliSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, immColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using root
    · have root :=
        immConstraintRootZero row witness direct 230
          (by simp [immConstraintRoots])
      have equation :
          M31.reduce row.semantic.result.limb3.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          immEvaluation, immProgram, kind,
          Programs.slli, Programs.slliSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, immColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using root
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem immRightMovement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : ImmFixedConsequences row)
    (notLeft : row.semantic.kind ≠ .sll) :
    shiftRightEquations row.semantic.limbIndex row.semantic.multiplier
      row.semantic.signNat row.semantic.rs1Next row.semantic.result
      row.semantic.carry0 row.semantic.carry1
      row.semantic.carry2 row.semantic.carry3 := by
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  rcases limbIndexCases ranges.2 with limb | limb | limb | limb
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 238
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry1 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb0.toNat -
                M31.reduce row.semantic.carry0)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 fixed.carry1 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 246
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 254
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 263
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb3.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 265
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 267
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 269
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 274
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 276
          (by simp [immConstraintRoots])
      have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 278
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 281
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have root :=
        immConstraintRootZero row witness direct 282
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have root :=
        immConstraintRootZero row witness direct 284
          (by simp [immConstraintRoots])
      have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using root
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have root :=
        immConstraintRootZero row witness direct 287
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb1 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb1
          row.semantic.rs1Sign equation
    · have root :=
        immConstraintRootZero row witness direct 288
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have root :=
        immConstraintRootZero row witness direct 289
          (by simp [immConstraintRoots])
      have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srli, Programs.srliSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
        · simpa [
            immEvaluation, immProgram, selected,
            Programs.srai, Programs.sraiSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, immColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using root
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem regLeftMovement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : RegFixedConsequences row)
    (kind : row.semantic.kind = .sll) :
    shiftLeftEquations row.semantic.limbIndex row.semantic.multiplier
      row.semantic.rs1Next row.semantic.result
      row.semantic.carry0 row.semantic.carry1
      row.semantic.carry2 row.semantic.carry3 := by
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  rcases limbIndexCases ranges.2 with limb | limb | limb | limb
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          M31.reduce row.semantic.result.limb0.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 179
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have equation :
          (M31.reduce row.semantic.result.limb1.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 186
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 193
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry2 -
                M31.reduce 256 * M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.rs1Next.limb3.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 200
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 fixed.carry2 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · apply byteNatZero row.semantic.result.limb0
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 202
          (by simp [regConstraintRoots])
    · have equation :
          M31.reduce row.semantic.result.limb1.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 207
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have equation :
          (M31.reduce row.semantic.result.limb2.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 212
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry1 -
                M31.reduce 256 * M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.rs1Next.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 217
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry1 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · apply byteNatZero row.semantic.result.limb0
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 219
          (by simp [regConstraintRoots])
    · apply byteNatZero row.semantic.result.limb1
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 220
          (by simp [regConstraintRoots])
    · have equation :
          M31.reduce row.semantic.result.limb2.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 225
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)
    · have equation :
          (M31.reduce row.semantic.result.limb3.toNat -
              (M31.reduce row.semantic.carry0 -
                M31.reduce 256 * M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.rs1Next.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 230
            (by simp [regConstraintRoots])
      exact
        leftContinuationNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry0 multiplierBound equation
  · rw [limb]
    simp only [shiftLeftEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · apply byteNatZero row.semantic.result.limb0
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 232
          (by simp [regConstraintRoots])
    · apply byteNatZero row.semantic.result.limb1
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 233
          (by simp [regConstraintRoots])
    · apply byteNatZero row.semantic.result.limb2
      simpa [
        regEvaluation, regProgram, kind,
        Programs.sll, Programs.sllSource,
        LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
        LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
        LocalValues.getSymbolic, newestValueSymbolic, regColumns,
        kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
      ] using
        regConstraintRootZero row witness direct 234
          (by simp [regConstraintRoots])
    · have equation :
          M31.reduce row.semantic.result.limb3.toNat +
                M31.reduce 256 * M31.reduce row.semantic.carry0 -
              M31.reduce row.semantic.rs1Next.limb0.toNat *
                M31.reduce row.semantic.multiplier = 0 := by
        simpa [
          regEvaluation, regProgram, kind,
          Programs.sll, Programs.sllSource,
          LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
          LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
          LocalValues.getSymbolic, newestValueSymbolic, regColumns,
          kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          bitVecM31,
        ] using
          regConstraintRootZero row witness direct 239
            (by simp [regConstraintRoots])
      exact
        leftStartNatural _ _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 multiplierBound
          ((M31.sub_eq_zero_iff _ _).mp equation)

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem regRightMovement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : RegFixedConsequences row)
    (notLeft : row.semantic.kind ≠ .sll) :
    shiftRightEquations row.semantic.limbIndex row.semantic.multiplier
      row.semantic.signNat row.semantic.rs1Next row.semantic.result
      row.semantic.carry0 row.semantic.carry1
      row.semantic.carry2 row.semantic.carry3 := by
  have multiplierBound := multiplierLe128 row.semantic ranges.1
  rcases limbIndexCases ranges.2 with limb | limb | limb | limb
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          (M31.reduce row.semantic.carry1 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb0.toNat -
                M31.reduce row.semantic.carry0)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 247
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 247
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb0)
          fixed.carry0 fixed.carry1 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 255
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 255
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 263
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 263
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb3.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 272
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 272
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb3)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          (M31.reduce row.semantic.carry2 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb1.toNat -
                M31.reduce row.semantic.carry1)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 274
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 274
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb1)
          fixed.carry1 fixed.carry2 multiplierBound equation
    · have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 276
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 276
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb2.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 278
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 278
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb2)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 283
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 283
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          (M31.reduce row.semantic.carry3 * M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb2.toNat -
                M31.reduce row.semantic.carry2)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 285
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 285
              (by simp [regConstraintRoots])
      exact
        rightMovementNatural _ _ _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb2)
          fixed.carry2 fixed.carry3 multiplierBound equation
    · have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb1.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 287
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 287
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb1)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 290
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 290
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 291
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 291
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation
  · rw [limb]
    simp only [shiftRightEquations]
    refine ⟨?_, ?_, ?_, ?_⟩
    · have equation :
          (boolM31 row.semantic.rs1Sign *
                (M31.reduce row.semantic.multiplier - 1) *
                M31.reduce 256 +
              (M31.reduce row.semantic.rs1Next.limb3.toNat -
                M31.reduce row.semantic.carry3)) -
            M31.reduce row.semantic.result.limb0.toNat *
              M31.reduce row.semantic.multiplier = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 293
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
            bitVecM31,
          ] using
            regConstraintRootZero row witness direct 293
              (by simp [regConstraintRoots])
      exact
        rightTopNatural row.semantic _ _ _
          (byteNatBound row.semantic.result.limb0)
          (byteNatBound row.semantic.rs1Next.limb3)
          fixed.carry3 multiplierBound equation
    · have equation :
          bitVecM31 row.semantic.result.limb1 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 296
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 296
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb1
          row.semantic.rs1Sign equation
    · have equation :
          bitVecM31 row.semantic.result.limb2 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 297
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 297
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb2
          row.semantic.rs1Sign equation
    · have equation :
          bitVecM31 row.semantic.result.limb3 -
            boolM31 row.semantic.rs1Sign * M31.reduce 255 = 0 := by
        cases selected : row.semantic.kind
        · exact False.elim (notLeft selected)
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.srl, Programs.srlSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 298
              (by simp [regConstraintRoots])
        · simpa [
            regEvaluation, regProgram, selected,
            Programs.sra, Programs.sraSource,
            LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
            LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
            LocalValues.getSymbolic, newestValueSymbolic, regColumns,
            kindIs, boolM31, marker, limb, leftMultiplier, rightMultiplier,
          ] using
            regConstraintRootZero row witness direct 298
              (by simp [regConstraintRoots])
      simpa [ShiftRow.signNat] using
        byteNatSignFill row.semantic.result.limb3
          row.semantic.rs1Sign equation

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem immNextPcNode
    (row : ShiftsImmRow)
    (witness : ImmWitness row) :
    (immEvaluation row witness).nodes.getSymbolic 329 =
      bitVecM31 row.pc + M31.reduce 4 := by
  cases kind : row.semantic.kind
  · simpa [
      immEvaluation, immProgram, kind,
      Programs.slli, Programs.slliSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, immColumns,
    ]
  · simpa [
      immEvaluation, immProgram, kind,
      Programs.srli, Programs.srliSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, immColumns,
    ]
  · simpa [
      immEvaluation, immProgram, kind,
      Programs.srai, Programs.sraiSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, immColumns,
    ]

set_option maxRecDepth 30000 in
set_option maxHeartbeats 0 in
private theorem regNextPcNode
    (row : ShiftsRegRow)
    (witness : RegWitness row) :
    (regEvaluation row witness).nodes.getSymbolic 346 =
      bitVecM31 row.pc + M31.reduce 4 := by
  cases kind : row.semantic.kind
  · simpa [
      regEvaluation, regProgram, kind,
      Programs.sll, Programs.sllSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, regColumns,
    ]
  · simpa [
      regEvaluation, regProgram, kind,
      Programs.srl, Programs.srlSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, regColumns,
    ]
  · simpa [
      regEvaluation, regProgram, kind,
      Programs.sra, Programs.sraSource,
      LocalProgram.evalSymbolic, LocalProgram.evalNodesSymbolic,
      LocalExprNode.evalAllSymbolic, LocalExprNode.evalSymbolic,
      LocalValues.getSymbolic, newestValueSymbolic, regColumns,
    ]

private theorem immNextPcResult
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness) :
    row.claimedNextPc = nextPc row.pc := by
  apply
    Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
      row.claimedNextPc (nextPc row.pc)
      admission.claimedNextPcCanonical
  · rw [
      Air.Bridge.TeamACommon.nextPcToNat row.pc admission.pcBound,
    ]
    exact admission.pcBound
  · calc
      bitVecM31 row.claimedNextPc =
          (immEvaluation row witness).nodes.getSymbolic 329 :=
        bindings.nextPcProjection
      _ = bitVecM31 row.pc + M31.reduce 4 :=
        immNextPcNode row witness
      _ = bitVecM31 (nextPc row.pc) :=
        Air.Bridge.TeamACommon.nextPcField row.pc admission.pcBound

private theorem regNextPcResult
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness) :
    row.claimedNextPc = nextPc row.pc := by
  apply
    Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
      row.claimedNextPc (nextPc row.pc)
      admission.claimedNextPcCanonical
  · rw [
      Air.Bridge.TeamACommon.nextPcToNat row.pc admission.pcBound,
    ]
    exact admission.pcBound
  · calc
      bitVecM31 row.claimedNextPc =
          (regEvaluation row witness).nodes.getSymbolic 346 :=
        bindings.nextPcProjection
      _ = bitVecM31 row.pc + M31.reduce 4 :=
        regNextPcNode row witness
      _ = bitVecM31 (nextPc row.pc) :=
        Air.Bridge.TeamACommon.nextPcField row.pc admission.pcBound

private theorem immCoreHolds
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (direct : (immEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : ImmFixedConsequences row) :
    ShiftHolds row.semantic := by
  have destination :=
    immDestinationConsequences row witness direct
  refine {
    limbIndexRange := ranges.2
    bitIndexRange := ranges.1
    signIsLogicalZero :=
      immSignIsLogicalZero row witness direct
    signLowerBound := fixed.signLower
    signUpperBound := fixed.signUpper
    carry0Range := fixed.carry0
    carry1Range := fixed.carry1
    carry2Range := fixed.carry2
    carry3Range := fixed.carry3
    sourceReadOnly := immSourceReadOnly row witness direct
    leftMovement :=
      immLeftMovement row witness direct ranges fixed
    rightMovement :=
      immRightMovement row witness direct ranges fixed
    destinationFlag := destination.flag
    destinationLimb0 := ?_
    destinationLimb1 := ?_
    destinationLimb2 := ?_
    destinationLimb3 := ?_
  }
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb0) destination.bytes
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb1) destination.bytes
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb2) destination.bytes
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb3) destination.bytes

private theorem regCoreHolds
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (direct : (regEvaluation row witness).constraintsHold = true)
    (ranges :
      row.semantic.bitIndex < 8 ∧ row.semantic.limbIndex < 4)
    (fixed : RegFixedConsequences row) :
    ShiftHolds row.semantic := by
  have destination :=
    regDestinationConsequences row witness direct
  refine {
    limbIndexRange := ranges.2
    bitIndexRange := ranges.1
    signIsLogicalZero :=
      regSignIsLogicalZero row witness direct
    signLowerBound := fixed.signLower
    signUpperBound := fixed.signUpper
    carry0Range := fixed.carry0
    carry1Range := fixed.carry1
    carry2Range := fixed.carry2
    carry3Range := fixed.carry3
    sourceReadOnly := regSourceReadOnly row witness direct
    leftMovement :=
      regLeftMovement row witness direct ranges fixed
    rightMovement :=
      regRightMovement row witness direct ranges fixed
    destinationFlag := destination.flag
    destinationLimb0 := ?_
    destinationLimb1 := ?_
    destinationLimb2 := ?_
    destinationLimb3 := ?_
  }
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb0) destination.bytes
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb1) destination.bytes
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb2) destination.bytes
  · cases nonzero : row.semantic.rdNonzero <;>
      simpa [nonzero] using
        congrArg (fun bytes : WordBytes => bytes.limb3) destination.bytes

/--
Exact generated-AIR acceptance derives the reviewed semantic capsule; no
`Holds` predicate is present among the premises.
-/
theorem immHoldsOfAccepted
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness)
    (accepted : ImmAcceptance row witness relationHolds) :
    ShiftsImmHolds row := by
  have ranges :=
    immIndexRanges row witness accepted.directConstraints
  have fixed :=
    immFixedConsequences row witness admission
      accepted.directConstraints accepted.fixedTableRequests
  exact {
    core :=
      immCoreHolds row witness accepted.directConstraints ranges fixed
    clockPositive := admission.clockPositive
    sourceClock := fixed.sourceClock
    destinationClock := fixed.destinationClock
    immediateBinds :=
      immImmediateBinds row witness admission accepted.directConstraints
    nextPcResult :=
      immNextPcResult row witness admission bindings
  }

theorem regHoldsOfAccepted
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness)
    (accepted : RegAcceptance row witness relationHolds) :
    ShiftsRegHolds row := by
  have ranges :=
    regIndexRanges row witness accepted.directConstraints
  have fixed :=
    regFixedConsequences row witness admission
      accepted.directConstraints accepted.fixedTableRequests
  exact {
    core :=
      regCoreHolds row witness accepted.directConstraints ranges fixed
    clockPositive := admission.clockPositive
    sourceClock := fixed.sourceClock
    secondSourceClock := fixed.secondSourceClock
    destinationClock := fixed.destinationClock
    secondSourceReadOnly :=
      regSecondSourceReadOnly row witness accepted.directConstraints
    shiftAmountBinds := fixed.shiftAmountBinds
    nextPcResult :=
      regNextPcResult row witness admission bindings
  }

private def programRelationLookup
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

private def immediateProgramRelationLookup
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

def generatedProgramIdentity (program : LocalProgram) :
    ProgramIdentity where
  manifestId := program.source.opcodeSelector.manifestId
  mnemonic := program.source.opcodeSelector.mnemonic
  family := program.source.family
  contentDigest := program.source.contentDigest

def sllProgramIdentity : ProgramIdentity where
  manifestId := 2
  mnemonic := "sll"
  family := .shiftsReg
  contentDigest :=
    "7b62fb42ff92827bf55533d67d584724c700ea179d1efcfd2f9b5ae3e20fbb32"

def srlProgramIdentity : ProgramIdentity where
  manifestId := 6
  mnemonic := "srl"
  family := .shiftsReg
  contentDigest :=
    "869c9706b00fd61143a8f6ed5b08507aa171c82b784c7d236555f6d2eb679f93"

def sraProgramIdentity : ProgramIdentity where
  manifestId := 7
  mnemonic := "sra"
  family := .shiftsReg
  contentDigest :=
    "4abb1006eb351fc2d570346833d1f3fa4c3175a30d02d0d4f05b5d8098b78b45"

def slliProgramIdentity : ProgramIdentity where
  manifestId := 16
  mnemonic := "slli"
  family := .shiftsImm
  contentDigest :=
    "4c055fd72015887caae84bca79261a77464b5c5357adfa57a9959938f53f1dc5"

def srliProgramIdentity : ProgramIdentity where
  manifestId := 17
  mnemonic := "srli"
  family := .shiftsImm
  contentDigest :=
    "dc75bfeb776b77851cf313d9228b476d03d806df30af3de0ec40ca2ee94d03ee"

def sraiProgramIdentity : ProgramIdentity where
  manifestId := 18
  mnemonic := "srai"
  family := .shiftsImm
  contentDigest :=
    "f0ebdc717fd1cb70b182fba5dc42dd4294ac8597fa23e04b702e9601292ad637"

structure ExactSelectorIdentity
    (program : LocalProgram)
    (expected : ProgramIdentity) : Prop where
  exactProgram : generatedProgramIdentity program = expected
  familyAdmission :
    program.source.family.validOpcode
      program.source.opcodeSelector.manifestId
      program.source.opcodeSelector.mnemonic = true
  manifestUnique :
    actualProgramIdentities.filter
        (fun identity =>
          decide (identity.manifestId = expected.manifestId)) =
      [expected]
  mnemonicUnique :
    actualProgramIdentities.filter
        (fun identity =>
          decide (identity.mnemonic = expected.mnemonic)) =
      [expected]

set_option maxRecDepth 30000 in
theorem sll_exactSelectorIdentity :
    ExactSelectorIdentity Programs.sll sllProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem srl_exactSelectorIdentity :
    ExactSelectorIdentity Programs.srl srlProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem sra_exactSelectorIdentity :
    ExactSelectorIdentity Programs.sra sraProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem slli_exactSelectorIdentity :
    ExactSelectorIdentity Programs.slli slliProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem srli_exactSelectorIdentity :
    ExactSelectorIdentity Programs.srli srliProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

set_option maxRecDepth 30000 in
theorem srai_exactSelectorIdentity :
    ExactSelectorIdentity Programs.srai sraiProgramIdentity := by
  refine {
    exactProgram := rfl
    familyAdmission := by decide
    manifestUnique := by
      rw [exactProductionProgramIdentities]
      decide
    mnemonicUnique := by
      rw [exactProductionProgramIdentities]
      decide
  }

/-!
An exact production program is part of each public premise.  Its accepted
opcode-selector expression pins the row's semantic tag; callers do not supply
that internal tag as a separate assumption.
-/
set_option maxRecDepth 30000 in
private theorem regProgramNodesShared (expected : ShiftKind) :
    (regProgram expected).nodes = Programs.sll.nodes := by
  cases expected <;> rfl

set_option maxRecDepth 30000 in
private theorem immProgramNodesShared (expected : ShiftKind) :
    (immProgram expected).nodes = Programs.slli.nodes := by
  cases expected <;> rfl

private def lookupTupleEntry?
    (index : Nat)
    (lookup : Option EvaluatedLookup) :
    Option M31 :=
  lookup.bind fun evaluated => evaluated.tuple[index]?

private theorem shiftsRegOpcodeIdBound (kind : ShiftKind) :
    shiftsRegOpcodeId kind < M31.modulus := by
  cases kind <;> decide

private theorem shiftsImmOpcodeIdBound (kind : ShiftKind) :
    shiftsImmOpcodeId kind < M31.modulus := by
  cases kind <;> decide

private theorem sllSourceProjection :
    Programs.sll.source = Programs.sllSource := rfl

private theorem srlSourceProjection :
    Programs.srl.source = Programs.srlSource := rfl

private theorem sraSourceProjection :
    Programs.sra.source = Programs.sraSource := rfl

private theorem slliSourceProjection :
    Programs.slli.source = Programs.slliSource := rfl

private theorem srliSourceProjection :
    Programs.srli.source = Programs.srliSource := rfl

private theorem sraiSourceProjection :
    Programs.srai.source = Programs.sraiSource := rfl

set_option maxRecDepth 30000 in
private theorem regSelectorNodeFromProjection
    (row : ShiftsRegRow)
    (witness : RegWitness row) :
    (regEvaluation row witness).nodes.getSymbolic 345 =
      M31.reduce (shiftsRegOpcodeId row.semantic.kind) := by
  have projected :=
    congrArg (lookupTupleEntry? 1)
      (reg_exactRelationProjection row witness).program
  cases kind : row.semantic.kind <;>
    simpa [
      lookupTupleEntry?,
      regEvaluation, regProgram, kind,
      sllSourceProjection, srlSourceProjection, sraSourceProjection,
      Programs.sllSource, Programs.srlSource, Programs.sraSource,
      LocalProgram.evalSymbolic,
      SymbolicEvaluation.lookup?, Event.evalSymbolic,
      EvaluatedEvent.lookup?,
      programRelationLookup, shiftsRegOpcodeId,
    ] using projected

set_option maxRecDepth 30000 in
private theorem immSelectorNodeFromProjection
    (row : ShiftsImmRow)
    (witness : ImmWitness row) :
    (immEvaluation row witness).nodes.getSymbolic 328 =
      M31.reduce (shiftsImmOpcodeId row.semantic.kind) := by
  have projected :=
    congrArg (lookupTupleEntry? 1)
      (imm_exactRelationProjection row witness).program
  cases kind : row.semantic.kind <;>
    simpa [
      lookupTupleEntry?,
      immEvaluation, immProgram, kind,
      slliSourceProjection, srliSourceProjection, sraiSourceProjection,
      Programs.slliSource, Programs.srliSource, Programs.sraiSource,
      LocalProgram.evalSymbolic,
      SymbolicEvaluation.lookup?, Event.evalSymbolic,
      EvaluatedEvent.lookup?,
      immediateProgramRelationLookup, shiftsImmOpcodeId,
    ] using projected

set_option maxRecDepth 30000 in
private theorem regExactSelectorNode
    (expected : ShiftKind)
    (row : ShiftsRegRow)
    (witness : RegWitness row) :
    ((regProgram expected).evalNodesSymbolic
        (regColumns row witness)).getSymbolic 345 =
      M31.reduce (shiftsRegOpcodeId row.semantic.kind) := by
  simpa only [
    regEvaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    regProgramNodesShared,
  ] using regSelectorNodeFromProjection row witness

set_option maxRecDepth 30000 in
private theorem immExactSelectorNode
    (expected : ShiftKind)
    (row : ShiftsImmRow)
    (witness : ImmWitness row) :
    ((immProgram expected).evalNodesSymbolic
        (immColumns row witness)).getSymbolic 328 =
      M31.reduce (shiftsImmOpcodeId row.semantic.kind) := by
  simpa only [
    immEvaluation,
    LocalProgram.evalSymbolic,
    LocalProgram.evalNodesSymbolic,
    immProgramNodesShared,
  ] using immSelectorNodeFromProjection row witness

set_option maxRecDepth 30000 in
private theorem regAcceptedSelectorNode
    (expected : ShiftKind)
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (active :
      ((regProgram expected).evalSymbolic
          (regColumns row witness)).activeSelectorsAccepted = true) :
    ((regProgram expected).evalNodesSymbolic
        (regColumns row witness)).getSymbolic 345 =
      M31.reduce (shiftsRegOpcodeId expected) := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have opcodeAccepted := selectorsAccepted.2
  cases expected <;>
    simpa [
      regProgram,
      LocalProgram.evalSymbolic,
      sllSourceProjection, srlSourceProjection, sraSourceProjection,
      Programs.sllSource, Programs.srlSource, Programs.sraSource,
      M31.ofNat?, M31.modulus_eq,
      beq_iff_eq, shiftsRegOpcodeId,
    ] using opcodeAccepted

set_option maxRecDepth 30000 in
private theorem immAcceptedSelectorNode
    (expected : ShiftKind)
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (active :
      ((immProgram expected).evalSymbolic
          (immColumns row witness)).activeSelectorsAccepted = true) :
    ((immProgram expected).evalNodesSymbolic
        (immColumns row witness)).getSymbolic 328 =
      M31.reduce (shiftsImmOpcodeId expected) := by
  have selectorsAccepted := active
  simp only [
    SymbolicEvaluation.activeSelectorsAccepted,
    Bool.and_eq_true,
  ] at selectorsAccepted
  have opcodeAccepted := selectorsAccepted.2
  cases expected <;>
    simpa [
      immProgram,
      LocalProgram.evalSymbolic,
      slliSourceProjection, srliSourceProjection, sraiSourceProjection,
      Programs.slliSource, Programs.srliSource, Programs.sraiSource,
      M31.ofNat?, M31.modulus_eq,
      beq_iff_eq, shiftsImmOpcodeId,
    ] using opcodeAccepted

private theorem regKindOfExactActive
    (expected : ShiftKind)
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (active :
      ((regProgram expected).evalSymbolic
          (regColumns row witness)).activeSelectorsAccepted = true) :
    row.semantic.kind = expected := by
  have ids :
      M31.reduce (shiftsRegOpcodeId row.semantic.kind) =
        M31.reduce (shiftsRegOpcodeId expected) := by
    calc
      _ = ((regProgram expected).evalNodesSymbolic
            (regColumns row witness)).getSymbolic 345 :=
        (regExactSelectorNode expected row witness).symm
      _ = _ := regAcceptedSelectorNode expected row witness active
  have opcodeIds :
      shiftsRegOpcodeId row.semantic.kind =
        shiftsRegOpcodeId expected :=
    (M31.reduce_injective_of_lt
      (shiftsRegOpcodeIdBound row.semantic.kind)
      (shiftsRegOpcodeIdBound expected)).mp ids
  cases expected <;>
    cases actual : row.semantic.kind <;>
    simp_all [shiftsRegOpcodeId]

private theorem immKindOfExactActive
    (expected : ShiftKind)
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (active :
      ((immProgram expected).evalSymbolic
          (immColumns row witness)).activeSelectorsAccepted = true) :
    row.semantic.kind = expected := by
  have ids :
      M31.reduce (shiftsImmOpcodeId row.semantic.kind) =
        M31.reduce (shiftsImmOpcodeId expected) := by
    calc
      _ = ((immProgram expected).evalNodesSymbolic
            (immColumns row witness)).getSymbolic 328 :=
        (immExactSelectorNode expected row witness).symm
      _ = _ := immAcceptedSelectorNode expected row witness active
  have opcodeIds :
      shiftsImmOpcodeId row.semantic.kind =
        shiftsImmOpcodeId expected :=
    (M31.reduce_injective_of_lt
      (shiftsImmOpcodeIdBound row.semantic.kind)
      (shiftsImmOpcodeIdBound expected)).mp ids
  cases expected <;>
    cases actual : row.semantic.kind <;>
    simp_all [shiftsImmOpcodeId]

structure ImmPublicationResult
    (program : LocalProgram)
    (expected : ProgramIdentity)
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (environment : ShiftsImmEnvironment row)
    (relationHolds : EvaluatedLookup → Prop) : Prop where
  selectedProgram : immProgram row.semantic.kind = program
  selectorIdentity : ExactSelectorIdentity program expected
  activeProductionRow :
    (immEvaluation row witness).activeSelectorsAccepted = true
  holds : ShiftsImmHolds row
  semantic : ShiftsImmRefinement row environment
  exactOrderedTuples : ImmExactRelationProjection row witness
  everyLiveNonFixedRelation :
    ∀ lookup, lookup ∈ (immEvaluation row witness).liveLookups →
      lookup.tableId = none → relationHolds lookup

structure RegPublicationResult
    (program : LocalProgram)
    (expected : ProgramIdentity)
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (environment : ShiftsRegEnvironment row)
    (relationHolds : EvaluatedLookup → Prop) : Prop where
  selectedProgram : regProgram row.semantic.kind = program
  selectorIdentity : ExactSelectorIdentity program expected
  activeProductionRow :
    (regEvaluation row witness).activeSelectorsAccepted = true
  holds : ShiftsRegHolds row
  semantic : ShiftsRegRefinement row environment
  exactOrderedTuples : RegExactRelationProjection row witness
  everyLiveNonFixedRelation :
    ∀ lookup, lookup ∈ (regEvaluation row witness).liveLookups →
      lookup.tableId = none → relationHolds lookup

/-
Publication implication for the exact generated SLL evaluator.  Its premises
are only production acceptance, profile admission, and explicit
program/register/projection bindings; `ShiftsRegHolds` is derived.
-/
set_option maxRecDepth 30000 in
theorem sll_accepted_air_implies_retirement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsRegEnvironment row)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.sll.evalSymbolic (regColumns row witness))
        relationHolds) :
    RegPublicationResult Programs.sll sllProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSll environment.word = true ∧
      shiftsRegRetirement row =
        executeSll environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd := by
  have selector : row.semantic.kind = .sll :=
    regKindOfExactActive .sll row witness accepted.activeProductionRow
  have acceptedRow : RegAcceptance row witness relationHolds := by
    simpa only [RegAcceptance, regEvaluation, selector, regProgram]
      using accepted
  have holds :=
    regHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    sll_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [regProgram, selector]
    selectorIdentity := sll_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := reg_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem srl_accepted_air_implies_retirement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsRegEnvironment row)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.srl.evalSymbolic (regColumns row witness))
        relationHolds) :
    RegPublicationResult Programs.srl srlProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSrl environment.word = true ∧
      shiftsRegRetirement row =
        executeSrl environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd ∧
      row.semantic.rs1Sign = false := by
  have selector : row.semantic.kind = .srl :=
    regKindOfExactActive .srl row witness accepted.activeProductionRow
  have acceptedRow : RegAcceptance row witness relationHolds := by
    simpa only [RegAcceptance, regEvaluation, selector, regProgram]
      using accepted
  have holds :=
    regHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    srl_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [regProgram, selector]
    selectorIdentity := srl_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := reg_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem sra_accepted_air_implies_retirement
    (row : ShiftsRegRow)
    (witness : RegWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsRegEnvironment row)
    (admission : RegAdmission row)
    (bindings : RegBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.sra.evalSymbolic (regColumns row witness))
        relationHolds) :
    RegPublicationResult Programs.sra sraProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSra environment.word = true ∧
      shiftsRegRetirement row =
        executeSra environment.pre.pc
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rs2) row.semantic.rd ∧
      row.semantic.rs1Sign =
        (environment.pre.registers row.rs1).msb := by
  have selector : row.semantic.kind = .sra :=
    regKindOfExactActive .sra row witness accepted.activeProductionRow
  have acceptedRow : RegAcceptance row witness relationHolds := by
    simpa only [RegAcceptance, regEvaluation, selector, regProgram]
      using accepted
  have holds :=
    regHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    sra_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [regProgram, selector]
    selectorIdentity := sra_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := reg_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem slli_accepted_air_implies_retirement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsImmEnvironment row)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.slli.evalSymbolic (immColumns row witness))
        relationHolds) :
    ImmPublicationResult Programs.slli slliProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSlli environment.word = true ∧
      shiftsImmRetirement row =
        executeSlli environment.pre.pc
          (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) := by
  have selector : row.semantic.kind = .sll :=
    immKindOfExactActive .sll row witness accepted.activeProductionRow
  have acceptedRow : ImmAcceptance row witness relationHolds := by
    simpa only [ImmAcceptance, immEvaluation, selector, immProgram]
      using accepted
  have holds :=
    immHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    slli_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [immProgram, selector]
    selectorIdentity := slli_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := imm_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem srli_accepted_air_implies_retirement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsImmEnvironment row)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.srli.evalSymbolic (immColumns row witness))
        relationHolds) :
    ImmPublicationResult Programs.srli srliProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSrli environment.word = true ∧
      shiftsImmRetirement row =
        executeSrli environment.pre.pc
          (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) ∧
      row.semantic.rs1Sign = false := by
  have selector : row.semantic.kind = .srl :=
    immKindOfExactActive .srl row witness accepted.activeProductionRow
  have acceptedRow : ImmAcceptance row witness relationHolds := by
    simpa only [ImmAcceptance, immEvaluation, selector, immProgram]
      using accepted
  have holds :=
    immHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    srli_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [immProgram, selector]
    selectorIdentity := srli_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := imm_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

set_option maxRecDepth 30000 in
theorem srai_accepted_air_implies_retirement
    (row : ShiftsImmRow)
    (witness : ImmWitness row)
    (relationHolds : EvaluatedLookup → Prop)
    (environment : ShiftsImmEnvironment row)
    (admission : ImmAdmission row)
    (bindings : ImmBindings row witness)
    (accepted :
      AcceptedProductionEvaluation
        (Programs.srai.evalSymbolic (immColumns row witness))
        relationHolds) :
    ImmPublicationResult Programs.srai sraiProgramIdentity
        row witness environment relationHolds ∧
      Decode.isSrai environment.word = true ∧
      shiftsImmRetirement row =
        executeSrai environment.pre.pc
          (environment.pre.registers row.rs1)
          row.semantic.rd (shiftsImmShamt row) ∧
      row.semantic.rs1Sign =
        (environment.pre.registers row.rs1).msb := by
  have selector : row.semantic.kind = .sra :=
    immKindOfExactActive .sra row witness accepted.activeProductionRow
  have acceptedRow : ImmAcceptance row witness relationHolds := by
    simpa only [ImmAcceptance, immEvaluation, selector, immProgram]
      using accepted
  have holds :=
    immHoldsOfAccepted
      row witness relationHolds admission bindings acceptedRow
  have opcode :=
    srai_refines row environment holds selector
  exact ⟨{
    selectedProgram := by simp [immProgram, selector]
    selectorIdentity := srai_exactSelectorIdentity
    activeProductionRow := acceptedRow.activeProductionRow
    holds
    semantic := opcode.1
    exactOrderedTuples := imm_exactRelationProjection row witness
    everyLiveNonFixedRelation := acceptedRow.liveRelations
  }, opcode.2⟩

end RiscvRefinement.Publication.TeamB.Shifts
