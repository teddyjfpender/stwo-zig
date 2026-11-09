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

def bitVecM31 {width : Nat} (value : BitVec width) : M31 :=
  M31.reduce value.toNat

def boolM31 : Bool → M31
  | false => 0
  | true => 1

def kindIs (expected actual : ShiftKind) : Bool :=
  decide (actual = expected)

def marker (index expected : Nat) : M31 :=
  if index = expected then 1 else 0

def leftMultiplier (row : ShiftRow) : M31 :=
  if row.kind = .sll then M31.reduce row.multiplier else 0

def rightMultiplier (row : ShiftRow) : M31 :=
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

theorem byteBound (value : Byte) :
    value.toNat < M31.modulus := by
  have := value.isLt
  simp [M31.modulus_eq] at *
  omega

theorem byteNatBound (value : Byte) :
    value.toNat < 256 := by
  simpa only [Nat.reducePow] using value.isLt

theorem byteEq
    (left right : Byte)
    (equality : bitVecM31 left = bitVecM31 right) :
    left = right :=
  Air.Bridge.TeamACommon.bitVecM31_injective_of_bounds
    left right (byteBound left) (byteBound right) equality

theorem byteNatZero
    (value : Byte)
    (equation : bitVecM31 value = 0) :
    value.toNat = 0 := by
  have values := congrArg M31.val equation
  rw [show (bitVecM31 value).val = value.toNat by
    exact M31.reduce_val_of_lt _ (byteBound value)] at values
  exact values

theorem byteNatSignFill
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

end RiscvRefinement.Publication.TeamB.Shifts
