import RiscvRefinement.Publication.TeamB.Shifts.RegRight

/-! Bounded shift publication proof owner: Acceptance. -/
namespace RiscvRefinement.Publication.TeamB.Shifts

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family
open RiscvRefinement.Air.Generated
open RiscvRefinement.Opcodes
open RiscvRefinement.Sail.Reviewed

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

end RiscvRefinement.Publication.TeamB.Shifts
