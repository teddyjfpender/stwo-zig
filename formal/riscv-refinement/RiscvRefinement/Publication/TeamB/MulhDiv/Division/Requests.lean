import RiscvRefinement.Publication.TeamB.MulhDiv.Division.Air

namespace RiscvRefinement.Publication.TeamB.MulhDiv

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Family

namespace Division

/-- Compact, evaluator-independent receipt for every fixed-table request used
by the DIV-family semantic bridge. -/
structure FixedRequests (row : Row) : Prop where
  sourceOneClock :
    (clockLookup row 1 84 row.rs1PreviousClock).fixedRequestHolds = true
  sourceTwoClock :
    (clockLookup row 2 87 row.rs2PreviousClock).fixedRequestHolds = true
  carry0 :
    (carryLookup row 90 row.quotient.limb0
      (carry0Field row)).fixedRequestHolds = true
  carry1 :
    (carryLookup row 91 row.quotient.limb1
      (carry1Field row)).fixedRequestHolds = true
  carry2 :
    (carryLookup row 92 row.quotient.limb2
      (carry2Field row)).fixedRequestHolds = true
  carry3 :
    (carryLookup row 93 row.quotient.limb3
      (carry3Field row)).fixedRequestHolds = true
  carry4 :
    (carryLookup row 94 row.remainder.limb0
      (carry4Field row)).fixedRequestHolds = true
  carry5 :
    (carryLookup row 95 row.remainder.limb1
      (carry5Field row)).fixedRequestHolds = true
  carry6 :
    (carryLookup row 96 row.remainder.limb2
      (carry6Field row)).fixedRequestHolds = true
  carry7 :
    (carryLookup row 97 row.remainder.limb3
      (carry7Field row)).fixedRequestHolds = true
  quotientSign : (quotientSignLookup row).fixedRequestHolds = true
  operandSigns : (signRangeLookup row).fixedRequestHolds = true
  positiveDiff : (positiveDiffLookup row).fixedRequestHolds = true
  destinationClock :
    (clockLookup row 3 103 row.rdPreviousClock).fixedRequestHolds = true

set_option maxRecDepth 30000 in
opaque fixedRequestsOfAcceptance
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true) :
    FixedRequests row := by
  have projection := exactFixedProjection selector row witness
  exact {
    sourceOneClock :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 84
        (clockLookup row 1 84 row.rs1PreviousClock)
        fixed projection.sourceOneClock
    sourceTwoClock :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 87
        (clockLookup row 2 87 row.rs2PreviousClock)
        fixed projection.sourceTwoClock
    carry0 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 90
        (carryLookup row 90 row.quotient.limb0 (carry0Field row))
        fixed projection.carry0
    carry1 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 91
        (carryLookup row 91 row.quotient.limb1 (carry1Field row))
        fixed projection.carry1
    carry2 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 92
        (carryLookup row 92 row.quotient.limb2 (carry2Field row))
        fixed projection.carry2
    carry3 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 93
        (carryLookup row 93 row.quotient.limb3 (carry3Field row))
        fixed projection.carry3
    carry4 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 94
        (carryLookup row 94 row.remainder.limb0 (carry4Field row))
        fixed projection.carry4
    carry5 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 95
        (carryLookup row 95 row.remainder.limb1 (carry5Field row))
        fixed projection.carry5
    carry6 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 96
        (carryLookup row 96 row.remainder.limb2 (carry6Field row))
        fixed projection.carry6
    carry7 :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 97
        (carryLookup row 97 row.remainder.limb3 (carry7Field row))
        fixed projection.carry7
    quotientSign :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 98 (quotientSignLookup row)
        fixed projection.quotientSign
    operandSigns :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 99 (signRangeLookup row)
        fixed projection.operandSigns
    positiveDiff :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 100 (positiveDiffLookup row)
        fixed projection.positiveDiff
    destinationClock :=
      SymbolicEvaluation.fixedRequestHolds_of_lookup
        (evaluation selector row witness) 103
        (clockLookup row 3 103 row.rdPreviousClock)
        fixed projection.destinationClock
  }

/-- Bounded meanings extracted from all fixed-table requests.  No symbolic
evaluator appears in this receipt, which keeps later semantic proofs small. -/
structure FixedBounds (row : Row) : Prop where
  sourceOneGap :
    (clockGapField row 1 row.rs1PreviousClock).val < 2 ^ 20
  sourceTwoGap :
    (clockGapField row 2 row.rs2PreviousClock).val < 2 ^ 20
  destinationGap :
    (clockGapField row 3 row.rdPreviousClock).val < 2 ^ 20
  carry0Bound : (carry0Field row).val < 2 ^ 11
  carry1Bound : (carry1Field row).val < 2 ^ 11
  carry2Bound : (carry2Field row).val < 2 ^ 11
  carry3Bound : (carry3Field row).val < 2 ^ 11
  carry4Bound : (carry4Field row).val < 2 ^ 11
  carry5Bound : (carry5Field row).val < 2 ^ 11
  carry6Bound : (carry6Field row).val < 2 ^ 11
  carry7Bound : (carry7Field row).val < 2 ^ 11
  operandSignBounds :
    signedField row = 1 →
      ((bitVecM31 row.rs1Next.limb3 -
            boolM31 row.bSign * M31.reduce 128) *
          M31.reduce 2).val < 2 ^ 8 ∧
        ((bitVecM31 row.rs2Next.limb3 -
              boolM31 row.cSign * M31.reduce 128) *
            M31.reduce 2).val < 2 ^ 8
  quotientSignBound :
    quotientSignActiveField row = 1 →
      (bitVecM31 row.quotient.limb3 -
          boolM31 row.qSign * M31.reduce 128).val < 2 ^ 7
  positiveDiffBound :
    activeField row - specialField row = 1 →
      (M31.reduce row.ltDiff - M31.reduce 1).val < 2 ^ 20

set_option maxRecDepth 30000 in
opaque fixedBoundsOfAcceptance
    (selector : Selector)
    (row : Row)
    (witness : Witness row)
    (selectors : SelectorConsequences selector row)
    (fixed : (evaluation selector row witness).fixedLookupsHold = true) :
    FixedBounds row := by
  let production := evaluation selector row witness
  have projection := exactFixedProjection selector row witness
  have activeLive : -activeField row ≠ 0 := by
    rw [selectors.activeOne]
    decide
  exact {
    sourceOneGap :=
      MulhDiv.fixedRange20BoundOfLookup production 84
        (-activeField row) (clockGapField row 1 row.rs1PreviousClock)
        (some 1) fixed
        (by simpa [clockLookup] using projection.sourceOneClock)
        activeLive
    sourceTwoGap :=
      MulhDiv.fixedRange20BoundOfLookup production 87
        (-activeField row) (clockGapField row 2 row.rs2PreviousClock)
        (some 2) fixed
        (by simpa [clockLookup] using projection.sourceTwoClock)
        activeLive
    destinationGap :=
      MulhDiv.fixedRange20BoundOfLookup production 103
        (-activeField row) (clockGapField row 3 row.rdPreviousClock)
        (some 3) fixed
        (by simpa [clockLookup] using projection.destinationClock)
        activeLive
    carry0Bound := (MulhDiv.fixedRange811BoundsOfLookup production 90
      (-activeField row) (bitVecM31 row.quotient.limb0) (carry0Field row)
      fixed (by simpa [carryLookup] using projection.carry0) activeLive).2
    carry1Bound := (MulhDiv.fixedRange811BoundsOfLookup production 91
      (-activeField row) (bitVecM31 row.quotient.limb1) (carry1Field row)
      fixed (by simpa [carryLookup] using projection.carry1) activeLive).2
    carry2Bound := (MulhDiv.fixedRange811BoundsOfLookup production 92
      (-activeField row) (bitVecM31 row.quotient.limb2) (carry2Field row)
      fixed (by simpa [carryLookup] using projection.carry2) activeLive).2
    carry3Bound := (MulhDiv.fixedRange811BoundsOfLookup production 93
      (-activeField row) (bitVecM31 row.quotient.limb3) (carry3Field row)
      fixed (by simpa [carryLookup] using projection.carry3) activeLive).2
    carry4Bound := (MulhDiv.fixedRange811BoundsOfLookup production 94
      (-activeField row) (bitVecM31 row.remainder.limb0) (carry4Field row)
      fixed (by simpa [carryLookup] using projection.carry4) activeLive).2
    carry5Bound := (MulhDiv.fixedRange811BoundsOfLookup production 95
      (-activeField row) (bitVecM31 row.remainder.limb1) (carry5Field row)
      fixed (by simpa [carryLookup] using projection.carry5) activeLive).2
    carry6Bound := (MulhDiv.fixedRange811BoundsOfLookup production 96
      (-activeField row) (bitVecM31 row.remainder.limb2) (carry6Field row)
      fixed (by simpa [carryLookup] using projection.carry6) activeLive).2
    carry7Bound := (MulhDiv.fixedRange811BoundsOfLookup production 97
      (-activeField row) (bitVecM31 row.remainder.limb3) (carry7Field row)
      fixed (by simpa [carryLookup] using projection.carry7) activeLive).2
    operandSignBounds := by
      intro signedOne
      have bounds := MulhDiv.fixedRange88BoundsOfLookup production 99
        (-activeField row)
        (signedField row *
          (bitVecM31 row.rs1Next.limb3 -
            boolM31 row.bSign * M31.reduce 128) * M31.reduce 2)
        (signedField row *
          (bitVecM31 row.rs2Next.limb3 -
            boolM31 row.cSign * M31.reduce 128) * M31.reduce 2)
        fixed (by simpa [signRangeLookup] using projection.operandSigns)
        activeLive
      simpa [signedOne] using bounds
    quotientSignBound := by
      intro requestActive
      apply MulhDiv.fixedRangeM31HighBoundOfLookup production 98
        (-quotientSignActiveField row) 0
        (bitVecM31 row.quotient.limb3 -
          boolM31 row.qSign * M31.reduce 128) fixed
      · simpa [quotientSignLookup] using projection.quotientSign
      · rw [requestActive]
        decide
    positiveDiffBound := by
      intro requestActive
      apply MulhDiv.fixedRange20BoundOfLookup production 100
        (-(activeField row -
          (boolM31 row.zeroDivisor + boolM31 row.rZero)))
        (M31.reduce row.ltDiff - M31.reduce 1) none fixed
      · simpa [positiveDiffLookup] using projection.positiveDiff
      · have requestActive' :
            activeField row -
                (boolM31 row.zeroDivisor + boolM31 row.rZero) = 1 := by
          simpa [specialField] using requestActive
        rw [requestActive']
        decide
  }

end Division

end RiscvRefinement.Publication.TeamB.MulhDiv
