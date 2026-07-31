import RiscvRefinement.Air.LocalEval

/-!
# Publication-level production acceptance

Family bridges historically packaged direct and fixed-table acceptance while
leaving global relation closure implicit in their environment.  FV-2 requires
the complete premise explicitly.  This shared record is the exact common
front of every publication theorem; family-specific wrappers derive their
older acceptance records from its first three fields and retain
`liveRelations` in the final cross-project composition.
-/

namespace RiscvRefinement.Publication

open RiscvRefinement.Air

/--
Acceptance of one exact localized production evaluation, including every live
non-fixed lookup request.  `relationHolds` is bound by each opcode theorem to
its program/register/memory environment; it is not a replacement semantic
function.
-/
structure AcceptedProductionEvaluation
    (evaluation : SymbolicEvaluation)
    (relationHolds : EvaluatedLookup → Prop) : Prop where
  activeProductionRow : evaluation.activeSelectorsAccepted = true
  directConstraints : evaluation.constraintsHold = true
  fixedTableRequests : evaluation.fixedLookupsHold = true
  liveRelations :
    ∀ lookup, lookup ∈ evaluation.liveLookups →
      lookup.tableId = none → relationHolds lookup

/--
The relation premise is non-optional: every live non-fixed request can be
recovered from publication acceptance.
-/
theorem liveRelationRequest
    {evaluation : SymbolicEvaluation}
    {relationHolds : EvaluatedLookup → Prop}
    (accepted : AcceptedProductionEvaluation evaluation relationHolds)
    (lookup : EvaluatedLookup)
    (live : lookup ∈ evaluation.liveLookups)
    (nonFixed : lookup.tableId = none) :
    relationHolds lookup :=
  accepted.liveRelations lookup live nonFixed

/--
A shallow interpretation of the second component of a production
`rangeCheckM31` request.  Keeping this consequence at the acceptance boundary
lets opcode bridges consume an exact generated lookup locally without
exporting that generated evaluation through their theorem interfaces.
-/
theorem rangeCheckM31HighBoundOfFixedRequest
    (ordinal : Nat)
    (accessOrdinal : Option Nat)
    (low high : M31)
    (holds :
      (EvaluatedLookup.fixedRequestHolds {
        ordinal
        domain := .rangeCheckM31
        numerator := -(1 : M31)
        tuple := #[low, high]
        role := .request
        tableId := some .rangeCheckM31
        accessOrdinal
      }) = true) :
    high.val < 2 ^ 7 := by
  simp only [
    EvaluatedLookup.fixedRequestHolds,
    EvaluatedLookup.isLive,
    EvaluatedLookup.fixedMembership,
    Option.map,
    Option.getD,
    FixedTableId.contains,
    M31.toNat,
  ] at holds
  simp at holds
  rcases holds with impossible | membership
  · have nonzero : (-(1 : M31)) ≠ 0 := by decide
    exact False.elim (nonzero impossible)
  · exact membership.1.2

end RiscvRefinement.Publication
