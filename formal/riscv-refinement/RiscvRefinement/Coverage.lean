import RiscvRefinement.Publication.Coverage

/-!
# Legacy coverage import

The active verification inventory is `RiscvRefinement.Publication.Coverage`.
This module remains only as a source-compatible import for older downstream
code.  Coverage is one manifest-wide property; contributor allocation is not
part of the statement.
-/

namespace RiscvRefinement.Coverage

abbrev manifestIds : List Nat :=
  Publication.localManifestIds

abbrev theoremIdentities : List String :=
  Publication.localTheoremIdentities

theorem aggregate_coverage_exact :
    manifestIds.length = 46 ∧
      manifestIds.Nodup ∧
      (∀ id ∈ List.range 46, id ∈ manifestIds) :=
  Publication.exactLocalManifestCoverage

theorem theorem_identity_coverage_exact :
    theoremIdentities.length = 46 ∧ theoremIdentities.Nodup :=
  Publication.exactLocalTheoremIdentityCoverage

end RiscvRefinement.Coverage
