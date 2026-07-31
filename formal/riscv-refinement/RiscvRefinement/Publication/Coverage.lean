import RiscvRefinement.Publication.TeamA.Common
import RiscvRefinement.Publication.TeamB.Common

/-!
# Exact local publication coverage

The two imported inventories are implementation artifacts from the historical
parallel rollout.  The publication claim has one semantic inventory: exactly
the 46 manifest IDs and exactly 46 distinct local theorem identities.  No
public theorem below exposes the old contributor-team partition.
-/

namespace RiscvRefinement.Publication

def localManifestIds : List Nat :=
  TeamA.manifestIds ++ TeamB.manifestIds

def localTheoremIdentities : List String :=
  TeamA.localTheoremIdentities ++ TeamB.localTheoremIdentities

theorem exactLocalManifestCoverage :
    localManifestIds.length = 46 ∧
      localManifestIds.Nodup ∧
      (∀ id ∈ List.range 46, id ∈ localManifestIds) := by
  decide

theorem exactLocalManifestOrderFilter :
    (List.range 46).filter (· ∈ localManifestIds) =
      List.range 46 := by
  decide

theorem exactLocalTheoremIdentityCoverage :
    localTheoremIdentities.length = 46 ∧
      localTheoremIdentities.Nodup := by
  exact ⟨by decide, by decide⟩

end RiscvRefinement.Publication
