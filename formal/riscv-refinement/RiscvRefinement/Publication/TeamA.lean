import RiscvRefinement.Publication.TeamA.Common
import RiscvRefinement.Publication.TeamA.BaseAlu
import RiscvRefinement.Publication.TeamA.Compare
import RiscvRefinement.Publication.TeamA.Branches
import RiscvRefinement.Publication.TeamA.Control
import RiscvRefinement.Publication.TeamA.Pilots

/-!
# Team A FV-2 publication surface

Importing this module brings the 24 accepted-production-AIR-to-retirement
theorems into the audited environment.  `TeamA.Common.selectors` is the exact,
injective 24-selector inventory used by the machine-readable receipt.
-/

namespace RiscvRefinement.Publication.TeamA

theorem localPublicationCoverage :
    selectors.length = 24 ∧
      selectors.Nodup ∧
      manifestIds.length = 24 ∧
      manifestIds.Nodup ∧
      localTheoremIdentities.length = 24 ∧
      localTheoremIdentities.Nodup :=
  ⟨
    selectors_length,
    selectors_nodup,
    manifestIds_length,
    manifestIds_nodup,
    localTheoremIdentities_length,
    localTheoremIdentities_nodup
  ⟩

end RiscvRefinement.Publication.TeamA
