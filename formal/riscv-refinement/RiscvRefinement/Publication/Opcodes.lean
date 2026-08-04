import RiscvRefinement.Publication.TeamA
import RiscvRefinement.Publication.TeamB.Multiply
import RiscvRefinement.Publication.TeamB.MulhDiv
import RiscvRefinement.Publication.TeamB.Shifts
import RiscvRefinement.Publication.TeamB.LoadStore
import RiscvRefinement.Publication.Coverage

/-!
# Opcode publication identity surface

This is the neutral repository entry point for the exact 46-opcode identity
inventory and the canonical proof modules currently safe to compile. The
inventory below proves exact metadata order and uniqueness; it deliberately
does not prove that every named final implication has been delivered. Only the
publication evidence builder may promote that claim after it finds all theorem
constants in kernel axiom reports.

The imported contributor-team paths are temporary implementation history.
Downstream code imports this module and consumes the one exact identity
inventory from `Publication.Coverage`.
-/

namespace RiscvRefinement.Publication

/-- Exact manifest and expected-theorem-name inventory. This is not a 46/46
proof-completion theorem. -/
theorem exactOpcodePublicationInventory :
    localManifestIds.length = 46 ∧
      localManifestIds.Nodup ∧
      localTheoremIdentities.length = 46 ∧
      localTheoremIdentities.Nodup := by
  exact ⟨
    exactLocalManifestCoverage.1,
    exactLocalManifestCoverage.2.1,
    exactLocalTheoremIdentityCoverage.1,
    exactLocalTheoremIdentityCoverage.2
  ⟩

end RiscvRefinement.Publication
