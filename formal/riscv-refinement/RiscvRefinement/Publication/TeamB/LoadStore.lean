import RiscvRefinement.Air.Bridge.LoadStoreBridge
import RiscvRefinement.Opcodes.LoadStore
import RiscvRefinement.Publication.Acceptance
import RiscvRefinement.Publication.TeamB.Common

/-!
# Load/store publication status

The exact compact production bridge lives in
`Air.Bridge.LoadStoreBridge`. It binds the typed load/store semantics to the
generated 48-column, 301-node, 63-root, 16-lookup circuit and proves:

* every semantic row satisfies every production constraint root;
* every live fixed-table request is admitted; and
* every ordered lookup tuple is exactly the tuple emitted by production.

The converse publication theorem -- exact accepted production AIR implies
`LoadStoreHolds`, and therefore architectural retirement -- was already an
unfinished issue-136 item before the compact layout. The former canonical
module stopped at `fixedConsequences`; its complete continuation remains in
`checkpoints/issue-136/LoadStore.publication-wip.lean` and is intentionally
outside the Lake library. That checkpoint targets the superseded 56-column
layout and must not be counted as evidence for this circuit.

This module deliberately does not declare the eight
`*_accepted_air_implies_retirement` names listed by the publication inventory.
The evidence builder therefore remains fail-closed until a reverse bridge for
the exact compact circuit is completed and kernel-audited. Keeping this status
module small also avoids maintaining a second handwritten copy of the
production evaluator.
-/

namespace RiscvRefinement.Publication.TeamB.LoadStore

open RiscvRefinement.Air.Bridge

set_option maxRecDepth 10000 in
/-- Kernel-checked shape of the compact load/store circuit used by production. -/
theorem exactCompactProductionShape :
    loadStoreCircuit.columns.length = 48 ∧
      loadStoreCircuit.nodes.length = 301 ∧
      loadStoreCircuit.constraints.length = 63 ∧
      loadStoreCircuit.lookups.length = 16 := by
  decide

/-- The checked source digest is exposed at the publication boundary so a
future reverse bridge cannot silently bind a different generated circuit. -/
theorem exactCompactProductionDigest :
    loadStoreProgramIrDigest =
      "be64f6f847266cff147de247401d07f6b7b1b83031d6291cd2dd1e2a5987a1c5" := by
  rfl

end RiscvRefinement.Publication.TeamB.LoadStore
