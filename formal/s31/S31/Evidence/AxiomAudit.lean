import S31
import Lean.Elab.Command
import Lean.Util.CollectAxioms

open Lean Elab Command

/-- Use the existing refinement audit's source-range selection policy. Report
every S31 source theorem, including helpers and premise-free controls. -/
elab "#audit_s31_theorems" : command => do
  let environment ← getEnv
  for (name, information) in environment.constants.toList do
    if (name.toString.startsWith "S31." ||
        name.toString.startsWith "RiscvRefinement.M31." ||
        name.toString.startsWith "RiscvRefinement.Recursion.CompactPoseidon.") && !name.isInternal then
      match information with
      | .thmInfo _ =>
          if (← findDeclarationRangesCore? name).isSome then
            logInfo m!"S31_THEOREM {name}"
            for axiomName in (← collectAxioms name) do
              logInfo m!"S31_AXIOM {name} {axiomName}"
      | _ => pure ()

#audit_s31_theorems
