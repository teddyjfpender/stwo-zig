import RiscvRefinement
import Lean.Elab.Command
import Lean.Util.CollectAxioms

open Lean Elab Command

elab "#audit_refinement_theorems" : command => do
  let environment ← getEnv
  for (name, information) in environment.constants.toList do
    if name.toString.startsWith "RiscvRefinement." then
      match information with
      | .thmInfo _ =>
          if let some ranges ← findDeclarationRangesCore? name then
            if ranges.range.pos != ranges.selectionRange.pos then do
              logInfo m!"REFINEMENT_THEOREM {name}"
              for axiomName in (← collectAxioms name) do
                logInfo m!"REFINEMENT_AXIOM {name} {axiomName}"
      | _ => pure ()

#audit_refinement_theorems
