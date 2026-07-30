import RiscvRefinement
import Lean.Elab.Command
import Lean.Util.CollectAxioms

open Lean Elab Command

/-- Report every source-declared theorem in the development together with the
axioms it depends on.

The selection is deliberately wide: any non-internal theorem whose name starts
with `RiscvRefinement.` and which has a source declaration range. An earlier
version additionally required the declaration range to differ from the selection
range, which quietly excluded most theorems -- the audit reported 54 of 204.
A theorem the audit does not report is a theorem whose axioms nobody checks, so
the filter now excludes only compiler-internal names. -/
elab "#audit_refinement_theorems" : command => do
  let environment ← getEnv
  for (name, information) in environment.constants.toList do
    if name.toString.startsWith "RiscvRefinement." && !name.isInternal then
      match information with
      | .thmInfo _ =>
          if (← findDeclarationRangesCore? name).isSome then
            logInfo m!"REFINEMENT_THEOREM {name}"
            for axiomName in (← collectAxioms name) do
              logInfo m!"REFINEMENT_AXIOM {name} {axiomName}"
      | _ => pure ()

#audit_refinement_theorems
