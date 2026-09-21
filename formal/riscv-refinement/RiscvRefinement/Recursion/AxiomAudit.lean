import RiscvRefinement.Recursion.CompactPoseidon
import RiscvRefinement.Recursion.FrameworkBoundary
import Lean.Elab.Command
import Lean.Util.CollectAxioms

open Lean Elab Command

/-- Fresh focused audit: every public theorem in the two checked modules must
be visible and depend only on the standard logical kernel axioms. -/
elab "#audit_recursive_air" : command => do
  let environment ← getEnv
  let mut count := 0
  for (name, information) in environment.constants.toList do
    if name.toString.startsWith "RiscvRefinement.Recursion.CompactPoseidon." ||
        name.toString.startsWith "RiscvRefinement.Recursion.FrameworkBoundary." then
      match information with
      | .thmInfo _ =>
        if !name.isInternal && (← findDeclarationRangesCore? name).isSome then
          count := count + 1
          logInfo m!"RECURSIVE_AIR_THEOREM {name}"
          for axiomName in (← collectAxioms name) do
            unless axiomName == ``propext || axiomName == ``Quot.sound ||
                axiomName == ``Classical.choice do
              throwError "Unexpected kernel dependency in {name}: {axiomName}"
            logInfo m!"RECURSIVE_AIR_AXIOM {name} {axiomName}"
      | _ => pure ()
  unless count == 10 do
    throwError "Expected exactly 10 public recursive AIR theorems; found {count}"
  logInfo m!"RECURSIVE_AIR_CHECKED {count}"

#audit_recursive_air
