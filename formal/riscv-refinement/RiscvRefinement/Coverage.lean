import RiscvRefinement.NonVacuity

namespace RiscvRefinement.Coverage

inductive PilotOpcode
  | lui
  | addi
deriving DecidableEq, Repr

def covered : List PilotOpcode := [.lui, .addi]

theorem pilot_coverage_exact :
    covered.length = 2 ∧
      covered.contains .lui ∧
      covered.contains .addi := by
  decide

end RiscvRefinement.Coverage
