-- Every module in the development, imported here on purpose.
--
-- `lakefile.toml` globs the whole directory so nothing goes uncompiled, but
-- the axiom audit walks the *environment*, and the environment only contains
-- what this root module transitively imports. A file that Lake compiles but
-- this root does not import would be checked for errors and never audited for
-- axioms, which is exactly the silent gap the audit exists to close.
import RiscvRefinement.Common
import RiscvRefinement.Memory
import RiscvRefinement.Mutation
import RiscvRefinement.Arith.Division
import RiscvRefinement.Bridge.Decode
import RiscvRefinement.Bridge.DecodeTeamB
import RiscvRefinement.Air.Generated.Pilot
import RiscvRefinement.Air.Family.LoadStore
import RiscvRefinement.Air.Family.Shifts
import RiscvRefinement.Air.Family.Multiply
import RiscvRefinement.Air.Family.Div
import RiscvRefinement.Sail.Generated.Pilot
import RiscvRefinement.Sail.Reviewed.LoadStore
import RiscvRefinement.Sail.Reviewed.Shifts
import RiscvRefinement.Sail.Reviewed.Multiply
import RiscvRefinement.Sail.Reviewed.Div
import RiscvRefinement.Opcodes.Lui
import RiscvRefinement.Opcodes.Addi
import RiscvRefinement.Opcodes.LoadStore
import RiscvRefinement.Opcodes.Shifts
import RiscvRefinement.Opcodes.Multiply
import RiscvRefinement.Opcodes.MultiplyMutation
import RiscvRefinement.Opcodes.Div
import RiscvRefinement.NonVacuity
import RiscvRefinement.Coverage
