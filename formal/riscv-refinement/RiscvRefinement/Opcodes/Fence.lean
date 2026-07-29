import RiscvRefinement.Air.Bridge.Fence
import RiscvRefinement.Bridge.DecodeTeamA

/-!
# FENCE production refinement

Under the single-hart RV32IM profile, FENCE retires as a state-only no-op. The
reserved instruction fields stay bound to the fetched word and production
program tuple, but there is no register or memory effect.

Boundary: the architectural function here is the normalized interface consumed
by the generated-Sail composition layer; this file does not itself claim the
still-open full generated step-loop framing theorem.
-/

namespace RiscvRefinement.Opcodes

open RiscvRefinement

namespace Fence

abbrev Row := Air.Bridge.Fence.Row
abbrev Admission := Air.Bridge.Fence.Admission

def execute (pc : Word) : Retirement where
  nextPc := RiscvRefinement.nextPc pc
  write := none

def word (row : Row) : InstructionWord :=
  Decode.encodeFence row.immediate row.rs1 row.rd

def programTuple (row : Row) : ProgramTuple where
  pc := row.pc
  opcodeId := 45
  rd := row.rd.toNat
  rs1 := row.rs1.toNat
  operand := row.immediate.toNat

structure Refinement (row : Row) : Prop where
  production : Air.Bridge.Fence.ProductionRefinement row
  decode :
    Decode.isFence (word row) = true ∧
      Decode.decodeIImmediate (word row) = row.immediate ∧
      Decode.decodeRs1 (word row) = row.rs1 ∧
      Decode.decodeRd (word row) = row.rd
  retirement :
    execute row.pc = {
      nextPc := RiscvRefinement.nextPc row.pc
      write := none
      read := none
      store := none
    }
  program :
    programTuple row = {
      pc := row.pc
      opcodeId := 45
      rd := row.rd.toNat
      rs1 := row.rs1.toNat
      operand := row.immediate.toNat
    }
  noRegisterOrMemoryEffect :
    (execute row.pc).write = none ∧
      (execute row.pc).read = none ∧
      (execute row.pc).store = none

theorem refines
    (row : Row)
    (admission : Admission row) :
    Refinement row := by
  refine {
    production := Air.Bridge.Fence.sound row admission
    decode := ?_
    retirement := rfl
    program := rfl
    noRegisterOrMemoryEffect := by simp [execute]
  }
  exact Decode.encode_fence_is_canonical row.immediate row.rs1 row.rd

theorem fence_exists :
    ∃ row, Admission row ∧ Refinement row :=
  ⟨Air.Bridge.Fence.exampleRow,
    Air.Bridge.Fence.exampleAdmission,
    refines
      Air.Bridge.Fence.exampleRow
      Air.Bridge.Fence.exampleAdmission⟩

end Fence

end RiscvRefinement.Opcodes
