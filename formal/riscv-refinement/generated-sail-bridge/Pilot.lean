import LeanRV32IM.InstsEnd
import RiscvRefinement.Sail.Generated.Pilot

/-!
Kernel-checked bridge from the pinned generated Sail instruction-clause monads
to the repository's normalized LUI/ADDI retirement capsule.

This file is intentionally outside the `RiscvRefinement` Lake library: it must
be checked with both that library and the separately generated
`Lean_RV32IM` project on `LEAN_PATH`. The refinement tooling owns that
cross-project invocation and refuses any generated backend except the pinned
one.

The final two theorems cover the exact base-instruction fragment shared by the
generated step loop: write sequential `nextPC`, execute the generated clause,
then `tick_pc`. They do not claim fetch, interrupt, trap, counter, or later-step
framing; that wider step-loop obligation remains separate.
-/

open Sail
open PreSail

namespace LeanRV32IM.Functions

open ExecutionResult
open iop
open Register
open uop

theorem execute_UTYPE_LUI_eq
    (imm : BitVec 20)
    (rd : regidx) :
    execute_UTYPE imm rd .LUI =
      (do
        wX_bits rd
          (sign_extend (m := 32) (imm +++ (0x000#12)))
        pure RETIRE_SUCCESS) := by
  rfl

theorem execute_ITYPE_ADDI_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_ITYPE imm rs1 rd .ADDI =
      (do
        let immext : xlenbits := sign_extend (m := 32) imm
        wX_bits rd ((← rX_bits rs1) + immext)
        pure RETIRE_SUCCESS) := by
  simp [execute_ITYPE]

def applyNormalizedWrite :
    Option RiscvRefinement.RegisterWrite → SailM Unit
  | none => pure ()
  | some write => wX_bits (.Regidx write.rd) write.value

@[simp]
theorem generatedLuiValue_eq
    (imm : BitVec 20) :
    sign_extend (m := 32) (imm +++ (0x000#12)) =
      RiscvRefinement.Sail.Generated.executeLuiValue imm := by
  rfl

@[simp]
theorem generatedAddiValue_eq
    (source : BitVec 32)
    (imm : BitVec 12) :
    source + sign_extend (m := 32) imm =
      RiscvRefinement.Sail.Generated.executeAddiValue source imm := by
  rfl

@[simp]
theorem wX_bits_zero
    (value : BitVec 32) :
    wX_bits (.Regidx (0#5)) value = pure () := by
  simp [wX_bits, wX, Sail.BitVec.toNatInt]

theorem execute_LUI_normalizes_write
    (pc : BitVec 32)
    (imm : BitVec 20)
    (rd : BitVec 5) :
    execute_UTYPE imm (.Regidx rd) .LUI =
      (do
        applyNormalizedWrite
          (RiscvRefinement.Sail.Generated.executeLui pc rd imm).write
        pure RETIRE_SUCCESS) := by
  by_cases h : rd = RiscvRefinement.zeroRegister
  · subst rd
    simp [
      execute_UTYPE,
      applyNormalizedWrite,
      RiscvRefinement.Sail.Generated.executeLui,
      RiscvRefinement.architecturalWrite,
      RiscvRefinement.zeroRegister,
    ]
  · simp [
      execute_UTYPE,
      applyNormalizedWrite,
      RiscvRefinement.Sail.Generated.executeLui,
      RiscvRefinement.architecturalWrite,
      h,
    ]

theorem execute_ADDI_normalizes_write
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    execute_ITYPE imm (.Regidx rs1) (.Regidx rd) .ADDI =
      (do
        let source ← rX_bits (.Regidx rs1)
        applyNormalizedWrite
          (RiscvRefinement.Sail.Generated.executeAddi
            pc source rd imm).write
        pure RETIRE_SUCCESS) := by
  by_cases h : rd = RiscvRefinement.zeroRegister
  · subst rd
    simp [
      execute_ITYPE,
      applyNormalizedWrite,
      RiscvRefinement.Sail.Generated.executeAddi,
      RiscvRefinement.architecturalWrite,
      RiscvRefinement.zeroRegister,
    ]
  · simp [
      execute_ITYPE,
      applyNormalizedWrite,
      RiscvRefinement.Sail.Generated.executeAddi,
      RiscvRefinement.architecturalWrite,
      h,
    ]

def completeBaseExecution
    (pc : BitVec 32)
    (instructionBody : SailM ExecutionResult) :
    SailM ExecutionResult := do
  PreSail.writeReg nextPC (Sail.BitVec.addInt pc 4)
  let result ← instructionBody
  tick_pc ()
  pure result

def runNormalizedRetirement
    (nextPcValue : BitVec 32)
    (write : SailM (Option RiscvRefinement.RegisterWrite)) :
    SailM ExecutionResult := do
  PreSail.writeReg nextPC nextPcValue
  applyNormalizedWrite (← write)
  tick_pc ()
  pure RETIRE_SUCCESS

def normalizedLuiWrite
    (pc : BitVec 32)
    (imm : BitVec 20)
    (rd : BitVec 5) :
    SailM (Option RiscvRefinement.RegisterWrite) :=
  pure
    (RiscvRefinement.Sail.Generated.executeLui pc rd imm).write

def normalizedAddiWrite
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    SailM (Option RiscvRefinement.RegisterWrite) := do
  let source ← rX_bits (.Regidx rs1)
  pure
    (RiscvRefinement.Sail.Generated.executeAddi pc source rd imm).write

@[simp]
theorem generatedNextPc_eq
    (pc : BitVec 32) :
    Sail.BitVec.addInt pc 4 = RiscvRefinement.nextPc pc := by
  rfl

theorem complete_LUI_normalizes
    (pc : BitVec 32)
    (imm : BitVec 20)
    (rd : BitVec 5) :
    completeBaseExecution pc
        (execute_UTYPE imm (.Regidx rd) .LUI) =
      runNormalizedRetirement (RiscvRefinement.nextPc pc)
        (normalizedLuiWrite pc imm rd) := by
  rw [execute_LUI_normalizes_write pc imm rd]
  simp [
    completeBaseExecution,
    runNormalizedRetirement,
    normalizedLuiWrite,
    RiscvRefinement.Sail.Generated.executeLui,
  ]

theorem complete_ADDI_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_ITYPE imm (.Regidx rs1) (.Regidx rd) .ADDI) =
      runNormalizedRetirement (RiscvRefinement.nextPc pc)
        (normalizedAddiWrite pc imm rs1 rd) := by
  rw [execute_ADDI_normalizes_write pc imm rs1 rd]
  simp [
    completeBaseExecution,
    runNormalizedRetirement,
    normalizedAddiWrite,
  ]

#print axioms execute_LUI_normalizes_write
#print axioms execute_ADDI_normalizes_write
#print axioms complete_LUI_normalizes
#print axioms complete_ADDI_normalizes

end LeanRV32IM.Functions
