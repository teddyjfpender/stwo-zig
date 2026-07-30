import LeanRV32IM.InstsEnd
import RiscvRefinement.Sail.Generated.Pilot

/-!
Kernel-checked bridge from the pinned generated Sail instruction-clause monads
to the repository's normalized LUI/ADDI retirement capsule, plus exact
generated-clause input bindings for every Team A selector. The control-flow
bindings cover BTYPE, JAL, JALR, and FENCE without normalizing their monadic
effects to repository retirements.

This file is intentionally outside the `RiscvRefinement` Lake library: it must
be checked with both that library and the separately generated
`Lean_RV32IM` project on `LEAN_PATH`. The refinement tooling owns that
cross-project invocation and refuses any generated backend except the pinned
one.

The final two theorems cover the exact LUI/ADDI fragment shared by the
generated step loop: write sequential `nextPC`, execute the generated clause,
then `tick_pc`. They do not claim fetch, interrupt, trap, counter, or later-step
framing. The additional selector equations below are input-binding lemmas, not
normalized retirement or full-step composition theorems.
-/

open Sail
open PreSail

namespace LeanRV32IM.Functions

open ExecutionResult
open iop
open Register
open rop
open uop
open Sail.ConcurrencyInterfaceV1

theorem execute_UTYPE_LUI_eq
    (imm : BitVec 20)
    (rd : regidx) :
    execute_UTYPE imm rd .LUI =
      (do
        wX_bits rd
          (sign_extend (m := 32) (imm +++ (0x000#12)))
        pure RETIRE_SUCCESS) := by
  simp [execute_UTYPE]

theorem execute_ITYPE_ADDI_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_ITYPE imm rs1 rd .ADDI =
      (do
        let immext : xlenbits := sign_extend (m := 32) imm
        wX_bits rd ((← rX_bits rs1) + immext)
        pure RETIRE_SUCCESS) := by
  simp [execute_ITYPE]

theorem execute_UTYPE_AUIPC_eq
    (imm : BitVec 20)
    (rd : regidx) :
    execute_UTYPE imm rd .AUIPC =
      (do
        wX_bits rd
          ((← get_arch_pc ()) +
            sign_extend (m := 32) (imm +++ (0x000#12)))
        pure RETIRE_SUCCESS) := by
  simp [execute_UTYPE]

theorem execute_ITYPE_SLTI_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_ITYPE imm rs1 rd .SLTI =
      (do
        let immext : xlenbits := sign_extend (m := 32) imm
        wX_bits rd
          (zero_extend (m := 32)
            (bool_to_bit (zopz0zI_s (← rX_bits rs1) immext)))
        pure RETIRE_SUCCESS) := by
  simp [execute_ITYPE]

theorem execute_ITYPE_SLTIU_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_ITYPE imm rs1 rd .SLTIU =
      (do
        let immext : xlenbits := sign_extend (m := 32) imm
        wX_bits rd
          (zero_extend (m := 32)
            (bool_to_bit (zopz0zI_u (← rX_bits rs1) immext)))
        pure RETIRE_SUCCESS) := by
  simp [execute_ITYPE]

theorem execute_ITYPE_ANDI_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_ITYPE imm rs1 rd .ANDI =
      (do
        let immext : xlenbits := sign_extend (m := 32) imm
        wX_bits rd ((← rX_bits rs1) &&& immext)
        pure RETIRE_SUCCESS) := by
  simp [execute_ITYPE]

theorem execute_ITYPE_ORI_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_ITYPE imm rs1 rd .ORI =
      (do
        let immext : xlenbits := sign_extend (m := 32) imm
        wX_bits rd ((← rX_bits rs1) ||| immext)
        pure RETIRE_SUCCESS) := by
  simp [execute_ITYPE]

theorem execute_ITYPE_XORI_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_ITYPE imm rs1 rd .XORI =
      (do
        let immext : xlenbits := sign_extend (m := 32) imm
        wX_bits rd ((← rX_bits rs1) ^^^ immext)
        pure RETIRE_SUCCESS) := by
  simp [execute_ITYPE]

theorem execute_RTYPE_ADD_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .ADD =
      (do
        wX_bits rd ((← rX_bits rs1) + (← rX_bits rs2))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_SUB_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .SUB =
      (do
        wX_bits rd ((← rX_bits rs1) - (← rX_bits rs2))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_XOR_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .XOR =
      (do
        wX_bits rd ((← rX_bits rs1) ^^^ (← rX_bits rs2))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_OR_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .OR =
      (do
        wX_bits rd ((← rX_bits rs1) ||| (← rX_bits rs2))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_AND_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .AND =
      (do
        wX_bits rd ((← rX_bits rs1) &&& (← rX_bits rs2))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_SLT_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .SLT =
      (do
        wX_bits rd
          (zero_extend (m := 32)
            (bool_to_bit (zopz0zI_s (← rX_bits rs1) (← rX_bits rs2))))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_SLTU_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .SLTU =
      (do
        wX_bits rd
          (zero_extend (m := 32)
            (bool_to_bit (zopz0zI_u (← rX_bits rs1) (← rX_bits rs2))))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_BTYPE_BEQ_eq
    (imm : BitVec 13)
    (rs2 rs1 : regidx) :
    execute_BTYPE imm rs2 rs1 .BEQ =
      (do
        let taken ←
          ((do
            pure ((← rX_bits rs1) == (← rX_bits rs2))) :
            SailM Bool)
        if taken
        then
          jump_to
            ((← Sail.readReg PC) + sign_extend (m := 32) imm)
        else pure RETIRE_SUCCESS) := by
  rfl

theorem execute_BTYPE_BNE_eq
    (imm : BitVec 13)
    (rs2 rs1 : regidx) :
    execute_BTYPE imm rs2 rs1 .BNE =
      (do
        let taken ←
          ((do
            pure ((← rX_bits rs1) != (← rX_bits rs2))) :
            SailM Bool)
        if taken
        then
          jump_to
            ((← Sail.readReg PC) + sign_extend (m := 32) imm)
        else pure RETIRE_SUCCESS) := by
  rfl

theorem execute_BTYPE_BLT_eq
    (imm : BitVec 13)
    (rs2 rs1 : regidx) :
    execute_BTYPE imm rs2 rs1 .BLT =
      (do
        let taken ←
          ((do
            pure
              (zopz0zI_s
                (← rX_bits rs1)
                (← rX_bits rs2))) :
            SailM Bool)
        if taken
        then
          jump_to
            ((← Sail.readReg PC) + sign_extend (m := 32) imm)
        else pure RETIRE_SUCCESS) := by
  rfl

theorem execute_BTYPE_BGE_eq
    (imm : BitVec 13)
    (rs2 rs1 : regidx) :
    execute_BTYPE imm rs2 rs1 .BGE =
      (do
        let taken ←
          ((do
            pure
              (zopz0zKzJ_s
                (← rX_bits rs1)
                (← rX_bits rs2))) :
            SailM Bool)
        if taken
        then
          jump_to
            ((← Sail.readReg PC) + sign_extend (m := 32) imm)
        else pure RETIRE_SUCCESS) := by
  rfl

theorem execute_BTYPE_BLTU_eq
    (imm : BitVec 13)
    (rs2 rs1 : regidx) :
    execute_BTYPE imm rs2 rs1 .BLTU =
      (do
        let taken ←
          ((do
            pure
              (zopz0zI_u
                (← rX_bits rs1)
                (← rX_bits rs2))) :
            SailM Bool)
        if taken
        then
          jump_to
            ((← Sail.readReg PC) + sign_extend (m := 32) imm)
        else pure RETIRE_SUCCESS) := by
  rfl

theorem execute_BTYPE_BGEU_eq
    (imm : BitVec 13)
    (rs2 rs1 : regidx) :
    execute_BTYPE imm rs2 rs1 .BGEU =
      (do
        let taken ←
          ((do
            pure
              (zopz0zKzJ_u
                (← rX_bits rs1)
                (← rX_bits rs2))) :
            SailM Bool)
        if taken
        then
          jump_to
            ((← Sail.readReg PC) + sign_extend (m := 32) imm)
        else pure RETIRE_SUCCESS) := by
  rfl

theorem execute_JAL_eq
    (imm : BitVec 21)
    (rd : regidx) :
    execute_JAL imm rd =
      (do
        let linkAddress ← get_next_pc ()
        match
          (← jump_to
            ((← Sail.readReg PC) + sign_extend (m := 32) imm))
        with
        | .Retire_Success () =>
          do
            wX_bits rd linkAddress
            pure (Retire_Success ())
        | failure => pure failure) := by
  rfl

theorem execute_JALR_eq
    (imm : BitVec 12)
    (rs1 rd : regidx) :
    execute_JALR imm rs1 rd =
      (do
        update_elp_state rs1
        let linkAddress ← get_next_pc ()
        let target ←
          pure
            ((← rX_bits rs1) +
              sign_extend (m := 32) imm)
        match
          (← jump_to (BitVec.update target 0 0#1))
        with
        | .Retire_Success () =>
          do
            wX_bits rd linkAddress
            pure (Retire_Success ())
        | failure => pure failure) := by
  rfl

theorem execute_FENCE_eq
    (fm pred succ : BitVec 4)
    (rs rd : regidx) :
    execute_FENCE fm pred succ rs rd =
      (do
        let fiom ← is_fiom_active ()
        let pred := effective_fence_set pred fiom
        let succ := effective_fence_set succ fiom
        match
          (Sail.BitVec.extractLsb pred 1 0,
            Sail.BitVec.extractLsb succ 1 0)
        with
        | (0b11, 0b11) =>
          sail_barrier Barrier_RISCV_rw_rw
        | (0b10, 0b11) =>
          sail_barrier Barrier_RISCV_r_rw
        | (0b10, 0b10) =>
          sail_barrier Barrier_RISCV_r_r
        | (0b11, 0b01) =>
          sail_barrier Barrier_RISCV_rw_w
        | (0b01, 0b01) =>
          sail_barrier Barrier_RISCV_w_w
        | (0b01, 0b11) =>
          sail_barrier Barrier_RISCV_w_rw
        | (0b11, 0b10) =>
          sail_barrier Barrier_RISCV_rw_r
        | (0b10, 0b01) =>
          sail_barrier Barrier_RISCV_r_w
        | (0b01, 0b10) =>
          sail_barrier Barrier_RISCV_w_r
        | (_, 0b00) => pure ()
        | (_, _) => pure ()
        pure RETIRE_SUCCESS) := by
  rfl

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
#print axioms execute_UTYPE_LUI_eq
#print axioms execute_UTYPE_AUIPC_eq
#print axioms execute_ITYPE_ADDI_eq
#print axioms execute_ITYPE_SLTI_eq
#print axioms execute_ITYPE_SLTIU_eq
#print axioms execute_ITYPE_ANDI_eq
#print axioms execute_ITYPE_ORI_eq
#print axioms execute_ITYPE_XORI_eq
#print axioms execute_RTYPE_ADD_eq
#print axioms execute_RTYPE_SUB_eq
#print axioms execute_RTYPE_XOR_eq
#print axioms execute_RTYPE_OR_eq
#print axioms execute_RTYPE_AND_eq
#print axioms execute_RTYPE_SLT_eq
#print axioms execute_RTYPE_SLTU_eq
#print axioms execute_BTYPE_BEQ_eq
#print axioms execute_BTYPE_BNE_eq
#print axioms execute_BTYPE_BLT_eq
#print axioms execute_BTYPE_BGE_eq
#print axioms execute_BTYPE_BLTU_eq
#print axioms execute_BTYPE_BGEU_eq
#print axioms execute_JAL_eq
#print axioms execute_JALR_eq
#print axioms execute_FENCE_eq

end LeanRV32IM.Functions
