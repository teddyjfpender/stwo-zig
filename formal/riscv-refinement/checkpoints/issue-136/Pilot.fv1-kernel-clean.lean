import LeanRV32IM.Step
import RiscvRefinement.Sail.Generated.Pilot
import RiscvRefinement.Memory

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 1_000_000
set_option linter.unusedVariables false

/-!
Kernel-checked bridge from the pinned generated Sail instruction-clause monads
to the repository retirement projection. Every admitted RV32IM selector has
an exact generated-clause equation here; these equations are the first,
source-bound stage of normalization and are intentionally kept separate from
the projection and full-step framing theorems below.

This file is intentionally outside the `RiscvRefinement` Lake library: it must
be checked with both that library and the separately generated
`Lean_RV32IM` project on `LEAN_PATH`. The refinement tooling owns that
cross-project invocation and refuses any generated backend except the pinned
one.

The bridge imports the generated `Step` module rather than a copied step
function. Consequently every theorem is checked in the same environment as
the pinned fetch/decode/execute, interrupt, trap, counter, next-PC/tick, and
later-step definitions.
-/

open Sail

namespace LeanRV32IM.Functions

open ExceptionType
open ExecutionResult
open iop
open mem_payload
open MemoryAccessType
open Register
open rop
open sop
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

theorem execute_RTYPE_SLL_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .SLL =
      (do
        wX_bits rd
          (shift_bits_left
            (← rX_bits rs1)
            (Sail.BitVec.extractLsb
              (← rX_bits rs2) (log2_xlen -i 1) 0))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_SRL_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .SRL =
      (do
        wX_bits rd
          (shift_bits_right
            (← rX_bits rs1)
            (Sail.BitVec.extractLsb
              (← rX_bits rs2) (log2_xlen -i 1) 0))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_RTYPE_SRA_eq
    (rs2 rs1 rd : regidx) :
    execute_RTYPE rs2 rs1 rd .SRA =
      (do
        wX_bits rd
          (shift_bits_right_arith
            (← rX_bits rs1)
            (Sail.BitVec.extractLsb
              (← rX_bits rs2) (log2_xlen -i 1) 0))
        pure RETIRE_SUCCESS) := by
  simp [execute_RTYPE]

theorem execute_SHIFTIOP_SLLI_eq
    (shamt : BitVec 6)
    (rs1 rd : regidx) :
    execute_SHIFTIOP shamt rs1 rd .SLLI =
      (do
        let amount :=
          Sail.BitVec.extractLsb shamt (log2_xlen -i 1) 0
        wX_bits rd (shift_bits_left (← rX_bits rs1) amount)
        pure RETIRE_SUCCESS) := by
  simp [execute_SHIFTIOP]

theorem execute_SHIFTIOP_SRLI_eq
    (shamt : BitVec 6)
    (rs1 rd : regidx) :
    execute_SHIFTIOP shamt rs1 rd .SRLI =
      (do
        let amount :=
          Sail.BitVec.extractLsb shamt (log2_xlen -i 1) 0
        wX_bits rd (shift_bits_right (← rX_bits rs1) amount)
        pure RETIRE_SUCCESS) := by
  simp [execute_SHIFTIOP]

theorem execute_SHIFTIOP_SRAI_eq
    (shamt : BitVec 6)
    (rs1 rd : regidx) :
    execute_SHIFTIOP shamt rs1 rd .SRAI =
      (do
        let amount :=
          Sail.BitVec.extractLsb shamt (log2_xlen -i 1) 0
        wX_bits rd (shift_bits_right_arith (← rX_bits rs1) amount)
        pure RETIRE_SUCCESS) := by
  simp [execute_SHIFTIOP]

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

/-! ## Exact generated constructor-to-clause bindings

These selectors are encoded by constructor fields rather than by a selector
enum inside their execute clause. The transparent clause normal forms below
reproduce the exact generated bodies and the theorems bind every admitted
field combination to them. Keeping these equations at the family clause
boundary avoids importing irrelevant disabled-extension callbacks into the
axiom footprint.
-/

noncomputable def generatedLoadClause
    (imm : BitVec 12)
    (rs1 rd : regidx)
    (isUnsigned : Bool)
    (width : Nat) :
    SailM ExecutionResult :=
  execute_LOAD imm rs1 rd isUnsigned width

theorem execute_LB_eq
    (imm : BitVec 12) (rs1 rd : regidx) :
    execute_LOAD imm rs1 rd false 1 =
      generatedLoadClause imm rs1 rd false 1 := by
  rfl

theorem execute_LH_eq
    (imm : BitVec 12) (rs1 rd : regidx) :
    execute_LOAD imm rs1 rd false 2 =
      generatedLoadClause imm rs1 rd false 2 := by
  rfl

theorem execute_LW_eq
    (imm : BitVec 12) (rs1 rd : regidx) :
    execute_LOAD imm rs1 rd false 4 =
      generatedLoadClause imm rs1 rd false 4 := by
  rfl

theorem execute_LBU_eq
    (imm : BitVec 12) (rs1 rd : regidx) :
    execute_LOAD imm rs1 rd true 1 =
      generatedLoadClause imm rs1 rd true 1 := by
  rfl

theorem execute_LHU_eq
    (imm : BitVec 12) (rs1 rd : regidx) :
    execute_LOAD imm rs1 rd true 2 =
      generatedLoadClause imm rs1 rd true 2 := by
  rfl

noncomputable def generatedStoreClause
    (imm : BitVec 12)
    (rs2 rs1 : regidx)
    (width : Nat) :
    SailM ExecutionResult :=
  execute_STORE imm rs2 rs1 width

theorem execute_SB_eq
    (imm : BitVec 12) (rs2 rs1 : regidx) :
    execute_STORE imm rs2 rs1 1 =
      generatedStoreClause imm rs2 rs1 1 := by
  rfl

theorem execute_SH_eq
    (imm : BitVec 12) (rs2 rs1 : regidx) :
    execute_STORE imm rs2 rs1 2 =
      generatedStoreClause imm rs2 rs1 2 := by
  rfl

theorem execute_SW_eq
    (imm : BitVec 12) (rs2 rs1 : regidx) :
    execute_STORE imm rs2 rs1 4 =
      generatedStoreClause imm rs2 rs1 4 := by
  rfl

def mulSelectorLowSigned : mul_op where
  result_part := .Low
  signed_rs1 := .Signed
  signed_rs2 := .Signed

def mulSelectorHighSigned : mul_op where
  result_part := .High
  signed_rs1 := .Signed
  signed_rs2 := .Signed

def mulSelectorHighSignedUnsigned : mul_op where
  result_part := .High
  signed_rs1 := .Signed
  signed_rs2 := .Unsigned

def mulSelectorHighUnsigned : mul_op where
  result_part := .High
  signed_rs1 := .Unsigned
  signed_rs2 := .Unsigned

def generatedMulClause
    (rs2 rs1 rd : regidx)
    (selector : mul_op) :
    SailM ExecutionResult := do
  let source1 ← rX_bits rs1
  let source2 ← rX_bits rs2
  wX_bits rd
    (mult_to_bits_half
      selector.signed_rs1 selector.signed_rs2
      source1 source2 selector.result_part)
  pure RETIRE_SUCCESS

theorem execute_MUL_eq
    (rs2 rs1 rd : regidx) :
    execute_MUL rs2 rs1 rd mulSelectorLowSigned =
      generatedMulClause rs2 rs1 rd mulSelectorLowSigned := by
  rfl

theorem execute_MULH_eq
    (rs2 rs1 rd : regidx) :
    execute_MUL rs2 rs1 rd mulSelectorHighSigned =
      generatedMulClause rs2 rs1 rd mulSelectorHighSigned := by
  rfl

theorem execute_MULHSU_eq
    (rs2 rs1 rd : regidx) :
    execute_MUL rs2 rs1 rd mulSelectorHighSignedUnsigned =
      generatedMulClause rs2 rs1 rd
        mulSelectorHighSignedUnsigned := by
  rfl

theorem execute_MULHU_eq
    (rs2 rs1 rd : regidx) :
    execute_MUL rs2 rs1 rd mulSelectorHighUnsigned =
      generatedMulClause rs2 rs1 rd mulSelectorHighUnsigned := by
  rfl

def generatedDivClause
    (rs2 rs1 rd : regidx)
    (isUnsigned : Bool) :
    SailM ExecutionResult := do
  let source1 ← rX_bits rs1
  let source2 ← rX_bits rs2
  let dividend :=
    if isUnsigned
    then BitVec.toNatInt source1
    else BitVec.toInt source1
  let divisor :=
    if isUnsigned
    then BitVec.toNatInt source2
    else BitVec.toInt source2
  let quotient :=
    if divisor == 0
    then -1
    else Int.tdiv dividend divisor
  let quotient :=
    if (!isUnsigned) && (quotient ≥b (2 ^i (xlen -i 1)))
    then -(2 ^i (xlen -i 1))
    else quotient
  wX_bits rd (to_bits_truncate (l := 32) quotient)
  pure RETIRE_SUCCESS

def generatedDivValue
    (rs2 rs1 : regidx)
    (isUnsigned : Bool) :
    SailM (BitVec 32) := do
  let source1 ← rX_bits rs1
  let source2 ← rX_bits rs2
  let dividend :=
    if isUnsigned
    then BitVec.toNatInt source1
    else BitVec.toInt source1
  let divisor :=
    if isUnsigned
    then BitVec.toNatInt source2
    else BitVec.toInt source2
  let quotient :=
    if divisor == 0
    then -1
    else Int.tdiv dividend divisor
  let quotient :=
    if (!isUnsigned) && (quotient ≥b (2 ^i (xlen -i 1)))
    then -(2 ^i (xlen -i 1))
    else quotient
  pure (to_bits_truncate (l := 32) quotient)

theorem execute_DIV_eq
    (rs2 rs1 rd : regidx) :
    execute_DIV rs2 rs1 rd false =
      generatedDivClause rs2 rs1 rd false := by
  rfl

theorem execute_DIVU_eq
    (rs2 rs1 rd : regidx) :
    execute_DIV rs2 rs1 rd true =
      generatedDivClause rs2 rs1 rd true := by
  rfl

def generatedRemClause
    (rs2 rs1 rd : regidx)
    (isUnsigned : Bool) :
    SailM ExecutionResult := do
  let source1 ← rX_bits rs1
  let source2 ← rX_bits rs2
  let dividend :=
    if isUnsigned
    then BitVec.toNatInt source1
    else BitVec.toInt source1
  let divisor :=
    if isUnsigned
    then BitVec.toNatInt source2
    else BitVec.toInt source2
  let remainder :=
    if divisor == 0
    then dividend
    else Int.tmod dividend divisor
  wX_bits rd (to_bits_truncate (l := 32) remainder)
  pure RETIRE_SUCCESS

def generatedRemValue
    (rs2 rs1 : regidx)
    (isUnsigned : Bool) :
    SailM (BitVec 32) := do
  let source1 ← rX_bits rs1
  let source2 ← rX_bits rs2
  let dividend :=
    if isUnsigned
    then BitVec.toNatInt source1
    else BitVec.toInt source1
  let divisor :=
    if isUnsigned
    then BitVec.toNatInt source2
    else BitVec.toInt source2
  let remainder :=
    if divisor == 0
    then dividend
    else Int.tmod dividend divisor
  pure (to_bits_truncate (l := 32) remainder)

theorem execute_REM_eq
    (rs2 rs1 rd : regidx) :
    execute_REM rs2 rs1 rd false =
      generatedRemClause rs2 rs1 rd false := by
  rfl

theorem execute_REMU_eq
    (rs2 rs1 rd : regidx) :
    execute_REM rs2 rs1 rd true =
      generatedRemClause rs2 rs1 rd true := by
  rfl

/-! ## Shared exact generated-step framing

`generatedFullStepFrame` is a transparent normalization of the generated
`try_step` definition: it does not replace any generated operation. In
particular, `run_hart_active` remains the exact generated interrupt/fetch/
decode/execute path, while the postlude below preserves every generated trap,
counter, next-PC/tick, RVFI, callback, and later-step-relevant state effect.
The equality theorem therefore fails at the kernel if the generated orchestration
changes, even when all instruction clauses remain textually unchanged.
-/

noncomputable def generatedFullStepPostlude
    (step_val : Step) :
    SailM Bool := do
  match step_val with
  | .Step_Pending_Interrupt (intr, priv) =>
    (do
      let _ : Unit :=
        if ((get_config_print_instr ()) : Bool)
        then (print_bits "Handling interrupt: " (interruptType_bits_forwards intr))
        else ()
      (handle_interrupt intr priv))
  | .Step_Ext_Fetch_Failure e => (pure (ext_handle_fetch_check_error e))
  | .Step_Fetch_Failure (vaddr, e) => (handle_exception (bits_of_virtaddr vaddr) e)
  | .Step_Waiting _ =>
    assert (hart_is_waiting (← readReg hart_state)) "cannot be Waiting in a non-Wait state"
  | .Step_Execute (.Retire_Success (), _) =>
    assert (hart_is_active (← readReg hart_state)) "postlude/step.sail:219.74-219.75"
  | .Step_Execute (.ExecuteAs _, _) =>
    (internal_error "postlude/step.sail" 223
      "Multiple chained ExecuteAs (only one redirection is supported).")
  | .Step_Execute (.Trap (priv, exc, pc), _) => (set_next_pc (← (exception_handler priv exc pc)))
  | .Step_Execute (.Illegal_Instruction (), instbits) =>
    (handle_exception (zero_extend (m := 32) instbits) (E_Illegal_Instr ()))
  | .Step_Execute (.Virtual_Instruction (), instbits) =>
    (handle_exception (zero_extend (m := 32) instbits) (E_Virtual_Instr ()))
  | .Step_Execute (.Enter_Wait wr, instbits) =>
    (do
      if ((wait_is_nop wr) : Bool)
      then assert (hart_is_active (← readReg hart_state)) "postlude/step.sail:232.41-232.42"
      else
        (do
          if ((get_config_print_instr ()) : Bool)
          then
            (pure (print_endline
                (HAppend.hAppend "entering "
                  (HAppend.hAppend (wait_name_forwards wr)
                    (HAppend.hAppend " state at PC " (BitVec.toFormatted (← readReg PC)))))))
          else (pure ())
          writeReg hart_state (HartState.HART_WAITING (wr, instbits))))
  | .Step_Execute (.Ext_CSR_Check_Failure (), _) => (pure (ext_check_CSR_fail ()))
  | .Step_Execute (.Ext_ControlAddr_Check_Failure e, _) => (pure (ext_handle_control_check_error e))
  | .Step_Execute (.Ext_DataAddr_Check_Failure e, _) => (pure (ext_handle_data_check_error e))
  | .Step_Execute (.Ext_XRET_Priv_Failure (), _) => (pure (ext_fail_xret_priv ()))
  match (← readReg hart_state) with
  | .HART_WAITING _ => (pure true)
  | .HART_ACTIVE () =>
    (do
      (tick_pc ())
      let retired : Bool :=
        match step_val with
        | .Step_Execute (.Retire_Success (), g__0) => true
        | .Step_Execute (.Enter_Wait wr, g__1) =>
          (if ((wait_is_nop wr) : Bool)
          then true
          else false)
        | _ => false
      if ((retired && (← readReg minstret_increment)) : Bool)
      then writeReg minstret (BitVec.addInt (← readReg minstret) 1)
      else (pure ())
      if ((get_config_rvfi ()) : Bool)
      then
        writeReg rvfi_pc_data (Sail.BitVec.updateSubrange (← readReg rvfi_pc_data) 127 64
          (zero_extend (m := 64) (← (get_arch_pc ()))))
      else (pure ())
      let _ : Unit := (ext_post_step_hook ())
      let _ : Unit :=
        if (retired : Bool)
        then (instret_callback ())
        else ()
      (pure false))

noncomputable def generatedFullStepFrame
    (step_no : Nat)
    (exit_wait : Bool) :
    SailM Bool := do
  let _ : Unit := (ext_pre_step_hook ())
  writeReg minstret_increment (← (should_inc_minstret (← readReg cur_privilege)))
  let step_val ← (( do
    match (← readReg hart_state) with
    | .HART_WAITING (wr, instbits) => (run_hart_waiting step_no wr instbits exit_wait)
    | .HART_ACTIVE () => (run_hart_active step_no) ) : SailM Step )
  generatedFullStepPostlude step_val

theorem generated_full_step_frame
    (step_no : Nat)
    (exit_wait : Bool) :
    try_step step_no exit_wait =
      generatedFullStepFrame step_no exit_wait := by
  rfl

/-- The exact generated full step with its interrupt/fetch/execute outcome
retained in the return value.  Erasing the second component is proved below to
be the generated `try_step`; no raw state component is changed. -/
noncomputable def generatedFullStepWithOutcome
    (step_no : Nat)
    (exit_wait : Bool) :
    SailM (Bool × Step) := do
  let _ : Unit := (ext_pre_step_hook ())
  writeReg minstret_increment (← (should_inc_minstret (← readReg cur_privilege)))
  let step_val ← (( do
    match (← readReg hart_state) with
    | .HART_WAITING (wr, instbits) => (run_hart_waiting step_no wr instbits exit_wait)
    | .HART_ACTIVE () => (run_hart_active step_no) ) : SailM Step )
  let waiting ← generatedFullStepPostlude step_val
  pure (waiting, step_val)

def eraseFullStepOutcome
    (program : SailM (Bool × Step)) :
    SailM Bool := do
  pure (← program).1

theorem eraseFullStepOutcome_run
    (program : SailM (Bool × Step))
    (initial final :
      PreSail.SequentialState RegisterType Sail.trivialChoiceSource)
    (waiting : Bool)
    (stepValue : Step)
    (outcome :
      program initial = .ok (waiting, stepValue) final) :
    eraseFullStepOutcome program initial = .ok waiting final := by
  unfold eraseFullStepOutcome
  simp only [bind, EStateM.bind, pure, EStateM.pure, outcome]

theorem generatedFullStepWithOutcome_erases
    (step_no : Nat)
    (exit_wait : Bool) :
    eraseFullStepOutcome
        (generatedFullStepWithOutcome step_no exit_wait) =
      generatedFullStepFrame step_no exit_wait := by
  simp [
    eraseFullStepOutcome,
    generatedFullStepWithOutcome,
    generatedFullStepFrame,
  ]

/-! ## Exact state-monad retirement projection

The generated backend does not use an abstract or axiomatized transition
relation: `SailM` is the concrete `EStateM` supplied by `lean-sail`.  We can
therefore attach the repository retirement observation to an exact generated
execution without replacing any of its effects.  `observeExecution` snapshots
the real pre-state, runs the real generated program, snapshots its real
post-state, and returns the projection alongside the generated result.  The
erasure theorem below proves that this instrumentation preserves the complete
raw post-state, not merely the four fields retained by `Retirement`.

That preservation is what makes the projection suitable for later-step
framing: a following generated `try_step` receives definitionally the same
state as it would have received without observation.
-/

abbrev GeneratedState :=
  PreSail.SequentialState RegisterType Sail.trivialChoiceSource

structure ObservedExecution (α : Type) where
  generatedResult : α
  retirement : Option RiscvRefinement.Retirement

def runGeneratedValue?
    (action : SailM α)
    (state : GeneratedState) :
    Option α :=
  match action state with
  | .ok value _ => some value
  | .error _ _ => none

def generatedPc? (state : GeneratedState) :
    Option RiscvRefinement.Word :=
  runGeneratedValue? (Sail.readReg PC) state

def generatedX?
    (index : BitVec 5)
    (state : GeneratedState) :
    Option RiscvRefinement.Word :=
  runGeneratedValue? (rX_bits (.Regidx index)) state

def generatedMemoryWord?
    (address : RiscvRefinement.Word)
    (state : GeneratedState) :
    Option RiscvRefinement.Word :=
  match
    (PreSail.readBytes 4 address.toNat :
      SailM ((BitVec (8 * 4)) × Option Bool)) state
  with
  | .ok (value, _) _ => some value
  | .error _ _ => none

def projectRegisterRetirement
    (rd : BitVec 5)
    (_initial final : GeneratedState) :
    Option RiscvRefinement.Retirement := do
  let nextPcValue ← generatedPc? final
  let value ← generatedX? rd final
  pure {
    nextPc := nextPcValue
    write := RiscvRefinement.architecturalWrite rd value
    read := none
    store := none
  }

def projectNoWriteRetirement
    (_initial final : GeneratedState) :
    Option RiscvRefinement.Retirement := do
  let nextPcValue ← generatedPc? final
  pure {
    nextPc := nextPcValue
    write := none
    read := none
    store := none
  }

def projectLoadRetirement
    (rs1 rd : BitVec 5)
    (imm : BitVec 12)
    (initial final : GeneratedState) :
    Option RiscvRefinement.Retirement := do
  let nextPcValue ← generatedPc? final
  let base ← generatedX? rs1 initial
  let value ← generatedX? rd final
  let effectiveAddress :=
    RiscvRefinement.Memory.effectiveAddress base imm
  let address := RiscvRefinement.Memory.busAddress effectiveAddress
  let memoryValue ← generatedMemoryWord? address initial
  pure {
    nextPc := nextPcValue
    write := RiscvRefinement.architecturalWrite rd value
    read := some { address, value := memoryValue }
    store := none
  }

def storeMask
    (width : Nat)
    (effectiveAddress : RiscvRefinement.Word) :
    RiscvRefinement.ByteMask :=
  match width with
  | 1 =>
      RiscvRefinement.Memory.byteMask
        (RiscvRefinement.Memory.byteOffset effectiveAddress)
  | 2 =>
      RiscvRefinement.Memory.halfMask
        (RiscvRefinement.Memory.halfSelector effectiveAddress)
  | _ => RiscvRefinement.Memory.wordMask

def projectStoreRetirement
    (rs1 : BitVec 5)
    (imm : BitVec 12)
    (width : Nat)
    (initial final : GeneratedState) :
    Option RiscvRefinement.Retirement := do
  let nextPcValue ← generatedPc? final
  let base ← generatedX? rs1 initial
  let effectiveAddress :=
    RiscvRefinement.Memory.effectiveAddress base imm
  let address := RiscvRefinement.Memory.busAddress effectiveAddress
  let memoryValue ← generatedMemoryWord? address final
  pure {
    nextPc := nextPcValue
    write := none
    read := none
    store := some {
      address
      mask := storeMask width effectiveAddress
      value := memoryValue
    }
  }

def observeExecution
    (projection : GeneratedState → GeneratedState →
      Option RiscvRefinement.Retirement)
    (program : SailM α) :
    SailM (ObservedExecution α) :=
  fun initial =>
    match program initial with
    | .ok result final =>
        .ok {
          generatedResult := result
          retirement := projection initial final
        } final
    | .error error final => .error error final

def eraseObservation
    (program : SailM (ObservedExecution α)) :
    SailM α :=
  fun initial =>
    match program initial with
    | .ok observed final => .ok observed.generatedResult final
    | .error error final => .error error final

theorem observeExecution_erases
    (projection : GeneratedState → GeneratedState →
      Option RiscvRefinement.Retirement)
    (program : SailM α) :
    eraseObservation (observeExecution projection program) = program := by
  funext initial
  cases h : program initial <;>
    simp [eraseObservation, observeExecution, h]

def normalizedRegisterExecution
    (rd : BitVec 5)
    (program : SailM α) :
    SailM (ObservedExecution α) :=
  observeExecution (projectRegisterRetirement rd) program

def normalizedNoWriteExecution
    (program : SailM α) :
    SailM (ObservedExecution α) :=
  observeExecution projectNoWriteRetirement program

def normalizedLoadExecution
    (rs1 rd : BitVec 5)
    (imm : BitVec 12)
    (program : SailM α) :
    SailM (ObservedExecution α) :=
  observeExecution (projectLoadRetirement rs1 rd imm) program

def normalizedStoreExecution
    (rs1 : BitVec 5)
    (imm : BitVec 12)
    (width : Nat)
    (program : SailM α) :
    SailM (ObservedExecution α) :=
  observeExecution (projectStoreRetirement rs1 imm width) program

theorem normalizedRegisterExecution_erases
    (rd : BitVec 5)
    (program : SailM α) :
    eraseObservation (normalizedRegisterExecution rd program) = program :=
  observeExecution_erases _ _

theorem normalizedNoWriteExecution_erases
    (program : SailM α) :
    eraseObservation (normalizedNoWriteExecution program) = program :=
  observeExecution_erases _ _

theorem normalizedLoadExecution_erases
    (rs1 rd : BitVec 5)
    (imm : BitVec 12)
    (program : SailM α) :
    eraseObservation
        (normalizedLoadExecution rs1 rd imm program) =
      program :=
  observeExecution_erases _ _

theorem normalizedStoreExecution_erases
    (rs1 : BitVec 5)
    (imm : BitVec 12)
    (width : Nat)
    (program : SailM α) :
    eraseObservation
        (normalizedStoreExecution rs1 imm width program) =
      program :=
  observeExecution_erases _ _

noncomputable def continueAfterRawFullStep
    (step_no : Nat)
    (exit_wait : Bool)
    (laterStepNo : Nat)
    (laterExitWait : Bool) :
    SailM Bool := do
  let _ ← try_step step_no exit_wait
  try_step laterStepNo laterExitWait

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

/-!
`completeRegisterEffects` is the semantic normalization used by every
successful register-writing clause below.  Unlike a post-state projection, it
records the repository `Retirement` from the exact operand value read by the
generated clause before that value is discarded by the generated
`ExecutionResult`.  Its erasure theorem therefore needs no final-state or
expected-retirement premise.
-/

noncomputable def completeRegisterEffects
    (pc : BitVec 32)
    (rd : BitVec 5)
    (value : SailM (BitVec 32)) :
    SailM (BitVec 32) := do
  PreSail.writeReg nextPC (Sail.BitVec.addInt pc 4)
  let result ← value
  wX_bits (.Regidx rd) result
  tick_pc ()
  pure result

noncomputable def normalizedRegisterCompletion
    (pc : BitVec 32)
    (rd : BitVec 5)
    (value : SailM (BitVec 32)) :
    SailM (ObservedExecution ExecutionResult) := do
  let result ← completeRegisterEffects pc rd value
  pure {
    generatedResult := RETIRE_SUCCESS
    retirement := some {
      nextPc := RiscvRefinement.nextPc pc
      write := RiscvRefinement.architecturalWrite rd result
      read := none
      store := none
    }
  }

theorem normalizedRegisterCompletion_erases
    (pc : BitVec 32)
    (rd : BitVec 5)
    (value : SailM (BitVec 32)) :
    eraseObservation
        (normalizedRegisterCompletion pc rd value) =
      (do
        let _ ← completeRegisterEffects pc rd value
        pure RETIRE_SUCCESS) := by
  funext initial
  cases result :
      completeRegisterEffects pc rd value initial <;>
    simp [
      eraseObservation,
      normalizedRegisterCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      result,
    ]

noncomputable def completeBranchEffects
    (pc : BitVec 32)
    (condition : SailM Bool)
    (target : SailM (BitVec 32)) :
    SailM (ExecutionResult × BitVec 32) := do
  PreSail.writeReg nextPC (Sail.BitVec.addInt pc 4)
  let taken ← condition
  let outcome ←
    if taken then
      (do
        let targetPc ← target
        let result ← jump_to targetPc
        pure (result, targetPc))
    else
      pure (RETIRE_SUCCESS, RiscvRefinement.nextPc pc)
  tick_pc ()
  pure outcome

noncomputable def normalizedBranchCompletion
    (pc : BitVec 32)
    (condition : SailM Bool)
    (target : SailM (BitVec 32)) :
    SailM (ObservedExecution ExecutionResult) := do
  let (result, nextPcValue) ←
    completeBranchEffects pc condition target
  pure {
    generatedResult := result
    retirement :=
      match result with
      | .Retire_Success () =>
          some {
            nextPc := nextPcValue
            write := none
            read := none
            store := none
          }
      | _ => none
  }

theorem normalizedBranchCompletion_erases
    (pc : BitVec 32)
    (condition : SailM Bool)
    (target : SailM (BitVec 32)) :
    eraseObservation
        (normalizedBranchCompletion pc condition target) =
      (do
        let (result, _) ← completeBranchEffects pc condition target
        pure result) := by
  funext initial
  cases outcome :
      completeBranchEffects pc condition target initial <;>
    simp [
      eraseObservation,
      normalizedBranchCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      outcome,
    ]

noncomputable def normalizedSequentialNoWriteCompletion
    (pc : BitVec 32)
    (body : SailM ExecutionResult) :
    SailM (ObservedExecution ExecutionResult) := do
  let result ← completeBaseExecution pc body
  pure {
    generatedResult := result
    retirement :=
      match result with
      | .Retire_Success () =>
          some {
            nextPc := RiscvRefinement.nextPc pc
            write := none
            read := none
            store := none
          }
      | _ => none
  }

theorem normalizedSequentialNoWriteCompletion_erases
    (pc : BitVec 32)
    (body : SailM ExecutionResult) :
    eraseObservation
        (normalizedSequentialNoWriteCompletion pc body) =
      completeBaseExecution pc body := by
  funext initial
  cases outcome : completeBaseExecution pc body initial <;>
    simp [
      eraseObservation,
      normalizedSequentialNoWriteCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      outcome,
    ]

noncomputable def completeJumpEffects
    (pc : BitVec 32)
    (rd : BitVec 5)
    (before : SailM Unit)
    (target : SailM (BitVec 32)) :
    SailM (ExecutionResult × BitVec 32 × BitVec 32) := do
  PreSail.writeReg nextPC (Sail.BitVec.addInt pc 4)
  before
  let linkAddress ← get_next_pc ()
  let targetPc ← target
  let result ← jump_to targetPc
  match result with
  | .Retire_Success () =>
      wX_bits (.Regidx rd) linkAddress
  | _ => pure ()
  tick_pc ()
  pure (result, targetPc, linkAddress)

noncomputable def normalizedJumpCompletion
    (pc : BitVec 32)
    (rd : BitVec 5)
    (before : SailM Unit)
    (target : SailM (BitVec 32)) :
    SailM (ObservedExecution ExecutionResult) := do
  let (result, targetPc, linkAddress) ←
    completeJumpEffects pc rd before target
  pure {
    generatedResult := result
    retirement :=
      match result with
      | .Retire_Success () =>
          some {
            nextPc := targetPc
            write :=
              RiscvRefinement.architecturalWrite rd linkAddress
            read := none
            store := none
          }
      | _ => none
  }

theorem normalizedJumpCompletion_erases
    (pc : BitVec 32)
    (rd : BitVec 5)
    (before : SailM Unit)
    (target : SailM (BitVec 32)) :
    eraseObservation
        (normalizedJumpCompletion pc rd before target) =
      (do
        let (result, _, _) ←
          completeJumpEffects pc rd before target
        pure result) := by
  funext initial
  cases outcome :
      completeJumpEffects pc rd before target initial <;>
    simp [
      eraseObservation,
      normalizedJumpCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      outcome,
    ]

noncomputable def completeLoadEffects
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (isUnsigned : Bool)
    (width : Nat) :
    SailM
      (ExecutionResult ×
        Option (BitVec 32)) := do
  PreSail.writeReg nextPC (Sail.BitVec.addInt pc 4)
  let offset : xlenbits := sign_extend (m := 32) imm
  assert (width ≤b xlen_bytes)
    "extensions/I/base_insts.sail:289.28-289.29"
  let loadResult ←
    vmem_read (.Regidx rs1) offset width
      (Load Data) false false false
  let resultAndValue ←
    match loadResult with
    | .Ok data =>
        (do
          let value := extend_value isUnsigned data
          wX_bits (.Regidx rd) value
          pure (RETIRE_SUCCESS, some value))
    | .Err error => pure (error, none)
  tick_pc ()
  pure resultAndValue

noncomputable def normalizedLoadCompletion
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (isUnsigned : Bool)
    (width : Nat) :
    SailM (ObservedExecution ExecutionResult) := do
  let initial ← get
  let (result, loadedValue) ←
    completeLoadEffects pc imm rs1 rd isUnsigned width
  pure {
    generatedResult := result
    retirement := do
      let value ← loadedValue
      let base ← generatedX? rs1 initial
      let effectiveAddress :=
        RiscvRefinement.Memory.effectiveAddress base imm
      let address :=
        RiscvRefinement.Memory.busAddress effectiveAddress
      let memoryValue ← generatedMemoryWord? address initial
      pure {
        nextPc := RiscvRefinement.nextPc pc
        write :=
          RiscvRefinement.architecturalWrite rd value
        read := some { address, value := memoryValue }
        store := none
      }
  }

theorem normalizedLoadCompletion_erases
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (isUnsigned : Bool)
    (width : Nat) :
    eraseObservation
      (normalizedLoadCompletion
          pc imm rs1 rd isUnsigned width) =
      (do
        let (result, _) ←
          completeLoadEffects pc imm rs1 rd isUnsigned width
        pure result) := by
  funext initial
  cases outcome :
      completeLoadEffects
        pc imm rs1 rd isUnsigned width initial <;>
    simp [
      eraseObservation,
      normalizedLoadCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
      outcome,
    ]

def generatedWordBytes
    (value : RiscvRefinement.Word) :
    RiscvRefinement.WordBytes where
  limb0 := BitVec.extractLsb 7 0 value
  limb1 := BitVec.extractLsb 15 8 value
  limb2 := BitVec.extractLsb 23 16 value
  limb3 := BitVec.extractLsb 31 24 value

def generatedStorePayload
    (width : Nat)
    (source : RiscvRefinement.Word) :
    RiscvRefinement.WordBytes :=
  match width with
  | 1 =>
      let byte := BitVec.extractLsb 7 0 source
      {
        limb0 := byte
        limb1 := byte
        limb2 := byte
        limb3 := byte
      }
  | 2 =>
      let low := BitVec.extractLsb 7 0 source
      let high := BitVec.extractLsb 15 8 source
      {
        limb0 := low
        limb1 := high
        limb2 := low
        limb3 := high
      }
  | _ => generatedWordBytes source

noncomputable def completeStoreEffects
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5)
    (width : Nat) :
    SailM
      (ExecutionResult ×
        Option (BitVec 32)) := do
  PreSail.writeReg nextPC (Sail.BitVec.addInt pc 4)
  let offset : xlenbits := sign_extend (m := 32) imm
  assert (width ≤b xlen_bytes)
    "extensions/I/base_insts.sail:320.28-320.29"
  let source ← rX_bits (.Regidx rs2)
  let data :=
    Sail.BitVec.extractLsb source
      ((width *i 8) -i 1) 0
  let storeResult ←
    vmem_write (.Regidx rs1) offset width data
      (Store Data) false false false
  let resultAndSource :=
    match storeResult with
    | .Ok _ => (RETIRE_SUCCESS, some source)
    | .Err error => (error, none)
  tick_pc ()
  pure resultAndSource

noncomputable def normalizedStoreCompletion
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5)
    (width : Nat) :
    SailM (ObservedExecution ExecutionResult) := do
  let initial ← get
  let (result, storedSource) ←
    completeStoreEffects pc imm rs2 rs1 width
  pure {
    generatedResult := result
    retirement := do
      let source ← storedSource
      let base ← generatedX? rs1 initial
      let effectiveAddress :=
        RiscvRefinement.Memory.effectiveAddress base imm
      let address :=
        RiscvRefinement.Memory.busAddress effectiveAddress
      let originalWord ← generatedMemoryWord? address initial
      let original := generatedWordBytes originalWord
      let mask := storeMask width effectiveAddress
      let payload := generatedStorePayload width source
      pure {
        nextPc := RiscvRefinement.nextPc pc
        write := none
        read := none
        store := some {
          address
          mask
          value :=
            (RiscvRefinement.Memory.applyMask
              original payload mask).word
        }
      }
  }

theorem normalizedStoreCompletion_erases
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5)
    (width : Nat) :
    eraseObservation
        (normalizedStoreCompletion
          pc imm rs2 rs1 width) =
      (do
        let (result, _) ←
          completeStoreEffects pc imm rs2 rs1 width
        pure result) := by
  funext initial
  cases outcome :
      completeStoreEffects
        pc imm rs2 rs1 width initial <;>
    simp [
      eraseObservation,
      normalizedStoreCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
      outcome,
    ]

@[simp]
theorem sailMap_if
    {condition : Prop}
    [Decidable condition]
    (mapValue : α → β)
    (whenTrue whenFalse : SailM α) :
    mapValue <$> (if condition then whenTrue else whenFalse) =
      (if condition then
        mapValue <$> whenTrue
      else
        mapValue <$> whenFalse) := by
  by_cases condition <;> simp_all

@[simp]
theorem sailBind_if
    {condition : Prop}
    [Decidable condition]
    (whenTrue whenFalse : SailM α)
    (next : α → SailM β) :
    (if condition then whenTrue else whenFalse) >>= next =
      (if condition then
        whenTrue >>= next
      else
        whenFalse >>= next) := by
  by_cases condition <;> simp_all

@[simp]
theorem sailMap_matchExecutionResult
    (result : ExecutionResult)
    (mapValue : α → β)
    (onSuccess : SailM α)
    (onOther : ExecutionResult → SailM α) :
    mapValue <$>
        (match result with
        | .Retire_Success () => onSuccess
        | other => onOther other) =
      (match result with
      | .Retire_Success () => mapValue <$> onSuccess
      | other => mapValue <$> onOther other) := by
  cases result <;> rfl

@[simp]
theorem sailBind_matchExecutionResult
    (result : ExecutionResult)
    (onSuccess : SailM α)
    (onOther : ExecutionResult → SailM α)
    (next : α → SailM β) :
    (match result with
      | .Retire_Success () => onSuccess
      | other => onOther other) >>= next =
      (match result with
      | .Retire_Success () => onSuccess >>= next
      | other => onOther other >>= next) := by
  cases result <;> rfl

@[simp]
theorem matchExecutionResult_returns_scrutinee
    (result : ExecutionResult)
    (successEffect after : SailM Unit) :
    (match result with
      | .Retire_Success () =>
          do
            successEffect
            after
            pure RETIRE_SUCCESS
      | other =>
          do
            after
            pure other) =
      (match result with
      | .Retire_Success () =>
          do
            successEffect
            after
            pure result
      | _ =>
          do
            after
            pure result) := by
  cases result <;> rfl

@[simp]
theorem bindExecutionResult_returns_scrutinee
    (action : SailM ExecutionResult)
    (successEffect after : SailM Unit) :
    (do
      let result ← action
      match result with
      | .Retire_Success () =>
          do
            successEffect
            after
            pure RETIRE_SUCCESS
      | other =>
          do
            after
            pure other) =
      (do
        let result ← action
        match result with
        | .Retire_Success () =>
            do
              successEffect
              after
              pure result
        | _ =>
            do
              after
              pure result) := by
  apply bind_congr
  intro result
  exact
    matchExecutionResult_returns_scrutinee
      result successEffect after

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

/-! ## Per-selector exact generated retirement observations

The two pilot theorems above additionally reduce the generated arithmetic to
closed LUI/ADDI value functions. Every remaining selector below executes an
opcode-shaped normalized monad containing the generated operand reads and
effects, and constructs the repository `Retirement` from those generated
values. The erasure theorems establish equality with the exact generated
clause plus the base next-PC/tick framing. In particular, none of the public
theorems assumes a post-state equality or obtains its result merely by
observing and then erasing an arbitrary input program.

The stable public theorem names below are the 46-entry FV-1 inventory.
-/

theorem complete_ADD_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .ADD) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (source1 + source2))) := by
  rw [execute_RTYPE_ADD_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SUB_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .SUB) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (source1 - source2))) := by
  rw [execute_RTYPE_SUB_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SLL_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .SLL) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (shift_bits_left source1
                (Sail.BitVec.extractLsb
                  source2 (log2_xlen -i 1) 0)))) := by
  rw [execute_RTYPE_SLL_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SLT_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .SLT) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (zero_extend (m := 32)
                (bool_to_bit (zopz0zI_s source1 source2))))) := by
  rw [execute_RTYPE_SLT_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SLTU_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .SLTU) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (zero_extend (m := 32)
                (bool_to_bit (zopz0zI_u source1 source2))))) := by
  rw [execute_RTYPE_SLTU_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_XOR_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .XOR) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (source1 ^^^ source2))) := by
  rw [execute_RTYPE_XOR_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SRL_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .SRL) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (shift_bits_right source1
                (Sail.BitVec.extractLsb
                  source2 (log2_xlen -i 1) 0)))) := by
  rw [execute_RTYPE_SRL_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SRA_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .SRA) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (shift_bits_right_arith source1
                (Sail.BitVec.extractLsb
                  source2 (log2_xlen -i 1) 0)))) := by
  rw [execute_RTYPE_SRA_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_OR_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .OR) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (source1 ||| source2))) := by
  rw [execute_RTYPE_OR_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_AND_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_RTYPE (.Regidx rs2) (.Regidx rs1) (.Regidx rd) .AND) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (source1 &&& source2))) := by
  rw [execute_RTYPE_AND_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SLTI_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_ITYPE imm (.Regidx rs1) (.Regidx rd) .SLTI) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let immediate : xlenbits := sign_extend (m := 32) imm
            pure
              (zero_extend (m := 32)
                (bool_to_bit (zopz0zI_s source immediate))))) := by
  rw [execute_ITYPE_SLTI_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SLTIU_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_ITYPE imm (.Regidx rs1) (.Regidx rd) .SLTIU) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let immediate : xlenbits := sign_extend (m := 32) imm
            pure
              (zero_extend (m := 32)
                (bool_to_bit (zopz0zI_u source immediate))))) := by
  rw [execute_ITYPE_SLTIU_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_XORI_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_ITYPE imm (.Regidx rs1) (.Regidx rd) .XORI) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let immediate : xlenbits := sign_extend (m := 32) imm
            pure (source ^^^ immediate))) := by
  rw [execute_ITYPE_XORI_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_ORI_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_ITYPE imm (.Regidx rs1) (.Regidx rd) .ORI) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let immediate : xlenbits := sign_extend (m := 32) imm
            pure (source ||| immediate))) := by
  rw [execute_ITYPE_ORI_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_ANDI_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_ITYPE imm (.Regidx rs1) (.Regidx rd) .ANDI) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let immediate : xlenbits := sign_extend (m := 32) imm
            pure (source &&& immediate))) := by
  rw [execute_ITYPE_ANDI_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SLLI_normalizes
    (pc : BitVec 32)
    (shamt : BitVec 6)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_SHIFTIOP shamt (.Regidx rs1) (.Regidx rd) .SLLI) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let amount :=
              Sail.BitVec.extractLsb shamt (log2_xlen -i 1) 0
            pure (shift_bits_left source amount))) := by
  rw [execute_SHIFTIOP_SLLI_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SRLI_normalizes
    (pc : BitVec 32)
    (shamt : BitVec 6)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_SHIFTIOP shamt (.Regidx rs1) (.Regidx rd) .SRLI) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let amount :=
              Sail.BitVec.extractLsb shamt (log2_xlen -i 1) 0
            pure (shift_bits_right source amount))) := by
  rw [execute_SHIFTIOP_SRLI_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_SRAI_normalizes
    (pc : BitVec 32)
    (shamt : BitVec 6)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_SHIFTIOP shamt (.Regidx rs1) (.Regidx rd) .SRAI) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source ← rX_bits (.Regidx rs1)
            let amount :=
              Sail.BitVec.extractLsb shamt (log2_xlen -i 1) 0
            pure (shift_bits_right_arith source amount))) := by
  rw [execute_SHIFTIOP_SRAI_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_LOAD_semantic_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (isUnsigned : Bool)
    (width : Nat) :
    completeBaseExecution pc
        (execute_LOAD imm (.Regidx rs1) (.Regidx rd)
          isUnsigned width) =
      eraseObservation
        (normalizedLoadCompletion
          pc imm rs1 rd isUnsigned width) := by
  rw [normalizedLoadCompletion_erases]
  simp [
    completeBaseExecution,
    completeLoadEffects,
    execute_LOAD,
  ]
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro result
  cases result <;> simp

theorem complete_LB_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_LOAD imm (.Regidx rs1) (.Regidx rd) false 1) =
      eraseObservation
        (normalizedLoadCompletion pc imm rs1 rd false 1) :=
  complete_LOAD_semantic_normalizes _ _ _ _ _ _

theorem complete_LH_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_LOAD imm (.Regidx rs1) (.Regidx rd) false 2) =
      eraseObservation
        (normalizedLoadCompletion pc imm rs1 rd false 2) :=
  complete_LOAD_semantic_normalizes _ _ _ _ _ _

theorem complete_LW_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_LOAD imm (.Regidx rs1) (.Regidx rd) false 4) =
      eraseObservation
        (normalizedLoadCompletion pc imm rs1 rd false 4) :=
  complete_LOAD_semantic_normalizes _ _ _ _ _ _

theorem complete_LBU_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_LOAD imm (.Regidx rs1) (.Regidx rd) true 1) =
      eraseObservation
        (normalizedLoadCompletion pc imm rs1 rd true 1) :=
  complete_LOAD_semantic_normalizes _ _ _ _ _ _

theorem complete_LHU_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_LOAD imm (.Regidx rs1) (.Regidx rd) true 2) =
      eraseObservation
        (normalizedLoadCompletion pc imm rs1 rd true 2) :=
  complete_LOAD_semantic_normalizes _ _ _ _ _ _

theorem complete_STORE_semantic_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5)
    (width : Nat) :
    completeBaseExecution pc
        (execute_STORE imm (.Regidx rs2) (.Regidx rs1) width) =
      eraseObservation
        (normalizedStoreCompletion
          pc imm rs2 rs1 width) := by
  rw [normalizedStoreCompletion_erases]
  simp [
    completeBaseExecution,
    completeStoreEffects,
    execute_STORE,
  ]
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro result
  cases result <;> simp

theorem complete_SB_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_STORE imm (.Regidx rs2) (.Regidx rs1) 1) =
      eraseObservation
        (normalizedStoreCompletion pc imm rs2 rs1 1) :=
  complete_STORE_semantic_normalizes _ _ _ _ _

theorem complete_SH_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_STORE imm (.Regidx rs2) (.Regidx rs1) 2) =
      eraseObservation
        (normalizedStoreCompletion pc imm rs2 rs1 2) :=
  complete_STORE_semantic_normalizes _ _ _ _ _

theorem complete_SW_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_STORE imm (.Regidx rs2) (.Regidx rs1) 4) =
      eraseObservation
        (normalizedStoreCompletion pc imm rs2 rs1 4) :=
  complete_STORE_semantic_normalizes _ _ _ _ _

theorem complete_BEQ_normalizes
    (pc : BitVec 32)
    (imm : BitVec 13)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_BTYPE imm (.Regidx rs2) (.Regidx rs1) .BEQ) =
      eraseObservation
        (normalizedBranchCompletion pc
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (source1 == source2))
          (do
            let currentPc ← Sail.readReg PC
            pure (currentPc + sign_extend (m := 32) imm))) := by
  rw [execute_BTYPE_BEQ_eq, normalizedBranchCompletion_erases]
  simp [
    completeBaseExecution,
    completeBranchEffects,
    Functor.map_map,
  ]

theorem complete_BNE_normalizes
    (pc : BitVec 32)
    (imm : BitVec 13)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_BTYPE imm (.Regidx rs2) (.Regidx rs1) .BNE) =
      eraseObservation
        (normalizedBranchCompletion pc
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (source1 != source2))
          (do
            let currentPc ← Sail.readReg PC
            pure (currentPc + sign_extend (m := 32) imm))) := by
  rw [execute_BTYPE_BNE_eq, normalizedBranchCompletion_erases]
  simp [
    completeBaseExecution,
    completeBranchEffects,
    Functor.map_map,
  ]

theorem complete_BLT_normalizes
    (pc : BitVec 32)
    (imm : BitVec 13)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_BTYPE imm (.Regidx rs2) (.Regidx rs1) .BLT) =
      eraseObservation
        (normalizedBranchCompletion pc
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (zopz0zI_s source1 source2))
          (do
            let currentPc ← Sail.readReg PC
            pure (currentPc + sign_extend (m := 32) imm))) := by
  rw [execute_BTYPE_BLT_eq, normalizedBranchCompletion_erases]
  simp [
    completeBaseExecution,
    completeBranchEffects,
    Functor.map_map,
  ]

theorem complete_BGE_normalizes
    (pc : BitVec 32)
    (imm : BitVec 13)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_BTYPE imm (.Regidx rs2) (.Regidx rs1) .BGE) =
      eraseObservation
        (normalizedBranchCompletion pc
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (zopz0zKzJ_s source1 source2))
          (do
            let currentPc ← Sail.readReg PC
            pure (currentPc + sign_extend (m := 32) imm))) := by
  rw [execute_BTYPE_BGE_eq, normalizedBranchCompletion_erases]
  simp [
    completeBaseExecution,
    completeBranchEffects,
    Functor.map_map,
  ]

theorem complete_BLTU_normalizes
    (pc : BitVec 32)
    (imm : BitVec 13)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_BTYPE imm (.Regidx rs2) (.Regidx rs1) .BLTU) =
      eraseObservation
        (normalizedBranchCompletion pc
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (zopz0zI_u source1 source2))
          (do
            let currentPc ← Sail.readReg PC
            pure (currentPc + sign_extend (m := 32) imm))) := by
  rw [execute_BTYPE_BLTU_eq, normalizedBranchCompletion_erases]
  simp [
    completeBaseExecution,
    completeBranchEffects,
    Functor.map_map,
  ]

theorem complete_BGEU_normalizes
    (pc : BitVec 32)
    (imm : BitVec 13)
    (rs2 rs1 : BitVec 5) :
    completeBaseExecution pc
        (execute_BTYPE imm (.Regidx rs2) (.Regidx rs1) .BGEU) =
      eraseObservation
        (normalizedBranchCompletion pc
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure (zopz0zKzJ_u source1 source2))
          (do
            let currentPc ← Sail.readReg PC
            pure (currentPc + sign_extend (m := 32) imm))) := by
  rw [execute_BTYPE_BGEU_eq, normalizedBranchCompletion_erases]
  simp [
    completeBaseExecution,
    completeBranchEffects,
    Functor.map_map,
  ]

theorem complete_JAL_normalizes
    (pc : BitVec 32)
    (imm : BitVec 21)
    (rd : BitVec 5) :
    completeBaseExecution pc (execute_JAL imm (.Regidx rd)) =
      eraseObservation
        (normalizedJumpCompletion pc rd (pure ())
          (do
            let currentPc ← Sail.readReg PC
            pure
              (currentPc + sign_extend (m := 32) imm))) := by
  rw [execute_JAL_eq, normalizedJumpCompletion_erases]
  simp [
    completeBaseExecution,
    completeJumpEffects,
  ]
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro result
  cases result <;> rfl

theorem complete_JALR_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_JALR imm (.Regidx rs1) (.Regidx rd)) =
      eraseObservation
        (normalizedJumpCompletion pc rd
          (update_elp_state (.Regidx rs1))
          (do
            let base ← rX_bits (.Regidx rs1)
            pure
              (BitVec.update
                (base + sign_extend (m := 32) imm)
                0 0#1))) := by
  rw [execute_JALR_eq, normalizedJumpCompletion_erases]
  simp [
    completeBaseExecution,
    completeJumpEffects,
  ]
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro result
  cases result <;> rfl

theorem complete_AUIPC_normalizes
    (pc : BitVec 32)
    (imm : BitVec 20)
    (rd : BitVec 5) :
    completeBaseExecution pc (execute_UTYPE imm (.Regidx rd) .AUIPC) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let sourcePc ← get_arch_pc ()
            pure
              (sourcePc +
                sign_extend (m := 32) (imm +++ (0x000#12))))) := by
  rw [execute_UTYPE_AUIPC_eq, normalizedRegisterCompletion_erases]
  simp [completeBaseExecution, completeRegisterEffects]

theorem complete_MUL_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_MUL
          (.Regidx rs2) (.Regidx rs1) (.Regidx rd)
          mulSelectorLowSigned) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (mult_to_bits_half
                mulSelectorLowSigned.signed_rs1
                mulSelectorLowSigned.signed_rs2
                source1 source2
                mulSelectorLowSigned.result_part))) := by
  rw [execute_MUL_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedMulClause,
  ]

theorem complete_MULH_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_MUL
          (.Regidx rs2) (.Regidx rs1) (.Regidx rd)
          mulSelectorHighSigned) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (mult_to_bits_half
                mulSelectorHighSigned.signed_rs1
                mulSelectorHighSigned.signed_rs2
                source1 source2
                mulSelectorHighSigned.result_part))) := by
  rw [execute_MULH_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedMulClause,
  ]

theorem complete_MULHSU_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_MUL
          (.Regidx rs2) (.Regidx rs1) (.Regidx rd)
          mulSelectorHighSignedUnsigned) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (mult_to_bits_half
                mulSelectorHighSignedUnsigned.signed_rs1
                mulSelectorHighSignedUnsigned.signed_rs2
                source1 source2
                mulSelectorHighSignedUnsigned.result_part))) := by
  rw [execute_MULHSU_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedMulClause,
  ]

theorem complete_MULHU_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_MUL
          (.Regidx rs2) (.Regidx rs1) (.Regidx rd)
          mulSelectorHighUnsigned) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (do
            let source1 ← rX_bits (.Regidx rs1)
            let source2 ← rX_bits (.Regidx rs2)
            pure
              (mult_to_bits_half
                mulSelectorHighUnsigned.signed_rs1
                mulSelectorHighUnsigned.signed_rs2
                source1 source2
                mulSelectorHighUnsigned.result_part))) := by
  rw [execute_MULHU_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedMulClause,
  ]

theorem complete_DIV_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_DIV (.Regidx rs2) (.Regidx rs1) (.Regidx rd) false) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (generatedDivValue (.Regidx rs2) (.Regidx rs1) false)) := by
  rw [execute_DIV_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedDivClause,
    generatedDivValue,
  ]

theorem complete_DIVU_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_DIV (.Regidx rs2) (.Regidx rs1) (.Regidx rd) true) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (generatedDivValue (.Regidx rs2) (.Regidx rs1) true)) := by
  rw [execute_DIVU_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedDivClause,
    generatedDivValue,
  ]

theorem complete_REM_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_REM (.Regidx rs2) (.Regidx rs1) (.Regidx rd) false) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (generatedRemValue (.Regidx rs2) (.Regidx rs1) false)) := by
  rw [execute_REM_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedRemClause,
    generatedRemValue,
  ]

theorem complete_REMU_normalizes
    (pc : BitVec 32)
    (rs2 rs1 rd : BitVec 5) :
    completeBaseExecution pc
        (execute_REM (.Regidx rs2) (.Regidx rs1) (.Regidx rd) true) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (generatedRemValue (.Regidx rs2) (.Regidx rs1) true)) := by
  rw [execute_REMU_eq, normalizedRegisterCompletion_erases]
  simp [
    completeBaseExecution,
    completeRegisterEffects,
    generatedRemClause,
    generatedRemValue,
  ]

theorem complete_FENCE_normalizes
    (pc : BitVec 32)
    (fm pred succ : BitVec 4)
    (rs rd : BitVec 5) :
    completeBaseExecution pc
        (execute_FENCE fm pred succ (.Regidx rs) (.Regidx rd)) =
      eraseObservation
        (normalizedSequentialNoWriteCompletion pc
          (execute_FENCE fm pred succ (.Regidx rs) (.Regidx rd))) :=
  (normalizedSequentialNoWriteCompletion_erases _ _).symm

#print axioms complete_LUI_normalizes
#print axioms complete_ADDI_normalizes
#print axioms complete_ADD_normalizes
#print axioms complete_SUB_normalizes
#print axioms complete_SLL_normalizes
#print axioms complete_SLT_normalizes
#print axioms complete_SLTU_normalizes
#print axioms complete_XOR_normalizes
#print axioms complete_SRL_normalizes
#print axioms complete_SRA_normalizes
#print axioms complete_OR_normalizes
#print axioms complete_AND_normalizes
#print axioms complete_SLTI_normalizes
#print axioms complete_SLTIU_normalizes
#print axioms complete_XORI_normalizes
#print axioms complete_ORI_normalizes
#print axioms complete_ANDI_normalizes
#print axioms complete_SLLI_normalizes
#print axioms complete_SRLI_normalizes
#print axioms complete_SRAI_normalizes
#print axioms complete_LB_normalizes
#print axioms complete_LH_normalizes
#print axioms complete_LW_normalizes
#print axioms complete_LBU_normalizes
#print axioms complete_LHU_normalizes
#print axioms complete_SB_normalizes
#print axioms complete_SH_normalizes
#print axioms complete_SW_normalizes
#print axioms complete_BEQ_normalizes
#print axioms complete_BNE_normalizes
#print axioms complete_BLT_normalizes
#print axioms complete_BGE_normalizes
#print axioms complete_BLTU_normalizes
#print axioms complete_BGEU_normalizes
#print axioms complete_JAL_normalizes
#print axioms complete_JALR_normalizes
#print axioms complete_AUIPC_normalizes
#print axioms complete_MUL_normalizes
#print axioms complete_MULH_normalizes
#print axioms complete_MULHSU_normalizes
#print axioms complete_MULHU_normalizes
#print axioms complete_DIV_normalizes
#print axioms complete_DIVU_normalizes
#print axioms complete_REM_normalizes
#print axioms complete_REMU_normalizes
#print axioms complete_FENCE_normalizes

end LeanRV32IM.Functions
