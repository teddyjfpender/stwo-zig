import ExecutionClosure
import DecodeControlState

/-!
# Constructive execution for generated control instructions

This module closes the row-local generated execution obligation for AUIPC,
JAL, JALR, and the six conditional branches.  Every final generated state is
constructed by the proof; no generated outcome, trace, or final state is a
caller premise.
-/

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication.ExecutionControl

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

/--
Package exact decoded-body and normalized-observer runs into the public
`ConstructiveGeneratedExecution` boundary.  Both final states are existential
outputs; the erasure equality fixes the raw generated retirement run.
-/
theorem constructiveExecution_of_runs
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (observed : SailM (Functions.ObservedExecution ExecutionResult))
    (initial : Functions.GeneratedState)
    (retirement : RiscvRefinement.Retirement)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (Functions.landing_pad_bits_backwards .NO_LP_EXPECTED))
    (bodySuccess :
      ∃ final : Functions.GeneratedState,
        Functions.execute decoded {
          initial with
          regs := initial.regs.insert Register.nextPC
            (RiscvRefinement.nextPc pc)
        } = .ok Functions.RETIRE_SUCCESS final)
    (normalizes :
      Functions.completeBaseExecution pc (Functions.execute decoded) =
        Functions.eraseObservation observed)
    (observedSuccess :
      ∃ final : Functions.GeneratedState,
        observed initial = .ok {
          generatedResult := Functions.RETIRE_SUCCESS
          retirement := some retirement
        } final) :
    Functions.ConstructiveGeneratedExecution stepNo word decoded
      (Functions.completeBaseExecution pc (Functions.execute decoded))
      observed initial retirement := by
  rcases observedSuccess with ⟨final, observedOutcome⟩
  constructor
  · exact ExecutionClosure.runBaseAfterDecode_succeeds_of_body
      stepNo word decoded pc initial pcBinding landingPadClear bodySuccess
  · constructor
    · exact normalizes.symm
    · refine ⟨final, observedOutcome, ?_⟩
      calc
        Functions.completeBaseExecution pc
            (Functions.execute decoded) initial =
            Functions.eraseObservation observed initial :=
          congrFun normalizes initial
        _ = .ok Functions.RETIRE_SUCCESS final := by
          simp [Functions.eraseObservation, observedOutcome]

/-! ## Generated jump totality -/

/-- Four-byte alignment clears the low generated Sail address bit. -/
theorem aligned_target_bit_zero
    (target : BitVec 32)
    (aligned : target.toNat % 4 = 0) :
    Sail.BitVec.access target 0 = 0#1 := by
  have low : target.toNat % 2 = 0 := by omega
  apply BitVec.eq_of_toNat_eq
  simp [
    Sail.BitVec.access,
    BitVec.getElem_eq_testBit_toNat,
    Nat.testBit_eq_decide_div_mod_eq,
    low,
  ]

/-- Four-byte alignment also clears the compressed-instruction address bit. -/
theorem aligned_target_bit_one
    (target : BitVec 32)
    (aligned : target.toNat % 4 = 0) :
    Sail.BitVec.access target 1 = 0#1 := by
  have low : target.toNat / 2 % 2 = 0 := by omega
  apply BitVec.eq_of_toNat_eq
  simp [
    Sail.BitVec.access,
    BitVec.getElem_eq_testBit_toNat,
    Nat.testBit_eq_decide_div_mod_eq,
    low,
  ]

/--
The pinned generated `jump_to` is constructive on a four-byte-aligned target:
the platform control hook is empty and the generated profile has no compressed
instruction support, so it installs the exact target in `nextPC` and retires.
-/
theorem currentlyEnabled_zca_disabled_succeeds
    (initial : Functions.GeneratedState)
    (misaValue : BitVec 32)
    (misaBinding :
      initial.regs.get? Register.misa = some misaValue) :
    Functions.currentlyEnabled extension.Ext_Zca initial =
      .ok false initial := by
  simp [
    Functions.currentlyEnabled,
    Functions.hartSupports,
    PreSail.readReg,
    misaBinding,
    Functions.not,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

theorem jump_to_aligned_succeeds
    (target : BitVec 32)
    (initial : Functions.GeneratedState)
    (misaValue : BitVec 32)
    (misaBinding :
      initial.regs.get? Register.misa = some misaValue)
    (aligned : target.toNat % 4 = 0) :
    Functions.jump_to target initial =
      .ok Functions.RETIRE_SUCCESS {
        initial with
        regs := initial.regs.insert Register.nextPC target
      } := by
  have bitZero := aligned_target_bit_zero target aligned
  have bitOne := aligned_target_bit_one target aligned
  have compressedOutcome :=
    currentlyEnabled_zca_disabled_succeeds initial misaValue misaBinding
  simp [
    Functions.jump_to,
    Functions.ext_control_check_pc,
    Functions.set_next_pc,
    Functions.sail_branch_announce,
    Functions.redirect_callback,
    Functions.bit_to_bool,
    Functions.bool_bit_backwards,
    Functions.not,
    PreSail.assert,
    bitZero,
    bitOne,
    compressedOutcome,
    SailME.run,
    PreSail.PreSailME.run,
    ExceptT.pure,
    ExceptT.bind,
    ExceptT.bindCont,
    ExceptT.lift,
    ExceptT.run,
    ExceptT.mk,
    liftM,
    monadLift,
    MonadLiftT.monadLift,
    MonadLift.monadLift,
    Functor.map,
    PreSail.readReg,
    PreSail.writeReg,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
    modify,
    modifyGet,
    MonadStateOf.modifyGet,
    EStateM.modifyGet,
  ]

/-- A four-byte-aligned PC plus a four-byte-aligned J immediate stays aligned. -/
theorem add_signExtend21_aligned
    (pc : BitVec 32)
    (immediate : BitVec 21)
    (pcAligned : pc.toNat % 4 = 0)
    (immediateAligned : immediate.toNat % 4 = 0) :
    (pc + Functions.sign_extend (m := 32) immediate).toNat % 4 = 0 := by
  have pcBound := pc.isLt
  have immediateBound := immediate.isLt
  simp only [
    Functions.sign_extend,
    Sail.BitVec.signExtend,
    BitVec.toNat_add,
    BitVec.toNat_signExtend,
    BitVec.toNat_setWidth,
  ]
  split <;> omega

/-- A four-byte-aligned PC plus a four-byte-aligned B immediate stays aligned. -/
theorem add_signExtend13_aligned
    (pc : BitVec 32)
    (immediate : BitVec 13)
    (pcAligned : pc.toNat % 4 = 0)
    (immediateAligned : immediate.toNat % 4 = 0) :
    (pc + Functions.sign_extend (m := 32) immediate).toNat % 4 = 0 := by
  have pcBound := pc.isLt
  have immediateBound := immediate.isLt
  simp only [
    Functions.sign_extend,
    Sail.BitVec.signExtend,
    BitVec.toNat_add,
    BitVec.toNat_signExtend,
    BitVec.toNat_setWidth,
  ]
  split <;> omega

/-- The generated wrapping addition agrees with the AIR's admitted B target. -/
theorem generated_branch_target_eq
    (pc : BitVec 32)
    (encoded : BitVec 12)
    (targetNoWrap :
      if (RiscvRefinement.Air.Bridge.Branches.immediate encoded).msb
      then
        2 ^ 13 -
            (RiscvRefinement.Air.Bridge.Branches.immediate encoded).toNat ≤
          pc.toNat
      else
        pc.toNat +
            (RiscvRefinement.Air.Bridge.Branches.immediate encoded).toNat <
          M31.modulus) :
    pc + Functions.sign_extend (m := 32)
        (RiscvRefinement.Decode.branchImmediate encoded) =
      RiscvRefinement.Air.Bridge.Branches.branchTarget pc encoded := by
  simp only [RiscvRefinement.Air.Bridge.Branches.immediate] at targetNoWrap
  apply BitVec.eq_of_toNat_eq
  simp only [
    RiscvRefinement.Air.Bridge.Branches.branchTarget,
    RiscvRefinement.Air.Bridge.Branches.immediate,
    Functions.sign_extend,
    Sail.BitVec.signExtend,
    BitVec.toNat_add,
    BitVec.toNat_signExtend,
    BitVec.toNat_setWidth,
    BitVec.toNat_ofNat,
  ]
  split <;> rename_i sign
  · rw [if_pos sign] at targetNoWrap
    simp [sign]
    have immediateBound :=
      (RiscvRefinement.Decode.branchImmediate encoded).isLt
    have pcBound := pc.isLt
    simp [M31.modulus_eq] at targetNoWrap
    omega
  · rw [if_neg sign] at targetNoWrap
    simp [sign]

/-- Clearing bit zero is exactly logical shift-right/shift-left by one. -/
theorem clear_low_bit_eq_shift
    (value : BitVec 32) :
    BitVec.update value 0 0#1 = (value >>> 1) <<< 1 := by
  rw [BitVec.shiftLeft_ushiftRight]
  ext index bound
  by_cases low : index = 0
  · subst index
    simp [Sail.BitVec.update, Sail.BitVec.updateSubrange']
  · simp [
      Sail.BitVec.update,
      Sail.BitVec.updateSubrange',
      low,
      bound,
    ]
    exact Bool.and_comm _ _

/-- The generated JALR bit update equals the AIR's arithmetic target. -/
theorem generated_jalr_target_eq
    (source : BitVec 32)
    (immediate : BitVec 12) :
    BitVec.update
        (source + Functions.sign_extend (m := 32) immediate) 0 0#1 =
      RiscvRefinement.Air.Bridge.Jalr.jumpTarget source immediate := by
  let unaligned : BitVec 32 :=
    source + Functions.sign_extend (m := 32) immediate
  have unalignedEq :
      RiscvRefinement.Air.Bridge.Jalr.unalignedTarget source immediate =
        unaligned := by
    simp [
      RiscvRefinement.Air.Bridge.Jalr.unalignedTarget,
      RiscvRefinement.Sail.Generated.executeAddiValue,
      Functions.sign_extend,
      Sail.BitVec.signExtend,
      unaligned,
    ]
  rw [show BitVec.update unaligned 0 0#1 =
      (unaligned >>> 1) <<< 1 by
    exact clear_low_bit_eq_shift unaligned]
  apply BitVec.eq_of_toNat_eq
  have unalignedBound := unaligned.isLt
  simp [
    unaligned,
    RiscvRefinement.Air.Bridge.Jalr.jumpTarget,
    unalignedEq,
    Functions.sign_extend,
    Sail.BitVec.signExtend,
    Nat.shiftRight_eq_div_pow,
    Nat.shiftLeft_eq,
  ]

/-- JALR's landing-pad update is state-neutral in the pinned no-Zicfilp profile. -/
theorem update_elp_state_succeeds
    (rs1 : BitVec 5)
    (initial : Functions.GeneratedState)
    (mseccfgValue : BitVec 64)
    (landingPadDisabled :
      Functions.hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    Functions.update_elp_state (.Regidx rs1) initial = .ok () initial := by
  simp [
    Functions.update_elp_state,
    Functions.currentlyEnabled,
    Functions.get_xLPE,
    Functions.hartSupports,
    PreSail.readReg,
    landingPadDisabled,
    privilegeBinding,
    mseccfgBinding,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

/-! ## Shared conditional-branch constructor -/

def eqBranchDecodeKind :
    RiscvRefinement.Air.Bridge.Branches.Eq.Kind →
      RiscvRefinement.Decode.BranchKind
  | .beq => .beq
  | .bne => .bne

def eqBranchCompute
    (kind : RiscvRefinement.Air.Bridge.Branches.Eq.Kind) :
    BitVec 32 → BitVec 32 → Bool :=
  match kind with
  | .beq => fun left right => left == right
  | .bne => fun left right => left != right

def ltBranchDecodeKind :
    RiscvRefinement.Air.Bridge.Branches.Lt.Kind →
      RiscvRefinement.Decode.BranchKind
  | .blt => .blt
  | .bge => .bge
  | .bltu => .bltu
  | .bgeu => .bgeu

def ltBranchCompute
    (kind : RiscvRefinement.Air.Bridge.Branches.Lt.Kind) :
    BitVec 32 → BitVec 32 → Bool :=
  match kind with
  | .blt => Functions.zopz0zI_s
  | .bge => Functions.zopz0zKzJ_s
  | .bltu => Functions.zopz0zI_u
  | .bgeu => Functions.zopz0zKzJ_u

/--
Construct an exact generated conditional branch from two register bindings,
an AIR-derived decision, and alignment of the encoded branch displacement.
-/
theorem branch_constructive
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (immediate : BitVec 13)
    (rs1 rs2 : BitVec 5)
    (source1 source2 : BitVec 32)
    (compute : BitVec 32 → BitVec 32 → Bool)
    (expectedTaken : Bool)
    (retirement : RiscvRefinement.Retirement)
    (initial : Functions.GeneratedState)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (Functions.landing_pad_bits_backwards .NO_LP_EXPECTED))
    (sourceOneBinding : generatedRegisterValue? initial rs1 = some source1)
    (sourceTwoBinding : generatedRegisterValue? initial rs2 = some source2)
    (decodeState : GeneratedDecodeStateBindings initial)
    (pcAligned : pc.toNat % 4 = 0)
    (immediateAligned : immediate.toNat % 4 = 0)
    (conditionMatches : compute source1 source2 = expectedTaken)
    (executeClause :
      Functions.execute decoded = do
        let taken ← ((do
          let operand1 ← Functions.rX_bits (.Regidx rs1)
          let operand2 ← Functions.rX_bits (.Regidx rs2)
          pure (compute operand1 operand2)) : SailM Bool)
        if taken then
          Functions.jump_to
            ((← Sail.readReg Register.PC) +
              Functions.sign_extend (m := 32) immediate)
        else pure Functions.RETIRE_SUCCESS)
    (normalizes :
      Functions.completeBaseExecution pc (Functions.execute decoded) =
        Functions.eraseObservation
          (Functions.normalizedBranchCompletion pc
            (do
              let operand1 ← Functions.rX_bits (.Regidx rs1)
              let operand2 ← Functions.rX_bits (.Regidx rs2)
              pure (compute operand1 operand2))
            (do
              let currentPc ← Sail.readReg Register.PC
              pure (currentPc +
                Functions.sign_extend (m := 32) immediate))))
    (retirementEq : retirement = {
      nextPc := if expectedTaken then
        pc + Functions.sign_extend (m := 32) immediate
      else RiscvRefinement.nextPc pc
      write := none
      read := none
      store := none
    }) :
    Functions.ConstructiveGeneratedExecution stepNo word decoded
      (Functions.completeBaseExecution pc (Functions.execute decoded))
      (Functions.normalizedBranchCompletion pc
        (do
          let operand1 ← Functions.rX_bits (.Regidx rs1)
          let operand2 ← Functions.rX_bits (.Regidx rs2)
          pure (compute operand1 operand2))
        (do
          let currentPc ← Sail.readReg Register.PC
          pure (currentPc + Functions.sign_extend (m := 32) immediate)))
      initial retirement := by
  let link : BitVec 32 := RiscvRefinement.nextPc pc
  let target : BitVec 32 :=
    pc + Functions.sign_extend (m := 32) immediate
  let afterNextPc : Functions.GeneratedState := {
    initial with regs := initial.regs.insert Register.nextPC link
  }
  have pcAfterNextPc :
      afterNextPc.regs.get? Register.PC = some pc := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using pcBinding
  have nextPcAfterNextPc :
      afterNextPc.regs.get? Register.nextPC = some link := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert_self]
  have sourceOneAfterNextPc :
      generatedRegisterValue? afterNextPc rs1 = some source1 := by
    rw [ExecutionClosure.generatedRegisterValue?_insert_nextPC]
    exact sourceOneBinding
  have sourceTwoAfterNextPc :
      generatedRegisterValue? afterNextPc rs2 = some source2 := by
    rw [ExecutionClosure.generatedRegisterValue?_insert_nextPC]
    exact sourceTwoBinding
  rcases decodeState.misa with
    ⟨misaValue, misaInitial, _misaMEnabled, _misaCDisabled⟩
  have misaAfterNextPc :
      afterNextPc.regs.get? Register.misa = some misaValue := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using misaInitial
  have pcReadAfterNextPc :
      ((Sail.readReg Register.PC : SailM (BitVec 32)) afterNextPc) =
        .ok pc afterNextPc := by
    simp [
      PreSail.readReg,
      pcAfterNextPc,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  have installNextPc :
      ((PreSail.writeReg Register.nextPC
          (RiscvRefinement.nextPc pc) : SailM PUnit) initial) =
        .ok () afterNextPc := by
    simp [
      PreSail.writeReg,
      afterNextPc,
      link,
      RiscvRefinement.nextPc,
      Sail.BitVec.addInt,
      modify,
      modifyGet,
      MonadStateOf.modifyGet,
      EStateM.modifyGet,
    ]
  have readOneOutcome := ExecutionClosure.generatedRegister_read_succeeds
    afterNextPc rs1 source1 sourceOneAfterNextPc
  have readTwoOutcome := ExecutionClosure.generatedRegister_read_succeeds
    afterNextPc rs2 source2 sourceTwoAfterNextPc
  have targetAligned : target.toNat % 4 = 0 := by
    exact add_signExtend13_aligned pc immediate pcAligned immediateAligned
  cases expectedTaken with
  | false =>
      have conditionFalse : compute source1 source2 = false := conditionMatches
      rcases ExecutionClosure.generated_tick_pc_succeeds
          afterNextPc link nextPcAfterNextPc with
        ⟨afterTick, tickOutcome⟩
      have bodySuccess :
          ∃ final : Functions.GeneratedState,
            Functions.execute decoded afterNextPc =
              .ok Functions.RETIRE_SUCCESS final := by
        refine ⟨afterNextPc, ?_⟩
        rw [executeClause]
        simp [
          readOneOutcome,
          readTwoOutcome,
          conditionFalse,
          bind,
          EStateM.bind,
          pure,
          EStateM.pure,
        ]
      have observedSuccess :
          ∃ final : Functions.GeneratedState,
            Functions.normalizedBranchCompletion pc
                (do
                  let operand1 ← Functions.rX_bits (.Regidx rs1)
                  let operand2 ← Functions.rX_bits (.Regidx rs2)
                  pure (compute operand1 operand2))
                (do
                  let currentPc ← Sail.readReg Register.PC
                  pure (currentPc +
                    Functions.sign_extend (m := 32) immediate)) initial =
              .ok {
                generatedResult := Functions.RETIRE_SUCCESS
                retirement := some retirement
              } final := by
        refine ⟨afterTick, ?_⟩
        rw [retirementEq]
        simp [
          Functions.normalizedBranchCompletion,
          Functions.completeBranchEffects,
          installNextPc,
          link,
          readOneOutcome,
          readTwoOutcome,
          conditionFalse,
          tickOutcome,
          Functions.RETIRE_SUCCESS,
          bind,
          EStateM.bind,
          pure,
          EStateM.pure,
        ]
      exact constructiveExecution_of_runs stepNo word decoded pc
        (Functions.normalizedBranchCompletion pc
          (do
            let operand1 ← Functions.rX_bits (.Regidx rs1)
            let operand2 ← Functions.rX_bits (.Regidx rs2)
            pure (compute operand1 operand2))
          (do
            let currentPc ← Sail.readReg Register.PC
            pure (currentPc + Functions.sign_extend (m := 32) immediate)))
        initial retirement pcBinding landingPadClear bodySuccess
        normalizes observedSuccess
  | true =>
      have conditionTrue : compute source1 source2 = true := conditionMatches
      let afterJump : Functions.GeneratedState := {
        afterNextPc with regs := afterNextPc.regs.insert Register.nextPC target
      }
      have jumpOutcome :
          Functions.jump_to target afterNextPc =
            .ok Functions.RETIRE_SUCCESS afterJump := by
        simpa [afterJump] using
          jump_to_aligned_succeeds target afterNextPc misaValue
            misaAfterNextPc targetAligned
      have nextPcAfterJump :
          afterJump.regs.get? Register.nextPC = some target := by
        simp [afterJump, Std.ExtDHashMap.get?_insert_self]
      rcases ExecutionClosure.generated_tick_pc_succeeds
          afterJump target nextPcAfterJump with
        ⟨afterTick, tickOutcome⟩
      have bodySuccess :
          ∃ final : Functions.GeneratedState,
            Functions.execute decoded afterNextPc =
              .ok Functions.RETIRE_SUCCESS final := by
        refine ⟨afterJump, ?_⟩
        rw [executeClause]
        simp [
          readOneOutcome,
          readTwoOutcome,
          conditionTrue,
          pcReadAfterNextPc,
          target,
          jumpOutcome,
          bind,
          EStateM.bind,
          pure,
          EStateM.pure,
        ]
      have observedSuccess :
          ∃ final : Functions.GeneratedState,
            Functions.normalizedBranchCompletion pc
                (do
                  let operand1 ← Functions.rX_bits (.Regidx rs1)
                  let operand2 ← Functions.rX_bits (.Regidx rs2)
                  pure (compute operand1 operand2))
                (do
                  let currentPc ← Sail.readReg Register.PC
                  pure (currentPc +
                    Functions.sign_extend (m := 32) immediate)) initial =
              .ok {
                generatedResult := Functions.RETIRE_SUCCESS
                retirement := some retirement
              } final := by
        refine ⟨afterTick, ?_⟩
        rw [retirementEq]
        simp [
          Functions.normalizedBranchCompletion,
          Functions.completeBranchEffects,
          installNextPc,
          readOneOutcome,
          readTwoOutcome,
          conditionTrue,
          pcReadAfterNextPc,
          target,
          jumpOutcome,
          tickOutcome,
          Functions.RETIRE_SUCCESS,
          bind,
          EStateM.bind,
          pure,
          EStateM.pure,
        ]
      exact constructiveExecution_of_runs stepNo word decoded pc
        (Functions.normalizedBranchCompletion pc
          (do
            let operand1 ← Functions.rX_bits (.Regidx rs1)
            let operand2 ← Functions.rX_bits (.Regidx rs2)
            pure (compute operand1 operand2))
          (do
            let currentPc ← Sail.readReg Register.PC
            pure (currentPc + Functions.sign_extend (m := 32) immediate)))
        initial retirement pcBinding landingPadClear bodySuccess
        normalizes observedSuccess

/-! ## AUIPC -/

/-- Exact generated AUIPC execution from the published component bindings. -/
theorem auipc_constructive
    (row : RiscvRefinement.Opcodes.Auipc.Row)
    (witness : RiscvRefinement.Opcodes.Auipc.Witness row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (stateBindings :
      GeneratedInstructionStateBindings row.pc
          (Functions.encodeAuipcControl row.immediateEncoded row.rd) initial ∧
        GeneratedDestinationStateBinding initial row.rd row.rdPrevious.word)
    (localRefinement :
      RiscvRefinement.Opcodes.Auipc.Refinement row witness) :
    Functions.ConstructiveGeneratedExecution stepNo
      (Functions.encodeAuipcControl row.immediateEncoded row.rd)
      (Functions.decodedAuipcControl row.immediateEncoded row.rd)
      (Functions.completeBaseExecution row.pc
        (Functions.execute
          (Functions.decodedAuipcControl row.immediateEncoded row.rd)))
      (Functions.normalizedRegisterCompletion row.pc row.rd
        (do
          let sourcePc ← Functions.get_arch_pc ()
          pure (sourcePc + Functions.sign_extend (m := 32)
            (row.immediateEncoded +++ (0x000#12)))))
      initial (RiscvRefinement.Opcodes.Auipc.airRetirement row) := by
  let valueProgram : SailM (BitVec 32) := do
    let sourcePc ← Functions.get_arch_pc ()
    pure (sourcePc + Functions.sign_extend (m := 32)
      (row.immediateEncoded +++ (0x000#12)))
  let value : BitVec 32 :=
    row.pc + Functions.sign_extend (m := 32)
      (row.immediateEncoded +++ (0x000#12))
  apply ExecutionClosure.constructiveRegisterExecution_of_value
    stepNo
    (Functions.encodeAuipcControl row.immediateEncoded row.rd)
    (Functions.decodedAuipcControl row.immediateEncoded row.rd)
    row.pc row.rd valueProgram value value
    (RiscvRefinement.Opcodes.Auipc.airRetirement row)
    initial stateBindings.1.programCounter stateBindings.1.landingPadClear
  · have pcAfterNextPc :
        (initial.regs.insert Register.nextPC
            (RiscvRefinement.nextPc row.pc)).get? Register.PC =
          some row.pc := by
      rw [Std.ExtDHashMap.get?_insert]
      simpa using stateBindings.1.programCounter
    simp [
      valueProgram,
      value,
      Functions.get_arch_pc,
      PreSail.readReg,
      pcAfterNextPc,
      bind,
      EStateM.bind,
      EStateM.map,
      Functor.map,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  · rfl
  · simpa [Functions.decodedAuipcControl, valueProgram] using
      Functions.execute_UTYPE_AUIPC_eq row.immediateEncoded (.Regidx row.rd)
  · simpa [Functions.decodedAuipcControl, valueProgram] using
      Functions.complete_AUIPC_normalizes
        row.pc row.immediateEncoded row.rd
  · rw [localRefinement.retirement]
    simp [
      RiscvRefinement.Opcodes.Auipc.execute,
      RiscvRefinement.Air.Bridge.Auipc.pcRelativeValue,
      RiscvRefinement.Air.Bridge.Auipc.immediateWord,
      RiscvRefinement.Decode.auipcImmediate,
      RiscvRefinement.Sail.Generated.executeLuiValue,
      Functions.sign_extend,
      Sail.BitVec.signExtend,
      value,
    ]


end LeanRV32IM.Publication.ExecutionControl
