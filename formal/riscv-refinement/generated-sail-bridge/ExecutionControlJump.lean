import ExecutionControl

/-!
# Constructive execution for generated jump instructions

JAL and JALR share the aligned generated `jump_to` constructor from
`ExecutionControl`, while keeping this proof unit below the repository's
per-file contribution ceiling.
-/

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000
set_option linter.unusedVariables false

open Sail

namespace LeanRV32IM.Publication.ExecutionControl

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

/-! ## JAL -/

/-- Exact generated JAL execution, including aligned jump and link write. -/
theorem jal_constructive
    (row : RiscvRefinement.Opcodes.Jal.Row)
    (witness : RiscvRefinement.Opcodes.Jal.Witness row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (stateBindings :
      GeneratedInstructionStateBindings row.pc
          (Functions.encodeJalControl row.immediateEncoded row.rd) initial ∧
        GeneratedDestinationStateBinding initial row.rd row.rdPrevious.word)
    (profileAdmission :
      GeneratedInstructionProfileAdmission row.pc
        (Functions.encodeJalControl row.immediateEncoded row.rd) initial)
    (admission : RiscvRefinement.Opcodes.Jal.Admission row)
    (localRefinement :
      RiscvRefinement.Opcodes.Jal.Refinement row witness) :
    Functions.ConstructiveGeneratedExecution stepNo
      (Functions.encodeJalControl row.immediateEncoded row.rd)
      (Functions.decodedJalControl row.immediateEncoded row.rd)
      (Functions.completeBaseExecution row.pc
        (Functions.execute
          (Functions.decodedJalControl row.immediateEncoded row.rd)))
      (Functions.normalizedJumpCompletion row.pc row.rd (pure ())
        (do
          let currentPc ← Sail.readReg Register.PC
          pure (currentPc + Functions.sign_extend (m := 32)
            (RiscvRefinement.Decode.jalImmediate row.immediateEncoded))))
      initial (RiscvRefinement.Opcodes.Jal.airRetirement row) := by
  let immediate : BitVec 21 :=
    RiscvRefinement.Decode.jalImmediate row.immediateEncoded
  let link : BitVec 32 := RiscvRefinement.nextPc row.pc
  let target : BitVec 32 :=
    row.pc + Functions.sign_extend (m := 32) immediate
  let afterNextPc : Functions.GeneratedState := {
    initial with regs := initial.regs.insert Register.nextPC link
  }
  let afterJump : Functions.GeneratedState := {
    afterNextPc with regs := afterNextPc.regs.insert Register.nextPC target
  }
  have pcAfterNextPc :
      afterNextPc.regs.get? Register.PC = some row.pc := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using stateBindings.1.programCounter
  have nextPcAfterNextPc :
      afterNextPc.regs.get? Register.nextPC = some link := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert_self]
  rcases stateBindings.1.decodeState.misa with
    ⟨misaValue, misaInitial, _misaMEnabled, _misaCDisabled⟩
  have misaAfterNextPc :
      afterNextPc.regs.get? Register.misa = some misaValue := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using misaInitial
  have installNextPc :
      ((PreSail.writeReg Register.nextPC
          (RiscvRefinement.nextPc row.pc) : SailM PUnit) initial) =
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
  have installNextPcGenerated :
      ((PreSail.writeReg Register.nextPC
          (Sail.BitVec.addInt row.pc 4) : SailM PUnit) initial) =
        .ok () afterNextPc := by
    simpa [link, RiscvRefinement.nextPc] using installNextPc
  have nextPcReadAfterNextPc :
      Functions.get_next_pc () afterNextPc = .ok link afterNextPc := by
    simp [
      Functions.get_next_pc,
      PreSail.readReg,
      nextPcAfterNextPc,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  have pcReadAfterNextPc :
      ((Sail.readReg Register.PC : SailM (BitVec 32)) afterNextPc) =
        .ok row.pc afterNextPc := by
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
  have targetAligned : target.toNat % 4 = 0 := by
    apply add_signExtend21_aligned row.pc immediate
      profileAdmission.instructionAligned
    simpa [immediate, RiscvRefinement.Air.Bridge.Jal.immediate] using
      admission.targetAligned
  have jumpOutcome :
      Functions.jump_to target afterNextPc =
        .ok Functions.RETIRE_SUCCESS afterJump := by
    simpa [afterJump] using
      jump_to_aligned_succeeds target afterNextPc misaValue
        misaAfterNextPc targetAligned
  have jumpOutcomeGenerated :
      Functions.jump_to
          (row.pc + Functions.sign_extend (m := 32) immediate)
          afterNextPc =
        .ok Functions.RETIRE_SUCCESS afterJump := by
    simpa [target] using jumpOutcome
  rcases ExecutionClosure.generatedRegister_write_succeeds
      afterJump row.rd link with
    ⟨afterWrite, writeOutcome, nextPcPreserved⟩
  have nextPcAfterJump :
      afterJump.regs.get? Register.nextPC = some target := by
    simp [afterJump, Std.ExtDHashMap.get?_insert_self]
  have nextPcAfterWrite :
      afterWrite.regs.get? Register.nextPC = some target := by
    rw [nextPcPreserved]
    exact nextPcAfterJump
  rcases ExecutionClosure.generated_tick_pc_succeeds
      afterWrite target nextPcAfterWrite with
    ⟨afterTick, tickOutcome⟩
  have bodySuccess :
      ∃ final : Functions.GeneratedState,
        Functions.execute
            (Functions.decodedJalControl row.immediateEncoded row.rd)
            afterNextPc =
          .ok Functions.RETIRE_SUCCESS final := by
    refine ⟨afterWrite, ?_⟩
    rw [show Functions.execute
        (Functions.decodedJalControl row.immediateEncoded row.rd) =
          Functions.execute_JAL immediate (.Regidx row.rd) by
      rfl]
    rw [Functions.execute_JAL_eq]
    simp only [
      nextPcReadAfterNextPc,
      pcReadAfterNextPc,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
    rw [jumpOutcomeGenerated]
    simp only [Functions.RETIRE_SUCCESS, bind, EStateM.bind]
    rw [writeOutcome]
    simp only [pure, EStateM.pure]
  have retirementEq :
      RiscvRefinement.Opcodes.Jal.airRetirement row = {
        nextPc := target
        write := RiscvRefinement.architecturalWrite row.rd link
        read := none
        store := none
      } := by
    rw [localRefinement.retirement]
    simp [
      RiscvRefinement.Opcodes.Jal.execute,
      RiscvRefinement.Air.Bridge.Jal.jumpTarget,
      RiscvRefinement.Air.Bridge.Jal.immediate,
      Functions.sign_extend,
      Sail.BitVec.signExtend,
      immediate,
      target,
      link,
    ]
  have observedSuccess :
      ∃ final : Functions.GeneratedState,
        Functions.normalizedJumpCompletion row.pc row.rd (pure ())
            (do
              let currentPc ← Sail.readReg Register.PC
              pure (currentPc + Functions.sign_extend (m := 32)
                (RiscvRefinement.Decode.jalImmediate
                  row.immediateEncoded))) initial =
          .ok {
            generatedResult := Functions.RETIRE_SUCCESS
            retirement := some
              (RiscvRefinement.Opcodes.Jal.airRetirement row)
          } final := by
    refine ⟨afterTick, ?_⟩
    rw [retirementEq]
    simp only [
      Functions.normalizedJumpCompletion,
      Functions.completeJumpEffects,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
    rw [installNextPcGenerated]
    simp only [bind, EStateM.bind, pure, EStateM.pure]
    rw [nextPcReadAfterNextPc]
    simp only [bind, EStateM.bind, pure, EStateM.pure]
    rw [pcReadAfterNextPc]
    simp only [immediate, bind, EStateM.bind, pure, EStateM.pure]
    rw [jumpOutcomeGenerated]
    simp only [Functions.RETIRE_SUCCESS, bind, EStateM.bind,
      pure, EStateM.pure]
    rw [writeOutcome]
    simp only [bind, EStateM.bind, pure, EStateM.pure]
    rw [tickOutcome]
  apply constructiveExecution_of_runs
    stepNo
    (Functions.encodeJalControl row.immediateEncoded row.rd)
    (Functions.decodedJalControl row.immediateEncoded row.rd)
    row.pc
    (Functions.normalizedJumpCompletion row.pc row.rd (pure ())
      (do
        let currentPc ← Sail.readReg Register.PC
        pure (currentPc + Functions.sign_extend (m := 32)
          (RiscvRefinement.Decode.jalImmediate row.immediateEncoded))))
    initial (RiscvRefinement.Opcodes.Jal.airRetirement row)
    stateBindings.1.programCounter stateBindings.1.landingPadClear
    bodySuccess
  · simpa [Functions.decodedJalControl, immediate] using
      Functions.complete_JAL_normalizes row.pc immediate row.rd
  · exact observedSuccess

/-! ## JALR -/

/-- Exact generated JALR execution, including read-before-write aliasing. -/
theorem jalr_constructive
    (row : RiscvRefinement.Opcodes.Jalr.Row)
    (witness : RiscvRefinement.Opcodes.Jalr.Witness row)
    (environment : RiscvRefinement.Opcodes.Jalr.Environment row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (stateBindings :
      GeneratedInstructionStateBindings row.pc
          (Functions.encodeJalrControl row.immediate row.rs1 row.rd) initial ∧
        GeneratedUnaryRegisterStateBindings initial row.rs1 row.rd
          (environment.pre.registers row.rs1)
          (environment.pre.registers row.rd))
    (profileAdmission :
      GeneratedInstructionProfileAdmission row.pc
        (Functions.encodeJalrControl row.immediate row.rs1 row.rd) initial)
    (localRefinement :
      RiscvRefinement.Opcodes.Jalr.Refinement row witness environment) :
    Functions.ConstructiveGeneratedExecution stepNo
      (Functions.encodeJalrControl row.immediate row.rs1 row.rd)
      (Functions.decodedJalrControl row.immediate row.rs1 row.rd)
      (Functions.completeBaseExecution row.pc
        (Functions.execute
          (Functions.decodedJalrControl row.immediate row.rs1 row.rd)))
      (Functions.normalizedJumpCompletion row.pc row.rd
        (Functions.update_elp_state (.Regidx row.rs1))
        (do
          let base ← Functions.rX_bits (.Regidx row.rs1)
          pure (BitVec.update
            (base + Functions.sign_extend (m := 32) row.immediate)
            0 0#1)))
      initial (RiscvRefinement.Opcodes.Jalr.airRetirement row) := by
  let source : BitVec 32 := environment.pre.registers row.rs1
  let link : BitVec 32 := RiscvRefinement.nextPc row.pc
  let target : BitVec 32 := BitVec.update
    (source + Functions.sign_extend (m := 32) row.immediate) 0 0#1
  let afterNextPc : Functions.GeneratedState := {
    initial with regs := initial.regs.insert Register.nextPC link
  }
  let afterJump : Functions.GeneratedState := {
    afterNextPc with regs := afterNextPc.regs.insert Register.nextPC target
  }
  have pcAfterNextPc :
      afterNextPc.regs.get? Register.PC = some row.pc := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using stateBindings.1.programCounter
  have nextPcAfterNextPc :
      afterNextPc.regs.get? Register.nextPC = some link := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert_self]
  rcases stateBindings.1.decodeState.misa with
    ⟨misaValue, misaInitial, _misaMEnabled, _misaCDisabled⟩
  have misaAfterNextPc :
      afterNextPc.regs.get? Register.misa = some misaValue := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using misaInitial
  have installNextPc :
      ((PreSail.writeReg Register.nextPC
          (RiscvRefinement.nextPc row.pc) : SailM PUnit) initial) =
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
  have installNextPcGenerated :
      ((PreSail.writeReg Register.nextPC
          (Sail.BitVec.addInt row.pc 4) : SailM PUnit) initial) =
        .ok () afterNextPc := by
    simpa [link, RiscvRefinement.nextPc] using installNextPc
  have nextPcReadAfterNextPc :
      Functions.get_next_pc () afterNextPc = .ok link afterNextPc := by
    simp [
      Functions.get_next_pc,
      PreSail.readReg,
      nextPcAfterNextPc,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ]
  have privilegeAfterNextPc :
      afterNextPc.regs.get? Register.cur_privilege = some .Machine := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using stateBindings.1.privilege
  rcases stateBindings.1.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgInitial⟩
  have mseccfgAfterNextPc :
      afterNextPc.regs.get? Register.mseccfg = some mseccfgValue := by
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simpa using mseccfgInitial
  have sourceAfterNextPc :
      generatedRegisterValue? afterNextPc row.rs1 = some source := by
    rw [ExecutionClosure.generatedRegisterValue?_insert_nextPC]
    exact stateBindings.2.source
  have readOutcome := ExecutionClosure.generatedRegister_read_succeeds
    afterNextPc row.rs1 source sourceAfterNextPc
  have beforeOutcome :
      Functions.update_elp_state (.Regidx row.rs1) afterNextPc =
        .ok () afterNextPc :=
    update_elp_state_succeeds row.rs1 afterNextPc mseccfgValue
      profileAdmission.landingPadExtensionDisabled privilegeAfterNextPc
      mseccfgAfterNextPc
  have targetEq : target = row.target.word := by
    rw [localRefinement.target]
    exact generated_jalr_target_eq source row.immediate
  have targetAligned : target.toNat % 4 = 0 := by
    rw [targetEq]
    exact localRefinement.successfulAlignment
  have jumpOutcome :
      Functions.jump_to target afterNextPc =
        .ok Functions.RETIRE_SUCCESS afterJump := by
    simpa [afterJump] using
      jump_to_aligned_succeeds target afterNextPc misaValue
        misaAfterNextPc targetAligned
  have jumpOutcomeGenerated :
      Functions.jump_to
          (BitVec.update
            (RiscvRefinement.Sail.Generated.executeAddiValue
              source row.immediate)
            0 0#1)
          afterNextPc =
        .ok Functions.RETIRE_SUCCESS afterJump := by
    simpa [target] using jumpOutcome
  rcases ExecutionClosure.generatedRegister_write_succeeds
      afterJump row.rd link with
    ⟨afterWrite, writeOutcome, nextPcPreserved⟩
  have nextPcAfterJump :
      afterJump.regs.get? Register.nextPC = some target := by
    simp [afterJump, Std.ExtDHashMap.get?_insert_self]
  have nextPcAfterWrite :
      afterWrite.regs.get? Register.nextPC = some target := by
    rw [nextPcPreserved]
    exact nextPcAfterJump
  rcases ExecutionClosure.generated_tick_pc_succeeds
      afterWrite target nextPcAfterWrite with
    ⟨afterTick, tickOutcome⟩
  have bodySuccess :
      ∃ final : Functions.GeneratedState,
        Functions.execute
            (Functions.decodedJalrControl
              row.immediate row.rs1 row.rd) afterNextPc =
          .ok Functions.RETIRE_SUCCESS final := by
    refine ⟨afterWrite, ?_⟩
    rw [show Functions.execute
        (Functions.decodedJalrControl row.immediate row.rs1 row.rd) =
          Functions.execute_JALR row.immediate
            (.Regidx row.rs1) (.Regidx row.rd) by
      rfl]
    rw [Functions.execute_JALR_eq]
    simp only [
      beforeOutcome,
      nextPcReadAfterNextPc,
      readOutcome,
      source,
      Functions.generatedAddiValue_eq,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
    rw [jumpOutcomeGenerated]
    simp only [Functions.RETIRE_SUCCESS, bind, EStateM.bind]
    rw [writeOutcome]
    simp only [pure, EStateM.pure]
  have retirementEq :
      RiscvRefinement.Opcodes.Jalr.airRetirement row = {
        nextPc := target
        write := RiscvRefinement.architecturalWrite row.rd link
        read := none
        store := none
      } := by
    rw [localRefinement.retirement]
    simp [
      RiscvRefinement.Opcodes.Jalr.execute,
      RiscvRefinement.Air.Bridge.Jalr.jumpTarget,
      Functions.sign_extend,
      Sail.BitVec.signExtend,
      generated_jalr_target_eq,
      environment.pcBinds,
      source,
      target,
      link,
    ]
  have observedSuccess :
      ∃ final : Functions.GeneratedState,
        Functions.normalizedJumpCompletion row.pc row.rd
            (Functions.update_elp_state (.Regidx row.rs1))
            (do
              let base ← Functions.rX_bits (.Regidx row.rs1)
              pure (BitVec.update
                (base + Functions.sign_extend (m := 32) row.immediate)
                0 0#1)) initial =
          .ok {
            generatedResult := Functions.RETIRE_SUCCESS
            retirement := some
              (RiscvRefinement.Opcodes.Jalr.airRetirement row)
          } final := by
    refine ⟨afterTick, ?_⟩
    rw [retirementEq]
    simp only [
      Functions.normalizedJumpCompletion,
      Functions.completeJumpEffects,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
    rw [installNextPcGenerated]
    simp only [bind, EStateM.bind, pure, EStateM.pure]
    rw [beforeOutcome]
    simp only [bind, EStateM.bind, pure, EStateM.pure]
    rw [nextPcReadAfterNextPc]
    simp only [bind, EStateM.bind, pure, EStateM.pure]
    rw [readOutcome]
    simp only [source, Functions.generatedAddiValue_eq,
      bind, EStateM.bind, pure, EStateM.pure]
    rw [jumpOutcomeGenerated]
    simp only [Functions.RETIRE_SUCCESS, bind, EStateM.bind,
      pure, EStateM.pure]
    rw [writeOutcome]
    simp only [bind, EStateM.bind, pure, EStateM.pure]
    rw [tickOutcome]
    rfl
  apply constructiveExecution_of_runs
    stepNo
    (Functions.encodeJalrControl row.immediate row.rs1 row.rd)
    (Functions.decodedJalrControl row.immediate row.rs1 row.rd)
    row.pc
    (Functions.normalizedJumpCompletion row.pc row.rd
      (Functions.update_elp_state (.Regidx row.rs1))
      (do
        let base ← Functions.rX_bits (.Regidx row.rs1)
        pure (BitVec.update
          (base + Functions.sign_extend (m := 32) row.immediate)
          0 0#1)))
    initial (RiscvRefinement.Opcodes.Jalr.airRetirement row)
    stateBindings.1.programCounter stateBindings.1.landingPadClear
    bodySuccess
  · simpa [Functions.decodedJalrControl] using
      Functions.complete_JALR_normalizes
        row.pc row.immediate row.rs1 row.rd
  · exact observedSuccess

end LeanRV32IM.Publication.ExecutionControl
