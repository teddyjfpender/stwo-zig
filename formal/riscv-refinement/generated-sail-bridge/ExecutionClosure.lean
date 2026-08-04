import Composition

/-!
# Constructive generated-execution closure

The generated opcode normalizers are equalities of concrete `SailM` programs.
This module records the stronger, execution-level fact needed by the FV-1/FV-2
boundary: the exact generated program actually succeeds from the bound initial
state and its observation is the AIR retirement.  In particular, the closure
does not accept a generated outcome, final state, or expected observation as a
premise.
-/

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 100_000

open Sail

namespace LeanRV32IM.Publication.ExecutionClosure

open RiscvRefinement

/--
An exact generated program and its non-destructive observation both succeed
from the same concrete initial state, reach the same raw final state, and expose
the stated retirement.  The final state is an output of the proposition, never
an input premise.
-/
structure SuccessfulGeneratedRetirement
    (program : SailM ExecutionResult)
    (observed : SailM
      (LeanRV32IM.Functions.ObservedExecution
        ExecutionResult))
    (initial : LeanRV32IM.Functions.GeneratedState)
    (retirement : RiscvRefinement.Retirement) : Prop where
  exactErasure :
    LeanRV32IM.Functions.eraseObservation observed = program
  execution :
    ∃ final : LeanRV32IM.Functions.GeneratedState,
      observed initial = .ok {
        generatedResult := LeanRV32IM.Functions.RETIRE_SUCCESS
        retirement := some retirement
      } final ∧
      program initial =
        .ok LeanRV32IM.Functions.RETIRE_SUCCESS final

/-- The raw generated success is a consequence, not an input hypothesis. -/
theorem SuccessfulGeneratedRetirement.generated_succeeds
    {program : SailM ExecutionResult}
    {observed : SailM
      (LeanRV32IM.Functions.ObservedExecution ExecutionResult)}
    {initial : LeanRV32IM.Functions.GeneratedState}
    {retirement : RiscvRefinement.Retirement}
    (closure : SuccessfulGeneratedRetirement
      program observed initial retirement) :
    ∃ final : LeanRV32IM.Functions.GeneratedState,
      program initial =
        .ok LeanRV32IM.Functions.RETIRE_SUCCESS final := by
  rcases closure.execution with ⟨final, _, generatedOutcome⟩
  exact ⟨final, generatedOutcome⟩

/-- The expected observation is likewise produced by execution. -/
theorem SuccessfulGeneratedRetirement.observed_succeeds
    {program : SailM ExecutionResult}
    {observed : SailM
      (LeanRV32IM.Functions.ObservedExecution ExecutionResult)}
    {initial : LeanRV32IM.Functions.GeneratedState}
    {retirement : RiscvRefinement.Retirement}
    (closure : SuccessfulGeneratedRetirement
      program observed initial retirement) :
    ∃ final : LeanRV32IM.Functions.GeneratedState,
      observed initial = .ok {
        generatedResult := LeanRV32IM.Functions.RETIRE_SUCCESS
        retirement := some retirement
      } final := by
  rcases closure.execution with ⟨final, observedOutcome, _⟩
  exact ⟨final, observedOutcome⟩

/--
The proposition that must become a field of every public opcode result.  Its
only inputs are the componentwise bindings already exposed at the publication
boundary.  A successful generated outcome and its raw final state occur only
under the existential in the conclusion.
-/
def ClosesFromComponents
    (stateBindings profileAdmission : Prop)
    (program : SailM ExecutionResult)
    (observed : SailM
      (LeanRV32IM.Functions.ObservedExecution ExecutionResult))
    (initial : LeanRV32IM.Functions.GeneratedState)
    (retirement : RiscvRefinement.Retirement) : Prop :=
  stateBindings → profileAdmission →
    SuccessfulGeneratedRetirement
      program observed initial retirement

/-- Exhaustive, kernel-proved case split for a generated integer register. -/
private theorem bitVec5_cases (index : BitVec 5) :
    index = 0#5 ∨ index = 1#5 ∨ index = 2#5 ∨ index = 3#5 ∨
    index = 4#5 ∨ index = 5#5 ∨ index = 6#5 ∨ index = 7#5 ∨
    index = 8#5 ∨ index = 9#5 ∨ index = 10#5 ∨ index = 11#5 ∨
    index = 12#5 ∨ index = 13#5 ∨ index = 14#5 ∨ index = 15#5 ∨
    index = 16#5 ∨ index = 17#5 ∨ index = 18#5 ∨ index = 19#5 ∨
    index = 20#5 ∨ index = 21#5 ∨ index = 22#5 ∨ index = 23#5 ∨
    index = 24#5 ∨ index = 25#5 ∨ index = 26#5 ∨ index = 27#5 ∨
    index = 28#5 ∨ index = 29#5 ∨ index = 30#5 ∨ index = 31#5 := by
  simp only [← BitVec.toNat_inj]
  have bound := index.isLt
  simp at bound ⊢
  omega

/-!
The next two lemmas are deliberately stated against the exact generated
`rX_bits`/`wX_bits` programs.  They are the reusable totality boundary needed
to turn register-value component bindings into constructive normalizer runs.
-/

theorem generatedRegister_read_succeeds
    (initial : LeanRV32IM.Functions.GeneratedState)
    (index : BitVec 5)
    (value : BitVec 32)
    (binding :
      LeanRV32IM.Publication.generatedRegisterValue?
          initial index = some value) :
    LeanRV32IM.Functions.rX_bits (.Regidx index) initial =
      .ok value initial := by
  rcases bitVec5_cases index with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [
      LeanRV32IM.Publication.generatedRegisterValue?,
      LeanRV32IM.Functions.generatedX?,
      LeanRV32IM.Functions.runGeneratedValue?,
      LeanRV32IM.Functions.rX_bits,
      LeanRV32IM.Functions.rX,
      PreSail.readReg,
      LeanRV32IM.Functions.regval_from_reg,
      LeanRV32IM.Functions.zero_reg,
      RiscvRefinement.zeroWord,
      Sail.BitVec.toNatInt,
      bind,
      EStateM.bind,
      EStateM.map,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
    ] at binding ⊢ <;>
    try simp_all <;>
    try rfl
  all_goals
    generalize hreg : initial.regs.get? _ = registerValue at binding ⊢
    cases registerValue with
    | none =>
        exfalso
        change (none : Option (BitVec 32)) = some value at binding
        simp at binding
    | some registerValue =>
        simp_all [EStateM.pure]

theorem generatedRegister_write_succeeds
    (initial : LeanRV32IM.Functions.GeneratedState)
    (index : BitVec 5)
    (value : BitVec 32) :
    ∃ final : LeanRV32IM.Functions.GeneratedState,
      LeanRV32IM.Functions.wX_bits (.Regidx index) value initial =
        .ok () final ∧
      final.regs.get? Register.nextPC =
        initial.regs.get? Register.nextPC := by
  rcases bitVec5_cases index with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [
      LeanRV32IM.Functions.wX_bits,
      LeanRV32IM.Functions.wX,
      LeanRV32IM.Functions.xreg_write_callback,
      LeanRV32IM.Functions.encdec_reg_forwards_matches,
      LeanRV32IM.Functions.encdec_reg_forwards,
      LeanRV32IM.Functions.get_config_use_abi_names,
      LeanRV32IM.Functions.not,
      LeanRV32IM.Functions.to_bits,
      LeanRV32IM.Functions.regval_into_reg,
      LeanRV32IM.Functions.xreg_full_write_callback,
      PreSail.writeReg,
      Sail.BitVec.toNatInt,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      modify,
      modifyGet,
      EStateM.modifyGet,
      Std.ExtDHashMap.get?_insert,
      LeanRV32IM.Functions.reg_name_forwards,
      LeanRV32IM.Functions.reg_arch_name_raw_forwards,
    ] <;>
    exact ⟨_, rfl, by simp [Std.ExtDHashMap.get?_insert]⟩

/-- `tick_pc` is total once the preceding base arm has installed `nextPC`. -/
theorem generated_tick_pc_succeeds
    (initial : LeanRV32IM.Functions.GeneratedState)
    (nextPcValue : BitVec 32)
    (binding :
      initial.regs.get? Register.nextPC = some nextPcValue) :
    ∃ final : LeanRV32IM.Functions.GeneratedState,
      LeanRV32IM.Functions.tick_pc () initial = .ok () final := by
  simp [
    LeanRV32IM.Functions.tick_pc,
    PreSail.readReg,
    PreSail.writeReg,
    binding,
    bind,
    EStateM.bind,
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
    LeanRV32IM.Functions.pc_write_callback,
  ]

/-!
## Reusable straight-line register constructors

The next-PC write performed by the generated base arm cannot change an
integer-register observation.  Keeping this fact separate avoids a 32-way
register reduction in every opcode publication theorem.
-/

theorem generatedRegisterValue?_insert_nextPC
    (initial : LeanRV32IM.Functions.GeneratedState)
    (index : BitVec 5)
    (nextPcValue : BitVec 32) :
    LeanRV32IM.Publication.generatedRegisterValue?
        { initial with
          regs := initial.regs.insert Register.nextPC nextPcValue }
        index =
      LeanRV32IM.Publication.generatedRegisterValue? initial index := by
  rcases bitVec5_cases index with
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl |
    rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [
      LeanRV32IM.Publication.generatedRegisterValue?,
      LeanRV32IM.Functions.generatedX?,
      LeanRV32IM.Functions.runGeneratedValue?,
      LeanRV32IM.Functions.rX_bits,
      LeanRV32IM.Functions.rX,
      PreSail.readReg,
      LeanRV32IM.Functions.regval_from_reg,
      LeanRV32IM.Functions.zero_reg,
      RiscvRefinement.zeroWord,
      Sail.BitVec.toNatInt,
      bind,
      EStateM.bind,
      EStateM.map,
      pure,
      EStateM.pure,
      MonadState.get,
      getThe,
      MonadStateOf.get,
      EStateM.get,
      Std.ExtDHashMap.get?_insert,
    ]
  all_goals
    generalize hreg : initial.regs.get? _ = registerValue at ⊢
    cases registerValue with
    | none =>
        change (none : Option (BitVec 32)) = none
        rfl
    | some registerValue =>
        change some registerValue = some registerValue
        rfl

/--
Lift exact success of a decoded body on the post-nextPC state into exact
success of the generated base arm.  The final state remains an existential
output.
-/
theorem runBaseAfterDecode_succeeds_of_body
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (initial : LeanRV32IM.Functions.GeneratedState)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (LeanRV32IM.Functions.landing_pad_bits_backwards
          .NO_LP_EXPECTED))
    (bodySuccess :
      ∃ final : LeanRV32IM.Functions.GeneratedState,
        LeanRV32IM.Functions.execute decoded {
          initial with
          regs := initial.regs.insert Register.nextPC
            (RiscvRefinement.nextPc pc)
        } = .ok LeanRV32IM.Functions.RETIRE_SUCCESS final) :
    LeanRV32IM.Functions.GeneratedRunBaseSuccess
      stepNo word decoded initial := by
  rcases bodySuccess with ⟨final, bodyOutcome⟩
  constructor
  simp [
    LeanRV32IM.Functions.runBaseAfterDecode,
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
    LeanRV32IM.Functions.is_landing_pad_expected,
    LeanRV32IM.Functions.landing_pad_bits_backwards,
    LeanRV32IM.Functions.get_config_print_instr,
    bodyOutcome,
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
    pcBinding,
    landingPadClear,
  ]
  exact ⟨final, rfl⟩

/--
Core constructor for a successful register-writing generated instruction.
The value program must be state-neutral on the concrete post-nextPC state;
pure, unary-read, and binary-read wrappers below discharge that condition.
-/
theorem constructiveRegisterExecution_of_value
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (rd : BitVec 5)
    (valueProgram : SailM (BitVec 32))
    (value retirementValue : BitVec 32)
    (retirement : RiscvRefinement.Retirement)
    (initial : LeanRV32IM.Functions.GeneratedState)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (LeanRV32IM.Functions.landing_pad_bits_backwards
          .NO_LP_EXPECTED))
    (valueSuccess :
      valueProgram {
        initial with
        regs := initial.regs.insert Register.nextPC
          (RiscvRefinement.nextPc pc)
      } = .ok value {
        initial with
        regs := initial.regs.insert Register.nextPC
          (RiscvRefinement.nextPc pc)
      })
    (valueMatchesRetirement : value = retirementValue)
    (executeClause :
      LeanRV32IM.Functions.execute decoded = do
        let result ← valueProgram
        LeanRV32IM.Functions.wX_bits (.Regidx rd) result
        pure LeanRV32IM.Functions.RETIRE_SUCCESS)
    (normalizes :
      LeanRV32IM.Functions.completeBaseExecution pc
          (LeanRV32IM.Functions.execute decoded) =
        LeanRV32IM.Functions.eraseObservation
          (LeanRV32IM.Functions.normalizedRegisterCompletion
            pc rd valueProgram))
    (retirementEq :
      retirement = {
        nextPc := RiscvRefinement.nextPc pc
        write := RiscvRefinement.architecturalWrite rd retirementValue
        read := none
        store := none
      }) :
    LeanRV32IM.Functions.ConstructiveGeneratedExecution
      stepNo word decoded
      (LeanRV32IM.Functions.completeBaseExecution pc
        (LeanRV32IM.Functions.execute decoded))
      (LeanRV32IM.Functions.normalizedRegisterCompletion
        pc rd valueProgram)
      initial retirement := by
  let afterNextPc : LeanRV32IM.Functions.GeneratedState := {
    initial with
    regs := initial.regs.insert Register.nextPC
      (RiscvRefinement.nextPc pc)
  }
  rcases generatedRegister_write_succeeds afterNextPc rd value with
    ⟨afterWrite, writeOutcome, nextPcPreserved⟩
  have nextPcBinding :
      afterNextPc.regs.get? Register.nextPC =
        some (RiscvRefinement.nextPc pc) := by
    simp [afterNextPc, Std.ExtDHashMap.get?_insert]
  have afterWriteNextPc :
      afterWrite.regs.get? Register.nextPC =
        some (RiscvRefinement.nextPc pc) := by
    rw [nextPcPreserved]
    exact nextPcBinding
  rcases generated_tick_pc_succeeds afterWrite
      (RiscvRefinement.nextPc pc) afterWriteNextPc with
    ⟨afterTick, tickOutcome⟩
  have bodySuccess :
      ∃ final : LeanRV32IM.Functions.GeneratedState,
        LeanRV32IM.Functions.execute decoded afterNextPc =
          .ok LeanRV32IM.Functions.RETIRE_SUCCESS final := by
    refine ⟨afterWrite, ?_⟩
    rw [executeClause]
    simp [
      afterNextPc,
      valueSuccess,
      writeOutcome,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
  have observedOutcome :
      LeanRV32IM.Functions.normalizedRegisterCompletion
          pc rd valueProgram initial =
        .ok {
          generatedResult := LeanRV32IM.Functions.RETIRE_SUCCESS
          retirement := some retirement
        } afterTick := by
    rw [retirementEq, ← valueMatchesRetirement]
    simp [
      LeanRV32IM.Functions.normalizedRegisterCompletion,
      LeanRV32IM.Functions.completeRegisterEffects,
      afterNextPc,
      valueSuccess,
      writeOutcome,
      tickOutcome,
      PreSail.writeReg,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
      modify,
      modifyGet,
      MonadStateOf.modifyGet,
      EStateM.modifyGet,
    ]
  constructor
  · exact runBaseAfterDecode_succeeds_of_body
      stepNo word decoded pc initial pcBinding landingPadClear bodySuccess
  · constructor
    · exact normalizes.symm
    · refine ⟨afterTick, observedOutcome, ?_⟩
      calc
        LeanRV32IM.Functions.completeBaseExecution pc
            (LeanRV32IM.Functions.execute decoded) initial =
            LeanRV32IM.Functions.eraseObservation
              (LeanRV32IM.Functions.normalizedRegisterCompletion
                pc rd valueProgram) initial :=
          congrFun normalizes initial
        _ = .ok LeanRV32IM.Functions.RETIRE_SUCCESS afterTick := by
          simp [
            LeanRV32IM.Functions.eraseObservation,
            observedOutcome,
          ]

/-- Constructive execution for a destination write with a pure value. -/
theorem constructivePureRegisterExecution
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (rd : BitVec 5)
    (value retirementValue : BitVec 32)
    (retirement : RiscvRefinement.Retirement)
    (initial : LeanRV32IM.Functions.GeneratedState)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (LeanRV32IM.Functions.landing_pad_bits_backwards
          .NO_LP_EXPECTED))
    (valueMatchesRetirement : value = retirementValue)
    (executeClause :
      LeanRV32IM.Functions.execute decoded = do
        LeanRV32IM.Functions.wX_bits (.Regidx rd) value
        pure LeanRV32IM.Functions.RETIRE_SUCCESS)
    (normalizes :
      LeanRV32IM.Functions.completeBaseExecution pc
          (LeanRV32IM.Functions.execute decoded) =
        LeanRV32IM.Functions.eraseObservation
          (LeanRV32IM.Functions.normalizedRegisterCompletion
            pc rd (pure value)))
    (retirementEq :
      retirement = {
        nextPc := RiscvRefinement.nextPc pc
        write := RiscvRefinement.architecturalWrite rd retirementValue
        read := none
        store := none
      }) :
    LeanRV32IM.Functions.ConstructiveGeneratedExecution
      stepNo word decoded
      (LeanRV32IM.Functions.completeBaseExecution pc
        (LeanRV32IM.Functions.execute decoded))
      (LeanRV32IM.Functions.normalizedRegisterCompletion
        pc rd (pure value))
      initial retirement := by
  apply constructiveRegisterExecution_of_value
    stepNo word decoded pc rd (pure value) value retirementValue retirement
    initial pcBinding landingPadClear
  · rfl
  · exact valueMatchesRetirement
  · simpa using executeClause
  · exact normalizes
  · exact retirementEq

/-- Constructive execution for a register write computed from one read. -/
theorem constructiveUnaryRegisterExecution
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (rs1 rd : BitVec 5)
    (source : BitVec 32)
    (compute : BitVec 32 → BitVec 32)
    (retirementValue : BitVec 32)
    (retirement : RiscvRefinement.Retirement)
    (initial : LeanRV32IM.Functions.GeneratedState)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (LeanRV32IM.Functions.landing_pad_bits_backwards
          .NO_LP_EXPECTED))
    (sourceBinding :
      LeanRV32IM.Publication.generatedRegisterValue? initial rs1 =
        some source)
    (valueMatchesRetirement : compute source = retirementValue)
    (executeClause :
      LeanRV32IM.Functions.execute decoded = do
        let operand ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
        LeanRV32IM.Functions.wX_bits (.Regidx rd) (compute operand)
        pure LeanRV32IM.Functions.RETIRE_SUCCESS)
    (normalizes :
      LeanRV32IM.Functions.completeBaseExecution pc
          (LeanRV32IM.Functions.execute decoded) =
        LeanRV32IM.Functions.eraseObservation
          (LeanRV32IM.Functions.normalizedRegisterCompletion pc rd (do
            let operand ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
            pure (compute operand))))
    (retirementEq :
      retirement = {
        nextPc := RiscvRefinement.nextPc pc
        write := RiscvRefinement.architecturalWrite rd retirementValue
        read := none
        store := none
      }) :
    LeanRV32IM.Functions.ConstructiveGeneratedExecution
      stepNo word decoded
      (LeanRV32IM.Functions.completeBaseExecution pc
        (LeanRV32IM.Functions.execute decoded))
      (LeanRV32IM.Functions.normalizedRegisterCompletion pc rd (do
        let operand ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
        pure (compute operand)))
      initial retirement := by
  let afterNextPc : LeanRV32IM.Functions.GeneratedState := {
    initial with
    regs := initial.regs.insert Register.nextPC
      (RiscvRefinement.nextPc pc)
  }
  have sourceAfterNextPc :
      LeanRV32IM.Publication.generatedRegisterValue?
          afterNextPc rs1 = some source := by
    rw [generatedRegisterValue?_insert_nextPC]
    exact sourceBinding
  have readOutcome := generatedRegister_read_succeeds
    afterNextPc rs1 source sourceAfterNextPc
  apply constructiveRegisterExecution_of_value
    stepNo word decoded pc rd
    (do
      let operand ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
      pure (compute operand))
    (compute source) retirementValue retirement initial
    pcBinding landingPadClear
  · simp [afterNextPc, readOutcome, bind, EStateM.bind, pure, EStateM.pure]
  · exact valueMatchesRetirement
  · simpa using executeClause
  · exact normalizes
  · exact retirementEq

/-- Constructive execution for a register write computed from two reads. -/
theorem constructiveBinaryRegisterExecution
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (rs1 rs2 rd : BitVec 5)
    (source1 source2 : BitVec 32)
    (compute : BitVec 32 → BitVec 32 → BitVec 32)
    (retirementValue : BitVec 32)
    (retirement : RiscvRefinement.Retirement)
    (initial : LeanRV32IM.Functions.GeneratedState)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (LeanRV32IM.Functions.landing_pad_bits_backwards
          .NO_LP_EXPECTED))
    (sourceOneBinding :
      LeanRV32IM.Publication.generatedRegisterValue? initial rs1 =
        some source1)
    (sourceTwoBinding :
      LeanRV32IM.Publication.generatedRegisterValue? initial rs2 =
        some source2)
    (valueMatchesRetirement :
      compute source1 source2 = retirementValue)
    (executeClause :
      LeanRV32IM.Functions.execute decoded = do
        let operand1 ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
        let operand2 ← LeanRV32IM.Functions.rX_bits (.Regidx rs2)
        LeanRV32IM.Functions.wX_bits (.Regidx rd)
          (compute operand1 operand2)
        pure LeanRV32IM.Functions.RETIRE_SUCCESS)
    (normalizes :
      LeanRV32IM.Functions.completeBaseExecution pc
          (LeanRV32IM.Functions.execute decoded) =
        LeanRV32IM.Functions.eraseObservation
          (LeanRV32IM.Functions.normalizedRegisterCompletion pc rd (do
            let operand1 ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
            let operand2 ← LeanRV32IM.Functions.rX_bits (.Regidx rs2)
            pure (compute operand1 operand2))))
    (retirementEq :
      retirement = {
        nextPc := RiscvRefinement.nextPc pc
        write := RiscvRefinement.architecturalWrite rd retirementValue
        read := none
        store := none
      }) :
    LeanRV32IM.Functions.ConstructiveGeneratedExecution
      stepNo word decoded
      (LeanRV32IM.Functions.completeBaseExecution pc
        (LeanRV32IM.Functions.execute decoded))
      (LeanRV32IM.Functions.normalizedRegisterCompletion pc rd (do
        let operand1 ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
        let operand2 ← LeanRV32IM.Functions.rX_bits (.Regidx rs2)
        pure (compute operand1 operand2)))
      initial retirement := by
  let afterNextPc : LeanRV32IM.Functions.GeneratedState := {
    initial with
    regs := initial.regs.insert Register.nextPC
      (RiscvRefinement.nextPc pc)
  }
  have sourceOneAfterNextPc :
      LeanRV32IM.Publication.generatedRegisterValue?
          afterNextPc rs1 = some source1 := by
    rw [generatedRegisterValue?_insert_nextPC]
    exact sourceOneBinding
  have sourceTwoAfterNextPc :
      LeanRV32IM.Publication.generatedRegisterValue?
          afterNextPc rs2 = some source2 := by
    rw [generatedRegisterValue?_insert_nextPC]
    exact sourceTwoBinding
  have readOneOutcome := generatedRegister_read_succeeds
    afterNextPc rs1 source1 sourceOneAfterNextPc
  have readTwoOutcome := generatedRegister_read_succeeds
    afterNextPc rs2 source2 sourceTwoAfterNextPc
  apply constructiveRegisterExecution_of_value
    stepNo word decoded pc rd
    (do
      let operand1 ← LeanRV32IM.Functions.rX_bits (.Regidx rs1)
      let operand2 ← LeanRV32IM.Functions.rX_bits (.Regidx rs2)
      pure (compute operand1 operand2))
    (compute source1 source2) retirementValue retirement initial
    pcBinding landingPadClear
  · simp [
      afterNextPc,
      readOneOutcome,
      readTwoOutcome,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
  · exact valueMatchesRetirement
  · simpa using executeClause
  · exact normalizes
  · exact retirementEq

/--
Execution-strength field to add to the current generic publication bundle.
Family modules fix `program` and `observed` to their exact generated
`completeBaseExecution` and reviewed normalizer; callers provide only
component bindings.  Full `try_step` construction remains the distinct FV-4
obligation; FV-1 supplies the existing premise-free erasure/framing theorem.
-/
structure ConstructiveGeneratedOpcodeComposition
    (stateBindings profileAdmission : Prop)
    (program : SailM ExecutionResult)
    (observed : SailM
      (LeanRV32IM.Functions.ObservedExecution ExecutionResult))
    (initial : LeanRV32IM.Functions.GeneratedState)
    (retirement : RiscvRefinement.Retirement) : Prop where
  opcodeExecution :
    ClosesFromComponents stateBindings profileAdmission
      program observed initial retirement

/-!
## Missing component obligations for full construction

The existing register bindings can construct the straight-line register
normalizers.  Control-flow rows additionally need the target-alignment branch
of `jump_to`; FENCE needs the state read by `is_fiom_active`; load/store rows
need their natural-alignment facts transported to generated
`is_aligned_vaddr`, a Bare/PMA ordinary-RAM argument, and reduction of the
non-reservation arguments before the generated reservation callbacks.

Consequently, constructing `ClosesFromComponents` for all 46 selectors from
the current records is not yet sound for memory: absent PMA facts leave trap
and MMIO branches live.  The exact next implementation step after the
register-only closure is to extend the shared memory profile/state boundary
with those component facts and instantiate one execution lemma per memory
normalizer.  Neither a monad outcome nor a final state should be added to that
boundary.
-/

end LeanRV32IM.Publication.ExecutionClosure
