import Pilot
import RiscvRefinement.Publication.Acceptance
import RiscvRefinement.Publication.Opcodes
import RiscvRefinement.Publication.TeamA.Pilots
import RiscvRefinement.Publication.TeamA.Control

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

/-!
Audited cross-project composition over the exact pinned generated Sail step.
This file is compiled only after `Pilot.lean`; its trace instrumentation
retains the generated branch discriminator and base decode payload while the
erasure theorems preserve every raw generated state effect.
-/

open Sail

namespace LeanRV32IM.Functions

structure GeneratedDecodedBase where
  word : BitVec 32
  decoded : instruction
  initial : GeneratedState
  final : GeneratedState
  exactOutcome :
    ext_decode word initial = .ok decoded final

structure GeneratedActiveTrace where
  step : Step
  decodedBase : Option GeneratedDecodedBase

structure GeneratedDecodeCertificate
    (word : BitVec 32)
    (decoded : instruction) : Prop where
  exactDecoder :
    ∀ (initial final : GeneratedState)
      (actual : instruction),
      ext_decode word initial = .ok actual final →
        actual = decoded

/--
State-indexed, non-vacuous generated decoder evidence.  The generated decoder
is read-only on the admitted RV32IM path, so the exact outcome retains the
bound initial state.  This is deliberately independent of the legacy
all-states implication above: feature-gated encodings such as M instructions
decode differently when the corresponding MISA bit is disabled.
-/
structure GeneratedDecodeCertificateAt
    (word : BitVec 32)
    (decoded : instruction)
    (initial : GeneratedState) : Prop where
  exactOutcome :
    ext_decode word initial = .ok decoded initial

/-- Exact decoder success is a conclusion, never an outcome premise. -/
theorem GeneratedDecodeCertificateAt.exactSuccess
    {word : BitVec 32}
    {decoded : instruction}
    {initial : GeneratedState}
    (certificate :
      GeneratedDecodeCertificateAt word decoded initial) :
    ∃ final : GeneratedState,
      ext_decode word initial = .ok decoded final := by
  exact ⟨initial, certificate.exactOutcome⟩

/-- Determinism gives uniqueness only at the same bound state. -/
theorem GeneratedDecodeCertificateAt.exactDecoder
    {word : BitVec 32}
    {decoded : instruction}
    {initial : GeneratedState}
    (certificate :
      GeneratedDecodeCertificateAt word decoded initial)
    (actual : instruction)
    (final : GeneratedState)
    (outcome : ext_decode word initial = .ok actual final) :
    actual = decoded := by
  rw [certificate.exactOutcome] at outcome
  cases outcome
  rfl

/-- Exhaustive, kernel-proved case split for a generated integer register. -/
theorem bitVec5_cases (index : BitVec 5) :
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

/-! Small exhaustive domains used to discharge generated totality branches. -/

theorem bitVec2_cases (index : BitVec 2) :
    index = 0#2 ∨ index = 1#2 ∨ index = 2#2 ∨ index = 3#2 := by
  simp only [← BitVec.toNat_inj]
  have bound := index.isLt
  simp at bound ⊢
  omega

/-- Generated FENCE is total in Machine mode; every barrier is state-neutral. -/
theorem execute_FENCE_machine_succeeds
    (fm pred succ : BitVec 4)
    (rs rd : BitVec 5)
    (initial : GeneratedState)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine) :
    execute_FENCE fm pred succ (.Regidx rs) (.Regidx rd) initial =
      .ok RETIRE_SUCCESS initial := by
  rcases bitVec2_cases (Sail.BitVec.extractLsb pred 1 0) with
    hp | hp | hp | hp <;>
  rcases bitVec2_cases (Sail.BitVec.extractLsb succ 1 0) with
    hs | hs | hs | hs <;>
  simp [
    execute_FENCE,
    is_fiom_active,
    effective_fence_set,
    PreSail.readReg,
    privilegeBinding,
    hp,
    hs,
    PreSail.ConcurrencyInterfaceV1.sail_barrier,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
    MonadState.get,
    getThe,
    MonadStateOf.get,
    EStateM.get,
  ]

/-- Generated FENCE.TSO is total and state-neutral. -/
theorem execute_FENCE_TSO_succeeds
    (initial : GeneratedState) :
    execute_FENCE_TSO () initial = .ok RETIRE_SUCCESS initial := by
  simp [
    execute_FENCE_TSO,
    PreSail.ConcurrencyInterfaceV1.sail_barrier,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

/-- Sequential completion is constructive for a state-neutral successful body. -/
theorem completeBaseExecution_neutral_succeeds
    (pc : BitVec 32)
    (body : SailM ExecutionResult)
    (initial : GeneratedState)
    (bodySuccess :
      body {
        initial with
        regs := initial.regs.insert Register.nextPC
          (RiscvRefinement.nextPc pc)
      } = .ok RETIRE_SUCCESS {
        initial with
        regs := initial.regs.insert Register.nextPC
          (RiscvRefinement.nextPc pc)
      }) :
    ∃ final,
      completeBaseExecution pc body initial =
        .ok RETIRE_SUCCESS final := by
  simp [
    completeBaseExecution,
    bodySuccess,
    tick_pc,
    pc_write_callback,
    PreSail.readReg,
    PreSail.writeReg,
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
  ]

def encodeLuiTrace
    (imm : BitVec 20)
    (rd : BitVec 5) :
    BitVec 32 :=
  RiscvRefinement.Decode.encodeLui imm rd

def decodedLuiTrace
    (imm : BitVec 20)
    (rd : BitVec 5) :
    instruction :=
  .UTYPE (imm, .Regidx rd, .LUI)

theorem execute_decodedLuiTrace_eq
    (imm : BitVec 20)
    (rd : BitVec 5) :
    execute (decodedLuiTrace imm rd) =
      execute_UTYPE imm (.Regidx rd) .LUI := by
  rfl

theorem execute_decodedLuiTrace_success_clause
    (imm : BitVec 20)
    (rd : BitVec 5) :
    execute (decodedLuiTrace imm rd) =
      (do
        wX_bits (.Regidx rd)
          (sign_extend (m := 32) (imm +++ (0x000#12)))
        pure RETIRE_SUCCESS) := by
  calc
    execute (decodedLuiTrace imm rd) =
        execute_UTYPE imm (.Regidx rd) .LUI :=
      execute_decodedLuiTrace_eq imm rd
    _ =
        (do
          wX_bits (.Regidx rd)
            (sign_extend (m := 32) (imm +++ (0x000#12)))
          pure RETIRE_SUCCESS) :=
      execute_UTYPE_LUI_eq imm (.Regidx rd)

theorem complete_decodedLuiTrace_normalizes
    (pc : BitVec 32)
    (imm : BitVec 20)
    (rd : BitVec 5) :
    completeBaseExecution pc
        (execute (decodedLuiTrace imm rd)) =
      eraseObservation
        (normalizedRegisterCompletion pc rd
          (pure
            (sign_extend (m := 32) (imm +++ (0x000#12))))) := by
  rw [execute_decodedLuiTrace_eq]
  exact complete_LUI_normalizes pc imm rd

noncomputable def generatedUtypeDecodePreamble :
    SailM Unit := do
  let _ ← currentlyEnabled extension.Ext_Zihintpause
  let _ ← currentlyEnabled extension.Ext_Zicfilp
  pure ()

noncomputable def generatedUtypeDecodeProgram
    (decoded : instruction) :
    SailM instruction := do
  let _ ← generatedUtypeDecodePreamble
  pure decoded

/--
The eager PAUSE/LPAD decoder prefix is total under the pinned Machine profile.
Although Zicfilp support is disabled, generated do-notation still evaluates
`get_xLPE`, hence the explicit `mseccfg` binding.
-/
theorem generatedUtypeDecodePreamble_exact_at
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    generatedUtypeDecodePreamble initial = .ok () initial := by
  simp [
    generatedUtypeDecodePreamble,
    currentlyEnabled,
    get_xLPE,
    PreSail.readReg,
    pauseDisabled,
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

theorem generatedUtypeDecodeProgram_success
    (decoded actual : instruction)
    (initial final : GeneratedState)
    (outcome :
      generatedUtypeDecodeProgram decoded initial =
        .ok actual final) :
    actual = decoded := by
  unfold generatedUtypeDecodeProgram at outcome
  cases preambleOutcome :
      generatedUtypeDecodePreamble initial with
  | ok value state =>
      simp [
        bind,
        EStateM.bind,
        pure,
        EStateM.pure,
        preambleOutcome,
      ] at outcome
      exact outcome.1.symm
  | error error state =>
      simp [
        bind,
        EStateM.bind,
        preambleOutcome,
      ] at outcome

private theorem encodeLuiTrace_imm
    (imm : BitVec 20)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeLuiTrace imm rd) 31 12 = imm := by
  simp only [
    encodeLuiTrace,
    RiscvRefinement.Decode.encodeLui,
    RiscvRefinement.Decode.luiOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    Nat.reduceSub,
    Nat.reduceAdd,
  ]
  simp only [BitVec.append_eq]
  rw [
    BitVec.extractLsb'_append_eq_of_le
      (start := 12) (len := 20) (by decide),
  ]
  exact BitVec.extractLsb'_eq_self

private theorem encodeLuiTrace_rd
    (imm : BitVec 20)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeLuiTrace imm rd) 11 7 = rd := by
  simp only [
    encodeLuiTrace,
    RiscvRefinement.Decode.encodeLui,
    RiscvRefinement.Decode.luiOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    Nat.reduceSub,
    Nat.reduceAdd,
  ]
  simp only [BitVec.append_eq]
  rw [
    BitVec.extractLsb'_append_eq_of_add_le
      (start := 7) (len := 5) (by decide),
    BitVec.extractLsb'_append_eq_of_le
      (start := 7) (len := 5) (by decide),
  ]
  exact BitVec.extractLsb'_eq_self

private theorem encodeLuiTrace_opcode
    (imm : BitVec 20)
    (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeLuiTrace imm rd) 6 0 =
      (0b0110111#7 : BitVec 7) := by
  simp only [
    encodeLuiTrace,
    RiscvRefinement.Decode.encodeLui,
    RiscvRefinement.Decode.luiOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    Nat.reduceSub,
    Nat.reduceAdd,
  ]
  simp only [BitVec.append_eq]
  rw [
    BitVec.extractLsb'_append_eq_of_add_le
      (start := 0) (len := 7) (by decide),
  ]
  exact BitVec.extractLsb'_append_eq_right

private theorem lowSeven_of_lowSlice_eq
    {width : Nat}
    (word : BitVec 32)
    (lowSlice : BitVec width)
    (enough : 7 ≤ width)
    (equality : BitVec.extractLsb' 0 width word = lowSlice) :
    BitVec.extractLsb' 0 7 word =
      BitVec.extractLsb' 0 7 lowSlice := by
  have nestedEquality :=
    congrArg
      (fun value : BitVec width => BitVec.extractLsb' 0 7 value)
      equality
  have nestedExtract :
      BitVec.extractLsb' 0 7
          (BitVec.extractLsb' 0 width word) =
        BitVec.extractLsb' 0 7 word :=
    BitVec.extractLsb'_extractLsb'_of_le
      (x := word)
      (start := 0)
      (len := 7)
      (len' := width)
      (by simpa using enough)
  exact nestedExtract.symm.trans nestedEquality

private theorem lowSlice_beq_false_of_opcode_ne
    {width : Nat}
    (word : BitVec 32)
    (lowSlice : BitVec width)
    (enough : 7 ≤ width)
    (opcode : BitVec 7)
    (wordOpcode : BitVec.extractLsb' 0 7 word = opcode)
    (mismatch : opcode ≠ BitVec.extractLsb' 0 7 lowSlice) :
    (BitVec.extractLsb' 0 width word == lowSlice) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven :=
    lowSeven_of_lowSlice_eq word lowSlice enough equality
  exact mismatch (wordOpcode.symm.trans lowSeven)

private theorem encodeLuiTrace_not_zicbop
    (imm : BitVec 20)
    (rd : BitVec 5) :
    ((let word := encodeLuiTrace imm rd
      let mapping1 : BitVec 5 :=
        Sail.BitVec.extractLsb word 19 15
      let mapping0 : BitVec 5 :=
        Sail.BitVec.extractLsb word 24 20
      (encdec_cbop_zicbop_backwards_matches mapping0 &&
          encdec_reg_backwards_matches mapping1) &&
        Sail.BitVec.extractLsb word 14 0 ==
          (0b110000000010011#15 : BitVec 15)) : Bool) =
      false := by
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeLuiTrace imm rd) 14 0 ==
        (0b110000000010011#15 : BitVec 15)) =
        false := by
    simpa only [
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ] using
      lowSlice_beq_false_of_opcode_ne
        (width := 15)
        (encodeLuiTrace imm rd)
        (0b110000000010011#15 : BitVec 15)
        (by decide)
        (0b0110111#7 : BitVec 7)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeLuiTrace_opcode imm rd)
        (by decide)
  simp [lowBits]

private theorem encodeLuiTrace_not_ntl
    (imm : BitVec 20)
    (rd : BitVec 5) :
    ((let word := encodeLuiTrace imm rd
      let mapping2 : BitVec 5 :=
        Sail.BitVec.extractLsb word 24 20
      encdec_ntl_backwards_matches mapping2 &&
        (Sail.BitVec.extractLsb word 31 25 ==
            (0b0000000#7 : BitVec 7) &&
          Sail.BitVec.extractLsb word 19 0 ==
            (0x00033#20 : BitVec 20))) : Bool) =
      false := by
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeLuiTrace imm rd) 19 0 ==
        (0x00033#20 : BitVec 20)) =
        false := by
    simpa only [
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ] using
      lowSlice_beq_false_of_opcode_ne
        (width := 20)
        (encodeLuiTrace imm rd)
        (0x00033#20 : BitVec 20)
        (by decide)
        (0b0110111#7 : BitVec 7)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeLuiTrace_opcode imm rd)
        (by decide)
  simp [lowBits]

private theorem encodeLuiTrace_not_pause
    (imm : BitVec 20)
    (rd : BitVec 5) :
    (encodeLuiTrace imm rd == (0x0100000F#32 : BitVec 32)) =
      false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven :=
    congrArg
      (fun word : BitVec 32 => BitVec.extractLsb' 0 7 word)
      equality
  have encodedOpcode :
      BitVec.extractLsb' 0 7 (encodeLuiTrace imm rd) =
        (0b0110111#7 : BitVec 7) :=
    encodeLuiTrace_opcode imm rd
  have concreteEquality :
      (0b0110111#7 : BitVec 7) =
        BitVec.extractLsb' 0 7 (0x0100000F#32 : BitVec 32) :=
    encodedOpcode.symm.trans lowSeven
  have mismatch :
      (0b0110111#7 : BitVec 7) ≠
        BitVec.extractLsb' 0 7 (0x0100000F#32 : BitVec 32) := by
    decide
  exact mismatch concreteEquality

private theorem lowSeven_of_lowTwelve_eq
    (word : BitVec 32)
    (lowTwelve : BitVec 12)
    (equality :
      BitVec.extractLsb' 0 12 word = lowTwelve) :
    BitVec.extractLsb' 0 7 word =
      BitVec.extractLsb' 0 7 lowTwelve := by
  have nestedEquality :
      BitVec.extractLsb' 0 7
          (BitVec.extractLsb' 0 12 word) =
        BitVec.extractLsb' 0 7 lowTwelve :=
    congrArg
      (fun value : BitVec 12 =>
        BitVec.extractLsb' 0 7 value)
      equality
  have nestedExtract :
      BitVec.extractLsb' 0 7
          (BitVec.extractLsb' 0 12 word) =
        BitVec.extractLsb' 0 7 word :=
    BitVec.extractLsb'_extractLsb'_of_le
      (x := word)
      (start := 0)
      (len := 7)
      (len' := 12)
      (by decide)
  exact nestedExtract.symm.trans nestedEquality

private theorem encodeLuiTrace_not_lpad
    (imm : BitVec 20)
    (rd : BitVec 5) :
    (Sail.BitVec.extractLsb (encodeLuiTrace imm rd) 11 0 ==
      (0x017#12 : BitVec 12)) =
      false := by
  apply beq_eq_false_iff_ne.mpr
  intro lowTwelve
  have lowTwelve' :
      BitVec.extractLsb' 0 12 (encodeLuiTrace imm rd) =
        (0x017#12 : BitVec 12) :=
    lowTwelve
  have lowSeven :=
    lowSeven_of_lowTwelve_eq
      (encodeLuiTrace imm rd)
      (0x017#12 : BitVec 12)
      lowTwelve'
  have encodedOpcode :
      BitVec.extractLsb' 0 7 (encodeLuiTrace imm rd) =
        (0b0110111#7 : BitVec 7) :=
    encodeLuiTrace_opcode imm rd
  have concreteEquality :
      (0b0110111#7 : BitVec 7) =
        BitVec.extractLsb' 0 7 (0x017#12 : BitVec 12) :=
    encodedOpcode.symm.trans lowSeven
  have opcodeMismatch :
      (0b0110111#7 : BitVec 7) ≠
        BitVec.extractLsb' 0 7 (0x017#12 : BitVec 12) := by
    decide
  exact opcodeMismatch concreteEquality

private theorem encodeLuiTrace_is_utype
    (imm : BitVec 20)
    (rd : BitVec 5) :
    ((let word := encodeLuiTrace imm rd
      let mapping4 : BitVec 7 :=
        Sail.BitVec.extractLsb word 6 0
      let mapping3 : BitVec 5 :=
        Sail.BitVec.extractLsb word 11 7
      encdec_reg_backwards_matches mapping3 &&
        encdec_uop_backwards_matches mapping4) : Bool) =
      true := by
  simp [
    encodeLuiTrace_rd,
    encodeLuiTrace_opcode,
    encdec_reg_backwards_matches,
    base_E_enabled,
    encdec_uop_backwards_matches,
    not,
  ]

private theorem encdec_reg_backwards_encodeLuiTrace_rd
    (imm : BitVec 20)
    (rd : BitVec 5) :
    encdec_reg_backwards
        (Sail.BitVec.extractLsb (encodeLuiTrace imm rd) 11 7) =
      pure (.Regidx rd) := by
  rw [encodeLuiTrace_rd]
  simp [
    encdec_reg_backwards,
    base_E_enabled,
    regidx_bit_width,
    not,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ]

private theorem encdec_uop_backwards_encodeLuiTrace_opcode
    (imm : BitVec 20)
    (rd : BitVec 5) :
    encdec_uop_backwards
        (Sail.BitVec.extractLsb (encodeLuiTrace imm rd) 6 0) =
      pure .LUI := by
  rw [encodeLuiTrace_opcode]
  rfl

private theorem ext_decode_lui_branch
    (imm : BitVec 20)
    (rd : BitVec 5) :
    ext_decode (encodeLuiTrace imm rd) =
      generatedUtypeDecodeProgram
        (decodedLuiTrace imm rd) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    encodeLuiTrace_not_zicbop,
    encodeLuiTrace_not_ntl,
    encodeLuiTrace_not_pause,
    encodeLuiTrace_not_lpad,
    encodeLuiTrace_is_utype,
    encodeLuiTrace_imm,
    encdec_reg_backwards_encodeLuiTrace_rd,
    encdec_uop_backwards_encodeLuiTrace_opcode,
    Bool.and_false,
    Bool.false_eq_true,
    if_false,
    if_true,
    pure_bind,
    bind_assoc,
    generatedUtypeDecodePreamble,
    generatedUtypeDecodeProgram,
    decodedLuiTrace,
  ]

theorem decode_lui_certificate
    (imm : BitVec 20)
    (rd : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeLuiTrace imm rd)
      (decodedLuiTrace imm rd) := by
  constructor
  intro initial final actual outcome
  rw [
    ext_decode_lui_branch
      imm rd,
  ] at outcome
  exact
    generatedUtypeDecodeProgram_success
      (decodedLuiTrace imm rd)
      actual initial final outcome

/-- Constructive, state-indexed LUI decode under the exact eager prefix. -/
theorem decode_lui_certificate_at
    (imm : BitVec 20)
    (rd : BitVec 5)
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeLuiTrace imm rd)
      (decodedLuiTrace imm rd)
      initial := by
  constructor
  rw [ext_decode_lui_branch]
  simp [
    generatedUtypeDecodeProgram,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    generatedUtypeDecodePreamble_exact_at
      initial mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding,
  ]

def encodeFenceTrace
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    BitVec 32 :=
  RiscvRefinement.Decode.encodeFence imm rs rd

def decodedFenceTrace
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    instruction :=
  if encodeFenceTrace imm rs rd ==
      (0x8330000F#32 : BitVec 32)
  then .FENCE_TSO ()
  else
    .FENCE (
      Sail.BitVec.extractLsb imm 11 8,
      Sail.BitVec.extractLsb imm 7 4,
      Sail.BitVec.extractLsb imm 3 0,
      .Regidx rs,
      .Regidx rd)

/--
The exact generated FENCE decode is input-conditional.  `FENCE.TSO` has an
unconditional earlier decoder clause at `0x8330000F`; PAUSE is disabled by
the explicit pinned-profile fact below rather than silently identified with a
base FENCE.
-/
inductive GeneratedFenceDecodeCase
    (imm : BitVec 12)
    (rs rd : BitVec 5) : Prop where
  | tso :
      encodeFenceTrace imm rs rd =
        (0x8330000F#32 : BitVec 32) →
      GeneratedFenceDecodeCase imm rs rd
  | ordinary :
      encodeFenceTrace imm rs rd ≠
        (0x8330000F#32 : BitVec 32) →
      GeneratedFenceDecodeCase imm rs rd

theorem generatedFenceDecodeCase_total
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    GeneratedFenceDecodeCase imm rs rd := by
  by_cases tso :
      encodeFenceTrace imm rs rd =
        (0x8330000F#32 : BitVec 32)
  · exact .tso tso
  · exact .ordinary tso

theorem execute_decodedFenceTrace_clause
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    execute (decodedFenceTrace imm rs rd) =
      if encodeFenceTrace imm rs rd ==
          (0x8330000F#32 : BitVec 32)
      then execute_FENCE_TSO ()
      else
        execute_FENCE
          (Sail.BitVec.extractLsb imm 11 8)
          (Sail.BitVec.extractLsb imm 7 4)
          (Sail.BitVec.extractLsb imm 3 0)
          (.Regidx rs)
          (.Regidx rd) := by
  by_cases tso :
      encodeFenceTrace imm rs rd ==
        (0x8330000F#32 : BitVec 32)
  · simp only [decodedFenceTrace, tso, if_true]
    rfl
  · simp only [decodedFenceTrace, tso, if_false]
    rfl

/-- The exact decoded FENCE/FENCE.TSO body succeeds without changing state. -/
theorem execute_decodedFenceTrace_machine_succeeds
    (imm : BitVec 12)
    (rs rd : BitVec 5)
    (initial : GeneratedState)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine) :
    execute (decodedFenceTrace imm rs rd) initial =
      .ok RETIRE_SUCCESS initial := by
  by_cases tso :
      encodeFenceTrace imm rs rd ==
        (0x8330000F#32 : BitVec 32)
  · simpa [execute_decodedFenceTrace_clause, tso] using
      execute_FENCE_TSO_succeeds initial
  · simpa [execute_decodedFenceTrace_clause, tso] using
      execute_FENCE_machine_succeeds
        (Sail.BitVec.extractLsb imm 11 8)
        (Sail.BitVec.extractLsb imm 7 4)
        (Sail.BitVec.extractLsb imm 3 0)
        rs rd initial privilegeBinding

theorem execute_FENCE_TSO_success_clause :
    execute_FENCE_TSO () =
      (do
        Sail.ConcurrencyInterfaceV1.sail_barrier
          Barrier_RISCV_tso
        pure RETIRE_SUCCESS) := by
  rfl

theorem complete_FENCE_TSO_normalizes
    (pc : BitVec 32) :
    completeBaseExecution pc (execute_FENCE_TSO ()) =
      eraseObservation
        (normalizedSequentialNoWriteCompletion
          pc (execute_FENCE_TSO ())) :=
  (normalizedSequentialNoWriteCompletion_erases _ _).symm

theorem complete_decodedFenceTrace_normalizes
    (pc : BitVec 32)
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    completeBaseExecution pc
        (execute (decodedFenceTrace imm rs rd)) =
      if encodeFenceTrace imm rs rd ==
          (0x8330000F#32 : BitVec 32)
      then
        eraseObservation
          (normalizedSequentialNoWriteCompletion
            pc (execute_FENCE_TSO ()))
      else
        eraseObservation
          (normalizedSequentialNoWriteCompletion pc
            (execute_FENCE
              (Sail.BitVec.extractLsb imm 11 8)
              (Sail.BitVec.extractLsb imm 7 4)
              (Sail.BitVec.extractLsb imm 3 0)
              (.Regidx rs)
              (.Regidx rd))) := by
  rw [execute_decodedFenceTrace_clause]
  by_cases tso :
      encodeFenceTrace imm rs rd ==
        (0x8330000F#32 : BitVec 32)
  · simp only [tso, if_true]
    exact complete_FENCE_TSO_normalizes pc
  · simp only [tso, if_false]
    exact
      (normalizedSequentialNoWriteCompletion_erases
        pc
        (execute_FENCE
          (Sail.BitVec.extractLsb imm 11 8)
          (Sail.BitVec.extractLsb imm 7 4)
          (Sail.BitVec.extractLsb imm 3 0)
          (.Regidx rs)
          (.Regidx rd))).symm

private theorem encodeFenceTrace_opcode
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 6 0 =
      (0b0001111#7 : BitVec 7) := by
  simp only [
    encodeFenceTrace,
    RiscvRefinement.Decode.encodeFence,
    RiscvRefinement.Decode.miscMemOpcode,
    RiscvRefinement.Decode.funct3Fence,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  exact BitVec.extractLsb'_append_eq_right

private theorem encodeFenceTrace_opcode_mismatch
    (imm : BitVec 12)
    (rs rd : BitVec 5)
    (opcode : BitVec 7)
    (mismatch :
      (0b0001111#7 : BitVec 7) ≠ opcode) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 == opcode) =
      false := by
  rw [encodeFenceTrace_opcode]
  exact beq_eq_false_iff_ne.mpr mismatch

private theorem encodeFenceTrace_not_jal
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b1101111#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_jalr
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b1100111#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_branch
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b1100011#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_itype
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b0010011#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_rtype
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b0110011#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_load
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b0000011#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_store
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b0100011#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_itypew
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b0011011#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_not_rtypew
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeFenceTrace imm rs rd) 6 0 ==
      (0b0111011#7 : BitVec 7)) =
      false :=
  encodeFenceTrace_opcode_mismatch
    imm rs rd _ (by decide)

private theorem encodeFenceTrace_funct3
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 14 12 =
      (0b000#3 : BitVec 3) := by
  simp only [
    encodeFenceTrace,
    RiscvRefinement.Decode.encodeFence,
    RiscvRefinement.Decode.miscMemOpcode,
    RiscvRefinement.Decode.funct3Fence,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 12) (len := 3) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeFenceTrace_rs
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 19 15 =
      rs := by
  simp only [
    encodeFenceTrace,
    RiscvRefinement.Decode.encodeFence,
    RiscvRefinement.Decode.miscMemOpcode,
    RiscvRefinement.Decode.funct3Fence,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 15) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 15) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeFenceTrace_rd
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 11 7 =
      rd := by
  simp only [
    encodeFenceTrace,
    RiscvRefinement.Decode.encodeFence,
    RiscvRefinement.Decode.miscMemOpcode,
    RiscvRefinement.Decode.funct3Fence,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 7) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeFenceTrace_fm
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 31 28 =
      Sail.BitVec.extractLsb imm 11 8 := by
  simp only [
    encodeFenceTrace,
    RiscvRefinement.Decode.encodeFence,
    RiscvRefinement.Decode.miscMemOpcode,
    RiscvRefinement.Decode.funct3Fence,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 28) (len := 4) (by decide)]

private theorem encodeFenceTrace_pred
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 27 24 =
      Sail.BitVec.extractLsb imm 7 4 := by
  simp only [
    encodeFenceTrace,
    RiscvRefinement.Decode.encodeFence,
    RiscvRefinement.Decode.miscMemOpcode,
    RiscvRefinement.Decode.funct3Fence,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 24) (len := 4) (by decide)]

private theorem encodeFenceTrace_succ
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 23 20 =
      Sail.BitVec.extractLsb imm 3 0 := by
  simp only [
    encodeFenceTrace,
    RiscvRefinement.Decode.encodeFence,
    RiscvRefinement.Decode.miscMemOpcode,
    RiscvRefinement.Decode.funct3Fence,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 20) (len := 4) (by decide)]

private theorem encodeFenceTrace_not_zicbop
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    ((let word := encodeFenceTrace imm rs rd
      let mapping1 : BitVec 5 :=
        Sail.BitVec.extractLsb word 19 15
      let mapping0 : BitVec 5 :=
        Sail.BitVec.extractLsb word 24 20
      (encdec_cbop_zicbop_backwards_matches mapping0 &&
          encdec_reg_backwards_matches mapping1) &&
        Sail.BitVec.extractLsb word 14 0 ==
          (0b110000000010011#15 : BitVec 15)) : Bool) =
      false := by
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeFenceTrace imm rs rd) 14 0 ==
        (0b110000000010011#15 : BitVec 15)) =
        false := by
    simpa only [
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ] using
      lowSlice_beq_false_of_opcode_ne
        (width := 15)
        (encodeFenceTrace imm rs rd)
        (0b110000000010011#15 : BitVec 15)
        (by decide)
        (0b0001111#7 : BitVec 7)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeFenceTrace_opcode imm rs rd)
        (by decide)
  simp [lowBits]

private theorem encodeFenceTrace_not_ntl
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    ((let word := encodeFenceTrace imm rs rd
      let mapping2 : BitVec 5 :=
        Sail.BitVec.extractLsb word 24 20
      encdec_ntl_backwards_matches mapping2 &&
        (Sail.BitVec.extractLsb word 31 25 ==
            (0b0000000#7 : BitVec 7) &&
          Sail.BitVec.extractLsb word 19 0 ==
            (0x00033#20 : BitVec 20))) : Bool) =
      false := by
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeFenceTrace imm rs rd) 19 0 ==
        (0x00033#20 : BitVec 20)) =
        false := by
    simpa only [
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      Nat.reduceSub,
      Nat.reduceAdd,
    ] using
      lowSlice_beq_false_of_opcode_ne
        (width := 20)
        (encodeFenceTrace imm rs rd)
        (0x00033#20 : BitVec 20)
        (by decide)
        (0b0001111#7 : BitVec 7)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeFenceTrace_opcode imm rs rd)
        (by decide)
  simp [lowBits]

private theorem encodeFenceTrace_not_lpad
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    (Sail.BitVec.extractLsb (encodeFenceTrace imm rs rd) 11 0 ==
      (0x017#12 : BitVec 12)) =
      false := by
  apply beq_eq_false_iff_ne.mpr
  intro lowTwelve
  have lowTwelve' :
      BitVec.extractLsb' 0 12 (encodeFenceTrace imm rs rd) =
        (0x017#12 : BitVec 12) :=
    lowTwelve
  have lowSeven :=
    lowSeven_of_lowTwelve_eq
      (encodeFenceTrace imm rs rd)
      (0x017#12 : BitVec 12)
      lowTwelve'
  have encodedOpcode :
      BitVec.extractLsb' 0 7 (encodeFenceTrace imm rs rd) =
        (0b0001111#7 : BitVec 7) :=
    encodeFenceTrace_opcode imm rs rd
  have concreteEquality :
      (0b0001111#7 : BitVec 7) =
        BitVec.extractLsb' 0 7 (0x017#12 : BitVec 12) :=
    encodedOpcode.symm.trans lowSeven
  have opcodeMismatch :
      (0b0001111#7 : BitVec 7) ≠
        BitVec.extractLsb' 0 7 (0x017#12 : BitVec 12) := by
    decide
  exact opcodeMismatch concreteEquality

private theorem encodeFenceTrace_not_utype
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    ((let word := encodeFenceTrace imm rs rd
      let mapping4 : BitVec 7 :=
        Sail.BitVec.extractLsb word 6 0
      let mapping3 : BitVec 5 :=
        Sail.BitVec.extractLsb word 11 7
      encdec_reg_backwards_matches mapping3 &&
        encdec_uop_backwards_matches mapping4) : Bool) =
      false := by
  simp [
    encodeFenceTrace_opcode,
    encdec_uop_backwards_matches,
  ]

private theorem currentlyEnabled_pause_of_disabled
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false) :
    currentlyEnabled extension.Ext_Zihintpause =
      pure false := by
  simp [currentlyEnabled, pauseDisabled]

private theorem encodeFenceTrace_is_fence
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    ((let word := encodeFenceTrace imm rs rd
      let mapping81 : BitVec 5 :=
        Sail.BitVec.extractLsb word 11 7
      let mapping80 : BitVec 5 :=
        Sail.BitVec.extractLsb word 19 15
      (encdec_reg_backwards_matches mapping80 &&
          encdec_reg_backwards_matches mapping81) &&
        (Sail.BitVec.extractLsb word 14 12 ==
            (0b000#3 : BitVec 3) &&
          Sail.BitVec.extractLsb word 6 0 ==
            (0b0001111#7 : BitVec 7))) : Bool) =
      true := by
  simp [
    encodeFenceTrace_opcode,
    encodeFenceTrace_funct3,
    encodeFenceTrace_rs,
    encodeFenceTrace_rd,
    encdec_reg_backwards_matches,
    base_E_enabled,
    not,
  ]

private theorem encdec_reg_backwards_encodeFenceTrace_rs
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    encdec_reg_backwards
        (Sail.BitVec.extractLsb
          (encodeFenceTrace imm rs rd) 19 15) =
      pure (.Regidx rs) := by
  rw [encodeFenceTrace_rs]
  simp [
    encdec_reg_backwards,
    base_E_enabled,
    regidx_bit_width,
    not,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ]

private theorem encdec_reg_backwards_encodeFenceTrace_rd
    (imm : BitVec 12)
    (rs rd : BitVec 5) :
    encdec_reg_backwards
        (Sail.BitVec.extractLsb
          (encodeFenceTrace imm rs rd) 11 7) =
      pure (.Regidx rd) := by
  rw [encodeFenceTrace_rd]
  simp [
    encdec_reg_backwards,
    base_E_enabled,
    regidx_bit_width,
    not,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ]

private theorem ext_decode_fence_branch
    (imm : BitVec 12)
    (rs rd : BitVec 5)
    (zicbopDisabled :
      hartSupports extension.Ext_Zicbop = false)
    (ntlDisabled :
      hartSupports extension.Ext_Zihintntl = false)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false) :
    ext_decode (encodeFenceTrace imm rs rd) =
      generatedUtypeDecodeProgram
        (decodedFenceTrace imm rs rd) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  by_cases tso :
      encodeFenceTrace imm rs rd ==
        (0x8330000F#32 : BitVec 32)
  · simp only [
      encodeFenceTrace_not_zicbop,
      encodeFenceTrace_not_ntl,
      currentlyEnabled_pause_of_disabled pauseDisabled,
      encodeFenceTrace_not_lpad,
      encodeFenceTrace_not_utype,
      encodeFenceTrace_not_jal,
      encodeFenceTrace_not_jalr,
      encodeFenceTrace_not_branch,
      encodeFenceTrace_not_itype,
      encodeFenceTrace_not_rtype,
      encodeFenceTrace_not_load,
      encodeFenceTrace_not_store,
      encodeFenceTrace_not_itypew,
      encodeFenceTrace_not_rtypew,
      tso,
      decodedFenceTrace,
      generatedUtypeDecodePreamble,
      generatedUtypeDecodeProgram,
      Bool.and_false,
      Bool.false_and,
      Bool.false_eq_true,
      if_false,
      if_true,
      pure_bind,
      bind_pure,
      bind_assoc,
    ]
  · simp only [
      encodeFenceTrace_not_zicbop,
      encodeFenceTrace_not_ntl,
      currentlyEnabled_pause_of_disabled pauseDisabled,
      encodeFenceTrace_not_lpad,
      encodeFenceTrace_not_utype,
      encodeFenceTrace_not_jal,
      encodeFenceTrace_not_jalr,
      encodeFenceTrace_not_branch,
      encodeFenceTrace_not_itype,
      encodeFenceTrace_not_rtype,
      encodeFenceTrace_not_load,
      encodeFenceTrace_not_store,
      encodeFenceTrace_not_itypew,
      encodeFenceTrace_not_rtypew,
      tso,
      encodeFenceTrace_is_fence,
      encodeFenceTrace_fm,
      encodeFenceTrace_pred,
      encodeFenceTrace_succ,
      encdec_reg_backwards_encodeFenceTrace_rs,
      encdec_reg_backwards_encodeFenceTrace_rd,
      decodedFenceTrace,
      generatedUtypeDecodePreamble,
      generatedUtypeDecodeProgram,
      Bool.and_false,
      Bool.false_and,
      Bool.false_eq_true,
      if_false,
      if_true,
      pure_bind,
      bind_pure,
      bind_assoc,
    ]

theorem decode_fence_certificate
    (imm : BitVec 12)
    (rs rd : BitVec 5)
    (zicbopDisabled :
      hartSupports extension.Ext_Zicbop = false)
    (ntlDisabled :
      hartSupports extension.Ext_Zihintntl = false)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false) :
    GeneratedDecodeCertificate
      (encodeFenceTrace imm rs rd)
      (decodedFenceTrace imm rs rd) := by
  constructor
  intro initial final actual outcome
  rw [
    ext_decode_fence_branch
      imm rs rd zicbopDisabled ntlDisabled
      pauseDisabled landingPadDisabled,
  ] at outcome
  exact
    generatedUtypeDecodeProgram_success
      (decodedFenceTrace imm rs rd)
      actual initial final outcome

/-- Constructive, state-indexed FENCE/FENCE.TSO decode. -/
theorem decode_fence_certificate_at
    (imm : BitVec 12)
    (rs rd : BitVec 5)
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (zicbopDisabled :
      hartSupports extension.Ext_Zicbop = false)
    (ntlDisabled :
      hartSupports extension.Ext_Zihintntl = false)
    (pauseDisabled :
      hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    GeneratedDecodeCertificateAt
      (encodeFenceTrace imm rs rd)
      (decodedFenceTrace imm rs rd)
      initial := by
  constructor
  rw [
    ext_decode_fence_branch
      imm rs rd zicbopDisabled ntlDisabled
      pauseDisabled landingPadDisabled,
  ]
  simp [
    generatedUtypeDecodeProgram,
    bind,
    EStateM.bind,
    EStateM.map,
    pure,
    EStateM.pure,
    generatedUtypeDecodePreamble_exact_at
      initial mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding,
  ]

def GeneratedActiveTrace.withoutBase
    (step : Step) :
    GeneratedActiveTrace where
  step
  decodedBase := none

def GeneratedActiveTrace.withBase
    (decodedBase : GeneratedDecodedBase)
    (step : Step) :
    GeneratedActiveTrace where
  step
  decodedBase := some decodedBase

abbrev GeneratedResult (α : Type) :=
  EStateM.Result (Sail.Error exception) GeneratedState α

noncomputable def observeSuccessfulResultAt
    (program : SailM α)
    (decorate :
      ∀ (initial final : GeneratedState) (value : α),
        program initial = .ok value final → β)
    (initial : GeneratedState)
    (result : GeneratedResult α) :
    program initial = result → GeneratedResult β :=
  match result with
    | .ok value final =>
        fun resultEq =>
          .ok (decorate initial final value resultEq) final
    | .error error final =>
        fun _ => .error error final

noncomputable def observeSuccessfulResult
    (program : SailM α)
    (decorate :
      ∀ (initial final : GeneratedState) (value : α),
        program initial = .ok value final → β) :
    SailM β :=
  fun initial =>
    (observeSuccessfulResultAt
      program decorate initial (program initial)) rfl

def eraseSuccessfulObservationAt
    (project : β → α)
    (result : GeneratedResult β) :
    GeneratedResult α :=
  match result with
    | .ok observed final => .ok (project observed) final
    | .error error final => .error error final

def eraseSuccessfulObservation
    (project : β → α)
    (program : SailM β) :
    SailM α :=
  fun initial =>
    eraseSuccessfulObservationAt project (program initial)

theorem map_eq_eraseSuccessfulObservation
    (project : β → α)
    (program : SailM β) :
    project <$> program =
      eraseSuccessfulObservation project program := by
  funext initial
  change
    (EStateM.map project program) initial =
      eraseSuccessfulObservationAt project (program initial)
  unfold EStateM.map eraseSuccessfulObservationAt
  cases outcome : program initial <;> rfl

theorem observeSuccessfulResultAt_erases
    (program : SailM α)
    (decorate :
      ∀ (initial final : GeneratedState) (value : α),
        program initial = .ok value final → β)
    (project : β → α)
    (projects :
      ∀ (initial final : GeneratedState) (value : α)
        (outcome : program initial = .ok value final),
        project (decorate initial final value outcome) = value)
    (initial : GeneratedState)
    (result : GeneratedResult α)
    (resultEq : program initial = result) :
    eraseSuccessfulObservationAt project
        ((observeSuccessfulResultAt
          program decorate initial result) resultEq) =
      result := by
  cases result with
  | ok value final =>
      simpa only [
        observeSuccessfulResultAt,
        eraseSuccessfulObservationAt,
      ] using
        (congrArg
          (fun projected =>
            (EStateM.Result.ok projected final :
              GeneratedResult α))
          (projects initial final value resultEq))
  | error error final =>
      rfl

theorem observeSuccessfulResult_erases
    (program : SailM α)
    (decorate :
      ∀ (initial final : GeneratedState) (value : α),
        program initial = .ok value final → β)
    (project : β → α)
    (projects :
      ∀ (initial final : GeneratedState) (value : α)
        (outcome : program initial = .ok value final),
        project (decorate initial final value outcome) = value) :
    eraseSuccessfulObservation project
        (observeSuccessfulResult program decorate) =
      program := by
  funext initial
  unfold eraseSuccessfulObservation observeSuccessfulResult
  exact
    observeSuccessfulResultAt_erases
      program decorate project projects
      initial (program initial) rfl

noncomputable def observeGeneratedDecode
    (word : BitVec 32) :
    SailM GeneratedDecodedBase :=
  observeSuccessfulResult (ext_decode word)
    (fun initial final decoded exactOutcome => {
      word
      decoded
      initial
      final
      exactOutcome
    })

def eraseGeneratedDecode
    (program : SailM GeneratedDecodedBase) :
    SailM instruction :=
  eraseSuccessfulObservation
    GeneratedDecodedBase.decoded program

theorem observeGeneratedDecode_erases
    (word : BitVec 32) :
    eraseGeneratedDecode (observeGeneratedDecode word) =
      ext_decode word := by
  unfold eraseGeneratedDecode observeGeneratedDecode
  exact
    observeSuccessfulResult_erases
      (program := ext_decode word)
      (decorate := fun initial final decoded exactOutcome => {
        word
        decoded
        initial
        final
        exactOutcome
      })
      (project := GeneratedDecodedBase.decoded)
      (by
        intro initial final decoded exactOutcome
        rfl)

@[simp]
theorem map_observeGeneratedDecode
    (word : BitVec 32) :
    (GeneratedDecodedBase.decoded <$>
        observeGeneratedDecode word) =
      ext_decode word := by
  rw [map_eq_eraseSuccessfulObservation]
  exact observeGeneratedDecode_erases word

theorem observeGeneratedDecode_bind_sailME
    (word : BitVec 32)
    (next : instruction → SailME ε α) :
    (do
      let observed ←
        (liftM (observeGeneratedDecode word) :
          SailME ε GeneratedDecodedBase)
      next observed.decoded) =
      (do
        let decoded ←
          (liftM (ext_decode word) : SailME ε instruction)
        next decoded) := by
  rw [← bind_map_left]
  rw [← monadLift_map]
  rw [map_observeGeneratedDecode]

noncomputable def runStepTrace
    (program : SailME Step GeneratedActiveTrace) :
    SailM GeneratedActiveTrace := do
  match ← ExceptT.run program with
  | .error (.inr step) =>
      pure (GeneratedActiveTrace.withoutBase step)
  | .error (.inl error) => throw error
  | .ok trace => pure trace

noncomputable def runCompressedAfterDecode
    (step_no : Nat)
    (halfword : BitVec 16)
    (decoded : instruction) :
    SailME Step Step := do
  let instbits : instbits := zero_extend (m := 32) halfword
  if get_config_print_instr () then
    pure
      (print_log_instr
        ("[" ++ Int.repr step_no ++ "] [" ++
          (← privLevel_to_str (← readReg Register.cur_privilege)) ++
          "]: " ++ BitVec.toFormatted (← readReg Register.PC) ++
          " (" ++ BitVec.toFormatted halfword ++ ") " ++
          (← instruction_to_str decoded))
        (zero_extend (m := 64) (← readReg Register.PC)))
  else pure ()
  if ← is_landing_pad_expected () then
    do
      let result ← trap (make_landing_pad_exception ())
      pure (.Step_Execute (result, instbits))
  else
    do
      if ← currentlyEnabled extension.Ext_Zca then
        do
          writeReg Register.nextPC
            (BitVec.addInt (← readReg Register.PC) 2)
          let result ←
            ((do
              match ← execute decoded with
              | .ExecuteAs other => execute other
              | result => pure result) :
                SailME Step ExecutionResult)
          pure (.Step_Execute (result, instbits))
      else
        pure
          (.Step_Execute
            (.Illegal_Instruction (), instbits))

noncomputable def runBaseAfterDecode
    (step_no : Nat)
    (word : BitVec 32)
    (decoded : instruction) :
    SailME Step Step := do
  let instbits : instbits := zero_extend (m := 32) word
  if get_config_print_instr () then
    pure
      (print_log_instr
        ("[" ++ Int.repr step_no ++ "] [" ++
          (← privLevel_to_str (← readReg Register.cur_privilege)) ++
          "]: " ++ BitVec.toFormatted (← readReg Register.PC) ++
          " (" ++ BitVec.toFormatted word ++ ") " ++
          (← instruction_to_str decoded))
        (zero_extend (m := 64) (← readReg Register.PC)))
  else pure ()
  if
      (← is_landing_pad_expected ()) &&
        !is_lpad_instruction decoded then
    do
      let result ← trap (make_landing_pad_exception ())
      pure (.Step_Execute (result, instbits))
  else
    do
      writeReg Register.nextPC
        (BitVec.addInt (← readReg Register.PC) 4)
      let result ←
        ((do
          match ← execute decoded with
          | .ExecuteAs other => execute other
          | result => pure result) :
            SailME Step ExecutionResult)
      pure (.Step_Execute (result, instbits))

/--
Constructive success of the exact generated base arm.  The final state is an
existential output, and the returned `Step` is fixed to successful retirement
of the exact input word.
-/
structure GeneratedRunBaseSuccess
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (initial : GeneratedState) : Prop where
  exactSuccess :
    ∃ final : GeneratedState,
      ExceptT.run (runBaseAfterDecode stepNo word decoded) initial =
        .ok (.ok (.Step_Execute
          (RETIRE_SUCCESS, zero_extend (m := 32) word))) final

/--
Construct the exact generated base arm from PC/landing-pad bindings and a
state-neutral successful decoded body.  No outcome or final state is a caller
premise; the sole semantic premise fixes the body on the concrete post-nextPC
state.
-/
theorem runBaseAfterDecode_neutral_succeeds
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (pc : BitVec 32)
    (initial : GeneratedState)
    (pcBinding : initial.regs.get? Register.PC = some pc)
    (landingPadClear :
      initial.regs.get? Register.elp =
        some (landing_pad_bits_backwards .NO_LP_EXPECTED))
    (bodySuccess :
      execute decoded {
        initial with
        regs := initial.regs.insert Register.nextPC
          (RiscvRefinement.nextPc pc)
      } = .ok RETIRE_SUCCESS {
        initial with
        regs := initial.regs.insert Register.nextPC
          (RiscvRefinement.nextPc pc)
      }) :
    GeneratedRunBaseSuccess stepNo word decoded initial := by
  constructor
  simp [
    runBaseAfterDecode,
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
    is_landing_pad_expected,
    landing_pad_bits_backwards,
    get_config_print_instr,
    bodySuccess,
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
  exact ⟨_, rfl⟩

/--
An exact generated program and its non-destructive observation both succeed
from the same concrete state and expose the stated AIR retirement.
-/
structure SuccessfulGeneratedRetirement
    (program : SailM ExecutionResult)
    (observed : SailM (ObservedExecution ExecutionResult))
    (initial : GeneratedState)
    (retirement : RiscvRefinement.Retirement) : Prop where
  exactErasure : eraseObservation observed = program
  execution :
    ∃ final : GeneratedState,
      observed initial = .ok {
        generatedResult := RETIRE_SUCCESS
        retirement := some retirement
      } final ∧
      program initial = .ok RETIRE_SUCCESS final

/--
The FV-2 row-local closure: exact generated base-arm success together with the
observed completion/tick retirement.  Full fetch/interrupt/`try_step`
construction remains the separate FV-4 obligation.
-/
structure ConstructiveGeneratedExecution
    (stepNo : Nat)
    (word : BitVec 32)
    (decoded : instruction)
    (program : SailM ExecutionResult)
    (observed : SailM (ObservedExecution ExecutionResult))
    (initial : GeneratedState)
    (retirement : RiscvRefinement.Retirement) : Prop where
  runBase : GeneratedRunBaseSuccess stepNo word decoded initial
  retirementExecution :
    SuccessfulGeneratedRetirement program observed initial retirement

noncomputable def run_hart_active_factored
    (step_no : Nat) :
    SailM Step := SailME.run do
  match (← dispatchInterrupt (← readReg Register.cur_privilege)) with
  | .some (intr, priv) =>
      SailME.throw
        (.Step_Pending_Interrupt (intr, priv))
  | none => pure ()
  match ext_fetch_hook (← fetch ()) with
  | .F_Ext_Error e =>
      pure (.Step_Ext_Fetch_Failure e)
  | .F_Error (e, addr) =>
      pure (.Step_Fetch_Failure (.Virtaddr addr, e))
  | .F_RVC halfword =>
    do
      let _ : Unit := sail_instr_announce halfword
      let _ : Unit := fetch_callback halfword
      let decoded ← ext_decode_compressed halfword
      runCompressedAfterDecode step_no halfword decoded
  | .F_Base word =>
    do
      let _ : Unit := sail_instr_announce word
      let _ : Unit := fetch_callback word
      let decoded ← ext_decode word
      runBaseAfterDecode step_no word decoded

theorem run_hart_active_factored_eq_generated
    (step_no : Nat) :
    run_hart_active_factored step_no =
      run_hart_active step_no := by
  rfl

theorem observedBaseAfterDecode_erases
    (step_no : Nat)
    (word : BitVec 32) :
    (do
      let observed ←
        (liftM (observeGeneratedDecode word) :
          SailME Step GeneratedDecodedBase)
      runBaseAfterDecode step_no word observed.decoded) =
      (do
        let decoded ←
          (liftM (ext_decode word) :
            SailME Step instruction)
        runBaseAfterDecode step_no word decoded) := by
  exact
    observeGeneratedDecode_bind_sailME word
      (runBaseAfterDecode step_no word)

noncomputable def run_hart_active_with_trace
    (step_no : Nat) :
    SailM GeneratedActiveTrace := runStepTrace do
  match (← dispatchInterrupt (← readReg Register.cur_privilege)) with
  | .some (intr, priv) =>
      SailME.throw
        (.Step_Pending_Interrupt (intr, priv))
  | none => pure ()
  match ext_fetch_hook (← fetch ()) with
  | .F_Ext_Error e =>
      pure
        (GeneratedActiveTrace.withoutBase
          (.Step_Ext_Fetch_Failure e))
  | .F_Error (e, addr) =>
      pure
        (GeneratedActiveTrace.withoutBase
          (.Step_Fetch_Failure (.Virtaddr addr, e)))
  | .F_RVC h =>
    do
      let _ : Unit := sail_instr_announce h
      let _ : Unit := fetch_callback h
      let decoded ← ext_decode_compressed h
      let step ←
        runCompressedAfterDecode step_no h decoded
      pure (GeneratedActiveTrace.withoutBase step)
  | .F_Base word =>
    do
      let _ : Unit := sail_instr_announce word
      let _ : Unit := fetch_callback word
      let decodedBase ← observeGeneratedDecode word
      let step ←
        runBaseAfterDecode step_no word decodedBase.decoded
      pure
        (GeneratedActiveTrace.withBase decodedBase step)

def eraseGeneratedActiveTrace
    (program : SailM GeneratedActiveTrace) :
    SailM Step := do
  pure (← program).step

@[simp]
theorem map_sailME_throw
    (f : α → β)
    (error : ε) :
    (f <$> (SailME.throw error : SailME ε α)) =
      (SailME.throw error : SailME ε β) := by
  rfl

@[simp]
theorem map_withoutBase_program
    (program : SailME Step Step) :
    (GeneratedActiveTrace.step <$>
        (do
          let step ← program
          pure (GeneratedActiveTrace.withoutBase step))) =
      program := by
  simp [GeneratedActiveTrace.withoutBase]

@[simp]
theorem map_withBase_program
    (decodedBase : GeneratedDecodedBase)
    (program : SailME Step Step) :
    (GeneratedActiveTrace.step <$>
        (do
          let step ← program
          pure
            (GeneratedActiveTrace.withBase decodedBase step))) =
      program := by
  simp [GeneratedActiveTrace.withBase]

theorem runStepTrace_erases
    (program : SailME Step GeneratedActiveTrace) :
    eraseGeneratedActiveTrace (runStepTrace program) =
      SailME.run
        (ExceptT.map GeneratedActiveTrace.step program) := by
  funext initial
  cases outcome : ExceptT.run program initial with
  | ok result final =>
      change program initial = _ at outcome
      cases result with
      | ok trace =>
          simp [
            eraseGeneratedActiveTrace,
            runStepTrace,
            SailME.run,
            PreSail.PreSailME.run,
            ExceptT.map,
            ExceptT.mk,
            ExceptT.run,
            bind,
            EStateM.bind,
            pure,
            EStateM.pure,
            outcome,
          ]
      | error error =>
          cases error with
          | inl underlying =>
            simp [
              eraseGeneratedActiveTrace,
              runStepTrace,
              SailME.run,
              PreSail.PreSailME.run,
              ExceptT.map,
              ExceptT.mk,
              ExceptT.run,
              bind,
              EStateM.bind,
              pure,
              EStateM.pure,
              outcome,
              GeneratedActiveTrace.withoutBase,
            ]
            change
              EStateM.Result.error underlying final =
                EStateM.Result.error underlying final
            rfl
          | inr step =>
            simp [
              eraseGeneratedActiveTrace,
              runStepTrace,
              SailME.run,
              PreSail.PreSailME.run,
              ExceptT.map,
              ExceptT.mk,
              ExceptT.run,
              bind,
              EStateM.bind,
              pure,
              EStateM.pure,
              outcome,
              GeneratedActiveTrace.withoutBase,
            ]
  | error error final =>
      change program initial = _ at outcome
      simp [
        eraseGeneratedActiveTrace,
        runStepTrace,
        SailME.run,
        PreSail.PreSailME.run,
        ExceptT.map,
        ExceptT.mk,
        ExceptT.run,
        bind,
        EStateM.bind,
        pure,
        EStateM.pure,
        outcome,
      ]

theorem run_hart_active_with_trace_erases_factored
    (step_no : Nat) :
    eraseGeneratedActiveTrace
        (run_hart_active_with_trace step_no) =
      run_hart_active_factored step_no := by
  unfold run_hart_active_with_trace
  rw [runStepTrace_erases]
  unfold run_hart_active_factored
  congr 1
  change
    (GeneratedActiveTrace.step <$>
      (_ : SailME Step GeneratedActiveTrace)) =
        (_ : SailME Step Step)
  simp only [
    map_bind,
    map_pure,
    pure_bind,
    GeneratedActiveTrace.withoutBase,
    GeneratedActiveTrace.withBase,
  ]
  apply bind_congr
  intro _
  apply bind_congr
  intro interrupt
  cases interrupt with
  | some pending =>
      rcases pending with ⟨intr, privilege⟩
      rfl
  | none =>
      simp only [
        map_bind,
        map_pure,
        pure_bind,
        GeneratedActiveTrace.withoutBase,
        GeneratedActiveTrace.withBase,
      ]
      apply bind_congr
      intro fetched
      cases fetched with
      | F_Ext_Error error =>
          rfl
      | F_Error errorAndAddress =>
          rfl
      | F_RVC halfword =>
        simp only [
          ext_fetch_hook,
          map_bind,
          map_pure,
          pure_bind,
          GeneratedActiveTrace.withoutBase,
          GeneratedActiveTrace.withBase,
        ]
        apply bind_congr
        intro decoded
        simp only [bind_pure]
      | F_Base word =>
        simp only [
          ext_fetch_hook,
          map_bind,
          map_pure,
          pure_bind,
          GeneratedActiveTrace.withoutBase,
          GeneratedActiveTrace.withBase,
        ]
        simp only [bind_pure]
        exact
          observedBaseAfterDecode_erases
            step_no word

theorem run_hart_active_with_trace_erases
    (step_no : Nat) :
    eraseGeneratedActiveTrace
        (run_hart_active_with_trace step_no) =
      run_hart_active step_no := by
  calc
    eraseGeneratedActiveTrace
        (run_hart_active_with_trace step_no) =
        run_hart_active_factored step_no :=
      run_hart_active_with_trace_erases_factored step_no
    _ = run_hart_active step_no :=
      run_hart_active_factored_eq_generated step_no

noncomputable def generatedStepTraceFrame
    (step_no : Nat)
    (exit_wait : Bool) :
    SailM GeneratedActiveTrace := do
  match ← readReg Register.hart_state with
  | .HART_WAITING (reason, instbits) =>
      let step ←
        run_hart_waiting step_no reason instbits exit_wait
      pure (GeneratedActiveTrace.withoutBase step)
  | .HART_ACTIVE () =>
      run_hart_active_with_trace step_no

theorem generatedStepTraceFrame_erases
    (step_no : Nat)
    (exit_wait : Bool) :
    eraseGeneratedActiveTrace
        (generatedStepTraceFrame step_no exit_wait) =
      (do
        match ← readReg Register.hart_state with
        | .HART_WAITING (reason, instbits) =>
            run_hart_waiting step_no reason instbits exit_wait
        | .HART_ACTIVE () =>
            run_hart_active step_no) := by
  unfold generatedStepTraceFrame
  unfold eraseGeneratedActiveTrace
  simp only [bind_assoc]
  apply bind_congr
  intro hartState
  cases hartState with
  | HART_WAITING waiting =>
      rcases waiting with ⟨reason, instbits⟩
      simp [GeneratedActiveTrace.withoutBase]
  | HART_ACTIVE unit =>
      cases unit
      exact run_hart_active_with_trace_erases step_no

noncomputable def generatedFullStepWithTrace
    (step_no : Nat)
    (exit_wait : Bool) :
    SailM (Bool × GeneratedActiveTrace) := do
  let _ : Unit := ext_pre_step_hook ()
  writeReg Register.minstret_increment
    (← should_inc_minstret (← readReg Register.cur_privilege))
  let trace ← generatedStepTraceFrame step_no exit_wait
  let waiting ← generatedFullStepPostlude trace.step
  pure (waiting, trace)

def eraseGeneratedFullStepTrace
    (program : SailM (Bool × GeneratedActiveTrace)) :
    SailM (Bool × Step) := do
  let (waiting, trace) ← program
  pure (waiting, trace.step)

theorem generatedFullStepWithTrace_erases
    (step_no : Nat)
    (exit_wait : Bool) :
    eraseGeneratedFullStepTrace
        (generatedFullStepWithTrace step_no exit_wait) =
      generatedFullStepWithOutcome step_no exit_wait := by
  unfold
    eraseGeneratedFullStepTrace
    generatedFullStepWithTrace
    generatedFullStepWithOutcome
  simp only [bind_assoc]
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  apply bind_congr
  intro _
  calc
    (do
        let trace ←
          generatedStepTraceFrame step_no exit_wait
        let waiting ←
          generatedFullStepPostlude trace.step
        pure (waiting, trace.step)) =
        (do
          let step ←
            eraseGeneratedActiveTrace
              (generatedStepTraceFrame step_no exit_wait)
          let waiting ←
            generatedFullStepPostlude step
          pure (waiting, step)) := by
            unfold eraseGeneratedActiveTrace
            simp only [bind_assoc, pure_bind]
    _ =
        (do
          let step ←
            (do
              let hartState ←
                readReg Register.hart_state
              match hartState with
              | .HART_WAITING (reason, instbits) =>
                  run_hart_waiting
                    step_no reason instbits exit_wait
              | .HART_ACTIVE () =>
                  run_hart_active step_no)
          let waiting ←
            generatedFullStepPostlude step
          pure (waiting, step)) := by
            exact
              congrArg
                (fun program : SailM Step => do
                  let step ← program
                  let waiting ←
                    generatedFullStepPostlude step
                  pure (waiting, step))
                (generatedStepTraceFrame_erases
                  step_no exit_wait)
    _ =
        (readReg Register.hart_state >>= fun hartState =>
          ((match hartState with
            | .HART_WAITING (reason, instbits) =>
                run_hart_waiting
                  step_no reason instbits exit_wait
            | .HART_ACTIVE () =>
                run_hart_active step_no) : SailM Step) >>= fun step =>
          generatedFullStepPostlude step >>= fun waiting =>
          pure (waiting, step)) := by
            simp only [bind_assoc]

/--
Erase the instrumentation while retaining the generated `try_step` result.
The trace program itself still returns the generated `Step` discriminator and,
on the base-instruction arm, the fetched word and exact decoded instruction.
-/
def eraseGeneratedTracedTryStep
    (program : SailM (Bool × GeneratedActiveTrace)) :
    SailM Bool := do
  pure (← program).1

theorem generatedFullStepWithTrace_erases_try_step
    (step_no : Nat)
    (exit_wait : Bool) :
    eraseGeneratedTracedTryStep
        (generatedFullStepWithTrace step_no exit_wait) =
      try_step step_no exit_wait := by
  calc
    eraseGeneratedTracedTryStep
        (generatedFullStepWithTrace step_no exit_wait) =
        eraseFullStepOutcome
          (eraseGeneratedFullStepTrace
            (generatedFullStepWithTrace step_no exit_wait)) := by
          simp [
            eraseGeneratedTracedTryStep,
            eraseGeneratedFullStepTrace,
            eraseFullStepOutcome,
            bind_assoc,
          ]
    _ =
        eraseFullStepOutcome
          (generatedFullStepWithOutcome step_no exit_wait) := by
          rw [generatedFullStepWithTrace_erases]
    _ = generatedFullStepFrame step_no exit_wait :=
      generatedFullStepWithOutcome_erases step_no exit_wait
    _ = try_step step_no exit_wait :=
      (generated_full_step_frame step_no exit_wait).symm

noncomputable def continueAfterGeneratedFullStepTrace
    (step_no : Nat)
    (exit_wait : Bool)
    (laterStepNo : Nat)
    (laterExitWait : Bool) :
    SailM Bool := do
  let _ ←
    eraseGeneratedTracedTryStep
      (generatedFullStepWithTrace step_no exit_wait)
  try_step laterStepNo laterExitWait

/--
Premise-free full-step framing for the exact pinned generated model.

`generatedFullStepWithTrace` executes the generated interrupt/fetch/decode/
execute path and the complete generated postlude.  Its return value retains
the `Step` branch discriminator plus the fetched base word and decoded
instruction when that branch is taken.  The fields below prove that erasing
only those observations yields the exact generated outcome and `try_step`,
and that every later generated step starts from the identical raw state.
-/
structure GeneratedFullStepRetirementComposition
    (step_no : Nat)
    (exit_wait : Bool) : Prop where
  outcomeErasure :
    eraseGeneratedFullStepTrace
        (generatedFullStepWithTrace step_no exit_wait) =
      generatedFullStepWithOutcome step_no exit_wait
  rawTryStepErasure :
    eraseGeneratedTracedTryStep
        (generatedFullStepWithTrace step_no exit_wait) =
      try_step step_no exit_wait
  laterState :
    ∀ (laterStepNo : Nat) (laterExitWait : Bool),
      continueAfterGeneratedFullStepTrace
          step_no exit_wait laterStepNo laterExitWait =
        continueAfterRawFullStep
          step_no exit_wait laterStepNo laterExitWait

theorem generated_full_step_retirement_composition
    (step_no : Nat)
    (exit_wait : Bool) :
    GeneratedFullStepRetirementComposition step_no exit_wait := by
  exact {
    outcomeErasure :=
      generatedFullStepWithTrace_erases step_no exit_wait
    rawTryStepErasure :=
      generatedFullStepWithTrace_erases_try_step step_no exit_wait
    laterState := by
      intro laterStepNo laterExitWait
      unfold
        continueAfterGeneratedFullStepTrace
        continueAfterRawFullStep
      rw [
        generatedFullStepWithTrace_erases_try_step
          step_no exit_wait,
      ]
  }

end LeanRV32IM.Functions

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

/--
The one neutral, manifest-ordered selector space used by the generated-Sail
publication layer.  Contributor allocation is intentionally absent from this
type.
-/
inductive GeneratedOpcodeSelector where
  | add
  | sub
  | sll
  | slt
  | sltu
  | xor
  | srl
  | sra
  | or
  | and
  | addi
  | slti
  | sltiu
  | xori
  | ori
  | andi
  | slli
  | srli
  | srai
  | lb
  | lh
  | lw
  | lbu
  | lhu
  | sb
  | sh
  | sw
  | beq
  | bne
  | blt
  | bge
  | bltu
  | bgeu
  | jal
  | jalr
  | lui
  | auipc
  | mul
  | mulh
  | mulhsu
  | mulhu
  | div
  | divu
  | rem
  | remu
  | fence
deriving DecidableEq, Repr

def GeneratedOpcodeSelector.manifestId :
    GeneratedOpcodeSelector → Nat
  | .add => 0
  | .sub => 1
  | .sll => 2
  | .slt => 3
  | .sltu => 4
  | .xor => 5
  | .srl => 6
  | .sra => 7
  | .or => 8
  | .and => 9
  | .addi => 10
  | .slti => 11
  | .sltiu => 12
  | .xori => 13
  | .ori => 14
  | .andi => 15
  | .slli => 16
  | .srli => 17
  | .srai => 18
  | .lb => 19
  | .lh => 20
  | .lw => 21
  | .lbu => 22
  | .lhu => 23
  | .sb => 24
  | .sh => 25
  | .sw => 26
  | .beq => 27
  | .bne => 28
  | .blt => 29
  | .bge => 30
  | .bltu => 31
  | .bgeu => 32
  | .jal => 33
  | .jalr => 34
  | .lui => 35
  | .auipc => 36
  | .mul => 37
  | .mulh => 38
  | .mulhsu => 39
  | .mulhu => 40
  | .div => 41
  | .divu => 42
  | .rem => 43
  | .remu => 44
  | .fence => 45

def GeneratedOpcodeSelector.mnemonic :
    GeneratedOpcodeSelector → String
  | .add => "add"
  | .sub => "sub"
  | .sll => "sll"
  | .slt => "slt"
  | .sltu => "sltu"
  | .xor => "xor"
  | .srl => "srl"
  | .sra => "sra"
  | .or => "or"
  | .and => "and"
  | .addi => "addi"
  | .slti => "slti"
  | .sltiu => "sltiu"
  | .xori => "xori"
  | .ori => "ori"
  | .andi => "andi"
  | .slli => "slli"
  | .srli => "srli"
  | .srai => "srai"
  | .lb => "lb"
  | .lh => "lh"
  | .lw => "lw"
  | .lbu => "lbu"
  | .lhu => "lhu"
  | .sb => "sb"
  | .sh => "sh"
  | .sw => "sw"
  | .beq => "beq"
  | .bne => "bne"
  | .blt => "blt"
  | .bge => "bge"
  | .bltu => "bltu"
  | .bgeu => "bgeu"
  | .jal => "jal"
  | .jalr => "jalr"
  | .lui => "lui"
  | .auipc => "auipc"
  | .mul => "mul"
  | .mulh => "mulh"
  | .mulhsu => "mulhsu"
  | .mulhu => "mulhu"
  | .div => "div"
  | .divu => "divu"
  | .rem => "rem"
  | .remu => "remu"
  | .fence => "fence"

def generatedOpcodeSelectors : List GeneratedOpcodeSelector := [
  .add, .sub, .sll, .slt, .sltu, .xor, .srl, .sra, .or, .and,
  .addi, .slti, .sltiu, .xori, .ori, .andi, .slli, .srli, .srai,
  .lb, .lh, .lw, .lbu, .lhu, .sb, .sh, .sw,
  .beq, .bne, .blt, .bge, .bltu, .bgeu,
  .jal, .jalr, .lui, .auipc,
  .mul, .mulh, .mulhsu, .mulhu, .div, .divu, .rem, .remu,
  .fence
]

theorem generatedOpcodeSelectors_exact :
    generatedOpcodeSelectors.length = 46 ∧
      generatedOpcodeSelectors.Nodup ∧
      generatedOpcodeSelectors.map
          GeneratedOpcodeSelector.manifestId =
        List.range 46 := by
  decide

/--
Exact binding between one production evaluator, its manifest selector, and
the concrete instruction word passed to the pinned generated decoder.
-/
structure InputBoundSelectorIdentity
    (selector : GeneratedOpcodeSelector)
    (program : LocalProgram)
    (contentDigest : String)
    (inputWord expectedWord : BitVec 32) : Prop where
  schemaVersion :
    program.source.schemaVersion = 2
  manifestId :
    program.source.opcodeSelector.manifestId = selector.manifestId
  mnemonic :
    program.source.opcodeSelector.mnemonic = selector.mnemonic
  digest :
    program.source.contentDigest = contentDigest
  inputWord :
    inputWord = expectedWord

/--
Uniform result type for every public accepted-AIR/generated-Sail theorem.

The family-specific propositions remain parameters so their exact typed row,
tuple, register, memory, and retirement statements are preserved rather than
coerced into a weaker common semantic function.
-/
structure AcceptedGeneratedOpcodeComposition
    (selector : GeneratedOpcodeSelector)
    (program : LocalProgram)
    (contentDigest : String)
    (evaluation : SymbolicEvaluation)
    (relationHolds : EvaluatedLookup → Prop)
    (inputWord expectedWord : BitVec 32)
    (decoded : instruction)
    (initial : Functions.GeneratedState)
    (StateBindings ProfileAdmission Admission LocalRefinement ExactTuple
      GeneratedExecuteClause NormalizedRetirement
      ConstructiveExecution : Prop)
    (stepNo : Nat)
    (exitWait : Bool) : Prop where
  acceptedProduction :
    RiscvRefinement.Publication.AcceptedProductionEvaluation
      evaluation relationHolds
  inputBoundSelector :
    InputBoundSelectorIdentity
      selector program contentDigest inputWord expectedWord
  stateBindings :
    StateBindings
  profileAdmission :
    ProfileAdmission
  admission :
    Admission
  admissionProofUnique :
    ∀ (first second : Admission), first = second
  localRefinement :
    LocalRefinement
  exactTuple :
    ExactTuple
  decoder :
    Functions.GeneratedDecodeCertificateAt inputWord decoded initial
  generatedExecuteSuccess :
    GeneratedExecuteClause
  normalizedRetirement :
    NormalizedRetirement
  constructiveExecution :
    ConstructiveExecution
  fullStepFraming :
    Functions.GeneratedFullStepRetirementComposition stepNo exitWait

theorem successfulTraceDecode_of_certificate
    (stepNo : Nat)
    (exitWait : Bool)
    (inputWord : BitVec 32)
    (decoded : instruction)
    (certificate :
      Functions.GeneratedDecodeCertificate inputWord decoded) :
    ∀ (initial final : Functions.GeneratedState)
      (waiting : Bool)
      (trace : Functions.GeneratedActiveTrace)
      (decodedBase : Functions.GeneratedDecodedBase),
      Functions.generatedFullStepWithTrace stepNo exitWait initial =
          .ok (waiting, trace) final →
        trace.decodedBase = some decodedBase →
        decodedBase.word = inputWord →
        decodedBase.decoded = decoded := by
  intro initial final waiting trace decodedBase
    _fullStepOutcome _traceDecode wordEq
  exact
    certificate.exactDecoder
      decodedBase.initial
      decodedBase.final
      decodedBase.decoded
      (by
        simpa [wordEq] using decodedBase.exactOutcome)

/--
Uniform componentwise state needed by the pinned RV32IM decoder and by the
eager Zca check in control execution.  Existentials retain concrete register
values without smuggling a monad outcome or final state into the boundary.
-/
structure GeneratedDecodeStateBindings
    (initial : Functions.GeneratedState) : Prop where
  misa :
    ∃ value : BitVec 32,
      initial.regs.get? Register.misa = some value ∧
      Functions._get_Misa_M value = 1#1 ∧
      Functions._get_Misa_C value = 0#1
  mseccfg :
    ∃ value : BitVec 64,
      initial.regs.get? Register.mseccfg = some value

/--
Componentwise generated state bindings for a production FENCE row.  These
facts select the concrete fetch input but do not assert a generated monad
outcome or final state.
-/
structure GeneratedFenceStateBindings
    (row : RiscvRefinement.Opcodes.Fence.Row)
    (initial : Functions.GeneratedState) : Prop where
  hartActive :
    initial.regs.get? Register.hart_state =
      some (.HART_ACTIVE PUnit.unit)
  pc :
    initial.regs.get? Register.PC = some row.pc
  privilege :
    initial.regs.get? Register.cur_privilege = some .Machine
  decodeState : GeneratedDecodeStateBindings initial
  landingPadClear :
    initial.regs.get? Register.elp =
      some (Functions.landing_pad_bits_backwards .NO_LP_EXPECTED)
  htifDisabled :
    initial.regs.get? Register.htif_tohost_base = some none

/--
Pinned generated profile for FENCE decode and fetch.  The four disabled
extension facts are load-bearing: they rule out ZICBOP, NTL, PAUSE, and LPAD
before the ordinary base decoder.  `FENCE_TSO` is not disabled and remains an
explicit input-conditional case.
-/
structure GeneratedFenceProfileAdmission
    (row : RiscvRefinement.Opcodes.Fence.Row)
    (initial : Functions.GeneratedState) : Prop where
  rv32 :
    Functions.xlen = 32
  instructionAligned :
    row.pc.toNat % 4 = 0
  instructionAddressBound :
    row.pc.toNat ≤ 1073741820
  rvfiDisabled :
    Functions.get_config_rvfi () = false
  clintDisabled :
    Functions.plat_have_clint = false
  signatureDisabled :
    Functions.plat_have_sig = false
  compressedDisabled :
    Functions.hartSupports extension.Ext_Zca = false
  zicbopDisabled :
    Functions.hartSupports extension.Ext_Zicbop = false
  ntlDisabled :
    Functions.hartSupports extension.Ext_Zihintntl = false
  pauseDisabled :
    Functions.hartSupports extension.Ext_Zihintpause = false
  landingPadExtensionDisabled :
    Functions.hartSupports extension.Ext_Zicfilp = false
  instructionByte0 :
    initial.mem.get? row.pc.toNat =
      some
        (Sail.BitVec.extractLsb
          (Functions.encodeFenceTrace
            row.immediate row.rs1 row.rd)
          7 0)
  instructionByte1 :
    initial.mem.get? (row.pc.toNat + 1) =
      some
        (Sail.BitVec.extractLsb
          (Functions.encodeFenceTrace
            row.immediate row.rs1 row.rd)
          15 8)
  instructionByte2 :
    initial.mem.get? (row.pc.toNat + 2) =
      some
        (Sail.BitVec.extractLsb
          (Functions.encodeFenceTrace
            row.immediate row.rs1 row.rd)
          23 16)
  instructionByte3 :
    initial.mem.get? (row.pc.toNat + 3) =
      some
        (Sail.BitVec.extractLsb
          (Functions.encodeFenceTrace
            row.immediate row.rs1 row.rd)
          31 24)
  exactDecodeCase :
    Functions.GeneratedFenceDecodeCase
      row.immediate row.rs1 row.rd

/-- Exact generated execution dispatch selected by the FENCE input.  Its two
successful retirement branches are normalized by `FenceNormalizedRetirement`.
-/
structure GeneratedFenceExecuteSuccess
    (row : RiscvRefinement.Opcodes.Fence.Row) : Prop where
  exactDispatch :
    Functions.execute
        (Functions.decodedFenceTrace
          row.immediate row.rs1 row.rd) =
      if Functions.encodeFenceTrace
            row.immediate row.rs1 row.rd ==
          (0x8330000F#32 : BitVec 32)
      then Functions.execute_FENCE_TSO ()
      else
        Functions.execute_FENCE
          (Sail.BitVec.extractLsb row.immediate 11 8)
          (Sail.BitVec.extractLsb row.immediate 7 4)
          (Sail.BitVec.extractLsb row.immediate 3 0)
          (.Regidx row.rs1)
          (.Regidx row.rd)

def FenceExactProgramTuple
    (row : RiscvRefinement.Opcodes.Fence.Row) : Prop :=
  (Air.Bridge.Fence.programLookup row).tuple = #[
    Air.Bridge.Fence.bitVecM31 row.pc,
    M31.reduce 45,
    Air.Bridge.Fence.bitVecM31 row.rd,
    Air.Bridge.Fence.bitVecM31 row.rs1,
    Air.Bridge.Fence.bitVecM31 row.immediate
  ]

def FenceNormalizedRetirement
    (row : RiscvRefinement.Opcodes.Fence.Row) : Prop :=
  Functions.completeBaseExecution row.pc
      (Functions.execute
        (Functions.decodedFenceTrace
          row.immediate row.rs1 row.rd)) =
    if Functions.encodeFenceTrace
          row.immediate row.rs1 row.rd ==
        (0x8330000F#32 : BitVec 32)
    then
      Functions.eraseObservation
        (Functions.normalizedSequentialNoWriteCompletion
          row.pc (Functions.execute_FENCE_TSO ()))
    else
      Functions.eraseObservation
        (Functions.normalizedSequentialNoWriteCompletion row.pc
          (Functions.execute_FENCE
            (Sail.BitVec.extractLsb row.immediate 11 8)
            (Sail.BitVec.extractLsb row.immediate 7 4)
            (Sail.BitVec.extractLsb row.immediate 3 0)
            (.Regidx row.rs1)
            (.Regidx row.rd)))

def FenceExpectedRetirement
    (row : RiscvRefinement.Opcodes.Fence.Row) :
    RiscvRefinement.Retirement := {
  nextPc := RiscvRefinement.nextPc row.pc
  write := none
  read := none
  store := none
}

noncomputable def FenceObservedCompletion
    (row : RiscvRefinement.Opcodes.Fence.Row) :
    SailM (Functions.ObservedExecution ExecutionResult) :=
  if Functions.encodeFenceTrace
        row.immediate row.rs1 row.rd ==
      (0x8330000F#32 : BitVec 32)
  then
    Functions.normalizedSequentialNoWriteCompletion
      row.pc (Functions.execute_FENCE_TSO ())
  else
    Functions.normalizedSequentialNoWriteCompletion row.pc
      (Functions.execute_FENCE
        (Sail.BitVec.extractLsb row.immediate 11 8)
        (Sail.BitVec.extractLsb row.immediate 7 4)
        (Sail.BitVec.extractLsb row.immediate 3 0)
        (.Regidx row.rs1)
        (.Regidx row.rd))

def FenceConstructiveExecution
    (row : RiscvRefinement.Opcodes.Fence.Row)
    (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution
    stepNo
    (Functions.encodeFenceTrace row.immediate row.rs1 row.rd)
    (Functions.decodedFenceTrace row.immediate row.rs1 row.rd)
    (Functions.completeBaseExecution row.pc
      (Functions.execute
        (Functions.decodedFenceTrace
          row.immediate row.rs1 row.rd)))
    (FenceObservedCompletion row)
    initial
    (FenceExpectedRetirement row)

/-- Exact FENCE observation and generated completion from component bindings. -/
theorem fenceObservedCompletion_succeeds
    (row : RiscvRefinement.Opcodes.Fence.Row)
    (initial : Functions.GeneratedState)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine) :
    ∃ final,
      FenceObservedCompletion row initial = .ok {
        generatedResult := Functions.RETIRE_SUCCESS
        retirement := some (FenceExpectedRetirement row)
      } final ∧
      Functions.completeBaseExecution row.pc
        (Functions.execute
          (Functions.decodedFenceTrace
            row.immediate row.rs1 row.rd)) initial =
        .ok Functions.RETIRE_SUCCESS final := by
  let afterNextPc : Functions.GeneratedState := {
    initial with
    regs := initial.regs.insert Register.nextPC
      (RiscvRefinement.nextPc row.pc)
  }
  have afterPrivilege :
      afterNextPc.regs.get? Register.cur_privilege = some .Machine := by
    have keys :
        (Register.nextPC == Register.cur_privilege) = false := by decide
    simp only [afterNextPc]
    rw [Std.ExtDHashMap.get?_insert]
    simp [keys, privilegeBinding]
  have body :
      Functions.execute
        (Functions.decodedFenceTrace
          row.immediate row.rs1 row.rd) afterNextPc =
        .ok Functions.RETIRE_SUCCESS afterNextPc :=
    Functions.execute_decodedFenceTrace_machine_succeeds
      row.immediate row.rs1 row.rd afterNextPc afterPrivilege
  rcases Functions.completeBaseExecution_neutral_succeeds
      row.pc
      (Functions.execute
        (Functions.decodedFenceTrace
          row.immediate row.rs1 row.rd))
      initial body with
    ⟨final, completion⟩
  refine ⟨final, ?_, completion⟩
  by_cases tso :
      Functions.encodeFenceTrace row.immediate row.rs1 row.rd ==
        (0x8330000F#32 : BitVec 32)
  · have branchCompletion :
        Functions.completeBaseExecution row.pc
          (Functions.execute_FENCE_TSO ()) initial =
            .ok Functions.RETIRE_SUCCESS final := by
      simpa [Functions.execute_decodedFenceTrace_clause, tso] using completion
    simp [
      FenceObservedCompletion,
      FenceExpectedRetirement,
      Functions.normalizedSequentialNoWriteCompletion,
      Functions.RETIRE_SUCCESS,
      tso,
      branchCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]
  · have branchCompletion :
        Functions.completeBaseExecution row.pc
          (Functions.execute_FENCE
            (Sail.BitVec.extractLsb row.immediate 11 8)
            (Sail.BitVec.extractLsb row.immediate 7 4)
            (Sail.BitVec.extractLsb row.immediate 3 0)
            (.Regidx row.rs1) (.Regidx row.rd)) initial =
          .ok Functions.RETIRE_SUCCESS final := by
      simpa [Functions.execute_decodedFenceTrace_clause, tso] using completion
    simp [
      FenceObservedCompletion,
      FenceExpectedRetirement,
      Functions.normalizedSequentialNoWriteCompletion,
      Functions.RETIRE_SUCCESS,
      tso,
      branchCompletion,
      bind,
      EStateM.bind,
      pure,
      EStateM.pure,
    ]

def FenceAcceptedGeneratedComposition
    (row : RiscvRefinement.Opcodes.Fence.Row)
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (exitWait : Bool) : Prop :=
  AcceptedGeneratedOpcodeComposition
    .fence
    Programs.fence
    "3d7901704479363a7fc48613fe6953559346fc69a80b45fa252636317010aeb2"
    (Programs.fence.evalSymbolic
      (Air.Bridge.Fence.columns row))
    relationHolds
    (Functions.encodeFenceTrace
      row.immediate row.rs1 row.rd)
    (Functions.encodeFenceTrace
      row.immediate row.rs1 row.rd)
    (Functions.decodedFenceTrace
      row.immediate row.rs1 row.rd)
    initial
    (GeneratedFenceStateBindings row initial)
    (GeneratedFenceProfileAdmission row initial)
    (Air.Bridge.Fence.Admission row)
    (RiscvRefinement.Opcodes.Fence.Refinement row)
    (FenceExactProgramTuple row)
    (GeneratedFenceExecuteSuccess row)
    (FenceNormalizedRetirement row)
    (FenceConstructiveExecution row initial stepNo)
    stepNo
    exitWait

/--
Accepted production FENCE AIR refines the exact input-conditional generated
FENCE/FENCE.TSO execution.  No generated outcome, final state, decoder
equality, or prebuilt publication certificate is a premise.
-/
theorem FENCE_accepted_air_refines
    (row : RiscvRefinement.Opcodes.Fence.Row)
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      RiscvRefinement.Publication.AcceptedProductionEvaluation
        (Programs.fence.evalSymbolic
          (Air.Bridge.Fence.columns row))
        relationHolds)
    (admission : Air.Bridge.Fence.Admission row)
    (initial : Functions.GeneratedState)
    (stateBindings :
      GeneratedFenceStateBindings row initial)
    (profileAdmission :
      GeneratedFenceProfileAdmission row initial)
    (stepNo : Nat)
    (exitWait : Bool) :
    FenceAcceptedGeneratedComposition
      row relationHolds initial stepNo exitWait := by
  let legacyAcceptance :
      RiscvRefinement.Publication.TeamA.Control.FenceAcceptance row := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  let legacyCertificate :=
    RiscvRefinement.Publication.TeamA.Control.fence_accepted_air_implies_retirement
      row admission legacyAcceptance
  rcases stateBindings.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoder :
      Functions.GeneratedDecodeCertificateAt
        (Functions.encodeFenceTrace
          row.immediate row.rs1 row.rd)
        (Functions.decodedFenceTrace
          row.immediate row.rs1 row.rd)
        initial :=
    Functions.decode_fence_certificate_at
      row.immediate row.rs1 row.rd
      initial mseccfgValue
      profileAdmission.zicbopDisabled
      profileAdmission.ntlDisabled
      profileAdmission.pauseDisabled
      profileAdmission.landingPadExtensionDisabled
      stateBindings.privilege
      mseccfgBinding
  exact {
    acceptedProduction := accepted
    inputBoundSelector := {
      schemaVersion := rfl
      manifestId := rfl
      mnemonic := rfl
      digest := rfl
      inputWord := rfl
    }
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    admission := admission
    admissionProofUnique := by
      intro first second
      exact Subsingleton.elim first second
    localRefinement :=
      legacyCertificate.semanticRefinement
    exactTuple := by
      exact legacyCertificate.exactProgramTuple
    decoder := decoder
    generatedExecuteSuccess := {
      exactDispatch :=
        Functions.execute_decodedFenceTrace_clause
          row.immediate row.rs1 row.rd
    }
    normalizedRetirement :=
      Functions.complete_decodedFenceTrace_normalizes
        row.pc row.immediate row.rs1 row.rd
    constructiveExecution := by
      unfold FenceConstructiveExecution
      constructor
      · let afterNextPc : Functions.GeneratedState := {
          initial with
          regs := initial.regs.insert Register.nextPC
            (RiscvRefinement.nextPc row.pc)
        }
        have afterPrivilege :
            afterNextPc.regs.get? Register.cur_privilege = some .Machine := by
          have keys :
              (Register.nextPC == Register.cur_privilege) = false := by decide
          simp only [afterNextPc]
          rw [Std.ExtDHashMap.get?_insert]
          simp [keys, stateBindings.privilege]
        have body :
            Functions.execute
              (Functions.decodedFenceTrace
                row.immediate row.rs1 row.rd) afterNextPc =
              .ok Functions.RETIRE_SUCCESS afterNextPc :=
          Functions.execute_decodedFenceTrace_machine_succeeds
            row.immediate row.rs1 row.rd afterNextPc afterPrivilege
        exact Functions.runBaseAfterDecode_neutral_succeeds
          stepNo
          (Functions.encodeFenceTrace row.immediate row.rs1 row.rd)
          (Functions.decodedFenceTrace row.immediate row.rs1 row.rd)
          row.pc initial stateBindings.pc stateBindings.landingPadClear body
      · constructor
        · by_cases tso :
              Functions.encodeFenceTrace row.immediate row.rs1 row.rd ==
                (0x8330000F#32 : BitVec 32) <;>
            simp [
              FenceObservedCompletion,
              tso,
              Functions.execute_decodedFenceTrace_clause,
              Functions.normalizedSequentialNoWriteCompletion_erases,
            ]
        · exact fenceObservedCompletion_succeeds
            row initial stateBindings.privilege
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition
        stepNo exitWait
  }

def generatedRegisterValue?
    (state : Functions.GeneratedState)
    (index : BitVec 5) :
    Option (BitVec 32) :=
  Functions.generatedX? index state

structure GeneratedLuiStateBindings
    (row : LuiRow)
    (environment :
      Opcodes.LuiEnvironment (Air.Bridge.Lui.interpretedRow row))
    (initial : Functions.GeneratedState) : Prop where
  hartActive :
    initial.regs.get? Register.hart_state =
      some (.HART_ACTIVE PUnit.unit)
  pc :
    initial.regs.get? Register.PC =
      some environment.pre.pc
  privilege :
    initial.regs.get? Register.cur_privilege =
      some .Machine
  decodeState : GeneratedDecodeStateBindings initial
  landingPadClear :
    initial.regs.get? Register.elp =
      some (Functions.landing_pad_bits_backwards .NO_LP_EXPECTED)
  destination :
    generatedRegisterValue? initial row.rd =
      some (environment.pre.registers row.rd)
  htifDisabled :
    initial.regs.get? Register.htif_tohost_base = some none

structure GeneratedLuiProfileAdmission
    (row : LuiRow)
    (environment :
      Opcodes.LuiEnvironment (Air.Bridge.Lui.interpretedRow row))
    (initial : Functions.GeneratedState) : Prop where
  rv32 : Functions.xlen = 32
  instructionAligned : environment.pre.pc.toNat % 4 = 0
  instructionAddressBound :
    environment.pre.pc.toNat ≤ 1073741820
  rvfiDisabled : Functions.get_config_rvfi () = false
  clintDisabled : Functions.plat_have_clint = false
  signatureDisabled : Functions.plat_have_sig = false
  multiplyEnabled :
    Functions.hartSupports extension.Ext_M = true
  compressedDisabled :
    Functions.hartSupports extension.Ext_Zca = false
  zicbopDisabled :
    Functions.hartSupports extension.Ext_Zicbop = false
  ntlDisabled :
    Functions.hartSupports extension.Ext_Zihintntl = false
  pauseDisabled :
    Functions.hartSupports extension.Ext_Zihintpause = false
  landingPadExtensionDisabled :
    Functions.hartSupports extension.Ext_Zicfilp = false
  instructionByte0 :
    initial.mem.get? environment.pre.pc.toNat =
      some (Sail.BitVec.extractLsb environment.word 7 0)
  instructionByte1 :
    initial.mem.get? (environment.pre.pc.toNat + 1) =
      some (Sail.BitVec.extractLsb environment.word 15 8)
  instructionByte2 :
    initial.mem.get? (environment.pre.pc.toNat + 2) =
      some (Sail.BitVec.extractLsb environment.word 23 16)
  instructionByte3 :
    initial.mem.get? (environment.pre.pc.toNat + 3) =
      some (Sail.BitVec.extractLsb environment.word 31 24)

def LuiOrderedLookups
    (row : LuiRow)
    (witness : Air.Bridge.Lui.Witness row) : Prop :=
  (Air.Bridge.Lui.evaluation row witness).lookup? 9 =
      some (Air.Bridge.Lui.programLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 10 =
      some (Air.Bridge.Lui.stateConsumeLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 11 =
      some (Air.Bridge.Lui.stateEmitLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 12 =
      some (Air.Bridge.Lui.immediateLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 13 =
      some (Air.Bridge.Lui.destinationConsumeLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 14 =
      some (Air.Bridge.Lui.destinationEmitLookup row) ∧
    (Air.Bridge.Lui.evaluation row witness).lookup? 15 =
      some (Air.Bridge.Lui.clockLookup row)

structure GeneratedLuiOpcodeExecution
    (row : LuiRow)
    (environment :
      Opcodes.LuiEnvironment
        (Air.Bridge.Lui.interpretedRow row)) : Prop where
  exactSuccessfulClause :
    Functions.execute
        (Functions.decodedLuiTrace
          (luiImmediate row.imm0 row.imm1 row.imm2)
          row.rd) =
      (do
        Functions.wX_bits (.Regidx row.rd)
          (Functions.sign_extend (m := 32)
            ((luiImmediate row.imm0 row.imm1 row.imm2) +++
              (0x000#12)))
        pure (.Retire_Success ()))
  normalizedRetirement :
    Functions.completeBaseExecution environment.pre.pc
        (Functions.execute_UTYPE
          (luiImmediate row.imm0 row.imm1 row.imm2)
          (.Regidx row.rd) .LUI) =
      Functions.eraseObservation
        (Functions.normalizedRegisterCompletion
          environment.pre.pc row.rd
          (pure
            (Functions.sign_extend (m := 32)
              ((luiImmediate row.imm0 row.imm1 row.imm2) +++
                (0x000#12)))))

def GeneratedLuiConstructiveExecution
    (row : LuiRow)
    (environment :
      Opcodes.LuiEnvironment (Air.Bridge.Lui.interpretedRow row))
    (initial : Functions.GeneratedState)
    (stepNo : Nat) : Prop :=
  Functions.ConstructiveGeneratedExecution
    stepNo environment.word
    (Functions.decodedLuiTrace
      (luiImmediate row.imm0 row.imm1 row.imm2) row.rd)
    (Functions.completeBaseExecution environment.pre.pc
      (Functions.execute
        (Functions.decodedLuiTrace
          (luiImmediate row.imm0 row.imm1 row.imm2) row.rd)))
    (Functions.normalizedRegisterCompletion environment.pre.pc row.rd
      (pure
        (Functions.sign_extend (m := 32)
          ((luiImmediate row.imm0 row.imm1 row.imm2) +++
            (0x000#12)))))
    initial
    (luiRetirement (Air.Bridge.Lui.interpretedRow row))

structure LuiPublicationResult
    (row : LuiRow)
    (witness : Air.Bridge.Lui.Witness row)
    (environment :
      Opcodes.LuiEnvironment (Air.Bridge.Lui.interpretedRow row))
    (relationHolds : EvaluatedLookup → Prop)
    (initial : Functions.GeneratedState)
    (stepNo : Nat)
    (exitWait : Bool) : Prop where
  exactProductionIdentity :
    Programs.lui.source.schemaVersion = 2 ∧
      Programs.lui.source.family = .lui ∧
      Programs.lui.source.opcodeSelector.manifestId = 35 ∧
      Programs.lui.source.opcodeSelector.mnemonic = "lui" ∧
      Programs.lui.source.contentDigest =
        "90b48bf81c506fc024785727ebe33de6e98b96e8e0973bd82299de2a278e287e"
  orderedLookups : LuiOrderedLookups row witness
  semanticRefinement :
    Opcodes.LuiRefinement
      (Air.Bridge.Lui.interpretedRow row) environment
  retirement :
    luiRetirement (Air.Bridge.Lui.interpretedRow row) =
      Sail.Generated.executeLui
        environment.pre.pc row.rd
        (luiImmediate row.imm0 row.imm1 row.imm2)
  exactProgramTuple :
    (Air.Bridge.Lui.programLookup row).tuple = #[
      Air.Bridge.Lui.bitVecM31 row.pc,
      M31.reduce 35,
      Air.Bridge.Lui.bitVecM31 row.rd,
      Air.Bridge.Lui.bitVecM31 row.imm0 +
        Air.Bridge.Lui.bitVecM31 row.imm1 * M31.reduce 16 +
        Air.Bridge.Lui.bitVecM31 row.imm2 * M31.reduce 4096,
      0
    ]
  liveRelations :
    ∀ lookup,
      lookup ∈
          (Programs.lui.evalSymbolic
            (Air.Bridge.Lui.columns row witness)).liveLookups →
        lookup.tableId = none →
        relationHolds lookup
  admissionProofUnique :
    ∀ (first second : Air.Bridge.Lui.Admission row),
      first = second
  decoder :
    Functions.GeneratedDecodeCertificateAt
      environment.word
      (Functions.decodedLuiTrace
        (luiImmediate row.imm0 row.imm1 row.imm2)
        row.rd)
      initial
  stateBindings :
    GeneratedLuiStateBindings row environment initial
  profileAdmission :
    GeneratedLuiProfileAdmission row environment initial
  opcodeExecution :
    GeneratedLuiOpcodeExecution row environment
  constructiveExecution :
    GeneratedLuiConstructiveExecution row environment initial stepNo
  fullStepFraming :
    Functions.GeneratedFullStepRetirementComposition stepNo exitWait

/--
Publication theorem for one accepted production LUI row.

The caller supplies only the production evaluation, its live-relation
interpretation, the AIR admission/environment, and the concrete generated
state/profile bindings.  The architectural retirement, exact generated
decoder result, generated execution clause, and full-step framing are all
derived internally.
-/
theorem LUI_accepted_air_refines
    (row : LuiRow)
    (witness : Air.Bridge.Lui.Witness row)
    (environment :
      Opcodes.LuiEnvironment (Air.Bridge.Lui.interpretedRow row))
    (relationHolds : EvaluatedLookup → Prop)
    (accepted :
      RiscvRefinement.Publication.AcceptedProductionEvaluation
        (Programs.lui.evalSymbolic
          (Air.Bridge.Lui.columns row witness))
        relationHolds)
    (admission : Air.Bridge.Lui.Admission row)
    (initial : Functions.GeneratedState)
    (stateBindings :
      GeneratedLuiStateBindings row environment initial)
    (profileAdmission :
      GeneratedLuiProfileAdmission row environment initial)
    (stepNo : Nat)
    (exitWait : Bool) :
    LuiPublicationResult
      row witness environment relationHolds initial stepNo exitWait := by
  let legacyAcceptance : Air.Bridge.Lui.Acceptance row witness := {
    selectors := accepted.activeProductionRow
    constraints := accepted.directConstraints
    fixedLookups := accepted.fixedTableRequests
  }
  let legacyCertificate :=
    RiscvRefinement.Publication.TeamA.Pilots.lui_accepted_air_implies_retirement
      row witness environment admission legacyAcceptance
  rcases stateBindings.decodeState.mseccfg with
    ⟨mseccfgValue, mseccfgBinding⟩
  have decoder :
      Functions.GeneratedDecodeCertificateAt
        environment.word
        (Functions.decodedLuiTrace
          (luiImmediate row.imm0 row.imm1 row.imm2)
          row.rd)
        initial := by
    rw [environment.wordBinds]
    exact
      Functions.decode_lui_certificate_at
        (luiImmediate row.imm0 row.imm1 row.imm2)
        row.rd initial mseccfgValue
        profileAdmission.pauseDisabled
        profileAdmission.landingPadExtensionDisabled
        stateBindings.privilege
        mseccfgBinding
  exact {
    exactProductionIdentity :=
      legacyCertificate.exactProduction.identity
    orderedLookups :=
      legacyCertificate.exactProduction.orderedLookups
    semanticRefinement :=
      legacyCertificate.semanticRefinement
    retirement := by
      simpa [Air.Bridge.Lui.interpretedRow] using
        legacyCertificate.retirement
    exactProgramTuple :=
      legacyCertificate.exactProgramTuple
    liveRelations :=
      accepted.liveRelations
    admissionProofUnique := by
      intro first second
      exact Subsingleton.elim first second
    decoder := decoder
    stateBindings := stateBindings
    profileAdmission := profileAdmission
    opcodeExecution := {
      exactSuccessfulClause :=
        Functions.execute_decodedLuiTrace_success_clause
          (luiImmediate row.imm0 row.imm1 row.imm2)
          row.rd
      normalizedRetirement := by
        simpa using
          Functions.complete_LUI_normalizes
            environment.pre.pc
            (luiImmediate row.imm0 row.imm1 row.imm2)
            row.rd
    }
    constructiveExecution := by
      unfold GeneratedLuiConstructiveExecution
      constructor
      · constructor
        rcases Functions.bitVec5_cases row.rd with
          h | h | h | h | h | h | h | h |
          h | h | h | h | h | h | h | h |
          h | h | h | h | h | h | h | h |
          h | h | h | h | h | h | h | h <;>
        simp [
          h,
          Functions.runBaseAfterDecode,
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
          Functions.execute_decodedLuiTrace_success_clause,
          Functions.is_landing_pad_expected,
          Functions.landing_pad_bits_backwards,
          Functions.get_config_print_instr,
          PreSail.readReg,
          PreSail.writeReg,
          Functions.wX_bits,
          Functions.wX,
          Functions.xreg_write_callback,
          Functions.encdec_reg_forwards_matches,
          Functions.encdec_reg_forwards,
          Functions.reg_name_forwards,
          Functions.reg_arch_name_raw_forwards,
          Functions.get_config_use_abi_names,
          Functions.not,
          Functions.to_bits,
          Functions.regval_into_reg,
          Functions.xreg_full_write_callback,
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
          modify,
          modifyGet,
          MonadStateOf.modifyGet,
          EStateM.modifyGet,
          stateBindings.pc,
          stateBindings.landingPadClear,
        ] <;>
        exact ⟨_, rfl⟩
      · constructor
        · exact (Functions.complete_decodedLuiTrace_normalizes
            environment.pre.pc
            (luiImmediate row.imm0 row.imm1 row.imm2)
            _).symm
        · rw [legacyCertificate.retirement]
          rcases Functions.bitVec5_cases row.rd with
            h | h | h | h | h | h | h | h |
            h | h | h | h | h | h | h | h |
            h | h | h | h | h | h | h | h |
            h | h | h | h | h | h | h | h <;>
          simp [
            h,
            Functions.normalizedRegisterCompletion,
            Functions.completeRegisterEffects,
            Functions.completeBaseExecution,
            Functions.execute_decodedLuiTrace_success_clause,
            Functions.tick_pc,
            PreSail.readReg,
            PreSail.writeReg,
            Functions.wX_bits,
            Functions.wX,
            Functions.xreg_write_callback,
            Functions.encdec_reg_forwards_matches,
            Functions.encdec_reg_forwards,
            Functions.reg_name_forwards,
            Functions.reg_arch_name_raw_forwards,
            Functions.get_config_use_abi_names,
            Functions.not,
            Functions.to_bits,
            Functions.regval_into_reg,
            Functions.xreg_full_write_callback,
            Functions.pc_write_callback,
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
            modify,
            modifyGet,
            MonadStateOf.modifyGet,
            EStateM.modifyGet,
            Std.ExtDHashMap.get?_insert,
            stateBindings.pc,
            Air.Bridge.Lui.interpretedRow,
            RiscvRefinement.Sail.Generated.executeLui,
            RiscvRefinement.Sail.Generated.executeLuiValue,
          ] <;>
          exact ⟨_, rfl, rfl⟩
    fullStepFraming :=
      Functions.generated_full_step_retirement_composition
        stepNo exitWait
  }

end LeanRV32IM.Publication

namespace LeanRV32IM.Publication

open RiscvRefinement
open RiscvRefinement.Air
open RiscvRefinement.Air.Generated

/-!
## Shared componentwise generated-state boundary

These records deliberately bind state and profile components rather than a
precomputed generated monad outcome.  Family publication theorems extend the
base record with their exact register or memory observations.
-/

structure GeneratedInstructionStateBindings
    (pc word : BitVec 32)
    (initial : Functions.GeneratedState) : Prop where
  hartActive :
    initial.regs.get? Register.hart_state =
      some (.HART_ACTIVE PUnit.unit)
  programCounter :
    initial.regs.get? Register.PC = some pc
  privilege :
    initial.regs.get? Register.cur_privilege = some .Machine
  decodeState : GeneratedDecodeStateBindings initial
  landingPadClear :
    initial.regs.get? Register.elp =
      some (Functions.landing_pad_bits_backwards .NO_LP_EXPECTED)
  htifDisabled :
    initial.regs.get? Register.htif_tohost_base = some none

structure GeneratedInstructionProfileAdmission
    (pc word : BitVec 32)
    (initial : Functions.GeneratedState) : Prop where
  rv32 : Functions.xlen = 32
  instructionAligned : pc.toNat % 4 = 0
  instructionAddressBound : pc.toNat ≤ 1073741820
  rvfiDisabled : Functions.get_config_rvfi () = false
  clintDisabled : Functions.plat_have_clint = false
  signatureDisabled : Functions.plat_have_sig = false
  compressedDisabled :
    Functions.hartSupports extension.Ext_Zca = false
  multiplyEnabled :
    Functions.hartSupports extension.Ext_M = true
  zicbopDisabled :
    Functions.hartSupports extension.Ext_Zicbop = false
  ntlDisabled :
    Functions.hartSupports extension.Ext_Zihintntl = false
  pauseDisabled :
    Functions.hartSupports extension.Ext_Zihintpause = false
  landingPadExtensionDisabled :
    Functions.hartSupports extension.Ext_Zicfilp = false
  instructionByte0 :
    initial.mem.get? pc.toNat =
      some (Sail.BitVec.extractLsb word 7 0)
  instructionByte1 :
    initial.mem.get? (pc.toNat + 1) =
      some (Sail.BitVec.extractLsb word 15 8)
  instructionByte2 :
    initial.mem.get? (pc.toNat + 2) =
      some (Sail.BitVec.extractLsb word 23 16)
  instructionByte3 :
    initial.mem.get? (pc.toNat + 3) =
      some (Sail.BitVec.extractLsb word 31 24)

structure GeneratedRegisterStateBindings
    (initial : Functions.GeneratedState)
    (rs1 rs2 rd : BitVec 5)
    (source1 source2 destination : BitVec 32) : Prop where
  sourceOne :
    generatedRegisterValue? initial rs1 = some source1
  sourceTwo :
    generatedRegisterValue? initial rs2 = some source2
  destination :
    generatedRegisterValue? initial rd = some destination

/-- Componentwise generated-register bindings for an R-type instruction. -/
structure GeneratedBinaryRegisterStateBindings
    (initial : Functions.GeneratedState)
    (rs1 rs2 rd : BitVec 5)
    (source1 source2 destination : BitVec 32) : Prop where
  sourceOne :
    generatedRegisterValue? initial rs1 = some source1
  sourceTwo :
    generatedRegisterValue? initial rs2 = some source2
  destination :
    generatedRegisterValue? initial rd = some destination

/-- Componentwise generated-register bindings for an I-type instruction. -/
structure GeneratedUnaryRegisterStateBindings
    (initial : Functions.GeneratedState)
    (rs1 rd : BitVec 5)
    (source destination : BitVec 32) : Prop where
  source :
    generatedRegisterValue? initial rs1 = some source
  destination :
    generatedRegisterValue? initial rd = some destination

/-- Read-only generated-register bindings used by branches and stores. -/
structure GeneratedReadPairStateBindings
    (initial : Functions.GeneratedState)
    (rs1 rs2 : BitVec 5)
    (source1 source2 : BitVec 32) : Prop where
  sourceOne :
    generatedRegisterValue? initial rs1 = some source1
  sourceTwo :
    generatedRegisterValue? initial rs2 = some source2

/-- Destination-only generated-register binding used by U/J-type rows. -/
structure GeneratedDestinationStateBinding
    (initial : Functions.GeneratedState)
    (rd : BitVec 5)
    (destination : BitVec 32) : Prop where
  destination :
    generatedRegisterValue? initial rd = some destination

/-- Four concrete little-endian bytes bound in generated Sail memory. -/
structure GeneratedMemoryWordBinding
    (initial : Functions.GeneratedState)
    (address value : BitVec 32) : Prop where
  byte0 :
    initial.mem.get? address.toNat =
      some (Sail.BitVec.extractLsb value 7 0)
  byte1 :
    initial.mem.get? (address.toNat + 1) =
      some (Sail.BitVec.extractLsb value 15 8)
  byte2 :
    initial.mem.get? (address.toNat + 2) =
      some (Sail.BitVec.extractLsb value 23 16)
  byte3 :
    initial.mem.get? (address.toNat + 3) =
      some (Sail.BitVec.extractLsb value 31 24)

end LeanRV32IM.Publication
