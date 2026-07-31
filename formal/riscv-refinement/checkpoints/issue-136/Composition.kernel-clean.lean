import Pilot
import RiscvRefinement.Publication.Acceptance
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
      runNormalizedRetirement
        (RiscvRefinement.nextPc pc)
        (normalizedLuiWrite pc imm rd) := by
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
    simp only [
      encodeLuiTrace,
      RiscvRefinement.Decode.encodeLui,
      RiscvRefinement.Decode.luiOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
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
    simp only [
      encodeLuiTrace,
      RiscvRefinement.Decode.encodeLui,
      RiscvRefinement.Decode.luiOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
  simp [lowBits]

private theorem encodeLuiTrace_not_pause
    (imm : BitVec 20)
    (rd : BitVec 5) :
    (encodeLuiTrace imm rd == (0x0100000F#32 : BitVec 32)) =
      false := by
  simp only [
    encodeLuiTrace,
    RiscvRefinement.Decode.encodeLui,
    RiscvRefinement.Decode.luiOpcode,
    BitVec.append_eq,
  ]
  bv_decide

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
  bv_decide

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
  bv_decide

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
  bv_decide

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
  bv_decide

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
  bv_decide

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
  bv_decide

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
  bv_decide

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
    simp only [
      encodeFenceTrace,
      RiscvRefinement.Decode.encodeFence,
      RiscvRefinement.Decode.miscMemOpcode,
      RiscvRefinement.Decode.funct3Fence,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
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
    simp only [
      encodeFenceTrace,
      RiscvRefinement.Decode.encodeFence,
      RiscvRefinement.Decode.miscMemOpcode,
      RiscvRefinement.Decode.funct3Fence,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
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
