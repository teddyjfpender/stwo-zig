import Composition
import RiscvRefinement.Bridge.DecodeBaseAlu
import RiscvRefinement.Bridge.DecodeLt

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

/-!
Generated-Sail decoder certificates for the admitted RV32I register-register
ALU family, plus the shared alias and register-decoder lemmas used by the
immediate and M-extension decoder modules.
-/

def generatedNtlMatchesAlu
    (word : BitVec 32) : Bool :=
  let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
  encdec_ntl_backwards_matches mapping &&
    ((Sail.BitVec.extractLsb word 31 25 == (0b0000000#7 : BitVec 7)) &&
     (Sail.BitVec.extractLsb word 19 0 == (0x00033#20 : BitVec 20)))

noncomputable def generatedNtlProbeAlu
    (word : BitVec 32) : SailM (Option instruction) := do
  let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
  if generatedNtlMatchesAlu word
  then
    let op ← encdec_ntl_backwards mapping
    if (← currentlyEnabled extension.Ext_Zihintntl)
    then pure (some (.NTL op))
    else pure none
  else pure none

private theorem generatedNtlProbeAlu_raw
    (word : BitVec 32) :
    (do
      let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      if encdec_ntl_backwards_matches mapping &&
          ((Sail.BitVec.extractLsb word 31 25 == (0b0000000#7 : BitVec 7)) &&
           (Sail.BitVec.extractLsb word 19 0 == (0x00033#20 : BitVec 20)))
      then
        let op ← encdec_ntl_backwards mapping
        if (← currentlyEnabled extension.Ext_Zihintntl)
        then pure (some (.NTL op))
        else pure none
      else pure none) = generatedNtlProbeAlu word := by
  rfl

private theorem generatedNtlMappingCasesAlu
    (mapping : BitVec 5)
    (matched : encdec_ntl_backwards_matches mapping = true) :
    mapping = (0b00010#5 : BitVec 5) ∨
      mapping = (0b00011#5 : BitVec 5) ∨
      mapping = (0b00100#5 : BitVec 5) ∨
      mapping = (0b00101#5 : BitVec 5) := by
  match mapping with
  | 0b00000 => simp [encdec_ntl_backwards_matches] at matched
  | 0b00001 => simp [encdec_ntl_backwards_matches] at matched
  | 0b00010 => exact Or.inl rfl
  | 0b00011 => exact Or.inr (Or.inl rfl)
  | 0b00100 => exact Or.inr (Or.inr (Or.inl rfl))
  | 0b00101 => exact Or.inr (Or.inr (Or.inr rfl))
  | 0b00110 => simp [encdec_ntl_backwards_matches] at matched
  | 0b00111 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01000 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01001 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01010 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01011 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01100 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01101 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01110 => simp [encdec_ntl_backwards_matches] at matched
  | 0b01111 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10000 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10001 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10010 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10011 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10100 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10101 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10110 => simp [encdec_ntl_backwards_matches] at matched
  | 0b10111 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11000 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11001 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11010 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11011 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11100 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11101 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11110 => simp [encdec_ntl_backwards_matches] at matched
  | 0b11111 => simp [encdec_ntl_backwards_matches] at matched

private theorem generatedNtlProbeAlu_disabled
    (word : BitVec 32)
    (disabled : hartSupports extension.Ext_Zihintntl = false) :
    generatedNtlProbeAlu word = pure none := by
  unfold generatedNtlProbeAlu
  let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
  by_cases live : generatedNtlMatchesAlu word = true
  · simp [generatedNtlMatchesAlu] at live
    have mappingMatches : encdec_ntl_backwards_matches mapping = true := by
      simpa [mapping] using live.1
    have cases := generatedNtlMappingCasesAlu mapping mappingMatches
    rcases cases with branch | branch | branch | branch <;>
      simp [
        generatedNtlMatchesAlu,
        mapping,
        branch,
        encdec_ntl_backwards,
        currentlyEnabled,
        disabled,
      ]
  · have dead : generatedNtlMatchesAlu word = false := by simpa using live
    simp [dead]

theorem currentlyEnabled_pause_disabled_alu
    (disabled : hartSupports extension.Ext_Zihintpause = false) :
    currentlyEnabled extension.Ext_Zihintpause = pure false := by
  simp [currentlyEnabled, disabled]

theorem encdec_reg_backwards_matches_all_alu
    (index : BitVec 5) : encdec_reg_backwards_matches index = true := by
  simp [encdec_reg_backwards_matches, base_E_enabled, not]

theorem encdec_reg_backwards_all_alu
    (index : BitVec 5) :
    encdec_reg_backwards index = pure (.Regidx index) := by
  simp [
    encdec_reg_backwards,
    base_E_enabled,
    regidx_bit_width,
    not,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ]

/-- A low slice cannot equal a target whose in-range subfield disagrees with
an already-proved field of the encoded instruction.  This is the structural,
kernel-checked replacement for bit-vector decision procedures in the decoder
field certificates below. -/
theorem lowSlice_beq_false_of_subfield_ne_alu
    {width start len : Nat}
    (word : BitVec 32)
    (target : BitVec width)
    (within : start + len ≤ width)
    (field : BitVec len)
    (encodedField : BitVec.extractLsb' start len word = field)
    (mismatch : field ≠ BitVec.extractLsb' start len target) :
    (BitVec.extractLsb' 0 width word == target) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro lowSlice
  have nestedEquality :
      BitVec.extractLsb' start len
          (BitVec.extractLsb' 0 width word) =
        BitVec.extractLsb' start len target :=
    congrArg
      (fun value : BitVec width =>
        BitVec.extractLsb' start len value)
      lowSlice
  have nestedExtract :
      BitVec.extractLsb' start len
          (BitVec.extractLsb' 0 width word) =
        BitVec.extractLsb' start len word :=
    BitVec.extractLsb'_extractLsb'_of_le
      (x := word)
      (start := start)
      (len := len)
      (len' := width)
      within
  exact mismatch
    (encodedField.symm.trans (nestedExtract.symm.trans nestedEquality))

inductive AdmittedBaseRTypeOp where
  | add | sub | sll | slt | sltu | xor | srl | sra | or | and
deriving DecidableEq, Repr

def admittedBaseRTypeFunct7 : AdmittedBaseRTypeOp → BitVec 7
  | .sub | .sra => RiscvRefinement.Decode.funct7Alt
  | _ => RiscvRefinement.Decode.funct7Base

def admittedBaseRTypeFunct3 : AdmittedBaseRTypeOp → BitVec 3
  | .add | .sub => 0b000#3
  | .sll => 0b001#3
  | .slt => 0b010#3
  | .sltu => 0b011#3
  | .xor => 0b100#3
  | .srl | .sra => 0b101#3
  | .or => 0b110#3
  | .and => 0b111#3

def admittedBaseRTypeInstruction
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) : instruction :=
  let generatedOp : rop :=
    match op with
    | .add => .ADD
    | .sub => .SUB
    | .sll => .SLL
    | .slt => .SLT
    | .sltu => .SLTU
    | .xor => .XOR
    | .srl => .SRL
    | .sra => .SRA
    | .or => .OR
    | .and => .AND
  .RTYPE (.Regidx rs2, .Regidx rs1, .Regidx rd, generatedOp)

def encodeAdmittedBaseRType
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) : BitVec 32 :=
  RiscvRefinement.Decode.encodeRType
    (admittedBaseRTypeFunct7 op) rs2 rs1
    (admittedBaseRTypeFunct3 op) rd

private theorem encodeAdmittedBaseRType_opcode_core
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 6 0 =
      (0b0110011#7 : BitVec 7) := by
  simp only [
    encodeAdmittedBaseRType,
    RiscvRefinement.Decode.encodeRType,
    RiscvRefinement.Decode.opOpcode,
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
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 0) (len := 7) (by decide)]
  exact BitVec.extractLsb'_append_eq_right

private theorem encodeAdmittedBaseRType_not_zicbop
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedBaseRType op rs2 rs1 rd
      let mapping1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
      let mapping0 : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      (encdec_cbop_zicbop_backwards_matches mapping0 &&
          encdec_reg_backwards_matches mapping1) &&
        Sail.BitVec.extractLsb word 14 0 ==
          (0b110000000010011#15 : BitVec 15)) : Bool) = false := by
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeAdmittedBaseRType op rs2 rs1 rd) 14 0 ==
        (0b110000000010011#15 : BitVec 15)) = false := by
    simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
      lowSlice_beq_false_of_subfield_ne_alu
        (width := 15) (start := 0) (len := 7)
        (encodeAdmittedBaseRType op rs2 rs1 rd)
        (0b110000000010011#15 : BitVec 15)
        (by decide)
        (0b0110011#7 : BitVec 7)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeAdmittedBaseRType_opcode_core op rs2 rs1 rd)
        (by decide)
  simp [lowBits]

private theorem encodeAdmittedBaseRType_opcode
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 6 0 =
      (0b0110011#7 : BitVec 7) :=
  encodeAdmittedBaseRType_opcode_core op rs2 rs1 rd

private theorem encodeAdmittedBaseRType_not_lpad
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 11 0 ==
      (0x017#12 : BitVec 12)) = false := by
  simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
    lowSlice_beq_false_of_subfield_ne_alu
      (width := 12) (start := 0) (len := 7)
      (encodeAdmittedBaseRType op rs2 rs1 rd)
      (0x017#12 : BitVec 12)
      (by decide)
      (0b0110011#7 : BitVec 7)
      (by
        simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
          encodeAdmittedBaseRType_opcode_core op rs2 rs1 rd)
      (by decide)

private theorem encodeAdmittedBaseRType_funct3
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 14 12 =
      admittedBaseRTypeFunct3 op := by
  simp only [
    encodeAdmittedBaseRType,
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 12) (len := 3) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 12) (len := 3) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedBaseRType_funct7
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 31 25 =
      admittedBaseRTypeFunct7 op := by
  simp only [
    encodeAdmittedBaseRType,
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 25) (len := 7) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedBaseRType_rs2
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 24 20 = rs2 := by
  simp only [
    encodeAdmittedBaseRType,
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 20) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 20) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedBaseRType_rs1
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 19 15 = rs1 := by
  simp only [
    encodeAdmittedBaseRType,
    RiscvRefinement.Decode.encodeRType,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 15) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 15) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 15) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

private theorem encodeAdmittedBaseRType_rd
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedBaseRType op rs2 rs1 rd) 11 7 = rd := by
  simp only [
    encodeAdmittedBaseRType,
    RiscvRefinement.Decode.encodeRType,
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
  rw [BitVec.extractLsb'_append_eq_of_add_le
    (start := 7) (len := 5) (by decide)]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 7) (len := 5) (by decide)]
  exact BitVec.extractLsb'_eq_self

theorem ext_decode_admitted_base_rtype_branch
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5)
    (ntlDisabled : hartSupports extension.Ext_Zihintntl = false)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false) :
    ext_decode (encodeAdmittedBaseRType op rs2 rs1 rd) =
      generatedUtypeDecodeProgram
        (admittedBaseRTypeInstruction op rs2 rs1 rd) := by
  cases op <;>
    rw [ext_decode.eq_1, encdec_backwards.eq_def] <;>
    simp only [
      encodeAdmittedBaseRType_not_zicbop,
      Bool.false_eq_true,
      if_false,
      pure_bind,
    ] <;>
    rw [
      generatedNtlProbeAlu_raw,
      generatedNtlProbeAlu_disabled _ ntlDisabled,
    ] <;>
    simp only [
      currentlyEnabled_pause_disabled_alu pauseDisabled,
      encodeAdmittedBaseRType_not_lpad,
      encodeAdmittedBaseRType_opcode,
      encodeAdmittedBaseRType_funct3,
      encodeAdmittedBaseRType_funct7,
      encodeAdmittedBaseRType_rs2,
      encodeAdmittedBaseRType_rs1,
      encodeAdmittedBaseRType_rd,
      encdec_reg_backwards_matches_all_alu,
      encdec_reg_backwards_all_alu,
      encdec_uop_backwards_matches,
      generatedUtypeDecodePreamble,
      generatedUtypeDecodeProgram,
      admittedBaseRTypeFunct7,
      admittedBaseRTypeFunct3,
      admittedBaseRTypeInstruction,
      RiscvRefinement.Decode.funct7Base,
      RiscvRefinement.Decode.funct7Alt,
      Bool.false_and,
      Bool.and_false,
      Bool.false_eq_true,
      if_false,
      pure_bind,
      bind_assoc,
    ] <;> simp

theorem decode_admitted_base_rtype_certificate
    (op : AdmittedBaseRTypeOp)
    (rs2 rs1 rd : BitVec 5)
    (ntlDisabled : hartSupports extension.Ext_Zihintntl = false)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false) :
    GeneratedDecodeCertificate
      (encodeAdmittedBaseRType op rs2 rs1 rd)
      (admittedBaseRTypeInstruction op rs2 rs1 rd) := by
  constructor
  intro initial final actual outcome
  rw [
    ext_decode_admitted_base_rtype_branch
      op rs2 rs1 rd ntlDisabled pauseDisabled,
  ] at outcome
  exact
    generatedUtypeDecodeProgram_success
      (admittedBaseRTypeInstruction op rs2 rs1 rd)
      actual initial final outcome

def generatedZicbopMatchesAlu
    (word : BitVec 32) : Bool :=
  let mapping1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
  let mapping0 : BitVec 5 := Sail.BitVec.extractLsb word 24 20
  (encdec_cbop_zicbop_backwards_matches mapping0 &&
      encdec_reg_backwards_matches mapping1) &&
    Sail.BitVec.extractLsb word 14 0 ==
      (0b110000000010011#15 : BitVec 15)

noncomputable def generatedZicbopProbeAlu
    (word : BitVec 32) : SailM (Option instruction) := do
  let offset11_5 : BitVec 7 := Sail.BitVec.extractLsb word 31 25
  let mapping1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
  let mapping0 : BitVec 5 := Sail.BitVec.extractLsb word 24 20
  if generatedZicbopMatchesAlu word
  then
    let cbop ← encdec_cbop_zicbop_backwards mapping0
    let rs1 ← encdec_reg_backwards mapping1
    if (← currentlyEnabled extension.Ext_Zicbop)
    then
      pure
        (some
          (.ZICBOP
            (cbop, rs1,
              ((offset11_5 : BitVec 7) +++ (0b00000#5)))))
    else pure none
  else pure none

theorem generatedZicbopProbeAlu_raw
    (word : BitVec 32) :
    (do
      if (((let mapping1 : BitVec 5 :=
              Sail.BitVec.extractLsb word 19 15
            let mapping0 : BitVec 5 :=
              Sail.BitVec.extractLsb word 24 20
            encdec_cbop_zicbop_backwards_matches mapping0 &&
              encdec_reg_backwards_matches mapping1) &&
          Sail.BitVec.extractLsb word 14 0 ==
            (0b110000000010011#15 : BitVec 15)) : Bool)
      then
        let offset11_5 : BitVec 7 :=
          Sail.BitVec.extractLsb word 31 25
        let offset11_5 : BitVec 7 :=
          Sail.BitVec.extractLsb word 31 25
        let mapping1 : BitVec 5 :=
          Sail.BitVec.extractLsb word 19 15
        let mapping0 : BitVec 5 :=
          Sail.BitVec.extractLsb word 24 20
        match
            ((← encdec_cbop_zicbop_backwards mapping0),
              (← encdec_reg_backwards mapping1)) with
        | (cbop, rs1) =>
          if (← currentlyEnabled extension.Ext_Zicbop)
          then
            pure
              (some
                (.ZICBOP
                  (cbop, rs1,
                    ((offset11_5 : BitVec 7) +++ (0b00000#5)))))
          else pure none
      else pure none) = generatedZicbopProbeAlu word := by
  rfl

private theorem generatedZicbopMappingCasesAlu
    (mapping : BitVec 5)
    (matched : encdec_cbop_zicbop_backwards_matches mapping = true) :
    mapping = (0b00000#5 : BitVec 5) ∨
      mapping = (0b00001#5 : BitVec 5) ∨
      mapping = (0b00011#5 : BitVec 5) := by
  match mapping with
  | 0b00000 => exact Or.inl rfl
  | 0b00001 => exact Or.inr (Or.inl rfl)
  | 0b00010 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b00011 => exact Or.inr (Or.inr rfl)
  | 0b00100 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b00101 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b00110 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b00111 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01000 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01001 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01010 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01011 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01100 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01101 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01110 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b01111 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10000 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10001 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10010 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10011 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10100 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10101 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10110 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b10111 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11000 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11001 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11010 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11011 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11100 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11101 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11110 => simp [encdec_cbop_zicbop_backwards_matches] at matched
  | 0b11111 => simp [encdec_cbop_zicbop_backwards_matches] at matched

theorem generatedZicbopProbeAlu_disabled
    (word : BitVec 32)
    (disabled : hartSupports extension.Ext_Zicbop = false) :
    generatedZicbopProbeAlu word = pure none := by
  unfold generatedZicbopProbeAlu
  let mapping0 : BitVec 5 := Sail.BitVec.extractLsb word 24 20
  by_cases live : generatedZicbopMatchesAlu word = true
  · simp [generatedZicbopMatchesAlu] at live
    have mappingMatches :
        encdec_cbop_zicbop_backwards_matches mapping0 = true := by
      simpa [mapping0] using live.1.1
    have cases := generatedZicbopMappingCasesAlu mapping0 mappingMatches
    rcases cases with branch | branch | branch <;>
      simp [
        generatedZicbopMatchesAlu,
        mapping0,
        branch,
        encdec_cbop_zicbop_backwards,
        encdec_reg_backwards_all_alu,
        currentlyEnabled,
        disabled,
      ]
  · have dead : generatedZicbopMatchesAlu word = false := by simpa using live
    simp [dead]

end LeanRV32IM.Functions
