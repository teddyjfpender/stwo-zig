import DecodeAluBase

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

inductive AdmittedShiftITypeOp where
  | slli | srli | srai
deriving DecidableEq, Repr

def admittedShiftITypeFunct7 : AdmittedShiftITypeOp → BitVec 7
  | .srai => RiscvRefinement.Decode.funct7Alt
  | .slli | .srli => RiscvRefinement.Decode.funct7Base

def admittedShiftITypeFunct3 : AdmittedShiftITypeOp → BitVec 3
  | .slli => RiscvRefinement.Decode.funct3Sll
  | .srli => RiscvRefinement.Decode.funct3Srl
  | .srai => RiscvRefinement.Decode.funct3Sra

def admittedShiftITypeGeneratedOp : AdmittedShiftITypeOp → sop
  | .slli => .SLLI
  | .srli => .SRLI
  | .srai => .SRAI

def encodeAdmittedShiftIType
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) : BitVec 32 :=
  RiscvRefinement.Decode.encodeShiftImm
    (admittedShiftITypeFunct7 op) shamt rs1
    (admittedShiftITypeFunct3 op) rd

def admittedShiftITypeInstruction
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) : instruction :=
  .SHIFTIOP
    (((0#1 : BitVec 1) +++ shamt),
      .Regidx rs1,
      .Regidx rd,
      admittedShiftITypeGeneratedOp op)

private theorem encodeAdmittedShiftIType_opcode_core
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 6 0 =
      (0b0010011#7 : BitVec 7) := by
  simp only [
    encodeAdmittedShiftIType,
    RiscvRefinement.Decode.encodeShiftImm,
    RiscvRefinement.Decode.opImmOpcode,
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

private theorem encodeAdmittedShiftIType_funct3_core
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 14 12 =
      admittedShiftITypeFunct3 op := by
  simp only [
    encodeAdmittedShiftIType,
    RiscvRefinement.Decode.encodeShiftImm,
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

theorem encodeAdmittedShiftIType_not_zicbop
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedShiftIType op shamt rs1 rd
      let mapping1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
      let mapping0 : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      (encdec_cbop_zicbop_backwards_matches mapping0 &&
          encdec_reg_backwards_matches mapping1) &&
        Sail.BitVec.extractLsb word 14 0 ==
          (0b110000000010011#15 : BitVec 15)) : Bool) = false := by
  have funct3Mismatch :
      admittedShiftITypeFunct3 op ≠
        BitVec.extractLsb' 12 3
          (0b110000000010011#15 : BitVec 15) := by
    cases op <;>
      simp [
        admittedShiftITypeFunct3,
        RiscvRefinement.Decode.funct3Sll,
        RiscvRefinement.Decode.funct3Srl,
        RiscvRefinement.Decode.funct3Sra,
      ]
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeAdmittedShiftIType op shamt rs1 rd) 14 0 ==
        (0b110000000010011#15 : BitVec 15)) = false := by
    simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
      lowSlice_beq_false_of_subfield_ne_alu
        (width := 15) (start := 12) (len := 3)
        (encodeAdmittedShiftIType op shamt rs1 rd)
        (0b110000000010011#15 : BitVec 15)
        (by decide)
        (admittedShiftITypeFunct3 op)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeAdmittedShiftIType_funct3_core op shamt rs1 rd)
        funct3Mismatch
  simp [lowBits]

theorem encodeAdmittedShiftIType_not_ntl
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedShiftIType op shamt rs1 rd
      let mapping : BitVec 5 := Sail.BitVec.extractLsb word 24 20
      encdec_ntl_backwards_matches mapping &&
        ((Sail.BitVec.extractLsb word 31 25 ==
          (0b0000000#7 : BitVec 7)) &&
         (Sail.BitVec.extractLsb word 19 0 ==
          (0x00033#20 : BitVec 20)))) : Bool) = false := by
  have lowBits :
      (Sail.BitVec.extractLsb
          (encodeAdmittedShiftIType op shamt rs1 rd) 19 0 ==
        (0x00033#20 : BitVec 20)) = false := by
    simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
      lowSlice_beq_false_of_subfield_ne_alu
        (width := 20) (start := 0) (len := 7)
        (encodeAdmittedShiftIType op shamt rs1 rd)
        (0x00033#20 : BitVec 20)
        (by decide)
        (0b0010011#7 : BitVec 7)
        (by
          simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
            encodeAdmittedShiftIType_opcode_core op shamt rs1 rd)
        (by decide)
  simp [lowBits]

theorem encodeAdmittedShiftIType_not_lpad
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedShiftIType op shamt rs1 rd) 11 0 ==
      (0x017#12 : BitVec 12)) = false := by
  simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
    lowSlice_beq_false_of_subfield_ne_alu
      (width := 12) (start := 0) (len := 7)
      (encodeAdmittedShiftIType op shamt rs1 rd)
      (0x017#12 : BitVec 12)
      (by decide)
      (0b0010011#7 : BitVec 7)
      (by
        simpa only [Sail.BitVec.extractLsb, BitVec.extractLsb] using
          encodeAdmittedShiftIType_opcode_core op shamt rs1 rd)
      (by decide)

theorem encodeAdmittedShiftIType_opcode
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 6 0 =
      (0b0010011#7 : BitVec 7) :=
  encodeAdmittedShiftIType_opcode_core op shamt rs1 rd

theorem encodeAdmittedShiftIType_opcode_mismatch
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5)
    (opcode : BitVec 7)
    (mismatch : (0b0010011#7 : BitVec 7) ≠ opcode) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedShiftIType op shamt rs1 rd) 6 0 == opcode) = false := by
  rw [encodeAdmittedShiftIType_opcode]
  exact beq_eq_false_iff_ne.mpr mismatch

theorem encodeAdmittedShiftIType_not_jal
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedShiftIType op shamt rs1 rd) 6 0 ==
      (0b1101111#7 : BitVec 7)) = false :=
  encodeAdmittedShiftIType_opcode_mismatch op shamt rs1 rd _ (by decide)

theorem encodeAdmittedShiftIType_not_jalr
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedShiftIType op shamt rs1 rd) 6 0 ==
      (0b1100111#7 : BitVec 7)) = false :=
  encodeAdmittedShiftIType_opcode_mismatch op shamt rs1 rd _ (by decide)

theorem encodeAdmittedShiftIType_not_branch
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (encodeAdmittedShiftIType op shamt rs1 rd) 6 0 ==
      (0b1100011#7 : BitVec 7)) = false :=
  encodeAdmittedShiftIType_opcode_mismatch op shamt rs1 rd _ (by decide)

theorem encodeAdmittedShiftIType_not_utype
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedShiftIType op shamt rs1 rd
      let opcode : BitVec 7 := Sail.BitVec.extractLsb word 6 0
      let destination : BitVec 5 := Sail.BitVec.extractLsb word 11 7
      encdec_reg_backwards_matches destination &&
        encdec_uop_backwards_matches opcode) : Bool) = false := by
  simp [
    encodeAdmittedShiftIType_opcode,
    encdec_uop_backwards_matches,
  ]

theorem encodeAdmittedShiftIType_funct3
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 14 12 =
      admittedShiftITypeFunct3 op :=
  encodeAdmittedShiftIType_funct3_core op shamt rs1 rd

theorem encodeAdmittedShiftIType_not_itype
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    ((let word := encodeAdmittedShiftIType op shamt rs1 rd
      let destination : BitVec 5 := Sail.BitVec.extractLsb word 11 7
      let operation : BitVec 3 := Sail.BitVec.extractLsb word 14 12
      let source : BitVec 5 := Sail.BitVec.extractLsb word 19 15
      (encdec_reg_backwards_matches source &&
          (encdec_iop_backwards_matches operation &&
            encdec_reg_backwards_matches destination)) &&
        Sail.BitVec.extractLsb word 6 0 ==
          (0b0010011#7 : BitVec 7)) : Bool) = false := by
  cases op <;>
    simp only [
      encodeAdmittedShiftIType_funct3,
      admittedShiftITypeFunct3,
      RiscvRefinement.Decode.funct3Sll,
      RiscvRefinement.Decode.funct3Srl,
      RiscvRefinement.Decode.funct3Sra,
      encdec_iop_backwards_matches,
      Bool.false_and,
      Bool.and_false,
    ]
  all_goals simp

theorem encodeAdmittedShiftIType_top6
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 31 26 =
      Sail.BitVec.extractLsb (admittedShiftITypeFunct7 op) 6 1 := by
  simp only [
    encodeAdmittedShiftIType,
    RiscvRefinement.Decode.encodeShiftImm,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  rw [BitVec.extractLsb'_append_eq_of_le
    (start := 26) (len := 6) (by decide)]

theorem encodeAdmittedShiftIType_shamt6
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 25 20 =
      ((0#1 : BitVec 1) +++ shamt) := by
  cases op <;>
    simp only [
      encodeAdmittedShiftIType,
      admittedShiftITypeFunct7,
      RiscvRefinement.Decode.encodeShiftImm,
      RiscvRefinement.Decode.funct7Base,
      RiscvRefinement.Decode.funct7Alt,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
  all_goals
    rw [BitVec.extractLsb'_append_eq_ite]
    simp only [
      show 20 < 25 by decide,
      show ¬20 + 6 ≤ 25 by decide,
      dif_pos,
      dif_neg,
    ]
    rw [BitVec.extractLsb'_append_eq_left]
    simp

theorem encodeAdmittedShiftIType_rs1
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 19 15 = rs1 := by
  simp only [
    encodeAdmittedShiftIType,
    RiscvRefinement.Decode.encodeShiftImm,
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

theorem encodeAdmittedShiftIType_rd
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAdmittedShiftIType op shamt rs1 rd) 11 7 = rd := by
  simp only [
    encodeAdmittedShiftIType,
    RiscvRefinement.Decode.encodeShiftImm,
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

/-!
The generated decoder implements the three shift-immediate cases as a local
three-probe option cascade followed by the rest of the decoder.  Naming the
probes and the cascade lets a leaf replace that rest with an opaque `fallback`
*before* simplification starts.  This is the same continuation-factoring
boundary used for the generated M-extension gate.
-/

noncomputable abbrev generatedSlliProbe
    (word : BitVec 32) : SailM (Option instruction) := do
  if (((let rd : BitVec 5 := Sail.BitVec.extractLsb word 11 7
        let rs1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
        encdec_reg_backwards_matches rs1 &&
          encdec_reg_backwards_matches rd) &&
      ((Sail.BitVec.extractLsb word 31 26 == (0b000000#6 : BitVec 6)) &&
        ((Sail.BitVec.extractLsb word 14 12 == (0b001#3 : BitVec 3)) &&
          (Sail.BitVec.extractLsb word 6 0 ==
            (0b0010011#7 : BitVec 7))))) : Bool)
  then
    let shamt : BitVec 6 := Sail.BitVec.extractLsb word 25 20
    let rdBits : BitVec 5 := Sail.BitVec.extractLsb word 11 7
    let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb word 19 15
    match ((← encdec_reg_backwards rs1Bits),
        (← encdec_reg_backwards rdBits)) with
    | (rs1, rd) =>
      if (((xlen == 64) || ((BitVec.access shamt 5) == 0#1)) : Bool)
      then pure (some (.SHIFTIOP (shamt, rs1, rd, .SLLI)))
      else pure none
  else pure none

noncomputable abbrev generatedSrliProbe
    (word : BitVec 32) : SailM (Option instruction) := do
  if (((let rd : BitVec 5 := Sail.BitVec.extractLsb word 11 7
        let rs1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
        encdec_reg_backwards_matches rs1 &&
          encdec_reg_backwards_matches rd) &&
      ((Sail.BitVec.extractLsb word 31 26 == (0b000000#6 : BitVec 6)) &&
        ((Sail.BitVec.extractLsb word 14 12 == (0b101#3 : BitVec 3)) &&
          (Sail.BitVec.extractLsb word 6 0 ==
            (0b0010011#7 : BitVec 7))))) : Bool)
  then
    let shamt : BitVec 6 := Sail.BitVec.extractLsb word 25 20
    let rdBits : BitVec 5 := Sail.BitVec.extractLsb word 11 7
    let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb word 19 15
    match ((← encdec_reg_backwards rs1Bits),
        (← encdec_reg_backwards rdBits)) with
    | (rs1, rd) =>
      if (((xlen == 64) || ((BitVec.access shamt 5) == 0#1)) : Bool)
      then pure (some (.SHIFTIOP (shamt, rs1, rd, .SRLI)))
      else pure none
  else pure none

noncomputable abbrev generatedSraiProbe
    (word : BitVec 32) : SailM (Option instruction) := do
  if (((let rd : BitVec 5 := Sail.BitVec.extractLsb word 11 7
        let rs1 : BitVec 5 := Sail.BitVec.extractLsb word 19 15
        encdec_reg_backwards_matches rs1 &&
          encdec_reg_backwards_matches rd) &&
      ((Sail.BitVec.extractLsb word 31 26 == (0b010000#6 : BitVec 6)) &&
        ((Sail.BitVec.extractLsb word 14 12 == (0b101#3 : BitVec 3)) &&
          (Sail.BitVec.extractLsb word 6 0 ==
            (0b0010011#7 : BitVec 7))))) : Bool)
  then
    let shamt : BitVec 6 := Sail.BitVec.extractLsb word 25 20
    let rdBits : BitVec 5 := Sail.BitVec.extractLsb word 11 7
    let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb word 19 15
    match ((← encdec_reg_backwards rs1Bits),
        (← encdec_reg_backwards rdBits)) with
    | (rs1, rd) =>
      if (((xlen == 64) || ((BitVec.access shamt 5) == 0#1)) : Bool)
      then pure (some (.SHIFTIOP (shamt, rs1, rd, .SRAI)))
      else pure none
  else pure none

/-!
These equalities deliberately repeat the generated surface syntax.  Rewriting
them immediately after `encdec_backwards.eq_def` folds the three direct probes
to opaque names without asking the simplifier to traverse their fallback.
-/

theorem generatedSlliProbe_raw (word : BitVec 32) :
    (do
      let value := word
      if (((let rdBits : BitVec 5 := Sail.BitVec.extractLsb value 11 7
            let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb value 19 15
            encdec_reg_backwards_matches rs1Bits &&
              encdec_reg_backwards_matches rdBits) &&
          ((Sail.BitVec.extractLsb value 31 26 ==
              (0b000000#6 : BitVec 6)) &&
            ((Sail.BitVec.extractLsb value 14 12 ==
                (0b001#3 : BitVec 3)) &&
              (Sail.BitVec.extractLsb value 6 0 ==
                (0b0010011#7 : BitVec 7))))) : Bool)
      then
        let shamt : BitVec 6 := Sail.BitVec.extractLsb value 25 20
        let rdBits : BitVec 5 := Sail.BitVec.extractLsb value 11 7
        let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb value 19 15
        match ((← encdec_reg_backwards rs1Bits),
            (← encdec_reg_backwards rdBits)) with
        | (rs1, rd) =>
          if (((xlen == 64) ||
              ((BitVec.access shamt 5) == 0#1)) : Bool)
          then pure (some (.SHIFTIOP (shamt, rs1, rd, .SLLI)))
          else pure none
      else pure none) = generatedSlliProbe word := by
  rfl

theorem generatedSrliProbe_raw (word : BitVec 32) :
    (do
      let value := word
      if (((let rdBits : BitVec 5 := Sail.BitVec.extractLsb value 11 7
            let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb value 19 15
            encdec_reg_backwards_matches rs1Bits &&
              encdec_reg_backwards_matches rdBits) &&
          ((Sail.BitVec.extractLsb value 31 26 ==
              (0b000000#6 : BitVec 6)) &&
            ((Sail.BitVec.extractLsb value 14 12 ==
                (0b101#3 : BitVec 3)) &&
              (Sail.BitVec.extractLsb value 6 0 ==
                (0b0010011#7 : BitVec 7))))) : Bool)
      then
        let shamt : BitVec 6 := Sail.BitVec.extractLsb value 25 20
        let rdBits : BitVec 5 := Sail.BitVec.extractLsb value 11 7
        let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb value 19 15
        match ((← encdec_reg_backwards rs1Bits),
            (← encdec_reg_backwards rdBits)) with
        | (rs1, rd) =>
          if (((xlen == 64) ||
              ((BitVec.access shamt 5) == 0#1)) : Bool)
          then pure (some (.SHIFTIOP (shamt, rs1, rd, .SRLI)))
          else pure none
      else pure none) = generatedSrliProbe word := by
  rfl

theorem generatedSraiProbe_raw (word : BitVec 32) :
    (do
      let value := word
      if (((let rdBits : BitVec 5 := Sail.BitVec.extractLsb value 11 7
            let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb value 19 15
            encdec_reg_backwards_matches rs1Bits &&
              encdec_reg_backwards_matches rdBits) &&
          ((Sail.BitVec.extractLsb value 31 26 ==
              (0b010000#6 : BitVec 6)) &&
            ((Sail.BitVec.extractLsb value 14 12 ==
                (0b101#3 : BitVec 3)) &&
              (Sail.BitVec.extractLsb value 6 0 ==
                (0b0010011#7 : BitVec 7))))) : Bool)
      then
        let shamt : BitVec 6 := Sail.BitVec.extractLsb value 25 20
        let rdBits : BitVec 5 := Sail.BitVec.extractLsb value 11 7
        let rs1Bits : BitVec 5 := Sail.BitVec.extractLsb value 19 15
        match ((← encdec_reg_backwards rs1Bits),
            (← encdec_reg_backwards rdBits)) with
        | (rs1, rd) =>
          if (((xlen == 64) ||
              ((BitVec.access shamt 5) == 0#1)) : Bool)
          then pure (some (.SHIFTIOP (shamt, rs1, rd, .SRAI)))
          else pure none
      else pure none) = generatedSraiProbe word := by
  rfl

noncomputable def generatedShiftITypeBody
    (word : BitVec 32)
    (fallback : SailM instruction) : SailM instruction := do
  match (← generatedSlliProbe word) with
  | some result => pure result
  | none =>
    match (← generatedSrliProbe word) with
    | some result => pure result
    | none =>
      match (← generatedSraiProbe word) with
      | some result => pure result
      | none => fallback

/-- Replace the exact local generated option cascade before visiting fallback. -/
theorem generatedShiftITypeBody_factor
    (word : BitVec 32)
    (fallback : SailM instruction) :
    (do
      match (← generatedSlliProbe word) with
      | some result => pure result
      | none =>
        match (← generatedSrliProbe word) with
        | some result => pure result
        | none =>
          match (← generatedSraiProbe word) with
          | some result => pure result
          | none => fallback) =
      generatedShiftITypeBody word fallback := by
  rfl

/-- Fold the shift cascade without rewriting beneath the generated LPAD read. -/
theorem generatedShiftITypeBody_factor_after_zicfilp
    (word : BitVec 32)
    (fallback : SailM instruction) :
    (do
      let _ ← currentlyEnabled extension.Ext_Zicfilp
      match (← generatedSlliProbe word) with
      | some result => pure result
      | none =>
        match (← generatedSrliProbe word) with
        | some result => pure result
        | none =>
          match (← generatedSraiProbe word) with
          | some result => pure result
          | none => fallback) =
      (do
        let _ ← currentlyEnabled extension.Ext_Zicfilp
        generatedShiftITypeBody word fallback) := by
  rfl

theorem generatedShiftITypeBody_slli
    (word : BitVec 32)
    (fallback : SailM instruction)
    (decoded : instruction)
    (slliExact : generatedSlliProbe word = pure (some decoded)) :
    generatedShiftITypeBody word fallback = pure decoded := by
  unfold generatedShiftITypeBody
  rw [slliExact]
  rfl

theorem generatedShiftITypeBody_srli
    (word : BitVec 32)
    (fallback : SailM instruction)
    (decoded : instruction)
    (slliMiss : generatedSlliProbe word = pure none)
    (srliExact : generatedSrliProbe word = pure (some decoded)) :
    generatedShiftITypeBody word fallback = pure decoded := by
  unfold generatedShiftITypeBody
  rw [slliMiss, srliExact]
  rfl

theorem generatedShiftITypeBody_srai
    (word : BitVec 32)
    (fallback : SailM instruction)
    (decoded : instruction)
    (slliMiss : generatedSlliProbe word = pure none)
    (srliMiss : generatedSrliProbe word = pure none)
    (sraiExact : generatedSraiProbe word = pure (some decoded)) :
    generatedShiftITypeBody word fallback = pure decoded := by
  unfold generatedShiftITypeBody
  rw [slliMiss, srliMiss, sraiExact]
  rfl

noncomputable def generatedShiftITypeGate
    (word : BitVec 32)
    (fallback : SailM instruction) : SailM instruction := do
  let _ ← generatedUtypeDecodePreamble
  generatedShiftITypeBody word fallback

theorem generatedShiftITypeGate_exact_at
    (word : BitVec 32)
    (fallback : SailM instruction)
    (decoded : instruction)
    (initial : GeneratedState)
    (mseccfgValue : BitVec 64)
    (pauseDisabled : hartSupports extension.Ext_Zihintpause = false)
    (landingPadDisabled : hartSupports extension.Ext_Zicfilp = false)
    (privilegeBinding :
      initial.regs.get? Register.cur_privilege = some .Machine)
    (mseccfgBinding :
      initial.regs.get? Register.mseccfg = some mseccfgValue) :
    (bodyExact :
      generatedShiftITypeBody word fallback = pure decoded) →
    generatedShiftITypeGate word fallback initial = .ok decoded initial := by
  intro bodyExact
  simp only [
    generatedShiftITypeGate,
    bodyExact,
    generatedUtypeDecodePreamble_exact_at
      initial mseccfgValue pauseDisabled landingPadDisabled
      privilegeBinding mseccfgBinding,
    bind,
    EStateM.bind,
    pure,
    EStateM.pure,
  ]

theorem generatedShiftITypeGate_success
    (word : BitVec 32)
    (fallback : SailM instruction)
    (decoded actual : instruction)
    (initial final : GeneratedState)
    (bodyExact :
      generatedShiftITypeBody word fallback = pure decoded)
    (outcome :
      generatedShiftITypeGate word fallback initial = .ok actual final) :
    actual = decoded := by
  unfold generatedShiftITypeGate at outcome
  rw [bodyExact] at outcome
  exact generatedUtypeDecodeProgram_success decoded actual initial final
    (by simpa only [generatedUtypeDecodeProgram] using outcome)

/-- The generated NTL probe, named before its disabled continuation expands. -/
theorem generatedNtlProbeShift_raw
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

theorem encodeAdmittedShiftIType_ntl_dead
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    generatedNtlMatchesAlu
      (encodeAdmittedShiftIType op shamt rs1 rd) = false := by
  simpa only [generatedNtlMatchesAlu] using
    encodeAdmittedShiftIType_not_ntl op shamt rs1 rd

theorem generatedNtlProbeShift_dead
    (op : AdmittedShiftITypeOp)
    (shamt : BitVec 5)
    (rs1 rd : BitVec 5) :
    generatedNtlProbeAlu (encodeAdmittedShiftIType op shamt rs1 rd) =
      pure none := by
  unfold generatedNtlProbeAlu
  simp only [
    encodeAdmittedShiftIType_ntl_dead,
    Bool.false_eq_true,
    if_false,
  ]

end LeanRV32IM.Functions
