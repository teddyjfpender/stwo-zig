import Composition
import RiscvRefinement.Bridge.DecodeTeamB

set_option maxHeartbeats 1_000_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

/-!
Kernel-checked generated-Sail decoder certificates for the eight admitted
RV32I load/store encodings.  The generic family lemmas retain the generated
validity predicates; the stable concrete wrappers discharge them for the
production selectors.
-/

private theorem encdec_reg_backwards_matches_all
    (index : BitVec 5) :
    encdec_reg_backwards_matches index = true := by
  simp [encdec_reg_backwards_matches, base_E_enabled, not]

private theorem encdec_reg_backwards_all
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

private theorem bool_bit_backwards_matches_all
    (bit : BitVec 1) :
    bool_bit_backwards_matches bit = true := by
  match bit with
  | 0 => rfl
  | 1 => rfl

private theorem width_enc_backwards_matches_all
    (bits : BitVec 2) :
    width_enc_backwards_matches bits = true := by
  match bits with
  | 0b00 => rfl
  | 0b01 => rfl
  | 0b10 => rfl
  | 0b11 => rfl

private theorem encodeLoad_low_opcode
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
      (0b0000011#7 : BitVec 7) := by
  have admitted :=
    (RiscvRefinement.Decode.encode_load_is_canonical
      funct3 imm rs1 rd).1
  have fields := RiscvRefinement.Decode.isLoad_fields admitted
  simpa [
    RiscvRefinement.Decode.decodeOpcodeField,
    RiscvRefinement.Decode.loadOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using fields.1

private theorem encodeLoad_zicbop_suffix_mismatch
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 14 0 ==
      (0b110000000010011#15 : BitVec 15)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 15 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
        (0b0010011#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  have encoded :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
        (0b0000011#7 : BitVec 7) := by
    simp only [
      RiscvRefinement.Decode.encodeLoad,
      RiscvRefinement.Decode.loadOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
  exact (by decide :
    (0b0000011#7 : BitVec 7) ≠ (0b0010011#7 : BitVec 7))
    (encoded.symm.trans concrete)

private theorem encodeLoad_not_ntl
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    ((let word :=
        RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd
      let mapping : BitVec 5 :=
        Sail.BitVec.extractLsb word 24 20
      encdec_ntl_backwards_matches mapping &&
        ((Sail.BitVec.extractLsb word 31 25 ==
            (0b0000000#7 : BitVec 7)) &&
          (Sail.BitVec.extractLsb word 19 0 ==
            (0x00033#20 : BitVec 20)))) : Bool) = false := by
  apply Bool.eq_false_iff.mpr
  intro matched
  simp only [Bool.and_eq_true, beq_iff_eq] at matched
  have lowSeven := congrArg
    (fun value : BitVec 20 => BitVec.extractLsb' 0 7 value)
    matched.2.2
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
        (0b0110011#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  exact (by decide :
    (0b0000011#7 : BitVec 7) ≠ (0b0110011#7 : BitVec 7))
    ((encodeLoad_low_opcode funct3 imm rs1 rd).symm.trans concrete)

private theorem encodeLoad_not_pause
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd ==
      (0x0100000F#32 : BitVec 32)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 32 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
        (0b0001111#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  have encoded :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
        (0b0000011#7 : BitVec 7) := by
    simp only [
      RiscvRefinement.Decode.encodeLoad,
      RiscvRefinement.Decode.loadOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
  exact (by decide :
    (0b0000011#7 : BitVec 7) ≠ (0b0001111#7 : BitVec 7))
    (encoded.symm.trans concrete)

private theorem encodeLoad_not_lpad
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    (Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 11 0 ==
      (0x017#12 : BitVec 12)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 12 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
        (0b0010111#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  exact (by decide :
    (0b0000011#7 : BitVec 7) ≠ (0b0010111#7 : BitVec 7))
    ((encodeLoad_low_opcode funct3 imm rs1 rd).symm.trans concrete)

private theorem encodeLoad_opcode
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 6 0 =
      (0b0000011#7 : BitVec 7) :=
  encodeLoad_low_opcode funct3 imm rs1 rd

private theorem encodeLoad_imm
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 31 20 = imm := by
  simp only [
    RiscvRefinement.Decode.encodeLoad,
    RiscvRefinement.Decode.loadOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeLoad_rs1
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 19 15 = rs1 := by
  simp only [
    RiscvRefinement.Decode.encodeLoad,
    RiscvRefinement.Decode.loadOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeLoad_rd
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 11 7 = rd := by
  simp only [
    RiscvRefinement.Decode.encodeLoad,
    RiscvRefinement.Decode.loadOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeLoad_unsigned_bit
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 14 14 =
      Sail.BitVec.extractLsb funct3 2 2 := by
  simp only [
    RiscvRefinement.Decode.encodeLoad,
    RiscvRefinement.Decode.loadOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeLoad_width_bits
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) 13 12 =
      Sail.BitVec.extractLsb funct3 1 0 := by
  simp only [
    RiscvRefinement.Decode.encodeLoad,
    RiscvRefinement.Decode.loadOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

def decodedLoadMemory
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .LOAD
    (imm,
      .Regidx rs1,
      .Regidx rd,
      bool_bit_backwards (Sail.BitVec.extractLsb funct3 2 2),
      width_enc_backwards (Sail.BitVec.extractLsb funct3 1 0))

theorem ext_decode_load_memory
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (valid :
      valid_load_encdec
          (width_enc_backwards (Sail.BitVec.extractLsb funct3 1 0))
          (bool_bit_backwards (Sail.BitVec.extractLsb funct3 2 2)) = true) :
    ext_decode (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd) =
      generatedUtypeDecodeProgram
        (decodedLoadMemory funct3 imm rs1 rd) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    encodeLoad_zicbop_suffix_mismatch,
    encodeLoad_not_ntl,
    encodeLoad_not_pause,
    encodeLoad_not_lpad,
    encodeLoad_opcode,
    encodeLoad_imm,
    encodeLoad_rs1,
    encodeLoad_rd,
    encodeLoad_unsigned_bit,
    encodeLoad_width_bits,
    encdec_reg_backwards_matches_all,
    encdec_reg_backwards_all,
    bool_bit_backwards_matches_all,
    width_enc_backwards_matches_all,
    encdec_uop_backwards_matches,
    valid,
    generatedUtypeDecodePreamble,
    generatedUtypeDecodeProgram,
    decodedLoadMemory,
    Bool.and_false,
    Bool.false_eq_true,
    if_false,
    if_true,
    pure_bind,
    bind_assoc,
  ]
  simp

theorem decode_load_memory_certificate
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs1 rd : BitVec 5)
    (valid :
      valid_load_encdec
          (width_enc_backwards (Sail.BitVec.extractLsb funct3 1 0))
          (bool_bit_backwards (Sail.BitVec.extractLsb funct3 2 2)) = true) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeLoad imm rs1 funct3 rd)
      (decodedLoadMemory funct3 imm rs1 rd) := by
  constructor
  intro initial final actual outcome
  rw [ext_decode_load_memory funct3 imm rs1 rd valid] at outcome
  exact generatedUtypeDecodeProgram_success
    (decodedLoadMemory funct3 imm rs1 rd) actual initial final outcome

def decodedLbMemory
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .LOAD (imm, .Regidx rs1, .Regidx rd, false, 1)

def decodedLhMemory
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .LOAD (imm, .Regidx rs1, .Regidx rd, false, 2)

def decodedLwMemory
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .LOAD (imm, .Regidx rs1, .Regidx rd, false, 4)

def decodedLbuMemory
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .LOAD (imm, .Regidx rs1, .Regidx rd, true, 1)

def decodedLhuMemory
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .LOAD (imm, .Regidx rs1, .Regidx rd, true, 2)

theorem decode_lb_memory_certificate
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeLb imm rs1 rd)
      (decodedLbMemory imm rs1 rd) := by
  simpa [
    RiscvRefinement.Decode.encodeLb,
    RiscvRefinement.Decode.funct3Lb,
    decodedLoadMemory,
    decodedLbMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using
    decode_load_memory_certificate
      (RiscvRefinement.Decode.funct3Lb) imm rs1 rd (by decide)

theorem decode_lh_memory_certificate
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeLh imm rs1 rd)
      (decodedLhMemory imm rs1 rd) := by
  simpa [
    RiscvRefinement.Decode.encodeLh,
    RiscvRefinement.Decode.funct3Lh,
    decodedLoadMemory,
    decodedLhMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using
    decode_load_memory_certificate
      (RiscvRefinement.Decode.funct3Lh) imm rs1 rd (by decide)

theorem decode_lw_memory_certificate
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeLw imm rs1 rd)
      (decodedLwMemory imm rs1 rd) := by
  simpa [
    RiscvRefinement.Decode.encodeLw,
    RiscvRefinement.Decode.funct3Lw,
    decodedLoadMemory,
    decodedLwMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using
    decode_load_memory_certificate
      (RiscvRefinement.Decode.funct3Lw) imm rs1 rd (by decide)

theorem decode_lbu_memory_certificate
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeLbu imm rs1 rd)
      (decodedLbuMemory imm rs1 rd) := by
  simpa [
    RiscvRefinement.Decode.encodeLbu,
    RiscvRefinement.Decode.funct3Lbu,
    decodedLoadMemory,
    decodedLbuMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using
    decode_load_memory_certificate
      (RiscvRefinement.Decode.funct3Lbu) imm rs1 rd (by decide)

theorem decode_lhu_memory_certificate
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeLhu imm rs1 rd)
      (decodedLhuMemory imm rs1 rd) := by
  simpa [
    RiscvRefinement.Decode.encodeLhu,
    RiscvRefinement.Decode.funct3Lhu,
    decodedLoadMemory,
    decodedLhuMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using
    decode_load_memory_certificate
      (RiscvRefinement.Decode.funct3Lhu) imm rs1 rd (by decide)

private theorem encodeStore_zicbop_suffix_mismatch
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    (Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 14 0 ==
      (0b110000000010011#15 : BitVec 15)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 15 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0010011#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  have encoded :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0100011#7 : BitVec 7) := by
    simp only [
      RiscvRefinement.Decode.encodeStore,
      RiscvRefinement.Decode.storeOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
  exact (by decide :
    (0b0100011#7 : BitVec 7) ≠ (0b0010011#7 : BitVec 7))
    (encoded.symm.trans concrete)

private theorem encodeStore_ntl_suffix_mismatch
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    (Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 19 0 ==
      (0x00033#20 : BitVec 20)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 20 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0110011#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  have encoded :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0100011#7 : BitVec 7) := by
    simp only [
      RiscvRefinement.Decode.encodeStore,
      RiscvRefinement.Decode.storeOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
  exact (by decide :
    (0b0100011#7 : BitVec 7) ≠ (0b0110011#7 : BitVec 7))
    (encoded.symm.trans concrete)

private theorem encodeStore_not_pause
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3 ==
      (0x0100000F#32 : BitVec 32)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 32 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0001111#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  have encoded :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0100011#7 : BitVec 7) := by
    simp only [
      RiscvRefinement.Decode.encodeStore,
      RiscvRefinement.Decode.storeOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
  exact (by decide :
    (0b0100011#7 : BitVec 7) ≠ (0b0001111#7 : BitVec 7))
    (encoded.symm.trans concrete)

private theorem encodeStore_not_lpad
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    (Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 11 0 ==
      (0x017#12 : BitVec 12)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 12 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0010111#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  have encoded :
      Sail.BitVec.extractLsb
          (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
        (0b0100011#7 : BitVec 7) := by
    simp only [
      RiscvRefinement.Decode.encodeStore,
      RiscvRefinement.Decode.storeOpcode,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
      BitVec.append_eq,
    ]
    bv_decide
  exact (by decide :
    (0b0100011#7 : BitVec 7) ≠ (0b0010111#7 : BitVec 7))
    (encoded.symm.trans concrete)

private theorem encodeStore_opcode
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 6 0 =
      (0b0100011#7 : BitVec 7) := by
  simp only [
    RiscvRefinement.Decode.encodeStore,
    RiscvRefinement.Decode.storeOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeStore_rs2
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 24 20 = rs2 := by
  simp only [
    RiscvRefinement.Decode.encodeStore,
    RiscvRefinement.Decode.storeOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeStore_rs1
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 19 15 = rs1 := by
  simp only [
    RiscvRefinement.Decode.encodeStore,
    RiscvRefinement.Decode.storeOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeStore_zero_bit
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 14 14 =
      Sail.BitVec.extractLsb funct3 2 2 := by
  simp only [
    RiscvRefinement.Decode.encodeStore,
    RiscvRefinement.Decode.storeOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeStore_width_bits
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 13 12 =
      Sail.BitVec.extractLsb funct3 1 0 := by
  simp only [
    RiscvRefinement.Decode.encodeStore,
    RiscvRefinement.Decode.storeOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeStore_imm_high
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 31 25 =
      Sail.BitVec.extractLsb imm 11 5 := by
  simp only [
    RiscvRefinement.Decode.encodeStore,
    RiscvRefinement.Decode.storeOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encodeStore_imm_low
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) 11 7 =
      Sail.BitVec.extractLsb imm 4 0 := by
  simp only [
    RiscvRefinement.Decode.encodeStore,
    RiscvRefinement.Decode.storeOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem storeImmediate_reconstruct
    (imm : BitVec 12) :
    Sail.BitVec.extractLsb imm 11 5 +++
        Sail.BitVec.extractLsb imm 4 0 = imm := by
  simp only [Sail.BitVec.extractLsb, BitVec.extractLsb]
  bv_decide

def decodedStoreMemory
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) : instruction :=
  .STORE
    (imm,
      .Regidx rs2,
      .Regidx rs1,
      width_enc_backwards (Sail.BitVec.extractLsb funct3 1 0))

theorem ext_decode_store_memory
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5)
    (zeroBit :
      Sail.BitVec.extractLsb funct3 2 2 = (0#1 : BitVec 1))
    (widthFits :
      ((width_enc_backwards
          (Sail.BitVec.extractLsb funct3 1 0) ≤b xlen_bytes) : Bool) = true) :
    ext_decode (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3) =
      generatedUtypeDecodeProgram
        (decodedStoreMemory funct3 imm rs2 rs1) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    encodeStore_zicbop_suffix_mismatch,
    encodeStore_ntl_suffix_mismatch,
    encodeStore_not_pause,
    encodeStore_not_lpad,
    encodeStore_opcode,
    encodeStore_rs2,
    encodeStore_rs1,
    encodeStore_zero_bit,
    encodeStore_width_bits,
    encodeStore_imm_high,
    encodeStore_imm_low,
    storeImmediate_reconstruct,
    zeroBit,
    widthFits,
    encdec_reg_backwards_matches_all,
    encdec_reg_backwards_all,
    width_enc_backwards_matches_all,
    encdec_uop_backwards_matches,
    generatedUtypeDecodePreamble,
    generatedUtypeDecodeProgram,
    decodedStoreMemory,
    Bool.and_false,
    Bool.false_eq_true,
    if_false,
    if_true,
    pure_bind,
    bind_assoc,
  ]
  simp

theorem decode_store_memory_certificate
    (funct3 : BitVec 3)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5)
    (zeroBit :
      Sail.BitVec.extractLsb funct3 2 2 = (0#1 : BitVec 1))
    (widthFits :
      ((width_enc_backwards
          (Sail.BitVec.extractLsb funct3 1 0) ≤b xlen_bytes) : Bool) = true) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeStore imm rs2 rs1 funct3)
      (decodedStoreMemory funct3 imm rs2 rs1) := by
  constructor
  intro initial final actual outcome
  rw [
    ext_decode_store_memory funct3 imm rs2 rs1 zeroBit widthFits,
  ] at outcome
  exact generatedUtypeDecodeProgram_success
    (decodedStoreMemory funct3 imm rs2 rs1) actual initial final outcome

def decodedSbMemory
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) : instruction :=
  .STORE (imm, .Regidx rs2, .Regidx rs1, 1)

def decodedShMemory
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) : instruction :=
  .STORE (imm, .Regidx rs2, .Regidx rs1, 2)

def decodedSwMemory
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) : instruction :=
  .STORE (imm, .Regidx rs2, .Regidx rs1, 4)

theorem decode_sb_memory_certificate
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeSb imm rs2 rs1)
      (decodedSbMemory imm rs2 rs1) := by
  simpa [
    RiscvRefinement.Decode.encodeSb,
    RiscvRefinement.Decode.funct3Sb,
    decodedStoreMemory,
    decodedSbMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    xlen_bytes,
  ] using
    decode_store_memory_certificate
      (RiscvRefinement.Decode.funct3Sb) imm rs2 rs1 (by decide) (by decide)

theorem decode_sh_memory_certificate
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeSh imm rs2 rs1)
      (decodedShMemory imm rs2 rs1) := by
  simpa [
    RiscvRefinement.Decode.encodeSh,
    RiscvRefinement.Decode.funct3Sh,
    decodedStoreMemory,
    decodedShMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    xlen_bytes,
  ] using
    decode_store_memory_certificate
      (RiscvRefinement.Decode.funct3Sh) imm rs2 rs1 (by decide) (by decide)

theorem decode_sw_memory_certificate
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (RiscvRefinement.Decode.encodeSw imm rs2 rs1)
      (decodedSwMemory imm rs2 rs1) := by
  simpa [
    RiscvRefinement.Decode.encodeSw,
    RiscvRefinement.Decode.funct3Sw,
    decodedStoreMemory,
    decodedSwMemory,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    xlen_bytes,
  ] using
    decode_store_memory_certificate
      (RiscvRefinement.Decode.funct3Sw) imm rs2 rs1 (by decide) (by decide)

end LeanRV32IM.Functions
