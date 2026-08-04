import Composition
import RiscvRefinement.Bridge.DecodeTeamA
import RiscvRefinement.Bridge.DecodeBranches

set_option maxHeartbeats 2_000_000
set_option maxRecDepth 2_000_000

open Sail

namespace LeanRV32IM.Functions

/-!
Kernel-checked exact decoder certificates for the admitted RV32I control-flow
encodings. AUIPC retains the generated landing-pad extension query; the other
control encodings are structurally disjoint from every earlier alias clause.
-/

def encodeAuipcControl
    (imm : BitVec 20)
    (rd : BitVec 5) : BitVec 32 :=
  RiscvRefinement.Decode.encodeAuipc imm rd

def decodedAuipcControl
    (imm : BitVec 20)
    (rd : BitVec 5) : instruction :=
  .UTYPE (imm, .Regidx rd, .AUIPC)

def encodeJalControl
    (imm : BitVec 20)
    (rd : BitVec 5) : BitVec 32 :=
  RiscvRefinement.Decode.encodeJal imm rd

def decodedJalControl
    (imm : BitVec 20)
    (rd : BitVec 5) : instruction :=
  .JAL (RiscvRefinement.Decode.jalImmediate imm, .Regidx rd)

def encodeJalrControl
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : BitVec 32 :=
  RiscvRefinement.Decode.encodeJalr imm rs1 rd

def decodedJalrControl
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) : instruction :=
  .JALR (imm, .Regidx rs1, .Regidx rd)

def generatedBranchOp :
    RiscvRefinement.Decode.BranchKind → bop
  | .beq => .BEQ
  | .bne => .BNE
  | .blt => .BLT
  | .bge => .BGE
  | .bltu => .BLTU
  | .bgeu => .BGEU

def encodeBranchControl
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) : BitVec 32 :=
  RiscvRefinement.Decode.encodeBranch kind imm rs2 rs1

def decodedBranchControl
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) : instruction :=
  .BTYPE
    (RiscvRefinement.Decode.branchImmediate imm,
      .Regidx rs2,
      .Regidx rs1,
      generatedBranchOp kind)

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

private theorem control_not_zicbop_reduced
    (word : BitVec 32)
    (opcode : BitVec 7)
    (opcodeField :
      Sail.BitVec.extractLsb word 6 0 = opcode)
    (different : opcode ≠ (0b0010011#7 : BitVec 7)) :
    (encdec_cbop_zicbop_backwards_matches
          (Sail.BitVec.extractLsb word 24 20) &&
        Sail.BitVec.extractLsb word 14 0 ==
          (0b110000000010011#15 : BitVec 15)) = false := by
  apply Bool.eq_false_iff.mpr
  intro matched
  simp only [Bool.and_eq_true, beq_iff_eq] at matched
  have lowSeven :
      Sail.BitVec.extractLsb word 6 0 =
        (0b0010011#7 : BitVec 7) := by
    have nested := congrArg
      (fun value : BitVec 15 => BitVec.extractLsb' 0 7 value)
      matched.2
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using nested
  exact different (opcodeField.symm.trans lowSeven)

private theorem control_not_ntl
    (word : BitVec 32)
    (opcode : BitVec 7)
    (opcodeField :
      Sail.BitVec.extractLsb word 6 0 = opcode)
    (different : opcode ≠ (0b0110011#7 : BitVec 7)) :
    ((let mapping : BitVec 5 :=
        Sail.BitVec.extractLsb word 24 20
      encdec_ntl_backwards_matches mapping &&
        (Sail.BitVec.extractLsb word 31 25 ==
            (0b0000000#7 : BitVec 7) &&
          Sail.BitVec.extractLsb word 19 0 ==
            (0x00033#20 : BitVec 20))) : Bool) =
      false := by
  apply Bool.eq_false_iff.mpr
  intro matched
  simp only [Bool.and_eq_true, beq_iff_eq] at matched
  have lowSeven :
      Sail.BitVec.extractLsb word 6 0 =
        (0b0110011#7 : BitVec 7) := by
    have nested := congrArg
      (fun value : BitVec 20 => BitVec.extractLsb' 0 7 value)
      matched.2.2
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using nested
  exact different (opcodeField.symm.trans lowSeven)

private theorem control_not_pause
    (word : BitVec 32)
    (opcode : BitVec 7)
    (opcodeField :
      Sail.BitVec.extractLsb word 6 0 = opcode)
    (different : opcode ≠ (0b0001111#7 : BitVec 7)) :
    (word == (0x0100000F#32 : BitVec 32)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 32 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb word 6 0 =
        (0b0001111#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  exact different (opcodeField.symm.trans concrete)

private theorem control_not_lpad
    (word : BitVec 32)
    (opcode : BitVec 7)
    (opcodeField :
      Sail.BitVec.extractLsb word 6 0 = opcode)
    (different : opcode ≠ (0b0010111#7 : BitVec 7)) :
    (Sail.BitVec.extractLsb word 11 0 ==
      (0x017#12 : BitVec 12)) = false := by
  apply beq_eq_false_iff_ne.mpr
  intro equality
  have lowSeven := congrArg
    (fun value : BitVec 12 => BitVec.extractLsb' 0 7 value)
    equality
  have concrete :
      Sail.BitVec.extractLsb word 6 0 =
        (0b0010111#7 : BitVec 7) := by
    simpa [Sail.BitVec.extractLsb, BitVec.extractLsb] using lowSeven
  exact different (opcodeField.symm.trans concrete)

private theorem encodeAuipcControl_imm
    (imm : BitVec 20) (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAuipcControl imm rd) 31 12 = imm := by
  have canonical :=
    (RiscvRefinement.Decode.encode_auipc_is_canonical imm rd).2.1
  simpa only [
    encodeAuipcControl,
    RiscvRefinement.Decode.decodeLuiImmediate,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeAuipcControl_rd
    (imm : BitVec 20) (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAuipcControl imm rd) 11 7 = rd := by
  have canonical :=
    (RiscvRefinement.Decode.encode_auipc_is_canonical imm rd).2.2
  simpa [
    encodeAuipcControl,
    RiscvRefinement.Decode.decodeRd,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeAuipcControl_opcode
    (imm : BitVec 20) (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeAuipcControl imm rd) 6 0 =
      (0b0010111#7 : BitVec 7) := by
  simp only [
    encodeAuipcControl,
    RiscvRefinement.Decode.encodeAuipc,
    RiscvRefinement.Decode.auipcOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encdec_uop_backwards_auipc :
    encdec_uop_backwards (0b0010111#7 : BitVec 7) = pure .AUIPC := by
  rfl

theorem ext_decode_auipc_control
    (imm : BitVec 20)
    (rd : BitVec 5)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false) :
    ext_decode (encodeAuipcControl imm rd) =
      generatedUtypeDecodeProgram (decodedAuipcControl imm rd) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    control_not_zicbop_reduced _ _
      (encodeAuipcControl_opcode imm rd) (by decide),
    control_not_ntl _ _ (encodeAuipcControl_opcode imm rd) (by decide),
    control_not_pause _ _ (encodeAuipcControl_opcode imm rd) (by decide),
    encodeAuipcControl_opcode,
    encodeAuipcControl_imm,
    encodeAuipcControl_rd,
    encdec_reg_backwards_matches_all,
    encdec_reg_backwards_all,
    encdec_uop_backwards_matches,
    encdec_uop_backwards_auipc,
    Bool.and_false,
    Bool.true_and,
    Bool.false_eq_true,
    Bool.and_true,
    if_false,
    if_true,
    pure_bind,
    bind_assoc,
    generatedUtypeDecodePreamble,
    generatedUtypeDecodeProgram,
    decodedAuipcControl,
  ]
  simp [currentlyEnabled, landingPadDisabled]

theorem decode_auipc_control_certificate
    (imm : BitVec 20)
    (rd : BitVec 5)
    (landingPadDisabled :
      hartSupports extension.Ext_Zicfilp = false) :
    GeneratedDecodeCertificate
      (encodeAuipcControl imm rd)
      (decodedAuipcControl imm rd) := by
  constructor
  intro initial final actual outcome
  rw [ext_decode_auipc_control imm rd landingPadDisabled] at outcome
  exact generatedUtypeDecodeProgram_success
    (decodedAuipcControl imm rd) actual initial final outcome

private theorem encodeJalControl_opcode
    (imm : BitVec 20) (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeJalControl imm rd) 6 0 =
      (0b1101111#7 : BitVec 7) := by
  have canonical :=
    (RiscvRefinement.Decode.encode_jal_is_canonical imm rd).1
  simpa [
    RiscvRefinement.Decode.isJal,
    RiscvRefinement.Decode.decodeOpcodeField,
    RiscvRefinement.Decode.jalOpcode,
    encodeJalControl,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeJalControl_rd
    (imm : BitVec 20) (rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeJalControl imm rd) 11 7 = rd := by
  have canonical :=
    (RiscvRefinement.Decode.encode_jal_is_canonical imm rd).2.2
  simpa [
    RiscvRefinement.Decode.decodeRd,
    encodeJalControl,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeJalControl_generated_imm
    (imm : BitVec 20) (rd : BitVec 5) :
    (((Sail.BitVec.extractLsb (encodeJalControl imm rd) 31 31 +++
          Sail.BitVec.extractLsb (encodeJalControl imm rd) 19 12) +++
        Sail.BitVec.extractLsb (encodeJalControl imm rd) 20 20) +++
      Sail.BitVec.extractLsb (encodeJalControl imm rd) 30 21) +++
      (0#1 : BitVec 1) =
        RiscvRefinement.Decode.jalImmediate imm := by
  simp only [
    encodeJalControl,
    RiscvRefinement.Decode.encodeJal,
    RiscvRefinement.Decode.jalImmediate,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  bv_decide

private theorem encdec_uop_backwards_matches_jal_opcode :
    encdec_uop_backwards_matches
      (0b1101111#7 : BitVec 7) = false := by
  decide

private theorem jal_opcode_beq_self :
    ((0b1101111#7 : BitVec 7) ==
      (0b1101111#7 : BitVec 7)) = true := by
  decide

theorem ext_decode_jal_control
    (imm : BitVec 20)
    (rd : BitVec 5) :
    ext_decode (encodeJalControl imm rd) =
      generatedUtypeDecodeProgram (decodedJalControl imm rd) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    control_not_zicbop_reduced _ _
      (encodeJalControl_opcode imm rd) (by decide),
    control_not_ntl _ _ (encodeJalControl_opcode imm rd) (by decide),
    control_not_pause _ _ (encodeJalControl_opcode imm rd) (by decide),
    control_not_lpad _ _ (encodeJalControl_opcode imm rd) (by decide),
    encodeJalControl_opcode,
    encodeJalControl_rd,
    encodeJalControl_generated_imm,
    encdec_reg_backwards_matches_all,
    encdec_reg_backwards_all,
    Bool.true_and,
    Bool.and_false,
    Bool.false_eq_true,
    Bool.and_true,
    if_false,
    pure_bind,
    bind_assoc,
    generatedUtypeDecodePreamble,
    generatedUtypeDecodeProgram,
    decodedJalControl,
  ]
  rw [encdec_uop_backwards_matches_jal_opcode]
  simp only [Bool.false_eq_true, if_false, pure_bind]
  rw [jal_opcode_beq_self]
  simp only [if_true, pure_bind]

theorem decode_jal_control_certificate
    (imm : BitVec 20)
    (rd : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeJalControl imm rd)
      (decodedJalControl imm rd) := by
  constructor
  intro initial final actual outcome
  rw [ext_decode_jal_control imm rd] at outcome
  exact generatedUtypeDecodeProgram_success
    (decodedJalControl imm rd) actual initial final outcome

private theorem encodeJalrControl_opcode
    (imm : BitVec 12) (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 6 0 =
      (0b1100111#7 : BitVec 7) := by
  have canonical :=
    (RiscvRefinement.Decode.encode_jalr_is_canonical imm rs1 rd).1
  have fields :
      Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 6 0 =
          (0b1100111#7 : BitVec 7) ∧
        Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 14 12 =
          (0b000#3 : BitVec 3) := by
    simpa [
      RiscvRefinement.Decode.isJalr,
      RiscvRefinement.Decode.decodeOpcodeField,
      RiscvRefinement.Decode.decodeFunct3,
      RiscvRefinement.Decode.jalrOpcode,
      RiscvRefinement.Decode.funct3Jalr,
      encodeJalrControl,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
    ] using canonical
  exact fields.1

private theorem encodeJalrControl_funct3
    (imm : BitVec 12) (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 14 12 =
      (0b000#3 : BitVec 3) := by
  have canonical :=
    (RiscvRefinement.Decode.encode_jalr_is_canonical imm rs1 rd).1
  have fields :
      Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 6 0 =
          (0b1100111#7 : BitVec 7) ∧
        Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 14 12 =
          (0b000#3 : BitVec 3) := by
    simpa [
      RiscvRefinement.Decode.isJalr,
      RiscvRefinement.Decode.decodeOpcodeField,
      RiscvRefinement.Decode.decodeFunct3,
      RiscvRefinement.Decode.jalrOpcode,
      RiscvRefinement.Decode.funct3Jalr,
      encodeJalrControl,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
    ] using canonical
  exact fields.2

private theorem encodeJalrControl_imm
    (imm : BitVec 12) (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 31 20 = imm := by
  have canonical :=
    (RiscvRefinement.Decode.encode_jalr_is_canonical imm rs1 rd).2.1
  simpa [
    RiscvRefinement.Decode.decodeIImmediate,
    encodeJalrControl,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeJalrControl_rs1
    (imm : BitVec 12) (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 19 15 = rs1 := by
  have canonical :=
    (RiscvRefinement.Decode.encode_jalr_is_canonical imm rs1 rd).2.2.1
  simpa [
    RiscvRefinement.Decode.decodeRs1,
    encodeJalrControl,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeJalrControl_rd
    (imm : BitVec 12) (rs1 rd : BitVec 5) :
    Sail.BitVec.extractLsb (encodeJalrControl imm rs1 rd) 11 7 = rd := by
  have canonical :=
    (RiscvRefinement.Decode.encode_jalr_is_canonical imm rs1 rd).2.2.2
  simpa [
    RiscvRefinement.Decode.decodeRd,
    encodeJalrControl,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem jalr_uop_matches_false :
    encdec_uop_backwards_matches
      (0b1100111#7 : BitVec 7) = false := by
  decide

private theorem jalr_not_jal_opcode :
    ((0b1100111#7 : BitVec 7) ==
      (0b1101111#7 : BitVec 7)) = false := by
  decide

private theorem jalr_funct3_beq_self :
    ((0b000#3 : BitVec 3) == (0b000#3 : BitVec 3)) = true := by
  decide

private theorem jalr_opcode_beq_self :
    ((0b1100111#7 : BitVec 7) ==
      (0b1100111#7 : BitVec 7)) = true := by
  decide

theorem ext_decode_jalr_control
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    ext_decode (encodeJalrControl imm rs1 rd) =
      generatedUtypeDecodeProgram (decodedJalrControl imm rs1 rd) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    control_not_zicbop_reduced _ _
      (encodeJalrControl_opcode imm rs1 rd) (by decide),
    control_not_ntl _ _
      (encodeJalrControl_opcode imm rs1 rd) (by decide),
    control_not_pause _ _
      (encodeJalrControl_opcode imm rs1 rd) (by decide),
    control_not_lpad _ _
      (encodeJalrControl_opcode imm rs1 rd) (by decide),
    encodeJalrControl_opcode,
    encodeJalrControl_funct3,
    encodeJalrControl_imm,
    encodeJalrControl_rs1,
    encodeJalrControl_rd,
    encdec_reg_backwards_matches_all,
    encdec_reg_backwards_all,
    Bool.and_false,
    Bool.true_and,
    Bool.false_eq_true,
    Bool.and_true,
    if_false,
    pure_bind,
    bind_assoc,
    generatedUtypeDecodePreamble,
    generatedUtypeDecodeProgram,
    decodedJalrControl,
  ]
  rw [jalr_uop_matches_false]
  simp only [Bool.false_eq_true, if_false, pure_bind]
  rw [jalr_not_jal_opcode]
  simp only [Bool.false_eq_true, if_false, pure_bind]
  rw [jalr_funct3_beq_self, jalr_opcode_beq_self]
  simp only [Bool.and_true, Bool.true_and, if_true, pure_bind]

theorem decode_jalr_control_certificate
    (imm : BitVec 12)
    (rs1 rd : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeJalrControl imm rs1 rd)
      (decodedJalrControl imm rs1 rd) := by
  constructor
  intro initial final actual outcome
  rw [ext_decode_jalr_control imm rs1 rd] at outcome
  exact generatedUtypeDecodeProgram_success
    (decodedJalrControl imm rs1 rd) actual initial final outcome

private theorem encodeBranchControl_opcode
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeBranchControl kind imm rs2 rs1) 6 0 =
      (0b1100011#7 : BitVec 7) := by
  have canonical :=
    (RiscvRefinement.Decode.encode_branch_is_canonical
      kind imm rs2 rs1).1
  have fields :
      Sail.BitVec.extractLsb
          (encodeBranchControl kind imm rs2 rs1) 6 0 =
          (0b1100011#7 : BitVec 7) ∧
        Sail.BitVec.extractLsb
          (encodeBranchControl kind imm rs2 rs1) 14 12 =
          kind.funct3 := by
    simpa [
      RiscvRefinement.Decode.isBranch,
      RiscvRefinement.Decode.decodeOpcodeField,
      RiscvRefinement.Decode.decodeFunct3,
      RiscvRefinement.Decode.branchOpcode,
      encodeBranchControl,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
    ] using canonical
  exact fields.1

private theorem encodeBranchControl_funct3
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeBranchControl kind imm rs2 rs1) 14 12 =
      kind.funct3 := by
  have canonical :=
    (RiscvRefinement.Decode.encode_branch_is_canonical
      kind imm rs2 rs1).1
  have fields :
      Sail.BitVec.extractLsb
          (encodeBranchControl kind imm rs2 rs1) 6 0 =
          (0b1100011#7 : BitVec 7) ∧
        Sail.BitVec.extractLsb
          (encodeBranchControl kind imm rs2 rs1) 14 12 =
          kind.funct3 := by
    simpa [
      RiscvRefinement.Decode.isBranch,
      RiscvRefinement.Decode.decodeOpcodeField,
      RiscvRefinement.Decode.decodeFunct3,
      RiscvRefinement.Decode.branchOpcode,
      encodeBranchControl,
      Sail.BitVec.extractLsb,
      BitVec.extractLsb,
    ] using canonical
  exact fields.2

private theorem encodeBranchControl_rs2
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeBranchControl kind imm rs2 rs1) 24 20 = rs2 := by
  have canonical :=
    (RiscvRefinement.Decode.encode_branch_is_canonical
      kind imm rs2 rs1).2.2.1
  simpa [
    RiscvRefinement.Decode.decodeRs2,
    encodeBranchControl,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeBranchControl_rs1
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    Sail.BitVec.extractLsb
        (encodeBranchControl kind imm rs2 rs1) 19 15 = rs1 := by
  have canonical :=
    (RiscvRefinement.Decode.encode_branch_is_canonical
      kind imm rs2 rs1).2.2.2
  simpa [
    RiscvRefinement.Decode.decodeRs1,
    encodeBranchControl,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
  ] using canonical

private theorem encodeBranchControl_generated_imm
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    (((Sail.BitVec.extractLsb
          (encodeBranchControl kind imm rs2 rs1) 31 31 +++
        Sail.BitVec.extractLsb
          (encodeBranchControl kind imm rs2 rs1) 7 7) +++
      Sail.BitVec.extractLsb
        (encodeBranchControl kind imm rs2 rs1) 30 25) +++
      Sail.BitVec.extractLsb
        (encodeBranchControl kind imm rs2 rs1) 11 8) +++
      (0#1 : BitVec 1) =
        RiscvRefinement.Decode.branchImmediate imm := by
  simp only [
    encodeBranchControl,
    RiscvRefinement.Decode.encodeBranch,
    RiscvRefinement.Decode.branchImmediate,
    RiscvRefinement.Decode.BranchKind.funct3,
    RiscvRefinement.Decode.branchOpcode,
    Sail.BitVec.extractLsb,
    BitVec.extractLsb,
    BitVec.append_eq,
  ]
  cases kind <;> bv_decide

private theorem encdec_bop_backwards_matches_kind
    (kind : RiscvRefinement.Decode.BranchKind) :
    encdec_bop_backwards_matches kind.funct3 = true := by
  cases kind <;> rfl

private theorem encdec_bop_backwards_kind
    (kind : RiscvRefinement.Decode.BranchKind) :
    encdec_bop_backwards kind.funct3 =
      pure (generatedBranchOp kind) := by
  cases kind <;> rfl

private theorem branch_uop_matches_false :
    encdec_uop_backwards_matches
      (0b1100011#7 : BitVec 7) = false := by
  decide

private theorem branch_not_jal_opcode :
    ((0b1100011#7 : BitVec 7) ==
      (0b1101111#7 : BitVec 7)) = false := by
  decide

private theorem branch_not_jalr_opcode :
    ((0b1100011#7 : BitVec 7) ==
      (0b1100111#7 : BitVec 7)) = false := by
  decide

private theorem branch_opcode_beq_self :
    ((0b1100011#7 : BitVec 7) ==
      (0b1100011#7 : BitVec 7)) = true := by
  decide

private theorem encodeBranchControl_not_zicbop_reduced
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    (encdec_cbop_zicbop_backwards_matches rs2 &&
        Sail.BitVec.extractLsb
          (encodeBranchControl kind imm rs2 rs1) 14 0 ==
          (0b110000000010011#15 : BitVec 15)) = false := by
  simpa only [encodeBranchControl_rs2] using
    control_not_zicbop_reduced
      (encodeBranchControl kind imm rs2 rs1)
      (0b1100011#7 : BitVec 7)
      (encodeBranchControl_opcode kind imm rs2 rs1)
      (by decide)

private theorem encodeBranchControl_not_ntl
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    (encdec_ntl_backwards_matches rs2 &&
        (Sail.BitVec.extractLsb
              (encodeBranchControl kind imm rs2 rs1) 31 25 ==
            (0b0000000#7 : BitVec 7) &&
          Sail.BitVec.extractLsb
              (encodeBranchControl kind imm rs2 rs1) 19 0 ==
            (0x00033#20 : BitVec 20))) = false := by
  simpa only [encodeBranchControl_rs2] using
    control_not_ntl
      (encodeBranchControl kind imm rs2 rs1)
      (0b1100011#7 : BitVec 7)
      (encodeBranchControl_opcode kind imm rs2 rs1)
      (by decide)

theorem ext_decode_branch_control
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    ext_decode (encodeBranchControl kind imm rs2 rs1) =
      generatedUtypeDecodeProgram
        (decodedBranchControl kind imm rs2 rs1) := by
  rw [ext_decode.eq_1, encdec_backwards.eq_def]
  simp only [
    control_not_pause _ _
      (encodeBranchControl_opcode kind imm rs2 rs1) (by decide),
    control_not_lpad _ _
      (encodeBranchControl_opcode kind imm rs2 rs1) (by decide),
    encodeBranchControl_opcode,
    encodeBranchControl_funct3,
    encodeBranchControl_rs2,
    encodeBranchControl_rs1,
    encodeBranchControl_generated_imm,
    encdec_reg_backwards_matches_all,
    encdec_reg_backwards_all,
    encdec_bop_backwards_matches_kind,
    encdec_bop_backwards_kind,
    Bool.and_false,
    Bool.true_and,
    Bool.false_eq_true,
    Bool.and_true,
    if_false,
    pure_bind,
    bind_assoc,
    generatedUtypeDecodePreamble,
    generatedUtypeDecodeProgram,
    decodedBranchControl,
  ]
  rw [
    encodeBranchControl_not_zicbop_reduced,
    encodeBranchControl_not_ntl,
  ]
  simp only [Bool.false_eq_true, if_false, pure_bind]
  rw [branch_uop_matches_false]
  simp only [Bool.false_eq_true, if_false, pure_bind]
  rw [branch_not_jal_opcode]
  simp only [Bool.false_eq_true, if_false, pure_bind]
  rw [branch_not_jalr_opcode]
  simp only [Bool.and_false, Bool.false_eq_true, if_false, pure_bind]
  rw [branch_opcode_beq_self]
  simp only [Bool.and_true, if_true, pure_bind]

theorem decode_branch_control_certificate
    (kind : RiscvRefinement.Decode.BranchKind)
    (imm : BitVec 12)
    (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeBranchControl kind imm rs2 rs1)
      (decodedBranchControl kind imm rs2 rs1) := by
  constructor
  intro initial final actual outcome
  rw [ext_decode_branch_control kind imm rs2 rs1] at outcome
  exact generatedUtypeDecodeProgram_success
    (decodedBranchControl kind imm rs2 rs1)
    actual initial final outcome

theorem decode_beq_control_certificate
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeBranchControl .beq imm rs2 rs1)
      (decodedBranchControl .beq imm rs2 rs1) :=
  decode_branch_control_certificate .beq imm rs2 rs1

theorem decode_bne_control_certificate
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeBranchControl .bne imm rs2 rs1)
      (decodedBranchControl .bne imm rs2 rs1) :=
  decode_branch_control_certificate .bne imm rs2 rs1

theorem decode_blt_control_certificate
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeBranchControl .blt imm rs2 rs1)
      (decodedBranchControl .blt imm rs2 rs1) :=
  decode_branch_control_certificate .blt imm rs2 rs1

theorem decode_bge_control_certificate
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeBranchControl .bge imm rs2 rs1)
      (decodedBranchControl .bge imm rs2 rs1) :=
  decode_branch_control_certificate .bge imm rs2 rs1

theorem decode_bltu_control_certificate
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeBranchControl .bltu imm rs2 rs1)
      (decodedBranchControl .bltu imm rs2 rs1) :=
  decode_branch_control_certificate .bltu imm rs2 rs1

theorem decode_bgeu_control_certificate
    (imm : BitVec 12) (rs2 rs1 : BitVec 5) :
    GeneratedDecodeCertificate
      (encodeBranchControl .bgeu imm rs2 rs1)
      (decodedBranchControl .bgeu imm rs2 rs1) :=
  decode_branch_control_certificate .bgeu imm rs2 rs1

end LeanRV32IM.Functions
