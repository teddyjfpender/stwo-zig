"""RV32IM instruction encoders: the single encoding authority for the corpus."""

from __future__ import annotations


def _mask(value: int, bits: int) -> int:
    return value & ((1 << bits) - 1)


def enc_r(funct7: int, rs2: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    return funct7 << 25 | rs2 << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode


def enc_i(imm: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    return _mask(imm, 12) << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode


def enc_s(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    imm = _mask(imm, 12)
    return (imm >> 5) << 25 | rs2 << 20 | rs1 << 15 | funct3 << 12 | (imm & 0x1F) << 7 | opcode


def enc_b(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    imm = _mask(imm, 13)
    return (
        (imm >> 12) << 31
        | ((imm >> 5) & 0x3F) << 25
        | rs2 << 20
        | rs1 << 15
        | funct3 << 12
        | ((imm >> 1) & 0xF) << 8
        | ((imm >> 11) & 0x1) << 7
        | opcode
    )


def enc_u(imm: int, rd: int, opcode: int) -> int:
    return _mask(imm, 32) & 0xFFFFF000 | rd << 7 | opcode


def enc_j(imm: int, rd: int, opcode: int) -> int:
    imm = _mask(imm, 21)
    return (
        (imm >> 20) << 31
        | ((imm >> 1) & 0x3FF) << 21
        | ((imm >> 11) & 0x1) << 20
        | ((imm >> 12) & 0xFF) << 12
        | rd << 7
        | opcode
    )


def ADDI(rd, rs1, imm):
    return enc_i(imm, rs1, 0x0, rd, 0x13)


def XORI(rd, rs1, imm):
    return enc_i(imm, rs1, 0x4, rd, 0x13)


def ORI(rd, rs1, imm):
    return enc_i(imm, rs1, 0x6, rd, 0x13)


def ANDI(rd, rs1, imm):
    return enc_i(imm, rs1, 0x7, rd, 0x13)


def SLTI(rd, rs1, imm):
    return enc_i(imm, rs1, 0x2, rd, 0x13)


def SLTIU(rd, rs1, imm):
    return enc_i(imm, rs1, 0x3, rd, 0x13)


def SLLI(rd, rs1, sh):
    return enc_i(sh, rs1, 0x1, rd, 0x13)


def SRLI(rd, rs1, sh):
    return enc_i(sh, rs1, 0x5, rd, 0x13)


def SRAI(rd, rs1, sh):
    return enc_i(0x400 | sh, rs1, 0x5, rd, 0x13)


def ADD(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x0, rd, 0x33)


def SUB(rd, rs1, rs2):
    return enc_r(0x20, rs2, rs1, 0x0, rd, 0x33)


def SLL(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x1, rd, 0x33)


def SLT(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x2, rd, 0x33)


def SLTU(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x3, rd, 0x33)


def XOR(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x4, rd, 0x33)


def SRL(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x5, rd, 0x33)


def SRA(rd, rs1, rs2):
    return enc_r(0x20, rs2, rs1, 0x5, rd, 0x33)


def OR(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x6, rd, 0x33)


def AND(rd, rs1, rs2):
    return enc_r(0x00, rs2, rs1, 0x7, rd, 0x33)


def MUL(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x0, rd, 0x33)


def MULH(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x1, rd, 0x33)


def MULHSU(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x2, rd, 0x33)


def MULHU(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x3, rd, 0x33)


def DIV(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x4, rd, 0x33)


def DIVU(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x5, rd, 0x33)


def REM(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x6, rd, 0x33)


def REMU(rd, rs1, rs2):
    return enc_r(0x01, rs2, rs1, 0x7, rd, 0x33)


def LB(rd, rs1, imm):
    return enc_i(imm, rs1, 0x0, rd, 0x03)


def LH(rd, rs1, imm):
    return enc_i(imm, rs1, 0x1, rd, 0x03)


def LW(rd, rs1, imm):
    return enc_i(imm, rs1, 0x2, rd, 0x03)


def LBU(rd, rs1, imm):
    return enc_i(imm, rs1, 0x4, rd, 0x03)


def LHU(rd, rs1, imm):
    return enc_i(imm, rs1, 0x5, rd, 0x03)


def SB(rs2, rs1, imm):
    return enc_s(imm, rs2, rs1, 0x0, 0x23)


def SH(rs2, rs1, imm):
    return enc_s(imm, rs2, rs1, 0x1, 0x23)


def SW(rs2, rs1, imm):
    return enc_s(imm, rs2, rs1, 0x2, 0x23)


def BEQ(rs1, rs2, imm):
    return enc_b(imm, rs2, rs1, 0x0, 0x63)


def BNE(rs1, rs2, imm):
    return enc_b(imm, rs2, rs1, 0x1, 0x63)


def BLT(rs1, rs2, imm):
    return enc_b(imm, rs2, rs1, 0x4, 0x63)


def BGE(rs1, rs2, imm):
    return enc_b(imm, rs2, rs1, 0x5, 0x63)


def BLTU(rs1, rs2, imm):
    return enc_b(imm, rs2, rs1, 0x6, 0x63)


def BGEU(rs1, rs2, imm):
    return enc_b(imm, rs2, rs1, 0x7, 0x63)


def JAL(rd, imm):
    return enc_j(imm, rd, 0x6F)


def JALR(rd, rs1, imm):
    return enc_i(imm, rs1, 0x0, rd, 0x67)


def LUI(rd, imm):
    return enc_u(imm, rd, 0x37)


def AUIPC(rd, imm):
    return enc_u(imm, rd, 0x17)


def FENCE(pred=0xF, succ=0xF, fm=0, rs1=0, rd=0):
    if any(not 0 <= value <= limit for value, limit in (
        (pred, 0xF),
        (succ, 0xF),
        (fm, 0xF),
        (rs1, 0x1F),
        (rd, 0x1F),
    )):
        raise ValueError("FENCE fields exceed their architectural encoding width")
    immediate = fm << 8 | pred << 4 | succ
    return enc_i(immediate, rs1, 0, rd, 0x0F)


def ECALL():
    return 0x0000_0073
