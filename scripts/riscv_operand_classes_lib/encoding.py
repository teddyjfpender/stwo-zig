"""RV32IM instruction encoding and field decoding for operand-class cases.

Encoders build the case bodies the pinned Sail model executes; the field
decoder classifies retirements when the audit measures an existing corpus.
Neither is a semantic authority: every encoded word is echoed back by Sail
with its decoded `rd`/`rs*` register indices asserted against the intent,
and every architectural result in the committed corpus is Sail's, so an
encoder bug surfaces as a loud generation failure rather than as a case
that silently tests something else.
"""

from __future__ import annotations

MASK32 = 0xFFFF_FFFF


class EncodingError(ValueError):
    """An instruction field is outside its encodable range."""


def _check_reg(reg: int, label: str) -> int:
    if not 0 <= reg <= 31:
        raise EncodingError(f"{label} must be a register index, found {reg}")
    return reg


def _check_signed(value: int, bits: int, label: str) -> int:
    bound = 1 << (bits - 1)
    if not -bound <= value < bound:
        raise EncodingError(f"{label} must fit in {bits} signed bits, found {value}")
    return value & ((1 << bits) - 1)


def r_type(opcode: int, funct3: int, funct7: int, rd: int, rs1: int, rs2: int) -> int:
    return (
        (funct7 << 25)
        | (_check_reg(rs2, "rs2") << 20)
        | (_check_reg(rs1, "rs1") << 15)
        | (funct3 << 12)
        | (_check_reg(rd, "rd") << 7)
        | opcode
    )


def i_type(opcode: int, funct3: int, rd: int, rs1: int, imm: int) -> int:
    return (
        (_check_signed(imm, 12, "imm") << 20)
        | (_check_reg(rs1, "rs1") << 15)
        | (funct3 << 12)
        | (_check_reg(rd, "rd") << 7)
        | opcode
    )


def s_type(opcode: int, funct3: int, rs1: int, rs2: int, imm: int) -> int:
    encoded = _check_signed(imm, 12, "imm")
    return (
        ((encoded >> 5) << 25)
        | (_check_reg(rs2, "rs2") << 20)
        | (_check_reg(rs1, "rs1") << 15)
        | (funct3 << 12)
        | ((encoded & 0x1F) << 7)
        | opcode
    )


def b_type(funct3: int, rs1: int, rs2: int, offset: int) -> int:
    if offset % 2:
        raise EncodingError(f"branch offset must be even, found {offset}")
    encoded = _check_signed(offset, 13, "offset")
    return (
        ((encoded >> 12) << 31)
        | (((encoded >> 5) & 0x3F) << 25)
        | (_check_reg(rs2, "rs2") << 20)
        | (_check_reg(rs1, "rs1") << 15)
        | (funct3 << 12)
        | (((encoded >> 1) & 0xF) << 8)
        | (((encoded >> 11) & 1) << 7)
        | 0x63
    )


def u_type(opcode: int, rd: int, imm20: int) -> int:
    if not 0 <= imm20 <= 0xFFFFF:
        raise EncodingError(f"imm20 must be 20 unsigned bits, found {imm20}")
    return (imm20 << 12) | (_check_reg(rd, "rd") << 7) | opcode


def jal(rd: int, offset: int) -> int:
    if offset % 2:
        raise EncodingError(f"jump offset must be even, found {offset}")
    encoded = _check_signed(offset, 21, "offset")
    return (
        ((encoded >> 20) << 31)
        | (((encoded >> 1) & 0x3FF) << 21)
        | (((encoded >> 11) & 1) << 20)
        | (((encoded >> 12) & 0xFF) << 12)
        | (_check_reg(rd, "rd") << 7)
        | 0x6F
    )


# R-type OP encodings: mnemonic -> (funct3, funct7).
_OP_R = {
    "add": (0b000, 0b0000000),
    "sub": (0b000, 0b0100000),
    "sll": (0b001, 0b0000000),
    "slt": (0b010, 0b0000000),
    "sltu": (0b011, 0b0000000),
    "xor": (0b100, 0b0000000),
    "srl": (0b101, 0b0000000),
    "sra": (0b101, 0b0100000),
    "or": (0b110, 0b0000000),
    "and": (0b111, 0b0000000),
    "mul": (0b000, 0b0000001),
    "mulh": (0b001, 0b0000001),
    "mulhsu": (0b010, 0b0000001),
    "mulhu": (0b011, 0b0000001),
    "div": (0b100, 0b0000001),
    "divu": (0b101, 0b0000001),
    "rem": (0b110, 0b0000001),
    "remu": (0b111, 0b0000001),
}

_OP_IMM = {
    "addi": 0b000,
    "slti": 0b010,
    "sltiu": 0b011,
    "xori": 0b100,
    "ori": 0b110,
    "andi": 0b111,
}

_SHIFT_IMM = {"slli": (0b001, 0), "srli": (0b101, 0), "srai": (0b101, 0b0100000)}
_LOAD = {"lb": 0b000, "lh": 0b001, "lw": 0b010, "lbu": 0b100, "lhu": 0b101}
_STORE = {"sb": 0b000, "sh": 0b001, "sw": 0b010}
_BRANCH = {"beq": 0b000, "bne": 0b001, "blt": 0b100, "bge": 0b101, "bltu": 0b110, "bgeu": 0b111}

FENCE_WORD = 0x0FF0_000F


def op(mnemonic: str, rd: int, rs1: int, rs2: int) -> int:
    funct3, funct7 = _OP_R[mnemonic]
    return r_type(0x33, funct3, funct7, rd, rs1, rs2)


def op_imm(mnemonic: str, rd: int, rs1: int, imm: int) -> int:
    return i_type(0x13, _OP_IMM[mnemonic], rd, rs1, imm)


def shift_imm(mnemonic: str, rd: int, rs1: int, shamt: int) -> int:
    if not 0 <= shamt <= 31:
        raise EncodingError(f"shamt must be 0..31, found {shamt}")
    funct3, funct7 = _SHIFT_IMM[mnemonic]
    return r_type(0x13, funct3, funct7, rd, rs1, shamt)


def load(mnemonic: str, rd: int, rs1: int, imm: int) -> int:
    return i_type(0x03, _LOAD[mnemonic], rd, rs1, imm)


def store(mnemonic: str, rs1: int, rs2: int, imm: int) -> int:
    return s_type(0x23, _STORE[mnemonic], rs1, rs2, imm)


def branch(mnemonic: str, rs1: int, rs2: int, offset: int) -> int:
    return b_type(_BRANCH[mnemonic], rs1, rs2, offset)


def lui(rd: int, imm20: int) -> int:
    return u_type(0x37, rd, imm20)


def auipc(rd: int, imm20: int) -> int:
    return u_type(0x17, rd, imm20)


def jalr(rd: int, rs1: int, imm: int) -> int:
    return i_type(0x67, 0b000, rd, rs1, imm)


def materialize(reg: int, value: int) -> list[int]:
    """Load an arbitrary u32 into `reg` with the minimal LUI/ADDI pair.

    The standard split: ADDI sign-extends its 12-bit immediate, so the upper
    part must absorb the sign of the lower part, hence the `+ 0x800` before
    truncation. Exactness over all of u32 is asserted rather than assumed.
    """
    value &= MASK32
    signed = value - (1 << 32) if value >= (1 << 31) else value
    if -2048 <= signed < 2048:
        return [op_imm("addi", reg, 0, signed)]
    upper = ((value + 0x800) >> 12) & 0xFFFFF
    low = value - ((upper << 12) & MASK32)
    if low >= (1 << 31):
        low -= 1 << 32
    composed = ((upper << 12) + low) & MASK32
    if composed != value:
        raise EncodingError(f"materialize({value:#x}) composed {composed:#x}")
    if low == 0:
        return [lui(reg, upper)]
    return [lui(reg, upper), op_imm("addi", reg, reg, low)]


# ---------------------------------------------------------------------------
# Field decoding, for classifying retirements during the audit
# ---------------------------------------------------------------------------


def sign_extend(value: int, bits: int) -> int:
    value &= (1 << bits) - 1
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _decode_imm(word: int, kind: str) -> int:
    if kind == "i":
        return sign_extend(word >> 20, 12)
    if kind == "s":
        return sign_extend(((word >> 25) << 5) | ((word >> 7) & 0x1F), 12)
    if kind == "b":
        raw = (
            (((word >> 31) & 1) << 12)
            | (((word >> 7) & 1) << 11)
            | (((word >> 25) & 0x3F) << 5)
            | (((word >> 8) & 0xF) << 1)
        )
        return sign_extend(raw, 13)
    if kind == "u":
        return word & 0xFFFF_F000
    raw = (
        (((word >> 31) & 1) << 20)
        | (((word >> 12) & 0xFF) << 12)
        | (((word >> 20) & 1) << 11)
        | (((word >> 21) & 0x3FF) << 1)
    )
    return sign_extend(raw, 21)


_R_BY_FUNCT = {(f3, f7): name for name, (f3, f7) in _OP_R.items()}
_IMM_BY_FUNCT = {f3: name for name, f3 in _OP_IMM.items()}
_LOAD_BY_FUNCT = {f3: name for name, f3 in _LOAD.items()}
_STORE_BY_FUNCT = {f3: name for name, f3 in _STORE.items()}
_BRANCH_BY_FUNCT = {f3: name for name, f3 in _BRANCH.items()}


def decode(word: int) -> dict | None:
    """Mnemonic and fields of one profile word, or None when outside RV32IM.

    Used only to bucket retirements for coverage measurement; acceptance and
    semantics stay with the pinned Sail model and the production decoder.
    """
    opcode = word & 0x7F
    rd = (word >> 7) & 0x1F
    funct3 = (word >> 12) & 0x7
    rs1 = (word >> 15) & 0x1F
    rs2 = (word >> 20) & 0x1F
    funct7 = word >> 25
    fields = {"rd": rd, "rs1": rs1, "rs2": rs2, "imm": 0}
    if opcode == 0x33:
        name = _R_BY_FUNCT.get((funct3, funct7))
        return {"op": name, **fields} if name else None
    if opcode == 0x13:
        if funct3 in (0b001, 0b101):
            for name, (f3, f7) in _SHIFT_IMM.items():
                if f3 == funct3 and f7 == funct7:
                    return {"op": name, **fields, "imm": rs2}
            return None
        return {"op": _IMM_BY_FUNCT[funct3], **fields, "imm": _decode_imm(word, "i")}
    if opcode == 0x03:
        name = _LOAD_BY_FUNCT.get(funct3)
        return {"op": name, **fields, "imm": _decode_imm(word, "i")} if name else None
    if opcode == 0x23:
        name = _STORE_BY_FUNCT.get(funct3)
        return {"op": name, **fields, "imm": _decode_imm(word, "s")} if name else None
    if opcode == 0x63:
        name = _BRANCH_BY_FUNCT.get(funct3)
        return {"op": name, **fields, "imm": _decode_imm(word, "b")} if name else None
    if opcode == 0x37:
        return {"op": "lui", **fields, "imm": _decode_imm(word, "u")}
    if opcode == 0x17:
        return {"op": "auipc", **fields, "imm": _decode_imm(word, "u")}
    if opcode == 0x6F:
        return {"op": "jal", **fields, "imm": _decode_imm(word, "j")}
    if opcode == 0x67 and funct3 == 0:
        return {"op": "jalr", **fields, "imm": _decode_imm(word, "i")}
    if opcode == 0x0F and funct3 == 0:
        return {"op": "fence", **fields}
    return None
