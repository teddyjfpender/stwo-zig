"""The RV32IM operand-class enumeration: which operands matter, per opcode.

Coverage until now picked operand words by hand, one clever probe per bug.
This module enumerates the operand classes the ISA admits and the AIR's
structure distinguishes, so tests can ask for "the sign-boundary cases of
SRA" instead of transcribing a word. Each class is (a) a predicate over an
observed retirement, used both to certify the generated case and to measure
what an existing corpus touches, and (b) one or more concrete cases: a
self-contained instruction body the pinned Sail model executes to produce
the committed architectural expectation.

Where the classes come from -- each is derived, not guessed:

* The AIR commits words as four 8-bit limbs with explicit carry/borrow
  witnesses, so mid-word carry chains (`carry_ripple`, `borrow_ripple`,
  `address_carry`) are distinct witness shapes, not just big numbers.
* Sign handling lives in limb 3 (`>= 128`) with dedicated sign columns:
  bit-31 boundaries (`sign_bit_operand`, `max_positive`, `sign_crossing`,
  the shift sign-fill classes, load sign extension) each activate or
  deactivate those columns.
* Shifts decompose into a limb shift and a bit shift with a bit-multiplier
  witness, so amounts 0/1/7/8/31 select structurally different rows
  (identity, bit-only, bit-crossing, limb-aligned, maximal), and the ISA
  reads only rs2[4:0] for register shifts (`shift_mod32_wrap`).
* The M extension defines division by zero, signed overflow, and
  round-toward-zero sign cases as explicit results (RISC-V unprivileged
  spec 13.2); the div AIR additionally proves `r < c` by a high-to-low
  limb scan, so the limb at which remainder and divisor first differ is a
  class of its own (`div_scan_limb*`).
* Loads and stores decompose into byte lanes with partial-word
  recomposition, so each legal alignment lane and each width-sign
  boundary is a class; misaligned accesses are NOT classes because the
  profile rejects them before retirement (`rv32im-sail-profile.json`).
* The register file hardwires x0 and the AIR gates destination writes on
  `rd != 0`, so x0-as-source, x0-as-destination, `rd == rs1`, and
  `rs1 == rs2` are access-pattern classes the ISA admits and the operand
  values alone cannot express.
* Branch/jump targets are pc-relative with sign-extended immediates, so
  taken/not-taken at each comparison boundary, backward-taken offsets, the
  JALR bit-0 clear, and the AUIPC wrap past 2^32 are target-arithmetic
  classes.

Beyond the task brief's list this adds: x0 discard/source classes, same-
source and read-write-overlap register patterns, mid-word carry/borrow
ripple, the div remainder-scan limb positions, MULHSU's asymmetric signed
by unsigned case, MUL low-word wraparound, load/store address-arithmetic
carries, the JALR LSB clear and base-overwrite, backward-taken control
flow, AUIPC pc wraparound, and the FENCE no-op retirement -- each earned
by one of the structural facts above.

Register discipline: bodies write only x6, x7, x10, x28-x31 -- never x1-x5,
which the guest ELF fixture prologue/epilogue owns -- and never read a
register they did not first materialize, so every case is position- and
environment-independent apart from explicitly pc-relative expectations.
"""

from __future__ import annotations

import dataclasses

from . import encoding

MASK32 = 0xFFFF_FFFF

RS1, RS2, RD = 6, 7, 10
MARK, MARK2, ADDR, VAL = 28, 29, 30, 31
WRITABLE = {0, RS1, RS2, RD, MARK, MARK2, ADDR, VAL}

# Scratch memory inside the guest fixture's stack region [0x1FFC00, 0x200000):
# legal sparse RW memory for the runner and ordinary main memory for Sail.
SCRATCH = 0x001F_FC00

# Reference operand words. P* have bit 31 clear, N* have it set; both carry
# distinct bytes so a limb permutation cannot go unnoticed.
P_ODD = 0x4C3A_55B5
N_ODD = 0xA55A_3CC7
P_WORD = 0x7654_3211
N_WORD = 0x8ABC_DEF1
SIGN_LANES = 0x807F_FF80  # byte lanes [80, FF, 7F, 80], halves [FF80, 807F]
CLEAR_LANES = 0x7FFF_7F00  # halves [7F00, 7FFF]: width-sign bits clear


@dataclasses.dataclass(frozen=True)
class CaseSpec:
    """One executable case: a body, the instruction under test, one class."""

    name: str
    op: str
    tag: str
    body: tuple[int, ...]
    under_test: int
    # Body index of a follow-up retirement whose rd value the corpus also
    # pins (the read-back of a store). None for single-check cases.
    readback: int | None = None


@dataclasses.dataclass(frozen=True)
class Obs:
    """One observed retirement, as the class predicates see it."""

    op: str
    rs1: int
    rs2: int
    imm: int
    rd_idx: int
    rs1_idx: int
    rs2_idx: int
    pc: int
    next_pc: int
    mem_addr: int
    mem_rmask: int
    mem_wmask: int
    mem_rdata: int

    def op2(self) -> int:
        """Second data operand: rs2 wherever the op reads one (R-type,
        branches, stores), the immediate as u32 otherwise."""
        if self.op in READS_RS2:
            return self.rs2
        return self.imm & MASK32

    def shamt(self) -> int:
        if self.op in ("slli", "srli", "srai"):
            return self.imm & 31
        return self.rs2 & 31

    def taken(self) -> bool:
        return self.next_pc != (self.pc + 4) & MASK32


R_TYPE_OPS = frozenset(encoding._OP_R)
READS_RS1 = R_TYPE_OPS | frozenset(encoding._OP_IMM) | frozenset(encoding._SHIFT_IMM) | \
    frozenset(encoding._LOAD) | frozenset(encoding._STORE) | frozenset(encoding._BRANCH) | \
    frozenset(("jalr",))
READS_RS2 = R_TYPE_OPS | frozenset(encoding._STORE) | frozenset(encoding._BRANCH)
WRITES_RD = READS_RS1 - frozenset(encoding._STORE) - frozenset(encoding._BRANCH) | \
    frozenset(("lui", "auipc", "jal"))


def _sgn(value: int) -> int:
    return value - (1 << 32) if value & 0x8000_0000 else value


def _limbs(value: int) -> list[int]:
    return [(value >> (8 * k)) & 0xFF for k in range(4)]


def _unsigned_scan_limb(dividend: int, divisor: int) -> int | None:
    """Highest limb at which `dividend % divisor` and the divisor differ.

    That limb is where the div AIR's high-to-low `r < c` scan closes, so it
    indexes structurally different remainder-bound rows.
    """
    if divisor == 0:
        return None
    r, c = _limbs(dividend % divisor), _limbs(divisor)
    for k in (3, 2, 1, 0):
        if r[k] != c[k]:
            return k
    return None


def _signed_overflow_add(a: int, b: int) -> bool:
    result = (a + b) & MASK32
    return bool((~(a ^ b)) & (a ^ result) & 0x8000_0000)


def _signed_overflow_sub(a: int, b: int) -> bool:
    result = (a - b) & MASK32
    return bool((a ^ b) & (a ^ result) & 0x8000_0000)


def _crosses_byte_boundary(base: int, imm: int) -> bool:
    return (base & 0xFFFF_FF00) != ((base + imm) & MASK32 & 0xFFFF_FF00)


# ---------------------------------------------------------------------------
# Class predicates: the meaning of each tag, shared by generation (which
# asserts every case satisfies its own tag) and by the corpus audit (which
# measures what existing tests touch).
# ---------------------------------------------------------------------------

PREDICATES = {
    "zero_operand": lambda o: o.rs1 == 0 or o.op2() == 0,
    "one_operand": lambda o: o.rs1 == 1 or o.op2() == 1,
    "all_ones_operand": lambda o: MASK32 in (o.rs1, o.op2()),
    "sign_bit_operand": lambda o: 0x8000_0000 in (o.rs1, o.op2()),
    "max_positive_operand": lambda o: 0x7FFF_FFFF in (o.rs1, o.op2()),
    "carry_ripple": lambda o: (o.rs1 & 0xFF_FFFF) + (o.op2() & 0xFF_FFFF) > 0xFF_FFFF,
    "borrow_ripple": lambda o: (o.rs1 & 0xFF_FFFF) < (o.op2() & 0xFF_FFFF),
    "sign_crossing_add": lambda o: _signed_overflow_add(o.rs1, o.op2()),
    "sign_crossing_sub": lambda o: _signed_overflow_sub(o.rs1, o.op2()),
    "bitwise_complement_pattern": lambda o: (o.rs1 ^ o.op2()) == MASK32,
    "bitwise_equal_operands": lambda o: o.rs1 == o.op2(),
    "bitwise_byte_sign_edge": lambda o: any(
        limb in (0x7F, 0x80) for limb in _limbs(o.rs1) + _limbs(o.op2())
    ),
    "imm_min": lambda o: o.imm == -2048,
    "imm_max": lambda o: o.imm == 2047,
    "imm_zero": lambda o: o.imm == 0,
    "imm_minus_one": lambda o: o.imm == -1,
    "same_source_registers": lambda o: o.rs1_idx == o.rs2_idx and o.rs1_idx != 0,
    "rd_equals_rs1": lambda o: o.rd_idx == o.rs1_idx and o.rd_idx != 0,
    "rs_x0_source": lambda o: (o.op in READS_RS1 and o.rs1_idx == 0)
    or (o.op in READS_RS2 and o.rs2_idx == 0),
    "rd_x0_discard": lambda o: o.op in WRITES_RD and o.rd_idx == 0,
    "shift_zero": lambda o: o.shamt() == 0,
    "shift_one": lambda o: o.shamt() == 1,
    "shift_seven": lambda o: o.shamt() == 7,
    "shift_eight": lambda o: o.shamt() == 8,
    "shift_thirty_one": lambda o: o.shamt() == 31,
    "shift_sign_operand": lambda o: bool(o.rs1 & 0x8000_0000),
    "shift_mod32_wrap": lambda o: o.rs2 > 31,
    "cmp_equal_operands": lambda o: o.rs1 == o.op2(),
    "cmp_off_by_one": lambda o: o.rs1 == (o.op2() + 1) & MASK32
    or o.op2() == (o.rs1 + 1) & MASK32,
    "cmp_signed_unsigned_disagree": lambda o: (_sgn(o.rs1) < _sgn(o.op2()))
    != (o.rs1 < o.op2()),
    "cmp_both_negative": lambda o: bool(o.rs1 & o.op2() & 0x8000_0000),
    "sltiu_seqz_idiom": lambda o: o.op == "sltiu" and o.imm == 1,
    "mul_sign_pp": lambda o: not (o.rs1 | o.rs2) & 0x8000_0000
    and o.rs1 > 1 and o.rs2 > 1,
    "mul_sign_pn": lambda o: not o.rs1 & 0x8000_0000 and bool(o.rs2 & 0x8000_0000),
    "mul_sign_np": lambda o: bool(o.rs1 & 0x8000_0000) and not o.rs2 & 0x8000_0000,
    "mul_sign_nn": lambda o: bool(o.rs1 & o.rs2 & 0x8000_0000),
    "mul_all_ones_square": lambda o: o.rs1 == o.rs2 == MASK32,
    "mul_sign_bit_square": lambda o: o.rs1 == o.rs2 == 0x8000_0000,
    "mul_low_word_wrap": lambda o: o.rs1 != 0 and o.rs2 != 0
    and (o.rs1 * o.rs2) & MASK32 == 0,
    "div_by_zero": lambda o: o.rs2 == 0 and o.rs1 != 0,
    "div_zero_by_zero": lambda o: o.rs1 == 0 and o.rs2 == 0,
    "div_signed_overflow": lambda o: o.rs1 == 0x8000_0000 and o.rs2 == MASK32,
    "div_exact": lambda o: o.rs2 != 0 and _div_remainder(o) == 0 and o.rs1 != 0,
    "div_max_remainder": lambda o: o.rs2 != 0
    and _div_remainder(o) == _div_modulus(o) - 1,
    "div_dividend_smaller": lambda o: o.rs2 != 0 and o.rs1 != 0
    and abs(_sgn(o.rs1)) < abs(_sgn(o.rs2))
    if o.op in ("div", "rem")
    else o.rs2 != 0 and 0 < o.rs1 < o.rs2,
    "div_sign_pn": lambda o: not o.rs1 & 0x8000_0000 and bool(o.rs2 & 0x8000_0000)
    and o.rs2 != 0,
    "div_sign_np": lambda o: bool(o.rs1 & 0x8000_0000) and not o.rs2 & 0x8000_0000
    and o.rs2 != 0,
    "div_sign_nn": lambda o: bool(o.rs1 & o.rs2 & 0x8000_0000),
    "div_divisor_one": lambda o: o.rs2 == 1,
    "div_equal_operands": lambda o: o.rs1 == o.rs2 != 0,
    "div_scan_limb0": lambda o: _unsigned_scan_limb(o.rs1, o.rs2) == 0,
    "div_scan_limb1": lambda o: _unsigned_scan_limb(o.rs1, o.rs2) == 1,
    "div_scan_limb2": lambda o: _unsigned_scan_limb(o.rs1, o.rs2) == 2,
    "div_scan_limb3": lambda o: _unsigned_scan_limb(o.rs1, o.rs2) == 3,
    "mem_lane_0": lambda o: o.mem_addr % 4 == 0,
    "mem_lane_1": lambda o: o.mem_addr % 4 == 1,
    "mem_lane_2": lambda o: o.mem_addr % 4 == 2,
    "mem_lane_3": lambda o: o.mem_addr % 4 == 3,
    "load_value_sign_set": lambda o: _load_width_sign(o) is True,
    "load_value_sign_clear": lambda o: _load_width_sign(o) is False,
    "load_value_all_ones": lambda o: _load_raw(o) == _load_width_mask(o) != 0,
    "mem_negative_offset": lambda o: o.imm < 0,
    "mem_address_carry": lambda o: _crosses_byte_boundary(o.rs1, o.imm),
    "store_neighbor_preservation": lambda o: 0 < o.mem_wmask < 0xF,
    "branch_taken": lambda o: o.taken(),
    "branch_not_taken": lambda o: not o.taken(),
    "branch_backward_taken": lambda o: o.taken() and o.imm < 0,
    "branch_offset_negative_not_taken": lambda o: not o.taken() and o.imm < 0,
    "jump_link": lambda o: o.rd_idx != 0,
    "jump_discard_link": lambda o: o.rd_idx == 0,
    "jump_backward": lambda o: o.imm < 0,
    "jalr_lsb_clear": lambda o: (o.rs1 + o.imm) & 1 == 1,
    "upper_imm_zero": lambda o: o.imm == 0,
    "upper_imm_one": lambda o: o.imm == 0x1000,
    "upper_imm_sign_bit": lambda o: o.imm & MASK32 == 0x8000_0000,
    "upper_imm_all_ones": lambda o: o.imm & MASK32 == 0xFFFF_F000,
    "auipc_pc_wrap": lambda o: o.pc + (o.imm & MASK32) > MASK32,
    "fence_nop": lambda o: o.op == "fence",
}


def _div_modulus(o: Obs) -> int:
    return abs(_sgn(o.rs2)) if o.op in ("div", "rem") else o.rs2


def _div_remainder(o: Obs) -> int:
    if o.op in ("div", "rem"):
        return abs(_sgn(o.rs1)) % abs(_sgn(o.rs2)) if o.rs2 else abs(_sgn(o.rs1))
    return o.rs1 % o.rs2 if o.rs2 else o.rs1


def _load_width_mask(o: Obs) -> int:
    return {1: 0xFF, 3: 0xFFFF, 0xF: MASK32}.get(o.mem_rmask, 0)


def _load_raw(o: Obs) -> int:
    return o.mem_rdata & _load_width_mask(o)


def _load_width_sign(o: Obs) -> bool | None:
    """Width-sign bit of the loaded value; None for full-word loads."""
    if o.mem_rmask == 1:
        return bool(o.mem_rdata & 0x80)
    if o.mem_rmask == 3:
        return bool(o.mem_rdata & 0x8000)
    return None


# ---------------------------------------------------------------------------
# Case construction
# ---------------------------------------------------------------------------


def _case(name, op_name, tag, body, under_test, readback=None) -> CaseSpec:
    return CaseSpec(name, op_name, tag, tuple(body), under_test, readback)


def _reg_case(op_name, tag, a, b, *, rd=RD, suffix="") -> CaseSpec:
    body = encoding.materialize(RS1, a) + encoding.materialize(RS2, b)
    body.append(encoding.op(op_name, rd, RS1, RS2))
    return _case(f"{op_name}/{tag}{suffix}", op_name, tag, body, len(body) - 1)


def _imm_case(op_name, tag, a, imm, *, rd=RD, suffix="") -> CaseSpec:
    body = encoding.materialize(RS1, a)
    body.append(encoding.op_imm(op_name, rd, RS1, imm))
    return _case(f"{op_name}/{tag}{suffix}", op_name, tag, body, len(body) - 1)


def _alu_reg_cases() -> list[CaseSpec]:
    cases = []
    for op_name in ("add", "sub", "xor", "or", "and"):
        cases.append(_reg_case(op_name, "zero_operand", P_WORD, 0))
        cases.append(_reg_case(op_name, "all_ones_operand", P_WORD, MASK32))
        cases.append(_reg_case(op_name, "sign_bit_operand", P_WORD, 0x8000_0000))
    for op_name in ("add", "sub"):
        cases.append(_reg_case(op_name, "one_operand", N_WORD, 1))
        cases.append(_reg_case(op_name, "max_positive_operand", 0x7FFF_FFFF, 1))
    cases.append(_reg_case("add", "carry_ripple", 0x00FF_FFFF, 1))
    cases.append(_reg_case("add", "carry_ripple", 0xFFFF_FFFF, 1, suffix="/wrap"))
    cases.append(_reg_case("add", "sign_crossing_add", 0x7FFF_FFFF, 1))
    cases.append(_reg_case("sub", "borrow_ripple", 0, 1))
    cases.append(_reg_case("sub", "borrow_ripple", 0x0100_0000, 1, suffix="/mid"))
    cases.append(_reg_case("sub", "sign_crossing_sub", 0x8000_0000, 1))
    for op_name in ("xor", "or", "and"):
        cases.append(_reg_case(op_name, "bitwise_complement_pattern", 0xAAAA_AAAA, 0x5555_5555))
        cases.append(_reg_case(op_name, "bitwise_byte_sign_edge", 0x7F80_FF00, 0x80FF_007F))
    # Access-pattern classes on one representative arithmetic opcode each.
    body = encoding.materialize(RS1, P_WORD) + [encoding.op("add", RD, RS1, RS1)]
    cases.append(_case("add/same_source_registers", "add", "same_source_registers", body, len(body) - 1))
    body = encoding.materialize(RS1, N_WORD) + [encoding.op("xor", RD, RS1, RS1)]
    cases.append(_case("xor/bitwise_equal_operands", "xor", "bitwise_equal_operands", body, len(body) - 1))
    body = encoding.materialize(RS1, P_WORD) + encoding.materialize(RS2, 0x0101_0101)
    body.append(encoding.op("add", RS1, RS1, RS2))
    cases.append(_case("add/rd_equals_rs1", "add", "rd_equals_rs1", body, len(body) - 1))
    body = encoding.materialize(RS2, P_WORD) + [encoding.op("sub", RD, 0, RS2)]
    cases.append(_case("sub/rs_x0_source", "sub", "rs_x0_source", body, len(body) - 1))
    cases.append(_reg_case("add", "rd_x0_discard", P_WORD, N_WORD, rd=0))
    return cases


def _alu_imm_cases() -> list[CaseSpec]:
    cases = []
    for op_name in ("addi", "xori", "ori", "andi"):
        cases.append(_imm_case(op_name, "imm_min", P_WORD, -2048))
        cases.append(_imm_case(op_name, "imm_minus_one", P_WORD, -1))
        cases.append(_imm_case(op_name, "imm_zero", N_WORD, 0))
        cases.append(_imm_case(op_name, "imm_max", N_WORD, 2047))
    cases.append(_imm_case("addi", "carry_ripple", 0x00FF_FFFF, 1))
    cases.append(_imm_case("addi", "sign_crossing_add", 0x7FFF_FFFF, 1))
    cases.append(_imm_case("addi", "borrow_ripple", 0, -1))
    cases.append(_imm_case("addi", "rd_x0_discard", P_WORD, 42, rd=0))
    body = [encoding.op_imm("addi", RD, 0, -2048)]
    cases.append(_case("addi/rs_x0_source", "addi", "rs_x0_source", body, 0))
    return cases


def _shift_cases() -> list[CaseSpec]:
    cases = []
    positive_amounts = (
        ("shift_zero", 0),
        ("shift_one", 1),
        ("shift_seven", 7),
        ("shift_eight", 8),
        ("shift_thirty_one", 31),
    )
    negative_amounts = (("shift_one", 1), ("shift_eight", 8), ("shift_thirty_one", 31))
    for op_name in ("sll", "srl", "sra"):
        for tag, amount in positive_amounts:
            cases.append(_reg_case(op_name, tag, P_ODD, amount))
        for tag, amount in negative_amounts:
            body = encoding.materialize(RS1, N_ODD) + encoding.materialize(RS2, amount)
            body.append(encoding.op(op_name, RD, RS1, RS2))
            cases.append(
                _case(f"{op_name}/shift_sign_operand/{tag}", op_name,
                      "shift_sign_operand", body, len(body) - 1)
            )
        for suffix, raw in (("/32", 32), ("/0xffffffe1", 0xFFFF_FFE1)):
            cases.append(_reg_case(op_name, "shift_mod32_wrap", N_ODD, raw, suffix=suffix))
    for op_name in ("slli", "srli", "srai"):
        for tag, amount in positive_amounts:
            body = encoding.materialize(RS1, P_ODD)
            body.append(encoding.shift_imm(op_name, RD, RS1, amount))
            cases.append(_case(f"{op_name}/{tag}", op_name, tag, body, len(body) - 1))
        for tag, amount in negative_amounts:
            body = encoding.materialize(RS1, N_ODD)
            body.append(encoding.shift_imm(op_name, RD, RS1, amount))
            cases.append(
                _case(f"{op_name}/shift_sign_operand/{tag}", op_name,
                      "shift_sign_operand", body, len(body) - 1)
            )
    return cases


def _compare_cases() -> list[CaseSpec]:
    cases = []
    for op_name in ("slt", "sltu"):
        cases.append(_reg_case(op_name, "cmp_equal_operands", P_WORD, P_WORD))
        cases.append(_reg_case(op_name, "cmp_off_by_one", P_WORD, P_WORD + 1))
        cases.append(_reg_case(op_name, "cmp_off_by_one", P_WORD + 1, P_WORD, suffix="/above"))
        cases.append(_reg_case(op_name, "cmp_signed_unsigned_disagree", 0x8000_0000, 1))
        cases.append(_reg_case(op_name, "cmp_signed_unsigned_disagree", 1, 0x8000_0000, suffix="/b"))
        cases.append(_reg_case(op_name, "cmp_both_negative", N_WORD, N_WORD + 8))
    for op_name in ("slti", "sltiu"):
        cases.append(_imm_case(op_name, "imm_min", 0x8000_0000, -2048))
        cases.append(_imm_case(op_name, "imm_minus_one", P_WORD, -1))
        cases.append(_imm_case(op_name, "imm_max", 2047, 2047))
        cases.append(_imm_case(op_name, "cmp_equal_operands", 100, 100))
    cases.append(_imm_case("sltiu", "sltiu_seqz_idiom", 0, 1))
    cases.append(_imm_case("sltiu", "sltiu_seqz_idiom", 7, 1, suffix="/nonzero"))
    return cases


def _mul_cases() -> list[CaseSpec]:
    pairs = (
        ("mul_sign_pp", P_WORD, 0x0123_4567),
        ("mul_sign_pn", P_WORD, N_WORD),
        ("mul_sign_np", N_WORD, P_WORD),
        ("mul_sign_nn", N_WORD, 0xFEDC_BA99),
        ("mul_all_ones_square", MASK32, MASK32),
        ("mul_sign_bit_square", 0x8000_0000, 0x8000_0000),
    )
    cases = []
    for op_name in ("mul", "mulh", "mulhsu", "mulhu"):
        for tag, a, b in pairs:
            cases.append(_reg_case(op_name, tag, a, b))
    cases.append(_reg_case("mul", "mul_low_word_wrap", 0x0001_0000, 0x0001_0000))
    cases.append(_reg_case("mul", "one_operand", N_WORD, 1))
    cases.append(_reg_case("mul", "zero_operand", N_WORD, 0))
    cases.append(_reg_case("mulhu", "one_operand", MASK32, 1))
    cases.append(_reg_case("mulhu", "zero_operand", MASK32, 0))
    cases.append(_reg_case("mul", "rd_x0_discard", P_WORD, N_WORD, rd=0))
    return cases


def _div_cases() -> list[CaseSpec]:
    cases = []
    scan_c = 0x0101_0101
    scan_remainders = {3: 0x00FF_FFFF, 2: 0x0100_FFFF, 1: 0x0101_00FF, 0: 0x0101_0100}
    for op_name in ("div", "divu", "rem", "remu"):
        cases.append(_reg_case(op_name, "div_by_zero", 0x1234_5678, 0))
        cases.append(_reg_case(op_name, "div_zero_by_zero", 0, 0))
        cases.append(_reg_case(op_name, "div_exact", 0x0F00_0F00, 0x0000_0F00))
        cases.append(_reg_case(op_name, "div_max_remainder", 3 * 0x102 + 0x101, 0x102))
        cases.append(_reg_case(op_name, "div_dividend_smaller", 0x99, 0x0001_0000))
        cases.append(_reg_case(op_name, "div_divisor_one", N_WORD, 1))
        cases.append(_reg_case(op_name, "div_equal_operands", 0x000A_BCDE, 0x000A_BCDE))
    for op_name in ("div", "rem"):
        cases.append(_reg_case(op_name, "div_signed_overflow", 0x8000_0000, MASK32))
        cases.append(_reg_case(op_name, "div_sign_pn", 0x0006_0007, (-0x102) & MASK32))
        cases.append(_reg_case(op_name, "div_sign_np", (-0x0006_0007) & MASK32, 0x102))
        cases.append(_reg_case(op_name, "div_sign_nn", (-0x0006_0007) & MASK32, (-0x102) & MASK32))
    for op_name in ("divu", "remu"):
        cases.append(_reg_case(op_name, "div_sign_nn", N_WORD, 0xF000_0001))
        for limb, remainder in scan_remainders.items():
            cases.append(
                _reg_case(op_name, f"div_scan_limb{limb}", 2 * scan_c + remainder, scan_c)
            )
    return cases


def _mem_setup(target: int, word: int) -> list[int]:
    """Materialize the aligned word containing `target` into ADDR and store
    `word` there, so every later access reads or overwrites bytes this case
    itself defined -- initial memory contents are environment-defined and
    never relied on. Returns the body prefix; ADDR holds `target & ~3`."""
    body = encoding.materialize(ADDR, target & ~3) + encoding.materialize(VAL, word)
    body.append(encoding.store("sw", ADDR, VAL, 0))
    return body


def _load_case(op_name, tag, *, word=SIGN_LANES, base=SCRATCH, offset=0,
               rd=RD, suffix="") -> CaseSpec:
    """Self-contained load: seed the aligned word containing `base + offset`,
    point ADDR at `base` (re-materializing when it is not that aligned word,
    which is what expresses negative-offset and carry addressing), load."""
    target = (base + offset) & MASK32
    body = _mem_setup(target, word)
    if base != target & ~3:
        body += encoding.materialize(ADDR, base)
    body.append(encoding.load(op_name, rd, ADDR, offset))
    return _case(f"{op_name}/{tag}{suffix}", op_name, tag, body, len(body) - 1)


def _load_cases() -> list[CaseSpec]:
    return [
        _load_case("lb", "mem_lane_0", offset=0),
        _load_case("lb", "mem_lane_1", offset=1),
        _load_case("lb", "mem_lane_2", offset=2),
        _load_case("lb", "mem_lane_3", offset=3),
        _load_case("lb", "load_value_sign_clear", word=CLEAR_LANES, offset=1),
        _load_case("lbu", "load_value_sign_set", offset=0),
        _load_case("lbu", "mem_lane_3", offset=3),
        _load_case("lh", "mem_lane_0", offset=0),
        _load_case("lh", "mem_lane_2", offset=2),
        _load_case("lh", "load_value_sign_clear", word=CLEAR_LANES, offset=2),
        _load_case("lhu", "load_value_sign_set", offset=0),
        _load_case("lw", "mem_lane_0", offset=0),
        _load_case("lw", "load_value_all_ones", word=MASK32),
        _load_case("lb", "load_value_all_ones", word=MASK32, offset=2),
        _load_case("lw", "rd_x0_discard", rd=0),
        _load_case("lw", "mem_negative_offset", base=SCRATCH + 8, offset=-8),
        _load_case("lw", "mem_address_carry", base=SCRATCH + 0xFC, offset=4),
        _load_case("lb", "mem_address_carry", base=SCRATCH + 0xFF, offset=1),
    ]


def _store_case(op_name, tag, value, *, base=SCRATCH, offset=0, suffix="") -> CaseSpec:
    """Store over a self-written all-ones word, then read the word back, so
    the corpus pins the composed word through Sail's own load semantics
    rather than through a mask computation of ours."""
    target = (base + offset) & MASK32
    aligned = target & ~3
    body = _mem_setup(target, MASK32)
    if base != aligned:
        body += encoding.materialize(ADDR, base)
    body += encoding.materialize(VAL, value)
    body.append(encoding.store(op_name, ADDR, VAL, offset))
    body.append(encoding.load("lw", RD, ADDR, aligned - base))
    return _case(
        f"{op_name}/{tag}{suffix}", op_name, tag, body, len(body) - 2,
        readback=len(body) - 1,
    )


def _store_cases() -> list[CaseSpec]:
    return [
        _store_case("sb", "mem_lane_0", 0xC3, offset=0),
        _store_case("sb", "mem_lane_1", 0x7F, offset=1),
        _store_case("sb", "mem_lane_2", 0x80, offset=2),
        _store_case("sb", "mem_lane_3", 0x00, offset=3),
        _store_case("sh", "mem_lane_0", 0x8001, offset=0),
        _store_case("sh", "mem_lane_2", 0x7FFE, offset=2),
        _store_case("sw", "mem_lane_0", 0x0180_7F55, offset=0),
        _store_case("sb", "store_neighbor_preservation", 0x00, offset=2, suffix="/zero"),
        _store_case("sw", "mem_address_carry", 0x1122_3344, base=SCRATCH + 0xFC, offset=4),
        _store_case("sb", "mem_negative_offset", 0x55, base=SCRATCH + 8, offset=-7),
    ]


def _forward_branch(op_name, tag, a, b, *, suffix="") -> CaseSpec:
    """Branch forward over one marker: both paths merge two words later, so
    the body embeds in a straight-line guest whichever way Sail decides."""
    body = encoding.materialize(RS1, a) + encoding.materialize(RS2, b)
    body.append(encoding.branch(op_name, RS1, RS2, 8))
    body.append(encoding.op_imm("addi", MARK, 0, 1))
    body.append(encoding.op_imm("addi", MARK2, 0, 2))
    return _case(f"{op_name}/{tag}{suffix}", op_name, tag, body, len(body) - 3)


def _backward_case(builder, op_name, tag, materialization) -> CaseSpec:
    """Trampoline for a backward-taken transfer: hop over a landing pad,
    take the transfer back into the pad, and exit forward past the end.
    Every instruction retires at most once, so the body remains a bounded
    guest and the under-test transfer is genuinely backward."""
    pad = [
        encoding.jal(0, 12),  # over the two-word pad, onto the materialization
        encoding.op_imm("addi", MARK, 0, 1),
        None,  # exit hop, patched once the body length is known
    ]
    body = pad + materialization
    under_test = len(body)
    target_offset = (1 - under_test) * 4
    body.append(builder(target_offset))
    body[2] = encoding.jal(0, (len(body) - 2) * 4)
    return _case(f"{op_name}/{tag}", op_name, tag, body, under_test)


def _branch_cases() -> list[CaseSpec]:
    cases = []
    taken_pairs = {
        "beq": (P_WORD, P_WORD), "bne": (P_WORD, N_WORD),
        "blt": (N_WORD, P_WORD), "bge": (P_WORD, N_WORD),
        "bltu": (P_WORD, N_WORD), "bgeu": (N_WORD, P_WORD),
    }
    not_taken_pairs = {
        "beq": (P_WORD, N_WORD), "bne": (P_WORD, P_WORD),
        "blt": (P_WORD, N_WORD), "bge": (N_WORD, P_WORD),
        "bltu": (N_WORD, P_WORD), "bgeu": (P_WORD, N_WORD),
    }
    for op_name in ("beq", "bne", "blt", "bge", "bltu", "bgeu"):
        cases.append(_forward_branch(op_name, "branch_taken", *taken_pairs[op_name]))
        cases.append(_forward_branch(op_name, "branch_not_taken", *not_taken_pairs[op_name]))
        cases.append(_forward_branch(op_name, "cmp_equal_operands", N_WORD, N_WORD, suffix="/eq"))
        a, b = taken_pairs[op_name]
        materialization = encoding.materialize(RS1, a) + encoding.materialize(RS2, b)
        cases.append(_backward_case(
            lambda off, op=op_name: encoding.branch(op, RS1, RS2, off),
            op_name, "branch_backward_taken", materialization,
        ))
        na, nb = not_taken_pairs[op_name]
        body = encoding.materialize(RS1, na) + encoding.materialize(RS2, nb)
        body.append(encoding.branch(op_name, RS1, RS2, -8))
        cases.append(_case(f"{op_name}/branch_offset_negative_not_taken", op_name,
                           "branch_offset_negative_not_taken", body, len(body) - 1))
    for op_name in ("blt", "bge", "bltu", "bgeu"):
        cases.append(_forward_branch(op_name, "cmp_signed_unsigned_disagree", 0x8000_0000, 1))
        cases.append(_forward_branch(op_name, "cmp_off_by_one", P_WORD, P_WORD + 1))
    return cases


def _jump_cases() -> list[CaseSpec]:
    cases = []
    body = [encoding.jal(RD, 8), encoding.op_imm("addi", MARK, 0, 1),
            encoding.op_imm("addi", MARK2, 0, 2)]
    cases.append(_case("jal/jump_link", "jal", "jump_link", body, 0))
    body = [encoding.jal(0, 8), encoding.op_imm("addi", MARK, 0, 1),
            encoding.op_imm("addi", MARK2, 0, 2)]
    cases.append(_case("jal/jump_discard_link", "jal", "jump_discard_link", body, 0))
    cases.append(_backward_case(lambda off: encoding.jal(RD, off), "jal", "jump_backward", []))

    def jalr_forward(name, tag, imm, rd=RD):
        body = [
            encoding.auipc(RS1, 0),
            encoding.jalr(rd, RS1, imm),
            encoding.op_imm("addi", MARK, 0, 1),
            encoding.op_imm("addi", MARK2, 0, 2),
        ]
        return _case(name, "jalr", tag, body, 1)

    # Targets are auipc-relative, so the case is position-independent: the
    # immediate is measured from the AUIPC's pc, one word before the JALR.
    cases.append(jalr_forward("jalr/jump_link", "jump_link", 12))
    cases.append(jalr_forward("jalr/jalr_lsb_clear", "jalr_lsb_clear", 13))
    cases.append(jalr_forward("jalr/jump_discard_link", "jump_discard_link", 12, rd=0))
    body = [
        encoding.auipc(RS1, 0),
        encoding.jalr(RS1, RS1, 12),
        encoding.op_imm("addi", MARK, 0, 1),
        encoding.op_imm("addi", MARK2, 0, 2),
    ]
    cases.append(_case("jalr/rd_equals_rs1", "jalr", "rd_equals_rs1", body, 1))
    cases.append(_backward_case(
        lambda off: encoding.jalr(RD, RS1, off + 4), "jalr", "jump_backward",
        [encoding.auipc(RS1, 0)],
    ))
    return cases


def _upper_and_fence_cases() -> list[CaseSpec]:
    cases = []
    for tag, imm20 in (("upper_imm_zero", 0), ("upper_imm_one", 1),
                       ("upper_imm_sign_bit", 0x80000), ("upper_imm_all_ones", 0xFFFFF)):
        cases.append(_case(f"lui/{tag}", "lui", tag, [encoding.lui(RD, imm20)], 0))
    cases.append(_case("lui/rd_x0_discard", "lui", "rd_x0_discard",
                       [encoding.lui(0, 0xABCDE)], 0))
    for tag, imm20 in (("upper_imm_zero", 0), ("upper_imm_sign_bit", 0x80000),
                       ("auipc_pc_wrap", 0xFFFFF)):
        cases.append(_case(f"auipc/{tag}", "auipc", tag, [encoding.auipc(RD, imm20)], 0))
    cases.append(_case("fence/fence_nop", "fence", "fence_nop", [encoding.FENCE_WORD], 0))
    return cases


def all_cases() -> list[CaseSpec]:
    return (
        _alu_reg_cases() + _alu_imm_cases() + _shift_cases() + _compare_cases()
        + _mul_cases() + _div_cases() + _load_cases() + _store_cases()
        + _branch_cases() + _jump_cases() + _upper_and_fence_cases()
    )


# Output-file grouping for the generated Zig corpus, so each stays well
# under the repository's file-size ceiling.
GROUPS = {
    "alu": ("add", "sub", "xor", "or", "and", "addi", "xori", "ori", "andi"),
    "shift": ("sll", "srl", "sra", "slli", "srli", "srai"),
    "cmp_branch": ("slt", "sltu", "slti", "sltiu",
                   "beq", "bne", "blt", "bge", "bltu", "bgeu"),
    "mul_div": ("mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"),
    "mem": ("lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw"),
    "flow": ("jal", "jalr", "lui", "auipc", "fence"),
}


class CaseValidationError(ValueError):
    """A case violates the body discipline the guest fixture requires."""


def validate_cases(cases: list[CaseSpec]) -> None:
    """Enforce the register and memory discipline every body promises.

    Static, conservative checks: no register outside the writable set is
    ever written (the fixture owns x1-x5), no register is read before the
    body defines it (so expectations are environment-independent), and no
    load precedes the body's first store (so no case depends on initial
    memory contents).
    """
    names = set()
    for case in cases:
        if case.name in names:
            raise CaseValidationError(f"duplicate case name {case.name}")
        names.add(case.name)
        if not 0 <= case.under_test < len(case.body):
            raise CaseValidationError(f"{case.name}: under_test out of range")
        defined = {0}
        stored = False
        for index, word in enumerate(case.body):
            decoded = encoding.decode(word)
            if decoded is None:
                raise CaseValidationError(f"{case.name}[{index}]: unknown word {word:#010x}")
            op_name = decoded["op"]
            if op_name in READS_RS1 and decoded["rs1"] not in defined:
                raise CaseValidationError(f"{case.name}[{index}]: reads undefined x{decoded['rs1']}")
            if op_name in READS_RS2 and decoded["rs2"] not in defined:
                raise CaseValidationError(f"{case.name}[{index}]: reads undefined x{decoded['rs2']}")
            if op_name in encoding._LOAD and not stored:
                raise CaseValidationError(f"{case.name}[{index}]: load before any store")
            if op_name in encoding._STORE:
                stored = True
            if op_name in WRITES_RD:
                if decoded["rd"] not in WRITABLE:
                    raise CaseValidationError(f"{case.name}[{index}]: writes reserved x{decoded['rd']}")
                defined.add(decoded["rd"])
        expected_op = encoding.decode(case.body[case.under_test])["op"]
        if expected_op != case.op:
            raise CaseValidationError(f"{case.name}: under_test decodes as {expected_op}")
        if case.tag not in PREDICATES:
            raise CaseValidationError(f"{case.name}: unknown class tag {case.tag}")
