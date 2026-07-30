"""Division, multiplication, and shift witnesses."""

from __future__ import annotations

from pathlib import Path

from .core import (
    INT_MIN,
    M31,
    WitnessError,
    _limbs,
    _signed,
    check_witness,
    modular_inverse,
)

__all__ = [
    "DIV_SELECTORS",
    "quotient_and_remainder",
    "division_row",
    "DIV_WITNESSES",
    "check_div_witnesses",
    "REM_WITNESSES",
    "check_rem_witnesses",
    "multiply_low_row",
    "multiply_high_row",
    "check_multiply_witnesses",
    "_shift_core",
    "shift_immediate_row",
    "SHIFT_WITNESSES",
    "check_shift_witnesses",
    "shift_register_row",
    "SHIFT_REG_WITNESSES",
    "check_register_shift_witnesses",
]

# --------------------------------------------------------------------------
# DIV-family witnesses — the Stage B3 arithmetic stress gate
# --------------------------------------------------------------------------

DIV_SELECTORS = ("div", "divu", "rem", "remu")


def quotient_and_remainder(selector: str, lhs: int, rhs: int) -> tuple[int, int]:
    """The architectural quotient and remainder, as unsigned 32-bit words.

    This is the RISC-V convention, not Python's: division truncates toward
    zero and the remainder takes the sign of the dividend, so it is `Int.tdiv`
    and `Int.tmod` rather than floor division.
    """
    if selector not in DIV_SELECTORS:
        raise WitnessError(f"unknown DIV-family selector {selector!r}")
    if rhs == 0:
        # DIV and DIVU yield all ones; REM and REMU yield the dividend.
        return 0xFFFFFFFF, lhs
    if selector in ("div", "rem"):
        dividend, divisor = _signed(lhs), _signed(rhs)
        if dividend == -(1 << 31) and divisor == -1:
            # Signed overflow: the quotient is not representable, so the
            # architecture pins it to INT_MIN and the remainder to zero.
            return INT_MIN, 0
        quotient = abs(dividend) // abs(divisor)
        if (dividend < 0) != (divisor < 0):
            quotient = -quotient
        remainder = dividend - divisor * quotient
        return quotient & 0xFFFFFFFF, remainder & 0xFFFFFFFF
    return lhs // rhs, lhs % rhs


def division_row(
    selector: str,
    lhs: int,
    rhs: int,
    rd: int = 7,
    *,
    clock: int = 1,
    pc: int = 0x1000,
) -> tuple[dict[str, int], int]:
    """Build a complete admitted DIV/DIVU/REM/REMU row and its result."""
    is_signed = selector in ("div", "rem")
    is_division = selector in ("div", "divu")
    quotient, remainder = quotient_and_remainder(selector, lhs, rhs)
    result = quotient if is_division else remainder

    zero_divisor = 1 if rhs == 0 else 0
    remainder_zero = 1 if remainder == 0 else 0
    dividend_sign = (lhs >> 31) & 1 if is_signed else 0
    divisor_sign = (rhs >> 31) & 1 if is_signed else 0
    sign_xor = dividend_sign ^ divisor_sign

    if zero_divisor:
        quotient_sign = 1 if is_signed else 0
    elif is_signed and _signed(lhs) == -(1 << 31) and _signed(rhs) == -1:
        # The signed-overflow class deliberately witnesses q_sign = 0 even
        # though the quotient's bit 31 is set: that is what closes the
        # eight-limb product identity for this case.
        quotient_sign = 0
    else:
        quotient_sign = (quotient >> 31) & 1 if is_signed else 0

    quotient_limbs = _limbs(quotient)
    remainder_limbs = _limbs(remainder)
    dividend_limbs = _limbs(lhs)
    divisor_limbs = _limbs(rhs)
    absolute = _limbs((-remainder) & 0xFFFFFFFF) if sign_xor else remainder_limbs

    special = zero_divisor + remainder_zero
    markers = [0, 0, 0, 0]
    comparison_difference = 0
    if not special:
        factor = -1 if divisor_sign else 1
        for limb in (3, 2, 1, 0):
            difference = factor * (divisor_limbs[limb] - absolute[limb])
            if difference % M31 != 0:
                markers[limb] = 1
                comparison_difference = difference % M31
                break

    nonzero = 1 if rd else 0
    destination = _limbs(result) if nonzero else [0, 0, 0, 0]
    divisor_sum = sum(divisor_limbs)
    remainder_sum = sum(remainder_limbs)

    assignment = {
        "clock": clock,
        "pc": pc,
        "rs1_addr": 5,
        "rs1_previous_clock": 0,
        "rs2_addr": 6,
        "rs2_previous_clock": 0,
        "rd_addr": rd,
        "rd_previous_clock": 0,
        "zero_divisor": zero_divisor,
        "r_zero": remainder_zero,
        "b_sign": dividend_sign,
        "c_sign": divisor_sign,
        "q_sign": quotient_sign,
        "sign_xor": sign_xor,
        "c_sum_inv": modular_inverse(divisor_sum) if divisor_sum % M31 else 0,
        "r_sum_inv": modular_inverse(remainder_sum) if remainder_sum % M31 else 0,
        "lt_diff": comparison_difference,
        "is_div": 0,
        "is_divu": 0,
        "is_rem": 0,
        "is_remu": 0,
        "destination_nonzero": nonzero,
        "destination_inverse": modular_inverse(rd) if rd else 0,
        "bus_value_67": {"div": 41, "divu": 42, "rem": 43, "remu": 44}[selector],
        "bus_value_68": pc + 4,
        "bus_value_69": clock + 1,
        "bus_value_70": (clock - 1) * 4 + 1,
        "bus_value_71": (clock - 1) * 4 + 2,
        "bus_value_72": (clock - 1) * 4 + 3,
    }
    assignment[f"is_{selector}"] = 1
    for index in range(4):
        assignment[f"rs1_previous_{index}"] = dividend_limbs[index]
        assignment[f"rs1_next_{index}"] = dividend_limbs[index]
        assignment[f"rs2_previous_{index}"] = divisor_limbs[index]
        assignment[f"rs2_next_{index}"] = divisor_limbs[index]
        assignment[f"rd_previous_{index}"] = 0
        assignment[f"rd_next_{index}"] = destination[index]
        assignment[f"q_{index}"] = quotient_limbs[index]
        assignment[f"r_{index}"] = remainder_limbs[index]
        assignment[f"r_abs_{index}"] = absolute[index]
        assignment[f"r_inv_{index}"] = modular_inverse(absolute[index] - 256)
        assignment[f"lt_markers_{index}"] = markers[index]
    return assignment, result


#: (name, selector, dividend, divisor, expected result).
#:
#: Issue #137 Stage B3 names the required honest witnesses: zero divisor,
#: signed overflow, signed negative remainder, high-bit DIVU, aliases, and x0.
DIV_WITNESSES: tuple[tuple[str, str, int, int, int], ...] = (
    ("divu-zero-divisor", "divu", 0x2A, 0, 0xFFFFFFFF),
    ("div-zero-divisor", "div", 0x2A, 0, 0xFFFFFFFF),
    ("rem-zero-divisor", "rem", 0x2A, 0, 0x0000002A),
    ("remu-zero-divisor", "remu", 0x2A, 0, 0x0000002A),
    ("div-signed-overflow", "div", INT_MIN, 0xFFFFFFFF, INT_MIN),
    ("rem-signed-overflow", "rem", INT_MIN, 0xFFFFFFFF, 0x00000000),
    ("divu-high-bit", "divu", 0x8ABCDEF1, 1, 0x8ABCDEF1),
    ("divu-plain", "divu", 100, 7, 14),
    ("remu-plain", "remu", 100, 7, 2),
    ("rem-negative-remainder", "rem", 0xFFFFFF9C, 7, 0xFFFFFFFE),
    ("div-negative-quotient", "div", 0xFFFFFF9C, 7, 0xFFFFFFF2),
    ("div-both-negative", "div", 0xFFFFFF9C, 0xFFFFFFF9, 14),
)


def check_div_witnesses(air_ir_dir: Path) -> str:
    for name, selector, lhs, rhs, expected in DIV_WITNESSES:
        assignment, result = division_row(selector, lhs, rhs)
        if result != expected:
            raise WitnessError(
                f"DIV witness {name} computes {result:#010x}, "
                f"expected {expected:#010x}"
            )
        try:
            check_witness(air_ir_dir, "div", assignment)
        except WitnessError as error:
            raise WitnessError(f"DIV witness {name}: {error}") from error

    # x0 destination and operand aliasing, on top of the named cases.
    for name, assignment in (
        ("destination-x0", division_row("div", 100, 7, rd=0)[0]),
        ("destination-aliases-dividend", division_row("div", 100, 7, rd=5)[0]),
        ("destination-aliases-divisor", division_row("divu", 100, 7, rd=6)[0]),
    ):
        try:
            check_witness(air_ir_dir, "div", assignment)
        except WitnessError as error:
            raise WitnessError(f"DIV witness {name}: {error}") from error

    return (
        f"DIV non-vacuity: {len(DIV_WITNESSES) + 3} witnesses reachable in the "
        "exported production AIR, covering every exceptional case"
    )


#: (name, selector, dividend, divisor, expected result).
#:
#: The remainder selectors get their own battery because their conventions
#: are exactly where a wrong-but-satisfiable transcription would hide:
#: * the remainder takes the SIGN OF THE DIVIDEND — rem(-100, 7) is -2, not
#:   the +5 that floor-mod (Python's ``%``) would give;
#: * REM/REMU by zero yield the DIVIDEND, unlike DIV/DIVU's all-ones;
#: * the signed-overflow class rem(INT_MIN, -1) yields zero.
REM_WITNESSES: tuple[tuple[str, str, int, int, int], ...] = (
    ("rem-negative-dividend", "rem", 0xFFFFFF9C, 7, 0xFFFFFFFE),
    ("rem-positive-dividend-negative-divisor", "rem", 100, 0xFFFFFFF9, 0x00000002),
    ("rem-both-negative", "rem", 0xFFFFFF9C, 0xFFFFFFF9, 0xFFFFFFFE),
    ("rem-zero-divisor-yields-dividend", "rem", 0x2A, 0, 0x0000002A),
    ("rem-zero-divisor-negative-dividend", "rem", 0xDEADBEEF, 0, 0xDEADBEEF),
    ("remu-zero-divisor-yields-dividend", "remu", 0xDEADBEEF, 0, 0xDEADBEEF),
    ("rem-signed-overflow", "rem", INT_MIN, 0xFFFFFFFF, 0x00000000),
    ("remu-plain", "remu", 100, 7, 0x00000002),
    ("remu-high-bit-dividend", "remu", 0x8ABCDEF1, 0x10000, 0x0000DEF1),
    ("remu-exact-division", "remu", 105, 7, 0x00000000),
)


def check_rem_witnesses(air_ir_dir: Path) -> str:
    # The convention checks, asserted architecturally before any AIR run so a
    # wrong table cannot pass by matching a wrong builder.
    _, remainder = quotient_and_remainder("rem", 0xFFFFFF9C, 7)
    if _signed(remainder) != -2:
        raise WitnessError(
            f"rem(-100, 7) must be -2 (the dividend's sign under truncated "
            f"division), got {_signed(remainder)}; +5 would be the floor-mod "
            "convention RISC-V does not use"
        )
    for selector in ("rem", "remu"):
        _, by_zero = quotient_and_remainder(selector, 0xDEADBEEF, 0)
        if by_zero != 0xDEADBEEF:
            raise WitnessError(
                f"{selector}(x, 0) must yield the dividend, got {by_zero:#010x}"
            )
        quotient, _ = quotient_and_remainder(selector, 0xDEADBEEF, 0)
        if quotient != 0xFFFFFFFF:
            raise WitnessError(
                "the zero-divisor quotient convention moved; the DIV and REM "
                "conventions are no longer the documented pair"
            )
    _, overflow = quotient_and_remainder("rem", INT_MIN, 0xFFFFFFFF)
    if overflow != 0:
        raise WitnessError(
            f"rem(INT_MIN, -1) must be 0 (signed overflow), got {overflow:#x}"
        )

    for name, selector, lhs, rhs, expected in REM_WITNESSES:
        assignment, result = division_row(selector, lhs, rhs)
        if result != expected:
            raise WitnessError(
                f"REM witness {name} computes {result:#010x}, "
                f"expected {expected:#010x}"
            )
        try:
            check_witness(air_ir_dir, "div", assignment)
        except WitnessError as error:
            raise WitnessError(f"REM witness {name}: {error}") from error

    # x0 destination and operand aliasing on the remainder selectors.
    for name, assignment in (
        ("destination-x0", division_row("rem", 100, 7, rd=0)[0]),
        ("destination-aliases-dividend", division_row("rem", 0xFFFFFF9C, 7, rd=5)[0]),
        ("destination-aliases-divisor", division_row("remu", 100, 7, rd=6)[0]),
    ):
        try:
            check_witness(air_ir_dir, "div", assignment)
        except WitnessError as error:
            raise WitnessError(f"REM witness {name}: {error}") from error

    return (
        f"REM/REMU non-vacuity: {len(REM_WITNESSES) + 3} witnesses reachable "
        "in the exported production AIR; the remainder takes the dividend's "
        "sign, divisor zero yields the dividend, signed overflow yields zero"
    )


# --------------------------------------------------------------------------
# Multiply witnesses — MUL and the MULH/MULHSU/MULHU family
# --------------------------------------------------------------------------


def multiply_low_row(
    lhs: int, rhs: int, rd: int = 7, *, clock: int = 1, pc: int = 0x1000
) -> tuple[dict[str, int], int]:
    """Build an admitted `MUL` row and the low 32 bits of the product."""
    low = (lhs * rhs) & 0xFFFFFFFF
    nonzero = 1 if rd else 0
    result = _limbs(low)
    assignment = {
        "enabler": 1,
        "clock": clock,
        "pc": pc,
        "rs1_addr": 5,
        "rs2_addr": 6,
        "rd_addr": rd,
        "rs1_previous_clock": 0,
        "rs2_previous_clock": 0,
        "rd_previous_clock": 0,
        "destination_nonzero": nonzero,
        "destination_inverse": modular_inverse(rd) if rd else 0,
        "bus_value_39": pc + 4,
        "bus_value_40": clock + 1,
        "bus_value_41": (clock - 1) * 4 + 1,
        "bus_value_42": (clock - 1) * 4 + 2,
        "bus_value_43": (clock - 1) * 4 + 3,
    }
    for index in range(4):
        assignment[f"rs1_previous_{index}"] = _limbs(lhs)[index]
        assignment[f"rs1_next_{index}"] = _limbs(lhs)[index]
        assignment[f"rs2_previous_{index}"] = _limbs(rhs)[index]
        assignment[f"rs2_next_{index}"] = _limbs(rhs)[index]
        assignment[f"rd_previous_{index}"] = 0
        assignment[f"rd_next_{index}"] = result[index] if nonzero else 0
        assignment[f"result_{index}"] = result[index]
    return assignment, low


def multiply_high_row(
    selector: str,
    lhs: int,
    rhs: int,
    rd: int = 7,
    *,
    clock: int = 1,
    pc: int = 0x1000,
) -> tuple[dict[str, int], int]:
    """Build an admitted MULH/MULHSU/MULHU row and the high product word.

    Note the production column naming: the group called `rd_high` carries the
    *low* 32 bits of the 64-bit product, and `result` — the value written to
    rd — carries the *high* 32 bits.
    """
    if selector not in ("mulh", "mulhsu", "mulhu"):
        raise WitnessError(f"unknown multiply-high selector {selector!r}")
    left = _signed(lhs) if selector in ("mulh", "mulhsu") else lhs
    right = _signed(rhs) if selector == "mulh" else rhs
    product = (left * right) & 0xFFFFFFFFFFFFFFFF
    low, high = product & 0xFFFFFFFF, (product >> 32) & 0xFFFFFFFF

    left_sign = (lhs >> 31) & 1 if selector in ("mulh", "mulhsu") else 0
    right_sign = (rhs >> 31) & 1 if selector == "mulh" else 0
    nonzero = 1 if rd else 0
    result = _limbs(high)

    assignment = {
        "clock": clock,
        "pc": pc,
        "rs1_addr": 5,
        "rs2_addr": 6,
        "rd_addr": rd,
        "rs1_previous_clock": 0,
        "rs2_previous_clock": 0,
        "rd_previous_clock": 0,
        "rs1_sign": left_sign,
        "rs2_sign": right_sign,
        "is_mulh": 0,
        "is_mulhsu": 0,
        "is_mulhu": 0,
        "destination_nonzero": nonzero,
        "destination_inverse": modular_inverse(rd) if rd else 0,
        "bus_value_47": {"mulh": 38, "mulhsu": 39, "mulhu": 40}[selector],
        "bus_value_48": pc + 4,
        "bus_value_49": clock + 1,
        "bus_value_50": (clock - 1) * 4 + 1,
        "bus_value_51": (clock - 1) * 4 + 2,
        "bus_value_52": (clock - 1) * 4 + 3,
    }
    assignment[f"is_{selector}"] = 1
    for index in range(4):
        assignment[f"rs1_previous_{index}"] = _limbs(lhs)[index]
        assignment[f"rs1_next_{index}"] = _limbs(lhs)[index]
        assignment[f"rs2_previous_{index}"] = _limbs(rhs)[index]
        assignment[f"rs2_next_{index}"] = _limbs(rhs)[index]
        assignment[f"rd_previous_{index}"] = 0
        assignment[f"rd_next_{index}"] = result[index] if nonzero else 0
        assignment[f"rd_high_{index}"] = _limbs(low)[index]
        assignment[f"result_{index}"] = result[index]
    return assignment, high


def check_multiply_witnesses(air_ir_dir: Path) -> str:
    low_cases = (
        ("mul-small", 6, 7, 7, 0x0000002A),
        ("mul-high-word-nonzero", 0x12345678, 0x9ABCDEF0, 7, 0x242D2080),
        ("mul-by-zero", 0x12345678, 0, 7, 0x00000000),
        ("mul-destination-x0", 6, 7, 0, 0x0000002A),
        ("mul-destination-aliases-source", 6, 7, 5, 0x0000002A),
    )
    for name, lhs, rhs, rd, expected in low_cases:
        assignment, low = multiply_low_row(lhs, rhs, rd)
        if low != expected:
            raise WitnessError(
                f"MUL witness {name} computes {low:#010x}, expected {expected:#010x}"
            )
        try:
            check_witness(air_ir_dir, "mul", assignment)
        except WitnessError as error:
            raise WitnessError(f"MUL witness {name}: {error}") from error

    high_cases = (
        ("mulhu-high-nonzero", "mulhu", 0xFFFFFFFF, 0xFFFFFFFF, 7, 0xFFFFFFFE),
        ("mulh-negative-times-negative", "mulh", 0xFFFFFFFF, 0xFFFFFFFF, 7, 0),
        ("mulh-negative-times-positive", "mulh", INT_MIN, 2, 7, 0xFFFFFFFF),
        ("mulhsu-negative-times-unsigned", "mulhsu", INT_MIN, 0xFFFFFFFF, 7, INT_MIN),
        ("mulhu-high-zero", "mulhu", 6, 7, 7, 0),
        ("mulh-destination-x0", "mulh", 0xFFFFFFFF, 0xFFFFFFFF, 0, 0),
        ("mulh-destination-aliases-source", "mulh", 0xFFFFFFFF, 0xFFFFFFFF, 5, 0),
    )
    for name, selector, lhs, rhs, rd, expected in high_cases:
        assignment, high = multiply_high_row(selector, lhs, rhs, rd)
        if high != expected:
            raise WitnessError(
                f"multiply-high witness {name} computes {high:#010x}, "
                f"expected {expected:#010x}"
            )
        try:
            check_witness(air_ir_dir, "mulh", assignment)
        except WitnessError as error:
            raise WitnessError(f"multiply-high witness {name}: {error}") from error

    total = len(low_cases) + len(high_cases)
    return (
        f"multiply non-vacuity: {total} witnesses reachable in the exported "
        "production AIR"
    )


# --------------------------------------------------------------------------
# Shift witnesses — SLLI, SRLI, SRAI and the register forms SLL, SRL, SRA
# --------------------------------------------------------------------------


def _shift_core(
    selector: str, source: int, amount: int
) -> tuple[int, list[int], int, int, int, int]:
    """The shift semantics both the immediate and register rows share.

    Returns ``(shifted, carries, multiplier, bit_shift, limb_shift, sign)``
    for the 5-bit shift ``amount & 31`` — the same masking the architecture
    applies to both the immediate field and the rs2 register value.
    """
    if selector not in ("sll", "srl", "sra"):
        raise WitnessError(f"unknown shift selector {selector!r}")
    amount &= 31
    bit_shift, limb_shift = amount & 7, amount >> 3
    multiplier = 1 << bit_shift
    source_limbs = _limbs(source)
    sign = (source >> 31) & 1 if selector == "sra" else 0

    if selector == "sll":
        shifted = (source << amount) & 0xFFFFFFFF
        carries = [
            (source_limbs[index] >> (8 - bit_shift)) if bit_shift else 0
            for index in range(4)
        ]
    else:
        if selector == "srl":
            shifted = source >> amount
        elif source & INT_MIN:
            shifted = ((source - (1 << 32)) >> amount) & 0xFFFFFFFF
        else:
            shifted = source >> amount
        carries = [
            (source_limbs[index] & (multiplier - 1)) if bit_shift else 0
            for index in range(4)
        ]
    return shifted, carries, multiplier, bit_shift, limb_shift, sign


def shift_immediate_row(
    selector: str,
    source: int,
    amount: int,
    rd: int = 7,
    *,
    clock: int = 1,
    pc: int = 0x1000,
) -> tuple[dict[str, int], int]:
    """Build an admitted SLLI/SRLI/SRAI row and the shifted word."""
    shifted, carries, multiplier, bit_shift, limb_shift, sign = _shift_core(
        selector, source, amount
    )
    amount &= 31
    source_limbs = _limbs(source)

    result = _limbs(shifted)
    nonzero = 1 if rd else 0
    assignment = {
        "clk": clock,
        "pc": pc,
        "semantic_rs1_addr": 5,
        "semantic_rs1_previous_clock": 0,
        "semantic_rd_addr": rd,
        "semantic_rd_previous_clock": 0,
        "semantic_rs1_sign": sign,
        "imm_truncated": amount,
        "semantic_is_sll": 0,
        "semantic_is_srl": 0,
        "semantic_is_sra": 0,
        "semantic_bit_multiplier_left": multiplier if selector == "sll" else 0,
        "semantic_bit_multiplier_right": multiplier if selector != "sll" else 0,
        "semantic_destination_nonzero": nonzero,
        "semantic_destination_inverse": modular_inverse(rd) if rd else 0,
        "bus_value_51": {"sll": 16, "srl": 17, "sra": 18}[selector],
        "bus_value_52": pc + 4,
        "bus_value_53": clock + 1,
        "bus_value_54": (clock - 1) * 4 + 1,
        "bus_value_55": (clock - 1) * 4 + 2,
    }
    assignment[f"semantic_is_{selector}"] = 1
    for index in range(8):
        assignment[f"semantic_bit_markers_{index}"] = 1 if index == bit_shift else 0
    for index in range(4):
        assignment[f"semantic_limb_markers_{index}"] = (
            1 if index == limb_shift else 0
        )
        assignment[f"semantic_rs1_previous_{index}"] = source_limbs[index]
        assignment[f"semantic_rs1_next_{index}"] = source_limbs[index]
        assignment[f"semantic_rd_previous_{index}"] = 0
        assignment[f"semantic_rd_next_{index}"] = result[index] if nonzero else 0
        assignment[f"semantic_result_{index}"] = result[index]
        assignment[f"semantic_carries_{index}"] = carries[index]
    return assignment, shifted


#: (name, selector, source, amount, expected result).
SHIFT_WITNESSES: tuple[tuple[str, str, int, int, int], ...] = (
    ("slli-amount-zero", "sll", 0x12345678, 0, 0x12345678),
    ("slli-amount-one", "sll", 0x12345678, 1, 0x2468ACF0),
    ("slli-byte-boundary", "sll", 0x12345678, 8, 0x34567800),
    ("slli-amount-thirtyone", "sll", 1, 31, INT_MIN),
    ("srli-amount-zero", "srl", 0x12345678, 0, 0x12345678),
    ("srli-zero-fill", "srl", 0x12345678, 4, 0x01234567),
    ("srli-high-bit-zero-fill", "srl", INT_MIN, 31, 1),
    ("srai-negative-sign-fill", "sra", INT_MIN, 4, 0xF8000000),
    ("srai-negative-saturates", "sra", 0xFFFFFFFF, 31, 0xFFFFFFFF),
    ("srai-nonnegative-matches-srli", "sra", 0x12345678, 4, 0x01234567),
    ("srai-amount-zero-negative", "sra", INT_MIN, 0, INT_MIN),
)


def check_shift_witnesses(air_ir_dir: Path) -> str:
    for name, selector, source, amount, expected in SHIFT_WITNESSES:
        assignment, shifted = shift_immediate_row(selector, source, amount)
        if shifted != expected:
            raise WitnessError(
                f"shift witness {name} computes {shifted:#010x}, "
                f"expected {expected:#010x}"
            )
        try:
            check_witness(air_ir_dir, "shifts_imm", assignment)
        except WitnessError as error:
            raise WitnessError(f"shift witness {name}: {error}") from error

    for name, assignment in (
        ("destination-x0", shift_immediate_row("sra", INT_MIN, 4, rd=0)[0]),
        ("destination-aliases-source", shift_immediate_row("sll", 3, 2, rd=5)[0]),
    ):
        try:
            check_witness(air_ir_dir, "shifts_imm", assignment)
        except WitnessError as error:
            raise WitnessError(f"shift witness {name}: {error}") from error

    return (
        f"shift non-vacuity: {len(SHIFT_WITNESSES) + 2} witnesses reachable in "
        "the exported production AIR"
    )


def shift_register_row(
    selector: str,
    source: int,
    rs2_value: int,
    rd: int = 7,
    *,
    clock: int = 1,
    pc: int = 0x1000,
) -> tuple[dict[str, int], int]:
    """Build an admitted SLL/SRL/SRA (register form) row and the shifted word.

    The shift amount is the low five bits of the rs2 *register value*, not of
    the instruction word. The production AIR binds the marker-encoded amount to
    ``rs2_next_0`` through a ``range_check_20`` request on
    ``7 - (rs2_next_0 - amount) * 2**26``: over M31 that quotient is exactly
    ``rs2_next_0 >> 5``, so the request is satisfiable precisely when the
    encoded amount equals ``rs2_next_0 mod 32``. Only the low byte of rs2
    enters that binding — the three high limbs are architecturally ignored, and
    the masked witnesses below exercise exactly that.
    """
    rs2_value &= 0xFFFFFFFF
    amount = rs2_value & 31
    shifted, carries, multiplier, bit_shift, limb_shift, sign = _shift_core(
        selector, source, amount
    )
    source_limbs = _limbs(source)
    rs2_limbs = _limbs(rs2_value)
    result = _limbs(shifted)
    nonzero = 1 if rd else 0

    assignment = {
        "clk": clock,
        "pc": pc,
        "semantic_rs1_addr": 5,
        "semantic_rs1_previous_clock": 0,
        "rs2_addr": 6,
        "rs2_previous_clock": 0,
        "semantic_rd_addr": rd,
        "semantic_rd_previous_clock": 0,
        "semantic_rs1_sign": sign,
        "semantic_is_sll": 0,
        "semantic_is_srl": 0,
        "semantic_is_sra": 0,
        "semantic_bit_multiplier_left": multiplier if selector == "sll" else 0,
        "semantic_bit_multiplier_right": multiplier if selector != "sll" else 0,
        "semantic_destination_nonzero": nonzero,
        "semantic_destination_inverse": modular_inverse(rd) if rd else 0,
        "bus_value_60": {"sll": 2, "srl": 6, "sra": 7}[selector],
        "bus_value_61": pc + 4,
        "bus_value_62": clock + 1,
        "bus_value_63": (clock - 1) * 4 + 1,
        "bus_value_64": (clock - 1) * 4 + 2,
        "bus_value_65": (clock - 1) * 4 + 3,
    }
    assignment[f"semantic_is_{selector}"] = 1
    for index in range(8):
        assignment[f"semantic_bit_markers_{index}"] = 1 if index == bit_shift else 0
    for index in range(4):
        assignment[f"semantic_limb_markers_{index}"] = (
            1 if index == limb_shift else 0
        )
        assignment[f"semantic_rs1_previous_{index}"] = source_limbs[index]
        assignment[f"semantic_rs1_next_{index}"] = source_limbs[index]
        assignment[f"rs2_previous_{index}"] = rs2_limbs[index]
        assignment[f"rs2_next_{index}"] = rs2_limbs[index]
        assignment[f"semantic_rd_previous_{index}"] = 0
        assignment[f"semantic_rd_next_{index}"] = result[index] if nonzero else 0
        assignment[f"semantic_result_{index}"] = result[index]
        assignment[f"semantic_carries_{index}"] = carries[index]
    return assignment, shifted


#: (name, selector, source, full rs2 register value, expected result).
#:
#: The rs2 value is deliberately NOT pre-masked: several cases carry high bits
#: (or whole high limbs) beyond bit 4, so a production AIR that shifted by the
#: raw register value instead of its low five bits would refuse the row.
SHIFT_REG_WITNESSES: tuple[tuple[str, str, int, int, int], ...] = (
    ("sll-reg-amount-zero", "sll", 0x12345678, 0, 0x12345678),
    ("sll-reg-amount-thirtyone", "sll", 1, 31, INT_MIN),
    ("srl-reg-amount-thirtyone", "srl", INT_MIN, 31, 1),
    # 33 & 31 == 1: the row is a shift by one, not by thirty-three.
    ("sll-reg-masked-low-bits", "sll", 0x12345678, 33, 0x2468ACF0),
    # Only the low byte of rs2 binds the amount; the high limbs are ignored.
    ("srl-reg-masked-high-limbs", "srl", 0x12345678, 0xFFFFFF04, 0x01234567),
    # 0x44 & 31 == 4, with a negative operand so the sign fill is exercised.
    ("sra-reg-negative-masked", "sra", INT_MIN, 0x44, 0xF8000000),
    # 0x5F & 31 == 31: a masked amount at the top of the range.
    ("sra-reg-negative-saturates", "sra", 0xFFFFFFFF, 0x5F, 0xFFFFFFFF),
)


def check_register_shift_witnesses(air_ir_dir: Path) -> str:
    masked = [
        name
        for name, _, _, rs2_value, _ in SHIFT_REG_WITNESSES
        if (rs2_value & 0xFFFFFFFF) != (rs2_value & 31)
    ]
    if len(masked) < 3:
        raise WitnessError(
            "the register-shift witness table no longer exercises rs2 "
            "masking; it needs amounts whose low five bits differ from the "
            "full register value"
        )
    for name, selector, source, rs2_value, expected in SHIFT_REG_WITNESSES:
        assignment, shifted = shift_register_row(selector, source, rs2_value)
        if shifted != expected:
            raise WitnessError(
                f"register-shift witness {name} computes {shifted:#010x}, "
                f"expected {expected:#010x}"
            )
        try:
            check_witness(air_ir_dir, "shifts_reg", assignment)
        except WitnessError as error:
            raise WitnessError(
                f"register-shift witness {name}: {error}"
            ) from error

    for name, assignment in (
        ("destination-x0", shift_register_row("sra", INT_MIN, 0x44, rd=0)[0]),
        (
            "destination-aliases-shift-source",
            shift_register_row("sll", 3, 2, rd=5)[0],
        ),
    ):
        try:
            check_witness(air_ir_dir, "shifts_reg", assignment)
        except WitnessError as error:
            raise WitnessError(
                f"register-shift witness {name}: {error}"
            ) from error

    return (
        f"register-shift non-vacuity: {len(SHIFT_REG_WITNESSES) + 2} witnesses "
        "reachable in the exported production AIR, including masked rs2 amounts"
    )
