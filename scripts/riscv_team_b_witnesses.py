#!/usr/bin/env python3
"""Check Team B non-vacuity witnesses against the exported production AIR.

A Lean non-vacuity theorem proves that some row satisfies the *transcribed*
capsule. That is necessary but not sufficient: if the transcription drifted from
the shipped AIR, a witness could satisfy the capsule and be unreachable in
production, and the "honest witness" would be honest about the wrong system.

This module closes that gap from the other side. It evaluates the same witness
against the *exported production* symbolic AIR — every constraint root over M31,
and every range-check lookup against the domain widths the production lookup
tables actually provide. A witness that passes both this gate and its Lean
counterpart is reachable in the shipped AIR and satisfies the capsule, so the two
agree at least at that point.

It is a cross-check, not a substitute for either. It cannot prove the capsule is
a faithful transcription; it can only refute a witness that is not reachable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

M31 = 2147483647

#: Range-check domains and the bit width of each tuple coordinate.
#: ``range_check_m31`` additionally rejects the maximal tuple, matching
#: ``src/frontends/riscv/air/lookups/entry.zig``.
RANGE_DOMAINS: dict[str, tuple[int, ...]] = {
    "range_check_20": (20,),
    "range_check_8_11": (8, 11),
    "range_check_8_8": (8, 8),
    "range_check_8_8_4": (8, 8, 4),
    "range_check_m31": (8, 7),
}


class WitnessError(RuntimeError):
    """A witness failed the production AIR. Every path out raises this."""


def modular_inverse(value: int) -> int:
    return pow(value % M31, M31 - 2, M31)


def load_family(air_ir_dir: Path, family: str) -> dict[str, Any]:
    path = air_ir_dir / f"{family}.json"
    if not path.is_file():
        raise WitnessError(f"exported AIR for {family} is absent at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(payload: dict[str, Any], assignment: dict[str, int]) -> list[int]:
    """Evaluate the flat AIR DAG over M31 under ``assignment``."""
    declared = {column["name"] for column in payload["columns"]}
    unknown = set(assignment) - declared
    if unknown:
        raise WitnessError(
            "witness assigns columns the AIR does not declare: "
            + ", ".join(sorted(unknown))
        )
    missing = declared - set(assignment)
    if missing:
        raise WitnessError(
            "witness leaves AIR columns unassigned: " + ", ".join(sorted(missing))
        )

    values: list[int] = []
    for node in payload["nodes"]:
        operation = node["op"]
        if operation == "const":
            value = node["value"] % M31
        elif operation == "col":
            value = assignment[node["name"]] % M31
        elif operation == "neg":
            value = (-values[node["args"][0]]) % M31
        elif operation == "add":
            value = (values[node["args"][0]] + values[node["args"][1]]) % M31
        elif operation == "sub":
            value = (values[node["args"][0]] - values[node["args"][1]]) % M31
        elif operation == "mul":
            value = (values[node["args"][0]] * values[node["args"][1]]) % M31
        else:
            raise WitnessError(f"unsupported AIR node operation {operation!r}")
        values.append(value)
    return values


def check_constraints(payload: dict[str, Any], values: list[int]) -> None:
    unsatisfied = [
        index
        for index, root in enumerate(payload["constraints"])
        if values[root] != 0
    ]
    if unsatisfied:
        raise WitnessError(
            "witness does not satisfy production AIR constraint roots "
            + ", ".join(str(index) for index in unsatisfied)
        )


def check_range_lookups(payload: dict[str, Any], values: list[int]) -> int:
    """Every requested range-check tuple must exist in its production table."""
    checked = 0
    for index, lookup in enumerate(payload["lookups"]):
        domain = lookup["domain"]
        widths = RANGE_DOMAINS.get(domain)
        if widths is None:
            continue
        if values[lookup["numerator"]] == 0:
            # An inactive request asserts nothing, exactly as in production.
            continue
        tuple_values = [values[node] for node in lookup["tuple"]]
        if len(tuple_values) != len(widths):
            raise WitnessError(
                f"lookup {index} on {domain} has arity {len(tuple_values)}, "
                f"expected {len(widths)}"
            )
        for coordinate, (value, width) in enumerate(zip(tuple_values, widths)):
            if value >= 1 << width:
                raise WitnessError(
                    f"lookup {index} on {domain} coordinate {coordinate} is "
                    f"{value}, outside the {width}-bit production table"
                )
        if domain == "range_check_m31" and tuple_values == [255, 127]:
            raise WitnessError(
                f"lookup {index} requests the tuple production rejects (255, 127)"
            )
        checked += 1
    return checked


def check_witness(
    air_ir_dir: Path, family: str, assignment: dict[str, int]
) -> str:
    payload = load_family(air_ir_dir, family)
    values = evaluate(payload, assignment)
    check_constraints(payload, values)
    checked = check_range_lookups(payload, values)
    return (
        f"{family}: {len(payload['constraints'])} constraints satisfied, "
        f"{checked} active range requests inside their production tables"
    )


# --------------------------------------------------------------------------
# LH witnesses — the Stage B2 memory stress gate
# --------------------------------------------------------------------------


def load_halfword_row(
    base: int,
    displacement: int,
    memory_word: int,
    rd: int,
    *,
    clock: int = 1,
    pc: int = 0x1000,
    rs1_addr: int = 5,
) -> tuple[dict[str, int], int]:
    """Build a complete admitted `LH` row and the architectural result.

    ``displacement`` is the signed 12-bit immediate. The caller supplies a
    halfword-aligned effective address; a misaligned one raises, because a
    misaligned LH is outside the admitted language rather than a row with a
    different meaning.
    """
    effective = base + displacement
    offset = effective & 3
    if offset not in (0, 2):
        raise WitnessError(
            f"effective address {effective:#x} is not halfword aligned; a "
            "misaligned LH is outside the admitted language"
        )
    aligned = effective - offset

    memory = [(memory_word >> (8 * index)) & 0xFF for index in range(4)]
    half = (memory_word >> (16 if offset == 2 else 0)) & 0xFFFF
    negative = (half >> 15) & 1
    result_word = half | (0xFFFF0000 if negative else 0)
    result = [(result_word >> (8 * index)) & 0xFF for index in range(4)]
    source = [(base >> (8 * index)) & 0xFF for index in range(4)]
    nonzero = 1 if rd != 0 else 0
    destination = result if nonzero else [0, 0, 0, 0]

    assignment = {
        "clk": clock,
        "pc": pc,
        "rs1_addr": rs1_addr,
        "rs1_previous_clock": 0,
        "src_addr": aligned,
        "src_previous_clock": 0,
        "dst_addr": rd,
        "dst_previous_clock": 0,
        "r2_idx": rd,
        "imm_felt": displacement % M31,
        "src_msb": negative,
        "shift_amount": offset,
        "src_addr_selector": aligned,
        "dst_addr_selector": rd,
        "markers_0": 1 if offset == 0 else 0,
        "markers_1": 1 if offset == 0 else 0,
        "markers_2": 1 if offset == 2 else 0,
        "markers_3": 1 if offset == 2 else 0,
        "is_lb": 0,
        "is_lh": 1,
        "is_lbu": 0,
        "is_lhu": 0,
        "is_lw": 0,
        "is_sb": 0,
        "is_sh": 0,
        "is_sw": 0,
        "destination_nonzero": nonzero,
        "destination_inverse": modular_inverse(rd) if rd else 0,
        # Synthesized lookup-argument aliases, each pinned by its own
        # defining constraint in the exported AIR.
        "bus_value_56": 20,
        "bus_value_57": pc + 4,
        "bus_value_58": clock + 1,
        "bus_value_59": (clock - 1) * 4 + 1,
        "bus_value_60": 1,
        "bus_value_61": (clock - 1) * 4 + 3,
        "bus_value_62": 0,
        "bus_value_63": (clock - 1) * 4 + 2,
    }
    for index in range(4):
        assignment[f"rs1_previous_{index}"] = source[index]
        assignment[f"rs1_next_{index}"] = source[index]
        assignment[f"src_previous_{index}"] = memory[index]
        assignment[f"src_next_{index}"] = memory[index]
        assignment[f"dst_previous_{index}"] = 0
        assignment[f"dst_next_{index}"] = destination[index]
        assignment[f"result_{index}"] = result[index]
    return assignment, result_word


#: (name, base, displacement, memory word, rd, expected architectural result).
#:
#: Every case is required by issue #137 Stage B2. The negative high half is the
#: one that actually exercises the sign path: a zero or positive low-half
#: witness would leave sign extension untested.
LH_WITNESSES: tuple[tuple[str, int, int, int, int, int], ...] = (
    ("negative-high-half", 0x2000, 2, 0x8ABC1234, 7, 0xFFFF8ABC),
    ("nonnegative-low-half", 0x2000, 0, 0x8ABC1234, 7, 0x00001234),
    ("negative-low-half", 0x2000, 0, 0x1234FEDC, 7, 0xFFFFFEDC),
    ("destination-x0", 0x2000, 2, 0x8ABC1234, 0, 0xFFFF8ABC),
    ("destination-aliases-source", 0x2000, 2, 0x8ABC1234, 5, 0xFFFF8ABC),
    ("negative-displacement", 0x2010, -16, 0x0000FFFF, 7, 0xFFFFFFFF),
    ("top-admitted-address", 0x3FFFFC, 0, 0xFFFF7FFF, 7, 0x00007FFF),
)

#: The largest halfword-aligned effective address an admitted row can carry.
#:
#: The production AIR bounds addresses twice: the base-address
#: ``range_check_m31`` forces the high limb of `rs1` below 128, and the
#: aligned-address ``range_check_20`` request carries ``aligned / 4``, so
#: ``aligned < 2 ** 22``. A true 32-bit address wrap is therefore *not
#: reachable* in an admitted production row. Architectural wrap is real and the
#: Sail side defines it; the AIR narrows it away. An LH theorem must carry that
#: range premise explicitly rather than claim the AIR derives wrap behaviour.
MAX_ADMITTED_ALIGNED_ADDRESS = (2**20 - 1) * 4


def check_lh_witnesses(air_ir_dir: Path) -> str:
    for name, base, displacement, memory_word, rd, expected in LH_WITNESSES:
        assignment, result = load_halfword_row(
            base, displacement, memory_word, rd
        )
        if result != expected:
            raise WitnessError(
                f"LH witness {name} computes {result:#010x}, "
                f"expected {expected:#010x}"
            )
        try:
            check_witness(air_ir_dir, "load_store", assignment)
        except WitnessError as error:
            raise WitnessError(f"LH witness {name}: {error}") from error
    return (
        f"LH non-vacuity: {len(LH_WITNESSES)} witnesses reachable in the "
        "exported production AIR"
    )


# --------------------------------------------------------------------------
# DIV-family witnesses — the Stage B3 arithmetic stress gate
# --------------------------------------------------------------------------

DIV_SELECTORS = ("div", "divu", "rem", "remu")

INT_MIN = 0x80000000


def _limbs(word: int) -> list[int]:
    return [(word >> (8 * index)) & 0xFF for index in range(4)]


def _signed(word: int) -> int:
    return word - (1 << 32) if word & INT_MIN else word


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--air-ir-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(check_lh_witnesses(args.air_ir_dir))
        print(check_div_witnesses(args.air_ir_dir))
    except WitnessError as error:
        print(f"witness gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
