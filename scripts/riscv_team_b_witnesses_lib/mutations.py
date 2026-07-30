"""Mutation rows that the exported production AIR must refuse."""

from __future__ import annotations

from pathlib import Path

from .arithmetic import (
    division_row,
    multiply_high_row,
    shift_immediate_row,
    shift_register_row,
)
from .core import (
    EXPORT_COMMAND,
    INT_MIN,
    M31,
    WitnessError,
    _limbs,
    check_witness,
    modular_inverse,
)
from .memory import load_halfword_row, load_row, store_row

__all__ = [
    "mutation_counter_cases",
    "check_mutation_refusals",
]

# --------------------------------------------------------------------------
# Mutation battery: rows the production AIR must REFUSE
# --------------------------------------------------------------------------


def mutation_counter_cases() -> tuple[tuple[str, str, dict[str, int]], ...]:
    """Deliberately tampered rows, each of which production must refuse.

    Every case starts from an honest witness this file already proves
    reachable, then re-introduces one classic prover cheat: a deleted
    preservation, a value at the wrong offset, an amount decoupled from its
    register, a flipped or free sign, a relabelled selector. If any of these
    rows is ever ACCEPTED, the production AIR lost the constraint that used to
    refuse it — precisely the regression the coverage ledger's
    `air_level_counterexample_gate` promises to catch.
    """
    cases: list[tuple[str, str, dict[str, int]]] = []

    def case(name: str, family: str, assignment: dict[str, int]) -> None:
        cases.append((name, family, assignment))

    # --- loads -----------------------------------------------------------
    tampered, _ = load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
    tampered["result_0"] = (tampered["result_0"] + 1) % 256
    case("lh-tampered-result-limb", "load_store", tampered)

    flipped, _ = load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
    flipped["src_msb"] = 0
    case("lh-flipped-sign-witness", "load_store", flipped)

    swapped, _ = load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
    swapped["src_next_2"], swapped["src_next_3"] = (
        swapped["src_next_3"],
        swapped["src_next_2"],
    )
    case("lh-swapped-endian-bytes", "load_store", swapped)

    unpreserved, _ = load_halfword_row(0x2000, 2, 0x8ABC1234, 7)
    unpreserved["src_next_0"] = (unpreserved["src_next_0"] + 1) % 256
    case("lh-clobbered-memory-word", "load_store", unpreserved)

    # --- per-opcode loads ------------------------------------------------
    lb_flipped, _ = load_row("lb", 0x2000, 1, 0xDDCC9CAA, 7)
    # The sign witness is released while the retired word stays sign-extended:
    # the extension constraints must object.
    lb_flipped["src_msb"] = 0
    case("lb-flipped-sign-witness", "load_store", lb_flipped)

    lb_unsigned, _ = load_row("lb", 0x2000, 1, 0xDDCC9CAA, 7)
    # LBU semantics claimed on an LB row: zero-extend the negative byte and
    # release the sign together, so every polynomial constraint still holds.
    # Only the is_lb-gated sign-binding range_check_m31 request — the tuple
    # (0, result_0 - 128*src_msb) with a seven-bit second coordinate — can
    # refuse this internally consistent row.
    lb_unsigned["src_msb"] = 0
    for index, limb in enumerate(_limbs(0x0000009C)):
        lb_unsigned[f"result_{index}"] = limb
        lb_unsigned[f"dst_next_{index}"] = limb
    case("lb-zero-extended-negative-byte", "load_store", lb_unsigned)

    lhu_signed, _ = load_row("lhu", 0x2000, 2, 0x8ABC1234, 7)
    # A zero-extending LHU claiming a sign: src_msb has no meaning outside
    # signed loads and the retired word may not carry an extension.
    lhu_signed["src_msb"] = 1
    for index, limb in enumerate(_limbs(0xFFFF8ABC)):
        lhu_signed[f"result_{index}"] = limb
        lhu_signed[f"dst_next_{index}"] = limb
    case("lhu-claimed-sign-extension", "load_store", lhu_signed)

    lw_tampered, _ = load_row("lw", 0x2000, 4, 0xDEADBEEF, 7)
    lw_tampered["result_2"] = (lw_tampered["result_2"] + 1) % 256
    case("lw-tampered-result-limb", "load_store", lw_tampered)

    # --- stores ----------------------------------------------------------
    clobbered, _ = store_row("sb", 0x2000, 1, 0xDDCCBBAA, 0x11223344)
    clobbered["dst_next_3"] = (clobbered["dst_next_3"] + 1) % 256
    case("sb-clobbered-unselected-byte", "load_store", clobbered)

    misplaced, _ = store_row("sb", 0x2000, 1, 0xDDCCBBAA, 0x11223344)
    # The stored byte lands one lane too high; the selected lane keeps its
    # old value. Both the write constraint and the preservation must object.
    misplaced["dst_next_1"] = misplaced["dst_previous_1"]
    misplaced["dst_next_2"] = 0x44
    case("sb-byte-at-wrong-offset", "load_store", misplaced)

    halfway, _ = store_row("sh", 0x2000, 0, 0xDDCCBBAA, 0x11223344)
    halfway["dst_next_0"] = halfway["dst_previous_0"]
    halfway["dst_next_1"] = halfway["dst_previous_1"]
    halfway["dst_next_2"] = 0x44
    halfway["dst_next_3"] = 0x33
    case("sh-half-at-wrong-offset", "load_store", halfway)

    truncated, _ = store_row("sw", 0x2000, 0, 0xDDCCBBAA, 0x11223344)
    truncated["dst_next_2"] = truncated["dst_previous_2"]
    truncated["dst_next_3"] = truncated["dst_previous_3"]
    case("sw-truncated-word-write", "load_store", truncated)

    drifted, _ = store_row("sb", 0x2000, 1, 0xDDCCBBAA, 0x11223344)
    # The marker moves to another lane while shift_amount (and therefore the
    # store address) stays put.
    drifted["markers_1"] = 0
    drifted["markers_2"] = 1
    case("sb-marker-shift-mismatch", "load_store", drifted)

    # --- DIV family ------------------------------------------------------
    free_sign, _ = division_row("div", 0xFFFFFF9C, 7)
    free_sign["q_sign"] ^= 1
    case("div-free-quotient-sign", "div", free_sign)

    convention, _ = division_row("divu", 42, 0)
    convention["q_0"] = 0
    case("divu-deleted-zero-divisor-convention", "div", convention)

    wrong_sign, _ = division_row("rem", 0xFFFFFF9C, 7)
    wrong_sign["r_0"] = 2  # +2 instead of the architectural -2
    case("rem-wrong-remainder-sign", "div", wrong_sign)

    released, _ = division_row("divu", 100, 7)
    for index in range(4):
        released[f"lt_markers_{index}"] = 0
    case("divu-released-comparison-witness", "div", released)

    relabelled, _ = division_row("divu", 100, 7)
    relabelled["is_divu"] = 0
    relabelled["is_remu"] = 1
    case("divu-relabelled-as-remu", "div", relabelled)

    # --- REM family ------------------------------------------------------
    retired_quotient, _ = division_row("rem", 100, 7)
    # A REM row retiring the quotient (14) instead of the remainder (2):
    # the selector-driven result mux must object.
    for index, limb in enumerate(_limbs(14)):
        retired_quotient[f"rd_next_{index}"] = limb
    case("rem-retired-the-quotient", "div", retired_quotient)

    oversize, _ = division_row("remu", 100, 7)
    # An internally consistent 100 = 7*13 + 9 whose remainder is NOT smaller
    # than its divisor. The eight-limb product identity holds, so only the
    # positive_remainder_diff range_check_20 request on lt_diff - 1 can
    # refuse the negative comparison difference 7 - 9.
    for index, limb in enumerate(_limbs(13)):
        oversize[f"q_{index}"] = limb
    for index, limb in enumerate(_limbs(9)):
        oversize[f"r_{index}"] = limb
        oversize[f"r_abs_{index}"] = limb
        oversize[f"rd_next_{index}"] = limb
        oversize[f"r_inv_{index}"] = modular_inverse(limb - 256)
    oversize["r_sum_inv"] = modular_inverse(9)
    oversize["lt_diff"] = (7 - 9) % M31
    case("remu-remainder-not-below-divisor", "div", oversize)

    # --- multiply --------------------------------------------------------
    high_limb, _ = multiply_high_row("mulhu", 0xFFFFFFFF, 0xFFFFFFFF)
    high_limb["result_0"] = (high_limb["result_0"] + 1) % 256
    case("mulhu-tampered-high-word", "mulh", high_limb)

    unbound, _ = multiply_high_row("mulh", 0xFFFFFFFF, 0xFFFFFFFF)
    unbound["rs1_sign"] = 0
    case("mulh-unbound-operand-sign", "mulh", unbound)

    claimed, _ = multiply_high_row("mulhu", 0xFFFFFFFF, 0xFFFFFFFF)
    claimed["rs1_sign"] = 1
    case("mulhu-claimed-signed-operand", "mulh", claimed)

    # --- immediate shifts ------------------------------------------------
    released_sra, _ = shift_immediate_row("sra", INT_MIN, 4)
    released_sra["semantic_rs1_sign"] = 0
    case("srai-released-sign-witness", "shifts_imm", released_sra)

    claimed_srl, _ = shift_immediate_row("srl", INT_MIN, 4)
    claimed_srl["semantic_rs1_sign"] = 1
    case("srli-claimed-sign", "shifts_imm", claimed_srl)

    mismatched, _ = shift_immediate_row("sll", 0x12345678, 8)
    mismatched["imm_truncated"] = 9
    case("slli-mismatched-amount", "shifts_imm", mismatched)

    # --- register shifts -------------------------------------------------
    # The row shifts by 3 while rs2 actually holds 33 (low five bits 1): a
    # shift amount decoupled from — unmasked against — the register value.
    # The internal shift semantics stay consistent, so only the production
    # rs2-binding range request can refuse it.
    unmasked, _ = shift_register_row("sll", 0x12345678, 3)
    for index, limb in enumerate(_limbs(33)):
        unmasked[f"rs2_previous_{index}"] = limb
        unmasked[f"rs2_next_{index}"] = limb
    case("sll-reg-unmasked-shift-amount", "shifts_reg", unmasked)

    reg_released, _ = shift_register_row("sra", INT_MIN, 0x44)
    reg_released["semantic_rs1_sign"] = 0
    case("sra-reg-released-sign-witness", "shifts_reg", reg_released)

    reg_claimed, _ = shift_register_row("srl", INT_MIN, 4)
    reg_claimed["semantic_rs1_sign"] = 1
    case("srl-reg-claimed-sign", "shifts_reg", reg_claimed)

    return tuple(cases)


def check_mutation_refusals(air_ir_dir: Path) -> str:
    """Every tampered row must be refused; an accepted one fails the gate."""
    cases = mutation_counter_cases()
    families: set[str] = set()
    for name, family, assignment in cases:
        families.add(family)
        try:
            check_witness(air_ir_dir, family, assignment)
        except WitnessError as error:
            if "column set" in str(error):
                raise WitnessError(
                    f"mutation {name} failed for the wrong reason — the "
                    "mutated row no longer matches the exported column "
                    "layout, so nothing was actually tested: "
                    f"{error}"
                ) from error
            continue
        raise WitnessError(
            f"mutation {name} was ACCEPTED by the production AIR. A row this "
            "gate requires to be impossible is reachable: either the AIR "
            "lost the refusing constraint, or the mutation no longer tampers "
            "with anything. Diff the export against the previous one with "
            f"`{EXPORT_COMMAND}` before trusting any proof."
        )
    return (
        f"mutation counter-check: {len(cases)} tampered rows across "
        f"{len(families)} families all refused by the production AIR"
    )
