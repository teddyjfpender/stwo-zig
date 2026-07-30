"""Load/store witnesses and the address-aliasing regression."""

from __future__ import annotations

from pathlib import Path

from .core import (
    M31,
    WitnessError,
    _limbs,
    check_range_lookups,
    check_witness,
    evaluate,
    load_family,
    modular_inverse,
)

__all__ = [
    "LOAD_OPCODE_IDS",
    "load_row",
    "load_halfword_row",
    "LH_WITNESSES",
    "MAX_ADMITTED_ALIGNED_ADDRESS",
    "check_lh_witnesses",
    "LOAD_WITNESSES",
    "_DISCRIMINATING_LOAD_PAIRS",
    "check_load_witnesses",
    "store_row",
    "STORE_WITNESSES",
    "_STORE_LANES",
    "check_store_witnesses",
    "ALIASING_BASE",
    "ALIASING_DISPLACEMENT",
    "address_aliasing_row",
    "check_address_aliasing_rejected",
]

# --------------------------------------------------------------------------
# Load witnesses — LH (the Stage B2 memory stress gate) and the per-opcode
# LB/LBU/LHU/LW selectors
# --------------------------------------------------------------------------

#: Program-ROM opcode identifiers per load selector, pinned by
#: ``programLookup`` in src/frontends/riscv/air/semantics/load_store.zig.
LOAD_OPCODE_IDS: dict[str, int] = {
    "lb": 19,
    "lh": 20,
    "lw": 21,
    "lbu": 22,
    "lhu": 23,
}


def load_row(
    selector: str,
    base: int,
    displacement: int,
    memory_word: int,
    rd: int,
    *,
    clock: int = 1,
    pc: int = 0x1000,
    rs1_addr: int = 5,
) -> tuple[dict[str, int], int]:
    """Build a complete admitted load row and the architectural result.

    ``displacement`` is the signed 12-bit immediate. The caller supplies a
    suitably aligned effective address; a misaligned one raises, because a
    misaligned load is outside the admitted language rather than a row with a
    different meaning. The architectural result is what retires to ``rd``:
    sign-extended for LB/LH, zero-extended for LBU/LHU, and the memory word
    itself for LW.
    """
    if selector not in LOAD_OPCODE_IDS:
        raise WitnessError(f"unknown load selector {selector!r}")
    effective = base + displacement
    offset = effective & 3
    if selector in ("lh", "lhu") and offset not in (0, 2):
        raise WitnessError(
            f"effective address {effective:#x} is not halfword aligned; a "
            f"misaligned {selector.upper()} is outside the admitted language"
        )
    if selector == "lw" and offset != 0:
        raise WitnessError(
            f"effective address {effective:#x} is not word aligned; a "
            "misaligned LW is outside the admitted language"
        )
    aligned = effective - offset

    memory = [(memory_word >> (8 * index)) & 0xFF for index in range(4)]
    if selector in ("lb", "lbu"):
        loaded = memory[offset]
        negative = (loaded >> 7) & 1 if selector == "lb" else 0
        result_word = loaded | (0xFFFFFF00 if negative else 0)
        # A byte access marks exactly its own lane (marker_sum = 1).
        markers = [1 if index == offset else 0 for index in range(4)]
    elif selector in ("lh", "lhu"):
        loaded = (memory_word >> (8 * offset)) & 0xFFFF
        negative = (loaded >> 15) & 1 if selector == "lh" else 0
        result_word = loaded | (0xFFFF0000 if negative else 0)
        # A halfword access marks both lanes of its half (marker_sum = 2,
        # shift_id 1 for the low half and 5 for the high half).
        markers = [
            1 if offset == 0 else 0,
            1 if offset == 0 else 0,
            1 if offset == 2 else 0,
            1 if offset == 2 else 0,
        ]
    else:
        negative = 0
        result_word = memory_word
        # The markers are free bits on a word access; production leaves them
        # unconstrained there and the honest witness writes zero.
        markers = [0, 0, 0, 0]
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
        "markers_0": markers[0],
        "markers_1": markers[1],
        "markers_2": markers[2],
        "markers_3": markers[3],
        "is_lb": 0,
        "is_lh": 0,
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
        "bus_value_56": LOAD_OPCODE_IDS[selector],
        "bus_value_57": pc + 4,
        "bus_value_58": clock + 1,
        "bus_value_59": (clock - 1) * 4 + 1,
        "bus_value_60": 1,
        "bus_value_61": (clock - 1) * 4 + 3,
        "bus_value_62": 0,
        "bus_value_63": (clock - 1) * 4 + 2,
    }
    assignment[f"is_{selector}"] = 1
    for index in range(4):
        assignment[f"rs1_previous_{index}"] = source[index]
        assignment[f"rs1_next_{index}"] = source[index]
        assignment[f"src_previous_{index}"] = memory[index]
        assignment[f"src_next_{index}"] = memory[index]
        assignment[f"dst_previous_{index}"] = 0
        assignment[f"dst_next_{index}"] = destination[index]
        assignment[f"result_{index}"] = result[index]
    return assignment, result_word


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
    """Build a complete admitted `LH` row and the architectural result."""
    return load_row(
        "lh",
        base,
        displacement,
        memory_word,
        rd,
        clock=clock,
        pc=pc,
        rs1_addr=rs1_addr,
    )


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


#: (name, selector, base, displacement, memory word, rd, expected result).
#:
#: The point of this table is DISCRIMINATION, not mere reachability: LB and
#: LBU read the same negative byte at the same offset, LH's negative-high-half
#: witness and LHU read the same negative halfword, and LW must retire the
#: memory word verbatim at four distinct aligned addresses. If the paired
#: results did not differ, the opcodes would be indistinguishable at this
#: level; ``check_load_witnesses`` asserts the architectural results
#: explicitly rather than settling for constraint satisfaction.
LOAD_WITNESSES: tuple[tuple[str, str, int, int, int, int, int], ...] = (
    # LB vs LBU on the SAME negative byte 0x9C at the same offset: sign-
    # versus zero-extension is the entire difference between the opcodes.
    ("lb-negative-byte", "lb", 0x2000, 1, 0xDDCC9CAA, 7, 0xFFFFFF9C),
    ("lbu-same-negative-byte", "lbu", 0x2000, 1, 0xDDCC9CAA, 7, 0x0000009C),
    ("lb-positive-byte-offset-zero", "lb", 0x2000, 0, 0xDDCC9C7F, 7, 0x0000007F),
    ("lb-negative-byte-offset-two", "lb", 0x2000, 2, 0xDD80BBAA, 7, 0xFFFFFF80),
    ("lb-negative-byte-offset-three", "lb", 0x2000, 3, 0x81CCBBAA, 7, 0xFFFFFF81),
    ("lbu-high-bit-offset-three", "lbu", 0x2000, 3, 0x81CCBBAA, 7, 0x00000081),
    # effective = 0x2010 - 15 = 0x2001: offset one through a negative
    # displacement.
    ("lbu-negative-displacement", "lbu", 0x2010, -15, 0xDDCC9CAA, 7, 0x0000009C),
    # LHU vs LH on the SAME negative halfword as LH_WITNESSES
    # negative-high-half (0x8ABC): zero- versus sign-extended.
    ("lhu-negative-high-half", "lhu", 0x2000, 2, 0x8ABC1234, 7, 0x00008ABC),
    ("lhu-negative-low-half", "lhu", 0x2000, 0, 0x1234FEDC, 7, 0x0000FEDC),
    # LW at four distinct aligned addresses, identity with the memory word.
    ("lw-aligned-word-zero", "lw", 0x2000, 0, 0x8ABC1234, 7, 0x8ABC1234),
    ("lw-aligned-word-one", "lw", 0x2000, 4, 0xDEADBEEF, 7, 0xDEADBEEF),
    ("lw-aligned-word-two", "lw", 0x2000, 8, 0x00000000, 7, 0x00000000),
    ("lw-aligned-word-three", "lw", 0x2000, 12, 0xFFFFFFFF, 7, 0xFFFFFFFF),
    ("lb-destination-x0", "lb", 0x2000, 1, 0xDDCC9CAA, 0, 0xFFFFFF9C),
    ("lw-destination-aliases-base", "lw", 0x2000, 4, 0xDEADBEEF, 5, 0xDEADBEEF),
)

#: The discriminating pairs the table must keep: same datum, same offset,
#: different selector, and the retired words MUST differ.
_DISCRIMINATING_LOAD_PAIRS: tuple[tuple[str, str, int, int, int, int], ...] = (
    # (signed selector, unsigned selector, base, displacement, word, mask)
    ("lb", "lbu", 0x2000, 1, 0xDDCC9CAA, 0xFF),
    ("lh", "lhu", 0x2000, 2, 0x8ABC1234, 0xFFFF),
)


def check_load_witnesses(air_ir_dir: Path) -> str:
    for name, selector, base, displacement, memory_word, rd, expected in (
        LOAD_WITNESSES
    ):
        assignment, result = load_row(selector, base, displacement, memory_word, rd)
        if result != expected:
            raise WitnessError(
                f"load witness {name} computes {result:#010x}, "
                f"expected {expected:#010x}"
            )
        if selector == "lw" and result != memory_word:
            raise WitnessError(
                f"load witness {name}: LW must retire the memory word "
                f"{memory_word:#010x} verbatim, got {result:#010x}"
            )
        try:
            check_witness(air_ir_dir, "load_store", assignment)
        except WitnessError as error:
            raise WitnessError(f"load witness {name}: {error}") from error

    # The architectural discrimination, asserted explicitly: on the same
    # negative datum the signed and unsigned selectors MUST retire different
    # words — the unsigned one is the raw datum, the signed one carries an
    # all-ones extension. Equal results would mean LB/LBU (or LH/LHU) are
    # indistinguishable at this level and the witness pair proves nothing.
    for signed_sel, unsigned_sel, base, displacement, word, mask in (
        _DISCRIMINATING_LOAD_PAIRS
    ):
        _, signed_result = load_row(signed_sel, base, displacement, word, 7)
        _, unsigned_result = load_row(unsigned_sel, base, displacement, word, 7)
        if signed_result == unsigned_result:
            raise WitnessError(
                f"{signed_sel.upper()} and {unsigned_sel.upper()} agree "
                f"({signed_result:#010x}) on the same negative datum; the "
                "pair no longer discriminates sign- from zero-extension"
            )
        if unsigned_result > mask:
            raise WitnessError(
                f"{unsigned_sel.upper()} retired {unsigned_result:#010x}, "
                "which is not zero-extended"
            )
        if signed_result != (unsigned_result | (0xFFFFFFFF & ~mask)):
            raise WitnessError(
                f"{signed_sel.upper()} retired {signed_result:#010x}, which "
                f"is not the sign-extension of {unsigned_result:#010x}"
            )

    covered = {
        (base + displacement) & 3
        for _, selector, base, displacement, _, _, _ in LOAD_WITNESSES
        if selector in ("lb", "lbu")
    }
    if covered != {0, 1, 2, 3}:
        raise WitnessError(
            f"byte-load witnesses cover offsets {sorted(covered)}, not all four"
        )

    return (
        f"per-opcode load non-vacuity: {len(LOAD_WITNESSES)} LB/LBU/LHU/LW "
        "witnesses reachable in the exported production AIR; sign- and "
        "zero-extension discriminated on the same negative datum, LW equals "
        "the memory word at four aligned addresses"
    )

# --------------------------------------------------------------------------
# Store witnesses — SB, SH, SW, with unselected-byte preservation
# --------------------------------------------------------------------------


def store_row(
    selector: str,
    base: int,
    displacement: int,
    memory_word: int,
    stored: int,
    r2: int = 6,
    *,
    clock: int = 1,
    pc: int = 0x1000,
    rs1_addr: int = 5,
) -> tuple[dict[str, int], int]:
    """Build a complete admitted SB/SH/SW row and the memory word it leaves.

    In the production `load_store` family a store swaps the roles of the two
    access blocks: `src` reads the *stored register* (`r2_idx`, register
    space), and `dst` is the *memory word* (RAM space) — the mirror image of a
    load. The unselected bytes of the memory word are carried through
    ``dst_previous -> dst_next`` unchanged; that preservation is exactly what
    constraints C54–C57 of the exported AIR demand, and what the mutation
    battery clobbers to prove they still exist.
    """
    if selector not in ("sb", "sh", "sw"):
        raise WitnessError(f"unknown store selector {selector!r}")
    effective = base + displacement
    offset = effective & 3
    if selector == "sh" and offset not in (0, 2):
        raise WitnessError(
            f"effective address {effective:#x} is not halfword aligned; a "
            "misaligned SH is outside the admitted language"
        )
    if selector == "sw" and offset != 0:
        raise WitnessError(
            f"effective address {effective:#x} is not word aligned; a "
            "misaligned SW is outside the admitted language"
        )
    aligned = effective - offset

    old = _limbs(memory_word)
    value = _limbs(stored)
    new = list(old)
    markers = [0, 0, 0, 0]
    if selector == "sb":
        new[offset] = value[0]
        markers[offset] = 1
    elif selector == "sh":
        new[offset] = value[0]
        new[offset + 1] = value[1]
        markers[offset] = 1
        markers[offset + 1] = 1
    else:
        new = list(value)
    new_word = sum(limb << (8 * index) for index, limb in enumerate(new))

    source = _limbs(base)
    nonzero = 1 if r2 else 0
    assignment = {
        "clk": clock,
        "pc": pc,
        "rs1_addr": rs1_addr,
        "rs1_previous_clock": 0,
        # For a store, `src` is the stored register's file entry ...
        "src_addr": r2,
        "src_previous_clock": 0,
        # ... and `dst` is the memory word being written.
        "dst_addr": aligned,
        "dst_previous_clock": 0,
        "r2_idx": r2,
        "imm_felt": displacement % M31,
        "src_msb": 0,
        "shift_amount": offset,
        "src_addr_selector": r2,
        "dst_addr_selector": aligned,
        "markers_0": markers[0],
        "markers_1": markers[1],
        "markers_2": markers[2],
        "markers_3": markers[3],
        "is_lb": 0,
        "is_lh": 0,
        "is_lbu": 0,
        "is_lhu": 0,
        "is_lw": 0,
        "is_sb": 1 if selector == "sb" else 0,
        "is_sh": 1 if selector == "sh" else 0,
        "is_sw": 1 if selector == "sw" else 0,
        "destination_nonzero": nonzero,
        "destination_inverse": modular_inverse(r2) if r2 else 0,
        "bus_value_56": {"sb": 24, "sh": 25, "sw": 26}[selector],
        "bus_value_57": pc + 4,
        "bus_value_58": clock + 1,
        "bus_value_59": (clock - 1) * 4 + 1,
        "bus_value_60": 0,
        "bus_value_61": (clock - 1) * 4 + 2,
        "bus_value_62": 1,
        "bus_value_63": (clock - 1) * 4 + 3,
    }
    for index in range(4):
        assignment[f"rs1_previous_{index}"] = source[index]
        assignment[f"rs1_next_{index}"] = source[index]
        assignment[f"src_previous_{index}"] = value[index]
        assignment[f"src_next_{index}"] = value[index]
        assignment[f"dst_previous_{index}"] = old[index]
        assignment[f"dst_next_{index}"] = new[index]
        # A store writes no destination register, and the production AIR pins
        # every `result` limb to zero on store rows (C65–C68).
        assignment[f"result_{index}"] = 0
    return assignment, new_word


#: (name, selector, base, displacement, old memory word, stored register
#: value, expected memory word afterwards). A byte store at each of the four
#: offsets, a half store at both offsets, and a word store; the shared old
#: word 0xDDCCBBAA makes any clobbered unselected byte visible by eye.
STORE_WITNESSES: tuple[tuple[str, str, int, int, int, int, int], ...] = (
    ("sb-offset-zero", "sb", 0x2000, 0, 0xDDCCBBAA, 0x11223344, 0xDDCCBB44),
    ("sb-offset-one", "sb", 0x2000, 1, 0xDDCCBBAA, 0x11223344, 0xDDCC44AA),
    ("sb-offset-two", "sb", 0x2000, 2, 0xDDCCBBAA, 0x11223344, 0xDD44BBAA),
    ("sb-offset-three", "sb", 0x2000, 3, 0xDDCCBBAA, 0x11223344, 0x44CCBBAA),
    ("sh-offset-zero", "sh", 0x2000, 0, 0xDDCCBBAA, 0x11223344, 0xDDCC3344),
    ("sh-offset-two", "sh", 0x2000, 2, 0xDDCCBBAA, 0x11223344, 0x3344BBAA),
    ("sw-whole-word", "sw", 0x2000, 0, 0xDDCCBBAA, 0x11223344, 0x11223344),
    # effective = 0x2010 - 15 = 0x2001: a byte store through a negative
    # displacement still lands at offset one of the aligned word.
    ("sb-negative-displacement", "sb", 0x2010, -15, 0xDDCCBBAA, 0x11223344, 0xDDCC44AA),
    # Only the LOW half of the stored register reaches memory, even when its
    # high half is all ones.
    ("sh-high-half-ignored", "sh", 0x2000, 2, 0x00000000, 0xFFFF8ABC, 0x8ABC0000),
)

#: Which byte lanes each store witness writes; the complement must survive.
_STORE_LANES = {"sb": 1, "sh": 2, "sw": 4}


def check_store_witnesses(air_ir_dir: Path) -> str:
    for name, selector, base, displacement, memory_word, stored, expected in (
        STORE_WITNESSES
    ):
        assignment, new_word = store_row(
            selector, base, displacement, memory_word, stored
        )
        if new_word != expected:
            raise WitnessError(
                f"store witness {name} computes {new_word:#010x}, "
                f"expected {expected:#010x}"
            )
        # Assert unselected-byte preservation explicitly: every byte lane the
        # store does not write must reach the expected word unchanged. This
        # guards the witness table itself; the production AIR's own C54–C57
        # are exercised by the row passing (and by the mutation battery).
        offset = (base + displacement) & 3
        written = set(range(offset, offset + _STORE_LANES[selector]))
        for lane in set(range(4)) - written:
            before = (memory_word >> (8 * lane)) & 0xFF
            after = (expected >> (8 * lane)) & 0xFF
            if before != after:
                raise WitnessError(
                    f"store witness {name} expects unselected byte {lane} to "
                    f"change from {before:#04x} to {after:#04x}; the table "
                    "no longer states preservation"
                )
        try:
            check_witness(air_ir_dir, "load_store", assignment)
        except WitnessError as error:
            raise WitnessError(f"store witness {name}: {error}") from error

    # The stored register may alias the base-address register.
    aliased, _ = store_row("sb", 0x2000, 1, 0xDDCCBBAA, 0x2000, r2=5, rs1_addr=5)
    try:
        check_witness(air_ir_dir, "load_store", aliased)
    except WitnessError as error:
        raise WitnessError(
            f"store witness stored-register-aliases-base: {error}"
        ) from error

    return (
        f"store non-vacuity: {len(STORE_WITNESSES) + 1} witnesses reachable in "
        "the exported production AIR, unselected bytes preserved at every "
        "byte and half offset"
    )


# --------------------------------------------------------------------------
# Regression for the former production load_store address-aliasing gap
# --------------------------------------------------------------------------

#: Base register value whose field-arithmetic address diverges from its
#: architectural address. Constraint root 69 must now reject this row.
ALIASING_BASE = 0x7FFFFFFB
ALIASING_DISPLACEMENT = 8


def address_aliasing_row(
    base: int = ALIASING_BASE,
    displacement: int = ALIASING_DISPLACEMENT,
    memory_word: int = 0xDEADBEEF,
    rd: int = 7,
    *,
    clock: int = 1,
    pc: int = 0x1000,
) -> tuple[dict[str, int], int, int]:
    """The historical `LW` aliasing counterexample.

    Returns the row, the architectural effective address, and the address the
    AIR's base-field sum would name without the high-base-limb bound. The AIR
    computes
    ``mem_addr = composeU32(rs1.next) + imm_felt`` in the M31 base field, not
    modulo 2^32. A base just under the field modulus plus a small displacement
    wraps the *field* and lands on a small aligned address while the
    architectural 32-bit address is somewhere else entirely. Production
    constraint root 69 now pins the base's high byte to zero on active rows,
    so this assignment is deliberately not reachable.
    """
    field_address = (base + displacement) % M31
    architectural = (base + displacement) & 0xFFFFFFFF
    memory = _limbs(memory_word)
    source = _limbs(base)

    assignment = {
        "clk": clock,
        "pc": pc,
        "rs1_addr": 5,
        "rs1_previous_clock": 0,
        "src_addr": field_address,
        "src_previous_clock": 0,
        "dst_addr": rd,
        "dst_previous_clock": 0,
        "r2_idx": rd,
        "imm_felt": displacement % M31,
        "src_msb": 0,
        "shift_amount": 0,
        "src_addr_selector": field_address,
        "dst_addr_selector": rd,
        # The markers are free bits on a word access; production leaves them
        # unconstrained there and the honest witness writes zero.
        "markers_0": 0,
        "markers_1": 0,
        "markers_2": 0,
        "markers_3": 0,
        "is_lb": 0,
        "is_lh": 0,
        "is_lbu": 0,
        "is_lhu": 0,
        "is_lw": 1,
        "is_sb": 0,
        "is_sh": 0,
        "is_sw": 0,
        "destination_nonzero": 1,
        "destination_inverse": modular_inverse(rd),
        "bus_value_56": 21,
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
        assignment[f"dst_next_{index}"] = memory[index]
        assignment[f"result_{index}"] = memory[index]
    return assignment, architectural, field_address


def check_address_aliasing_rejected(air_ir_dir: Path) -> str:
    """Require the historical aliasing row to fail at exactly the new root.

    Checking the exact refusing root makes this a regression for the source
    fix, not merely a test that some unrelated later constraint happens to
    reject a stale witness.
    """
    assignment, architectural, field_address = address_aliasing_row()
    payload = load_family(air_ir_dir, "load_store")
    values = evaluate(payload, assignment)
    unsatisfied = [
        index
        for index, root in enumerate(payload["constraints"])
        if values[root] != 0
    ]
    if unsatisfied != [69]:
        raise WitnessError(
            "the historical load_store aliasing row must be rejected by "
            f"constraint root 69 alone; observed roots {unsatisfied}"
        )
    checked = check_range_lookups(payload, values)
    if architectural == field_address:
        raise WitnessError("the aliasing row no longer diverges; update this check")
    return (
        "load_store address-aliasing regression: historical base "
        f"{ALIASING_BASE:#010x} + {ALIASING_DISPLACEMENT} is architecturally "
        f"{architectural:#010x} but would alias to {field_address:#010x} in "
        f"M31; production constraint root 69 rejects it, with {checked} active "
        "range requests otherwise valid"
    )
