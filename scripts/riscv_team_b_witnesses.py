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

The gate runs two batteries. The witness battery proves reachability: every
honest row (each of the five load selectors LB/LH/LW/LBU/LHU, the SB/SH/SW
stores, the full DIV/DIVU/REM/REMU family, multiply, and both the immediate and
register shifts) must satisfy every production constraint root and range lookup.
The load and remainder batteries are additionally DISCRIMINATING: LB versus LBU
and LH versus LHU on the same negative datum must retire different words, and
the remainder witnesses pin the RISC-V conventions (dividend-signed remainder,
divisor-zero yields the dividend, signed overflow yields zero). The mutation
battery proves the opposite direction: each deliberately tampered row — a
clobbered unselected store byte, a byte written at the wrong offset, an unmasked
register-shift amount, a flipped or claimed sign, a relabelled selector, a REM
retiring its quotient, a remainder not below its divisor — must be REFUSED by
the production AIR. A witness gate that only proved reachability would accept an
AIR that lost a constraint.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

M31 = 2147483647

#: Repository root, derived from this file's location so the freshness guard
#: works no matter which directory the gate is invoked from.
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

#: Every Zig source that can change the exported production AIR lives under
#: this tree (the AIR components, their lookups, and the IR export tool). The
#: provenance check compares its newest mtime against the export's oldest.
AIR_SOURCE_ROOT = REPOSITORY_ROOT / "src" / "frontends" / "riscv"

#: The exact command that regenerates the exported production AIR this gate
#: reads. Failure messages quote it so a digest or shape drift tells the reader
#: what to run next instead of only what went wrong.
EXPORT_COMMAND = (
    "zig build riscv-refinement-ir -Driscv-refinement-ir-dir=zig-out/team-b-ir"
)

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

#: Lookup domains this gate deliberately does not check, with the reason. They
#: are multiset (bus) relations balanced across the whole trace — memory,
#: program and register consistency, and the preprocessed bitwise table — so a
#: single-row evaluation cannot decide them; the Lean side models them as
#: `unmodelled_bus_requests`. Every domain a family uses must appear either
#: here or in ``RANGE_DOMAINS``: an unknown domain is an ERROR, never a silent
#: skip, because a new production range table that this gate ignored would
#: quietly widen what a "reachable" witness is allowed to claim.
SKIPPED_DOMAINS: dict[str, str] = {
    "bitwise": "preprocessed AND/OR/XOR table; a trace-global lookup argument",
    "memory_access": "trace-global memory-consistency bus, not a range table",
    "program_access": "trace-global program-ROM consistency bus, not a range table",
    "registers_state": "trace-global register-file bus, not a range table",
}

#: Node operations the evaluator implements. ``audit_exported_families`` holds
#: every exported family to this set, and the test suite holds ``evaluate`` to
#: it, so the constant cannot drift from the dispatch below.
SUPPORTED_OPERATIONS = frozenset({"const", "col", "neg", "add", "sub", "mul"})


class WitnessError(RuntimeError):
    """A witness failed the production AIR. Every path out raises this."""


def modular_inverse(value: int) -> int:
    return pow(value % M31, M31 - 2, M31)


def load_family(air_ir_dir: Path, family: str) -> dict[str, Any]:
    path = air_ir_dir / f"{family}.json"
    if not path.is_file():
        raise WitnessError(f"exported AIR for {family} is absent at {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _column_drift_message(declared: set[str], assigned: set[str]) -> str:
    """Explain a witness/AIR column mismatch as new vs renamed vs removed.

    The witness builders in this file encode the column set the AIR had when
    they were written; ``declared`` is what the export has now. Diffing the two
    turns "unassigned columns" from a wall of names into a statement about what
    actually moved, which is exactly what a reader needs when Team A's AIR IR
    work or an opcode fix reshapes the exported production AIR.
    """
    missing = sorted(declared - assigned)  # in the AIR, not in the witness
    unknown = sorted(assigned - declared)  # in the witness, not in the AIR
    renamed: list[tuple[str, str]] = []
    unmatched_missing = list(missing)
    for old in unknown:
        candidates = difflib.get_close_matches(old, unmatched_missing, n=1)
        if candidates:
            renamed.append((old, candidates[0]))
            unmatched_missing.remove(candidates[0])
    renamed_old = {old for old, _ in renamed}
    added = unmatched_missing
    removed = [name for name in unknown if name not in renamed_old]

    lines = ["witness and exported AIR disagree on the column set:"]
    if missing:
        lines.append(
            "  witness leaves AIR columns unassigned: " + ", ".join(missing)
        )
    if unknown:
        lines.append(
            "  witness assigns columns the AIR does not declare: "
            + ", ".join(unknown)
        )
    if added:
        lines.append("  likely NEW in the AIR: " + ", ".join(added))
    if renamed:
        lines.append(
            "  likely RENAMED: "
            + ", ".join(f"{old} -> {new}" for old, new in renamed)
        )
    if removed:
        lines.append("  likely REMOVED from the AIR: " + ", ".join(removed))
    lines.append(
        "  likely cause: the exported production AIR changed shape (for "
        "example Team A's AIR IR v2 work or an opcode fix) while the witness "
        "builders in scripts/riscv_team_b_witnesses.py still describe the old "
        f"layout. Re-derive the export with `{EXPORT_COMMAND}`, then update "
        "the witness builders (and the Lean capsule transcription) to the new "
        "column set."
    )
    return "\n".join(lines)


def evaluate(payload: dict[str, Any], assignment: dict[str, int]) -> list[int]:
    """Evaluate the flat AIR DAG over M31 under ``assignment``."""
    declared = {column["name"] for column in payload["columns"]}
    if declared != set(assignment):
        raise WitnessError(_column_drift_message(declared, set(assignment)))

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


def _unknown_domain_error(family: str, domain: str) -> WitnessError:
    return WitnessError(
        f"family {family!r} uses lookup domain {domain!r}, which this gate "
        "does not know. It is neither a range-check domain "
        f"({', '.join(sorted(RANGE_DOMAINS))}) nor a deliberately skipped bus "
        f"domain ({', '.join(sorted(SKIPPED_DOMAINS))}). A new production "
        "lookup domain must be classified explicitly in RANGE_DOMAINS or "
        "SKIPPED_DOMAINS in scripts/riscv_team_b_witnesses.py — skipping it "
        "silently could hide an unchecked range table. If the domain is new, "
        f"re-derive the export with `{EXPORT_COMMAND}` and read "
        "src/frontends/riscv/air/lookups/ for what the domain provides."
    )


def check_range_lookups(payload: dict[str, Any], values: list[int]) -> int:
    """Every requested range-check tuple must exist in its production table.

    Domains are classified before activity is considered: an unknown domain is
    an error even on a row where the request is inactive, because
    classification is a property of the AIR's shape, not of one witness.
    """
    checked = 0
    for index, lookup in enumerate(payload["lookups"]):
        domain = lookup["domain"]
        widths = RANGE_DOMAINS.get(domain)
        if widths is None:
            if domain not in SKIPPED_DOMAINS:
                raise _unknown_domain_error(payload.get("family", "?"), domain)
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
    try:
        values = evaluate(payload, assignment)
        check_constraints(payload, values)
        checked = check_range_lookups(payload, values)
    except WitnessError as error:
        raise WitnessError(
            f"family {family!r} rejected the witness: {error}\n"
            "  If this appeared after the production AIR moved (Team A AIR IR "
            "work, an opcode fix), the witness builders here lag the export. "
            f"Re-derive it with `{EXPORT_COMMAND}` and diff "
            f"zig-out/team-b-ir/{family}.json against the previous export."
        ) from error
    return (
        f"{family}: {len(payload['constraints'])} constraints satisfied, "
        f"{checked} active range requests inside their production tables"
    )


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


# --------------------------------------------------------------------------
# Family-agnostic schema audit of the whole export
# --------------------------------------------------------------------------


def audit_exported_families(air_ir_dir: Path) -> str:
    """Audit every exported family JSON against what this gate can evaluate.

    Family-agnostic on purpose: it reads whatever families the export
    contains, so a brand-new family, node operation, or lookup domain arriving
    in production fails here by name instead of being silently outside the
    witness gate's vocabulary. Three properties are enforced:

    * every node operation present is one the evaluator implements;
    * every lookup domain present is classified — range-checked via
      ``RANGE_DOMAINS`` or deliberately skipped via ``SKIPPED_DOMAINS``;
    * no lookup domain is silently ignored (the unknown-domain path raises).
    """
    paths = sorted(air_ir_dir.glob("*.json"))
    if not paths:
        raise WitnessError(
            f"no exported AIR families found in {air_ir_dir}; "
            f"re-derive the export with `{EXPORT_COMMAND}`"
        )
    range_checked: set[str] = set()
    skipped: set[str] = set()
    for path in paths:
        payload = json.loads(path.read_text(encoding="utf-8"))
        family = payload.get("family", path.stem)
        operations = {node["op"] for node in payload["nodes"]}
        unsupported = operations - SUPPORTED_OPERATIONS
        if unsupported:
            raise WitnessError(
                f"family {family!r} uses node operations the evaluator does "
                f"not implement: {', '.join(sorted(unsupported))} (supported: "
                f"{', '.join(sorted(SUPPORTED_OPERATIONS))}). The evaluator "
                "in scripts/riscv_team_b_witnesses.py must learn them before "
                "any witness verdict on this family can be trusted."
            )
        for lookup in payload["lookups"]:
            domain = lookup["domain"]
            if domain in RANGE_DOMAINS:
                range_checked.add(domain)
            elif domain in SKIPPED_DOMAINS:
                skipped.add(domain)
            else:
                raise _unknown_domain_error(family, domain)
    return (
        f"schema audit: {len(paths)} exported families use only supported "
        f"node operations; {len(range_checked)} lookup domains range-checked, "
        f"{len(skipped)} deliberately skipped bus domains, none ignored"
    )


# --------------------------------------------------------------------------
# Export provenance: what exactly is this gate evaluating, and is it fresh?
# --------------------------------------------------------------------------


def export_digest(air_ir_dir: Path) -> str:
    """A single digest over every exported family, in name order."""
    paths = sorted(air_ir_dir.glob("*.json"))
    if not paths:
        raise WitnessError(
            f"no exported AIR families found in {air_ir_dir}; "
            f"re-derive the export with `{EXPORT_COMMAND}`"
        )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def check_export_provenance(
    air_ir_dir: Path, source_root: Path | None = None
) -> str:
    """Digest the export being evaluated and refuse a stale one.

    Every verdict this gate emits is a statement about the bytes in
    ``air_ir_dir``, not about the Zig source tree — so a stale local export
    would let every check pass against an AIR that no longer ships. Two
    defenses: the report always carries the export's digest (so a human can
    tie a log line to exact bytes), and any AIR source file newer than the
    export fails the gate with the re-derivation command.
    """
    digest = export_digest(air_ir_dir)
    paths = sorted(air_ir_dir.glob("*.json"))
    export_oldest = min(path.stat().st_mtime_ns for path in paths)

    root = AIR_SOURCE_ROOT if source_root is None else source_root
    if not root.is_dir():
        raise WitnessError(
            f"cannot establish export freshness: the AIR source tree is "
            f"absent at {root}. Run this gate from a checkout that contains "
            "the production AIR sources, or fix AIR_SOURCE_ROOT."
        )
    sources = list(root.rglob("*.zig"))
    if not sources:
        raise WitnessError(
            f"cannot establish export freshness: no Zig sources under {root}"
        )
    newest = max(sources, key=lambda path: path.stat().st_mtime_ns)
    if newest.stat().st_mtime_ns > export_oldest:
        raise WitnessError(
            f"the export in {air_ir_dir} is STALE: "
            f"{newest.relative_to(root)} is newer than the oldest exported "
            "family, so this gate would evaluate an AIR that may no longer "
            f"ship. Re-derive the export with `{EXPORT_COMMAND}`."
        )
    return (
        f"export provenance: {len(paths)} families, sha256 {digest[:16]}; "
        "no production AIR source is newer than the export"
    )


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


CHECKS = (
    check_export_provenance,
    audit_exported_families,
    check_lh_witnesses,
    check_load_witnesses,
    check_div_witnesses,
    check_rem_witnesses,
    check_multiply_witnesses,
    check_shift_witnesses,
    check_register_shift_witnesses,
    check_store_witnesses,
    check_mutation_refusals,
    check_address_aliasing_rejected,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--air-ir-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        for check in CHECKS:
            print(check(args.air_ir_dir))
    except WitnessError as error:
        print(f"witness gate failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
