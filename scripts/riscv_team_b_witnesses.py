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

if __package__:
    from .riscv_team_b_witnesses_lib.arithmetic import *
    from .riscv_team_b_witnesses_lib.core import *
    from .riscv_team_b_witnesses_lib.memory import *
    from .riscv_team_b_witnesses_lib.mutations import *
else:
    from riscv_team_b_witnesses_lib.arithmetic import *
    from riscv_team_b_witnesses_lib.core import *
    from riscv_team_b_witnesses_lib.memory import *
    from riscv_team_b_witnesses_lib.mutations import *


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
