"""Construction and exact executed-opcode accounting for the release corpus."""

from __future__ import annotations

import subprocess
from pathlib import Path

EXPECTED_PROOF_OPCODE_IDS = frozenset(range(46))


def branch_fib_program(addi, add, blt, beq, bne, bge, bltu, bgeu, epilogue):
    """Build fib(24) plus signed/unsigned taken and fallthrough branch edges."""
    return [
        addi(1, 0, 0),
        addi(2, 0, 1),
        addi(3, 0, 0),
        addi(4, 0, 24),
        add(5, 1, 2),
        addi(1, 2, 0),
        addi(2, 5, 0),
        addi(3, 3, 1),
        blt(3, 4, -16),
        beq(1, 2, 8),
        addi(6, 0, 1),
        addi(7, 0, -1),
        addi(8, 0, 1),
        bne(7, 8, 8),  # taken: -1 != 1
        addi(10, 0, 99),
        bne(8, 8, 8),  # not taken: 1 == 1
        addi(10, 0, 1),
        bge(7, 8, 8),  # not taken: signed -1 < 1
        addi(11, 0, 1),
        bge(8, 7, 8),  # taken: signed 1 >= -1
        addi(11, 0, 99),
        bltu(7, 8, 8),  # not taken: UINT_MAX > 1
        addi(12, 0, 1),
        bltu(8, 7, 8),  # taken: unsigned 1 < UINT_MAX
        addi(12, 0, 99),
        bgeu(7, 8, 8),  # taken: UINT_MAX >= 1
        addi(13, 0, 99),
        bgeu(8, 7, 8),  # not taken: unsigned 1 < UINT_MAX
        addi(13, 0, 1),
    ] + epilogue


def executed_opcode_ids(
    dumper: Path, elf_path: Path, trace: dict, root: Path
) -> list[int]:
    """Map executed PCs to proof IDs emitted by the production program decoder."""
    output = subprocess.run(
        [str(dumper), "--program-tuples", str(elf_path)],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    by_pc = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 5:
            raise ValueError(f"malformed program tuple line: {line!r}")
        by_pc[int(fields[0], 16)] = int(fields[1])
    try:
        return sorted({by_pc[row["pc"]] for row in trace["retirements"]})
    except KeyError as error:
        raise ValueError(
            f"executed PC has no declared program tuple: {error.args[0]:#x}"
        ) from error
