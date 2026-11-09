#!/usr/bin/env python3
"""Read the frozen OP PC census; never executes a block or claims a speedup."""
import argparse
import hashlib
import json
from pathlib import Path
from scripts.riscv64_ethereum_profile import build

SELECTED_ELF = "72c234488ca510aa864d0bae8d86d4001f5ccd30993be1883bafb3baabc3e930"
# Bound to this exact ELF's disassembly, not portable guesses for future guests.
LINE_ENTRY = 0x1AC344
LINE_END = 0x1AC90C
SERVICE_PC = 0x1AC720


def model(execution, elf):
    if hashlib.sha256(elf).hexdigest() != SELECTED_ELF:
        raise ValueError("unsupported frozen guest: regenerate PC authority")
    # Checks complete coverage, ELF identity, instruction sum and symbol ranges.
    build(execution, elf)
    profile = execution["pc_profile"]

    def count(pc):
        if not profile["start"] <= pc < profile["end"]:
            raise ValueError("profile omits required PC")
        return profile["counts"][(pc - profile["start"]) // 4]

    batches = count(LINE_ENTRY)
    calls = count(SERVICE_PC)
    if calls != execution["op_sparse034_calls"] or not 0 < batches <= calls:
        raise ValueError("service/line census disagrees")
    # Twelve Fq coordinates, four words each. Copy in/out each requires a load
    # and store. An all-skipped evaluation has no packet, hence entry count is
    # an UPPER bound on packets and the removed copy-work bound is conservative.
    copies = 12 * 4 * 2 * 2
    return {
        "elf_sha256": SELECTED_ELF,
        "instructions": execution["instructions"],
        "full_profile_retirements": sum(profile["counts"]),
        "outside_profile": profile["outside"],
        "line_evaluations": batches,
        "primitive_calls": calls,
        "wrapper_self_instructions": sum(count(pc) for pc in range(LINE_ENTRY, LINE_END, 4)),
        "old_accumulator_copy_instructions": copies * calls,
        "maximum_new_accumulator_copy_instructions": copies * batches,
        "removed_copy_instruction_lower_bound": copies * (calls - batches),
        "limit": "Copy-work model only; excludes changed loop codegen, padding and proving cost. No heavy candidate execution.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    result = model(json.loads(args.execution.read_text()), args.elf.read_bytes())
    result["execution_sha256"] = hashlib.sha256(args.execution.read_bytes()).hexdigest()
    args.report.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
