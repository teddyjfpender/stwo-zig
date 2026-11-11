#!/usr/bin/env python3
"""Read the frozen OP PC census; never executes a block or claims a speedup."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

SELECTED_ELF = "72c234488ca510aa864d0bae8d86d4001f5ccd30993be1883bafb3baabc3e930"
# Bound to this exact ELF's disassembly, not portable guesses for future guests.
LINE_ENTRY = 0x1AC344
LINE_END = 0x1AC90C
SERVICE_PC = 0x1AC720


# Validation-only extraction from retired profile CLI (2b16da21b). The frozen
# census needs complete source accounting, not its classifier/report launcher.
def require(condition, message):
    if not condition:
        raise ValueError(message)


def uint(value, message):
    require(type(value) is int and 0 <= value < 1 << 64, message)
    return value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def functions(raw):
    """Read defined nonempty STT_FUNC ranges from a static ELF64 RISC-V image."""
    require(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01', 'Expected ELF64 little endian')
    require(struct.unpack_from('<HH', raw, 16) == (2, 243), 'Expected RISC-V ET_EXEC')
    shoff = struct.unpack_from('<Q', raw, 40)[0]
    stride, count = struct.unpack_from('<HH', raw, 58)
    require(stride >= 64 and count > 0 and shoff + stride * count <= len(raw), 'Invalid ELF section table')
    sections = [struct.unpack_from('<IIQQQQIIQQ', raw, shoff + i * stride) for i in range(count)]
    tables = [s for s in sections if s[1] == 2]
    require(tables, 'ELF has no static symbol table')
    result = set()
    for section in tables:
        offset, size, link, entry = section[4], section[5], section[6], section[9]
        require(entry >= 24 and size % entry == 0 and offset + size <= len(raw) and link < count,
                'Invalid ELF symbol table')
        strings = sections[link]
        require(strings[1] == 3 and strings[4] + strings[5] <= len(raw), 'Invalid symbol strings')
        names = raw[strings[4]:strings[4] + strings[5]]
        for pos in range(offset, offset + size, entry):
            name, info, _, index, address, length = struct.unpack_from('<IBBHQQ', raw, pos)
            if info & 15 != 2 or index == 0 or length == 0:
                continue
            require(index < count and sections[index][2] & 4, 'Function is outside executable section')
            require(address + length <= 1 << 64, 'Function address overflow')
            owner = sections[index]
            require(owner[3] <= address and address + length <= owner[3] + owner[5],
                    'Function range exceeds executable section')
            require(name < len(names), 'Invalid function name offset')
            end = names.find(b'\0', name)
            require(end >= 0, 'Unterminated function name')
            label = names[name:end].decode('utf-8', errors='strict')
            require(bool(label), 'Empty function name')
            result.add((address, length, label))
    return sorted(result)


def validate_complete_profile(execution, elf_raw):
    require(execution.get('status') == 'completed' and execution.get('verified_output') is True,
            'A completed execution with verified_output=true is required')
    require(execution.get('elf_sha256') == sha(elf_raw), 'Execution ELF SHA256 differs')
    retired = uint(execution.get('instructions'), 'Invalid retired instruction total')
    require(retired > 0, 'Empty execution')
    profile = execution.get('pc_profile')
    require(isinstance(profile, dict), 'Missing dense pc_profile')
    start = uint(profile.get('start'), 'Invalid profile start')
    end = uint(profile.get('end'), 'Invalid profile end')
    require(start < end and start % 4 == end % 4 == 0 and end - start <= 8 * 1024 * 1024,
            'Invalid aligned profile range (maximum 8MiB)')
    counts = profile.get('counts')
    require(isinstance(counts, list) and len(counts) == (end - start) // 4, 'Profile count geometry differs')
    for count in counts:
        uint(count, 'Invalid instruction count')
    require(uint(profile.get('outside'), 'Missing or invalid outside count') == 0,
            'Profile has retired instructions outside its range')
    require(sum(counts) == retired, 'Profile counts do not account for all retirements')
    functions(elf_raw)


def model(execution, elf):
    if hashlib.sha256(elf).hexdigest() != SELECTED_ELF:
        raise ValueError("unsupported frozen guest: regenerate PC authority")
    # Checks complete coverage, ELF identity, instruction sum and symbol ranges.
    validate_complete_profile(execution, elf)
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
