"""Deterministic RV32 ELF construction for the release trace corpus."""

from __future__ import annotations

import struct

CODE_VADDR = 0x0001_0000
INPUT_START = 0x0010_0000
INPUT_END = INPUT_START
HALT_FLAG = 0x0010_0000
OUTPUT_LEN = 0x0010_0004
OUTPUT_DATA = 0x0010_0008
STACK_BOTTOM = 0x001F_FC00
STACK_TOP = 0x0020_0000
GLOBAL_POINTER = 0x0020_0800
OUTPUT_END = STACK_BOTTOM


def build_elf_with_symbols(
    instructions: list[int],
    symbols: dict[str, int],
) -> bytes:
    """Build a minimal RV32 ELF with a linker-symbol table."""
    code = b"".join(struct.pack("<I", inst) for inst in instructions)
    e_phoff = 52
    code_off = 52 + 32

    strtab = b"\x00"
    name_offsets = {}
    for name in symbols:
        name_offsets[name] = len(strtab)
        strtab += name.encode() + b"\x00"
    symtab = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    for name, value in symbols.items():
        symtab += struct.pack(
            "<IIIBBH",
            name_offsets[name],
            value,
            0,
            0x10,
            0,
            0xFFF1,
        )

    shstrtab = b"\x00.symtab\x00.strtab\x00.shstrtab\x00"
    symtab_off = code_off + len(code)
    strtab_off = symtab_off + len(symtab)
    shstrtab_off = strtab_off + len(strtab)
    shoff = shstrtab_off + len(shstrtab)

    def shdr(name_off, sh_type, offset, size, link, info, entsize):
        return struct.pack(
            "<IIIIIIIIII",
            name_off,
            sh_type,
            0,
            0,
            offset,
            size,
            link,
            info,
            1,
            entsize,
        )

    sections = b"".join(
        [
            shdr(0, 0, 0, 0, 0, 0, 0),
            shdr(1, 2, symtab_off, len(symtab), 2, 1, 16),
            shdr(9, 3, strtab_off, len(strtab), 0, 0, 0),
            shdr(17, 3, shstrtab_off, len(shstrtab), 0, 0, 0),
        ]
    )
    header = struct.pack(
        "<4sBBBBB7xHHIIIIIHHHHHH",
        b"\x7fELF",
        1,
        1,
        1,
        0,
        0,
        2,
        0xF3,
        1,
        CODE_VADDR,
        e_phoff,
        shoff,
        0,
        52,
        32,
        1,
        40,
        4,
        3,
    )
    phdr = struct.pack(
        "<IIIIIIII",
        1,
        code_off,
        CODE_VADDR,
        CODE_VADDR,
        len(code),
        len(code),
        0,
        0,
    )
    return header + phdr + code + symtab + strtab + shstrtab + sections


def build_elf(instructions: list[int]) -> bytes:
    """Build the no-symbol RV32 ELF retained for an ABI-negative diagnostic."""
    code = b"".join(struct.pack("<I", inst) for inst in instructions)
    e_phoff = 52
    code_off = 52 + 32
    header = struct.pack(
        "<4sBBBBB7xHHIIIIIHHHHHH",
        b"\x7fELF",
        1,
        1,
        1,
        0,
        0,
        2,
        0xF3,
        1,
        CODE_VADDR,
        e_phoff,
        0,
        0,
        52,
        32,
        1,
        0,
        0,
        0,
    )
    phdr = struct.pack(
        "<IIIIIIII",
        1,
        code_off,
        CODE_VADDR,
        CODE_VADDR,
        len(code),
        len(code),
        0,
        0,
    )
    return header + phdr + code


def release_symbols(instructions: list[int]) -> dict[str, int]:
    """Return the explicit zkVM linker contract for a corpus program."""
    return {
        "__text_start": CODE_VADDR,
        "__text_len": len(instructions) * 4,
        "__data_start": STACK_TOP,
        "__data_len": 0,
        "__global_pointer$": GLOBAL_POINTER,
        "__stack_bottom": STACK_BOTTOM,
        "__stack_top": STACK_TOP,
        "__input_start": INPUT_START,
        "__input_end": INPUT_END,
        "__halt_flag": HALT_FLAG,
        "__output_len": OUTPUT_LEN,
        "__output_data": OUTPUT_DATA,
        "__output_end": OUTPUT_END,
    }


def build_release_elf(instructions: list[int]) -> bytes:
    """Build a symbol-bearing ELF with the complete release I/O ABI."""
    return build_elf_with_symbols(instructions, release_symbols(instructions))
