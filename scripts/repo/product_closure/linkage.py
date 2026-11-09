"""Final binary linkage and static ELF inspection for focused products."""

from __future__ import annotations

import hashlib
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class LinkageError(ValueError):
    pass


@dataclass(frozen=True)
class DynamicLinkage:
    inspector: str
    output: str


@dataclass(frozen=True)
class ElfIdentity:
    bits: int
    machine: str
    has_interpreter: bool


MACHINES = {
    3: "x86",
    40: "arm",
    62: "x86_64",
    183: "aarch64",
    243: "riscv",
}


def inspect_dynamic(binary: Path) -> DynamicLinkage:
    if not binary.is_file():
        raise LinkageError(f"binary does not exist: {binary}")
    if sys.platform == "darwin":
        tool = shutil.which("otool")
        args = [tool, "-L", str(binary)] if tool else None
    elif sys.platform.startswith("linux"):
        tool = shutil.which("readelf")
        args = [tool, "-d", str(binary)] if tool else None
        if args is None:
            tool = shutil.which("ldd")
            args = [tool, str(binary)] if tool else None
    else:
        raise LinkageError(f"unsupported linkage-inspection host: {sys.platform}")
    if args is None or tool is None:
        raise LinkageError("required dynamic-linkage inspector is unavailable")
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip()
        raise LinkageError(f"dynamic-linkage inspection failed: {diagnostic}")
    return DynamicLinkage(inspector=Path(tool).name, output=result.stdout)


def check_dynamic(
    linkage: DynamicLinkage,
    required: tuple[str, ...],
    forbidden: tuple[str, ...],
) -> list[str]:
    lowered = linkage.output.lower()
    errors = [
        f"binary is missing required dynamic dependency {token!r}"
        for token in required
        if token.lower() not in lowered
    ]
    errors.extend(
        f"binary links forbidden dynamic dependency {token!r}"
        for token in forbidden
        if token.lower() in lowered
    )
    return errors


def inspect_elf(binary: Path) -> ElfIdentity:
    data = binary.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise LinkageError(f"static artifact is not ELF: {binary}")
    elf_class = data[4]
    byte_order = data[5]
    endian = "<" if byte_order == 1 else ">" if byte_order == 2 else None
    if endian is None or elf_class not in (1, 2):
        raise LinkageError("unsupported ELF class or byte order")
    bits = 32 if elf_class == 1 else 64
    machine_number = struct.unpack_from(endian + "H", data, 18)[0]
    machine = MACHINES.get(machine_number, f"machine-{machine_number}")
    if bits == 64:
        program_offset = struct.unpack_from(endian + "Q", data, 32)[0]
        entry_size = struct.unpack_from(endian + "H", data, 54)[0]
        entry_count = struct.unpack_from(endian + "H", data, 56)[0]
    else:
        program_offset = struct.unpack_from(endian + "I", data, 28)[0]
        entry_size = struct.unpack_from(endian + "H", data, 42)[0]
        entry_count = struct.unpack_from(endian + "H", data, 44)[0]
    if entry_count and entry_size < 4:
        raise LinkageError("invalid ELF program-header size")
    end = program_offset + entry_size * entry_count
    if end > len(data):
        raise LinkageError("ELF program-header table exceeds artifact")
    has_interpreter = any(
        struct.unpack_from(endian + "I", data, program_offset + index * entry_size)[0] == 3
        for index in range(entry_count)
    )
    return ElfIdentity(bits=bits, machine=machine, has_interpreter=has_interpreter)


def check_static_elf(identity: ElfIdentity, machine: str, bits: int) -> list[str]:
    errors: list[str] = []
    if identity.machine != machine:
        errors.append(
            f"static ELF machine is {identity.machine!r}, expected {machine!r}"
        )
    if identity.bits != bits:
        errors.append(f"static ELF class is {identity.bits}, expected {bits}")
    if identity.has_interpreter:
        errors.append("static ELF contains a PT_INTERP program header")
    return errors


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
