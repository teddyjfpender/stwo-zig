#!/usr/bin/env python3
"""Attribute an execution-only PC census to its exact ELF32 function symbols.

Checks every instruction word against executable ELF bytes. This reports
execution frequencies, never a STARK, proof qualification or proving latency.
"""
from __future__ import annotations
import argparse
import bisect
import collections
import csv
import hashlib
import json
from pathlib import Path
import struct


def uint(value: object, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("noncanonical census integer")
    return value


def section(elf: bytes, offset: int, size: int) -> bytes:
    if offset < 0 or size < 0 or offset > len(elf) or size > len(elf) - offset:
        raise ValueError("ELF section exceeds file")
    return elf[offset:offset + size]


def elf_functions(elf: bytes) -> tuple[list[dict], list[tuple[int, bytes]]]:
    if len(elf) < 52 or elf[:7] != b"\x7fELF\x01\x01\x01" or struct.unpack_from("<H", elf, 18)[0] != 243:
        raise ValueError("expected little-endian ELF32 RISC-V")
    offset = struct.unpack_from("<I", elf, 32)[0]
    stride, count = struct.unpack_from("<HH", elf, 46)
    if stride != 40 or count == 0:
        raise ValueError("unsupported ELF section table")
    table = section(elf, offset, stride * count)
    headers = [struct.unpack_from("<10I", table, stride * i) for i in range(count)]
    executable = [(h[3], section(elf, h[4], h[5])) for h in headers if h[1] == 1 and h[2] & 4]
    by_range: dict[tuple[int, int], set[str]] = collections.defaultdict(set)
    for h in headers:
        if h[1] != 2:
            continue
        if h[6] >= count or h[9] != 16 or h[5] % 16:
            raise ValueError("invalid ELF symbol table")
        strings_header = headers[h[6]]
        if strings_header[1] != 3:
            raise ValueError("symbol names do not reference a string table")
        strings = section(elf, strings_header[4], strings_header[5])
        symbols = section(elf, h[4], h[5])
        for i in range(0, len(symbols), 16):
            name, address, size, info, _, index = struct.unpack_from("<IIIBBH", symbols, i)
            if info & 15 != 2 or not size or index == 0:
                continue
            if index >= count or not headers[index][2] & 4 or address + size > 1 << 32 or name >= len(strings):
                raise ValueError("invalid executable function symbol")
            end = strings.find(b"\0", name)
            if end < 0:
                raise ValueError("unterminated function name")
            text = strings[name:end].decode("utf-8")
            by_range[address, size].add(text)
    functions = [dict(address=address, size=size, name=sorted(names)[0], aliases=sorted(names)) for (address, size), names in sorted(by_range.items())]
    # Equal-address aliases are coalesced. Overlapping distinct function ranges
    # would make a nearest-start attribution ambiguous; fail instead of guessing.
    for previous, current in zip(functions, functions[1:]):
        if previous["address"] + previous["size"] > current["address"]:
            raise ValueError("overlapping distinct function ranges")
    return functions, executable


def attribute(census: dict, elf: bytes, source_sha256: str) -> dict:
    elf_sha256 = hashlib.sha256(elf).hexdigest()
    if census.get("elf_sha256") != elf_sha256 or census.get("proof_verified", False) is not False:
        raise ValueError("census ELF mismatch or inappropriate proof claim")
    if census.get("schema") not in {"stwo-b8-real-window-pc-census-v1", "stwo-b8-full-execution-pc-census-v1"}:
        raise ValueError("unsupported execution-only census")
    functions, executable = elf_functions(elf)
    starts = [f["address"] for f in functions]
    counts: collections.Counter[int] = collections.Counter()
    total = 0
    seen: set[int] = set()
    rows = census.get("pcs")
    if not isinstance(rows, list) or not rows:
        raise ValueError("missing PC observations")
    for row in rows:
        pc = uint(row["pc"], (1 << 32) - 1)
        word = uint(row["instruction_word"], (1 << 32) - 1)
        frequency = uint(row["count"], (1 << 64) - 1)
        if pc & 3 or pc in seen or frequency == 0:
            raise ValueError("duplicate, unaligned or empty PC observation")
        seen.add(pc)
        matching = [data[pc - address:pc - address + 4] for address, data in executable if address <= pc and pc + 4 <= address + len(data)]
        if len(matching) != 1 or int.from_bytes(matching[0], "little") != word:
            raise ValueError("observed instruction differs from executable ELF")
        index = bisect.bisect_right(starts, pc) - 1
        if index < 0 or pc >= functions[index]["address"] + functions[index]["size"]:
            index = -1
        counts[index] += frequency
        total += frequency
    if total != uint(census["core_rows"], (1 << 64) - 1):
        raise ValueError("PC count does not equal declared core rows")
    ranked = []
    for index, frequency in counts.most_common():
        description = functions[index] if index != -1 else dict(name="unattributed", aliases=[], address=None, size=None)
        ranked.append(dict(**description, core_rows=frequency, share=frequency / total))
    return dict(schema="stwo-b8-exact-elf-pc-function-attribution-v1", scope=census["scope"], proof_verified=False,
                source_sha256=source_sha256, elf_sha256=elf_sha256, cycles=census["cycles"], core_rows=total,
                external_retirements=census.get("external_retirements", 0), distinct_pcs=len(rows), functions=ranked)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument("--elf", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--csv", type=Path)
    args = parser.parse_args()
    source = args.census.read_bytes()
    report = attribute(json.loads(source), args.elf.read_bytes(), hashlib.sha256(source).hexdigest())
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.csv:
        with args.csv.open("w", newline="") as target:
            writer = csv.DictWriter(target, fieldnames=["address", "size", "name", "core_rows", "share"])
            writer.writeheader()
            for row in report["functions"]:
                writer.writerow({name: row[name] for name in writer.fieldnames})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
