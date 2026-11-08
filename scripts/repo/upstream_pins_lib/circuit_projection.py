"""The constraints-only projection of the compiled circuit and Cairo AIRs.

`vectors/circuit/official/compiled_air_constraints_v1.bin` (oracle `project-air`, rung R3): a
string table, a header, and per source the slot names and one digest-carrying record per
evaluation function. `parse_projection` decodes the v2 grammar and checks every record digest;
`circuit_recursion.py` authenticates the committed file with it.
"""

from __future__ import annotations

import hashlib
import struct

PROJECTION_MAGIC = b"STWOCAIR"
PROJECTION_VERSION = 2


class ProjectionError(ValueError):
    """The projection does not follow the documented v1 grammar."""


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0
        self.strings: list[str] = []
        # While a function record is read, the canonical record: the same bytes with every string
        # written inline (`u32:len utf8`) instead of as a table index.
        self.canonical: bytearray | None = None

    def _take(self, size: int) -> bytes:
        end = self.position + size
        if end > len(self.data):
            raise ProjectionError(f"truncated at byte {self.position}")
        chunk = self.data[self.position:end]
        self.position = end
        return chunk

    def take(self, size: int) -> bytes:
        chunk = self._take(size)
        if self.canonical is not None:
            self.canonical += chunk
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def string(self) -> str:
        index = struct.unpack("<I", self._take(4))[0]
        if index >= len(self.strings):
            raise ProjectionError(f"string index {index} out of range")
        value = self.strings[index]
        if self.canonical is not None:
            encoded = value.encode("utf-8")
            self.canonical += struct.pack("<I", len(encoded)) + encoded
        return value

    def many(self, item):
        return [item() for _ in range(self.u32())]

    def optional(self, item):
        flag = self.u8()
        if flag not in (0, 1):
            raise ProjectionError(f"invalid option flag {flag}")
        return item() if flag else None

    def use_or_yield(self) -> str:
        value = self.u8()
        if value not in (0, 1):
            raise ProjectionError(f"invalid use_or_yield {value}")
        return "Use" if value == 0 else "Yield"

    def expr(self) -> None:
        tag = self.u8()
        if tag == 0:
            if self.u32() >= 2**31 - 1:
                raise ProjectionError("non-canonical M31 constant")
        elif tag in (1, 2, 7, 8):
            self.string()
        elif tag == 3:
            if self.u8() not in (0, 1, 2):
                raise ProjectionError("invalid binary operator")
            self.expr()
            self.expr()
        elif tag == 4:
            if self.u8() != 1:
                raise ProjectionError("invalid unary operator")
            self.expr()
        elif tag == 5:
            self.string()
            self.many(self.expr)
        elif tag == 6:
            self.many(self.expr)
        elif tag != 9:
            raise ProjectionError(f"invalid expression tag {tag}")

    def step(self) -> None:
        tag = self.u8()
        if tag == 0:
            self.expr()
        elif tag == 1:
            self.many(self.string)
            self.expr()
        elif tag == 2:
            self.string()
            self.use_or_yield()
            self.many(self.expr)
            self.expr()
        else:
            raise ProjectionError(f"invalid step tag {tag}")

    def record(self) -> str:
        name = self.string()
        self.string()
        self.optional(self.u32)
        for _ in range(2):
            self.many(self.string)
        self.many(lambda: (self.string(), self.use_or_yield()))
        for _ in range(4):
            self.many(self.string)
        self.many(self.step)
        self.optional(self.expr)
        return name


def parse_projection(data: bytes) -> dict:
    """Decodes a v2 projection, verifying every record digest; returns its header summary.

    A function digest is `SHA-256(canonical(record))`: the record with every string inline, so
    that it does not depend on the order of the file's string table.
    """
    reader = _Reader(data)
    if reader.take(8) != PROJECTION_MAGIC:
        raise ProjectionError("bad magic")
    if reader.u32() != PROJECTION_VERSION:
        raise ProjectionError("unsupported version")
    for _ in range(reader.u32()):
        reader.strings.append(reader.take(reader.u32()).decode("utf-8"))
    summary = {
        "revision": reader.string(),
        "inputs_sha256": reader.string(),
        "constants": dict(reader.many(lambda: (reader.string(), reader.u32()))),
        "sources": {},
    }
    for _ in range(reader.u32()):
        label = reader.string()
        slots = reader.many(reader.string)
        hand_written = reader.many(reader.string)
        functions = []
        digest_offsets = []
        for _ in range(reader.u32()):
            length = reader.u32()
            digest_offsets.append(reader.position)
            digest = reader.take(32)
            start = reader.position
            if start + length > len(data):
                raise ProjectionError(f"truncated at byte {start}")
            reader.canonical = bytearray()
            functions.append(reader.record())
            canonical, reader.canonical = bytes(reader.canonical), None
            if reader.position != start + length:
                raise ProjectionError(f"{label}: record {functions[-1]} length mismatch")
            if hashlib.sha256(canonical).digest() != digest:
                raise ProjectionError(f"{label}: record at byte {start} has a bad digest")
        summary["sources"][label] = {
            "slots": slots,
            "hand_written": hand_written,
            "functions": functions,
            "digest_offsets": digest_offsets,
        }
    if reader.position != len(data):
        raise ProjectionError("trailing bytes")
    return summary
