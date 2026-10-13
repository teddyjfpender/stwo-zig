#!/usr/bin/env python3
"""Fail-closed source-order pin for the experimental CAS05 audit extractor.

This checks exact operational custody sites, not Zig semantics, Merkle
collision resistance, or Fiat-Shamir soundness. Native tests exercise the
accepted relation and hostile edits to its returned certificate.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RELATION = "src/core/pcs/paired_sparse_relation_experimental.zig"
WIRE = "src/core/pcs/paired_sparse_cascade_wire.zig"


def uncomment(source: str) -> str:
    return re.sub(r"//[^\n]*", "", source)


def ordered(source: str, markers: tuple[str, ...], errors: list[str], label: str) -> None:
    positions = [source.find(marker) for marker in markers]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append(f"{label}: missing or reordered custody marker")


def audit(sources: dict[str, str]) -> list[str]:
    errors: list[str] = []
    relation = uncomment(sources[RELATION])
    wire = uncomment(sources[WIRE])
    extractor = relation.split("pub fn verifyAndExtract(", 1)
    checker = relation.split("pub fn check(", 1)
    if len(extractor) != 2 or len(checker) != 2:
        return ["CAS05 relation checker or extractor missing"]
    ordered(
        extractor[1],
        (
            "try cascade.verifyAgainstStatement(a, proof, &staged, statement);",
            "cascade.bindVersion(&replay);",
            "const opened = try xdm.verifyAndCollect(",
            "try verifier.verify(a, rows, &columns, .{ .hash_witness = opening.hash_witness });",
            "try relation.check(a);",
            "if (!std.meta.eql(replay, staged))",
            "channel.* = staged;",
        ),
        errors,
        "extractor",
    )
    check_body = checker[1].split("\n};", 1)[0]
    for marker in (
        "for (self.raw_queries, 0..) |raw, query|",
        "for (0..h) |height|",
        "self.source.at(height, query, side, column)",
        "if (!projected.eql(expected_circle)) return error.InvalidQueryProjection;",
        "if (!folded.eql(self.forwarded[height][query])) return error.InvalidFoldRelation;",
        "return error.InvalidNormalizedFold;",
        "return error.InvalidForwardedLine;",
        "return error.InvalidTerminalRelation;",
    ):
        if marker not in check_body:
            errors.append(f"relation checker missing {marker}")
    wrapper = wire.split("pub fn verifyAndExtractRelation(", 1)
    if len(wrapper) != 2:
        errors.append("outer byte-wire extractor missing")
    else:
        ordered(
            wrapper[1],
            (
                "var decoded = try decode(allocator, encoded);",
                "defer decoded.deinit();",
                "return relation.verifyAndExtract(allocator, decoded.proof, channel, statement);",
            ),
            errors,
            "outer wire",
        )
    return errors


def main() -> int:
    errors = audit({path: (ROOT / path).read_text() for path in (RELATION, WIRE)})
    for error in errors:
        print(error)
    if errors:
        return 1
    print("CAS05 relation extractor source custody: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
