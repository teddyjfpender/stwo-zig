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
BATCH = "src/core/pcs/transposed_paired_sparse.zig"
CASCADE = "src/core/pcs/paired_sparse_cascade_experimental.zig"
INSERTION = "src/core/pcs/paired_cascade_experimental.zig"


def uncomment(source: str) -> str:
    return re.sub(r"//[^\n]*", "", source)


def ordered(source: str, markers: tuple[str, ...], errors: list[str], label: str) -> None:
    positions = [source.find(marker) for marker in markers]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        errors.append(f"{label}: missing or reordered custody marker")


def function(source: str, signature: str, errors: list[str]) -> str:
    """Select one actual Zig function body, excluding comments and later code."""
    source = uncomment(source)
    if source.count(signature) != 1:
        errors.append(f"missing or duplicated native function {signature}")
        return ""
    opening = source.find("{", source.index(signature) + len(signature))
    if opening < 0:
        errors.append(f"incomplete native function {signature}")
        return ""
    start = opening + 1
    depth = 1
    for end in range(start, len(source)):
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
            if depth == 0:
                return source[start:end]
    errors.append(f"incomplete native function {signature}")
    return ""


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
    normalized_start = check_body.find("const normalized_inserted = try pair(")
    normalized_body = check_body[normalized_start:] if normalized_start >= 0 else ""
    ordered(normalized_body, (
        "const normalized_inserted = try pair(",
        "try inserted_even.div(scale),",
        "try inserted_odd.div(scale),",
        "const carried = try pair(",
        "try previous[query * 2].div(scale),",
        "try previous[query * 2 + 1].div(scale),",
        "break :blk half.mul(carried)",
        ".add(self.alphas[height].square().mul(half.mul(normalized_inserted)));",
        "if (!folded.eql(two.mul(scale).mul(normalized)))",
        "scale = scale.mul(two);",
    ), errors, "normalized Protocol 3 row")
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
    # The Lean PairedProtocolRecurrence model is conditional field algebra.
    # These checks pin the *operational* challenge-power roster and native
    # recurrence that the model describes, without claiming Zig semantics or
    # a polynomial/proximity theorem.
    batch = function(sources[BATCH], "pub fn fromVerifiedOpenings(", errors)
    ordered(batch, (
        "if (raw_queries.len != profile.query_count or claims.len != profile.height_count)",
        "for (claims, 0..) |height_claims, height| {",
        "for (height_claims, coefficients, powers) |claim, *coefficient, *pair| {",
        "coefficient.* = try constraints.complexConjugateLineCoeffs(point, claim, QM31.one());",
        "pair[0] = power;",
        "power = power.mul(batch);",
        "pair[1] = power;",
        "const original = opened.at(height, query, j, col);",
        "const numerator = coefficient.c.mulM31(original)",
        "const quotient = numerator.mulCM31(inverse);",
        "answer = answer.add(pair[0].mul(QM31.fromBase(original)))",
        ".add(pair[1].mul(quotient));",
    ), errors, "original/own-quotient batch")
    advances = [m.start() for m in re.finditer(re.escape("power = power.mul(batch);"), batch)]
    quotient_power = batch.find("pair[1] = power;")
    if len(advances) != 2 or not advances[0] < quotient_power < advances[1]:
        errors.append("original/own-quotient batch: each word must advance one power")
    cascade = function(sources[CASCADE], "pub fn verifyAgainstStatement(", errors)
    ordered(cascade, (
        "const batch = drawBatchAfterOod(&staged, proof.claims);",
        "const raw = try queries.drawQueries(",
        "var opened = try xdm.verifyAndCollect(",
        "var answers = try paired.fromVerifiedOpenings(",
        "try verifyFolds(allocator, proof, raw, answers.values, alphas);",
        "channel.* = staged;",
    ), errors, "authenticated batch admission")
    folds = function(sources[CASCADE], "fn verifyFolds(", errors)
    ordered(folds, (
        "try verifier.verify(allocator, rows, &columns, .{ .hash_witness = opening.hash_witness });",
        "const inserted_even = answers[step][query * 2];",
        "const inserted_odd = answers[step][query * 2 + 1];",
        "try foldPair(inserted_even, inserted_odd, circle_y, alphas[step])",
        "break :blk try old.foldInsertedPair(",
        "return error.IntermediateFoldMismatch;",
        "return error.TerminalFoldMismatch;",
    ), errors, "native cascade folds")
    inserted = function(sources[INSERTION], "pub fn foldInsertedPair(", errors)
    ordered(inserted, (
        "const previous = try foldPair(previous_even, previous_odd, line_x, alpha);",
        "const inserted = try foldPair(inserted_even, inserted_odd, circle_y, alpha);",
        "return previous.add(alpha.square().mul(inserted));",
    ), errors, "Protocol 3 insertion order")
    return errors


def main() -> int:
    errors = audit({path: (ROOT / path).read_text()
                    for path in (RELATION, WIRE, BATCH, CASCADE, INSERTION)})
    for error in errors:
        print(error)
    if errors:
        return 1
    print("CAS05 relation extractor source custody: pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
