#!/usr/bin/env python3
"""Source-pinned CAS05 round and internal BLAKE2s finalization budget.

This counts the complete statement-bound verifier and the dense reference
prover separately. It does not instantiate a BCS/ROM soundness theorem.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path

if __package__:
    from .check_cas05_bcs_join import ROOT, audit as bcs_audit, require
else:
    from check_cas05_bcs_join import ROOT, audit as bcs_audit, require


def check_cost_sources(root: Path = ROOT) -> None:
    """Reject known control-flow changes that would invalidate these formulas."""
    # The existing BCS audit pins transcript order, tags, draws and admission.
    bcs_audit(root)
    check_secure_sampler_sources(root)
    files = {
        "cascade": "src/core/pcs/paired_sparse_cascade_experimental.zig",
        "source": "src/core/pcs/transposed_merkle_sparse.zig",
        "tree": "src/core/pcs/transposed_merkle_cascade.zig",
        "source_prover": "src/prover/pcs/transposed_cascade_experimental.zig",
        "line_verifier": "src/core/vcs_lifted/verifier.zig",
        "line_prover": "src/prover/vcs_lifted/prover.zig",
        "line_hasher": "src/core/vcs_lifted/blake2_merkle.zig",
        "channel": "src/core/channel/blake2s.zig",
    }
    s = {key: (root / path).read_text() for key, path in files.items()}
    require(s["cascade"], "one source and one line authentication per verifier call",
            "var opened = try xdm.verifyAndCollect(",
            "for (proof.line_openings, 0..) |opening, i| {",
            "try verifier.verify(allocator, rows, &columns, .{ .hash_witness = opening.hash_witness });")
    source_verify = s["source"].split("pub fn verifyAndCollect(", 1)[1]
    require(source_verify, "source hash sites and bounded loops",
            "for (raw_queries, 0..) |raw, query| {",
            "for (1..expected.height_count) |height| {",
            "for (0..2) |j| {",
            "tree.hashLeaf(values[0][offset..][0..cols])",
            "tree.hashInserted(left, right, values[height][offset..][0..cols])",
            "const bottom = k - expected.height_count + 1;",
            "while (level > 0) : (level -= 1) {",
            "if (position > 0 and index == active.items[position - 1]) continue;",
            "tree.hashUpper(left, right)")
    if source_verify.count("tree.hashLeaf(") != 1 or source_verify.count("tree.hashInserted(") != 1 or source_verify.count("tree.hashUpper(") != 1:
        raise ValueError("source authentication hash roster changed")
    require(s["tree"], "inserted source node is two finalizations",
            "const pair = hashUpper(left, right);", "h.update(\"S31XDI03\");",
            "return h.finalize();")
    line_verify = s["line_verifier"].split("fn verifyImpl(", 1)[1].split("\n    };", 1)[0]
    require(line_verify, "line multiproof hashes each deduplicated row and parent",
            "for (unique_positions.items) |pos| {",
            "var hasher = H.defaultWithInitialState();",
            "hasher.updateLeaf(row);",
            "hasher.finalize()",
            "while (layer < self.height) : (layer += 1) {",
            "H.hashChildren(.{ .left = left_hash, .right = right_hash })")
    if line_verify.count("hasher.finalize()") != 1 or line_verify.count("H.hashChildren(") != 1:
        raise ValueError("line authentication hash roster changed")
    require(s["line_hasher"], "one finalization per line leaf/parent",
            "pub const LEAF_PREFIX = makePrefix(\"leaf\");",
            "pub const NODE_PREFIX = makePrefix(\"node\");",
            "return InnerHasher.hashFinal64FromSeedWithMode(mode, nodeSeedWithMode(mode), &payload);")
    require(s["line_hasher"], "root absorption is one finalization",
            "blake2_hash.Blake2sHasherGeneric(is_m31_output).concatAndHash(digest, root)")
    require(s["channel"], "each transcript absorption/draw finalizes once",
            "pub fn mixFelts(", "pub fn mixU32s(", "pub fn mixU64(",
            "self.mixU32s(&[_]u32{", "self.updateDigest(hasher.finalize());",
            "const hash = hashBytes(hash_input[0..]);")
    require(s["source_prover"], "dense source commitment topology",
            "for (layers[k], 0..) |*leaf, row| {",
            "leaf.* = xdm.hashLeaf(values[0..source_columns[0].len]);",
            "const height = k - level;",
            "if (height < source_columns.len) {",
            "node.* = xdm.hashInserted(left, right, values[0..source_columns[height].len]);",
            "node.* = xdm.hashUpper(left, right);")
    require(s["line_prover"], "ordinary line tree commit path",
            "return commitWithOptions(", "return buildTreeFromOwnedLeaves(")


# Exact critical bodies are pinned separately from the wider, anchor-based
# transcript roster. Changing any of these requires rederiving the probability
# law below. The pin is a source audit, not a proof of Zig execution semantics.
SAMPLER_BODY_PINS = (
    ("src/core/channel/blake2s.zig", "fn nextDrawCounter(",
     "const metal_aot_transcript_secure",
     "a167d06701ce79dcff898802afd5552821458dfc16a1e352ab3184fa81f71340"),
    ("src/core/channel/blake2s.zig", "pub fn drawU32s(", "pub fn drawSecureFelt(",
     "b1491d6264ee97ad93902f3e022074695215cac9d90eed5f118f6593d994380e"),
    ("src/core/channel/blake2s.zig", "pub fn drawSecureFelt(", "pub fn drawSecureFelts(",
     "abaf35b20bc0ce1e45788a6c398847791e508e354aa03193c2ff19526c065260"),
    ("src/core/channel/blake2s.zig", "fn drawBaseFelts(", "fn hashBytes(",
     "915cb491be57393cbbf59bae9b36d970af40628831be385d818756d3cfd971ba"),
    ("src/core/channel/blake2s.zig", "fn readU32Le(",
     'test "blake2s channel: draw counters"',
     "2f4aaeb8665cec2a8532c484a92cc6517d5a552101b50273296069a086d6e55c"),
    ("src/core/fields/m31.zig", "pub inline fn fromU64(", "pub inline fn isZero(",
     "68731dea5f70b26ab10bfbb2268d24cff8400711c8870f6d31a9ee827a679c69"),
    ("src/core/fields/m31.zig", "inline fn reduce64(", "inline fn reduceProduct(",
     "c8f11a29764a5e876251f0fb9d44f6f314fab63b6a66f8e0b35038f9c20646ab"),
    ("src/core/fields/qm31.zig", "pub inline fn fromM31Array(", "pub inline fn toM31Array(",
     "7ca2b5f3f71864cc17572d1be4d1b1bc10e1757a0098df21b3cd7d9d1691cfa6"),
)


def check_secure_sampler_sources(root: Path = ROOT) -> None:
    """Pin the exact native eight-word rejection and QM31 reduction path."""
    channel = (root / "src/core/channel/blake2s.zig").read_text()
    m31 = (root / "src/core/fields/m31.zig").read_text()
    qm31 = (root / "src/core/fields/qm31.zig").read_text()
    for source, anchor in (
        (channel, "pub const FELTS_PER_HASH: usize = 8;"),
        (channel, "pub const Blake2sChannel = Blake2sChannelGeneric(false);"),
        (m31, "pub const Modulus: u32 = 0x7fffffff;"),
        (qm31, "pub const SECURE_EXTENSION_DEGREE: usize = 4;"),
    ):
        if source.count(anchor) != 1:
            raise ValueError(f"CAS05 secure sampler source changed: {anchor}")
    for path, start, end, expected in SAMPLER_BODY_PINS:
        source = (root / path).read_text()
        if source.count(start) != 1 or source.count(end) != 1:
            raise ValueError(f"CAS05 secure sampler function changed: {path} {start}")
        body = source.split(start, 1)[1].split(end, 1)[0]
        if hashlib.sha256(body.encode()).hexdigest() != expected:
            raise ValueError(f"CAS05 secure sampler body changed: {path} {start}")


def secure_sampler_tail(draws: int, attempts: int = 5) -> dict[str, object]:
    """Exact ideal-block law and union bound for all secure draws.

    This is the game in which each attempted 37-byte input obtains a fresh,
    independent, uniform 256-bit hash output. Real BLAKE2s/ROM transfer must
    separately account for adversarial prequeries and cross-epoch reuse.
    """
    if draws < 0 or attempts < 1:
        raise ValueError("invalid secure sampler tail dimensions")
    p = (1 << 31) - 1
    word_accept = Fraction(2 * p, 1 << 32)
    block_accept = word_accept ** 8
    block_reject = 1 - block_accept
    union_tail = draws * block_reject ** attempts
    # For 2<=h<=8, draws=h+2<=10. A rejected block requires at least one
    # of eight words in the two invalid u32 values. Hence r<8*2^-31=2^-28,
    # and 10*r^5 < 10*2^-140 < 2^-136.
    if draws <= 10 and attempts == 5 and not union_tail < Fraction(1, 1 << 136):
        raise AssertionError("five-block dyadic certificate failed")
    return {
        "field_modulus": p,
        "words_per_block": 8,
        "invalid_u32_values_per_word": 2,
        "block_acceptance_exact": f"{block_accept.numerator}/{block_accept.denominator}",
        "block_rejection_exact": f"{block_reject.numerator}/{block_reject.denominator}",
        "attempts_per_secure_draw_on_good_event": attempts,
        "secure_draws": draws,
        "any_draw_needs_more_than_attempts_union_bound_exact":
            f"{union_tail.numerator}/{union_tail.denominator}",
        "any_draw_needs_more_than_attempts_upper_dyadic_bits":
            136 if draws <= 10 and attempts == 5 else None,
        "model": "fresh independent uniform ideal hash blocks; ROM freshness and BLAKE2s transfer unproved",
        "protocol_enforces_attempt_cap": False,
    }


def budget(k: int, h: int, beta: int, q: int, columns: tuple[int, ...]) -> dict[str, object]:
    if not (2 <= h <= 8 and h + 2 <= k <= 22 and 1 <= beta <= k - h and
            1 <= q <= 1 << 14 and len(columns) == h and
            all(1 <= c <= 64 for c in columns)):
        raise ValueError("outside the XDM04/CAS05 verifier-admitted profile")
    fixed_source_wire_bytes = q * (4 + 8 * sum(columns))
    if fixed_source_wire_bytes > 64 * 1024 * 1024 - 128:
        raise ValueError("XDM04 fixed source rows exceed its 64 MiB admission budget")

    # The first batch and alpha_0 draws share one digest epoch. Each secure
    # challenge loops on rejection and may use the entire checked u32 counter.
    commitment_rounds = h + 2  # source, claims, h-1 line roots, terminal
    logical_reductions = h + 3  # OOD, batch, h folds, all queries
    transcript_absorptions = 8 * h + 11
    query_blocks = (q + 7) // 8
    secure_challenges = h + 2
    no_rejection_transcript = transcript_absorptions + secure_challenges + query_blocks
    sampler = secure_sampler_tail(secure_challenges)
    good_event_transcript = transcript_absorptions + 5 * secure_challenges + query_blocks
    # There are h+1 independent secure-draw epochs, each at most 2^32-1
    # successful counter increments on a nontrapping execution.
    hard_transcript = transcript_absorptions + (h + 1) * ((1 << 32) - 1) + query_blocks

    # XDM04 verifier hashes 2q leaves, 2q inserted nodes at each of h-1
    # heights (two finalizations each), and at most 2q active nodes at each
    # of k-h+1 upper levels. Duplicate queries can be rehashed.
    source_verifier = 2 * q * (k + h)
    # Line j (1 <= j < h) has 2q presented rows and k-j parent levels.
    line_verifier_by_height = [2 * q * (1 + k - j) for j in range(1, h)]
    line_verifier = sum(line_verifier_by_height)
    verifier_merkle = source_verifier + line_verifier

    # The host reference prover builds full trees. XDM03 has 2^k leaves,
    # inserted nodes at levels k-j for j=1..h-1, and ordinary upper nodes.
    host_source_tree = 3 * (1 << k) - (1 << (k - h + 1)) - 1
    host_line_trees = sum(2 * (1 << (k - j)) - 1 for j in range(1, h))
    return {
        "profile": {"k": k, "h": h, "log_blowup": beta, "q": q,
                    "columns": list(columns), "host_dense_prover_admitted": k <= 16},
        "rounds": {
            "native_commitment_challenge_barriers": commitment_rounds,
            "logical_random_reductions": logical_reductions,
            "published_Protocol_3_FRI_reductions_without_OOD": h + 2,
            "BCS_R_for_CAS05_proven_applicable": None,
            "batch_and_first_alpha_share_claims_message": True,
        },
        "hash_finalizations": {
            "transcript_absorptions_exact": transcript_absorptions,
            "secure_challenges": secure_challenges,
            "query_blocks_exact": query_blocks,
            "transcript_if_no_secure_rejections": no_rejection_transcript,
            "transcript_on_ideal_five_block_good_event_upper": good_event_transcript,
            "transcript_hard_nontrapping_upper": hard_transcript,
            "source_merkle_verifier_upper": source_verifier,
            "line_merkle_verifier_upper_by_height": line_verifier_by_height,
            "line_merkle_verifier_upper": line_verifier,
            "complete_verifier_internal_upper": hard_transcript + verifier_merkle,
            "complete_verifier_if_no_secure_rejections_upper": no_rejection_transcript + verifier_merkle,
            "complete_verifier_on_ideal_five_block_good_event_upper":
                good_event_transcript + verifier_merkle,
            "audit_extractor_internal_upper": 2 * (hard_transcript + verifier_merkle),
            "dense_host_source_tree_exact_if_admitted": host_source_tree if k <= 16 else None,
            "dense_host_line_trees_exact_if_admitted": host_line_trees if k <= 16 else None,
            "dense_host_prover_if_no_secure_rejections_exact_if_admitted":
                no_rejection_transcript + host_source_tree + host_line_trees if k <= 16 else None,
        },
        "external_adversarial_hash_queries_T": "independent explicit assumption; absent from internal counts",
        "conditional_ideal_secure_sampler": sampler,
        "native_security_bits": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--k", type=int, required=True)
    parser.add_argument("--h", type=int, required=True)
    parser.add_argument("--log-blowup", type=int, required=True)
    parser.add_argument("--queries", type=int, required=True)
    parser.add_argument("--columns", required=True, help="comma-separated source columns at each height")
    args = parser.parse_args()
    try:
        check_cost_sources()
        counts = tuple(int(part) for part in args.columns.split(","))
        result = budget(args.k, args.h, args.log_blowup, args.queries, counts)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
