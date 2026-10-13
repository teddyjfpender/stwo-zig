#!/usr/bin/env python3
"""Source-pinned CAS05 round and internal BLAKE2s finalization budget.

This counts the complete statement-bound verifier and the dense reference
prover separately. It does not instantiate a BCS/ROM soundness theorem.
"""

from __future__ import annotations

import argparse
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
            "transcript_hard_nontrapping_upper": hard_transcript,
            "source_merkle_verifier_upper": source_verifier,
            "line_merkle_verifier_upper_by_height": line_verifier_by_height,
            "line_merkle_verifier_upper": line_verifier,
            "complete_verifier_internal_upper": hard_transcript + verifier_merkle,
            "complete_verifier_if_no_secure_rejections_upper": no_rejection_transcript + verifier_merkle,
            "audit_extractor_internal_upper": 2 * (hard_transcript + verifier_merkle),
            "dense_host_source_tree_exact_if_admitted": host_source_tree if k <= 16 else None,
            "dense_host_line_trees_exact_if_admitted": host_line_trees if k <= 16 else None,
            "dense_host_prover_if_no_secure_rejections_exact_if_admitted":
                no_rejection_transcript + host_source_tree + host_line_trees if k <= 16 else None,
        },
        "external_adversarial_hash_queries_T": "independent explicit assumption; absent from internal counts",
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
