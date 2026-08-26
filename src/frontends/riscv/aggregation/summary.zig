//! Fixed-size native leaf and parent summaries for R-007.
//!
//! This module validates manifest membership and merge algebra only. It does
//! not verify a leaf STARK, constrain a summary to an interaction trace, or
//! recursively prove either child. Callers must not treat its booleans as a
//! recursive-proof result.

const std = @import("std");
const hash = @import("hash.zig");
const manifest = @import("manifest.zig");
const types = @import("types.zig");

pub const NATIVE_REFERENCE_ONLY = true;
pub const RECURSIVE_PROOF_VERIFICATION = false;

pub const LeafRelationSummaryV1 = struct {
    session_digest: hash.Digest,
    challenge_context_digest: hash.Digest,
    leaf_index: u32,
    leaf_role: types.LeafRole,
    leaf_statement_digest: hash.Digest,
    guest_call_commitment: hash.Digest,
    guest_call_count: u64,
    request_count: u64,
    supply_count: u64,
    signed_guest_sum: types.SecureFelt,
};

pub const NodeSummaryV1 = struct {
    session_digest: hash.Digest,
    challenge_context_digest: hash.Digest,
    left_child_digest: hash.Digest,
    right_child_digest: hash.Digest,
    first_leaf: u32,
    leaf_count: u32,
    height: u8,
    closed: bool,
    request_count: u64,
    supply_count: u64,
    residual_guest_sum: types.SecureFelt,
    request_subtree_digest: hash.Digest,
    call_subtree_digest: hash.Digest,
    statement_subtree_digest: hash.Digest,
    artifact_subtree_digest: hash.Digest,
};

pub const RootIdentityV1 = struct {
    statement_root: hash.Digest,
    artifact_root: hash.Digest,
};

pub const LEAF_SUMMARY_ENCODED_LEN: usize =
    32 + 32 + 4 + 1 + 32 + 32 + 8 + 8 + 8 + 16;
pub const NODE_SUMMARY_ENCODED_LEN: usize =
    32 + 32 + 32 + 32 + 4 + 4 + 1 + 1 + 8 + 8 + 16 +
    32 + 32 + 32 + 32;

comptime {
    std.debug.assert(LEAF_SUMMARY_ENCODED_LEN == 173);
    std.debug.assert(NODE_SUMMARY_ENCODED_LEN == 298);
}

/// Structural membership check only; the caller remains responsible for
/// obtaining this value from a verifier that proof-binds the leaf summary.
pub fn validateLeafStructure(
    session: *const manifest.PreparedSessionV1,
    summary: LeafRelationSummaryV1,
) !void {
    if (!hash.eql(summary.session_digest, session.session_digest)) {
        return error.SessionMismatch;
    }
    if (!hash.eql(summary.challenge_context_digest, session.challenge.challenge_context_digest)) {
        return error.ChallengeContextMismatch;
    }
    if (hash.isZero(summary.session_digest) or
        hash.isZero(summary.challenge_context_digest) or
        hash.isZero(summary.leaf_statement_digest) or
        hash.isZero(summary.guest_call_commitment))
    {
        return error.ZeroSummaryDigest;
    }
    try summary.signed_guest_sum.validate();
    try types.validateCallCount(summary.guest_call_count);

    const prepared_leaf = try session.leaf(summary.leaf_index);
    const descriptor = prepared_leaf.descriptor;
    if (summary.leaf_role != descriptor.role) return error.LeafRoleMismatch;
    if (!hash.eql(summary.leaf_statement_digest, descriptor.leaf_statement_digest)) {
        return error.LeafStatementMismatch;
    }
    if (!hash.eql(summary.guest_call_commitment, descriptor.guest_call_commitment)) {
        return error.CallCommitmentMismatch;
    }
    if (summary.guest_call_count != descriptor.guest_call_count) {
        return error.CallCountMismatch;
    }
    if (summary.guest_call_count == 0 and
        !summary.signed_guest_sum.isZero())
    {
        return error.NonZeroEmptyRelationSum;
    }
    switch (descriptor.role) {
        .core_request => {
            if (summary.request_count != summary.guest_call_count or
                summary.supply_count != 0)
            {
                return error.DerivedCountMismatch;
            }
        },
        .poseidon2_provider => {
            if (summary.request_count != 0 or
                summary.supply_count != summary.guest_call_count)
            {
                return error.DerivedCountMismatch;
            }
        },
    }
}

pub fn mergePair(
    session: *const manifest.PreparedSessionV1,
    core: LeafRelationSummaryV1,
    provider: LeafRelationSummaryV1,
) !NodeSummaryV1 {
    try validateLeafStructure(session, core);
    try validateLeafStructure(session, provider);
    if ((core.leaf_index & 1) != 0 or
        provider.leaf_index != std.math.add(u32, core.leaf_index, 1) catch
            return error.NonCanonicalPair)
    {
        return error.NonCanonicalPair;
    }
    if (core.leaf_role != .core_request or
        provider.leaf_role != .poseidon2_provider)
    {
        return error.NonCanonicalPair;
    }
    const core_leaf = try session.leaf(core.leaf_index);
    const provider_leaf = try session.leaf(provider.leaf_index);
    if (core_leaf.descriptor.pair_index !=
        provider_leaf.descriptor.pair_index or
        !hash.eql(core_leaf.descriptor.job_digest, provider_leaf.descriptor.job_digest))
    {
        return error.PairJobMismatch;
    }
    if (!hash.eql(core.guest_call_commitment, provider.guest_call_commitment)) {
        return error.PairCallCommitmentMismatch;
    }
    if (core.guest_call_count != provider.guest_call_count or
        core.request_count != provider.supply_count)
    {
        return error.PairCountMismatch;
    }
    const residual = core.signed_guest_sum.add(provider.signed_guest_sum);
    if (!residual.isZero()) return error.PairRelationNotClosed;

    return .{
        .session_digest = session.session_digest,
        .challenge_context_digest = session.challenge.challenge_context_digest,
        .left_child_digest = try leafDigest(core),
        .right_child_digest = try leafDigest(provider),
        .first_leaf = core.leaf_index,
        .leaf_count = 2,
        .height = 1,
        .closed = true,
        .request_count = core.request_count,
        .supply_count = provider.supply_count,
        .residual_guest_sum = residual,
        .request_subtree_digest = manifest.requestLeafDigest(
            core_leaf.descriptor.job_digest,
        ),
        .call_subtree_digest = manifest.callLeafDigest(
            core_leaf.descriptor.job_digest,
            core_leaf.descriptor.guest_call_commitment,
            core_leaf.descriptor.guest_call_count,
        ),
        .statement_subtree_digest = hash.hashPair(
            hash.STATEMENT_NODE_DOMAIN,
            core_leaf.statement_leaf_digest,
            provider_leaf.statement_leaf_digest,
        ),
        .artifact_subtree_digest = hash.hashPair(
            hash.ARTIFACT_NODE_DOMAIN,
            core_leaf.artifact_leaf_digest,
            provider_leaf.artifact_leaf_digest,
        ),
    };
}

pub fn mergeClosedSubtrees(
    session: *const manifest.PreparedSessionV1,
    left: NodeSummaryV1,
    right: NodeSummaryV1,
) !NodeSummaryV1 {
    try validateClosedNode(session, left);
    try validateClosedNode(session, right);
    if (left.leaf_count != right.leaf_count or
        left.height != right.height)
    {
        return error.UnequalSubtrees;
    }
    const expected_right = std.math.add(
        u32,
        left.first_leaf,
        left.leaf_count,
    ) catch return error.LeafRangeOverflow;
    if (right.first_leaf != expected_right) return error.NonAdjacentSubtrees;
    const parent_leaf_count = std.math.add(
        u32,
        left.leaf_count,
        right.leaf_count,
    ) catch return error.LeafRangeOverflow;
    if (left.first_leaf % parent_leaf_count != 0) {
        return error.NonCanonicalSubtreePosition;
    }
    const parent_end = std.math.add(
        u32,
        left.first_leaf,
        parent_leaf_count,
    ) catch return error.LeafRangeOverflow;
    if (parent_end > session.header.leaf_count) return error.LeafRangeOutOfBounds;

    const request_count = std.math.add(
        u64,
        left.request_count,
        right.request_count,
    ) catch return error.AggregateCountOverflow;
    const supply_count = std.math.add(
        u64,
        left.supply_count,
        right.supply_count,
    ) catch return error.AggregateCountOverflow;
    if (request_count != supply_count) return error.AggregateCountMismatch;
    const residual = left.residual_guest_sum.add(right.residual_guest_sum);
    if (!residual.isZero()) return error.AggregateRelationNotClosed;

    return .{
        .session_digest = session.session_digest,
        .challenge_context_digest = session.challenge.challenge_context_digest,
        .left_child_digest = try nodeDigest(left),
        .right_child_digest = try nodeDigest(right),
        .first_leaf = left.first_leaf,
        .leaf_count = parent_leaf_count,
        .height = std.math.add(u8, left.height, 1) catch
            return error.TreeHeightOverflow,
        .closed = true,
        .request_count = request_count,
        .supply_count = supply_count,
        .residual_guest_sum = residual,
        .request_subtree_digest = hash.hashPair(
            hash.REQUEST_NODE_DOMAIN,
            left.request_subtree_digest,
            right.request_subtree_digest,
        ),
        .call_subtree_digest = hash.hashPair(
            hash.CALL_NODE_DOMAIN,
            left.call_subtree_digest,
            right.call_subtree_digest,
        ),
        .statement_subtree_digest = hash.hashPair(
            hash.STATEMENT_NODE_DOMAIN,
            left.statement_subtree_digest,
            right.statement_subtree_digest,
        ),
        .artifact_subtree_digest = hash.hashPair(
            hash.ARTIFACT_NODE_DOMAIN,
            left.artifact_subtree_digest,
            right.artifact_subtree_digest,
        ),
    };
}

pub fn validateRoot(
    session: *const manifest.PreparedSessionV1,
    root: NodeSummaryV1,
    advertised: RootIdentityV1,
) !void {
    try validateClosedNode(session, root);
    if (root.first_leaf != 0 or
        root.leaf_count != session.header.leaf_count)
    {
        return error.IncompleteRootRange;
    }
    if (root.height != session.tree_height) return error.RootHeightMismatch;
    if (root.request_count != session.total_request_count or
        root.supply_count != session.total_supply_count)
    {
        return error.RootCountMismatch;
    }
    if (!hash.eql(root.request_subtree_digest, session.header.request_set_digest) or
        !hash.eql(root.request_subtree_digest, session.request_root))
    {
        return error.RootRequestIdentityMismatch;
    }
    if (!hash.eql(root.call_subtree_digest, session.call_root)) {
        return error.RootCallIdentityMismatch;
    }
    if (hash.isZero(advertised.statement_root) or
        hash.isZero(advertised.artifact_root) or
        !hash.eql(advertised.statement_root, session.statement_root) or
        !hash.eql(advertised.artifact_root, session.artifact_root) or
        !hash.eql(root.statement_subtree_digest, advertised.statement_root) or
        !hash.eql(root.artifact_subtree_digest, advertised.artifact_root))
    {
        return error.RootAdvertisedIdentityMismatch;
    }
}

fn validateClosedNode(
    session: *const manifest.PreparedSessionV1,
    node: NodeSummaryV1,
) !void {
    if (!hash.eql(node.session_digest, session.session_digest)) {
        return error.SessionMismatch;
    }
    if (!hash.eql(node.challenge_context_digest, session.challenge.challenge_context_digest)) {
        return error.ChallengeContextMismatch;
    }
    if (!node.closed) return error.SubtreeNotClosed;
    if (node.leaf_count < 2 or
        !std.math.isPowerOfTwo(node.leaf_count) or
        node.leaf_count > session.header.leaf_count)
    {
        return error.InvalidSubtreeSize;
    }
    if (node.first_leaf % node.leaf_count != 0) {
        return error.NonCanonicalSubtreePosition;
    }
    const end = std.math.add(u32, node.first_leaf, node.leaf_count) catch
        return error.LeafRangeOverflow;
    if (end > session.header.leaf_count) return error.LeafRangeOutOfBounds;
    if (node.height != types.log2ExactPowerOfTwo(node.leaf_count)) {
        return error.SubtreeHeightMismatch;
    }
    if (node.request_count != node.supply_count) {
        return error.AggregateCountMismatch;
    }
    if (node.request_count > session.total_request_count or
        node.supply_count > session.total_supply_count)
    {
        return error.AggregateCountOutOfBounds;
    }
    try node.residual_guest_sum.validate();
    if (!node.residual_guest_sum.isZero()) {
        return error.AggregateRelationNotClosed;
    }
    if (hash.isZero(node.session_digest) or
        hash.isZero(node.challenge_context_digest) or
        hash.isZero(node.left_child_digest) or
        hash.isZero(node.right_child_digest) or
        hash.isZero(node.request_subtree_digest) or
        hash.isZero(node.call_subtree_digest) or
        hash.isZero(node.statement_subtree_digest) or
        hash.isZero(node.artifact_subtree_digest))
    {
        return error.ZeroSummaryDigest;
    }
}

pub fn leafDigest(summary: LeafRelationSummaryV1) !hash.Digest {
    var sink = hash.HashSink.init(hash.LEAF_SUMMARY_DOMAIN);
    try writeLeafSummary(&sink, summary);
    return sink.finalize();
}

pub fn nodeDigest(summary: NodeSummaryV1) !hash.Digest {
    var sink = hash.HashSink.init(hash.NODE_SUMMARY_DOMAIN);
    try writeNodeSummary(&sink, summary);
    return sink.finalize();
}

pub fn encodeLeafSummary(
    summary: LeafRelationSummaryV1,
    destination: []u8,
) !usize {
    if (destination.len != LEAF_SUMMARY_ENCODED_LEN) {
        return error.IncorrectBufferLength;
    }
    var sink = hash.SliceSink{ .destination = destination };
    try writeLeafSummary(&sink, summary);
    std.debug.assert(sink.offset == LEAF_SUMMARY_ENCODED_LEN);
    return sink.offset;
}

pub fn encodeNodeSummary(
    summary: NodeSummaryV1,
    destination: []u8,
) !usize {
    if (destination.len != NODE_SUMMARY_ENCODED_LEN) {
        return error.IncorrectBufferLength;
    }
    var sink = hash.SliceSink{ .destination = destination };
    try writeNodeSummary(&sink, summary);
    std.debug.assert(sink.offset == NODE_SUMMARY_ENCODED_LEN);
    return sink.offset;
}

fn writeLeafSummary(sink: anytype, summary: LeafRelationSummaryV1) !void {
    try validateLeafWire(summary);
    try sink.writeAll(&summary.session_digest);
    try sink.writeAll(&summary.challenge_context_digest);
    try hash.writeU32(sink, summary.leaf_index);
    try sink.writeAll(&.{@intFromEnum(summary.leaf_role)});
    try sink.writeAll(&summary.leaf_statement_digest);
    try sink.writeAll(&summary.guest_call_commitment);
    try hash.writeU64(sink, summary.guest_call_count);
    try hash.writeU64(sink, summary.request_count);
    try hash.writeU64(sink, summary.supply_count);
    try writeSecureFelt(sink, summary.signed_guest_sum);
}

fn writeNodeSummary(sink: anytype, summary: NodeSummaryV1) !void {
    try validateNodeWire(summary);
    try sink.writeAll(&summary.session_digest);
    try sink.writeAll(&summary.challenge_context_digest);
    try sink.writeAll(&summary.left_child_digest);
    try sink.writeAll(&summary.right_child_digest);
    try hash.writeU32(sink, summary.first_leaf);
    try hash.writeU32(sink, summary.leaf_count);
    try sink.writeAll(&.{summary.height});
    try sink.writeAll(&.{@intFromBool(summary.closed)});
    try hash.writeU64(sink, summary.request_count);
    try hash.writeU64(sink, summary.supply_count);
    try writeSecureFelt(sink, summary.residual_guest_sum);
    try sink.writeAll(&summary.request_subtree_digest);
    try sink.writeAll(&summary.call_subtree_digest);
    try sink.writeAll(&summary.statement_subtree_digest);
    try sink.writeAll(&summary.artifact_subtree_digest);
}

fn writeSecureFelt(sink: anytype, felt: types.SecureFelt) !void {
    try felt.validate();
    for (felt.limbs) |limb| try hash.writeU32(sink, limb);
}

fn validateLeafWire(summary: LeafRelationSummaryV1) !void {
    if (hash.isZero(summary.session_digest) or
        hash.isZero(summary.challenge_context_digest) or
        hash.isZero(summary.leaf_statement_digest) or
        hash.isZero(summary.guest_call_commitment))
    {
        return error.ZeroSummaryDigest;
    }
    try summary.signed_guest_sum.validate();
    try types.validateCallCount(summary.guest_call_count);
    const empty_commitment = hash.emptyCallCommitment();
    if (summary.guest_call_count == 0) {
        if (!hash.eql(summary.guest_call_commitment, empty_commitment)) {
            return error.NonCanonicalEmptyCallCommitment;
        }
        if (!summary.signed_guest_sum.isZero()) {
            return error.NonZeroEmptyRelationSum;
        }
    } else if (hash.eql(summary.guest_call_commitment, empty_commitment)) {
        return error.EmptyCommitmentForNonEmptyCalls;
    }
    switch (summary.leaf_role) {
        .core_request => {
            if (summary.request_count != summary.guest_call_count or
                summary.supply_count != 0)
            {
                return error.DerivedCountMismatch;
            }
        },
        .poseidon2_provider => {
            if (summary.request_count != 0 or
                summary.supply_count != summary.guest_call_count)
            {
                return error.DerivedCountMismatch;
            }
        },
    }
}

fn validateNodeWire(summary: NodeSummaryV1) !void {
    if (hash.isZero(summary.session_digest) or
        hash.isZero(summary.challenge_context_digest) or
        hash.isZero(summary.left_child_digest) or
        hash.isZero(summary.right_child_digest) or
        hash.isZero(summary.request_subtree_digest) or
        hash.isZero(summary.call_subtree_digest) or
        hash.isZero(summary.statement_subtree_digest) or
        hash.isZero(summary.artifact_subtree_digest))
    {
        return error.ZeroSummaryDigest;
    }
    if (!summary.closed) return error.SubtreeNotClosed;
    if (summary.leaf_count < 2 or
        summary.leaf_count > types.MAX_LEAVES or
        !std.math.isPowerOfTwo(summary.leaf_count))
    {
        return error.InvalidSubtreeSize;
    }
    if (summary.first_leaf % summary.leaf_count != 0) {
        return error.NonCanonicalSubtreePosition;
    }
    _ = std.math.add(u32, summary.first_leaf, summary.leaf_count) catch
        return error.LeafRangeOverflow;
    if (summary.height != types.log2ExactPowerOfTwo(summary.leaf_count)) {
        return error.SubtreeHeightMismatch;
    }
    if (summary.request_count != summary.supply_count) {
        return error.AggregateCountMismatch;
    }
    try summary.residual_guest_sum.validate();
    if (!summary.residual_guest_sum.isZero()) {
        return error.AggregateRelationNotClosed;
    }
}
