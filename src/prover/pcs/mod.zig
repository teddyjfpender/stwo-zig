//! Public map for prover-side polynomial commitment scheme facilities.

const scheme = @import("scheme.zig");
const deferred_commit = @import("deferred_commit.zig");

pub const quotient_ops = scheme.quotient_ops;
pub const CommitmentSchemeError = scheme.CommitmentSchemeError;
pub const ColumnEvaluation = scheme.ColumnEvaluation;
pub const ColumnSource = @import("column_source.zig").ColumnSource;
pub const merkle_layer_cache = @import("merkle_layer_cache.zig");

pub fn CommitmentTreeProver(comptime H: type) type {
    return scheme.CommitmentTreeProver(H);
}

pub fn TreeDecommitmentResult(comptime H: type) type {
    return scheme.TreeDecommitmentResult(H);
}

pub fn CommitmentSchemeProver(comptime B: type, comptime H: type, comptime MC: type) type {
    return scheme.CommitmentSchemeProver(B, H, MC);
}

pub fn TreeBuilder(comptime B: type, comptime H: type, comptime MC: type) type {
    return scheme.TreeBuilder(B, H, MC);
}

pub fn StreamingTreeBuilder(comptime B: type, comptime H: type, comptime MC: type) type {
    return scheme.StreamingTreeBuilder(B, H, MC);
}

/// Resolves a deferred first tree before later transcript data is mixed.
pub fn flushPendingCommit(
    comptime MC: type,
    commitment_scheme: anytype,
    allocator: @import("std").mem.Allocator,
    channel: anytype,
) !void {
    try deferred_commit.resolve(MC, commitment_scheme, allocator, channel);
}
