//! Public map for prover-side polynomial commitment scheme facilities.

const scheme = @import("scheme.zig");
const deferred_commit = @import("deferred_commit.zig");

pub const quotient_ops = scheme.quotient_ops;
/// Diagnostic/backend parity owners. These are additive exports of the exact
/// executors already used by `quotient_ops`; external backends must not fork
/// the quotient formula when validating an accelerated result.
pub const quotient_tile_executor = @import("quotient_tile_executor.zig");
pub const quotient_tile_sink = @import("quotient_tile_sink.zig");
pub const CommitmentSchemeError = scheme.CommitmentSchemeError;
pub const ColumnEvaluation = scheme.ColumnEvaluation;
pub const ColumnSource = @import("column_source.zig").ColumnSource;
pub const BackingTeardownToken = @import("commitment_tree.zig").BackingTeardownToken;
pub const merkle_layer_cache = @import("merkle_layer_cache.zig");
pub const residency_estimate = @import("residency_estimate.zig");
pub const residency_shard_plan = @import("residency_shard_plan.zig");
pub const shell_work_profile = @import("shell_work_profile.zig");
/// Process-local sampled-value plan types shared with exact backend epochs.
/// These types contain borrowed slices and have no durable codec authority.
pub const sampled_coefficient_plans = @import("sampled_coefficient_plans.zig");

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
