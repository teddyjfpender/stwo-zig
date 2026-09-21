const std = @import("std");
const fri = @import("fri.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");

/// Index of the preprocessed trace tree in PCS tree vectors.
pub const PREPROCESSED_TRACE_IDX: usize = 0;

/// Default composition split retained by existing degree-+1 protocols.
pub const COMPOSITION_LOG_SPLIT: u32 = 1;
pub const MAX_COMPOSITION_LOG_SPLIT: u32 = 8;

pub fn compositionChunkCount(split_depth: u32) ?usize {
    if (split_depth == 0 or split_depth > MAX_COMPOSITION_LOG_SPLIT or
        split_depth >= @bitSizeOf(usize))
    {
        return null;
    }
    return @as(usize, 1) << @intCast(split_depth);
}

pub fn compositionColumnCount(split_depth: u32, extension_degree: usize) ?usize {
    const chunks = compositionChunkCount(split_depth) orelse return null;
    return std.math.mul(usize, chunks, extension_degree) catch null;
}

/// Shared domain for composition commitments, trace masks and quotient replay.
pub fn compositionMaskLogSize(composition_log_size: u32, split_depth: u32) ?u32 {
    if (compositionChunkCount(split_depth) == null or composition_log_size <= split_depth)
        return null;
    return composition_log_size - split_depth;
}

test "composition mask domain follows the admitted split" {
    try std.testing.expectEqual(@as(?u32, 8), compositionMaskLogSize(9, 1));
    try std.testing.expectEqual(@as(?u32, 9), compositionMaskLogSize(12, 3));
    try std.testing.expectEqual(@as(?u32, null), compositionMaskLogSize(9, 0));
    try std.testing.expectEqual(@as(?u32, null), compositionMaskLogSize(12, 9));
    try std.testing.expectEqual(@as(?u32, null), compositionMaskLogSize(3, 3));
}

pub const VerificationError = error{
    InvalidStructure,
    OodsNotMatching,
    ProofOfWork,
    ShapeMismatch,
    EmptySampledSet,
    EmptyTrees,
    InvalidPreprocessedTree,
    QueryPositionOutOfRange,
    ColumnIndexOutOfBounds,
    DivisionByZero,
    DegenerateLine,
    NonCanonical,
    NonUniqueXCoordinates,
    InvalidEvaluationLength,
} || fri.FriVerificationError || vcs_verifier.MerkleVerificationError;
