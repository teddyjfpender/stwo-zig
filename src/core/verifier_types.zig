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
