const fri = @import("fri.zig");
const vcs_verifier = @import("vcs_lifted/verifier.zig");

/// Index of the preprocessed trace tree in PCS tree vectors.
pub const PREPROCESSED_TRACE_IDX: usize = 0;

/// Hardcoded composition split used by upstream verifier flow.
pub const COMPOSITION_LOG_SPLIT: u32 = 1;

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
} || fri.FriVerificationError || vcs_verifier.MerkleVerificationError;
