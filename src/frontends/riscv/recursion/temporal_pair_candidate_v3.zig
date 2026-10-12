//! Native preflight for a V3 temporal leaf pair. This is not a proof verifier.
//!
//! The same 608-word metadata preimages and 412-word span statements must be
//! public inputs of a future proof-bearing parent. A checked native fold does
//! not turn a host-checked VerifiedLinkV3 into a recursively verified leaf.
//!
//! Minimum sound parent cohort:
//! 1. Freshly verify two V3 wrapper proofs under independently pinned leaf
//!    verifier keys. Each verifier must publish its exact metadata preimage,
//!    global statement, native V2 proof identity, and proof family.
//! 2. A fixed parent AIR must join each verifier publication to the ordered
//!    child input and constrain the complete span fold, 64-bit adjacency,
//!    CPU/sparse-memory boundary equality, and final-only completion.
//! 3. The parent verifier must pin its own key, PCS configuration and
//!    preprocessed root, and verify the parent proof before publication.
//!    An odd tail needs an explicit protocol-owned empty child or a separate
//!    carry rule; no fabricated proof may fill that slot.
const std = @import("std");
const global = @import("segment_leaf_local_authority_v3.zig");
const span = @import("span_statement.zig");
const channel = @import("poseidon2_channel.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const PARENT_PROOF_AVAILABLE = false;
pub const CHILD_COUNT: usize = 2;
pub const CHILD_METADATA_WORDS = global.METADATA_IDENTITY_WORDS;
pub const PARENT_STATEMENT_WORDS = span.SPAN_STATEMENT_CANONICAL_WORDS;

pub const Error = global.Error || span.Error || error{
    ParentStatementMismatch,
    CandidateChanged,
};

/// The exact public material the first proof-bearing parent must constrain.
/// This value makes no claim that either child has a recursive wrapper proof.
pub const CandidateV3 = struct {
    child_metadata_words: [CHILD_COUNT]global.IdentityWords,
    child_metadata_ids: [CHILD_COUNT]channel.Digest,
    parent_statement_words: span.StatementWords,

    pub fn init(
        left: *const global.MetadataV3,
        right: *const global.MetadataV3,
        expected_parent: *const span.StatementWords,
    ) Error!CandidateV3 {
        try global.requireAdjacentMetadata(left, right);
        const left_statement = try span.SpanStatement.fromCanonicalWords(
            &left.base_statement_words,
        );
        const right_statement = try span.SpanStatement.fromCanonicalWords(
            &right.base_statement_words,
        );
        const parent = try span.SpanStatement.fold(left_statement, right_statement);
        const parent_words = try parent.canonicalWords();
        if (!std.meta.eql(parent_words, expected_parent.*))
            return error.ParentStatementMismatch;

        const words = [CHILD_COUNT]global.IdentityWords{
            try left.identityWords(),
            try right.identityWords(),
        };
        return .{
            .child_metadata_words = words,
            .child_metadata_ids = .{
                channel.hashCanonicalWords(&words[0], global.METADATA_ID_DOMAIN),
                channel.hashCanonicalWords(&words[1], global.METADATA_ID_DOMAIN),
            },
            .parent_statement_words = parent_words,
        };
    }

    /// Rechecking borrowed metadata catches mutation after preflight. A future
    /// verifier must still bind these words to two verified wrapper proofs and
    /// to the parent STARK public input before publishing a result.
    pub fn validateAgainst(
        self: *const CandidateV3,
        left: *const global.MetadataV3,
        right: *const global.MetadataV3,
        expected_parent: *const span.StatementWords,
    ) Error!void {
        const fresh = try CandidateV3.init(left, right, expected_parent);
        if (!std.meta.eql(self.*, fresh)) return error.CandidateChanged;
    }
};

comptime {
    if (CHILD_METADATA_WORDS != 608 or PARENT_STATEMENT_WORDS != 412 or
        PRODUCTION_ACTIVATION or PARENT_PROOF_AVAILABLE)
    {
        @compileError("V3 temporal candidate must remain a non-proof preflight");
    }
}
