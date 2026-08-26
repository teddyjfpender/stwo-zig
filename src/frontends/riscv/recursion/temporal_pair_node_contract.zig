//! Internal temporal pair node authority shard; use temporal_pair_node.zig publicly.

pub const std = @import("std");
pub const builtin = @import("builtin");
pub const stwo_core = @import("stwo_core");

pub const M31 = stwo_core.fields.m31.M31;
pub const m31 = stwo_core.fields.m31;
pub const channel = @import("poseidon2_channel.zig");
pub const protocol = @import("protocol.zig");
pub const span_statement = @import("span_statement.zig");
pub const proof_kind_mod = @import("air/proof_kind.zig");
pub const roster = @import("air/universal_roster.zig");
pub const permutation_audit = @import("temporal_pair_node_permutation_audit.zig");
const recordScalarPoseidonInvocations =
    permutation_audit.recordScalarPoseidonInvocations;

pub const Digest = channel.Digest;
pub const ProofKind = proof_kind_mod.ProofKind;

pub const FORMAT_VERSION: u16 = 2;
pub const AUTHORITY_SCHEMA_VERSION: u16 = 1;
pub const NODE_ID_SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
pub const COMPLETE_ROSTER_COUNT: u8 = roster.COMPONENT_COUNT;
pub const KNOWN_FLAGS: u16 = 0;

pub const FORMAT_ID_DOMAIN: u32 = 0x5450_464d; // "TPFM"
pub const JOB_ID_DOMAIN: u32 = 0x5450_4a42; // "TPJB"
pub const CONTEXT_ID_DOMAIN: u32 = 0x5450_4358; // "TPCX"
pub const CHILD_ID_DOMAIN: u32 = 0x5450_4348; // "TPCH"
pub const CLOSURE_ID_DOMAIN: u32 = 0x5450_434c; // "TPCL"
pub const NODE_ID_DOMAIN: u32 = 0x5450_4e44; // "TPND"
pub const RECORD_ID_DOMAIN: u32 = 0x5450_5243; // "TPRC"

pub const FORMAT_ID_PREIMAGE_WORD_COUNT: usize = 20 + channel.RATE;
pub const JOB_ID_PREIMAGE_WORD_COUNT: usize =
    span_statement.canonical_layout.slot_start -
    span_statement.canonical_layout.job_start;
pub const CONTEXT_ID_PREIMAGE_WORD_COUNT: usize = 9 + 6 * channel.RATE;
pub const CHILD_ID_PREIMAGE_WORD_COUNT: usize = 10 + 17 * channel.RATE;
pub const CLOSURE_ID_PREIMAGE_WORD_COUNT: usize = 6 + 4 * channel.RATE;
pub const NODE_ID_PREIMAGE_WORD_COUNT: usize = 2 + 6 * channel.RATE;
pub const RECORD_ID_PREIMAGE_WORD_COUNT: usize = 1 + 5 * channel.RATE;
pub const STATEMENT_ID_PREIMAGE_WORD_COUNT: usize =
    span_statement.SPAN_STATEMENT_CANONICAL_WORDS;

pub const Error = span_statement.Error || error{
    AuthorityMismatch,
    ChildKindMismatch,
    ChildOrderMismatch,
    ClosureMismatch,
    ContextMismatch,
    DigestMismatch,
    EmptyChildHasProof,
    EmptyDigest,
    InvalidParentHeight,
    InvalidProofScope,
    NonCanonicalDigest,
    NonCanonicalField,
    RecordMismatch,
    RootVkMismatch,
    StatementMismatch,
    UnsupportedVersion,
    VerificationKeyMismatch,
};

pub const ChildPosition = enum(u8) {
    left = 0,
    right = 1,
};

pub const ProofScope = enum(u8) {
    protocol_padding = 0,
    complete_execution = 1,
};

/// Verifier-published proof and closure custody for one temporal child.
/// Empty leaves carry no proof and must use the canonical all-zero proof
/// identity fields below.
pub const VerifiedChildV2 = struct {
    position: ChildPosition,
    kind: ProofKind,
    scope: ProofScope,
    proof_present: bool,
    roster_count: u8,

    session_id: Digest,
    job_id: Digest,
    recursive_parent_vk_id: Digest,
    verification_key_id: Digest,
    air_program_id: Digest,
    manifest_id: Digest,
    profile_id: Digest,
    statement_words: span_statement.StatementWords,
    proof_id: Digest,
    transcript_id: Digest,
    capture_id: Digest,
    verifier_receipt_id: Digest,
    claimed_sums_id: Digest,
    relation_replay_id: Digest,
    auxiliary_claim_seal_id: Digest,
    closure_receipt_id: Digest,
    lineage_id: Digest,
    /// Exact result of the verifier's whole-roster closure check.  A complete
    /// child is admissible only when every coordinate is canonical zero.
    closure_value: [4]u32,

    pub fn statement(self: *const VerifiedChildV2) Error!span_statement.SpanStatement {
        return span_statement.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        );
    }

    pub fn statementId(self: *const VerifiedChildV2) Error!Digest {
        return statementWordsId(&self.statement_words);
    }

    pub fn id(self: *const VerifiedChildV2) Error!Digest {
        _ = try self.statement();
        return childIdFromStatementId(
            self,
            statementWordsIdAssumeValid(&self.statement_words),
        );
    }
};

/// Verifier-owned context for exactly one parent slot.  `job_id` and
/// `expected_parent_statement_id` are independently derived from the child
/// statements during validation; they are not caller-selected aliases.
pub const VerifierContextV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    authority_schema_version: u16 = AUTHORITY_SCHEMA_VERSION,
    flags: u16 = KNOWN_FLAGS,
    session_id: Digest,
    job_id: Digest,
    segment_leaf_vk_id: Digest,
    aggregator_vk_id: Digest,
    parent_node_index: u64,
    parent_height: u8,
    expected_parent_statement_id: Digest,

    pub fn validate(self: *const VerifierContextV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.authority_schema_version != AUTHORITY_SCHEMA_VERSION or
            self.flags != KNOWN_FLAGS)
        {
            return error.UnsupportedVersion;
        }
        try requireDigest(self.session_id);
        try requireDigest(self.job_id);
        try requireDigest(self.segment_leaf_vk_id);
        try requireDigest(self.aggregator_vk_id);
        try requireDigest(self.expected_parent_statement_id);
        if (self.parent_height == 0 or
            self.parent_height > span_statement.MAX_SLOT_HEIGHT)
        {
            return error.InvalidParentHeight;
        }
        const covered = @as(u64, 1) << @as(u6, @intCast(self.parent_height));
        _ = std.math.mul(u64, self.parent_node_index, covered) catch
            return error.InvalidParentHeight;
    }

    pub fn id(self: *const VerifierContextV2) Error!Digest {
        try self.validate();
        return contextIdAssumeValid(self);
    }
};

pub const VerifierAuthorityV2 = struct {
    context: VerifierContextV2,
    children: [CHILD_COUNT]VerifiedChildV2,

    pub fn validate(self: *const VerifierAuthorityV2) Error!void {
        const parent = try validateChildrenAndFold(
            &self.context,
            &self.children,
        );
        const words = try parent.canonicalWords();
        if (!std.meta.eql(
            statementWordsIdAssumeValid(&words),
            self.context.expected_parent_statement_id,
        )) return error.StatementMismatch;
    }
};

pub const RootVkPinV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    protocol_id: Digest = protocol.PROTOCOL_ID_WORDS,
    expected_aggregator_vk_id: Digest,

    pub fn validate(self: *const RootVkPinV2) Error!void {
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.protocol_id, protocol.PROTOCOL_ID_WORDS))
        {
            return error.UnsupportedVersion;
        }
        try requireDigest(self.expected_aggregator_vk_id);
    }
};

pub const AuthenticatedTemporalPairV2 = struct {
    format_id: Digest,
    protocol_id: Digest,
    session_id: Digest,
    job_id: Digest,
    aggregator_vk_id: Digest,
    parent_node_index: u64,
    parent_height: u8,
    parent_statement: span_statement.SpanStatement,
    parent_statement_words: span_statement.StatementWords,
    parent_statement_id: Digest,
    child_ids: [CHILD_COUNT]Digest,
    context_id: Digest,
    node_id: Digest,
    record_id: Digest,
};

pub const RootAuthenticatedTemporalPairV2 = struct {
    pair: AuthenticatedTemporalPairV2,
};

pub fn jobIdAssumeCanonical(
    words: *const span_statement.StatementWords,
) Digest {
    recordScalarPoseidonInvocations(
        permutationCount(JOB_ID_PREIMAGE_WORD_COUNT),
    );
    return channel.hashCanonicalWords(
        words[span_statement.canonical_layout.job_start..span_statement.canonical_layout.slot_start],
        JOB_ID_DOMAIN,
    );
}

pub fn closureReceiptId(child: *const VerifiedChildV2) Error!Digest {
    if (child.roster_count != COMPLETE_ROSTER_COUNT)
        return error.ClosureMismatch;
    try requireDigest(child.claimed_sums_id);
    try requireDigest(child.verifier_receipt_id);
    try requireDigest(child.relation_replay_id);
    try requireDigest(child.auxiliary_claim_seal_id);
    try requireZeroClosure(child.closure_value);
    var hash = AuthorityHasher.init(CLOSURE_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(child.roster_count);
    hash.digest(child.verifier_receipt_id);
    hash.digest(child.claimed_sums_id);
    hash.digest(child.relation_replay_id);
    hash.digest(child.auxiliary_claim_seal_id);
    hash.addU32s(&child.closure_value);
    return hash.finalize(CLOSURE_ID_PREIMAGE_WORD_COUNT);
}

pub fn validateChildrenAndFold(
    context: *const VerifierContextV2,
    children: *const [CHILD_COUNT]VerifiedChildV2,
) Error!span_statement.SpanStatement {
    try context.validate();
    var statements: [CHILD_COUNT]span_statement.SpanStatement = undefined;
    for (&statements, children, 0..) |*statement, *child, index| {
        const expected_position: ChildPosition = if (index == 0) .left else .right;
        if (child.position != expected_position)
            return error.ChildOrderMismatch;
        if (!std.meta.eql(child.session_id, context.session_id) or
            !std.meta.eql(child.job_id, context.job_id) or
            !std.meta.eql(
                child.recursive_parent_vk_id,
                context.aggregator_vk_id,
            ))
        {
            return error.ContextMismatch;
        }
        statement.* = try child.statement();
        const words_job_id = jobIdAssumeCanonical(&child.statement_words);
        if (!std.meta.eql(words_job_id, context.job_id))
            return error.ContextMismatch;
        try validateChildKind(context, child, statement.*);
    }

    const parent = try span_statement.SpanStatement.fold(
        statements[0],
        statements[1],
    );
    if (parent.slots.height != context.parent_height or
        parent.slots.nodeIndex() != context.parent_node_index)
    {
        return error.StatementMismatch;
    }
    return parent;
}

pub fn validateChildKind(
    context: *const VerifierContextV2,
    child: *const VerifiedChildV2,
    statement: span_statement.SpanStatement,
) Error!void {
    const expected_child_height = context.parent_height - 1;
    if (statement.slots.height != expected_child_height)
        return error.ChildKindMismatch;

    switch (child.kind) {
        .segment_leaf => {
            if (statement.slots.height != 0 or
                child.scope != .complete_execution or
                !child.proof_present)
            {
                return error.ChildKindMismatch;
            }
            switch (statement.body) {
                .executed => {},
                .empty => return error.ChildKindMismatch,
            }
            if (!std.meta.eql(
                child.verification_key_id,
                context.segment_leaf_vk_id,
            )) return error.VerificationKeyMismatch;
            try validateCompleteProofChild(child);
        },
        .binary_node => {
            if (statement.slots.height == 0 or
                child.scope != .complete_execution or
                !child.proof_present)
            {
                return error.ChildKindMismatch;
            }
            if (!std.meta.eql(
                child.verification_key_id,
                context.aggregator_vk_id,
            )) return error.VerificationKeyMismatch;
            try validateCompleteProofChild(child);
        },
        .empty_leaf => {
            if (statement.slots.height != 0 or
                child.scope != .protocol_padding or
                child.proof_present or
                child.roster_count != 0)
            {
                return error.ChildKindMismatch;
            }
            switch (statement.body) {
                .empty => {},
                .executed => return error.ChildKindMismatch,
            }
            if (!proofFieldsAreZero(child)) return error.EmptyChildHasProof;
            try requireZeroClosure(child.closure_value);
        },
    }
}

pub fn validateCompleteProofChild(child: *const VerifiedChildV2) Error!void {
    if (child.scope != .complete_execution or !child.proof_present)
        return error.InvalidProofScope;
    if (child.roster_count != COMPLETE_ROSTER_COUNT)
        return error.ClosureMismatch;
    inline for (.{
        child.verification_key_id,
        child.air_program_id,
        child.manifest_id,
        child.profile_id,
        child.proof_id,
        child.transcript_id,
        child.capture_id,
        child.verifier_receipt_id,
        child.claimed_sums_id,
        child.relation_replay_id,
        child.auxiliary_claim_seal_id,
        child.closure_receipt_id,
        child.lineage_id,
    }) |digest| try requireDigest(digest);
    const expected_closure = try closureReceiptId(child);
    if (!std.meta.eql(expected_closure, child.closure_receipt_id))
        return error.ClosureMismatch;
}

pub fn proofFieldsAreZero(child: *const VerifiedChildV2) bool {
    return digestIsZero(child.verification_key_id) and
        digestIsZero(child.air_program_id) and
        digestIsZero(child.manifest_id) and
        digestIsZero(child.profile_id) and
        digestIsZero(child.proof_id) and
        digestIsZero(child.transcript_id) and
        digestIsZero(child.capture_id) and
        digestIsZero(child.verifier_receipt_id) and
        digestIsZero(child.claimed_sums_id) and
        digestIsZero(child.relation_replay_id) and
        digestIsZero(child.auxiliary_claim_seal_id) and
        digestIsZero(child.closure_receipt_id) and
        digestIsZero(child.lineage_id);
}

pub fn contextIdAssumeValid(context: *const VerifierContextV2) Digest {
    var hash = AuthorityHasher.init(CONTEXT_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(AUTHORITY_SCHEMA_VERSION);
    hash.addU32(NODE_ID_SCHEMA_VERSION);
    hash.addU32(context.flags);
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.digest(context.session_id);
    hash.digest(context.job_id);
    hash.digest(context.segment_leaf_vk_id);
    hash.digest(context.aggregator_vk_id);
    hash.addU64(context.parent_node_index);
    hash.addU32(context.parent_height);
    hash.digest(context.expected_parent_statement_id);
    return hash.finalize(CONTEXT_ID_PREIMAGE_WORD_COUNT);
}

pub fn childIdFromStatementId(
    child: *const VerifiedChildV2,
    statement_id: Digest,
) Digest {
    var hash = AuthorityHasher.init(CHILD_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(@intFromEnum(child.position));
    hash.addU32(@intFromEnum(child.kind));
    hash.addU32(@intFromEnum(child.scope));
    hash.addU32(@intFromBool(child.proof_present));
    hash.addU32(child.roster_count);
    hash.digest(child.session_id);
    hash.digest(child.job_id);
    hash.digest(child.recursive_parent_vk_id);
    hash.digest(child.verification_key_id);
    hash.digest(child.air_program_id);
    hash.digest(child.manifest_id);
    hash.digest(child.profile_id);
    // The canonical statement remains retained in full for the AIR. Its
    // domain-separated identity is the transitive binding here, avoiding
    // another 52 scalar sponge permutations per child.
    hash.digest(statement_id);
    hash.digest(child.proof_id);
    hash.digest(child.transcript_id);
    hash.digest(child.capture_id);
    hash.digest(child.verifier_receipt_id);
    hash.digest(child.claimed_sums_id);
    hash.digest(child.relation_replay_id);
    hash.digest(child.auxiliary_claim_seal_id);
    hash.digest(child.closure_receipt_id);
    hash.digest(child.lineage_id);
    hash.addU32s(&child.closure_value);
    return hash.finalize(CHILD_ID_PREIMAGE_WORD_COUNT);
}

pub fn deriveNodeId(
    context_id: Digest,
    aggregator_vk_id: Digest,
    parent_statement_id: Digest,
    child_ids: [CHILD_COUNT]Digest,
) Digest {
    var hash = AuthorityHasher.init(NODE_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(NODE_ID_SCHEMA_VERSION);
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.digest(context_id);
    hash.digest(aggregator_vk_id);
    for (child_ids) |child_id| hash.digest(child_id);
    // The record retains and validates all 412 parent words.  Folding their
    // canonical statement identity removes one redundant full-statement hash
    // from every node while preserving the exact preimage commitment.
    hash.digest(parent_statement_id);
    return hash.finalize(NODE_ID_PREIMAGE_WORD_COUNT);
}

pub fn deriveRecordId(
    context_id: Digest,
    child_ids: [CHILD_COUNT]Digest,
    parent_statement_id: Digest,
    node_id: Digest,
) Digest {
    var hash = AuthorityHasher.init(RECORD_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.digest(context_id);
    for (child_ids) |child_id| hash.digest(child_id);
    hash.digest(parent_statement_id);
    hash.digest(node_id);
    return hash.finalize(RECORD_ID_PREIMAGE_WORD_COUNT);
}

pub fn statementWordsId(words: *const span_statement.StatementWords) Error!Digest {
    _ = try span_statement.SpanStatement.fromCanonicalWords(words);
    return statementWordsIdAssumeValid(words);
}

pub fn statementWordsIdAssumeValid(
    words: *const span_statement.StatementWords,
) Digest {
    var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word| {
        const value = word.toU32();
        std.debug.assert(value < m31.Modulus);
        destination.* = value;
    }
    recordScalarPoseidonInvocations(
        permutationCount(STATEMENT_ID_PREIMAGE_WORD_COUNT),
    );
    return protocol.statementId(&canonical);
}

pub fn requireZeroClosure(value: [4]u32) Error!void {
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalField;
        if (word != 0) return error.ClosureMismatch;
    }
}

pub fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalDigest;
        aggregate |= word;
    }
    if (aggregate == 0) return error.EmptyDigest;
}

pub fn digestIsZero(value: Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return false;
        aggregate |= word;
    }
    return aggregate == 0;
}

pub const AuthorityHasher = struct {
    inner: channel.CanonicalWordHasher,
    word_count: usize = 0,

    pub fn init(domain: u32) AuthorityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    pub fn addU32(self: *AuthorityHasher, value: anytype) void {
        const canonical: u32 = @intCast(value);
        std.debug.assert(canonical < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(canonical)};
        self.inner.update(&words);
        self.word_count += 1;
    }

    pub fn addU64(self: *AuthorityHasher, value: u64) void {
        self.addU32(@as(u32, @truncate(value & 0xffff)));
        self.addU32(@as(u32, @truncate((value >> 16) & 0xffff)));
        self.addU32(@as(u32, @truncate((value >> 32) & 0xffff)));
        self.addU32(@as(u32, @truncate(value >> 48)));
    }

    pub fn addU32s(self: *AuthorityHasher, values: []const u32) void {
        for (values) |value| self.addU32(value);
    }

    pub fn digest(self: *AuthorityHasher, value: Digest) void {
        self.addU32s(&value);
    }

    pub fn m31s(self: *AuthorityHasher, values: []const M31) void {
        self.inner.update(values);
        self.word_count += values.len;
    }

    pub fn finalize(
        self: *AuthorityHasher,
        comptime expected_word_count: usize,
    ) Digest {
        std.debug.assert(self.word_count == expected_word_count);
        recordScalarPoseidonInvocations(permutationCount(expected_word_count));
        return self.inner.finalize();
    }
};

pub fn permutationCount(comptime word_count: usize) usize {
    return channel.canonicalWordPermutationCount(word_count);
}
