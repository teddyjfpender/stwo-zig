//! Internal pair node authority shard; use pair_node.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");
pub const channel = @import("poseidon2_channel.zig");
pub const protocol = @import("protocol.zig");

pub const m31 = stwo_core.fields.m31;

pub const Digest = protocol.Digest;
pub const SecureFelt = protocol.SecureFelt;
pub const ChildPosition = protocol.ChildPosition;
pub const ChildRole = protocol.LeafRole;

pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const RECURSIVE_PROOF_VERIFICATION = false;
pub const RECURSIVE_PROOF_PRODUCTION = false;
pub const PRODUCTION_ACTIVATION = false;

pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'P', 'A', 'I', 'R', 0 };
pub const FORMAT_VERSION: u16 = 1;
pub const WIRE_SCHEMA_VERSION: u16 = 1;
pub const AUTHORITY_CONTEXT_SCHEMA_VERSION: u16 = 2;
pub const IDENTITY_FOLD_SCHEMA_VERSION: u16 = 1;
pub const NODE_ID_SCHEMA_VERSION: u16 = 2;
pub const KNOWN_FLAGS: u16 = 0;
pub const CHILD_COUNT: u8 = 2;
pub const PRESENT: u8 = 1;
pub const MAX_KAPPA: u32 = protocol.MAX_LEAVES;
pub const MAX_PAIR_INDEX: u32 = MAX_KAPPA / CHILD_COUNT - 1;

pub const FORMAT_ID_DOMAIN: u32 = 0x504e_464d; // "PNFM"
pub const AUTHORITY_CONTEXT_DOMAIN: u32 = 0x504e_4358; // "PNCX"
pub const STATEMENT_FOLD_DOMAIN: u32 = 0x504e_5354; // "PNST"
pub const PROOF_FOLD_DOMAIN: u32 = 0x504e_5052; // "PNPR"
pub const TRANSCRIPT_FOLD_DOMAIN: u32 = 0x504e_5452; // "PNTR"
pub const SUMMARY_FOLD_DOMAIN: u32 = 0x504e_5355; // "PNSU"
pub const NODE_ID_DOMAIN: u32 = 0x504e_4e44; // "PNND"
pub const RECORD_ID_DOMAIN: u32 = 0x504e_5749; // "PNWI"
pub const VERIFICATION_KEY_ID_DOMAIN: u32 = 0x504e_564b; // "PNVK"

pub const HEADER_ENCODED_LEN: usize = 96;
pub const CHILD_ENCODED_LEN: usize = 328;
pub const ENCODED_LEN: usize = HEADER_ENCODED_LEN + CHILD_COUNT * CHILD_ENCODED_LEN;

pub const FORMAT_ID_PREIMAGE_WORD_COUNT: usize = 50;
pub const AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT: usize =
    9 * channel.RATE + 2 + 4;
pub const ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT: usize =
    3 * channel.RATE + 3 + CHILD_COUNT * (4 + channel.RATE);
pub const SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT: usize =
    ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT + CHILD_COUNT * (4 + 4);
pub const NODE_ID_PREIMAGE_WORD_COUNT: usize =
    3 * channel.RATE + 4 + 4 * channel.RATE;

pub const AuthenticationPermutationPhaseV1 = enum(u8) {
    suite_preparation,
    context_preparation,
    authenticated_output,
};

pub const AuthenticationPermutationEncodingV1 = enum(u8) {
    canonical_words,
    injective_bytes,
};

pub const AuthenticationPermutationStageV1 = enum(u8) {
    format_id,
    protocol_id,
    relation_name_id,
    relation_domain_id,
    poseidon_parameter_id,
    empty_call_commitment,
    challenge_context_id,
    authority_context_id,
    statement_fold,
    proof_fold,
    transcript_fold,
    summary_fold,
    node_id,
};

/// One exact hash invocation in the successful V1 authentication call tree.
/// `unit_count` is a word count or byte count according to `encoding`.
pub const AuthenticationPermutationCallV1 = struct {
    stage: AuthenticationPermutationStageV1,
    phase: AuthenticationPermutationPhaseV1,
    encoding: AuthenticationPermutationEncodingV1,
    domain: u32,
    unit_count: usize,
    invocations: usize,
    permutations_per_invocation: usize,

    pub fn total(self: AuthenticationPermutationCallV1) usize {
        return self.invocations * self.permutations_per_invocation;
    }
};

/// Executable source-level instrumentation of every scalar Poseidon2-M31
/// permutation on the successful authentication path. Counts are derived from
/// the actual absorbed lengths, including the sponge end marker.
pub const AUTHENTICATION_PERMUTATION_CALL_TREE_V1 = [_]AuthenticationPermutationCallV1{
    permutationCall(
        .format_id,
        .suite_preparation,
        .canonical_words,
        FORMAT_ID_DOMAIN,
        FORMAT_ID_PREIMAGE_WORD_COUNT,
    ),
    permutationCall(
        .protocol_id,
        .suite_preparation,
        .canonical_words,
        protocol.PROTOCOL_ID_DOMAIN,
        protocol.PROTOCOL_ID_PREIMAGE_WORD_COUNT,
    ),
    permutationCall(
        .relation_name_id,
        .suite_preparation,
        .injective_bytes,
        protocol.RELATION_DOMAIN_ID_DOMAIN,
        protocol.RELATION_NAME.len,
    ),
    permutationCall(
        .relation_domain_id,
        .suite_preparation,
        .canonical_words,
        protocol.RELATION_DOMAIN_ID_DOMAIN,
        channel.RATE + 3,
    ),
    permutationCall(
        .poseidon_parameter_id,
        .suite_preparation,
        .canonical_words,
        channel.PARAMETER_ID_DOMAIN,
        channel.PARAMETER_WORD_COUNT,
    ),
    permutationCall(
        .empty_call_commitment,
        .context_preparation,
        .injective_bytes,
        protocol.EMPTY_CALL_ID_DOMAIN,
        protocol.RELATION_NAME.len,
    ),
    permutationCall(
        .challenge_context_id,
        .context_preparation,
        .canonical_words,
        protocol.CHALLENGE_CONTEXT_ID_DOMAIN,
        channel.RATE * 3,
    ),
    permutationCall(
        .authority_context_id,
        .context_preparation,
        .canonical_words,
        AUTHORITY_CONTEXT_DOMAIN,
        AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT,
    ),
    permutationCall(
        .statement_fold,
        .authenticated_output,
        .canonical_words,
        STATEMENT_FOLD_DOMAIN,
        ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT,
    ),
    permutationCall(
        .proof_fold,
        .authenticated_output,
        .canonical_words,
        PROOF_FOLD_DOMAIN,
        ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT,
    ),
    permutationCall(
        .transcript_fold,
        .authenticated_output,
        .canonical_words,
        TRANSCRIPT_FOLD_DOMAIN,
        ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT,
    ),
    permutationCall(
        .summary_fold,
        .authenticated_output,
        .canonical_words,
        SUMMARY_FOLD_DOMAIN,
        SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT,
    ),
    permutationCall(
        .node_id,
        .authenticated_output,
        .canonical_words,
        NODE_ID_DOMAIN,
        NODE_ID_PREIMAGE_WORD_COUNT,
    ),
};

pub fn authenticationPermutationTotal(
    phase: AuthenticationPermutationPhaseV1,
) usize {
    var total: usize = 0;
    for (AUTHENTICATION_PERMUTATION_CALL_TREE_V1) |call| {
        if (call.phase == phase) total += call.total();
    }
    return total;
}

/// Immutable RED baseline retained after the prepared-context optimization.
/// The 229 figure is the original conservative audit estimate; 55 and 94 are
/// exact pre-change call trees derived by the instrumentation above.
pub const AuthenticationPermutationBaselineV1 = struct {
    pub const historical_audit_static_estimate: usize = 229;
    pub const pre_context_cache_prepared_root: usize =
        authenticationPermutationTotal(.context_preparation) +
        authenticationPermutationTotal(.authenticated_output);
    pub const pre_context_cache_convenience_root: usize =
        authenticationPermutationTotal(.suite_preparation) +
        pre_context_cache_prepared_root;
};

/// Checked scalar-Poseidon cost ledger for successful V1 root authentication.
/// Suite preparation is tree-cold, context preparation is authority-cold, and
/// the prepared-context form retains only transcript-authoritative outputs on
/// its hot path.
pub const AuthenticationPermutationCostV1 = struct {
    pub const prior_audit_static_estimate: usize =
        AuthenticationPermutationBaselineV1.historical_audit_static_estimate;
    pub const suite_preparation: usize =
        authenticationPermutationTotal(.suite_preparation);
    pub const context_preparation: usize =
        authenticationPermutationTotal(.context_preparation);
    pub const successful_context_prepared_root: usize =
        authenticationPermutationTotal(.authenticated_output);
    pub const successful_prepared_root: usize =
        AuthenticationPermutationBaselineV1.pre_context_cache_prepared_root;
    pub const successful_convenience_root: usize =
        AuthenticationPermutationBaselineV1.pre_context_cache_convenience_root;
};

/// Exact heap-allocation ledger. All three capabilities are fixed-size values
/// and every operation accepts no allocator.
pub const AuthenticationAllocationCostV1 = struct {
    pub const suite_preparation: usize = 0;
    pub const context_preparation: usize = 0;
    pub const successful_context_prepared_root: usize = 0;
};

/// Poseidon2-M31 identity of the V1 wire envelope and pair-node domain suite.
/// Exact field order and identity preimages are additionally pinned by the
/// canonical codec and golden wire/fold/node vectors; this is intentionally
/// not presented as a generic reflection of the Zig struct ABI.
pub const FORMAT_ID_WORDS = Digest{
    1_280_860_399,
    1_757_885_852,
    133_459_384,
    1_288_702_946,
    1_604_617_872,
    329_028_813,
    336_786_798,
    649_316_935,
};

pub const Error = error{
    AggregatorVkMismatch,
    AliasedBuffer,
    AuthorityContextMismatch,
    CallCommitmentMismatch,
    ChallengeContextMismatch,
    ChildAuthorityMismatch,
    ChildCountMismatch,
    ChildIndexMismatch,
    ChildIndexOverflow,
    ChildOrderMismatch,
    ChildRoleMismatch,
    CountPadding,
    DuplicateChildIdentity,
    EmptyDigest,
    EmptyVerificationKey,
    EventCountMismatch,
    EventCountOutOfRange,
    FormatSealMismatch,
    InvalidMagic,
    KappaBoundExceeded,
    KappaBoundMismatch,
    LeafCountMismatch,
    LeafCountOverflow,
    LeafCountZero,
    NonCanonicalField,
    NonEmptyZeroCallCommitment,
    NonEmptyEmptyCallCommitment,
    NonZeroPadding,
    OmittedChild,
    PairIndexMismatch,
    PairIndexOutOfRange,
    PreparedContextMismatch,
    ProtocolMismatch,
    RelationDomainMismatch,
    RelationNotClosed,
    RootVkMismatch,
    PairOutsideSession,
    SessionLeafCountOutOfRange,
    SessionMismatch,
    UnknownFlags,
    UnsupportedVersion,
    VerificationKeyTooLarge,
};

/// Verifier-owned context shared by both children. It intentionally carries no
/// claimed challenge-context digest: that digest is re-derived from
/// `session_id` before either child record is admitted.
pub const VerifierContextV1 = struct {
    session_id: Digest,
    job_id: Digest,
    execution_statement_id: Digest,
    public_call_commitment: Digest,
    event_count: u64,
    /// Exact leaf count from the admitted session manifest. V1 pair nodes
    /// consume two leaves, so odd or partial final pairs are not representable.
    session_leaf_count: u32,
    pair_index: u32,
    aggregator_vk_id: Digest,

    pub fn validate(self: *const VerifierContextV1) Error!void {
        _ = try prepareProtocolSuite();
        try validateContextPayload(self);
    }

    pub fn challengeContextId(self: *const VerifierContextV1) Error!Digest {
        try self.validate();
        return deriveChallengeContextPinned(self.session_id);
    }

    pub fn contextId(self: *const VerifierContextV1) Error!Digest {
        try self.validate();
        const challenge_context_id = deriveChallengeContextPinned(self.session_id);
        return deriveAuthorityContextPrepared(self, challenge_context_id);
    }
};

/// Expected public output reconstructed by the caller from one successful
/// child-proof verification. This shadow module cannot enforce provenance;
/// copying a record's own claims here would provide no authentication. The
/// production seam must consume the actual child-verifier result type.
pub const VerifiedChildV1 = struct {
    position: ChildPosition,
    role: ChildRole,
    leaf_index: u32,
    pair_index: u32,
    leaf_count: u32,
    protocol_id: Digest,
    session_id: Digest,
    challenge_context_id: Digest,
    authority_context_id: Digest,
    parent_vk_id: Digest,
    statement_id: Digest,
    proof_id: Digest,
    transcript_id: Digest,
    summary_id: Digest,
    event_count: u64,
    signed_relation_total: SecureFelt,
};

pub const NodeIdentitiesV1 = struct {
    statement_id: Digest,
    proof_id: Digest,
    transcript_id: Digest,
    summary_id: Digest,
};

pub const PreparedSuiteState = enum(u8) { invalid = 0, validated = 1 };

/// Cold-path capability produced only after the immutable format, protocol,
/// relation, security profile, and Poseidon parameter seals agree. Reuse one
/// value across a tree to remove 39 scalar permutations from every node.
pub const PreparedProtocolSuiteV1 = struct {
    state: PreparedSuiteState,
};

pub fn prepareProtocolSuite() Error!PreparedProtocolSuiteV1 {
    try ensureFormatSeal();
    (protocol.Profile{}).validate() catch return error.ProtocolMismatch;
    return .{ .state = .validated };
}

pub fn formatId() Digest {
    var words: [FORMAT_ID_PREIMAGE_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    for (MAGIC) |byte| appendWord(&words, &at, byte);
    const prefix = [_]u32{
        FORMAT_VERSION,
        WIRE_SCHEMA_VERSION,
        AUTHORITY_CONTEXT_SCHEMA_VERSION,
        IDENTITY_FOLD_SCHEMA_VERSION,
        NODE_ID_SCHEMA_VERSION,
        KNOWN_FLAGS,
        CHILD_COUNT,
        PRESENT,
        HEADER_ENCODED_LEN,
        CHILD_ENCODED_LEN,
        ENCODED_LEN,
        MAX_KAPPA,
        MAX_PAIR_INDEX,
        @intFromEnum(ChildPosition.left),
        @intFromEnum(ChildPosition.right),
        @intFromEnum(ChildRole.core_request),
        @intFromEnum(ChildRole.poseidon2_provider),
        FORMAT_ID_DOMAIN,
        AUTHORITY_CONTEXT_DOMAIN,
        STATEMENT_FOLD_DOMAIN,
        PROOF_FOLD_DOMAIN,
        TRANSCRIPT_FOLD_DOMAIN,
        SUMMARY_FOLD_DOMAIN,
        NODE_ID_DOMAIN,
        RECORD_ID_DOMAIN,
        VERIFICATION_KEY_ID_DOMAIN,
    };
    appendWords(&words, &at, &prefix);
    appendDigest(&words, &at, protocol.PROTOCOL_ID_WORDS);
    appendDigest(&words, &at, protocol.RELATION_DOMAIN_ID_WORDS);
    std.debug.assert(at == words.len);
    return channel.hashCanonicalU32s(&words, FORMAT_ID_DOMAIN);
}

pub fn ensureFormatSeal() Error!void {
    if (!std.meta.eql(formatId(), FORMAT_ID_WORDS))
        return error.FormatSealMismatch;
    if (!std.meta.eql(protocol.protocolId(), protocol.PROTOCOL_ID_WORDS))
        return error.ProtocolMismatch;
    if (!std.meta.eql(protocol.relationDomainId(), protocol.RELATION_DOMAIN_ID_WORDS))
        return error.RelationDomainMismatch;
}

pub fn validateContextPayload(context: *const VerifierContextV1) Error!void {
    try requireDigest(context.session_id);
    try requireDigest(context.job_id);
    try requireDigest(context.execution_statement_id);
    try requireDigest(context.public_call_commitment);
    try requireDigest(context.aggregator_vk_id);
    try validateEventCount(context.event_count);
    if (context.session_leaf_count < CHILD_COUNT or
        context.session_leaf_count > MAX_KAPPA or
        !std.math.isPowerOfTwo(context.session_leaf_count))
    {
        return error.SessionLeafCountOutOfRange;
    }
    try validatePairIndex(context.pair_index);
    if (context.pair_index >= context.session_leaf_count / CHILD_COUNT)
        return error.PairOutsideSession;
    try validateCallCommitment(
        context.public_call_commitment,
        context.event_count,
    );
}

pub const PreparedAuthorityV1 = struct {
    session_id: Digest,
    challenge_context_id: Digest,
    authority_context_id: Digest,
};

pub fn deriveChallengeContextPinned(session_id: Digest) Digest {
    var words: [channel.RATE * 3]u32 = undefined;
    @memcpy(words[0..channel.RATE], &session_id);
    @memcpy(
        words[channel.RATE..][0..channel.RATE],
        &protocol.PROTOCOL_ID_WORDS,
    );
    @memcpy(
        words[2 * channel.RATE ..][0..channel.RATE],
        &protocol.RELATION_DOMAIN_ID_WORDS,
    );
    return channel.hashCanonicalU32s(&words, protocol.CHALLENGE_CONTEXT_ID_DOMAIN);
}

pub fn deriveAuthorityContextPrepared(
    authority: *const VerifierContextV1,
    challenge_context_id: Digest,
) Digest {
    var words: [AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    appendDigest(&words, &at, FORMAT_ID_WORDS);
    appendDigest(&words, &at, protocol.PROTOCOL_ID_WORDS);
    appendDigest(&words, &at, protocol.RELATION_DOMAIN_ID_WORDS);
    appendDigest(&words, &at, authority.session_id);
    appendDigest(&words, &at, challenge_context_id);
    appendDigest(&words, &at, authority.job_id);
    appendDigest(&words, &at, authority.execution_statement_id);
    appendDigest(&words, &at, authority.public_call_commitment);
    appendDigest(&words, &at, authority.aggregator_vk_id);
    appendWord(&words, &at, authority.session_leaf_count);
    appendWord(&words, &at, authority.pair_index);
    appendU64(&words, &at, authority.event_count);
    std.debug.assert(at == words.len);
    return channel.hashCanonicalU32s(&words, AUTHORITY_CONTEXT_DOMAIN);
}

pub fn nodeId(
    authority_context_id: Digest,
    aggregator_vk_id: Digest,
    pair_index: u32,
    first_leaf_index: u32,
    leaf_count: u32,
    session_leaf_count: u32,
    identities: NodeIdentitiesV1,
) Digest {
    var words: [NODE_ID_PREIMAGE_WORD_COUNT]u32 = undefined;
    var at: usize = 0;
    appendDigest(&words, &at, FORMAT_ID_WORDS);
    appendDigest(&words, &at, authority_context_id);
    appendDigest(&words, &at, aggregator_vk_id);
    appendWord(&words, &at, pair_index);
    appendWord(&words, &at, first_leaf_index);
    appendWord(&words, &at, leaf_count);
    appendWord(&words, &at, session_leaf_count);
    appendDigest(&words, &at, identities.statement_id);
    appendDigest(&words, &at, identities.proof_id);
    appendDigest(&words, &at, identities.transcript_id);
    appendDigest(&words, &at, identities.summary_id);
    std.debug.assert(at == words.len);
    return channel.hashCanonicalU32s(&words, NODE_ID_DOMAIN);
}

pub fn validatePairIndex(pair_index: u32) Error!void {
    if (pair_index > MAX_PAIR_INDEX) return error.PairIndexOutOfRange;
}

pub fn pairFirstLeaf(pair_index: u32) error{ChildIndexOverflow}!u32 {
    return std.math.mul(u32, pair_index, CHILD_COUNT) catch
        return error.ChildIndexOverflow;
}

pub fn validateEventCount(count: u64) Error!void {
    protocol.validateEventCount(count) catch return error.EventCountOutOfRange;
}

pub fn validateCallCommitment(commitment: Digest, event_count: u64) Error!void {
    if (event_count == 0) {
        if (!std.meta.eql(commitment, protocol.emptyCallCommitment()))
            return error.CallCommitmentMismatch;
    } else {
        if (isZeroDigest(commitment)) return error.NonEmptyZeroCallCommitment;
        if (std.meta.eql(commitment, protocol.emptyCallCommitment()))
            return error.NonEmptyEmptyCallCommitment;
    }
}

pub fn requireDigest(value: Digest) Error!void {
    for (value) |word| if (word >= m31.Modulus)
        return error.NonCanonicalField;
    if (isZeroDigest(value)) return error.EmptyDigest;
}

pub fn isZeroDigest(value: Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

pub fn allZero(bytes: []const u8) bool {
    var aggregate: u8 = 0;
    for (bytes) |byte| aggregate |= byte;
    return aggregate == 0;
}

pub fn appendDigest(words: anytype, at: *usize, value: Digest) void {
    appendWords(words, at, &value);
}

pub fn appendU64(words: anytype, at: *usize, value: u64) void {
    inline for (0..4) |index|
        appendWord(words, at, @intCast((value >> (16 * index)) & 0xffff));
}

pub fn appendWords(words: anytype, at: *usize, values: []const u32) void {
    for (values) |value| appendWord(words, at, value);
}

pub fn appendWord(words: anytype, at: *usize, value: u32) void {
    std.debug.assert(at.* < words.len);
    std.debug.assert(value < m31.Modulus);
    words[at.*] = value;
    at.* += 1;
}

pub fn permutationCall(
    stage: AuthenticationPermutationStageV1,
    phase: AuthenticationPermutationPhaseV1,
    encoding: AuthenticationPermutationEncodingV1,
    domain: u32,
    unit_count: usize,
) AuthenticationPermutationCallV1 {
    return .{
        .stage = stage,
        .phase = phase,
        .encoding = encoding,
        .domain = domain,
        .unit_count = unit_count,
        .invocations = 1,
        .permutations_per_invocation = switch (encoding) {
            .canonical_words => channel.canonicalWordPermutationCount(
                unit_count,
            ),
            .injective_bytes => channel.bytePermutationCount(unit_count),
        },
    };
}
