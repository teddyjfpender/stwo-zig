//! Frozen V1 protocol boundary for recursion-targeted RISC-V proofs.
//!
//! Proof bytes are untrusted values.  They do not select the field, hash,
//! transcript schedule, PCS security, leaf roles, or relation schema.  Those
//! choices live here and are absorbed into one Poseidon2-M31 protocol ID.
//!
//! V1 first authenticates the independently provable core/request and
//! Poseidon2/provider halves of one execution.  Both leaves must name the same
//! admitted execution, session, job, relation domain, call commitment, and
//! event count.  Their signed relation totals must close exactly.  Segment
//! continuation is deliberately outside this format; adding it requires a new
//! statement version with explicit entry/exit machine states.

const std = @import("std");
const stwo_core = @import("stwo_core");
const aggregation_types = @import("../aggregation/types.zig");
const public_data = @import("../air/public_data.zig");
const channel = @import("poseidon2_channel.zig");

const m31 = stwo_core.fields.m31;
const pcs = stwo_core.pcs;

pub const Digest = channel.Digest;
pub const SecureFelt = aggregation_types.SecureFelt;

pub const PROTOCOL_VERSION: u32 = 1;
pub const LEAF_STATEMENT_DOMAIN: u32 =
    public_data.STATEMENT_TRANSCRIPT_DOMAIN;
pub const LEAF_STATEMENT_VERSION: u32 = public_data.STATEMENT_TRANSCRIPT_VERSION;
pub const IDENTITY_DOMAIN_SUITE_VERSION: u32 = 1;
pub const PROTOCOL_ID_DOMAIN: u32 = 0x5250; // "RP"
pub const RELATION_DOMAIN_ID_DOMAIN: u32 = 0x5244; // "RD"
pub const PAIR_STATEMENT_ID_DOMAIN: u32 = 0x5251; // "RQ"
pub const EMPTY_CALL_ID_DOMAIN: u32 = 0x4543; // "EC"
pub const CHALLENGE_CONTEXT_ID_DOMAIN: u32 = 0x4343; // "CC"
pub const STATEMENT_ID_DOMAIN: u32 = 0x5354_4d54; // "STMT"
pub const PROOF_ID_DOMAIN: u32 = 0x5052_4f46; // "PROF"
pub const TRANSCRIPT_ID_DOMAIN: u32 = 0x5452_4e53; // "TRNS"
pub const SUMMARY_ID_DOMAIN: u32 = 0x5355_4d4d; // "SUMM"
pub const HASH_SUITE_ID: u32 = 0x5032_4d31; // "P2M1"
pub const FIELD_ID: u32 = 0x4d33_3101; // "M31" + version
pub const SECURE_EXTENSION_DEGREE: u32 = 4;
pub const INTERACTION_POW_BITS: u32 = 10;
pub const PCS_POW_BITS: u32 = 16;
pub const FRI_LOG_BLOWUP_FACTOR: u32 = 1;
pub const FRI_QUERY_COUNT: usize = 193;
pub const FRI_FOLD_STEP: u32 = 4;
pub const FRI_LOG_LAST_LAYER_DEGREE_BOUND: u32 = 0;
pub const COMMITMENT_TREE_COUNT: u32 = 4;
pub const PCS_LIFTING_MODE_NONE: u32 = 0;
/// The query-plus-PoW ledger is deliberately above the algebraic and hash
/// ceilings.  It is not itself an end-to-end security claim.
pub const MIN_CONFIGURED_PCS_BITS: u32 = 128;
pub const SECURE_FIELD_CAPACITY_BITS: u32 = 124;
pub const TARGET_SECURITY_BITS: u32 = 120;
pub const MAX_LEAVES: u32 = @intCast(aggregation_types.MAX_LEAVES);
pub const RELATION_SCHEMA_ID: u32 = aggregation_types.RELATION_SCHEMA_ID;
pub const RELATION_SCHEMA_VERSION: u32 = aggregation_types.RELATION_SCHEMA_VERSION;
pub const RELATION_ARITY: u32 = aggregation_types.RELATION_ARITY;
pub const RELATION_NAME = "stwo.riscv.guest_poseidon2_io";
pub const PROFILE_WORD_COUNT: usize = 32;
pub const PROTOCOL_IDENTITY_DOMAIN_COUNT: usize = 9;
pub const PROTOCOL_ID_PREIMAGE_WORD_COUNT: usize =
    PROFILE_WORD_COUNT + PROTOCOL_IDENTITY_DOMAIN_COUNT;

pub const POSEIDON_PARAMETER_ID_WORDS = Digest{
    1_552_978_421,
    1_023_370_636,
    374_843_654,
    773_724_958,
    693_890_342,
    438_823_919,
    709_179_351,
    1_509_913_758,
};

/// Cross-language conformance identities for the frozen V1 profile and
/// relation domain.  Intentional protocol changes update these values together
/// with the versioned manifest; accidental changes fail locally.
pub const PROTOCOL_ID_WORDS = Digest{
    369_535_897,
    1_353_874_838,
    1_147_415_759,
    568_299_296,
    1_554_543_833,
    1_672_540_135,
    1_992_443_198,
    914_248_870,
};
pub const RELATION_DOMAIN_ID_WORDS = Digest{
    1_306_696_982,
    1_726_603_315,
    1_397_393_048,
    902_790_331,
    1_854_055_429,
    843_052_026,
    1_890_344_447,
    149_606_425,
};

pub const PCS_CONFIG: pcs.PcsConfig = .{
    .pow_bits = PCS_POW_BITS,
    .fri_config = .{
        .log_blowup_factor = FRI_LOG_BLOWUP_FACTOR,
        .log_last_layer_degree_bound = FRI_LOG_LAST_LAYER_DEGREE_BOUND,
        .n_queries = FRI_QUERY_COUNT,
        .fold_step = FRI_FOLD_STEP,
    },
    .lifting_log_size = null,
};

pub const Error = error{
    CallCommitmentMismatch,
    ChallengeContextMismatch,
    ChildIndexMismatch,
    ChildOrderMismatch,
    ContextMismatch,
    DuplicateLeafIdentity,
    EmptyDigest,
    EventCountMismatch,
    EventCountOutOfRange,
    NonCanonicalDigest,
    NonCanonicalM31,
    NonEmptyZeroCallCommitment,
    NonEmptyEmptyCallCommitment,
    PairIndexOutOfRange,
    ProtocolMismatch,
    RelationDomainMismatch,
    RelationNotClosed,
    SecurityProfileMismatch,
};

pub const LeafRole = enum(u32) {
    core_request = 1,
    poseidon2_provider = 2,
};

pub const ChildPosition = enum(u32) {
    left = 0,
    right = 1,
};

/// Every verifier-owned protocol choice that affects recursive proof meaning.
pub const Profile = struct {
    protocol_version: u32 = PROTOCOL_VERSION,
    leaf_statement_domain: u32 = LEAF_STATEMENT_DOMAIN,
    leaf_statement_version: u32 = LEAF_STATEMENT_VERSION,
    field_id: u32 = FIELD_ID,
    field_modulus: u32 = m31.Modulus,
    secure_extension_degree: u32 = SECURE_EXTENSION_DEGREE,
    hash_suite_id: u32 = HASH_SUITE_ID,
    poseidon_parameter_id: Digest = POSEIDON_PARAMETER_ID_WORDS,
    poseidon_width: u32 = 16,
    poseidon_rate: u32 = @intCast(channel.RATE),
    interaction_pow_bits: u32 = INTERACTION_POW_BITS,
    pcs_pow_bits: u32 = PCS_POW_BITS,
    fri_log_blowup_factor: u32 = FRI_LOG_BLOWUP_FACTOR,
    fri_query_count: u32 = @intCast(FRI_QUERY_COUNT),
    fri_fold_step: u32 = FRI_FOLD_STEP,
    fri_log_last_layer_degree_bound: u32 =
        FRI_LOG_LAST_LAYER_DEGREE_BOUND,
    commitment_tree_count: u32 = COMMITMENT_TREE_COUNT,
    pcs_lifting_mode: u32 = PCS_LIFTING_MODE_NONE,
    relation_schema_id: u32 = RELATION_SCHEMA_ID,
    relation_schema_version: u32 = RELATION_SCHEMA_VERSION,
    relation_arity: u32 = RELATION_ARITY,
    max_leaves: u32 = MAX_LEAVES,
    secure_field_capacity_bits: u32 = SECURE_FIELD_CAPACITY_BITS,
    target_security_bits: u32 = TARGET_SECURITY_BITS,

    pub fn validate(self: Profile) Error!void {
        const expected = Profile{};
        if (!std.meta.eql(self, expected)) return error.SecurityProfileMismatch;
        if (!std.meta.eql(channel.parameterId(), POSEIDON_PARAMETER_ID_WORDS))
            return error.SecurityProfileMismatch;
        if (PCS_CONFIG.pow_bits != self.pcs_pow_bits or
            PCS_CONFIG.fri_config.log_blowup_factor != self.fri_log_blowup_factor or
            PCS_CONFIG.fri_config.log_last_layer_degree_bound !=
                self.fri_log_last_layer_degree_bound or
            PCS_CONFIG.fri_config.n_queries != self.fri_query_count or
            PCS_CONFIG.fri_config.fold_step != self.fri_fold_step or
            PCS_CONFIG.lifting_log_size != null or
            self.pcs_lifting_mode != PCS_LIFTING_MODE_NONE)
        {
            return error.SecurityProfileMismatch;
        }
        if (self.target_security_bits > self.secure_field_capacity_bits or
            self.target_security_bits > self.hashCollisionBits() or
            PCS_CONFIG.securityBits() < MIN_CONFIGURED_PCS_BITS)
        {
            return error.SecurityProfileMismatch;
        }
        if (PCS_CONFIG.securityBits() !=
            PCS_POW_BITS + FRI_LOG_BLOWUP_FACTOR * FRI_QUERY_COUNT)
        {
            return error.SecurityProfileMismatch;
        }
    }

    pub fn hashCollisionBits(self: Profile) u32 {
        return self.poseidon_rate * 31 / 2;
    }

    pub fn words(self: Profile) [PROFILE_WORD_COUNT]u32 {
        var result: [PROFILE_WORD_COUNT]u32 = undefined;
        var at: usize = 0;
        const prefix = [_]u32{
            self.protocol_version,
            self.leaf_statement_domain,
            self.leaf_statement_version,
            self.field_id,
            self.field_modulus & 0xffff,
            self.field_modulus >> 16,
            self.secure_extension_degree,
            self.hash_suite_id,
        };
        @memcpy(result[at..][0..prefix.len], &prefix);
        at += prefix.len;
        @memcpy(result[at..][0..self.poseidon_parameter_id.len], &self.poseidon_parameter_id);
        at += self.poseidon_parameter_id.len;
        const suffix = [_]u32{
            self.poseidon_width,
            self.poseidon_rate,
            self.interaction_pow_bits,
            self.pcs_pow_bits,
            self.fri_log_blowup_factor,
            self.fri_query_count,
            self.fri_fold_step,
            self.fri_log_last_layer_degree_bound,
            self.commitment_tree_count,
            self.pcs_lifting_mode,
            self.relation_schema_id,
            self.relation_schema_version,
            self.relation_arity,
            self.max_leaves,
            self.secure_field_capacity_bits,
            self.target_security_bits,
        };
        @memcpy(result[at..][0..suffix.len], &suffix);
        at += suffix.len;
        std.debug.assert(at == result.len);
        return result;
    }
};

pub fn protocolId() Digest {
    const profile = Profile{};
    const profile_words = profile.words();
    var words: [PROTOCOL_ID_PREIMAGE_WORD_COUNT]u32 = undefined;
    @memcpy(words[0..profile_words.len], &profile_words);
    const identity_domains = [_]u32{
        IDENTITY_DOMAIN_SUITE_VERSION,
        RELATION_DOMAIN_ID_DOMAIN,
        PAIR_STATEMENT_ID_DOMAIN,
        EMPTY_CALL_ID_DOMAIN,
        CHALLENGE_CONTEXT_ID_DOMAIN,
        STATEMENT_ID_DOMAIN,
        PROOF_ID_DOMAIN,
        TRANSCRIPT_ID_DOMAIN,
        SUMMARY_ID_DOMAIN,
    };
    std.debug.assert(identity_domains.len == PROTOCOL_IDENTITY_DOMAIN_COUNT);
    @memcpy(words[profile_words.len..], &identity_domains);
    return channel.hashCanonicalU32s(&words, PROTOCOL_ID_DOMAIN);
}

pub fn relationDomainId() Digest {
    const name_id = channel.hashBytes(RELATION_NAME, RELATION_DOMAIN_ID_DOMAIN);
    var words: [channel.RATE + 3]u32 = undefined;
    @memcpy(words[0..channel.RATE], &name_id);
    words[channel.RATE + 0] = RELATION_SCHEMA_ID;
    words[channel.RATE + 1] = RELATION_SCHEMA_VERSION;
    words[channel.RATE + 2] = RELATION_ARITY;
    return channel.hashCanonicalU32s(&words, RELATION_DOMAIN_ID_DOMAIN);
}

pub fn emptyCallCommitment() Digest {
    return channel.hashBytes(RELATION_NAME, EMPTY_CALL_ID_DOMAIN);
}

/// Shared relation challenges are session-specific and verifier-derived.  A
/// leaf cannot select an arbitrary nonzero context digest beside an otherwise
/// valid proof.
pub fn challengeContextId(session_id: Digest) Digest {
    var words: [channel.RATE * 3]u32 = undefined;
    @memcpy(words[0..channel.RATE], &session_id);
    const protocol_id = protocolId();
    @memcpy(words[channel.RATE..][0..channel.RATE], &protocol_id);
    const relation_domain_id = relationDomainId();
    @memcpy(words[2 * channel.RATE ..][0..channel.RATE], &relation_domain_id);
    return channel.hashCanonicalU32s(&words, CHALLENGE_CONTEXT_ID_DOMAIN);
}

/// Identity functions used by both the native verification boundary and the
/// future in-AIR verifier.  The caller must supply the versioned canonical
/// statement words and canonical proof bytes accepted by the selected V1
/// codecs; these helpers deliberately do not accept an in-memory struct ABI.
pub fn statementId(canonical_words: []const u32) Digest {
    return channel.hashCanonicalU32s(canonical_words, STATEMENT_ID_DOMAIN);
}

pub fn proofId(canonical_bytes: []const u8) Digest {
    return channel.hashBytes(canonical_bytes, PROOF_ID_DOMAIN);
}

pub fn transcriptId(terminal_digest: Digest, draw_count: u32) Digest {
    var words: [channel.RATE + 2]u32 = undefined;
    @memcpy(words[0..channel.RATE], &terminal_digest);
    words[channel.RATE] = draw_count & 0xffff;
    words[channel.RATE + 1] = draw_count >> 16;
    return channel.hashCanonicalU32s(&words, TRANSCRIPT_ID_DOMAIN);
}

/// Identity of the versioned canonical child-public/relation-summary bytes
/// returned beside an independently verified child proof. The byte length and
/// two-byte packing in `hashBytes` make this encoding injective.
pub fn summaryId(canonical_bytes: []const u8) Digest {
    return channel.hashBytes(canonical_bytes, SUMMARY_ID_DOMAIN);
}

/// Verifier-owned context shared by both independently proved halves.
///
/// `execution_statement_id` is the Poseidon2-M31 digest of the canonical native
/// RISC-V statement and public data.  The recursion leaf verifier must
/// recompute it from the verified inner proof; a value merely supplied beside
/// the proof is not authority.
pub const PairContextV1 = struct {
    protocol_id: Digest,
    session_id: Digest,
    job_id: Digest,
    challenge_context_id: Digest,
    execution_statement_id: Digest,
    relation_domain_id: Digest,
    public_call_commitment: Digest,
    event_count: u64,

    pub fn validate(self: PairContextV1) Error!void {
        try validateDigest(self.protocol_id);
        try validateDigest(self.session_id);
        try validateDigest(self.job_id);
        try validateDigest(self.challenge_context_id);
        try validateDigest(self.execution_statement_id);
        try validateDigest(self.relation_domain_id);
        try validateDigest(self.public_call_commitment);
        if (!std.meta.eql(self.protocol_id, protocolId()))
            return error.ProtocolMismatch;
        if (!std.meta.eql(self.relation_domain_id, relationDomainId()))
            return error.RelationDomainMismatch;
        if (!std.meta.eql(
            self.challenge_context_id,
            challengeContextId(self.session_id),
        )) return error.ChallengeContextMismatch;
        try validateEventCount(self.event_count);
        if (self.event_count == 0) {
            if (!std.meta.eql(self.public_call_commitment, emptyCallCommitment()))
                return error.CallCommitmentMismatch;
        } else {
            if (isZeroDigest(self.public_call_commitment))
                return error.NonEmptyZeroCallCommitment;
            if (std.meta.eql(self.public_call_commitment, emptyCallCommitment()))
                return error.NonEmptyEmptyCallCommitment;
        }
    }
};

pub const RelationTotalV1 = struct {
    event_count: u64,
    signed_total: SecureFelt,

    pub fn validate(self: RelationTotalV1) Error!void {
        try validateEventCount(self.event_count);
        self.signed_total.validate() catch return error.NonCanonicalM31;
        if (self.event_count == 0 and !self.signed_total.isZero())
            return error.RelationNotClosed;
    }
};

/// Fixed public input exposed by one recursion leaf branch.
pub const LeafPublicInputV1 = struct {
    context: PairContextV1,
    inner_statement_id: Digest,
    inner_proof_id: Digest,
    inner_transcript_id: Digest,
    leaf_index: u32,
    pair_index: u32,
    child_position: ChildPosition,
    role: LeafRole,
    relation: RelationTotalV1,

    pub fn validate(self: LeafPublicInputV1) Error!void {
        try self.context.validate();
        try validateDigest(self.inner_statement_id);
        try validateDigest(self.inner_proof_id);
        try validateDigest(self.inner_transcript_id);
        try self.relation.validate();
        if (self.relation.event_count != self.context.event_count)
            return error.EventCountMismatch;
        if (self.pair_index >= MAX_LEAVES / 2)
            return error.PairIndexOutOfRange;
        const position: u32 = @intFromEnum(self.child_position);
        if (self.leaf_index != self.pair_index * 2 + position)
            return error.ChildIndexMismatch;
        const correct_role = switch (self.child_position) {
            .left => self.role == .core_request,
            .right => self.role == .poseidon2_provider,
        };
        if (!correct_role) return error.ChildOrderMismatch;
    }
};

/// Canonical statement exposed by the first two-to-one recursion node.
pub const PairPublicInputV1 = struct {
    context: PairContextV1,
    pair_index: u32,
    first_leaf_index: u32,
    leaf_count: u32,
    pair_statement_id: Digest,
};

pub fn validateAndFoldPair(
    left: LeafPublicInputV1,
    right: LeafPublicInputV1,
) Error!PairPublicInputV1 {
    try left.validate();
    try right.validate();
    if (left.child_position != .left or right.child_position != .right)
        return error.ChildOrderMismatch;
    if (left.pair_index != right.pair_index or
        right.leaf_index != left.leaf_index + 1)
    {
        return error.ChildIndexMismatch;
    }
    if (!std.meta.eql(left.context, right.context)) return error.ContextMismatch;
    if (std.meta.eql(left.inner_statement_id, right.inner_statement_id) and
        std.meta.eql(left.inner_proof_id, right.inner_proof_id) and
        std.meta.eql(left.inner_transcript_id, right.inner_transcript_id))
    {
        return error.DuplicateLeafIdentity;
    }
    if (!left.relation.signed_total.add(right.relation.signed_total).isZero())
        return error.RelationNotClosed;

    return .{
        .context = left.context,
        .pair_index = left.pair_index,
        .first_leaf_index = left.leaf_index,
        .leaf_count = 2,
        .pair_statement_id = pairStatementId(left, right),
    };
}

fn pairStatementId(left: LeafPublicInputV1, right: LeafPublicInputV1) Digest {
    var words: [128]u32 = undefined;
    var len: usize = 0;
    appendDigest(&words, &len, left.context.protocol_id);
    appendDigest(&words, &len, left.context.session_id);
    appendDigest(&words, &len, left.context.job_id);
    appendDigest(&words, &len, left.context.challenge_context_id);
    appendDigest(&words, &len, left.context.execution_statement_id);
    appendDigest(&words, &len, left.context.relation_domain_id);
    appendDigest(&words, &len, left.context.public_call_commitment);
    appendWord(&words, &len, @intCast(left.context.event_count));
    appendLeafIdentity(&words, &len, left);
    appendLeafIdentity(&words, &len, right);
    return channel.hashCanonicalU32s(words[0..len], PAIR_STATEMENT_ID_DOMAIN);
}

fn appendLeafIdentity(
    words: *[128]u32,
    len: *usize,
    leaf: LeafPublicInputV1,
) void {
    appendDigest(words, len, leaf.inner_statement_id);
    appendDigest(words, len, leaf.inner_proof_id);
    appendDigest(words, len, leaf.inner_transcript_id);
    appendWord(words, len, leaf.leaf_index);
    appendWord(words, len, leaf.pair_index);
    appendWord(words, len, @intFromEnum(leaf.child_position));
    appendWord(words, len, @intFromEnum(leaf.role));
    for (leaf.relation.signed_total.limbs) |limb| appendWord(words, len, limb);
}

fn appendDigest(words: *[128]u32, len: *usize, digest: Digest) void {
    for (digest) |word| appendWord(words, len, word);
}

fn appendWord(words: *[128]u32, len: *usize, word: u32) void {
    std.debug.assert(len.* < words.len);
    std.debug.assert(word < m31.Modulus);
    words[len.*] = word;
    len.* += 1;
}

pub fn validateEventCount(event_count: u64) Error!void {
    aggregation_types.validateCallCount(event_count) catch
        return error.EventCountOutOfRange;
}

fn validateDigest(digest: Digest) Error!void {
    for (digest) |word| {
        if (word >= m31.Modulus) return error.NonCanonicalDigest;
    }
    if (isZeroDigest(digest)) return error.EmptyDigest;
}

fn isZeroDigest(digest: Digest) bool {
    var aggregate: u32 = 0;
    for (digest) |word| aggregate |= word;
    return aggregate == 0;
}

const Fixture = struct {
    left: LeafPublicInputV1,
    right: LeafPublicInputV1,

    fn init(event_count: u64) Fixture {
        const total = if (event_count == 0)
            SecureFelt.zero()
        else
            SecureFelt{ .limbs = .{ 5, 7, 11, 13 } };
        const context = PairContextV1{
            .protocol_id = protocolId(),
            .session_id = testId("session"),
            .job_id = testId("job"),
            .challenge_context_id = challengeContextId(testId("session")),
            .execution_statement_id = testId("execution"),
            .relation_domain_id = relationDomainId(),
            .public_call_commitment = if (event_count == 0)
                emptyCallCommitment()
            else
                testId("ordered-calls"),
            .event_count = event_count,
        };
        return .{
            .left = .{
                .context = context,
                .inner_statement_id = testId("core-statement"),
                .inner_proof_id = testId("core-proof"),
                .inner_transcript_id = testId("core-transcript"),
                .leaf_index = 6,
                .pair_index = 3,
                .child_position = .left,
                .role = .core_request,
                .relation = .{
                    .event_count = event_count,
                    .signed_total = total.neg(),
                },
            },
            .right = .{
                .context = context,
                .inner_statement_id = testId("provider-statement"),
                .inner_proof_id = testId("provider-proof"),
                .inner_transcript_id = testId("provider-transcript"),
                .leaf_index = 7,
                .pair_index = 3,
                .child_position = .right,
                .role = .poseidon2_provider,
                .relation = .{
                    .event_count = event_count,
                    .signed_total = total,
                },
            },
        };
    }
};

fn testId(label: []const u8) Digest {
    return channel.hashBytes(label, 0x5445); // "TE"
}

test "recursion protocol: profile and identifiers are frozen" {
    const profile = Profile{};
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 209), PCS_CONFIG.securityBits());
    try std.testing.expectEqual(@as(u32, 124), profile.hashCollisionBits());
    try std.testing.expectEqual(@as(u32, 120), profile.target_security_bits);
    try std.testing.expectEqual(POSEIDON_PARAMETER_ID_WORDS, channel.parameterId());
    try std.testing.expectEqual(PROTOCOL_ID_WORDS, protocolId());
    try std.testing.expectEqual(RELATION_DOMAIN_ID_WORDS, relationDomainId());
    try std.testing.expect(!std.meta.eql(PROTOCOL_ID_WORDS, RELATION_DOMAIN_ID_WORDS));
    std.debug.print(
        "\n  R-011 V1: protocol={any} relation_domain={any} configured_pcs_bits={d} target_bits={d}\n",
        .{
            protocolId(),
            relationDomainId(),
            PCS_CONFIG.securityBits(),
            profile.target_security_bits,
        },
    );
}

test "recursion protocol: canonical child identity domains are separated" {
    const payload = "canonical-child-public-v1";
    try std.testing.expect(!std.meta.eql(proofId(payload), summaryId(payload)));
    try std.testing.expect(!std.meta.eql(
        summaryId(payload),
        summaryId("canonical-child-public-v1\x00"),
    ));
}

test "recursion protocol: security identity binds parameters and transcript draws" {
    var mutated_profile = Profile{};
    mutated_profile.poseidon_parameter_id[0] +%= 1;
    try std.testing.expectError(
        error.SecurityProfileMismatch,
        mutated_profile.validate(),
    );

    const terminal = testId("terminal-transcript");
    try std.testing.expect(!std.meta.eql(
        transcriptId(terminal, 0),
        transcriptId(terminal, 1),
    ));
    try std.testing.expect(!std.meta.eql(
        statementId(&.{ 1, 2, 3 }),
        statementId(&.{ 1, 2, 4 }),
    ));
    try std.testing.expect(!std.meta.eql(
        proofId("proof-a"),
        proofId("proof-b"),
    ));
}

test "recursion protocol: core and provider leaves fold canonically" {
    const fixture = Fixture.init(2);
    const pair = try validateAndFoldPair(fixture.left, fixture.right);
    try std.testing.expectEqual(@as(u32, 3), pair.pair_index);
    try std.testing.expectEqual(@as(u32, 6), pair.first_leaf_index);
    try std.testing.expectEqual(@as(u32, 2), pair.leaf_count);
    try validateDigest(pair.pair_statement_id);
    try std.testing.expectEqualDeep(
        pair,
        try validateAndFoldPair(fixture.left, fixture.right),
    );
}

test "recursion protocol: swapped duplicated and non-adjacent leaves reject" {
    const fixture = Fixture.init(2);
    try std.testing.expectError(
        error.ChildOrderMismatch,
        validateAndFoldPair(fixture.right, fixture.left),
    );

    var duplicate = fixture.right;
    duplicate.inner_statement_id = fixture.left.inner_statement_id;
    duplicate.inner_proof_id = fixture.left.inner_proof_id;
    duplicate.inner_transcript_id = fixture.left.inner_transcript_id;
    try std.testing.expectError(
        error.DuplicateLeafIdentity,
        validateAndFoldPair(fixture.left, duplicate),
    );

    var non_adjacent = fixture.right;
    non_adjacent.leaf_index += 2;
    try std.testing.expectError(
        error.ChildIndexMismatch,
        validateAndFoldPair(fixture.left, non_adjacent),
    );
}

test "recursion protocol: cross-session/challenge and unclosed relations reject" {
    const fixture = Fixture.init(2);
    var cross_session = fixture.right;
    cross_session.context.session_id = testId("foreign-session");
    cross_session.context.challenge_context_id = challengeContextId(
        cross_session.context.session_id,
    );
    try std.testing.expectError(
        error.ContextMismatch,
        validateAndFoldPair(fixture.left, cross_session),
    );

    var cross_challenge = fixture.right;
    cross_challenge.context.session_id = testId("foreign-session-2");
    cross_challenge.context.challenge_context_id = challengeContextId(
        cross_challenge.context.session_id,
    );
    try std.testing.expectError(
        error.ContextMismatch,
        validateAndFoldPair(fixture.left, cross_challenge),
    );

    var supplied_challenge = fixture.right;
    supplied_challenge.context.challenge_context_id = testId("foreign-challenge");
    try std.testing.expectError(
        error.ChallengeContextMismatch,
        validateAndFoldPair(fixture.left, supplied_challenge),
    );

    var cross_transcript = fixture.right;
    cross_transcript.inner_transcript_id = fixture.left.inner_transcript_id;
    cross_transcript.inner_statement_id = fixture.left.inner_statement_id;
    cross_transcript.inner_proof_id = testId("different-proof");
    // A different proof remains a distinct leaf identity; changing a
    // transcript is bound into the resulting pair statement rather than
    // silently discarded.
    const changed = try validateAndFoldPair(fixture.left, cross_transcript);
    const canonical = try validateAndFoldPair(fixture.left, fixture.right);
    try std.testing.expect(!std.meta.eql(
        changed.pair_statement_id,
        canonical.pair_statement_id,
    ));

    var unclosed = fixture.right;
    unclosed.relation.signed_total.limbs[0] +%= 1;
    try std.testing.expectError(
        error.RelationNotClosed,
        validateAndFoldPair(fixture.left, unclosed),
    );
}

test "recursion protocol: empty relation and protocol authority are exact" {
    const empty = Fixture.init(0);
    _ = try validateAndFoldPair(empty.left, empty.right);

    var wrong_commitment = empty.left;
    wrong_commitment.context.public_call_commitment = testId("not-empty");
    try std.testing.expectError(
        error.CallCommitmentMismatch,
        wrong_commitment.validate(),
    );

    var nonempty_with_empty_commitment = Fixture.init(1).left;
    nonempty_with_empty_commitment.context.public_call_commitment =
        emptyCallCommitment();
    try std.testing.expectError(
        error.NonEmptyEmptyCallCommitment,
        nonempty_with_empty_commitment.validate(),
    );

    var wrong_protocol = empty.left;
    wrong_protocol.context.protocol_id = testId("foreign-protocol");
    try std.testing.expectError(
        error.ProtocolMismatch,
        wrong_protocol.validate(),
    );
}
