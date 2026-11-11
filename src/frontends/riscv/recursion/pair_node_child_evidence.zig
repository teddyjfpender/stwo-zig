//! Internal pair node authority shard; use pair_node.zig publicly.

const dependency_0 = @import("pair_node_contract.zig");

const CHILD_COUNT = dependency_0.CHILD_COUNT;
const ChildPosition = dependency_0.ChildPosition;
const ChildRole = dependency_0.ChildRole;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FORMAT_ID_WORDS = dependency_0.FORMAT_ID_WORDS;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const KNOWN_FLAGS = dependency_0.KNOWN_FLAGS;
const MAGIC = dependency_0.MAGIC;
const MAX_KAPPA = dependency_0.MAX_KAPPA;
const NodeIdentitiesV1 = dependency_0.NodeIdentitiesV1;
const ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT = dependency_0.ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT;
const PRESENT = dependency_0.PRESENT;
const PROOF_FOLD_DOMAIN = dependency_0.PROOF_FOLD_DOMAIN;
const PreparedAuthorityV1 = dependency_0.PreparedAuthorityV1;
const PreparedProtocolSuiteV1 = dependency_0.PreparedProtocolSuiteV1;
const STATEMENT_FOLD_DOMAIN = dependency_0.STATEMENT_FOLD_DOMAIN;
const SUMMARY_FOLD_DOMAIN = dependency_0.SUMMARY_FOLD_DOMAIN;
const SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT = dependency_0.SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT;
const SecureFelt = dependency_0.SecureFelt;
const TRANSCRIPT_FOLD_DOMAIN = dependency_0.TRANSCRIPT_FOLD_DOMAIN;
const VerifiedChildV1 = dependency_0.VerifiedChildV1;
const VerifierContextV1 = dependency_0.VerifierContextV1;
const allZero = dependency_0.allZero;
const appendDigest = dependency_0.appendDigest;
const appendU64 = dependency_0.appendU64;
const appendWord = dependency_0.appendWord;
const appendWords = dependency_0.appendWords;
const channel = dependency_0.channel;
const deriveAuthorityContextPrepared = dependency_0.deriveAuthorityContextPrepared;
const deriveChallengeContextPinned = dependency_0.deriveChallengeContextPinned;
const ensureFormatSeal = dependency_0.ensureFormatSeal;
const nodeId = dependency_0.nodeId;
const pairFirstLeaf = dependency_0.pairFirstLeaf;
const prepareProtocolSuite = dependency_0.prepareProtocolSuite;
const protocol = dependency_0.protocol;
const requireDigest = dependency_0.requireDigest;
const std = dependency_0.std;
const validateContextPayload = dependency_0.validateContextPayload;
const validateEventCount = dependency_0.validateEventCount;
const validatePairIndex = dependency_0.validatePairIndex;

/// Authority reconstructed from an admitted context and exactly two
/// independently verified child proofs. `authenticatePair` compares every
/// encoded child-public field against these verifier-owned outputs.
pub const VerifierAuthorityV1 = struct {
    context: VerifierContextV1,
    children: [CHILD_COUNT]VerifiedChildV1,

    pub fn validate(self: *const VerifierAuthorityV1) Error!void {
        _ = try prepareProtocolSuite();
        _ = try prepareAuthority(self);
    }

    pub fn challengeContextId(self: *const VerifierAuthorityV1) Error!Digest {
        _ = try prepareProtocolSuite();
        return (try prepareAuthority(self)).challenge_context_id;
    }

    pub fn contextId(self: *const VerifierAuthorityV1) Error!Digest {
        _ = try prepareProtocolSuite();
        return (try prepareAuthority(self)).authority_context_id;
    }
};

/// One child public record. Statement/proof/transcript identities use the
/// canonical helpers in `protocol.zig`; `summary_id` is
/// `protocol.summaryId(canonical_summary_bytes)`. All four must be obtained
/// from the successful child verifier; this shadow layer never treats values
/// supplied beside unverified proof bytes as authority.
pub const ChildEvidenceV1 = struct {
    present: u8 = PRESENT,
    position: ChildPosition,
    role: ChildRole,
    padding: u8 = 0,
    leaf_index: u32,
    pair_index: u32,
    leaf_count: u32 = 1,
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

/// Fixed-capacity, pointer-free wire record for the first pair node.
pub const PairNodeRecordV1 = struct {
    magic: [8]u8 = MAGIC,
    version: u16 = FORMAT_VERSION,
    flags: u16 = KNOWN_FLAGS,
    child_count: u8 = CHILD_COUNT,
    header_padding: [3]u8 = .{0} ** 3,
    pair_index: u32,
    first_leaf_index: u32,
    claimed_leaf_count: u32 = CHILD_COUNT,
    kappa_bound: u32 = MAX_KAPPA,
    aggregator_vk_id: Digest,
    authority_context_id: Digest,
    children: [CHILD_COUNT]ChildEvidenceV1,

    pub fn validate(self: *const PairNodeRecordV1) Error!void {
        try ensureFormatSeal();
        try validateRecordPayload(self, null);
    }
};

/// Authenticated public result of the shadow fold. `proof_id` is an ordered
/// identity of the two already-verified child proofs; it is not a parent proof.
pub const AuthenticatedPairV1 = struct {
    format_id: Digest,
    protocol_id: Digest,
    session_id: Digest,
    challenge_context_id: Digest,
    authority_context_id: Digest,
    aggregator_vk_id: Digest,
    pair_index: u32,
    first_leaf_index: u32,
    leaf_count: u32,
    session_leaf_count: u32,
    identities: NodeIdentitiesV1,
    node_id: Digest,
};

/// Distinct result type for the final root boundary. A caller cannot
/// accidentally treat an unpinned pair result as root-authorized.
pub const RootAuthenticatedPairV1 = struct {
    pair: AuthenticatedPairV1,
};

/// The expected aggregator VK is deliberately supplied by the recursion root.
/// Once the real circuit exists this value becomes a reviewed constant in the
/// root verifier, not another value accepted from the proof being checked.
pub const RootVkPinV1 = struct {
    format_id: Digest = FORMAT_ID_WORDS,
    protocol_id: Digest = protocol.PROTOCOL_ID_WORDS,
    expected_aggregator_vk_id: Digest,

    pub fn validate(self: *const RootVkPinV1) Error!void {
        try ensureFormatSeal();
        try validateRootPinPayload(self);
    }
};

/// Fixed-size, by-value snapshot of one successfully admitted root authority.
/// It is a native capability, never a wire format: callers retain the original
/// verifier-owned authority and root pin, and the hot API rejects either input
/// (or this snapshot) if it changes after preparation.
pub const PreparedRootContextV1 = struct {
    suite_snapshot: PreparedProtocolSuiteV1,
    authority_snapshot: VerifierAuthorityV1,
    root_pin_snapshot: RootVkPinV1,
    challenge_context_id: Digest,
    authority_context_id: Digest,
};

/// Authority-cold preparation. The suite has already amortized immutable
/// format/protocol/parameter hashing; this pass performs the exact 17
/// context-dependent permutations once and snapshots all verifier authority.
pub fn prepareRootContext(
    suite: *const PreparedProtocolSuiteV1,
    authority: *const VerifierAuthorityV1,
    pin: *const RootVkPinV1,
) Error!PreparedRootContextV1 {
    try requirePreparedSuite(suite);
    try validateRootPinPayload(pin);
    const prepared = try prepareAuthority(authority);
    if (!std.meta.eql(
        authority.context.aggregator_vk_id,
        pin.expected_aggregator_vk_id,
    )) return error.RootVkMismatch;
    return .{
        .suite_snapshot = suite.*,
        .authority_snapshot = authority.*,
        .root_pin_snapshot = pin.*,
        .challenge_context_id = prepared.challenge_context_id,
        .authority_context_id = prepared.authority_context_id,
    };
}

pub fn authenticatePair(
    authority: *const VerifierAuthorityV1,
    record: *const PairNodeRecordV1,
) Error!AuthenticatedPairV1 {
    const suite = try prepareProtocolSuite();
    return authenticatePairPrepared(&suite, authority, record);
}

pub fn authenticatePairPrepared(
    suite: *const PreparedProtocolSuiteV1,
    authority: *const VerifierAuthorityV1,
    record: *const PairNodeRecordV1,
) Error!AuthenticatedPairV1 {
    try requirePreparedSuite(suite);
    const prepared = try prepareAuthority(authority);
    return authenticatePairFromPreparedAuthority(authority, prepared, record);
}

pub fn authenticatePairFromPreparedAuthority(
    authority: *const VerifierAuthorityV1,
    prepared: PreparedAuthorityV1,
    record: *const PairNodeRecordV1,
) Error!AuthenticatedPairV1 {
    try validateRecordPayload(record, prepared);
    const context = &authority.context;
    if (record.pair_index != context.pair_index)
        return error.PairIndexMismatch;
    if (!std.meta.eql(record.aggregator_vk_id, context.aggregator_vk_id))
        return error.AggregatorVkMismatch;

    const expected_challenge = prepared.challenge_context_id;
    const expected_context = prepared.authority_context_id;
    if (!std.meta.eql(record.authority_context_id, expected_context))
        return error.AuthorityContextMismatch;
    for (&record.children, &authority.children) |*child, *verified| {
        if (!std.meta.eql(child.session_id, context.session_id))
            return error.SessionMismatch;
        if (!std.meta.eql(child.challenge_context_id, expected_challenge))
            return error.ChallengeContextMismatch;
        if (!std.meta.eql(child.authority_context_id, expected_context))
            return error.AuthorityContextMismatch;
        if (!std.meta.eql(child.parent_vk_id, context.aggregator_vk_id))
            return error.AggregatorVkMismatch;
        if (child.event_count != context.event_count)
            return error.EventCountMismatch;
        if (!matchesVerifiedChild(child, verified))
            return error.ChildAuthorityMismatch;
    }

    const identities = foldIdentities(record, expected_context);
    return .{
        .format_id = FORMAT_ID_WORDS,
        .protocol_id = protocol.PROTOCOL_ID_WORDS,
        .session_id = context.session_id,
        .challenge_context_id = expected_challenge,
        .authority_context_id = expected_context,
        .aggregator_vk_id = context.aggregator_vk_id,
        .pair_index = record.pair_index,
        .first_leaf_index = record.first_leaf_index,
        .leaf_count = record.claimed_leaf_count,
        .session_leaf_count = context.session_leaf_count,
        .identities = identities,
        .node_id = nodeId(
            expected_context,
            context.aggregator_vk_id,
            record.pair_index,
            record.first_leaf_index,
            record.claimed_leaf_count,
            context.session_leaf_count,
            identities,
        ),
    };
}

pub fn authenticateRoot(
    authority: *const VerifierAuthorityV1,
    record: *const PairNodeRecordV1,
    pin: *const RootVkPinV1,
) Error!RootAuthenticatedPairV1 {
    const suite = try prepareProtocolSuite();
    return authenticateRootPrepared(&suite, authority, record, pin);
}

pub fn authenticateRootPrepared(
    suite: *const PreparedProtocolSuiteV1,
    authority: *const VerifierAuthorityV1,
    record: *const PairNodeRecordV1,
    pin: *const RootVkPinV1,
) Error!RootAuthenticatedPairV1 {
    try requirePreparedSuite(suite);
    try validateRootPinPayload(pin);
    const pair = try authenticatePairPrepared(suite, authority, record);
    if (!std.meta.eql(pair.aggregator_vk_id, pin.expected_aggregator_vk_id))
        return error.RootVkMismatch;
    return .{ .pair = pair };
}

pub fn requirePreparedSuite(suite: *const PreparedProtocolSuiteV1) Error!void {
    if (suite.state != .validated) return error.FormatSealMismatch;
}

pub fn requirePreparedRootContext(
    prepared: *const PreparedRootContextV1,
    authority: *const VerifierAuthorityV1,
    pin: *const RootVkPinV1,
) Error!void {
    try requirePreparedSuite(&prepared.suite_snapshot);
    if (!std.meta.eql(prepared.authority_snapshot, authority.*) or
        !std.meta.eql(prepared.root_pin_snapshot, pin.*))
    {
        return error.PreparedContextMismatch;
    }
    const snapshot = &prepared.authority_snapshot;
    if (!std.meta.eql(
        snapshot.context.aggregator_vk_id,
        prepared.root_pin_snapshot.expected_aggregator_vk_id,
    ) or !std.meta.eql(
        prepared.challenge_context_id,
        snapshot.children[0].challenge_context_id,
    ) or !std.meta.eql(
        prepared.challenge_context_id,
        snapshot.children[1].challenge_context_id,
    ) or !std.meta.eql(
        prepared.authority_context_id,
        snapshot.children[0].authority_context_id,
    ) or !std.meta.eql(
        prepared.authority_context_id,
        snapshot.children[1].authority_context_id,
    )) {
        return error.PreparedContextMismatch;
    }
}

pub fn validateRootPinPayload(pin: *const RootVkPinV1) Error!void {
    try requireDigest(pin.format_id);
    try requireDigest(pin.protocol_id);
    try requireDigest(pin.expected_aggregator_vk_id);
    if (!std.meta.eql(pin.format_id, FORMAT_ID_WORDS))
        return error.FormatSealMismatch;
    if (!std.meta.eql(pin.protocol_id, protocol.PROTOCOL_ID_WORDS))
        return error.ProtocolMismatch;
}

pub fn prepareAuthority(
    authority: *const VerifierAuthorityV1,
) Error!PreparedAuthorityV1 {
    try validateContextPayload(&authority.context);
    const challenge_context_id = deriveChallengeContextPinned(
        authority.context.session_id,
    );
    const authority_context_id = deriveAuthorityContextPrepared(
        &authority.context,
        challenge_context_id,
    );
    for (&authority.children, 0..) |*child, index|
        try validateVerifiedChild(
            &authority.context,
            child,
            index,
            challenge_context_id,
            authority_context_id,
        );
    if (sameVerifiedIdentity(&authority.children[0], &authority.children[1]))
        return error.DuplicateChildIdentity;
    if (!authority.children[0].signed_relation_total.add(
        authority.children[1].signed_relation_total,
    ).isZero()) return error.RelationNotClosed;
    return .{
        .session_id = authority.context.session_id,
        .challenge_context_id = challenge_context_id,
        .authority_context_id = authority_context_id,
    };
}

pub const ChallengeCache = struct {
    valid: bool = false,
    session_id: Digest = undefined,
    challenge_context_id: Digest = undefined,

    fn fromPrepared(prepared: PreparedAuthorityV1) ChallengeCache {
        return .{
            .valid = true,
            .session_id = prepared.session_id,
            .challenge_context_id = prepared.challenge_context_id,
        };
    }

    fn get(self: *ChallengeCache, session_id: Digest) Digest {
        if (self.valid and std.meta.eql(self.session_id, session_id))
            return self.challenge_context_id;
        const challenge_context_id = deriveChallengeContextPinned(session_id);
        self.* = .{
            .valid = true,
            .session_id = session_id,
            .challenge_context_id = challenge_context_id,
        };
        return challenge_context_id;
    }
};

pub fn validateRecordPayload(
    record: *const PairNodeRecordV1,
    prepared: ?PreparedAuthorityV1,
) Error!void {
    if (!std.mem.eql(u8, &record.magic, &MAGIC)) return error.InvalidMagic;
    if (record.version != FORMAT_VERSION) return error.UnsupportedVersion;
    if (record.flags != KNOWN_FLAGS) return error.UnknownFlags;
    if (record.child_count != CHILD_COUNT) return error.ChildCountMismatch;
    if (!allZero(&record.header_padding)) return error.NonZeroPadding;
    if (record.kappa_bound != MAX_KAPPA) return error.KappaBoundMismatch;
    try validatePairIndex(record.pair_index);
    try requireDigest(record.aggregator_vk_id);
    try requireDigest(record.authority_context_id);

    const expected_first = pairFirstLeaf(record.pair_index) catch
        return error.ChildIndexOverflow;
    if (record.first_leaf_index != expected_first)
        return error.ChildIndexMismatch;

    // Check addition before individual bounds so hostile counts cannot hide
    // machine overflow behind a later range error.
    const folded_count = std.math.add(
        u32,
        record.children[0].leaf_count,
        record.children[1].leaf_count,
    ) catch return error.LeafCountOverflow;
    for (record.children) |child| {
        if (child.leaf_count == 0) return error.LeafCountZero;
        if (child.leaf_count > record.kappa_bound)
            return error.KappaBoundExceeded;
    }
    if (folded_count > record.kappa_bound) return error.KappaBoundExceeded;
    if (record.claimed_leaf_count != folded_count)
        return error.LeafCountMismatch;
    if (record.children[0].leaf_count != 1 or
        record.children[1].leaf_count != 1)
    {
        return error.CountPadding;
    }

    var challenge_cache = if (prepared) |value|
        ChallengeCache.fromPrepared(value)
    else
        ChallengeCache{};
    for (&record.children, 0..) |*child, index|
        try validateChild(record, child, index, &challenge_cache);
    const left = &record.children[0];
    const right = &record.children[1];
    if (!std.meta.eql(left.session_id, right.session_id))
        return error.SessionMismatch;
    if (!std.meta.eql(left.challenge_context_id, right.challenge_context_id))
        return error.ChallengeContextMismatch;
    if (left.event_count != right.event_count)
        return error.EventCountMismatch;
    if (sameEvidenceIdentity(left, right))
        return error.DuplicateChildIdentity;
    if (!left.signed_relation_total.add(right.signed_relation_total).isZero())
        return error.RelationNotClosed;
}

pub fn validateChild(
    record: *const PairNodeRecordV1,
    child: *const ChildEvidenceV1,
    index: usize,
    challenge_cache: *ChallengeCache,
) Error!void {
    if (child.present != PRESENT) return error.OmittedChild;
    if (child.padding != 0) return error.NonZeroPadding;
    const expected_position: ChildPosition = if (index == 0) .left else .right;
    const expected_role: ChildRole = if (index == 0)
        .core_request
    else
        .poseidon2_provider;
    if (child.position != expected_position) return error.ChildOrderMismatch;
    if (child.role != expected_role) return error.ChildRoleMismatch;
    if (child.pair_index != record.pair_index) return error.PairIndexMismatch;
    if (child.leaf_index != record.first_leaf_index + index)
        return error.ChildIndexMismatch;
    try requireDigest(child.protocol_id);
    try requireDigest(child.session_id);
    try requireDigest(child.challenge_context_id);
    try requireDigest(child.authority_context_id);
    try requireDigest(child.parent_vk_id);
    try requireDigest(child.statement_id);
    try requireDigest(child.proof_id);
    try requireDigest(child.transcript_id);
    try requireDigest(child.summary_id);
    if (!std.meta.eql(child.protocol_id, protocol.PROTOCOL_ID_WORDS))
        return error.ProtocolMismatch;
    if (!std.meta.eql(
        child.challenge_context_id,
        challenge_cache.get(child.session_id),
    )) return error.ChallengeContextMismatch;
    if (!std.meta.eql(child.authority_context_id, record.authority_context_id))
        return error.AuthorityContextMismatch;
    if (!std.meta.eql(child.parent_vk_id, record.aggregator_vk_id))
        return error.AggregatorVkMismatch;
    try validateEventCount(child.event_count);
    child.signed_relation_total.validate() catch
        return error.NonCanonicalField;
    if (child.event_count == 0 and !child.signed_relation_total.isZero())
        return error.RelationNotClosed;
}

pub fn sameEvidenceIdentity(left: *const ChildEvidenceV1, right: *const ChildEvidenceV1) bool {
    return std.meta.eql(left.statement_id, right.statement_id) and
        std.meta.eql(left.proof_id, right.proof_id) and
        std.meta.eql(left.transcript_id, right.transcript_id);
}

pub fn validateVerifiedChild(
    context: *const VerifierContextV1,
    child: *const VerifiedChildV1,
    index: usize,
    challenge_context_id: Digest,
    authority_context_id: Digest,
) Error!void {
    const expected_position: ChildPosition = if (index == 0) .left else .right;
    const expected_role: ChildRole = if (index == 0)
        .core_request
    else
        .poseidon2_provider;
    const first_leaf = pairFirstLeaf(context.pair_index) catch
        return error.ChildIndexOverflow;
    const expected_leaf = std.math.add(
        u32,
        first_leaf,
        @intCast(index),
    ) catch return error.ChildIndexOverflow;
    if (child.position != expected_position or child.role != expected_role or
        child.leaf_index != expected_leaf or
        child.pair_index != context.pair_index or child.leaf_count != 1)
    {
        return error.ChildAuthorityMismatch;
    }
    try requireDigest(child.protocol_id);
    try requireDigest(child.session_id);
    try requireDigest(child.challenge_context_id);
    try requireDigest(child.authority_context_id);
    try requireDigest(child.parent_vk_id);
    try requireDigest(child.statement_id);
    try requireDigest(child.proof_id);
    try requireDigest(child.transcript_id);
    try requireDigest(child.summary_id);
    if (!std.meta.eql(child.protocol_id, protocol.PROTOCOL_ID_WORDS))
        return error.ProtocolMismatch;
    if (!std.meta.eql(child.session_id, context.session_id))
        return error.SessionMismatch;
    if (!std.meta.eql(child.challenge_context_id, challenge_context_id))
        return error.ChallengeContextMismatch;
    if (!std.meta.eql(child.authority_context_id, authority_context_id))
        return error.AuthorityContextMismatch;
    if (!std.meta.eql(child.parent_vk_id, context.aggregator_vk_id))
        return error.AggregatorVkMismatch;
    if (child.event_count != context.event_count)
        return error.EventCountMismatch;
    try validateEventCount(child.event_count);
    child.signed_relation_total.validate() catch
        return error.NonCanonicalField;
    if (child.event_count == 0 and !child.signed_relation_total.isZero())
        return error.RelationNotClosed;
}

pub fn matchesVerifiedChild(
    claimed: *const ChildEvidenceV1,
    verified: *const VerifiedChildV1,
) bool {
    return claimed.position == verified.position and
        claimed.role == verified.role and
        claimed.leaf_index == verified.leaf_index and
        claimed.pair_index == verified.pair_index and
        claimed.leaf_count == verified.leaf_count and
        std.meta.eql(claimed.protocol_id, verified.protocol_id) and
        std.meta.eql(claimed.session_id, verified.session_id) and
        std.meta.eql(
            claimed.challenge_context_id,
            verified.challenge_context_id,
        ) and
        std.meta.eql(claimed.authority_context_id, verified.authority_context_id) and
        std.meta.eql(claimed.parent_vk_id, verified.parent_vk_id) and
        std.meta.eql(claimed.statement_id, verified.statement_id) and
        std.meta.eql(claimed.proof_id, verified.proof_id) and
        std.meta.eql(claimed.transcript_id, verified.transcript_id) and
        std.meta.eql(claimed.summary_id, verified.summary_id) and
        claimed.event_count == verified.event_count and
        std.meta.eql(
            claimed.signed_relation_total,
            verified.signed_relation_total,
        );
}

pub fn sameVerifiedIdentity(left: *const VerifiedChildV1, right: *const VerifiedChildV1) bool {
    return std.meta.eql(left.statement_id, right.statement_id) and
        std.meta.eql(left.proof_id, right.proof_id) and
        std.meta.eql(left.transcript_id, right.transcript_id);
}

pub const IdentityKind = enum { statement, proof, transcript, summary };

pub fn foldIdentities(
    record: *const PairNodeRecordV1,
    authority_context_id: Digest,
) NodeIdentitiesV1 {
    return .{
        .statement_id = foldIdentity(
            STATEMENT_FOLD_DOMAIN,
            record,
            authority_context_id,
            .statement,
        ),
        .proof_id = foldIdentity(
            PROOF_FOLD_DOMAIN,
            record,
            authority_context_id,
            .proof,
        ),
        .transcript_id = foldIdentity(
            TRANSCRIPT_FOLD_DOMAIN,
            record,
            authority_context_id,
            .transcript,
        ),
        .summary_id = foldIdentity(
            SUMMARY_FOLD_DOMAIN,
            record,
            authority_context_id,
            .summary,
        ),
    };
}

pub fn foldIdentity(
    comptime domain: u32,
    record: *const PairNodeRecordV1,
    authority_context_id: Digest,
    comptime kind: IdentityKind,
) Digest {
    const word_count = if (kind == .summary)
        SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT
    else
        ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT;
    var words: [word_count]u32 = undefined;
    var at: usize = 0;
    appendDigest(&words, &at, FORMAT_ID_WORDS);
    appendDigest(&words, &at, authority_context_id);
    appendDigest(&words, &at, record.aggregator_vk_id);
    appendWord(&words, &at, record.pair_index);
    appendWord(&words, &at, record.first_leaf_index);
    appendWord(&words, &at, record.claimed_leaf_count);
    for (&record.children) |*child| {
        appendWord(&words, &at, @intFromEnum(child.position));
        appendWord(&words, &at, @intFromEnum(child.role));
        appendWord(&words, &at, child.leaf_index);
        appendWord(&words, &at, child.leaf_count);
        appendDigest(&words, &at, switch (kind) {
            .statement => child.statement_id,
            .proof => child.proof_id,
            .transcript => child.transcript_id,
            .summary => child.summary_id,
        });
        if (kind == .summary) {
            appendU64(&words, &at, child.event_count);
            appendWords(&words, &at, &child.signed_relation_total.limbs);
        }
    }
    std.debug.assert(at == words.len);
    return channel.hashCanonicalU32s(&words, domain);
}
