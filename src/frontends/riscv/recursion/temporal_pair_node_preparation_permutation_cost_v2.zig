//! Internal temporal pair node authority shard; use temporal_pair_node.zig publicly.

const dependency_0 = @import("temporal_pair_node_contract.zig");

const AUTHORITY_SCHEMA_VERSION = dependency_0.AUTHORITY_SCHEMA_VERSION;
const AuthorityHasher = dependency_0.AuthorityHasher;
const CHILD_COUNT = dependency_0.CHILD_COUNT;
const CHILD_ID_DOMAIN = dependency_0.CHILD_ID_DOMAIN;
const CHILD_ID_PREIMAGE_WORD_COUNT = dependency_0.CHILD_ID_PREIMAGE_WORD_COUNT;
const CLOSURE_ID_DOMAIN = dependency_0.CLOSURE_ID_DOMAIN;
const CLOSURE_ID_PREIMAGE_WORD_COUNT = dependency_0.CLOSURE_ID_PREIMAGE_WORD_COUNT;
const COMPLETE_ROSTER_COUNT = dependency_0.COMPLETE_ROSTER_COUNT;
const CONTEXT_ID_DOMAIN = dependency_0.CONTEXT_ID_DOMAIN;
const CONTEXT_ID_PREIMAGE_WORD_COUNT = dependency_0.CONTEXT_ID_PREIMAGE_WORD_COUNT;
const ChildPosition = dependency_0.ChildPosition;
const Digest = dependency_0.Digest;
const Error = dependency_0.Error;
const FORMAT_ID_DOMAIN = dependency_0.FORMAT_ID_DOMAIN;
const FORMAT_ID_PREIMAGE_WORD_COUNT = dependency_0.FORMAT_ID_PREIMAGE_WORD_COUNT;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const JOB_ID_DOMAIN = dependency_0.JOB_ID_DOMAIN;
const JOB_ID_PREIMAGE_WORD_COUNT = dependency_0.JOB_ID_PREIMAGE_WORD_COUNT;
const KNOWN_FLAGS = dependency_0.KNOWN_FLAGS;
const M31 = dependency_0.M31;
const NODE_ID_DOMAIN = dependency_0.NODE_ID_DOMAIN;
const NODE_ID_PREIMAGE_WORD_COUNT = dependency_0.NODE_ID_PREIMAGE_WORD_COUNT;
const NODE_ID_SCHEMA_VERSION = dependency_0.NODE_ID_SCHEMA_VERSION;
const ProofKind = dependency_0.ProofKind;
const ProofScope = dependency_0.ProofScope;
const RECORD_ID_DOMAIN = dependency_0.RECORD_ID_DOMAIN;
const RECORD_ID_PREIMAGE_WORD_COUNT = dependency_0.RECORD_ID_PREIMAGE_WORD_COUNT;
const RootAuthenticatedTemporalPairV2 = dependency_0.RootAuthenticatedTemporalPairV2;
const RootVkPinV2 = dependency_0.RootVkPinV2;
const STATEMENT_ID_PREIMAGE_WORD_COUNT = dependency_0.STATEMENT_ID_PREIMAGE_WORD_COUNT;
const VerifiedChildV2 = dependency_0.VerifiedChildV2;
const VerifierAuthorityV2 = dependency_0.VerifierAuthorityV2;
const VerifierContextV2 = dependency_0.VerifierContextV2;
const builtin = dependency_0.builtin;
const childIdFromStatementId = dependency_0.childIdFromStatementId;
const contextIdAssumeValid = dependency_0.contextIdAssumeValid;
const deriveNodeId = dependency_0.deriveNodeId;
const deriveRecordId = dependency_0.deriveRecordId;
const jobIdAssumeCanonical = dependency_0.jobIdAssumeCanonical;
const permutationCount = dependency_0.permutationCount;
const protocol = dependency_0.protocol;
const span_statement = dependency_0.span_statement;
const statementWordsIdAssumeValid = dependency_0.statementWordsIdAssumeValid;
const std = dependency_0.std;
const validateChildrenAndFold = dependency_0.validateChildrenAndFold;

/// Exact successful cold-path scalar Poseidon2-M31 ledger. A complete child
/// contributes one closure-receipt hash; an empty protocol leaf contributes
/// none. The historical constants describe the implementation immediately
/// before `PreparedDerivationV2` removed repeated derivation walks.
pub const PreparationPermutationCostV2 = struct {
    pub const format_id = permutationCount(FORMAT_ID_PREIMAGE_WORD_COUNT);
    pub const job_id = permutationCount(JOB_ID_PREIMAGE_WORD_COUNT);
    pub const context_id = permutationCount(CONTEXT_ID_PREIMAGE_WORD_COUNT);
    pub const child_id = permutationCount(CHILD_ID_PREIMAGE_WORD_COUNT);
    pub const closure_id = permutationCount(CLOSURE_ID_PREIMAGE_WORD_COUNT);
    pub const node_id = permutationCount(NODE_ID_PREIMAGE_WORD_COUNT);
    pub const record_id = permutationCount(RECORD_ID_PREIMAGE_WORD_COUNT);
    pub const statement_id = permutationCount(STATEMENT_ID_PREIMAGE_WORD_COUNT);

    pub fn successfulPreparation(complete_child_count: usize) usize {
        std.debug.assert(complete_child_count <= CHILD_COUNT);
        return format_id +
            CHILD_COUNT * job_id +
            complete_child_count * closure_id +
            CHILD_COUNT * statement_id +
            CHILD_COUNT * child_id +
            statement_id +
            context_id +
            node_id +
            record_id;
    }

    pub fn historicalPreDedupPreparation(
        complete_child_count: usize,
    ) usize {
        std.debug.assert(complete_child_count <= CHILD_COUNT);
        return format_id +
            2 * CHILD_COUNT * job_id +
            2 * complete_child_count * closure_id +
            CHILD_COUNT * statement_id +
            CHILD_COUNT * child_id +
            4 * statement_id +
            context_id +
            node_id +
            record_id;
    }

    pub const successful_complete_pair = successfulPreparation(CHILD_COUNT);
    pub const historical_complete_pair = historicalPreDedupPreparation(CHILD_COUNT);
    pub const eliminated_complete_pair =
        historical_complete_pair - successful_complete_pair;
    pub const successful_tail_pair = successfulPreparation(1);
    pub const historical_tail_pair = historicalPreDedupPreparation(1);
    pub const eliminated_tail_pair = historical_tail_pair - successful_tail_pair;
};

pub const VERIFIER_CUSTODY_REQUIRED = true;
pub const SPLIT_PROOF_JOIN_COMPATIBLE = false;
pub const CROSS_CHILD_RELATION_REPAIR = false;
pub const TEMPORAL_FOLD_AUTHORITY = true;
pub const PRODUCTION_ACTIVATION = false;
pub const HOT_AUTHENTICATION_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS: usize = 0;

/// Pointer-free canonical authority record.  It is intentionally larger than
/// a hash-only handoff: the parent AIR needs the exact two child statements,
/// while native authentication compares all verifier publications before the
/// record is accepted.
pub const PairRecordV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    authority_schema_version: u16 = AUTHORITY_SCHEMA_VERSION,
    node_id_schema_version: u16 = NODE_ID_SCHEMA_VERSION,
    flags: u16 = KNOWN_FLAGS,
    context: VerifierContextV2,
    children: [CHILD_COUNT]VerifiedChildV2,
    parent_statement_words: span_statement.StatementWords,
    child_ids: [CHILD_COUNT]Digest,
    context_id: Digest,
    node_id: Digest,

    pub fn validate(self: *const PairRecordV2) Error!void {
        _ = try validateRecordAndDerive(self);
    }

    pub fn id(self: *const PairRecordV2) Error!Digest {
        return (try validateRecordAndDerive(self)).record_id;
    }
};

/// Cold, by-value admission of one immutable verifier authority and root pin.
/// All statement and identity hashes are paid exactly once here.  The hot
/// authentication path below performs only fixed-size equality checks and
/// publishes this already derived result; it executes no Poseidon permutation
/// and allocates no memory.
pub const PreparedRootContextV2 = struct {
    authority_snapshot: VerifierAuthorityV2,
    record_snapshot: PairRecordV2,
    pin_snapshot: RootVkPinV2,
    result: RootAuthenticatedTemporalPairV2,
};

/// One private, pointer-free derivation product owns every validated value and
/// identity needed by the canonical record and authenticated result. Keeping
/// it private prevents callers from treating intermediate hashes as an
/// admission capability; only `PreparedRootContextV2` crosses that boundary.
pub const PreparedDerivationV2 = struct {
    parent: span_statement.SpanStatement,
    parent_statement_words: span_statement.StatementWords,
    parent_statement_id: Digest,
    child_ids: [CHILD_COUNT]Digest,
    context_id: Digest,
    node_id: Digest,
    record_id: Digest,
};

pub fn recordFromAuthority(
    authority: *const VerifierAuthorityV2,
) Error!PairRecordV2 {
    const derived = try prepareDerivation(authority);
    return recordFromDerivation(authority, &derived);
}

pub fn prepareDerivation(
    authority: *const VerifierAuthorityV2,
) Error!PreparedDerivationV2 {
    const parent = try validateChildrenAndFold(
        &authority.context,
        &authority.children,
    );
    const parent_words = try parent.canonicalWords();
    const parent_statement_id = statementWordsIdAssumeValid(&parent_words);
    if (!std.meta.eql(
        parent_statement_id,
        authority.context.expected_parent_statement_id,
    )) return error.StatementMismatch;

    var child_ids: [CHILD_COUNT]Digest = undefined;
    for (&child_ids, &authority.children) |*destination, *child|
        destination.* = childIdFromStatementId(
            child,
            statementWordsIdAssumeValid(&child.statement_words),
        );
    const context_id = contextIdAssumeValid(&authority.context);
    const node_id = deriveNodeId(
        context_id,
        authority.context.aggregator_vk_id,
        parent_statement_id,
        child_ids,
    );
    return .{
        .parent = parent,
        .parent_statement_words = parent_words,
        .parent_statement_id = parent_statement_id,
        .child_ids = child_ids,
        .context_id = context_id,
        .node_id = node_id,
        .record_id = deriveRecordId(
            context_id,
            child_ids,
            parent_statement_id,
            node_id,
        ),
    };
}

pub fn recordFromDerivation(
    authority: *const VerifierAuthorityV2,
    derived: *const PreparedDerivationV2,
) PairRecordV2 {
    return .{
        .context = authority.context,
        .children = authority.children,
        .parent_statement_words = derived.parent_statement_words,
        .child_ids = derived.child_ids,
        .context_id = derived.context_id,
        .node_id = derived.node_id,
    };
}

pub fn validateRecordAndDerive(
    record: *const PairRecordV2,
) Error!PreparedDerivationV2 {
    if (record.format_version != FORMAT_VERSION or
        record.authority_schema_version != AUTHORITY_SCHEMA_VERSION or
        record.node_id_schema_version != NODE_ID_SCHEMA_VERSION or
        record.flags != KNOWN_FLAGS)
    {
        return error.UnsupportedVersion;
    }
    const authority = VerifierAuthorityV2{
        .context = record.context,
        .children = record.children,
    };
    const derived = try prepareDerivation(&authority);
    if (!std.meta.eql(recordFromDerivation(&authority, &derived), record.*))
        return error.RecordMismatch;
    return derived;
}

pub fn authenticateRoot(
    authority: *const VerifierAuthorityV2,
    record: *const PairRecordV2,
    pin: *const RootVkPinV2,
) Error!RootAuthenticatedTemporalPairV2 {
    const prepared = try prepareRootContext(authority, pin);
    return authenticateRootWithPreparedContext(
        &prepared,
        authority,
        record,
        pin,
    );
}

pub fn prepareRootContext(
    authority: *const VerifierAuthorityV2,
    pin: *const RootVkPinV2,
) Error!PreparedRootContextV2 {
    const derived = try prepareDerivation(authority);
    try pin.validate();
    if (!std.meta.eql(
        authority.context.aggregator_vk_id,
        pin.expected_aggregator_vk_id,
    )) return error.RootVkMismatch;
    const record = recordFromDerivation(authority, &derived);
    const result = RootAuthenticatedTemporalPairV2{ .pair = .{
        .format_id = formatId(),
        .protocol_id = protocol.PROTOCOL_ID_WORDS,
        .session_id = authority.context.session_id,
        .job_id = authority.context.job_id,
        .aggregator_vk_id = authority.context.aggregator_vk_id,
        .parent_node_index = authority.context.parent_node_index,
        .parent_height = authority.context.parent_height,
        .parent_statement = derived.parent,
        .parent_statement_words = derived.parent_statement_words,
        .parent_statement_id = derived.parent_statement_id,
        .child_ids = derived.child_ids,
        .context_id = derived.context_id,
        .node_id = derived.node_id,
        .record_id = derived.record_id,
    } };
    return .{
        .authority_snapshot = authority.*,
        .record_snapshot = record,
        .pin_snapshot = pin.*,
        .result = result,
    };
}

/// Repeated hot authentication for an immutable prepared node.  Passing the
/// original values remains mandatory so mutation after cold admission cannot
/// silently reuse a stale capability.
pub fn authenticateRootWithPreparedContext(
    prepared: *const PreparedRootContextV2,
    authority: *const VerifierAuthorityV2,
    record: *const PairRecordV2,
    pin: *const RootVkPinV2,
) Error!RootAuthenticatedTemporalPairV2 {
    if (!std.meta.eql(prepared.authority_snapshot, authority.*) or
        !std.meta.eql(prepared.record_snapshot, record.*) or
        !std.meta.eql(prepared.pin_snapshot, pin.*))
    {
        return error.AuthorityMismatch;
    }
    return prepared.result;
}

pub fn formatId() Digest {
    var hash = AuthorityHasher.init(FORMAT_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(AUTHORITY_SCHEMA_VERSION);
    hash.addU32(NODE_ID_SCHEMA_VERSION);
    hash.addU32(CHILD_COUNT);
    hash.addU32(COMPLETE_ROSTER_COUNT);
    hash.addU32(KNOWN_FLAGS);
    hash.addU32(@intFromEnum(ChildPosition.left));
    hash.addU32(@intFromEnum(ChildPosition.right));
    hash.addU32(@intFromEnum(ProofKind.segment_leaf));
    hash.addU32(@intFromEnum(ProofKind.binary_node));
    hash.addU32(@intFromEnum(ProofKind.empty_leaf));
    hash.addU32(@intFromEnum(ProofScope.protocol_padding));
    hash.addU32(@intFromEnum(ProofScope.complete_execution));
    hash.addU32(FORMAT_ID_DOMAIN);
    hash.addU32(JOB_ID_DOMAIN);
    hash.addU32(CONTEXT_ID_DOMAIN);
    hash.addU32(CHILD_ID_DOMAIN);
    hash.addU32(CLOSURE_ID_DOMAIN);
    hash.addU32(NODE_ID_DOMAIN);
    hash.addU32(RECORD_ID_DOMAIN);
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    return hash.finalize(FORMAT_ID_PREIMAGE_WORD_COUNT);
}

pub fn jobId(words: *const span_statement.StatementWords) Error!Digest {
    _ = try span_statement.SpanStatement.fromCanonicalWords(words);
    return jobIdAssumeCanonical(words);
}

/// Canonical position of this span in its unique next-height parent. Position
/// is already authenticated by the statement slot and must never be accepted
/// as detached caller context.
pub fn positionForNextParent(
    statement: span_statement.SpanStatement,
) Error!ChildPosition {
    try statement.validate();
    return if (statement.slots.nodeIndex() & 1 == 0) .left else .right;
}

comptime {
    if (CHILD_COUNT != 2 or COMPLETE_ROSTER_COUNT != 36 or
        SPLIT_PROOF_JOIN_COMPATIBLE or CROSS_CHILD_RELATION_REPAIR or
        !VERIFIER_CUSTODY_REQUIRED or !TEMPORAL_FOLD_AUTHORITY or
        PRODUCTION_ACTIVATION)
    {
        @compileError("temporal pair V2 soundness boundary drifted");
    }
    if (FORMAT_ID_PREIMAGE_WORD_COUNT != 28 or
        JOB_ID_PREIMAGE_WORD_COUNT != 207 or
        CONTEXT_ID_PREIMAGE_WORD_COUNT != 57 or
        CHILD_ID_PREIMAGE_WORD_COUNT != 146 or
        CLOSURE_ID_PREIMAGE_WORD_COUNT != 38 or
        NODE_ID_PREIMAGE_WORD_COUNT != 50 or
        RECORD_ID_PREIMAGE_WORD_COUNT != 41 or
        STATEMENT_ID_PREIMAGE_WORD_COUNT != 412 or
        PreparationPermutationCostV2.format_id != 4 or
        PreparationPermutationCostV2.job_id != 26 or
        PreparationPermutationCostV2.context_id != 8 or
        PreparationPermutationCostV2.child_id != 19 or
        PreparationPermutationCostV2.closure_id != 5 or
        PreparationPermutationCostV2.node_id != 7 or
        PreparationPermutationCostV2.record_id != 6 or
        PreparationPermutationCostV2.statement_id != 52 or
        PreparationPermutationCostV2.successful_complete_pair != 281 or
        PreparationPermutationCostV2.historical_complete_pair != 499 or
        PreparationPermutationCostV2.eliminated_complete_pair != 218 or
        PreparationPermutationCostV2.successful_tail_pair != 276 or
        PreparationPermutationCostV2.historical_tail_pair != 489 or
        PreparationPermutationCostV2.eliminated_tail_pair != 213)
    {
        @compileError("temporal pair V2 Poseidon cost ledger drifted");
    }
}
