//! Authenticated statement/witness source for one ordered outer-proof pair.
//!
//! This is the custody join immediately after `outer_parent_transcript_source`.
//! Two admitted outer proofs are replayed from their verifier-owned channel
//! checkpoints, then compared field-for-field with the separately supplied
//! `pair_node.VerifierAuthorityV1`.  Only that verifier-owned authority may
//! supply summary identities or signed relation totals.  The canonical pair
//! record is derived locally and authenticated with a caller-prepared protocol
//! suite, amortizing the immutable suite seal across the aggregation tree.
//!
//! The result is an allocation-free source for a future parent AIR/prover.  It
//! does not instantiate that AIR, produce a parent STARK, or independently
//! verify such a STARK, and therefore remains explicitly non-production.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;

const admission = @import("outer_parent_child_admission.zig");
const channel = @import("poseidon2_channel.zig");
const fixed_wire = @import("fixed_wire.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const transcript_source = @import("outer_parent_transcript_source.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SOURCE_ID_DOMAIN: u32 = 0x4f50_5353; // "OPSS"
pub const CHILD_COUNT: usize = transcript_source.CHILD_COUNT;
pub const HEAP_ALLOCATIONS_PER_PREPARE: usize = 0;

pub const ProductionStatus = enum(u8) {
    verifier_subsystem_only = 1,
};

pub const CURRENT_STATUS: ProductionStatus = .verifier_subsystem_only;
pub const COMPLETE_PARENT_STARK_VERIFIED = false;

pub const Error = transcript_source.Error || admission.Error || pair_node.Error || error{
    AliasedWorkspace,
    AuthorityMismatch,
    CheckpointMismatch,
    PairRecordMismatch,
    PreparedSourceMismatch,
    ProductionStatusMismatch,
    RelationClosureMismatch,
    StatementMismatch,
};

/// Verifier-owned authority and the root VK pin used by the canonical pair
/// authentication. `suite` is prepared once per process/tree, not once per
/// node; this removes `AuthenticationPermutationCostV1.suite_preparation`
/// scalar permutations from every successful parent-source construction.
pub const AuthorityInputsV1 = struct {
    pair: transcript_source.PairInputsV1,
    verified: *const pair_node.VerifierAuthorityV1,
    suite: *const pair_node.PreparedProtocolSuiteV1,
};

pub const ChildPublicV1 = struct {
    position: pair_node.ChildPosition,
    role: pair_node.ChildRole,
    leaf_index: u32,
    preprocessed_root: channel.Digest,
    statement_id: channel.Digest,
    proof_id: channel.Digest,
    transcript_id: channel.Digest,
    summary_id: channel.Digest,
};

/// Public parent statement. The authenticated pair carries the canonical
/// ordered folds and node ID; explicit context fields remain available to the
/// future AIR without asking it to reverse a hash preimage.
pub const ParentStatementV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    status: ProductionStatus = CURRENT_STATUS,
    protocol_id: channel.Digest = protocol.PROTOCOL_ID_WORDS,
    pair_format_id: channel.Digest = pair_node.FORMAT_ID_WORDS,
    session_id: channel.Digest,
    job_id: channel.Digest,
    challenge_context_id: channel.Digest,
    authority_context_id: channel.Digest,
    parent_vk_id: channel.Digest,
    execution_statement_id: channel.Digest,
    public_call_commitment: channel.Digest,
    event_count: u64,
    session_leaf_count: u32,
    pair_index: u32,
    children: [CHILD_COUNT]ChildPublicV1,
    authenticated_pair: pair_node.AuthenticatedPairV1,
    transcript_source_id: channel.Digest,
};

/// Exact custody bridge from the verifier checkpoint to the final transcript
/// identity used by the canonical pair node.
pub const CheckpointWitnessV1 = struct {
    pre_core: admission.ChannelCheckpointV1,
    receipt_id: channel.Digest,
    final_digest: channel.Digest,
    final_draw_count: u32,
    transcript_id: channel.Digest,

    fn validate(self: *const CheckpointWitnessV1) Error!void {
        try self.pre_core.validate();
        try requireDigest(self.receipt_id);
        try requireDigest(self.final_digest);
        try requireDigest(self.transcript_id);
        if (self.final_draw_count != 1 or !std.meta.eql(
            self.transcript_id,
            protocol.transcriptId(self.final_digest, self.final_draw_count),
        )) return error.CheckpointMismatch;
    }
};

pub const CustodyWitnessV1 = struct {
    profile_id: channel.Digest,
    capture_id: channel.Digest,
    receipt_id: channel.Digest,
    claimed_sums_id: channel.Digest,

    fn validate(self: *const CustodyWitnessV1) Error!void {
        try requireDigest(self.profile_id);
        try requireDigest(self.capture_id);
        try requireDigest(self.receipt_id);
        try requireDigest(self.claimed_sums_id);
    }
};

pub const RelationClosureV1 = struct {
    child_totals: [CHILD_COUNT]pair_node.SecureFelt,
    folded_total: pair_node.SecureFelt,

    fn validate(self: *const RelationClosureV1) Error!void {
        for (self.child_totals) |total| total.validate() catch
            return error.RelationClosureMismatch;
        self.folded_total.validate() catch return error.RelationClosureMismatch;
        const expected = self.child_totals[0].add(self.child_totals[1]);
        if (!expected.eql(self.folded_total) or !self.folded_total.isZero())
            return error.RelationClosureMismatch;
    }
};

pub const ParentWitnessV1 = struct {
    checkpoints: [CHILD_COUNT]CheckpointWitnessV1,
    custody: [CHILD_COUNT]CustodyWitnessV1,
    relation_closure: RelationClosureV1,
    authority: pair_node.VerifierAuthorityV1,
    record: pair_node.PairNodeRecordV1,
    authenticated_root: pair_node.RootAuthenticatedPairV1,
};

pub const PerformanceCountsV1 = struct {
    transcript: transcript_source.PerformanceCountsV1,
    pair_authentication_permutations: usize,
    suite_preparation_permutations: usize,
    source_identity_permutations: usize,
    retained_witness_bytes: usize,
    heap_allocations: usize = HEAP_ALLOCATIONS_PER_PREPARE,

    pub fn totalExecutedPermutations(self: PerformanceCountsV1) usize {
        return self.transcript.totalExecutedPermutations() +
            self.pair_authentication_permutations +
            self.source_identity_permutations;
    }
};

pub fn ChildBundle(comptime dimensions: fixed_wire.Dimensions) type {
    return transcript_source.ChildBundle(dimensions);
}

pub fn Prepared(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    const TranscriptPrepared = transcript_source.Prepared(dimensions);
    const Bundle = ChildBundle(dimensions);

    return struct {
        format_version: u16 = FORMAT_VERSION,
        status: ProductionStatus = CURRENT_STATUS,
        transcript: TranscriptPrepared,
        statement: ParentStatementV1,
        witness: ParentWitnessV1,
        source_id: channel.Digest,
        performance: PerformanceCountsV1,

        const Self = @This();

        pub fn productionReady(_: *const Self) bool {
            return COMPLETE_PARENT_STARK_VERIFIED;
        }

        /// Allocation-free and failure-atomic. `encoding_scratch` is reusable
        /// wire-validation workspace and may be overwritten on either success
        /// or error; `destination` is published only after every check passes.
        pub fn prepareInto(
            destination: *Self,
            encoding_scratch: []u8,
            inputs: AuthorityInputsV1,
            bundles: [CHILD_COUNT]Bundle,
        ) Error!void {
            try preflightAliases(Self, destination, encoding_scratch, inputs, bundles);

            var transcript: TranscriptPrepared = undefined;
            try TranscriptPrepared.prepareInto(
                &transcript,
                encoding_scratch,
                inputs.pair,
                bundles,
            );

            const authority = authorityFromTranscript(&transcript, inputs.pair.context);
            if (!std.meta.eql(authority, inputs.verified.*))
                return error.AuthorityMismatch;
            const record = recordFromAuthority(
                &authority,
                transcript.context.authority_context_id,
            );
            const authenticated_root = try pair_node.authenticateRootPrepared(
                inputs.suite,
                &authority,
                &record,
                &inputs.pair.root_pin,
            );

            var staged = Self{
                .transcript = transcript,
                .statement = statementFromAuthority(
                    &transcript,
                    &authority,
                    authenticated_root,
                ),
                .witness = witnessFromInputs(
                    &transcript,
                    bundles,
                    authority,
                    record,
                    authenticated_root,
                ),
                .source_id = undefined,
                .performance = undefined,
            };
            const identity = sourceIdentity(&staged);
            staged.source_id = identity.digest;
            staged.performance = performanceCounts(
                dimensions,
                &staged,
                identity.permutations,
            );
            try staged.validateRetained(authenticated_root);
            destination.* = staged;
        }

        /// Allocation-free hostile revalidation against the original custody
        /// inputs. This rebuilds into a private local and compares the complete
        /// retained source, leaving `self` untouched on all errors.
        pub fn validateAgainst(
            self: *const Self,
            encoding_scratch: []u8,
            inputs: AuthorityInputsV1,
            bundles: [CHILD_COUNT]Bundle,
        ) Error!void {
            if (byteSlicesOverlap(std.mem.asBytes(self), encoding_scratch))
                return error.AliasedWorkspace;
            var expected: Self = undefined;
            try Self.prepareInto(&expected, encoding_scratch, inputs, bundles);
            if (!std.meta.eql(self.*, expected))
                return error.PreparedSourceMismatch;
        }

        /// Revalidates retained state with the amortized protocol suite. This
        /// is the cold mutation-detection path; the successful prepare path
        /// authenticates the pair exactly once.
        pub fn validate(
            self: *const Self,
            suite: *const pair_node.PreparedProtocolSuiteV1,
        ) Error!void {
            const authenticated_root = try pair_node.authenticateRootPrepared(
                suite,
                &self.witness.authority,
                &self.witness.record,
                &.{ .expected_aggregator_vk_id = self.statement.parent_vk_id },
            );
            try self.validateRetained(authenticated_root);
        }

        fn validateRetained(
            self: *const Self,
            authenticated_root: pair_node.RootAuthenticatedPairV1,
        ) Error!void {
            if (self.format_version != FORMAT_VERSION or
                self.status != CURRENT_STATUS or self.productionReady())
            {
                return error.ProductionStatusMismatch;
            }
            try self.transcript.validate();
            const expected_authority = authorityFromTranscript(
                &self.transcript,
                self.witness.authority.context,
            );
            if (!std.meta.eql(expected_authority, self.witness.authority))
                return error.AuthorityMismatch;
            const expected_record = recordFromAuthority(
                &expected_authority,
                self.transcript.context.authority_context_id,
            );
            if (!std.meta.eql(expected_record, self.witness.record))
                return error.PairRecordMismatch;
            if (!std.meta.eql(authenticated_root, self.witness.authenticated_root))
                return error.AuthorityMismatch;

            for (&self.witness.checkpoints, &self.witness.custody, &self.transcript.children) |
                *checkpoint,
                *custody,
                *child,
            | {
                try checkpoint.validate();
                try custody.validate();
                if (!std.meta.eql(checkpoint.receipt_id, child.receipt_id) or
                    !std.meta.eql(checkpoint.final_digest, child.replay.final_digest) or
                    checkpoint.final_draw_count != child.replay.final_draw_count or
                    !std.meta.eql(checkpoint.transcript_id, child.transcript_id) or
                    !std.meta.eql(custody.profile_id, child.profile_id) or
                    !std.meta.eql(custody.capture_id, child.capture_id) or
                    !std.meta.eql(custody.receipt_id, child.receipt_id) or
                    !std.meta.eql(custody.claimed_sums_id, child.claimed_sums_id))
                {
                    return error.CheckpointMismatch;
                }
            }
            try self.witness.relation_closure.validate();
            const expected_statement = statementFromAuthority(
                &self.transcript,
                &expected_authority,
                authenticated_root,
            );
            if (!std.meta.eql(expected_statement, self.statement))
                return error.StatementMismatch;
            const identity = sourceIdentity(self);
            const expected_performance = performanceCounts(
                dimensions,
                self,
                identity.permutations,
            );
            if (!std.meta.eql(identity.digest, self.source_id) or
                !std.meta.eql(expected_performance, self.performance))
            {
                return error.PreparedSourceMismatch;
            }
        }
    };
}

fn authorityFromTranscript(
    transcript: anytype,
    context: pair_node.VerifierContextV1,
) pair_node.VerifierAuthorityV1 {
    var children: [CHILD_COUNT]pair_node.VerifiedChildV1 = undefined;
    for (&children, transcript.children) |*target, child| target.* = .{
        .position = child.position,
        .role = child.role,
        .leaf_index = child.leaf_index,
        .pair_index = child.pair_index,
        .leaf_count = 1,
        .protocol_id = protocol.PROTOCOL_ID_WORDS,
        .session_id = child.session_id,
        .challenge_context_id = transcript.context.challenge_context_id,
        .authority_context_id = transcript.context.authority_context_id,
        .parent_vk_id = child.parent_vk_id,
        .statement_id = child.statement_id,
        .proof_id = child.proof_id,
        .transcript_id = child.transcript_id,
        .summary_id = child.summary_id,
        .event_count = child.event_count,
        .signed_relation_total = child.signed_relation_total,
    };
    return .{ .context = context, .children = children };
}

fn recordFromAuthority(
    authority: *const pair_node.VerifierAuthorityV1,
    authority_context_id: channel.Digest,
) pair_node.PairNodeRecordV1 {
    var children: [CHILD_COUNT]pair_node.ChildEvidenceV1 = undefined;
    for (&children, authority.children) |*target, child| target.* = .{
        .position = child.position,
        .role = child.role,
        .leaf_index = child.leaf_index,
        .pair_index = child.pair_index,
        .leaf_count = child.leaf_count,
        .protocol_id = child.protocol_id,
        .session_id = child.session_id,
        .challenge_context_id = child.challenge_context_id,
        .authority_context_id = child.authority_context_id,
        .parent_vk_id = child.parent_vk_id,
        .statement_id = child.statement_id,
        .proof_id = child.proof_id,
        .transcript_id = child.transcript_id,
        .summary_id = child.summary_id,
        .event_count = child.event_count,
        .signed_relation_total = child.signed_relation_total,
    };
    return .{
        .pair_index = authority.context.pair_index,
        .first_leaf_index = authority.context.pair_index * @as(u32, CHILD_COUNT),
        .aggregator_vk_id = authority.context.aggregator_vk_id,
        .authority_context_id = authority_context_id,
        .children = children,
    };
}

fn statementFromAuthority(
    transcript: anytype,
    authority: *const pair_node.VerifierAuthorityV1,
    authenticated_root: pair_node.RootAuthenticatedPairV1,
) ParentStatementV1 {
    var children: [CHILD_COUNT]ChildPublicV1 = undefined;
    for (&children, authority.children, transcript.children) |*target, child, transcript_child| target.* = .{
        .position = child.position,
        .role = child.role,
        .leaf_index = child.leaf_index,
        .preprocessed_root = transcript_child.preprocessed_root,
        .statement_id = child.statement_id,
        .proof_id = child.proof_id,
        .transcript_id = child.transcript_id,
        .summary_id = child.summary_id,
    };
    return .{
        .session_id = authority.context.session_id,
        .job_id = authority.context.job_id,
        .challenge_context_id = transcript.context.challenge_context_id,
        .authority_context_id = transcript.context.authority_context_id,
        .parent_vk_id = authority.context.aggregator_vk_id,
        .execution_statement_id = authority.context.execution_statement_id,
        .public_call_commitment = authority.context.public_call_commitment,
        .event_count = authority.context.event_count,
        .session_leaf_count = authority.context.session_leaf_count,
        .pair_index = authority.context.pair_index,
        .children = children,
        .authenticated_pair = authenticated_root.pair,
        .transcript_source_id = transcript.source_id,
    };
}

fn witnessFromInputs(
    transcript: anytype,
    bundles: anytype,
    authority: pair_node.VerifierAuthorityV1,
    record: pair_node.PairNodeRecordV1,
    authenticated_root: pair_node.RootAuthenticatedPairV1,
) ParentWitnessV1 {
    var checkpoints: [CHILD_COUNT]CheckpointWitnessV1 = undefined;
    var custody: [CHILD_COUNT]CustodyWitnessV1 = undefined;
    var totals: [CHILD_COUNT]pair_node.SecureFelt = undefined;
    for (&checkpoints, &custody, &totals, bundles, transcript.children) |
        *checkpoint,
        *custody_item,
        *total,
        bundle,
        child,
    | {
        checkpoint.* = .{
            .pre_core = bundle.receipt.pre_core_channel,
            .receipt_id = child.receipt_id,
            .final_digest = child.replay.final_digest,
            .final_draw_count = child.replay.final_draw_count,
            .transcript_id = child.transcript_id,
        };
        custody_item.* = .{
            .profile_id = child.profile_id,
            .capture_id = child.capture_id,
            .receipt_id = child.receipt_id,
            .claimed_sums_id = child.claimed_sums_id,
        };
        total.* = child.signed_relation_total;
    }
    return .{
        .checkpoints = checkpoints,
        .custody = custody,
        .relation_closure = .{
            .child_totals = totals,
            .folded_total = totals[0].add(totals[1]),
        },
        .authority = authority,
        .record = record,
        .authenticated_root = authenticated_root,
    };
}

fn performanceCounts(
    comptime dimensions: fixed_wire.Dimensions,
    prepared: *const Prepared(dimensions),
    identity_permutations: usize,
) PerformanceCountsV1 {
    return .{
        .transcript = prepared.transcript.performance,
        .pair_authentication_permutations = pair_node.AuthenticationPermutationCostV1.successful_prepared_root,
        .suite_preparation_permutations = 0,
        .source_identity_permutations = identity_permutations,
        .retained_witness_bytes = @sizeOf(Prepared(dimensions)),
    };
}

const IdentityResult = struct {
    digest: channel.Digest,
    permutations: usize,
};

fn sourceIdentity(prepared: anytype) IdentityResult {
    var hash = AuthorityHasher.init(SOURCE_ID_DOMAIN);
    hash.addU32(FORMAT_VERSION);
    hash.addU32(@intFromEnum(CURRENT_STATUS));
    hash.digest(protocol.PROTOCOL_ID_WORDS);
    hash.digest(pair_node.FORMAT_ID_WORDS);
    hash.digest(prepared.transcript.source_id);

    const statement = prepared.statement;
    hash.digest(statement.session_id);
    hash.digest(statement.job_id);
    hash.digest(statement.challenge_context_id);
    hash.digest(statement.authority_context_id);
    hash.digest(statement.parent_vk_id);
    hash.digest(statement.execution_statement_id);
    hash.digest(statement.public_call_commitment);
    hash.addU64(statement.event_count);
    hash.addU32(statement.session_leaf_count);
    hash.addU32(statement.pair_index);
    for (statement.children) |child| {
        hash.addU32(@intFromEnum(child.position));
        hash.addU32(@intFromEnum(child.role));
        hash.addU32(child.leaf_index);
        hash.digest(child.preprocessed_root);
        hash.digest(child.statement_id);
        hash.digest(child.proof_id);
        hash.digest(child.transcript_id);
        hash.digest(child.summary_id);
    }
    hash.digest(statement.authenticated_pair.identities.statement_id);
    hash.digest(statement.authenticated_pair.identities.proof_id);
    hash.digest(statement.authenticated_pair.identities.transcript_id);
    hash.digest(statement.authenticated_pair.identities.summary_id);
    hash.digest(statement.authenticated_pair.node_id);

    for (prepared.witness.checkpoints, prepared.witness.custody) |
        checkpoint,
        custody,
    | {
        hash.digest(checkpoint.pre_core.digest);
        hash.addU32(checkpoint.pre_core.draw_count);
        hash.digest(checkpoint.receipt_id);
        hash.digest(checkpoint.final_digest);
        hash.addU32(checkpoint.final_draw_count);
        hash.digest(checkpoint.transcript_id);
        hash.digest(custody.profile_id);
        hash.digest(custody.capture_id);
        hash.digest(custody.receipt_id);
        hash.digest(custody.claimed_sums_id);
    }
    for (prepared.witness.relation_closure.child_totals) |total|
        hash.addU32s(&total.limbs);
    hash.addU32s(&prepared.witness.relation_closure.folded_total.limbs);
    return hash.finalize();
}

const AuthorityHasher = struct {
    inner: channel.CanonicalWordHasher,
    word_count: usize = 0,

    fn init(domain: u32) AuthorityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *AuthorityHasher, value: u32) void {
        std.debug.assert(value < stwo_core.fields.m31.Modulus);
        const word = [_]M31{M31.fromCanonical(value)};
        self.inner.update(&word);
        self.word_count += 1;
    }

    fn addU64(self: *AuthorityHasher, value: u64) void {
        self.addU32(@truncate(value & 0xffff));
        self.addU32(@truncate((value >> 16) & 0xffff));
        self.addU32(@truncate((value >> 32) & 0xffff));
        self.addU32(@truncate(value >> 48));
    }

    fn addU32s(self: *AuthorityHasher, values: []const u32) void {
        for (values) |value| self.addU32(value);
    }

    fn digest(self: *AuthorityHasher, value: channel.Digest) void {
        self.addU32s(&value);
    }

    fn finalize(self: *AuthorityHasher) IdentityResult {
        return .{
            .digest = self.inner.finalize(),
            .permutations = channel.canonicalWordPermutationCount(self.word_count),
        };
    }
};

fn preflightAliases(
    comptime PreparedType: type,
    destination: *PreparedType,
    encoding_scratch: []u8,
    inputs: AuthorityInputsV1,
    bundles: anytype,
) Error!void {
    const destination_bytes = std.mem.asBytes(destination);
    if (byteSlicesOverlap(destination_bytes, encoding_scratch) or
        byteSlicesOverlap(destination_bytes, std.mem.asBytes(&inputs.pair)) or
        byteSlicesOverlap(destination_bytes, std.mem.asBytes(inputs.verified)) or
        byteSlicesOverlap(destination_bytes, std.mem.asBytes(inputs.suite)) or
        byteSlicesOverlap(encoding_scratch, std.mem.asBytes(inputs.verified)) or
        byteSlicesOverlap(encoding_scratch, std.mem.asBytes(inputs.suite)))
    {
        return error.AliasedWorkspace;
    }
    for (bundles) |bundle| {
        if (byteSlicesOverlap(destination_bytes, std.mem.asBytes(bundle.wire)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(bundle.candidate)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(bundle.receipt)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(&bundle.seal)) or
            byteSlicesOverlap(destination_bytes, std.mem.asBytes(&bundle.binding)) or
            captureStorageOverlaps(destination_bytes, bundle.capture))
        {
            return error.AliasedWorkspace;
        }
    }
}

fn captureStorageOverlaps(bytes: []const u8, capture: anytype) bool {
    if (byteSlicesOverlap(bytes, std.mem.asBytes(capture)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.queries.raw)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.queries.unique)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.commitments)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.column_log_sizes)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.sampled_points)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.sampled_values)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.queried_values)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.deep_answers)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.trace_paths)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.fri.layers)) or
        byteSlicesOverlap(bytes, std.mem.sliceAsBytes(capture.last_layer_coefficients)))
    {
        return true;
    }
    for (capture.column_log_sizes) |logs|
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(logs))) return true;
    for (capture.sampled_points) |columns| {
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(columns))) return true;
        for (columns) |points|
            if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(points))) return true;
    }
    for (capture.trace_paths) |paths| {
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(paths.positions)) or
            byteSlicesOverlap(bytes, std.mem.sliceAsBytes(paths.siblings))) return true;
    }
    for (capture.fri.layers) |layer| {
        if (byteSlicesOverlap(bytes, std.mem.sliceAsBytes(layer.positions)) or
            byteSlicesOverlap(bytes, std.mem.sliceAsBytes(layer.values)) or
            byteSlicesOverlap(bytes, std.mem.sliceAsBytes(layer.siblings))) return true;
    }
    return false;
}

fn byteSlicesOverlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

fn requireDigest(value: channel.Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= stwo_core.fields.m31.Modulus)
            return error.StatementMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.StatementMismatch;
}

comptime {
    if (CHILD_COUNT != pair_node.CHILD_COUNT or
        transcript_source.COMPLETE_PARENT_PROOF_VERIFIED or
        pair_node.RECURSIVE_PROOF_VERIFICATION or
        HEAP_ALLOCATIONS_PER_PREPARE != 0)
    {
        @compileError("outer parent statement source production boundary drifted");
    }
}
