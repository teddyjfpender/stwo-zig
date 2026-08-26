//! Validated pre-challenge manifest and prepared native session. Preparation
//! is allocation-free, O(n), and caches membership data so later leaf checks
//! are O(1). This research reference does not verify a recursive proof.

const std = @import("std");
const challenge_mod = @import("challenge.zig");
const hash = @import("hash.zig");
const tree = @import("tree.zig");
const types = @import("types.zig");
const wire = @import("wire.zig");

pub const NATIVE_REFERENCE_ONLY = true;
pub const RECURSIVE_PROOF_VERIFICATION = false;

pub const PreparedLeafV1 = struct {
    descriptor: types.LeafDescriptorV1,
    descriptor_digest: hash.Digest,
    statement_leaf_digest: hash.Digest,
    artifact_leaf_digest: hash.Digest,
};

/// `leaves` borrows caller-owned, exactly-sized preparation storage. The
/// caller must keep it alive and immutable for the lifetime of this value.
pub const PreparedSessionV1 = struct {
    header: types.ManifestHeaderV1,
    leaves: []const PreparedLeafV1,
    session_digest: hash.Digest,
    challenge: challenge_mod.ChallengeContextV1,
    request_root: hash.Digest,
    call_root: hash.Digest,
    statement_root: hash.Digest,
    artifact_root: hash.Digest,
    total_request_count: u64,
    total_supply_count: u64,
    total_leaf_call_count: u64,
    tree_height: u8,

    pub fn leaf(self: *const PreparedSessionV1, index: u32) !*const PreparedLeafV1 {
        const native_index: usize = index;
        if (native_index >= self.leaves.len) return error.LeafIndexOutOfRange;
        return &self.leaves[native_index];
    }

    pub fn encodedLen(self: *const PreparedSessionV1) !usize {
        return wire.encodedLen(self.leaves.len);
    }

    /// Re-hashes the borrowed canonical descriptors before emitting bytes.
    /// This catches accidental mutation of preparation storage without making
    /// every O(1) merge pay an O(n) integrity scan.
    pub fn encodeCanonical(
        self: *const PreparedSessionV1,
        destination: []u8,
    ) !usize {
        const expected_len = try self.encodedLen();
        if (destination.len != expected_len) return error.IncorrectBufferLength;
        if (!hash.eql(hashCanonical(self), self.session_digest)) {
            return error.PreparedSessionMutated;
        }
        try self.challenge.validate();

        var sink = hash.SliceSink{ .destination = destination };
        try writeCanonical(&sink, self);
        std.debug.assert(sink.offset == expected_len);
        return sink.offset;
    }
};

pub fn prepare(
    view: types.ManifestViewV1,
    accepted: types.AcceptedProtocolV1,
    storage: []PreparedLeafV1,
) !PreparedSessionV1 {
    try accepted.validate();
    try validateHeader(view.header, accepted, view.descriptors.len);
    if (storage.len != view.descriptors.len) return error.IncorrectStorageLength;

    var request_frontier = tree.DigestFrontier.init(hash.REQUEST_NODE_DOMAIN);
    var call_frontier = tree.DigestFrontier.init(hash.CALL_NODE_DOMAIN);
    var statement_frontier = tree.DigestFrontier.init(hash.STATEMENT_NODE_DOMAIN);
    var artifact_frontier = tree.DigestFrontier.init(hash.ARTIFACT_NODE_DOMAIN);
    var total_request_count: u64 = 0;
    var total_supply_count: u64 = 0;
    var total_leaf_calls: u64 = 0;

    var pair_index: usize = 0;
    while (pair_index < view.descriptors.len / 2) : (pair_index += 1) {
        const left_index = pair_index * 2;
        const core = view.descriptors[left_index];
        const provider = view.descriptors[left_index + 1];
        try validateDescriptor(core, accepted, left_index, pair_index, .core_request);
        try validateDescriptor(
            provider,
            accepted,
            left_index + 1,
            pair_index,
            .poseidon2_provider,
        );
        try validatePair(core, provider);
        if (pair_index != 0) {
            const previous_job = view.descriptors[left_index - 2].job_digest;
            if (!hash.lessThan(previous_job, core.job_digest)) {
                return error.JobDigestsNotStrictlyIncreasing;
            }
        }

        total_request_count = std.math.add(
            u64,
            total_request_count,
            core.guest_call_count,
        ) catch return error.AggregateCountOverflow;
        total_supply_count = std.math.add(
            u64,
            total_supply_count,
            provider.guest_call_count,
        ) catch return error.AggregateCountOverflow;
        total_leaf_calls = std.math.add(
            u64,
            total_leaf_calls,
            core.guest_call_count,
        ) catch return error.AggregateCountOverflow;
        total_leaf_calls = std.math.add(
            u64,
            total_leaf_calls,
            provider.guest_call_count,
        ) catch return error.AggregateCountOverflow;

        try request_frontier.push(requestLeafDigest(core.job_digest));
        try call_frontier.push(callLeafDigest(
            core.job_digest,
            core.guest_call_commitment,
            core.guest_call_count,
        ));

        const pair = [_]types.LeafDescriptorV1{ core, provider };
        for (pair, 0..) |descriptor, side| {
            const index = left_index + side;
            const statement_digest = statementLeafDigest(
                @intCast(index),
                descriptor.leaf_statement_digest,
            );
            const artifact_digest = artifactLeafDigest(
                @intCast(index),
                descriptor.leaf_air_artifact_digest,
            );
            const descriptor_digest = wire.hashDescriptor(descriptor);
            if (hash.isZero(descriptor_digest) or
                hash.isZero(statement_digest) or
                hash.isZero(artifact_digest))
            {
                return error.ZeroDerivedDigest;
            }
            storage[index] = .{
                .descriptor = descriptor,
                .descriptor_digest = descriptor_digest,
                .statement_leaf_digest = statement_digest,
                .artifact_leaf_digest = artifact_digest,
            };
            try statement_frontier.push(statement_digest);
            try artifact_frontier.push(artifact_digest);
        }
    }
    const request_root = try request_frontier.finish();
    const call_root = try call_frontier.finish();
    const statement_root = try statement_frontier.finish();
    const artifact_root = try artifact_frontier.finish();
    if (!hash.eql(request_root, view.header.request_set_digest)) {
        return error.RequestSetDigestMismatch;
    }
    if (hash.isZero(request_root) or hash.isZero(call_root) or
        hash.isZero(statement_root) or hash.isZero(artifact_root))
    {
        return error.ZeroDerivedRoot;
    }

    var prepared = PreparedSessionV1{
        .header = view.header,
        .leaves = storage,
        .session_digest = undefined,
        .challenge = undefined,
        .request_root = request_root,
        .call_root = call_root,
        .statement_root = statement_root,
        .artifact_root = artifact_root,
        .total_request_count = total_request_count,
        .total_supply_count = total_supply_count,
        .total_leaf_call_count = total_leaf_calls,
        .tree_height = types.log2ExactPowerOfTwo(view.descriptors.len),
    };
    prepared.session_digest = hashCanonical(&prepared);
    if (hash.isZero(prepared.session_digest)) return error.ZeroSessionDigest;
    prepared.challenge = challenge_mod.derive(prepared.session_digest);
    if (hash.isZero(prepared.challenge.challenge_context_digest)) {
        return error.ZeroChallengeContextDigest;
    }
    return prepared;
}

fn validateHeader(
    header: types.ManifestHeaderV1,
    accepted: types.AcceptedProtocolV1,
    descriptor_count: usize,
) !void {
    if (!std.mem.eql(u8, &header.magic, &types.MANIFEST_MAGIC)) {
        return error.InvalidManifestMagic;
    }
    if (header.version != types.FORMAT_VERSION) return error.UnsupportedFormatVersion;
    if (header.aggregation_profile_id != types.AGGREGATION_PROFILE_ID) {
        return error.AggregationProfileMismatch;
    }
    if (header.execution_profile_id != types.EXECUTION_PROFILE_ID or
        !hash.eql(header.execution_semantic_digest, types.EXECUTION_SEMANTIC_DIGEST))
    {
        return error.ExecutionProfileMismatch;
    }
    if (header.relation_schema_id != types.RELATION_SCHEMA_ID or
        header.relation_schema_version != types.RELATION_SCHEMA_VERSION or
        header.relation_arity != types.RELATION_ARITY)
    {
        return error.RelationSchemaMismatch;
    }
    if (header.tree_policy !=
        .balanced_adjacent_position_preserving_two_to_one)
    {
        return error.TreePolicyMismatch;
    }
    if (!allZero(&header.reserved)) return error.NonZeroReservedBits;
    if (!hash.eql(header.proof_protocol_digest, accepted.proof_protocol_digest) or
        !hash.eql(header.relation_registry_digest, accepted.relation_registry_digest))
    {
        return error.ProtocolIdentityMismatch;
    }
    if (hash.isZero(header.proof_protocol_digest) or
        hash.isZero(header.execution_semantic_digest) or
        hash.isZero(header.relation_registry_digest) or
        hash.isZero(header.request_set_digest))
    {
        return error.ZeroManifestDigest;
    }
    const leaf_count: usize = header.leaf_count;
    if (!types.validLeafCount(leaf_count)) return error.InvalidLeafCount;
    if (leaf_count != descriptor_count) return error.DescriptorCountMismatch;
}

fn validateDescriptor(
    descriptor: types.LeafDescriptorV1,
    accepted: types.AcceptedProtocolV1,
    expected_leaf_index: usize,
    expected_pair_index: usize,
    expected_role: types.LeafRole,
) !void {
    if (descriptor.leaf_index != expected_leaf_index or
        descriptor.pair_index != expected_pair_index)
    {
        return error.NonCanonicalLeafPosition;
    }
    if (descriptor.role != expected_role) return error.LeafRoleMismatch;
    if (descriptor.flags != types.GUEST_COMPONENT_PRESENT) {
        return error.GuestComponentMissingOrUnknownFlags;
    }
    if (descriptor.reserved != 0 or descriptor.reserved_tail != 0) {
        return error.NonZeroReservedBits;
    }
    if (descriptor.execution_profile_id != types.EXECUTION_PROFILE_ID or
        !hash.eql(descriptor.execution_semantic_digest, types.EXECUTION_SEMANTIC_DIGEST))
    {
        return error.ExecutionProfileMismatch;
    }
    if (descriptor.relation_schema_id != types.RELATION_SCHEMA_ID or
        descriptor.relation_schema_version != types.RELATION_SCHEMA_VERSION or
        descriptor.relation_arity != types.RELATION_ARITY)
    {
        return error.RelationSchemaMismatch;
    }
    if (!hash.eql(descriptor.proof_protocol_digest, accepted.proof_protocol_digest) or
        !hash.eql(descriptor.relation_registry_digest, accepted.relation_registry_digest))
    {
        return error.ProtocolIdentityMismatch;
    }
    if (hash.isZero(descriptor.job_digest) or
        hash.isZero(descriptor.leaf_statement_digest) or
        hash.isZero(descriptor.leaf_air_artifact_digest) or
        hash.isZero(descriptor.preprocessed_root) or
        hash.isZero(descriptor.main_root) or
        hash.isZero(descriptor.guest_call_commitment) or
        hash.isZero(descriptor.proof_protocol_digest) or
        hash.isZero(descriptor.execution_semantic_digest) or
        hash.isZero(descriptor.relation_registry_digest))
    {
        return error.ZeroDescriptorDigest;
    }
    try types.validateCallCount(descriptor.guest_call_count);
    const empty_commitment = hash.emptyCallCommitment();
    if (descriptor.guest_call_count == 0) {
        if (!hash.eql(descriptor.guest_call_commitment, empty_commitment)) {
            return error.NonCanonicalEmptyCallCommitment;
        }
    } else if (hash.eql(descriptor.guest_call_commitment, empty_commitment)) {
        return error.EmptyCommitmentForNonEmptyCalls;
    }
}

fn validatePair(
    core: types.LeafDescriptorV1,
    provider: types.LeafDescriptorV1,
) !void {
    if (!hash.eql(core.job_digest, provider.job_digest)) {
        return error.PairJobMismatch;
    }
    if (!hash.eql(core.guest_call_commitment, provider.guest_call_commitment)) {
        return error.PairCallCommitmentMismatch;
    }
    if (core.guest_call_count != provider.guest_call_count) {
        return error.PairCallCountMismatch;
    }
    if (!hash.eql(core.proof_protocol_digest, provider.proof_protocol_digest) or
        core.execution_profile_id != provider.execution_profile_id or
        !hash.eql(core.execution_semantic_digest, provider.execution_semantic_digest) or
        !hash.eql(core.relation_registry_digest, provider.relation_registry_digest) or
        core.relation_schema_id != provider.relation_schema_id or
        core.relation_schema_version != provider.relation_schema_version or
        core.relation_arity != provider.relation_arity)
    {
        return error.PairProtocolMismatch;
    }
}

pub fn requestLeafDigest(job_digest: hash.Digest) hash.Digest {
    return hash.hashDomain(hash.REQUEST_LEAF_DOMAIN, &job_digest);
}

pub fn callLeafDigest(
    job_digest: hash.Digest,
    call_commitment: hash.Digest,
    call_count: u64,
) hash.Digest {
    var sink = hash.HashSink.init(hash.CALL_LEAF_DOMAIN);
    sink.writeAll(&job_digest) catch unreachable;
    sink.writeAll(&call_commitment) catch unreachable;
    hash.writeU64(&sink, call_count) catch unreachable;
    return sink.finalize();
}

pub fn statementLeafDigest(
    leaf_index: u32,
    statement_digest: hash.Digest,
) hash.Digest {
    var sink = hash.HashSink.init(hash.STATEMENT_LEAF_DOMAIN);
    hash.writeU32(&sink, leaf_index) catch unreachable;
    sink.writeAll(&statement_digest) catch unreachable;
    return sink.finalize();
}

pub fn artifactLeafDigest(
    leaf_index: u32,
    artifact_digest: hash.Digest,
) hash.Digest {
    var sink = hash.HashSink.init(hash.ARTIFACT_LEAF_DOMAIN);
    hash.writeU32(&sink, leaf_index) catch unreachable;
    sink.writeAll(&artifact_digest) catch unreachable;
    return sink.finalize();
}

pub fn hashCanonical(session: *const PreparedSessionV1) hash.Digest {
    var sink = hash.HashSink.init(hash.SESSION_DOMAIN);
    writeCanonical(&sink, session) catch unreachable;
    return sink.finalize();
}

fn writeCanonical(sink: anytype, session: *const PreparedSessionV1) !void {
    try wire.writeHeader(sink, session.header, @intCast(session.leaves.len));
    for (session.leaves) |leaf| try wire.writeDescriptor(sink, leaf.descriptor);
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}
