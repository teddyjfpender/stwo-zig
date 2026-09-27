//! Canonical role-separated leaf-statement envelopes for the R-008 split.
//!
//! These values are admission and transcript-binding substrate only. They do
//! not verify a STARK, prove the ordered call commitment, or activate a split
//! production protocol. In particular, `descriptor_leaf_statement_digest` is
//! the pre-session declaration already committed by the R-007 manifest. The
//! digest returned by `sessionEnvelopeDigest` binds that declaration to the
//! prepared session and its shared challenge; it must not be written back into
//! the descriptor, which would create a hash cycle.
//!
//! Encoding is a fixed stream of little-endian u32 words. Word collection,
//! byte emission, and Blake2s identity all pass through `writeCanonical`; this
//! file intentionally has no second serialization or hash-preimage path.

const std = @import("std");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_manifest = @import("../../aggregation/manifest.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const aggregation_wire = @import("../../aggregation/wire.zig");

pub const RESEARCH_ONLY = true;
pub const VERIFIES_SPLIT_STARKS = false;
pub const PROVES_ORDERED_CALL_COMMITMENT = false;
pub const ACTIVATES_PRODUCTION_TRANSCRIPT = false;

pub const Digest = aggregation_hash.Digest;
pub const format_version: u32 = 1;
pub const statement_flags: u32 = 0;
pub const word_count: usize = 133;
pub const encoded_size: usize = word_count * @sizeOf(u32);

pub const caller_magic = [8]u8{ 'S', 'T', 'W', 'C', 'L', 'S', '1', 0 };
pub const provider_magic = [8]u8{ 'S', 'T', 'W', 'P', 'L', 'S', '1', 0 };
pub const caller_digest_domain =
    "stwo-zig/riscv/split/caller-leaf-statement/v1\x00";
pub const provider_digest_domain =
    "stwo-zig/riscv/split/provider-leaf-statement/v1\x00";

const caller_magic_words = [2]u32{ 0x4357_5453, 0x0031_534c };
const provider_magic_words = [2]u32{ 0x5057_5453, 0x0031_534c };

/// Protocol facts selected by verifier policy, never copied out of an
/// untrusted leaf proof. `canonical` accepts the already verifier-owned R-007
/// protocol identity and completes it with the fixed V1 profile constants.
pub const VerifierOwnedProtocolIdentityV1 = struct {
    proof_protocol_digest: Digest,
    execution_profile_id: u16,
    execution_semantic_digest: Digest,
    relation_registry_digest: Digest,
    relation_schema_id: u32,
    relation_schema_version: u16,
    relation_arity: u16,

    pub fn canonical(
        accepted: aggregation_types.AcceptedProtocolV1,
    ) !VerifierOwnedProtocolIdentityV1 {
        try accepted.validate();
        return .{
            .proof_protocol_digest = accepted.proof_protocol_digest,
            .execution_profile_id = aggregation_types.EXECUTION_PROFILE_ID,
            .execution_semantic_digest = aggregation_types.EXECUTION_SEMANTIC_DIGEST,
            .relation_registry_digest = accepted.relation_registry_digest,
            .relation_schema_id = aggregation_types.RELATION_SCHEMA_ID,
            .relation_schema_version = aggregation_types.RELATION_SCHEMA_VERSION,
            .relation_arity = aggregation_types.RELATION_ARITY,
        };
    }

    pub fn validate(self: VerifierOwnedProtocolIdentityV1) !void {
        if (aggregation_hash.isZero(self.proof_protocol_digest) or
            aggregation_hash.isZero(self.relation_registry_digest))
        {
            return error.ZeroProtocolIdentity;
        }
        if (self.execution_profile_id !=
            aggregation_types.EXECUTION_PROFILE_ID or
            !aggregation_hash.eql(
                self.execution_semantic_digest,
                aggregation_types.EXECUTION_SEMANTIC_DIGEST,
            ))
        {
            return error.ExecutionProfileMismatch;
        }
        if (self.relation_schema_id != aggregation_types.RELATION_SCHEMA_ID or
            self.relation_schema_version !=
                aggregation_types.RELATION_SCHEMA_VERSION or
            self.relation_arity != aggregation_types.RELATION_ARITY)
        {
            return error.RelationSchemaMismatch;
        }
    }
};

/// Per-role AIR and preprocessing facts selected by verifier policy. There is
/// deliberately no constructor that copies these values from a manifest: the
/// verifier must supply the accepted artifact independently, then the leaf
/// descriptor is compared against it.
pub const VerifierOwnedArtifactIdentityV1 = struct {
    role: aggregation_types.LeafRole,
    air_artifact_digest: Digest,
    preprocessed_root: Digest,
    component: component_registry.Descriptor,

    pub fn validate(
        self: VerifierOwnedArtifactIdentityV1,
        expected_role: aggregation_types.LeafRole,
        guest_call_count: u64,
    ) !void {
        if (self.role != expected_role) return error.ArtifactRoleMismatch;
        if (aggregation_hash.isZero(self.air_artifact_digest) or
            aggregation_hash.isZero(self.preprocessed_root))
        {
            return error.ZeroArtifactIdentity;
        }
        const n_rows = std.math.cast(u32, guest_call_count) orelse
            return error.CallCountOutOfRange;
        const expected = try component_registry.Descriptor.canonical(
            componentKind(expected_role),
            n_rows,
        );
        try self.component.validate();
        if (!std.meta.eql(self.component, expected))
            return error.ArtifactComponentMismatch;
    }
};

pub const VerifierOwnedLeafIdentitiesV1 = struct {
    protocol: VerifierOwnedProtocolIdentityV1,
    artifact: VerifierOwnedArtifactIdentityV1,
};

/// Canonical body shared by the two statically distinct statement types.
/// Numeric wire tags remain explicit so every reserved and discriminant word
/// is authenticated rather than inherited from Zig's in-memory layout.
pub const LeafStatementBodyV1 = struct {
    magic_words: [2]u32,
    format_version: u32,
    encoded_word_count: u32,
    flags: u32,

    session_digest: Digest,
    challenge_context_digest: Digest,
    guest_z: aggregation_types.SecureFelt,
    guest_alpha: aggregation_types.SecureFelt,
    prepared_descriptor_digest: Digest,

    leaf_index: u32,
    pair_index: u32,
    leaf_role: u32,
    descriptor_flags: u32,
    descriptor_reserved: u32,
    job_digest: Digest,
    descriptor_leaf_statement_digest: Digest,
    leaf_air_artifact_digest: Digest,
    preprocessed_root: Digest,
    main_root: Digest,
    guest_call_commitment: Digest,
    guest_call_count: u64,
    proof_protocol_digest: Digest,
    execution_profile_id: u32,
    relation_schema_version: u32,
    execution_semantic_digest: Digest,
    relation_registry_digest: Digest,
    relation_schema_id: u32,
    relation_arity: u32,
    descriptor_reserved_tail: u32,

    component: component_registry.Descriptor,
    reserved: [4]u32,
};

/// A comptime role makes caller and provider statements non-interchangeable at
/// the API boundary while retaining one reviewed encoder and validator body.
pub fn LeafStatementV1(comptime expected_role: aggregation_types.LeafRole) type {
    return struct {
        const Self = @This();

        body: LeafStatementBodyV1,

        pub fn init(
            session: *const aggregation_manifest.PreparedSessionV1,
            leaf_index: u32,
            identities: *const VerifierOwnedLeafIdentitiesV1,
        ) !Self {
            const leaf = try validateSessionLeafAuthority(
                expected_role,
                session,
                leaf_index,
                identities,
            );
            return .{ .body = canonicalBody(
                expected_role,
                session,
                leaf,
                identities.artifact.component,
            ) };
        }

        /// Replays membership and verifier-owned identity checks in O(1) after
        /// R-007 preparation. Prepared storage is required to remain immutable;
        /// the selected descriptor is nevertheless re-hashed to fail closed on
        /// accidental mutation at this boundary.
        pub fn validateAgainstSession(
            self: Self,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const VerifierOwnedLeafIdentitiesV1,
        ) !void {
            const leaf = try validateSessionLeafAuthority(
                expected_role,
                session,
                self.body.leaf_index,
                identities,
            );
            try validateBody(expected_role, self.body, session, leaf, identities);
        }

        /// Streams the one canonical word sequence into a transcript or other
        /// caller-owned sink exposing `writeWord(u32) !void`.
        pub fn streamCanonicalWords(
            self: Self,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const VerifierOwnedLeafIdentitiesV1,
            sink: anytype,
        ) !void {
            try self.validateAgainstSession(session, identities);
            try writeCanonical(sink, self.body);
        }

        pub fn canonicalWords(
            self: Self,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const VerifierOwnedLeafIdentitiesV1,
        ) ![word_count]u32 {
            var words: [word_count]u32 = undefined;
            var sink = WordArraySink{ .destination = &words };
            try self.streamCanonicalWords(session, identities, &sink);
            if (sink.offset != words.len) return error.CanonicalWordCountDrift;
            return words;
        }

        /// Exact-size and preflight-first: every validation failure leaves the
        /// caller's destination untouched.
        pub fn encodeInto(
            self: Self,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const VerifierOwnedLeafIdentitiesV1,
            destination: []u8,
        ) !usize {
            if (destination.len != encoded_size)
                return error.IncorrectBufferLength;
            try self.validateAgainstSession(session, identities);
            var sink = ByteSliceWordSink{ .destination = destination };
            try writeCanonical(&sink, self.body);
            if (sink.offset != destination.len)
                return error.CanonicalWordCountDrift;
            return sink.offset;
        }

        pub fn encode(
            self: Self,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const VerifierOwnedLeafIdentitiesV1,
        ) ![encoded_size]u8 {
            var bytes: [encoded_size]u8 = undefined;
            _ = try self.encodeInto(session, identities, &bytes);
            return bytes;
        }

        /// Session-bound envelope identity. This is intentionally distinct
        /// from the descriptor's pre-session `leaf_statement_digest`.
        pub fn sessionEnvelopeDigest(
            self: Self,
            session: *const aggregation_manifest.PreparedSessionV1,
            identities: *const VerifierOwnedLeafIdentitiesV1,
        ) !Digest {
            try self.validateAgainstSession(session, identities);
            var sink = HashWordSink.init(digestDomain(expected_role));
            try writeCanonical(&sink, self.body);
            return sink.finalize();
        }
    };
}

pub const CallerLeafStatementV1 = LeafStatementV1(.core_request);
pub const ProviderLeafStatementV1 = LeafStatementV1(.poseidon2_provider);

fn validateSessionLeafAuthority(
    comptime expected_role: aggregation_types.LeafRole,
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf_index: u32,
    identities: *const VerifierOwnedLeafIdentitiesV1,
) !*const aggregation_manifest.PreparedLeafV1 {
    if (session.header.leaf_count != session.leaves.len)
        return error.PreparedSessionShapeMismatch;
    if (!aggregation_hash.eql(
        session.challenge.session_digest,
        session.session_digest,
    )) return error.SessionMismatch;
    try session.challenge.validate();

    const leaf = try session.leaf(leaf_index);
    const descriptor = leaf.descriptor;
    if (descriptor.leaf_index != leaf_index)
        return error.NonCanonicalLeafPosition;
    if (descriptor.role != expected_role) return error.LeafRoleMismatch;
    if (!aggregation_hash.eql(
        aggregation_wire.hashDescriptor(descriptor),
        leaf.descriptor_digest,
    )) return error.PreparedLeafMutated;

    try identities.protocol.validate();
    try validateProtocolAuthority(identities.protocol, session, descriptor);
    try identities.artifact.validate(expected_role, descriptor.guest_call_count);
    if (!aggregation_hash.eql(
        identities.artifact.air_artifact_digest,
        descriptor.leaf_air_artifact_digest,
    ) or !aggregation_hash.eql(
        identities.artifact.preprocessed_root,
        descriptor.preprocessed_root,
    )) return error.ArtifactIdentityMismatch;
    return leaf;
}

fn validateProtocolAuthority(
    protocol: VerifierOwnedProtocolIdentityV1,
    session: *const aggregation_manifest.PreparedSessionV1,
    descriptor: aggregation_types.LeafDescriptorV1,
) !void {
    if (!aggregation_hash.eql(
        protocol.proof_protocol_digest,
        session.header.proof_protocol_digest,
    ) or !aggregation_hash.eql(
        protocol.relation_registry_digest,
        session.header.relation_registry_digest,
    ) or protocol.execution_profile_id != session.header.execution_profile_id or
        !aggregation_hash.eql(
            protocol.execution_semantic_digest,
            session.header.execution_semantic_digest,
        ) or protocol.relation_schema_id != session.header.relation_schema_id or
        protocol.relation_schema_version !=
            session.header.relation_schema_version or
        protocol.relation_arity != session.header.relation_arity)
    {
        return error.ProtocolIdentityMismatch;
    }
    if (!aggregation_hash.eql(
        protocol.proof_protocol_digest,
        descriptor.proof_protocol_digest,
    ) or !aggregation_hash.eql(
        protocol.relation_registry_digest,
        descriptor.relation_registry_digest,
    ) or protocol.execution_profile_id != descriptor.execution_profile_id or
        !aggregation_hash.eql(
            protocol.execution_semantic_digest,
            descriptor.execution_semantic_digest,
        ) or protocol.relation_schema_id != descriptor.relation_schema_id or
        protocol.relation_schema_version != descriptor.relation_schema_version or
        protocol.relation_arity != descriptor.relation_arity)
    {
        return error.ProtocolIdentityMismatch;
    }
}

fn canonicalBody(
    comptime role: aggregation_types.LeafRole,
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf: *const aggregation_manifest.PreparedLeafV1,
    component: component_registry.Descriptor,
) LeafStatementBodyV1 {
    const descriptor = leaf.descriptor;
    return .{
        .magic_words = magicWords(role),
        .format_version = format_version,
        .encoded_word_count = word_count,
        .flags = statement_flags,
        .session_digest = session.session_digest,
        .challenge_context_digest = session.challenge.challenge_context_digest,
        .guest_z = session.challenge.z,
        .guest_alpha = session.challenge.alpha,
        .prepared_descriptor_digest = leaf.descriptor_digest,
        .leaf_index = descriptor.leaf_index,
        .pair_index = descriptor.pair_index,
        .leaf_role = @intFromEnum(descriptor.role),
        .descriptor_flags = descriptor.flags,
        .descriptor_reserved = descriptor.reserved,
        .job_digest = descriptor.job_digest,
        .descriptor_leaf_statement_digest = descriptor.leaf_statement_digest,
        .leaf_air_artifact_digest = descriptor.leaf_air_artifact_digest,
        .preprocessed_root = descriptor.preprocessed_root,
        .main_root = descriptor.main_root,
        .guest_call_commitment = descriptor.guest_call_commitment,
        .guest_call_count = descriptor.guest_call_count,
        .proof_protocol_digest = descriptor.proof_protocol_digest,
        .execution_profile_id = descriptor.execution_profile_id,
        .relation_schema_version = descriptor.relation_schema_version,
        .execution_semantic_digest = descriptor.execution_semantic_digest,
        .relation_registry_digest = descriptor.relation_registry_digest,
        .relation_schema_id = descriptor.relation_schema_id,
        .relation_arity = descriptor.relation_arity,
        .descriptor_reserved_tail = descriptor.reserved_tail,
        .component = component,
        .reserved = .{0} ** 4,
    };
}

fn validateBody(
    comptime role: aggregation_types.LeafRole,
    body: LeafStatementBodyV1,
    session: *const aggregation_manifest.PreparedSessionV1,
    leaf: *const aggregation_manifest.PreparedLeafV1,
    identities: *const VerifierOwnedLeafIdentitiesV1,
) !void {
    if (!std.mem.eql(u32, &body.magic_words, &magicWords(role)))
        return error.InvalidStatementMagic;
    if (body.format_version != format_version)
        return error.UnsupportedStatementVersion;
    if (body.encoded_word_count != word_count)
        return error.StatementWordCountMismatch;
    if (body.flags != statement_flags) return error.UnsupportedStatementFlags;
    if (!allZeroWords(&body.reserved)) return error.NonZeroReservedWords;

    if (!aggregation_hash.eql(body.session_digest, session.session_digest))
        return error.SessionMismatch;
    if (!aggregation_hash.eql(
        body.challenge_context_digest,
        session.challenge.challenge_context_digest,
    ) or !aggregation_types.SecureFelt.eql(body.guest_z, session.challenge.z) or
        !aggregation_types.SecureFelt.eql(
            body.guest_alpha,
            session.challenge.alpha,
        ))
    {
        return error.ChallengeContextMismatch;
    }
    if (!aggregation_hash.eql(
        body.prepared_descriptor_digest,
        leaf.descriptor_digest,
    )) return error.DescriptorDigestMismatch;

    const descriptor = leaf.descriptor;
    if (body.leaf_index != descriptor.leaf_index or
        body.pair_index != descriptor.pair_index)
    {
        return error.NonCanonicalLeafPosition;
    }
    if (body.leaf_role != @intFromEnum(role) or
        body.leaf_role != @intFromEnum(descriptor.role))
    {
        return error.LeafRoleMismatch;
    }
    if (body.descriptor_flags != descriptor.flags)
        return error.DescriptorFlagsMismatch;
    if (body.descriptor_reserved != descriptor.reserved or
        body.descriptor_reserved_tail != descriptor.reserved_tail)
    {
        return error.NonZeroReservedBits;
    }
    if (!aggregation_hash.eql(body.job_digest, descriptor.job_digest) or
        !aggregation_hash.eql(
            body.descriptor_leaf_statement_digest,
            descriptor.leaf_statement_digest,
        ))
    {
        return error.DescriptorIdentityMismatch;
    }
    if (!aggregation_hash.eql(
        body.leaf_air_artifact_digest,
        descriptor.leaf_air_artifact_digest,
    ) or !aggregation_hash.eql(
        body.leaf_air_artifact_digest,
        identities.artifact.air_artifact_digest,
    ) or !aggregation_hash.eql(
        body.preprocessed_root,
        descriptor.preprocessed_root,
    ) or !aggregation_hash.eql(
        body.preprocessed_root,
        identities.artifact.preprocessed_root,
    )) {
        return error.ArtifactIdentityMismatch;
    }
    if (!aggregation_hash.eql(body.main_root, descriptor.main_root))
        return error.MainRootMismatch;
    if (!aggregation_hash.eql(
        body.guest_call_commitment,
        descriptor.guest_call_commitment,
    )) return error.CallCommitmentMismatch;
    if (body.guest_call_count != descriptor.guest_call_count)
        return error.CallCountMismatch;

    if (!aggregation_hash.eql(
        body.proof_protocol_digest,
        identities.protocol.proof_protocol_digest,
    ) or body.execution_profile_id != identities.protocol.execution_profile_id or
        !aggregation_hash.eql(
            body.execution_semantic_digest,
            identities.protocol.execution_semantic_digest,
        ) or !aggregation_hash.eql(
        body.relation_registry_digest,
        identities.protocol.relation_registry_digest,
    ) or body.relation_schema_id != identities.protocol.relation_schema_id or
        body.relation_schema_version !=
            identities.protocol.relation_schema_version or
        body.relation_arity != identities.protocol.relation_arity)
    {
        return error.ProtocolIdentityMismatch;
    }
    if (!std.meta.eql(body.component, identities.artifact.component))
        return error.ArtifactComponentMismatch;
}

fn componentKind(role: aggregation_types.LeafRole) component_registry.Kind {
    return switch (role) {
        .core_request => .guest_poseidon2_call_v1,
        .poseidon2_provider => .guest_poseidon2_provider_compat_v1,
    };
}

fn magicWords(role: aggregation_types.LeafRole) [2]u32 {
    return switch (role) {
        .core_request => caller_magic_words,
        .poseidon2_provider => provider_magic_words,
    };
}

fn digestDomain(role: aggregation_types.LeafRole) []const u8 {
    return switch (role) {
        .core_request => caller_digest_domain,
        .poseidon2_provider => provider_digest_domain,
    };
}

fn allZeroWords(words: []const u32) bool {
    var combined: u32 = 0;
    for (words) |word| combined |= word;
    return combined == 0;
}

/// The single canonical serialization definition.
fn writeCanonical(sink: anytype, body: LeafStatementBodyV1) !void {
    var emitted: usize = 0;
    try emitWords(sink, &emitted, &body.magic_words);
    try emitWord(sink, &emitted, body.format_version);
    try emitWord(sink, &emitted, body.encoded_word_count);
    try emitWord(sink, &emitted, body.flags);

    try emitDigest(sink, &emitted, body.session_digest);
    try emitDigest(sink, &emitted, body.challenge_context_digest);
    try emitWords(sink, &emitted, &body.guest_z.limbs);
    try emitWords(sink, &emitted, &body.guest_alpha.limbs);
    try emitDigest(sink, &emitted, body.prepared_descriptor_digest);

    try emitWord(sink, &emitted, body.leaf_index);
    try emitWord(sink, &emitted, body.pair_index);
    try emitWord(sink, &emitted, body.leaf_role);
    try emitWord(sink, &emitted, body.descriptor_flags);
    try emitWord(sink, &emitted, body.descriptor_reserved);
    try emitDigest(sink, &emitted, body.job_digest);
    try emitDigest(sink, &emitted, body.descriptor_leaf_statement_digest);
    try emitDigest(sink, &emitted, body.leaf_air_artifact_digest);
    try emitDigest(sink, &emitted, body.preprocessed_root);
    try emitDigest(sink, &emitted, body.main_root);
    try emitDigest(sink, &emitted, body.guest_call_commitment);
    try emitU64(sink, &emitted, body.guest_call_count);
    try emitDigest(sink, &emitted, body.proof_protocol_digest);
    try emitWord(sink, &emitted, body.execution_profile_id);
    try emitWord(sink, &emitted, body.relation_schema_version);
    try emitDigest(sink, &emitted, body.execution_semantic_digest);
    try emitDigest(sink, &emitted, body.relation_registry_digest);
    try emitWord(sink, &emitted, body.relation_schema_id);
    try emitWord(sink, &emitted, body.relation_arity);
    try emitWord(sink, &emitted, body.descriptor_reserved_tail);

    try emitWord(sink, &emitted, @intFromEnum(body.component.slot));
    try emitWord(sink, &emitted, @intFromEnum(body.component.kind));
    try emitWord(sink, &emitted, body.component.version);
    try emitWord(sink, &emitted, body.component.n_rows);
    try emitWord(sink, &emitted, body.component.log_size);
    try emitWord(sink, &emitted, body.component.preprocessed_columns);
    try emitWord(sink, &emitted, body.component.main_columns);
    try emitWord(sink, &emitted, body.component.interaction_columns);
    try emitWords(sink, &emitted, &body.reserved);

    if (emitted != word_count) return error.CanonicalWordCountDrift;
}

fn emitWord(sink: anytype, emitted: *usize, value: u32) !void {
    try sink.writeWord(value);
    emitted.* += 1;
}

fn emitWords(sink: anytype, emitted: *usize, words: []const u32) !void {
    for (words) |word| try emitWord(sink, emitted, word);
}

fn emitDigest(sink: anytype, emitted: *usize, digest: Digest) !void {
    for (0..digest.len / @sizeOf(u32)) |index| {
        const offset = index * @sizeOf(u32);
        try emitWord(
            sink,
            emitted,
            std.mem.readInt(u32, digest[offset..][0..4], .little),
        );
    }
}

fn emitU64(sink: anytype, emitted: *usize, value: u64) !void {
    try emitWord(sink, emitted, @truncate(value));
    try emitWord(sink, emitted, @truncate(value >> 32));
}

const WordArraySink = struct {
    destination: *[word_count]u32,
    offset: usize = 0,

    fn writeWord(self: *WordArraySink, value: u32) !void {
        if (self.offset >= self.destination.len)
            return error.CanonicalWordCountDrift;
        self.destination[self.offset] = value;
        self.offset += 1;
    }
};

const ByteSliceWordSink = struct {
    destination: []u8,
    offset: usize = 0,

    fn writeWord(self: *ByteSliceWordSink, value: u32) !void {
        const end = std.math.add(usize, self.offset, @sizeOf(u32)) catch
            return error.CanonicalWordCountDrift;
        if (end > self.destination.len) return error.CanonicalWordCountDrift;
        std.mem.writeInt(
            u32,
            self.destination[self.offset..end][0..4],
            value,
            .little,
        );
        self.offset = end;
    }
};

const HashWordSink = struct {
    sink: aggregation_hash.HashSink,

    fn init(domain: []const u8) HashWordSink {
        return .{ .sink = aggregation_hash.HashSink.init(domain) };
    }

    fn writeWord(self: *HashWordSink, value: u32) !void {
        try aggregation_hash.writeU32(&self.sink, value);
    }

    fn finalize(self: *HashWordSink) Digest {
        return self.sink.finalize();
    }
};

comptime {
    if (word_count != 133 or encoded_size != 532)
        @compileError("R-008 split leaf statement V1 geometry drifted");
    if (@intFromEnum(aggregation_types.LeafRole.core_request) != 1 or
        @intFromEnum(aggregation_types.LeafRole.poseidon2_provider) != 2)
    {
        @compileError("R-007 leaf-role wire tags drifted");
    }
}
