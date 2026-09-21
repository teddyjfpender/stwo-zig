//! Append-only pair authority for recursive children with distinct VKs.
//!
//! Each child first crosses verifier-minted publication/artifact admission and
//! an exact node-profile check. The parent may then accept different child
//! verification keys while requiring one common authenticated next-parent VK.
//! The frozen homogeneous V2 pair and its identities are not modified.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const profile_mod = @import("recursive_temporal_node_profile_v1.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;
const temporal = recursion.temporal_pair_node;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CHILD_COUNT: usize = 2;
const CHILD_DOMAIN: u32 = 0x4850_4331; // "HPC1"
const PAIR_DOMAIN: u32 = 0x4850_5031; // "HPP1"
const CONTEXT_DOMAIN: u32 = 0x4850_5831; // "HPX1"
const NODE_DOMAIN: u32 = 0x4850_4e31; // "HPN1"
const RECORD_DOMAIN: u32 = 0x4850_5231; // "HPR1"
const ADJACENCY_DOMAIN: u32 = 0x4850_4131; // "HPA1"

pub const Digest = channel.Digest;

pub const PreparedChildV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    publication_sha_id: [32]u8,
    publication_id: Digest,
    artifact_id: Digest,
    child: temporal.VerifiedChildV2,
    child_id: Digest,
    profile: profile_mod.NodeProfileV1,
    admission_id: Digest,

    pub fn validate(self: *const PreparedChildV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            std.mem.allEqual(u8, &self.publication_sha_id, 0))
        {
            return error.InvalidHeterogeneousChild;
        }
        try self.profile.validate();
        const statement = try self.child.statement();
        if (statement.slots.height != self.profile.parent_height or
            !std.meta.eql(self.child.verification_key_id, self.profile.verification_key_id) or
            !std.meta.eql(self.child.recursive_parent_vk_id, self.profile.next_parent_vk_id) or
            !std.meta.eql(self.child.air_program_id, self.profile.air_program_id) or
            !std.meta.eql(self.child.profile_id, self.profile.profile_id) or
            !std.meta.eql(self.child_id, try self.child.id()) or
            !std.meta.eql(self.admission_id, childIdentity(self)))
        {
            return error.InvalidHeterogeneousChild;
        }
        try requireDigest(self.publication_id);
        try requireDigest(self.artifact_id);
        try requireDigest(self.child_id);
        try requireDigest(self.admission_id);
    }
};

pub fn admitInto(
    destination: *PreparedChildV1,
    publication: *const publication_mod.VerifiedPublicationV1,
    artifact: *const artifact_mod.VerifiedTemporalParentArtifactV1,
    profile: profile_mod.NodeProfileV1,
) !void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(publication)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(artifact)))
    {
        return error.AliasedDestination;
    }
    try profile.validateArtifact(publication, artifact);
    var result = PreparedChildV1{
        .publication_sha_id = publication.publication_sha_id,
        .publication_id = artifact.publication_id,
        .artifact_id = artifact.artifact_id,
        .child = artifact.child,
        .child_id = artifact.child_id,
        .profile = profile,
        .admission_id = undefined,
    };
    result.admission_id = childIdentity(&result);
    try result.validate();
    destination.* = result;
}

pub const AuthenticatedPairV1 = struct {
    session_id: Digest,
    job_id: Digest,
    verification_key_id: Digest,
    next_parent_vk_id: Digest,
    parent_height: u8,
    parent_node_index: u64,
    parent_statement: span.SpanStatement,
    parent_statement_words: span.StatementWords,
    parent_statement_id: Digest,
    child_ids: [CHILD_COUNT]Digest,
    child_verification_key_ids: [CHILD_COUNT]Digest,
    child_profile_sha_ids: [CHILD_COUNT][32]u8,
    context_id: Digest,
    node_id: Digest,
    record_id: Digest,
};

pub const PreparedPairV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    child_count: u8 = CHILD_COUNT,
    padding: [3]u8 = .{ 0, 0, 0 },
    children: [CHILD_COUNT]PreparedChildV1,
    parent_profile: profile_mod.NodeProfileV1,
    pair: AuthenticatedPairV1,
    adjacency_id: Digest,
    authority_id: Digest,

    pub fn validate(self: *const PreparedPairV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.child_count != CHILD_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.InvalidHeterogeneousPair;
        }
        for (&self.children) |*child| try child.validate();
        try self.parent_profile.validate();
        const expected = try derivePair(self.children, self.parent_profile);
        if (!std.meta.eql(expected, self.pair) or
            !std.meta.eql(self.adjacency_id, adjacencyIdentity(self)) or
            !std.meta.eql(self.authority_id, pairIdentity(self)))
        {
            return error.InvalidHeterogeneousPair;
        }
    }

    pub fn authenticatePrepared(self: *const PreparedPairV1) !AuthenticatedPairV1 {
        try self.validate();
        return self.pair;
    }
};

pub fn prepareInto(
    destination: *PreparedPairV1,
    left: *const PreparedChildV1,
    right: *const PreparedChildV1,
    parent_profile: profile_mod.NodeProfileV1,
    root_pin: *const temporal.RootVkPinV2,
) !void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(left)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(right)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(root_pin)))
    {
        return error.AliasedDestination;
    }
    try left.validate();
    try right.validate();
    try parent_profile.validate();
    try root_pin.validate();
    if (std.meta.eql(left.admission_id, right.admission_id) or
        std.meta.eql(left.child_id, right.child_id))
    {
        return error.DuplicateChild;
    }
    if (!std.meta.eql(
        root_pin.expected_aggregator_vk_id,
        parent_profile.verification_key_id,
    )) return error.VerificationKeyMismatch;
    const children = [CHILD_COUNT]PreparedChildV1{ left.*, right.* };
    const pair = try derivePair(children, parent_profile);
    var result = PreparedPairV1{
        .children = children,
        .parent_profile = parent_profile,
        .pair = pair,
        .adjacency_id = undefined,
        .authority_id = undefined,
    };
    result.adjacency_id = adjacencyIdentity(&result);
    result.authority_id = pairIdentity(&result);
    try result.validate();
    destination.* = result;
}

fn derivePair(
    children: [CHILD_COUNT]PreparedChildV1,
    parent_profile: profile_mod.NodeProfileV1,
) !AuthenticatedPairV1 {
    for (&children) |*child| try child.validate();
    try parent_profile.validate();
    const left_statement = try children[0].child.statement();
    const right_statement = try children[1].child.statement();
    const parent = span.SpanStatement.fold(left_statement, right_statement) catch |err|
        switch (err) {
            error.SlotsNotAdjacent => return error.ChildOrderMismatch,
            else => return err,
        };
    if (left_statement.slots.height != right_statement.slots.height or
        parent.slots.height != parent_profile.parent_height or
        !std.meta.eql(children[0].child.session_id, children[1].child.session_id) or
        !std.meta.eql(children[0].child.job_id, children[1].child.job_id) or
        !std.meta.eql(
            children[0].child.recursive_parent_vk_id,
            parent_profile.verification_key_id,
        ) or !std.meta.eql(
        children[1].child.recursive_parent_vk_id,
        parent_profile.verification_key_id,
    )) return error.InvalidHeterogeneousPair;
    const words = try parent.canonicalWords();
    const statement_id = statementId(&words);
    var result = AuthenticatedPairV1{
        .session_id = children[0].child.session_id,
        .job_id = children[0].child.job_id,
        .verification_key_id = parent_profile.verification_key_id,
        .next_parent_vk_id = parent_profile.next_parent_vk_id,
        .parent_height = parent.slots.height,
        .parent_node_index = parent.slots.nodeIndex(),
        .parent_statement = parent,
        .parent_statement_words = words,
        .parent_statement_id = statement_id,
        .child_ids = .{ children[0].child_id, children[1].child_id },
        .child_verification_key_ids = .{
            children[0].child.verification_key_id,
            children[1].child.verification_key_id,
        },
        .child_profile_sha_ids = .{
            children[0].profile.identity,
            children[1].profile.identity,
        },
        .context_id = undefined,
        .node_id = undefined,
        .record_id = undefined,
    };
    result.context_id = contextIdentity(&result);
    result.node_id = nodeIdentity(&result);
    result.record_id = recordIdentity(&result);
    return result;
}

fn childIdentity(value: *const PreparedChildV1) Digest {
    var hash = IdentityHasher.init(CHILD_DOMAIN);
    hash.digest(channel.hashBytes(
        &value.publication_sha_id,
        CHILD_DOMAIN + 2,
    ));
    hash.digest(value.publication_id);
    hash.digest(value.artifact_id);
    hash.digest(value.child_id);
    hash.digest(value.child.verification_key_id);
    hash.digest(value.child.recursive_parent_vk_id);
    hash.digest(channel.hashBytes(&value.profile.identity, CHILD_DOMAIN + 1));
    return hash.finalize();
}

test "prepared child identity binds verifier-minted publication bytes" {
    var value: PreparedChildV1 = undefined;
    @memset(std.mem.asBytes(&value), 0);
    value.publication_sha_id[0] = 1;
    const original = childIdentity(&value);
    value.publication_sha_id[0] = 2;
    try std.testing.expect(!std.meta.eql(original, childIdentity(&value)));
}

fn pairIdentity(value: *const PreparedPairV1) Digest {
    var hash = IdentityHasher.init(PAIR_DOMAIN);
    hash.digest(value.children[0].admission_id);
    hash.digest(value.children[1].admission_id);
    hash.digest(channel.hashBytes(&value.parent_profile.identity, PAIR_DOMAIN + 1));
    hash.digest(value.adjacency_id);
    hash.digest(value.pair.context_id);
    hash.digest(value.pair.node_id);
    hash.digest(value.pair.record_id);
    return hash.finalize();
}

fn adjacencyIdentity(value: *const PreparedPairV1) Digest {
    var hash = IdentityHasher.init(ADJACENCY_DOMAIN);
    hash.digest(value.pair.child_ids[0]);
    hash.digest(value.pair.child_ids[1]);
    hash.digest(value.pair.parent_statement_id);
    hash.addU32(value.pair.parent_height);
    return hash.finalize();
}

fn contextIdentity(value: *const AuthenticatedPairV1) Digest {
    var hash = IdentityHasher.init(CONTEXT_DOMAIN);
    hash.digest(value.session_id);
    hash.digest(value.job_id);
    hash.digest(value.verification_key_id);
    hash.digest(value.next_parent_vk_id);
    hash.addU64(value.parent_node_index);
    hash.addU32(value.parent_height);
    for (value.child_verification_key_ids) |item| hash.digest(item);
    for (value.child_profile_sha_ids) |item|
        hash.digest(channel.hashBytes(&item, CONTEXT_DOMAIN + 1));
    return hash.finalize();
}

fn nodeIdentity(value: *const AuthenticatedPairV1) Digest {
    var hash = IdentityHasher.init(NODE_DOMAIN);
    hash.digest(value.context_id);
    hash.digest(value.child_ids[0]);
    hash.digest(value.child_ids[1]);
    hash.digest(value.parent_statement_id);
    return hash.finalize();
}

fn recordIdentity(value: *const AuthenticatedPairV1) Digest {
    var hash = IdentityHasher.init(RECORD_DOMAIN);
    hash.digest(value.context_id);
    hash.digest(value.node_id);
    hash.digest(value.parent_statement_id);
    return hash.finalize();
}

fn statementId(words: *const span.StatementWords) Digest {
    var canonical: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return recursion.protocol.statementId(&canonical);
}

fn requireDigest(value: Digest) !void {
    var nonzero = false;
    for (value) |word| {
        if (word >= m31.Modulus) return error.InvalidHeterogeneousPair;
        nonzero = nonzero or word != 0;
    }
    if (!nonzero) return error.InvalidHeterogeneousPair;
}

fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

const IdentityHasher = struct {
    inner: channel.CanonicalWordHasher,

    fn init(domain: u32) IdentityHasher {
        return .{ .inner = channel.CanonicalWordHasher.init(domain) };
    }

    fn addU32(self: *IdentityHasher, value: u32) void {
        const words = [_]M31{M31.fromCanonical(value)};
        self.inner.update(&words);
    }

    fn addU64(self: *IdentityHasher, value: u64) void {
        self.addU32(@truncate(value));
        self.addU32(@truncate(value >> 32));
    }

    fn digest(self: *IdentityHasher, value: Digest) void {
        var words: [channel.RATE]M31 = undefined;
        for (&words, value) |*word, raw| word.* = M31.fromCanonical(raw);
        self.inner.update(&words);
    }

    fn finalize(self: *IdentityHasher) Digest {
        return self.inner.finalize();
    }
};

comptime {
    if (CHILD_COUNT != 2)
        @compileError("heterogeneous pair contract drifted");
}
