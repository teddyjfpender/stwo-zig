//! Authenticated temporal authority over two verified parent proofs.
//!
//! Each input must be the verifier-minted sidecar paired with the exact V3
//! publication that created it.  The module then uses the canonical temporal
//! pair node to fold two adjacent equal-height spans into their next-height
//! root. Schema 2 remains byte-for-byte pinned for the original height-2
//! authority; schema 3 is selected only for height 3 and above.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const temporal = recursion.temporal_pair_node;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const GENERIC_SCHEMA_VERSION: u16 = 3;
pub const CHILD_COUNT: usize = 2;
pub const FIRST_MULTI_LEVEL_HEIGHT: u8 = 2;
pub const ROOT_PROOF_AVAILABLE = false;
pub const PRODUCTION_ACTIVATION = false;
pub const HEAP_ALLOCATIONS_PER_PREPARE: usize = 0;

const CHILD_ADMISSION_ID_DOMAIN: u32 = 0x4d4c_4331; // "MLC1"
const PAIR_AUTHORITY_ID_DOMAIN: u32 = 0x4d4c_5031; // "MLP1"
const ADJACENCY_ID_DOMAIN: u32 = 0x4d4c_4131; // "MLA1"

pub const Digest = channel.Digest;
pub const Publication = publication_mod.VerifiedPublicationV1;
pub const Artifact = artifact_mod.VerifiedTemporalParentArtifactV1;
pub const RootVkPin = temporal.RootVkPinV2;

pub const Error = temporal.Error || error{
    AliasedDestination,
    AuthorityIdentityMismatch,
    DuplicateChild,
    ParentGeometryMismatch,
    PublicationMismatch,
    UnsupportedFormat,
};

pub const PreparedParentChildV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    publication_sha_id: [32]u8,
    publication_id: Digest,
    artifact_id: Digest,
    child: temporal.VerifiedChildV2,
    child_id: Digest,
    admission_id: Digest,

    pub fn validate(self: *const PreparedParentChildV1) !void {
        if (self.format_version != FORMAT_VERSION or
            (self.schema_version != SCHEMA_VERSION and
                self.schema_version != GENERIC_SCHEMA_VERSION) or
            !std.mem.allEqual(u8, &self.padding, 0) or
            std.mem.allEqual(u8, &self.publication_sha_id, 0))
        {
            return error.UnsupportedFormat;
        }
        inline for (.{
            self.publication_id,
            self.artifact_id,
            self.child_id,
            self.admission_id,
        }) |value| try requireDigest(value);
        const statement = try self.child.statement();
        if (self.child.kind != .binary_node or statement.slots.height == 0 or
            self.schema_version != childSchema(statement.slots.height) or
            !std.meta.eql(self.child_id, try self.child.id()) or
            !std.meta.eql(self.admission_id, childAdmissionIdentity(self)))
        {
            return error.ParentGeometryMismatch;
        }
    }

    pub fn validateAgainst(
        self: *const PreparedParentChildV1,
        publication: *const Publication,
        artifact: *const Artifact,
    ) !void {
        try self.validate();
        try artifact.validateAgainst(publication);
        if (!std.mem.eql(
            u8,
            &self.publication_sha_id,
            &publication.publication_sha_id,
        ) or !std.meta.eql(self.publication_id, artifact.publication_id) or
            !std.meta.eql(self.artifact_id, artifact.artifact_id) or
            !std.meta.eql(self.child, artifact.child) or
            !std.meta.eql(self.child_id, artifact.child_id))
        {
            return error.PublicationMismatch;
        }
    }
};

pub const PreparedLevel2PairV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    child_count: u8 = CHILD_COUNT,
    root_proof_available: bool = ROOT_PROOF_AVAILABLE,
    production_activation: bool = PRODUCTION_ACTIVATION,
    padding: [1]u8 = .{0},
    child_admission_ids: [CHILD_COUNT]Digest,
    child_publication_ids: [CHILD_COUNT]Digest,
    adjacency_id: Digest,
    prepared_root: temporal.PreparedRootContextV2,
    authority_id: Digest,

    pub fn validate(self: *const PreparedLevel2PairV1) !void {
        if (self.format_version != FORMAT_VERSION or
            (self.schema_version != SCHEMA_VERSION and
                self.schema_version != GENERIC_SCHEMA_VERSION) or
            self.child_count != CHILD_COUNT or self.root_proof_available or
            self.production_activation or !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.UnsupportedFormat;
        }
        for (self.child_admission_ids) |value| try requireDigest(value);
        for (self.child_publication_ids) |value| try requireDigest(value);
        try requireDigest(self.adjacency_id);
        try requireDigest(self.authority_id);
        const reconstructed = try temporal.prepareRootContext(
            &self.prepared_root.authority_snapshot,
            &self.prepared_root.pin_snapshot,
        );
        if (!std.meta.eql(reconstructed, self.prepared_root) or
            reconstructed.result.pair.parent_height < FIRST_MULTI_LEVEL_HEIGHT or
            self.schema_version != pairSchema(
                reconstructed.result.pair.parent_height,
            ) or
            !std.meta.eql(self.adjacency_id, adjacencyIdentity(self)) or
            !std.meta.eql(self.authority_id, pairAuthorityIdentity(self)))
        {
            return error.AuthorityIdentityMismatch;
        }
    }

    pub fn authenticatePrepared(
        self: *const PreparedLevel2PairV1,
    ) !temporal.RootAuthenticatedTemporalPairV2 {
        try self.validate();
        return self.prepared_root.result;
    }
};

/// Generic name for new callers. The original exported type remains an alias
/// so every height-2 layout, encoding, and identity stays unchanged.
pub const PreparedTemporalNodePairV1 = PreparedLevel2PairV1;

pub fn admitInto(
    destination: *PreparedParentChildV1,
    publication: *const Publication,
    artifact: *const Artifact,
) !void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(publication)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(artifact)))
    {
        return error.AliasedDestination;
    }
    try artifact.validateAgainst(publication);
    const statement = try artifact.child.statement();
    if (statement.slots.height == 0)
        return error.ParentGeometryMismatch;
    var result = PreparedParentChildV1{
        .schema_version = childSchema(statement.slots.height),
        .publication_sha_id = publication.publication_sha_id,
        .publication_id = artifact.publication_id,
        .artifact_id = artifact.artifact_id,
        .child = artifact.child,
        .child_id = artifact.child_id,
        .admission_id = undefined,
    };
    result.admission_id = childAdmissionIdentity(&result);
    try result.validate();
    destination.* = result;
}

pub fn prepareInto(
    destination: *PreparedLevel2PairV1,
    left: *const PreparedParentChildV1,
    right: *const PreparedParentChildV1,
    root_pin: *const RootVkPin,
) !void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(left)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(right)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(root_pin)))
    {
        return error.AliasedDestination;
    }
    try left.validate();
    try right.validate();
    try root_pin.validate();
    if (std.meta.eql(left.admission_id, right.admission_id) or
        std.meta.eql(left.child_id, right.child_id) or
        std.mem.eql(
            u8,
            &left.publication_sha_id,
            &right.publication_sha_id,
        )) return error.DuplicateChild;

    const children = [CHILD_COUNT]temporal.VerifiedChildV2{
        left.child,
        right.child,
    };
    const parent_statement = recursion.span_statement.SpanStatement.fold(
        try children[0].statement(),
        try children[1].statement(),
    ) catch |err| switch (err) {
        // The level-2 authority exposes sibling ordering as its stable public
        // contract; do not leak the lower span implementation's adjacency
        // spelling to callers.
        error.SlotsNotAdjacent => return error.ChildOrderMismatch,
        else => return err,
    };
    if (parent_statement.slots.height < FIRST_MULTI_LEVEL_HEIGHT)
        return error.ParentGeometryMismatch;
    const parent_words = try parent_statement.canonicalWords();
    var statement_probe = std.mem.zeroes(temporal.VerifiedChildV2);
    statement_probe.statement_words = parent_words;
    const authority = temporal.VerifierAuthorityV2{
        .context = .{
            .session_id = children[0].session_id,
            .job_id = children[0].job_id,
            .segment_leaf_vk_id = children[0].verification_key_id,
            .aggregator_vk_id = children[0].recursive_parent_vk_id,
            .parent_node_index = parent_statement.slots.nodeIndex(),
            .parent_height = parent_statement.slots.height,
            .expected_parent_statement_id = try statement_probe.statementId(),
        },
        .children = children,
    };
    const prepared_root = try temporal.prepareRootContext(&authority, root_pin);
    var result = PreparedLevel2PairV1{
        .schema_version = pairSchema(parent_statement.slots.height),
        .child_admission_ids = .{ left.admission_id, right.admission_id },
        .child_publication_ids = .{ left.publication_id, right.publication_id },
        .adjacency_id = undefined,
        .prepared_root = prepared_root,
        .authority_id = undefined,
    };
    result.adjacency_id = adjacencyIdentity(&result);
    result.authority_id = pairAuthorityIdentity(&result);
    try result.validate();
    destination.* = result;
}

fn childSchema(height: u8) u16 {
    return if (height == FIRST_MULTI_LEVEL_HEIGHT - 1)
        SCHEMA_VERSION
    else
        GENERIC_SCHEMA_VERSION;
}

fn pairSchema(height: u8) u16 {
    return if (height == FIRST_MULTI_LEVEL_HEIGHT)
        SCHEMA_VERSION
    else
        GENERIC_SCHEMA_VERSION;
}

fn childAdmissionIdentity(value: *const PreparedParentChildV1) Digest {
    var hasher = IdentityHasher.init(CHILD_ADMISSION_ID_DOMAIN);
    hasher.addU32(value.format_version);
    hasher.addU32(value.schema_version);
    hasher.digest(value.publication_id);
    hasher.digest(value.artifact_id);
    hasher.digest(value.child_id);
    hasher.digest(value.child.proof_id);
    hasher.digest(value.child.transcript_id);
    hasher.digest(value.child.lineage_id);
    return hasher.finalize();
}

fn pairAuthorityIdentity(value: *const PreparedLevel2PairV1) Digest {
    const pair = value.prepared_root.result.pair;
    var hasher = IdentityHasher.init(PAIR_AUTHORITY_ID_DOMAIN);
    hasher.addU32(value.format_version);
    hasher.addU32(value.schema_version);
    hasher.addU32(value.child_count);
    hasher.addU32(@intFromBool(value.root_proof_available));
    hasher.addU32(@intFromBool(value.production_activation));
    hasher.digest(value.child_admission_ids[0]);
    hasher.digest(value.child_admission_ids[1]);
    hasher.digest(value.child_publication_ids[0]);
    hasher.digest(value.child_publication_ids[1]);
    hasher.digest(value.adjacency_id);
    hasher.digest(pair.context_id);
    hasher.digest(pair.node_id);
    hasher.digest(pair.record_id);
    hasher.digest(pair.parent_statement_id);
    return hasher.finalize();
}

fn adjacencyIdentity(value: *const PreparedLevel2PairV1) Digest {
    const pair = value.prepared_root.result.pair;
    var hasher = IdentityHasher.init(ADJACENCY_ID_DOMAIN);
    hasher.addU32(value.format_version);
    hasher.addU32(value.schema_version);
    hasher.digest(value.child_publication_ids[0]);
    hasher.digest(value.child_publication_ids[1]);
    hasher.digest(pair.child_ids[0]);
    hasher.digest(pair.child_ids[1]);
    hasher.digest(pair.parent_statement_id);
    hasher.addU32(pair.parent_height);
    return hasher.finalize();
}

fn requireDigest(value: Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.AuthorityIdentityMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.AuthorityIdentityMismatch;
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
        std.debug.assert(value < m31.Modulus);
        const words = [_]M31{M31.fromCanonical(value)};
        self.inner.update(&words);
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

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("multi-level pair authority retains a pointer"),
        .optional => |optional| assertPointerFree(optional.child),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (CHILD_COUNT != 2 or FIRST_MULTI_LEVEL_HEIGHT != 2 or
        ROOT_PROOF_AVAILABLE or PRODUCTION_ACTIVATION or
        HEAP_ALLOCATIONS_PER_PREPARE != 0)
    {
        @compileError("multi-level temporal authority ABI drifted");
    }
    assertPointerFree(PreparedParentChildV1);
    assertPointerFree(PreparedLevel2PairV1);
}

test "multi-level authority cannot relabel its aggregation receipt as a proof" {
    try std.testing.expect(!ROOT_PROOF_AVAILABLE);
    try std.testing.expect(!PRODUCTION_ACTIVATION);
}
