//! Authenticated height-zero admission for recursive temporal leaves.
//!
//! A value is either an existing verifier-minted SegmentV2 admission or one
//! canonical proofless padding leaf derived from the same job/session/VK
//! authority. Proofless values are deliberately restricted to height zero;
//! higher empty spans must be produced by ordinary verified parent proofs.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const segment_child = @import("recursive_segment_v2_temporal_child_authority.zig");

const m31 = stwo_core.fields.m31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;
const temporal = recursion.temporal_pair_node;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const EMPTY_SCHEMA_VERSION: u16 = 1;
pub const PAIR_SCHEMA_VERSION: u16 = 1;
pub const HEIGHT_ZERO_ONLY = true;
pub const PROOFLESS_HIGHER_EMPTY_ACCEPTED = false;

const EMPTY_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-empty-leaf/v1\x00";
const LEAF_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-leaf-or-empty/v1\x00";
const PAIR_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-leaf-pair/v1\x00";

pub const Digest = channel.Digest;
pub const KindV1 = enum(u8) {
    segment = 0,
    empty = 1,
};

pub const Error = segment_child.Error || temporal.Error || span.Error || error{
    AdmissionIdentityMismatch,
    AliasedDestination,
    ChildAuthorityMismatch,
    DuplicateChild,
    EmptyIndexNotTrailing,
    InvalidLeafKind,
    ParentGeometryMismatch,
    UnsupportedFormat,
};

pub const PreparedEmptyLeafV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = EMPTY_SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    segment_leaf_vk_id: Digest,
    child: temporal.VerifiedChildV2,
    child_id: Digest,
    authority_sha_id: [32]u8,

    pub fn validate(self: *const PreparedEmptyLeafV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != EMPTY_SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.UnsupportedFormat;
        }
        try requireDigest(self.segment_leaf_vk_id);
        const statement = try self.child.statement();
        if (statement.slots.height != 0 or
            statement.slots.first < statement.job.segment_count or
            statement.slots.first >= statement.job.slotCapacity() or
            self.child.kind != .empty_leaf or
            self.child.scope != .protocol_padding or
            self.child.proof_present or self.child.roster_count != 0 or
            self.child.position != try temporal.positionForNextParent(statement))
        {
            return error.EmptyIndexNotTrailing;
        }
        switch (statement.body) {
            .empty => {},
            .executed => return error.InvalidLeafKind,
        }
        try requireDigest(self.child.session_id);
        try requireDigest(self.child.job_id);
        try requireDigest(self.child.recursive_parent_vk_id);
        if (!std.meta.eql(self.child.job_id, try temporal.jobId(&self.child.statement_words)) or
            !proofFieldsAreZero(&self.child) or
            !allZero(self.child.closure_value) or
            !std.meta.eql(self.child_id, try self.child.id()) or
            !std.mem.eql(
                u8,
                &self.authority_sha_id,
                &emptyAuthorityIdentity(self),
            ))
        {
            return error.ChildAuthorityMismatch;
        }
    }
};

const PayloadV1 = union(KindV1) {
    segment: segment_child.PreparedTemporalChildV1,
    empty: PreparedEmptyLeafV1,
};

/// Pointer-free, copy-safe height-zero authority consumed by topology and the
/// first parent layer. Its SHA identity binds the selected payload and the
/// payload's independently validated protocol identity.
pub const LeafOrEmptyV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    payload: PayloadV1,
    authority_sha_id: [32]u8,

    pub fn validate(self: *const LeafOrEmptyV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.UnsupportedFormat;
        }
        switch (self.payload) {
            .segment => |*value| try value.validate(),
            .empty => |*value| try value.validate(),
        }
        if (!std.mem.eql(
            u8,
            &self.authority_sha_id,
            &leafAuthorityIdentity(self),
        )) return error.AdmissionIdentityMismatch;
    }

    pub fn kind(self: *const LeafOrEmptyV1) KindV1 {
        return std.meta.activeTag(self.payload);
    }

    pub fn child(self: *const LeafOrEmptyV1) *const temporal.VerifiedChildV2 {
        return switch (self.payload) {
            .segment => |*value| &value.child,
            .empty => |*value| &value.child,
        };
    }

    pub fn statement(self: *const LeafOrEmptyV1) Error!span.SpanStatement {
        return self.child().statement();
    }

    pub fn segmentLeafVkId(self: *const LeafOrEmptyV1) Digest {
        return switch (self.payload) {
            .segment => |*value| value.child.verification_key_id,
            .empty => |*value| value.segment_leaf_vk_id,
        };
    }
};

pub fn admitSegmentInto(
    destination: *LeafOrEmptyV1,
    publication: *const segment_child.Publication,
) Error!void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(publication)))
        return error.AliasedDestination;
    var admitted: segment_child.PreparedTemporalChildV1 = undefined;
    try segment_child.admitInto(&admitted, publication);
    var staged = LeafOrEmptyV1{
        .payload = .{ .segment = admitted },
        .authority_sha_id = undefined,
    };
    staged.authority_sha_id = leafAuthorityIdentity(&staged);
    try staged.validate();
    destination.* = staged;
}

pub fn admitEmptyInto(
    destination: *LeafOrEmptyV1,
    job: span.JobContext,
    index: u32,
    session_id: Digest,
    segment_leaf_vk_id: Digest,
    recursive_parent_vk_id: Digest,
) Error!void {
    try job.validate();
    try requireDigest(session_id);
    try requireDigest(segment_leaf_vk_id);
    try requireDigest(recursive_parent_vk_id);
    if (index < job.segment_count or @as(u64, index) >= job.slotCapacity())
        return error.EmptyIndexNotTrailing;
    const statement = try span.SpanStatement.emptyLeaf(job, index);
    const words = try statement.canonicalWords();
    const zero = [_]u32{0} ** channel.RATE;
    var child = temporal.VerifiedChildV2{
        .position = try temporal.positionForNextParent(statement),
        .kind = .empty_leaf,
        .scope = .protocol_padding,
        .proof_present = false,
        .roster_count = 0,
        .session_id = session_id,
        .job_id = try temporal.jobId(&words),
        .recursive_parent_vk_id = recursive_parent_vk_id,
        .verification_key_id = zero,
        .air_program_id = zero,
        .manifest_id = zero,
        .profile_id = zero,
        .statement_words = words,
        .proof_id = zero,
        .transcript_id = zero,
        .capture_id = zero,
        .verifier_receipt_id = zero,
        .claimed_sums_id = zero,
        .relation_replay_id = zero,
        .auxiliary_claim_seal_id = zero,
        .closure_receipt_id = zero,
        .lineage_id = zero,
        .closure_value = .{ 0, 0, 0, 0 },
    };
    const child_id = try child.id();
    var empty = PreparedEmptyLeafV1{
        .segment_leaf_vk_id = segment_leaf_vk_id,
        .child = child,
        .child_id = child_id,
        .authority_sha_id = undefined,
    };
    empty.authority_sha_id = emptyAuthorityIdentity(&empty);
    var staged = LeafOrEmptyV1{
        .payload = .{ .empty = empty },
        .authority_sha_id = undefined,
    };
    staged.authority_sha_id = leafAuthorityIdentity(&staged);
    try staged.validate();
    destination.* = staged;
}

/// Authenticated first-layer fold over any two adjacent height-zero children.
/// The proofless variant remains confined to those children: the returned
/// parent is an authority for an ordinary proof-bearing height-one node.
pub const PreparedLeafPairV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = PAIR_SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    child_authority_sha_ids: [2][32]u8,
    prepared_root: temporal.PreparedRootContextV2,
    authority_sha_id: [32]u8,

    pub fn validate(self: *const PreparedLeafPairV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != PAIR_SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.UnsupportedFormat;
        }
        for (self.child_authority_sha_ids) |value|
            if (std.mem.allEqual(u8, &value, 0))
                return error.ChildAuthorityMismatch;
        const reconstructed = try temporal.prepareRootContext(
            &self.prepared_root.authority_snapshot,
            &self.prepared_root.pin_snapshot,
        );
        if (!std.meta.eql(reconstructed, self.prepared_root) or
            reconstructed.result.pair.parent_height != 1 or
            !std.mem.eql(
                u8,
                &self.authority_sha_id,
                &pairAuthorityIdentity(self),
            ))
        {
            return error.ChildAuthorityMismatch;
        }
    }

    pub fn validateAgainst(
        self: *const PreparedLeafPairV1,
        left: *const LeafOrEmptyV1,
        right: *const LeafOrEmptyV1,
    ) Error!void {
        try self.validate();
        try left.validate();
        try right.validate();
        if (!std.mem.eql(
            u8,
            &self.child_authority_sha_ids[0],
            &left.authority_sha_id,
        ) or !std.mem.eql(
            u8,
            &self.child_authority_sha_ids[1],
            &right.authority_sha_id,
        ) or !std.meta.eql(
            self.prepared_root.authority_snapshot.children[0],
            left.child().*,
        ) or !std.meta.eql(
            self.prepared_root.authority_snapshot.children[1],
            right.child().*,
        )) return error.ChildAuthorityMismatch;
    }
};

pub fn preparePairInto(
    destination: *PreparedLeafPairV1,
    left: *const LeafOrEmptyV1,
    right: *const LeafOrEmptyV1,
    root_pin: *const temporal.RootVkPinV2,
) Error!void {
    if (overlap(std.mem.asBytes(destination), std.mem.asBytes(left)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(right)) or
        overlap(std.mem.asBytes(destination), std.mem.asBytes(root_pin)))
    {
        return error.AliasedDestination;
    }
    try left.validate();
    try right.validate();
    try root_pin.validate();
    if (std.mem.eql(u8, &left.authority_sha_id, &right.authority_sha_id))
        return error.DuplicateChild;
    const left_statement = try left.statement();
    const right_statement = try right.statement();
    const parent = try span.SpanStatement.fold(left_statement, right_statement);
    if (parent.slots.height != 1 or
        !std.meta.eql(left_statement.job, right_statement.job) or
        !std.meta.eql(left.child().session_id, right.child().session_id) or
        !std.meta.eql(left.child().job_id, right.child().job_id) or
        !std.meta.eql(left.segmentLeafVkId(), right.segmentLeafVkId()) or
        !std.meta.eql(
            left.child().recursive_parent_vk_id,
            right.child().recursive_parent_vk_id,
        ))
    {
        return error.ParentGeometryMismatch;
    }
    const parent_words = try parent.canonicalWords();
    var statement_probe = std.mem.zeroes(temporal.VerifiedChildV2);
    statement_probe.statement_words = parent_words;
    const authority = temporal.VerifierAuthorityV2{
        .context = .{
            .session_id = left.child().session_id,
            .job_id = left.child().job_id,
            .segment_leaf_vk_id = left.segmentLeafVkId(),
            .aggregator_vk_id = left.child().recursive_parent_vk_id,
            .parent_node_index = parent.slots.nodeIndex(),
            .parent_height = 1,
            .expected_parent_statement_id = try statement_probe.statementId(),
        },
        .children = .{ left.child().*, right.child().* },
    };
    const prepared_root = try temporal.prepareRootContext(&authority, root_pin);
    var staged = PreparedLeafPairV1{
        .child_authority_sha_ids = .{
            left.authority_sha_id,
            right.authority_sha_id,
        },
        .prepared_root = prepared_root,
        .authority_sha_id = undefined,
    };
    staged.authority_sha_id = pairAuthorityIdentity(&staged);
    try staged.validateAgainst(left, right);
    destination.* = staged;
}

fn emptyAuthorityIdentity(value: *const PreparedEmptyLeafV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(EMPTY_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashDigest(&hash, value.segment_leaf_vk_id);
    hashDigest(&hash, value.child_id);
    hashDigest(&hash, value.child.session_id);
    hashDigest(&hash, value.child.job_id);
    hashDigest(&hash, value.child.recursive_parent_vk_id);
    return hash.finalResult();
}

fn leafAuthorityIdentity(value: *const LeafOrEmptyV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LEAF_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromEnum(value.kind()));
    switch (value.payload) {
        .segment => |*child| {
            hashDigest(&hash, child.child_id);
            hashDigest(&hash, child.admission_id);
            hashDigest(&hash, child.source_publication_id);
        },
        .empty => |*child| {
            hashDigest(&hash, child.child_id);
            hash.update(&child.authority_sha_id);
        },
    }
    return hash.finalResult();
}

fn pairAuthorityIdentity(value: *const PreparedLeafPairV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PAIR_AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.child_authority_sha_ids[0]);
    hash.update(&value.child_authority_sha_ids[1]);
    hashDigest(&hash, value.prepared_root.result.pair.context_id);
    hashDigest(&hash, value.prepared_root.result.pair.node_id);
    hashDigest(&hash, value.prepared_root.result.pair.record_id);
    return hash.finalResult();
}

fn requireDigest(value: Digest) Error!void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= m31.Modulus) return error.ChildAuthorityMismatch;
        aggregate |= word;
    }
    if (aggregate == 0) return error.ChildAuthorityMismatch;
}

fn hashDigest(hash: *Sha256, value: Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn allZero(values: anytype) bool {
    for (values) |value| if (value != 0) return false;
    return true;
}

fn proofFieldsAreZero(child: *const temporal.VerifiedChildV2) bool {
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
    }) |digest| if (!allZero(digest)) return false;
    return true;
}

fn overlap(left: []const u8, right: []const u8) bool {
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len;
    const right_end = right_start + right.len;
    return left_start < right_end and right_start < left_end;
}
