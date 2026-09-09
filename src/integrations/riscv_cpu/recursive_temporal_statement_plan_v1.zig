//! Pointer-free SSOT for the exact 210-leaf recursive statement plan.
//!
//! The controller may serialize this value, but never recreates a statement
//! hash. Zig validates ordered global metadata, derives the 46 canonical
//! trailing empties, folds all 255 parents breadth-first, and binds each node
//! to its exact current/next VK and transcript/profile authority.
//!
//! This pre-proof plan never predicts a verifier-minted publication identity.
//! Real leaves bind their materialized STWESG31 source bytes and MetadataV3
//! identity. Post-proof publication admission is a separate authority layer.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const profile_mod = @import("recursive_temporal_node_profile_v1.zig");
const topology_mod = @import("recursive_temporal_topology_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const global_v3 = recursion.segment_leaf_local_authority_v3;
const span = recursion.span_statement;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const REAL_LEAF_COUNT: usize = 210;
pub const PADDED_LEAF_COUNT: usize = 256;
pub const EMPTY_LEAF_COUNT: usize = PADDED_LEAF_COUNT - REAL_LEAF_COUNT;
pub const PARENT_COUNT: usize = PADDED_LEAF_COUNT - 1;
pub const NODE_COUNT: usize = PADDED_LEAF_COUNT + PARENT_COUNT;
pub const ROOT_HEIGHT: u8 = 8;
pub const UPPER_PROFILE_COUNT: usize = ROOT_HEIGHT - 1;
const PLAN_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-statement-plan/v1\x00";
const LEAF_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-statement-leaf/v1\x00";
const PARENT_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-statement-parent/v1\x00";
const STATEMENT_SHA_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-span-statement/v1\x00";
const EMPTY_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-empty-authority/v1\x00";

pub const Digest = channel.Digest;

pub const ExpectedRealLeafV1 = struct {
    metadata: global_v3.MetadataV3,
    metadata_id: Digest,
    source_sha_id: [32]u8,

    pub fn validate(self: *const ExpectedRealLeafV1) !void {
        try self.metadata.validate();
        if (!std.meta.eql(self.metadata_id, try self.metadata.identity()))
            return error.MetadataIdentityMismatch;
        if (std.mem.allEqual(u8, &self.source_sha_id, 0))
            return error.InvalidSourceAuthority;
    }
};

pub const EmptyAuthorityV1 = struct {
    session_id: Digest,
    segment_leaf_vk_id: Digest,
    authority_sha_id: [32]u8,

    pub fn init(
        session_id: Digest,
        segment_leaf_vk_id: Digest,
    ) !EmptyAuthorityV1 {
        var result = EmptyAuthorityV1{
            .session_id = session_id,
            .segment_leaf_vk_id = segment_leaf_vk_id,
            .authority_sha_id = undefined,
        };
        result.authority_sha_id = emptyAuthorityIdentity(result);
        try result.validate();
        return result;
    }

    pub fn validate(self: EmptyAuthorityV1) !void {
        try requireDigest(self.session_id);
        try requireDigest(self.segment_leaf_vk_id);
        if (!std.mem.eql(
            u8,
            &self.authority_sha_id,
            &emptyAuthorityIdentity(self),
        ))
            return error.InvalidEmptyAuthority;
    }
};

pub const ProfilePlanV1 = struct {
    real_h1: profile_mod.NodeProfileV1,
    empty_h1: profile_mod.NodeProfileV1,
    upper: [UPPER_PROFILE_COUNT]profile_mod.NodeProfileV1,

    pub fn validate(self: *const ProfilePlanV1) !void {
        try self.real_h1.validate();
        try self.empty_h1.validate();
        if (self.real_h1.kind != .real_parent_h1 or
            self.empty_h1.kind != .empty_parent_h1)
        {
            return error.InvalidProfilePlan;
        }
        for (&self.upper, 0..) |*profile, index| {
            try profile.validate();
            if (profile.kind != .recursive_parent or
                profile.parent_height != @as(u8, @intCast(index + 2)))
            {
                return error.InvalidProfilePlan;
            }
        }
        if (!std.meta.eql(
            self.real_h1.next_parent_vk_id,
            self.upper[0].verification_key_id,
        ) or !std.meta.eql(
            self.empty_h1.next_parent_vk_id,
            self.upper[0].verification_key_id,
        ) or !std.meta.eql(
            self.real_h1.parent_proof_security,
            self.upper[0].admitted_child_security,
        ) or !std.meta.eql(
            self.empty_h1.parent_proof_security,
            self.upper[0].admitted_child_security,
        )) return error.InvalidProfilePlan;
        for (self.upper[0 .. self.upper.len - 1], self.upper[1..]) |current, next|
            if (!std.meta.eql(
                current.next_parent_vk_id,
                next.verification_key_id,
            ) or !std.meta.eql(
                current.parent_proof_security,
                next.admitted_child_security,
            )) return error.InvalidProfilePlan;
    }

    /// Production plan admission is deliberately stronger than structural
    /// materialization. Functional profiles remain useful for focused proof
    /// tests, but can never authorize the 210-leaf product route.
    pub fn requireProductionSecurity(self: *const ProfilePlanV1) !void {
        try self.validate();
        try self.real_h1.requireProductionSecurity();
        try self.empty_h1.requireProductionSecurity();
        for (&self.upper) |*profile| try profile.requireProductionSecurity();
    }

    pub fn forNode(
        self: *const ProfilePlanV1,
        height: u8,
        kind: topology_mod.NodeKindV1,
    ) !*const profile_mod.NodeProfileV1 {
        try self.validate();
        if (height == 1) return switch (kind) {
            .real => &self.real_h1,
            .empty => &self.empty_h1,
            .mixed => error.InvalidProfilePlan,
        };
        if (height < 2 or height > ROOT_HEIGHT)
            return error.InvalidProfilePlan;
        return &self.upper[height - 2];
    }
};

pub const LeafRecordV1 = struct {
    index: u32,
    kind: topology_mod.NodeKindV1,
    metadata_id: Digest,
    source_sha_id: [32]u8,
    statement_words: span.StatementWords,
    statement_id: Digest,
    statement_sha_id: [32]u8,
    source_public_statement_sha_id: [32]u8,
    next_parent_vk_id: Digest,
    identity: [32]u8,

    pub fn validate(self: *const LeafRecordV1) !void {
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        );
        if (statement.slots.height != 0 or statement.slots.first != self.index or
            !std.meta.eql(self.statement_id, statementId(&self.statement_words)) or
            !std.mem.eql(
                u8,
                &self.statement_sha_id,
                &statementSha256(&self.statement_words),
            ) or
            !std.mem.eql(u8, &self.identity, &leafIdentity(self)))
        {
            return error.InvalidStatementPlan;
        }
        try requireDigest(self.next_parent_vk_id);
        switch (self.kind) {
            .real => {
                try requireDigest(self.metadata_id);
                if (std.mem.allEqual(u8, &self.source_sha_id, 0))
                    return error.InvalidStatementPlan;
                if (std.mem.allEqual(
                    u8,
                    &self.source_public_statement_sha_id,
                    0,
                )) return error.InvalidStatementPlan;
                switch (statement.body) {
                    .executed => {},
                    .empty => return error.InvalidStatementPlan,
                }
            },
            .empty => {
                if (!digestIsZero(self.metadata_id) or
                    !std.mem.allEqual(u8, &self.source_sha_id, 0) or
                    !std.mem.allEqual(
                        u8,
                        &self.source_public_statement_sha_id,
                        0,
                    ))
                {
                    return error.InvalidStatementPlan;
                }
                switch (statement.body) {
                    .empty => {},
                    .executed => return error.InvalidStatementPlan,
                }
            },
            .mixed => return error.InvalidStatementPlan,
        }
    }
};

pub const ParentRecordV1 = struct {
    ordinal: u32,
    height: u8,
    kind: topology_mod.NodeKindV1,
    padding: [2]u8 = .{ 0, 0 },
    index: u32,
    left_statement_id: Digest,
    right_statement_id: Digest,
    statement_words: span.StatementWords,
    statement_id: Digest,
    statement_sha_id: [32]u8,
    profile_sha_id: [32]u8,
    verification_key_id: Digest,
    next_parent_vk_id: Digest,
    transcript: @import("recursive_temporal_child_transcript_authority_v1.zig").DescriptorV1,
    identity: [32]u8,

    pub fn validate(self: *const ParentRecordV1) !void {
        if (self.height == 0 or self.height > ROOT_HEIGHT or
            !std.mem.allEqual(u8, &self.padding, 0) or
            std.mem.allEqual(u8, &self.profile_sha_id, 0))
        {
            return error.InvalidStatementPlan;
        }
        const statement = try span.SpanStatement.fromCanonicalWords(
            &self.statement_words,
        );
        if (statement.slots.height != self.height or
            statement.slots.nodeIndex() != self.index or
            !std.meta.eql(self.statement_id, statementId(&self.statement_words)) or
            !std.mem.eql(
                u8,
                &self.statement_sha_id,
                &statementSha256(&self.statement_words),
            ) or
            !std.mem.eql(u8, &self.identity, &parentIdentity(self)))
        {
            return error.InvalidStatementPlan;
        }
        try requireDigest(self.left_statement_id);
        try requireDigest(self.right_statement_id);
        try requireDigest(self.verification_key_id);
        try requireDigest(self.next_parent_vk_id);
        try self.transcript.validateForChildHeight(self.height);
    }
};

pub const MaterializedPlanV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    topology: topology_mod.TopologyPlanV1,
    empty_authority: EmptyAuthorityV1,
    profiles: ProfilePlanV1,
    leaves: [PADDED_LEAF_COUNT]LeafRecordV1,
    parents: [PARENT_COUNT]ParentRecordV1,
    root_statement_id: Digest,
    root_statement_sha_id: [32]u8,
    root_profile_sha_id: [32]u8,
    identity: [32]u8,

    pub fn validate(self: *const MaterializedPlanV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.InvalidStatementPlan;
        }
        try self.topology.validate();
        try self.empty_authority.validate();
        try self.profiles.validate();
        for (&self.leaves) |*leaf| try leaf.validate();
        for (&self.parents) |*parent| try parent.validate();
        const root = &self.parents[PARENT_COUNT - 1];
        if (root.height != ROOT_HEIGHT or root.index != 0 or
            !std.meta.eql(self.root_statement_id, root.statement_id) or
            !std.mem.eql(
                u8,
                &self.root_statement_sha_id,
                &root.statement_sha_id,
            ) or
            !std.mem.eql(u8, &self.root_profile_sha_id, &root.profile_sha_id) or
            !std.mem.eql(u8, &self.identity, &planIdentity(self)))
        {
            return error.InvalidStatementPlan;
        }
    }

    /// Reopens the deterministic source-side authority. `validate()` alone
    /// proves the plan is internally sealed, but cannot prove that a retained
    /// metadata identity still corresponds to the caller's STWESG31 bytes.
    pub fn validateAgainst(
        self: *const MaterializedPlanV1,
        real: *const [REAL_LEAF_COUNT]ExpectedRealLeafV1,
    ) !void {
        try self.validate();
        for (real, 0..) |*input, index| {
            try input.validate();
            const leaf = &self.leaves[index];
            if (leaf.kind != .real or
                !std.meta.eql(leaf.metadata_id, input.metadata_id) or
                !std.mem.eql(u8, &leaf.source_sha_id, &input.source_sha_id) or
                !std.meta.eql(
                    leaf.statement_words,
                    input.metadata.base_statement_words,
                ) or !std.meta.eql(
                leaf.statement_id,
                statementId(&input.metadata.base_statement_words),
            ) or !std.mem.eql(
                u8,
                &leaf.source_public_statement_sha_id,
                &try ethereumPublicStatementSha256(&input.metadata),
            )) return error.SourceAuthorityMismatch;
        }
    }
};

/// Fail-atomic exact campaign materializer. The caller-visible destination is
/// written only after all 511 statements and every profile edge validate.
pub fn materialize210Into(
    destination: *MaterializedPlanV1,
    real: *const [REAL_LEAF_COUNT]ExpectedRealLeafV1,
    empty_authority: EmptyAuthorityV1,
    profiles: ProfilePlanV1,
) !void {
    for (real) |*leaf| try leaf.validate();
    try empty_authority.validate();
    try profiles.validate();
    for (real[0 .. real.len - 1], real[1..]) |*left, *right|
        try global_v3.requireAdjacentMetadata(&left.metadata, &right.metadata);
    const first_statement = try span.SpanStatement.fromCanonicalWords(
        &real[0].metadata.base_statement_words,
    );
    const topology = try topology_mod.TopologyPlanV1.init(first_statement.job);
    if (topology.real_leaf_count != REAL_LEAF_COUNT or
        topology.padded_leaf_count != PADDED_LEAF_COUNT or
        topology.root_height != ROOT_HEIGHT)
    {
        return error.InvalidStatementPlan;
    }

    var staged: MaterializedPlanV1 = undefined;
    staged.format_version = FORMAT_VERSION;
    staged.schema_version = SCHEMA_VERSION;
    staged.padding = .{ 0, 0, 0, 0 };
    staged.topology = topology;
    staged.empty_authority = empty_authority;
    staged.profiles = profiles;
    for (real, 0..) |*input, index| {
        var record = LeafRecordV1{
            .index = @intCast(index),
            .kind = .real,
            .metadata_id = input.metadata_id,
            .source_sha_id = input.source_sha_id,
            .statement_words = input.metadata.base_statement_words,
            .statement_id = statementId(&input.metadata.base_statement_words),
            .statement_sha_id = statementSha256(
                &input.metadata.base_statement_words,
            ),
            .source_public_statement_sha_id = try ethereumPublicStatementSha256(&input.metadata),
            .next_parent_vk_id = profiles.real_h1.verification_key_id,
            .identity = undefined,
        };
        record.identity = leafIdentity(&record);
        try record.validate();
        staged.leaves[index] = record;
    }
    for (REAL_LEAF_COUNT..PADDED_LEAF_COUNT) |index| {
        const statement = try span.SpanStatement.emptyLeaf(
            first_statement.job,
            @intCast(index),
        );
        const words = try statement.canonicalWords();
        var record = LeafRecordV1{
            .index = @intCast(index),
            .kind = .empty,
            .metadata_id = [_]u32{0} ** channel.RATE,
            .source_sha_id = [_]u8{0} ** 32,
            .statement_words = words,
            .statement_id = statementId(&words),
            .statement_sha_id = statementSha256(&words),
            .source_public_statement_sha_id = [_]u8{0} ** 32,
            .next_parent_vk_id = profiles.empty_h1.verification_key_id,
            .identity = undefined,
        };
        record.identity = leafIdentity(&record);
        try record.validate();
        staged.leaves[index] = record;
    }

    var ordinal: usize = 0;
    var height: u8 = 1;
    while (height <= ROOT_HEIGHT) : (height += 1) {
        const count: usize = @intCast(try topology.nodeCount(height));
        for (0..count) |index| {
            const left_words = childWords(&staged, height, 2 * index);
            const right_words = childWords(&staged, height, 2 * index + 1);
            const parent = try span.SpanStatement.fold(
                try span.SpanStatement.fromCanonicalWords(left_words),
                try span.SpanStatement.fromCanonicalWords(right_words),
            );
            const words = try parent.canonicalWords();
            const kind = try topology.nodeKind(height, @intCast(index));
            const profile = try profiles.forNode(height, kind);
            var record = ParentRecordV1{
                .ordinal = @intCast(ordinal),
                .height = height,
                .kind = kind,
                .index = @intCast(index),
                .left_statement_id = statementId(left_words),
                .right_statement_id = statementId(right_words),
                .statement_words = words,
                .statement_id = statementId(&words),
                .statement_sha_id = statementSha256(&words),
                .profile_sha_id = profile.identity,
                .verification_key_id = profile.verification_key_id,
                .next_parent_vk_id = profile.next_parent_vk_id,
                .transcript = profile.transcript,
                .identity = undefined,
            };
            record.identity = parentIdentity(&record);
            try record.validate();
            staged.parents[ordinal] = record;
            ordinal += 1;
        }
    }
    if (ordinal != PARENT_COUNT) return error.InvalidStatementPlan;
    staged.root_statement_id = staged.parents[PARENT_COUNT - 1].statement_id;
    staged.root_statement_sha_id =
        staged.parents[PARENT_COUNT - 1].statement_sha_id;
    staged.root_profile_sha_id = staged.parents[PARENT_COUNT - 1].profile_sha_id;
    staged.identity = planIdentity(&staged);
    try staged.validateAgainst(real);
    destination.* = staged;
}

fn childWords(
    plan: *const MaterializedPlanV1,
    parent_height: u8,
    child_index: usize,
) *const span.StatementWords {
    if (parent_height == 1) return &plan.leaves[child_index].statement_words;
    const offset = levelOffset(parent_height - 1);
    return &plan.parents[offset + child_index].statement_words;
}

fn levelOffset(height: u8) usize {
    std.debug.assert(height >= 1 and height <= ROOT_HEIGHT);
    var result: usize = 0;
    var level: u8 = 1;
    while (level < height) : (level += 1)
        result += PADDED_LEAF_COUNT >> @as(u6, @intCast(level));
    return result;
}

fn statementId(words: *const span.StatementWords) Digest {
    var canonical: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return recursion.protocol.statementId(&canonical);
}

/// Transport-safe SHA authority shared by the native parent producer,
/// independent verifier, and controller. The preimage is exactly the
/// canonical M31 statement words encoded as little-endian `u32`s.
pub fn statementSha256(words: *const span.StatementWords) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(STATEMENT_SHA_DOMAIN);
    for (words) |word| hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn ethereumPublicStatementSha256(
    metadata: *const global_v3.MetadataV3,
) ![32]u8 {
    return frontend.prover_mod.guest_precompile.ethereum_segment_source_wire
        .publicStatementSha256(metadata);
}

fn emptyAuthorityIdentity(value: EmptyAuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(EMPTY_AUTHORITY_DOMAIN);
    hashDigest(&hash, value.session_id);
    hashDigest(&hash, value.segment_leaf_vk_id);
    return hash.finalResult();
}

fn leafIdentity(value: *const LeafRecordV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(LEAF_DOMAIN);
    hashInt(&hash, u32, value.index);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashDigest(&hash, value.metadata_id);
    hash.update(&value.source_sha_id);
    hashDigest(&hash, value.statement_id);
    hash.update(&value.statement_sha_id);
    hash.update(&value.source_public_statement_sha_id);
    hashDigest(&hash, value.next_parent_vk_id);
    return hash.finalResult();
}

fn parentIdentity(value: *const ParentRecordV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PARENT_DOMAIN);
    hashInt(&hash, u32, value.ordinal);
    hashInt(&hash, u8, value.height);
    hashInt(&hash, u8, @intFromEnum(value.kind));
    hashInt(&hash, u32, value.index);
    hashDigest(&hash, value.left_statement_id);
    hashDigest(&hash, value.right_statement_id);
    hashDigest(&hash, value.statement_id);
    hash.update(&value.statement_sha_id);
    hash.update(&value.profile_sha_id);
    hashDigest(&hash, value.verification_key_id);
    hashDigest(&hash, value.next_parent_vk_id);
    hashInt(&hash, u8, @intFromEnum(value.transcript.kind));
    return hash.finalResult();
}

fn planIdentity(value: *const MaterializedPlanV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(PLAN_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.topology.identity);
    hash.update(&value.empty_authority.authority_sha_id);
    for (value.leaves) |leaf| hash.update(&leaf.identity);
    for (value.parents) |parent| hash.update(&parent.identity);
    hashDigest(&hash, value.root_statement_id);
    hash.update(&value.root_statement_sha_id);
    hash.update(&value.root_profile_sha_id);
    return hash.finalResult();
}

fn requireDigest(value: Digest) !void {
    if (digestIsZero(value)) return error.InvalidStatementPlan;
    for (value) |word| if (word >= @import("stwo_core").fields.m31.Modulus)
        return error.InvalidStatementPlan;
}

fn digestIsZero(value: Digest) bool {
    for (value) |word| if (word != 0) return false;
    return true;
}

fn hashDigest(hash: *Sha256, value: Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (REAL_LEAF_COUNT != 210 or PADDED_LEAF_COUNT != 256 or
        EMPTY_LEAF_COUNT != 46 or PARENT_COUNT != 255 or NODE_COUNT != 511 or
        ROOT_HEIGHT != 8 or UPPER_PROFILE_COUNT != 7)
    {
        @compileError("temporal statement campaign geometry drifted");
    }
}
