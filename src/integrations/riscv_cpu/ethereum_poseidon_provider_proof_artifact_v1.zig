//! Append-only Stage-B proof artifact for the joint Poseidon provider split.
//!
//! The postcard proof remains a separate create-only regular file. This
//! canonical JSON receipt binds its exact file identity to one frozen public
//! `joint_proof` statement, the resource plan, and the Stage-A checkpoint.
//! Reopening derives the proof-preflight shape solely from that statement and
//! the verifier-selected recursive PCS suite before any proof allocation.
//!
//! No receipt in this module asserts successful verification. A final join
//! must decode and freshly verify every retained proof again before accepting
//! any `FreshProviderClaimV1` or closure.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const support = @import("ethereum_block_leaf_support.zig");

const joint_proof = frontend.testing.narrow_memory_provider_joint_proof;
const merkle_node = frontend.air.memory_commitment.merkle_node;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

const Engine = support.RecursiveEngine;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;

pub const schema = "stwo.ethereum.poseidon-provider-proof-artifact.v1";
pub const status = "proved-awaiting-fresh-verification";
pub const max_metadata_bytes: usize = 1024 * 1024;
pub const max_proof_bytes: usize = 256 * 1024 * 1024;
pub const composition_columns: u32 = 8;

pub const Role = enum {
    core,
    provider,

    pub fn text(self: Role) []const u8 {
        return switch (self) {
            .core => "core",
            .provider => "provider",
        };
    }

    pub fn parse(value: []const u8) !Role {
        if (std.mem.eql(u8, value, "core")) return .core;
        if (std.mem.eql(u8, value, "provider")) return .provider;
        return error.InvalidProviderProofRole;
    }
};

pub const CoreStatementWire = struct {
    call_list_commitment_sha256: []const u8,
    claims_m31: [merkle_node.N_SUMS][4]u32,
    core_stage_a_identity_sha256: []const u8,
    format: u32,
    geometry: joint_proof.CoreResidencyGeometryV1,
    identity_sha256: []const u8,
    manifest_identity_sha256: []const u8,
    plan_identity_sha256: []const u8,
    relation_context_identity_sha256: []const u8,

    fn validate(self: CoreStatementWire) !void {
        inline for (.{
            self.call_list_commitment_sha256,
            self.core_stage_a_identity_sha256,
            self.identity_sha256,
            self.manifest_identity_sha256,
            self.plan_identity_sha256,
            self.relation_context_identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        const canonical = try joint_proof.CoreResidencyGeometryV1.canonical(
            self.geometry.log_size,
            self.geometry.n_rows,
        );
        if (!std.meta.eql(canonical, self.geometry) or
            self.format != joint_proof.format_version)
        {
            return error.InvalidProviderProofStatement;
        }
        try validateClaimWords(&self.claims_m31);
    }
};

pub const ProviderStatementWire = struct {
    call_count: u32,
    claims_m31: [poseidon2_air.N_SUMS][4]u32,
    descriptor_identity_sha256: []const u8,
    first_call: u64,
    format: u32,
    identity_sha256: []const u8,
    log_size: u32,
    manifest_identity_sha256: []const u8,
    plan_identity_sha256: []const u8,
    relation_context_identity_sha256: []const u8,
    shard_index: u32,
    stage_a_identity_sha256: []const u8,

    fn validate(self: ProviderStatementWire) !void {
        inline for (.{
            self.descriptor_identity_sha256,
            self.identity_sha256,
            self.manifest_identity_sha256,
            self.plan_identity_sha256,
            self.relation_context_identity_sha256,
            self.stage_a_identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        if (self.format != joint_proof.format_version or
            self.call_count == 0 or self.log_size < 4 or self.log_size >= 30)
        {
            return error.InvalidProviderProofStatement;
        }
        const capacity = @as(u64, 1) << @intCast(self.log_size);
        if (self.call_count > capacity)
            return error.InvalidProviderProofStatement;
        try validateClaimWords(&self.claims_m31);
    }
};

pub const Artifact = struct {
    content_sha256: []const u8,
    core_statement: ?CoreStatementWire,
    producer_sha256: []const u8,
    production_eligible: bool,
    proof: contract.Identity,
    provider_statement: ?ProviderStatementWire,
    prove_timing: evidence.Timing,
    recursive_admissible: bool,
    resource_plan_identity_sha256: []const u8,
    role: []const u8,
    schema: []const u8,
    stage_a_checkpoint: contract.Identity,
    stage_a_checkpoint_content_sha256: []const u8,
    status: []const u8,

    pub fn validate(self: Artifact) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            self.production_eligible or self.recursive_admissible or
            self.prove_timing.wall_ns == 0)
        {
            return error.InvalidProviderProofArtifact;
        }
        const parsed_role = try Role.parse(self.role);
        switch (parsed_role) {
            .core => {
                if (self.core_statement == null or
                    self.provider_statement != null)
                {
                    return error.InvalidProviderProofArtifact;
                }
                try self.core_statement.?.validate();
            },
            .provider => {
                if (self.core_statement != null or
                    self.provider_statement == null)
                {
                    return error.InvalidProviderProofArtifact;
                }
                try self.provider_statement.?.validate();
            },
        }
        try self.proof.validate(false);
        try self.stage_a_checkpoint.validate(false);
        if (!std.fs.path.isAbsolute(self.proof.path) or
            !std.fs.path.isAbsolute(self.stage_a_checkpoint.path))
        {
            return error.InvalidProviderProofArtifact;
        }
        inline for (.{
            self.content_sha256,
            self.producer_sha256,
            self.resource_plan_identity_sha256,
            self.stage_a_checkpoint_content_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
    }
};

const CoreHexStorage = struct {
    call_list: [64]u8,
    core_stage_a: [64]u8,
    identity: [64]u8,
    manifest: [64]u8,
    plan: [64]u8,
    relation: [64]u8,
};

const ProviderHexStorage = struct {
    descriptor: [64]u8,
    identity: [64]u8,
    manifest: [64]u8,
    plan: [64]u8,
    relation: [64]u8,
    stage_a: [64]u8,
};

pub const CommonInput = struct {
    producer_sha256: [32]u8,
    proof: evidence.FileIdentity,
    prove_timing: evidence.Timing,
    resource_plan_identity: [32]u8,
    stage_a_checkpoint: evidence.FileIdentity,
    stage_a_checkpoint_content_sha256: [32]u8,
};

pub fn encodeCore(
    allocator: std.mem.Allocator,
    common: CommonInput,
    statement: joint_proof.CoreStatementV1,
) ![]u8 {
    const storage = CoreHexStorage{
        .call_list = hex(statement.call_list_commitment),
        .core_stage_a = hex(statement.core_stage_a_identity),
        .identity = hex(statement.identity),
        .manifest = hex(statement.manifest_identity),
        .plan = hex(statement.plan_identity),
        .relation = hex(statement.relation_context_identity),
    };
    return encodeInternal(allocator, common, .core, .{
        .call_list_commitment_sha256 = &storage.call_list,
        .claims_m31 = claimsWords(merkle_node.N_SUMS, statement.claims.sums),
        .core_stage_a_identity_sha256 = &storage.core_stage_a,
        .format = statement.format,
        .geometry = statement.geometry,
        .identity_sha256 = &storage.identity,
        .manifest_identity_sha256 = &storage.manifest,
        .plan_identity_sha256 = &storage.plan,
        .relation_context_identity_sha256 = &storage.relation,
    }, null);
}

pub fn encodeProvider(
    allocator: std.mem.Allocator,
    common: CommonInput,
    statement: joint_proof.ProviderStatementV1,
) ![]u8 {
    const storage = ProviderHexStorage{
        .descriptor = hex(statement.descriptor_identity),
        .identity = hex(statement.identity),
        .manifest = hex(statement.manifest_identity),
        .plan = hex(statement.plan_identity),
        .relation = hex(statement.relation_context_identity),
        .stage_a = hex(statement.stage_a_identity),
    };
    return encodeInternal(allocator, common, .provider, null, .{
        .call_count = statement.call_count,
        .claims_m31 = claimsWords(poseidon2_air.N_SUMS, statement.claims.sums),
        .descriptor_identity_sha256 = &storage.descriptor,
        .first_call = statement.first_call,
        .format = statement.format,
        .identity_sha256 = &storage.identity,
        .log_size = statement.log_size,
        .manifest_identity_sha256 = &storage.manifest,
        .plan_identity_sha256 = &storage.plan,
        .relation_context_identity_sha256 = &storage.relation,
        .shard_index = statement.shard_index,
        .stage_a_identity_sha256 = &storage.stage_a,
    });
}

fn encodeInternal(
    allocator: std.mem.Allocator,
    common: CommonInput,
    role: Role,
    core_statement: ?CoreStatementWire,
    provider_statement: ?ProviderStatementWire,
) ![]u8 {
    if (common.proof.bytes == 0 or common.proof.bytes > max_proof_bytes or
        common.prove_timing.wall_ns == 0)
    {
        return error.InvalidProviderProofArtifact;
    }
    const placeholder = [_]u8{'0'} ** 64;
    const producer = hex(common.producer_sha256);
    const resource_identity = hex(common.resource_plan_identity);
    const checkpoint_content = hex(common.stage_a_checkpoint_content_sha256);
    const proof_sha = hex(common.proof.sha256);
    const checkpoint_sha = hex(common.stage_a_checkpoint.sha256);
    const value = Artifact{
        .content_sha256 = &placeholder,
        .core_statement = core_statement,
        .producer_sha256 = &producer,
        .production_eligible = false,
        .proof = .{
            .bytes = common.proof.bytes,
            .path = common.proof.path,
            .sha256 = &proof_sha,
        },
        .provider_statement = provider_statement,
        .prove_timing = common.prove_timing,
        .recursive_admissible = false,
        .resource_plan_identity_sha256 = &resource_identity,
        .role = role.text(),
        .schema = schema,
        .stage_a_checkpoint = .{
            .bytes = common.stage_a_checkpoint.bytes,
            .path = common.stage_a_checkpoint.path,
            .sha256 = &checkpoint_sha,
        },
        .stage_a_checkpoint_content_sha256 = &checkpoint_content,
        .status = status,
    };
    const with_placeholder = try std.json.Stringify.valueAlloc(
        allocator,
        value,
        .{},
    );
    defer allocator.free(with_placeholder);
    const unsigned = try removeContentPlaceholder(allocator, with_placeholder);
    defer allocator.free(unsigned);
    const bytes = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    parsed.deinit();
    return bytes;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Artifact) {
    if (bytes.len == 0 or bytes.len > max_metadata_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Artifact, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(
        allocator,
        parsed.value,
        .{},
    );
    defer allocator.free(canonical);
    if (canonical.len + 1 != bytes.len or
        !std.mem.eql(u8, canonical, bytes[0..canonical.len]))
    {
        return error.InvalidCanonicalJson;
    }
    try parsed.value.validate();
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn publishCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}

pub fn serializeProofAlloc(
    allocator: std.mem.Allocator,
    proof: @import("stwo_core").proof.StarkProof(Engine.Hasher),
    shape: postcard.proof_preflight.Shape,
) ![]u8 {
    var output: std.ArrayList(u8) = .{};
    errdefer output.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        output.writer(allocator),
        proof,
    );
    if (output.items.len == 0 or output.items.len > max_proof_bytes)
        return error.ProviderProofResourceLimitExceeded;
    try postcard.proof_preflight.validate(output.items, shape);
    return output.toOwnedSlice(allocator);
}

pub fn deserializeProof(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    shape: postcard.proof_preflight.Shape,
) !@import("stwo_core").proof.StarkProof(Engine.Hasher) {
    try postcard.proof_preflight.validate(bytes, shape);
    var stream = std.io.fixedBufferStream(bytes);
    var proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        stream.reader(),
    );
    errdefer proof.deinit(allocator);
    if (stream.pos != bytes.len) return error.TrailingProofBytes;
    if (!std.meta.eql(
        proof.commitment_scheme_proof.config,
        support.recursive_pcs_config,
    )) return error.ProviderProofPcsConfigMismatch;
    return proof;
}

pub fn coreStatement(value: CoreStatementWire) !joint_proof.CoreStatementV1 {
    try value.validate();
    return .{
        .format = value.format,
        .plan_identity = try contract.parseSha256(value.plan_identity_sha256),
        .manifest_identity = try contract.parseSha256(
            value.manifest_identity_sha256,
        ),
        .core_stage_a_identity = try contract.parseSha256(
            value.core_stage_a_identity_sha256,
        ),
        .relation_context_identity = try contract.parseSha256(
            value.relation_context_identity_sha256,
        ),
        .call_list_commitment = try contract.parseSha256(
            value.call_list_commitment_sha256,
        ),
        .geometry = value.geometry,
        .claims = .{ .sums = claimValues(
            merkle_node.N_SUMS,
            value.claims_m31,
        ) },
        .identity = try contract.parseSha256(value.identity_sha256),
    };
}

pub fn providerStatement(
    value: ProviderStatementWire,
) !joint_proof.ProviderStatementV1 {
    try value.validate();
    return .{
        .format = value.format,
        .plan_identity = try contract.parseSha256(value.plan_identity_sha256),
        .manifest_identity = try contract.parseSha256(
            value.manifest_identity_sha256,
        ),
        .stage_a_identity = try contract.parseSha256(
            value.stage_a_identity_sha256,
        ),
        .descriptor_identity = try contract.parseSha256(
            value.descriptor_identity_sha256,
        ),
        .relation_context_identity = try contract.parseSha256(
            value.relation_context_identity_sha256,
        ),
        .shard_index = value.shard_index,
        .first_call = value.first_call,
        .call_count = value.call_count,
        .log_size = value.log_size,
        .claims = .{ .sums = claimValues(
            poseidon2_air.N_SUMS,
            value.claims_m31,
        ) },
        .identity = try contract.parseSha256(value.identity_sha256),
    };
}

pub fn coreProofShape(
    statement: joint_proof.CoreStatementV1,
) !postcard.proof_preflight.Shape {
    const expected = try joint_proof.CoreResidencyGeometryV1.canonical(
        statement.geometry.log_size,
        statement.geometry.n_rows,
    );
    if (!std.meta.eql(expected, statement.geometry))
        return error.InvalidProviderProofStatement;
    return proofShape(.{
        statement.geometry.tree0_columns,
        statement.geometry.tree1_columns,
        statement.geometry.tree2_columns,
        composition_columns,
    }, statement.geometry.composition_log_size -
        statement.geometry.composition_log_split);
}

pub fn providerProofShape(
    statement: joint_proof.ProviderStatementV1,
) !postcard.proof_preflight.Shape {
    if (statement.log_size < 4 or statement.log_size >= 30 or
        statement.call_count == 0 or
        statement.call_count > (@as(u32, 1) << @intCast(statement.log_size)))
    {
        return error.InvalidProviderProofStatement;
    }
    return proofShape(.{
        2,
        poseidon2_air.N_MAIN_COLUMNS,
        poseidon2_air.N_INTERACTION_COLUMNS,
        composition_columns,
    }, statement.log_size + 1);
}

fn proofShape(
    tree_columns: [4]u32,
    max_column_log_size: u32,
) !postcard.proof_preflight.Shape {
    if (@sizeOf(Engine.Hasher.Hash) != 32)
        return error.InvalidProviderProofHashWidth;
    const config = support.recursive_pcs_config;
    return .{
        .config = .{
            .pow_bits = config.pow_bits,
            .log_blowup_factor = config.fri_config.log_blowup_factor,
            .n_queries = config.fri_config.n_queries,
            .log_last_layer_degree_bound = config.fri_config.log_last_layer_degree_bound,
            .fold_step = config.fri_config.fold_step,
            .lifting_log_size = config.lifting_log_size,
        },
        .tree_columns = tree_columns,
        .max_column_log_size = max_column_log_size,
        .sample_width_limits = postcard.proof_preflight.DEFAULT_SAMPLE_WIDTH_LIMITS,
        .hash_size = @sizeOf(Engine.Hasher.Hash),
        .hash_encoding = .canonical_m31_words,
        .max_wire_bytes = max_proof_bytes,
    };
}

fn claimsWords(
    comptime count: usize,
    values: [count]QM31,
) [count][4]u32 {
    var result: [count][4]u32 = undefined;
    for (values, &result) |value, *destination| {
        for (value.toM31Array(), destination) |word, *coordinate|
            coordinate.* = word.toU32();
    }
    return result;
}

fn claimValues(
    comptime count: usize,
    values: [count][4]u32,
) [count]QM31 {
    var result: [count]QM31 = undefined;
    for (values, &result) |value, *destination|
        destination.* = QM31.fromU32Unchecked(
            value[0],
            value[1],
            value[2],
            value[3],
        );
    return result;
}

fn validateClaimWords(values: anytype) !void {
    for (values) |value|
        for (value) |word|
            if (word >= m31.Modulus)
                return error.NonCanonicalProviderProofClaim;
}

fn removeContentPlaceholder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderProofArtifact;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderProofArtifact;
    return std.fmt.allocPrint(allocator, "{{{s}", .{bytes[end + 2 ..]});
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try contract.parseSha256(expected);
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidContentSha256;
    const start = prefix.len;
    const end = start + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',' or
        !std.mem.eql(u8, bytes[start..end], expected))
    {
        return error.InvalidContentSha256;
    }
    const unsigned = try std.fmt.allocPrint(
        allocator,
        "{{{s}",
        .{bytes[end + 2 ..]},
    );
    defer allocator.free(unsigned);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(unsigned, &digest, .{});
    if (!std.mem.eql(u8, &hex(digest), expected))
        return error.InvalidContentSha256;
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

pub const testing = struct {
    pub fn statementRoundTrip(allocator: std.mem.Allocator) !void {
        const digest = [_]u8{0x51} ** 32;
        const core_value = joint_proof.CoreStatementV1{
            .format = joint_proof.format_version,
            .plan_identity = digest,
            .manifest_identity = digest,
            .core_stage_a_identity = digest,
            .relation_context_identity = digest,
            .call_list_commitment = digest,
            .geometry = try joint_proof.CoreResidencyGeometryV1.canonical(6, 41),
            .claims = .{ .sums = [_]QM31{
                QM31.fromU32Unchecked(1, 2, 3, 4),
                QM31.fromU32Unchecked(5, 6, 7, 8),
                QM31.fromU32Unchecked(9, 10, 11, 12),
            } },
            .identity = digest,
        };
        const common = CommonInput{
            .producer_sha256 = digest,
            .proof = .{
                .bytes = 19,
                .path = "/retained/core-proof.postcard",
                .sha256 = digest,
            },
            .prove_timing = .{ .wall_ns = 1, .user_ns = 0, .system_ns = 0 },
            .resource_plan_identity = digest,
            .stage_a_checkpoint = .{
                .bytes = 23,
                .path = "/retained/stage-a.json",
                .sha256 = digest,
            },
            .stage_a_checkpoint_content_sha256 = digest,
        };
        const core_bytes = try encodeCore(allocator, common, core_value);
        defer allocator.free(core_bytes);
        var parsed_core = try parse(allocator, core_bytes);
        defer parsed_core.deinit();
        const decoded_core = try coreStatement(parsed_core.value.core_statement.?);
        try std.testing.expect(std.meta.eql(core_value, decoded_core));
        const core_shape = try coreProofShape(decoded_core);
        try std.testing.expectEqual(
            [4]u32{ 2, 10, 12, 8 },
            core_shape.tree_columns,
        );
        try std.testing.expectEqual(@as(u32, 7), core_shape.max_column_log_size);

        const provider_value = joint_proof.ProviderStatementV1{
            .format = joint_proof.format_version,
            .plan_identity = digest,
            .manifest_identity = digest,
            .stage_a_identity = digest,
            .descriptor_identity = digest,
            .relation_context_identity = digest,
            .shard_index = 3,
            .first_call = 48,
            .call_count = 13,
            .log_size = 4,
            .claims = .{ .sums = [_]QM31{
                QM31.fromU32Unchecked(13, 14, 15, 16),
                QM31.fromU32Unchecked(17, 18, 19, 20),
            } },
            .identity = digest,
        };
        const provider_bytes = try encodeProvider(
            allocator,
            common,
            provider_value,
        );
        defer allocator.free(provider_bytes);
        var parsed_provider = try parse(allocator, provider_bytes);
        defer parsed_provider.deinit();
        const decoded_provider = try providerStatement(
            parsed_provider.value.provider_statement.?,
        );
        try std.testing.expect(std.meta.eql(provider_value, decoded_provider));
        const provider_shape = try providerProofShape(decoded_provider);
        try std.testing.expectEqual(
            [4]u32{ 2, 445, 8, 8 },
            provider_shape.tree_columns,
        );
        try std.testing.expectEqual(
            @as(u32, 5),
            provider_shape.max_column_log_size,
        );
    }
};
