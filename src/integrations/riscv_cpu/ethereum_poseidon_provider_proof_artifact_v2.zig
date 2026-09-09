//! Additive provider-V2 proof artifact with proof-bound ordered-call custody.
//!
//! V1 metadata remains byte/API stable. This V2 schema binds the 12-column
//! Tree2 geometry, global ordered-call commitment, exact shard range, and the
//! verifier-recomputed rolling endpoint used by `ProviderStatementV2`.

const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const proof_v1 = @import("ethereum_poseidon_provider_proof_artifact_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const provider_v2 = frontend.testing.narrow_memory_provider_joint_proof_v2;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;
const QM31 = core.fields.qm31.QM31;
const m31 = core.fields.m31;
const Engine = support.RecursiveEngine;

pub const schema = "stwo.ethereum.poseidon-provider-proof-artifact.v2";
pub const status = "proved-awaiting-fresh-verification";
pub const tree2_columns: u32 = 12;
pub const composition_columns: u32 = 8;

pub const OrderedCallClaimWire = struct {
    call_count: u32,
    first_call: u64,
    format: u32,
    terminal_m31: [4]u32,

    fn validate(self: OrderedCallClaimWire) !void {
        if (self.format == 0 or self.call_count == 0)
            return error.InvalidProviderV2Statement;
        try validateWords(&self.terminal_m31);
    }
};

pub const StatementWire = struct {
    call_count: u32,
    call_list_commitment_sha256: []const u8,
    claims_m31: [poseidon2_air.N_SUMS][4]u32,
    descriptor_identity_sha256: []const u8,
    first_call: u64,
    format: u32,
    identity_sha256: []const u8,
    log_size: u32,
    manifest_identity_sha256: []const u8,
    ordered_call_claim: OrderedCallClaimWire,
    plan_identity_sha256: []const u8,
    relation_context_identity_sha256: []const u8,
    shard_index: u32,
    stage_a_identity_sha256: []const u8,
    tree2_geometry: provider_v2.ProviderTree2GeometryV2,

    fn validate(self: StatementWire) !void {
        inline for (.{
            self.call_list_commitment_sha256,
            self.descriptor_identity_sha256,
            self.identity_sha256,
            self.manifest_identity_sha256,
            self.plan_identity_sha256,
            self.relation_context_identity_sha256,
            self.stage_a_identity_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        if (self.format != provider_v2.format_version or
            self.call_count == 0 or self.log_size < 4 or self.log_size >= 30 or
            self.call_count > (@as(u32, 1) << @intCast(self.log_size)) or
            self.ordered_call_claim.first_call != self.first_call or
            self.ordered_call_claim.call_count != self.call_count or
            !std.meta.eql(
                self.tree2_geometry,
                try provider_v2.ProviderTree2GeometryV2.canonical(
                    self.log_size,
                ),
            ) or self.tree2_geometry.total_columns != tree2_columns)
        {
            return error.InvalidProviderV2Statement;
        }
        try self.ordered_call_claim.validate();
        try validateWords(&self.claims_m31);
    }
};

pub const Artifact = struct {
    content_sha256: []const u8,
    producer_sha256: []const u8,
    production_eligible: bool,
    proof: contract.Identity,
    prove_timing: evidence.Timing,
    recursive_admissible: bool,
    resource_plan_identity_sha256: []const u8,
    schema: []const u8,
    stage_a_checkpoint: contract.Identity,
    stage_a_checkpoint_content_sha256: []const u8,
    statement: StatementWire,
    status: []const u8,

    pub fn validate(self: Artifact) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            self.production_eligible or self.recursive_admissible or
            self.prove_timing.wall_ns == 0)
        {
            return error.InvalidProviderV2ProofArtifact;
        }
        try self.proof.validate(false);
        try self.stage_a_checkpoint.validate(false);
        if (!std.fs.path.isAbsolute(self.proof.path) or
            !std.fs.path.isAbsolute(self.stage_a_checkpoint.path))
        {
            return error.InvalidProviderV2ProofArtifact;
        }
        inline for (.{
            self.content_sha256,
            self.producer_sha256,
            self.resource_plan_identity_sha256,
            self.stage_a_checkpoint_content_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        try self.statement.validate();
    }
};

pub const CommonInput = proof_v1.CommonInput;

const HexStorage = struct {
    call_list: [64]u8,
    descriptor: [64]u8,
    identity: [64]u8,
    manifest: [64]u8,
    plan: [64]u8,
    relation: [64]u8,
    stage_a: [64]u8,
};

pub fn encode(
    allocator: std.mem.Allocator,
    common: CommonInput,
    value: provider_v2.ProviderStatementV2,
) ![]u8 {
    if (common.proof.bytes == 0 or
        common.proof.bytes > proof_v1.max_proof_bytes or
        common.prove_timing.wall_ns == 0)
    {
        return error.InvalidProviderV2ProofArtifact;
    }
    const storage = HexStorage{
        .call_list = hex(value.call_list_commitment),
        .descriptor = hex(value.descriptor_identity),
        .identity = hex(value.identity),
        .manifest = hex(value.manifest_identity),
        .plan = hex(value.plan_identity),
        .relation = hex(value.relation_context_identity),
        .stage_a = hex(value.stage_a_identity),
    };
    const placeholder = [_]u8{'0'} ** 64;
    const producer = hex(common.producer_sha256);
    const proof_sha = hex(common.proof.sha256);
    const resource_identity = hex(common.resource_plan_identity);
    const checkpoint_sha = hex(common.stage_a_checkpoint.sha256);
    const checkpoint_content = hex(common.stage_a_checkpoint_content_sha256);
    const artifact = Artifact{
        .content_sha256 = &placeholder,
        .producer_sha256 = &producer,
        .production_eligible = false,
        .proof = .{
            .bytes = common.proof.bytes,
            .path = common.proof.path,
            .sha256 = &proof_sha,
        },
        .prove_timing = common.prove_timing,
        .recursive_admissible = false,
        .resource_plan_identity_sha256 = &resource_identity,
        .schema = schema,
        .stage_a_checkpoint = .{
            .bytes = common.stage_a_checkpoint.bytes,
            .path = common.stage_a_checkpoint.path,
            .sha256 = &checkpoint_sha,
        },
        .stage_a_checkpoint_content_sha256 = &checkpoint_content,
        .statement = .{
            .call_count = value.call_count,
            .call_list_commitment_sha256 = &storage.call_list,
            .claims_m31 = qm31ArrayWords(
                poseidon2_air.N_SUMS,
                value.claims.sums,
            ),
            .descriptor_identity_sha256 = &storage.descriptor,
            .first_call = value.first_call,
            .format = value.format,
            .identity_sha256 = &storage.identity,
            .log_size = value.log_size,
            .manifest_identity_sha256 = &storage.manifest,
            .ordered_call_claim = .{
                .call_count = value.ordered_call_claim.call_count,
                .first_call = value.ordered_call_claim.first_call,
                .format = value.ordered_call_claim.format,
                .terminal_m31 = qm31Words(value.ordered_call_claim.terminal),
            },
            .plan_identity_sha256 = &storage.plan,
            .relation_context_identity_sha256 = &storage.relation,
            .shard_index = value.shard_index,
            .stage_a_identity_sha256 = &storage.stage_a,
            .tree2_geometry = value.tree2_geometry,
        },
        .status = status,
    };
    const with_placeholder = try std.json.Stringify.valueAlloc(
        allocator,
        artifact,
        .{},
    );
    defer allocator.free(with_placeholder);
    const unsigned = try removeContentPlaceholder(allocator, with_placeholder);
    defer allocator.free(unsigned);
    const bytes = try evidence.seal(allocator, unsigned);
    errdefer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    defer parsed.deinit();
    _ = try statement(parsed.value.statement);
    return bytes;
}

pub fn parse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) !std.json.Parsed(Artifact) {
    if (bytes.len == 0 or bytes.len > proof_v1.max_metadata_bytes or
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
    _ = try statement(parsed.value.statement);
    try validateContentSha256(allocator, bytes, parsed.value.content_sha256);
    return parsed;
}

pub fn publishCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}

pub fn statement(
    value: StatementWire,
) !provider_v2.ProviderStatementV2 {
    try value.validate();
    const result = provider_v2.ProviderStatementV2{
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
        .call_list_commitment = try contract.parseSha256(
            value.call_list_commitment_sha256,
        ),
        .shard_index = value.shard_index,
        .first_call = value.first_call,
        .call_count = value.call_count,
        .log_size = value.log_size,
        .tree2_geometry = value.tree2_geometry,
        .claims = .{ .sums = qm31Array(
            poseidon2_air.N_SUMS,
            value.claims_m31,
        ) },
        .ordered_call_claim = .{
            .format = value.ordered_call_claim.format,
            .first_call = value.ordered_call_claim.first_call,
            .call_count = value.ordered_call_claim.call_count,
            .terminal = qm31(value.ordered_call_claim.terminal_m31),
        },
        .identity = try contract.parseSha256(value.identity_sha256),
    };
    if (!std.meta.eql(result.identity, provider_v2.providerStatementIdentity(result)))
        return error.InvalidProviderV2StatementIdentity;
    return result;
}

pub fn proofShape(
    value: provider_v2.ProviderStatementV2,
) !postcard.proof_preflight.Shape {
    if (!std.meta.eql(
        value.tree2_geometry,
        try provider_v2.ProviderTree2GeometryV2.canonical(value.log_size),
    ) or value.tree2_geometry.total_columns != tree2_columns or
        @sizeOf(Engine.Hasher.Hash) != 32)
    {
        return error.InvalidProviderV2ProofShape;
    }
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
        .tree_columns = .{
            2,
            poseidon2_air.N_MAIN_COLUMNS,
            tree2_columns,
            composition_columns,
        },
        .max_column_log_size = value.tree2_geometry.composition_log_size -
            value.tree2_geometry.composition_log_split,
        .sample_width_limits = postcard.proof_preflight.DEFAULT_SAMPLE_WIDTH_LIMITS,
        .hash_size = @sizeOf(Engine.Hasher.Hash),
        .hash_encoding = .canonical_m31_words,
        .max_wire_bytes = proof_v1.max_proof_bytes,
    };
}

pub const serializeProofAlloc = proof_v1.serializeProofAlloc;
pub const deserializeProof = proof_v1.deserializeProof;

fn qm31ArrayWords(
    comptime count: usize,
    values: [count]QM31,
) [count][4]u32 {
    var result: [count][4]u32 = undefined;
    for (values, &result) |value, *destination|
        destination.* = qm31Words(value);
    return result;
}

fn qm31Array(
    comptime count: usize,
    values: [count][4]u32,
) [count]QM31 {
    var result: [count]QM31 = undefined;
    for (values, &result) |value, *destination|
        destination.* = qm31(value);
    return result;
}

fn qm31Words(value: QM31) [4]u32 {
    var result: [4]u32 = undefined;
    for (value.toM31Array(), &result) |word, *destination|
        destination.* = word.toU32();
    return result;
}

fn qm31(value: [4]u32) QM31 {
    return QM31.fromU32Unchecked(value[0], value[1], value[2], value[3]);
}

fn validateWords(values: anytype) !void {
    for (values) |value| switch (@typeInfo(@TypeOf(value))) {
        .array => for (value) |word|
            if (word >= m31.Modulus)
                return error.NonCanonicalProviderV2Claim,
        else => if (value >= m31.Modulus)
            return error.NonCanonicalProviderV2Claim,
    };
}

fn removeContentPlaceholder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidProviderV2ProofArtifact;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidProviderV2ProofArtifact;
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
        const digest = [_]u8{0x73} ** 32;
        var value = provider_v2.ProviderStatementV2{
            .format = provider_v2.format_version,
            .plan_identity = digest,
            .manifest_identity = digest,
            .stage_a_identity = digest,
            .descriptor_identity = digest,
            .relation_context_identity = digest,
            .call_list_commitment = digest,
            .shard_index = 2,
            .first_call = 32,
            .call_count = 11,
            .log_size = 4,
            .tree2_geometry = try provider_v2.ProviderTree2GeometryV2
                .canonical(4),
            .claims = .{ .sums = .{
                QM31.fromU32Unchecked(1, 2, 3, 4),
                QM31.fromU32Unchecked(5, 6, 7, 8),
            } },
            .ordered_call_claim = .{
                .format = 1,
                .first_call = 32,
                .call_count = 11,
                .terminal = QM31.fromU32Unchecked(9, 10, 11, 12),
            },
            .identity = undefined,
        };
        value.identity = provider_v2.providerStatementIdentity(value);
        const common = CommonInput{
            .producer_sha256 = digest,
            .proof = .{
                .bytes = 17,
                .path = "/retained/provider-v2.postcard",
                .sha256 = digest,
            },
            .prove_timing = .{ .wall_ns = 1, .user_ns = 0, .system_ns = 0 },
            .resource_plan_identity = digest,
            .stage_a_checkpoint = .{
                .bytes = 19,
                .path = "/retained/stage-a.json",
                .sha256 = digest,
            },
            .stage_a_checkpoint_content_sha256 = digest,
        };
        const encoded = try encode(allocator, common, value);
        defer allocator.free(encoded);
        var parsed = try parse(allocator, encoded);
        defer parsed.deinit();
        const decoded = try statement(parsed.value.statement);
        try std.testing.expect(std.meta.eql(value, decoded));
        const shape = try proofShape(decoded);
        try std.testing.expectEqual(
            [4]u32{ 2, 445, 12, 8 },
            shape.tree_columns,
        );
        try std.testing.expectEqual(@as(u32, 5), shape.max_column_log_size);
    }
};
