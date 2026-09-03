//! Create-only Stage-A checkpoint for sequential Poseidon provider proofs.
//!
//! The checkpoint contains only the canonical caller/provider Tree0+Tree1
//! roots and the one shared interaction authority. On reopen, the caller must
//! independently reconstruct the authenticated call list, provider plan, and
//! resource plan. This module rebuilds the typed `JointManifest`, replays the
//! proof of work and relation draw, and rejects every detached or reordered
//! authority before Stage B may resume.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const contract = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const resource = @import("ethereum_poseidon_provider_resource_plan_v1.zig");
const support = @import("ethereum_block_leaf_support.zig");

const authority = frontend.testing.narrow_memory_provider_shard_authority;
const harness = frontend.testing.narrow_memory_provider_proof_harness;
const joint = frontend.testing.narrow_memory_provider_joint_protocol;
const poseidon2 = frontend.air.memory_commitment.poseidon2;
const poseidon2_air = frontend.air.memory_commitment.poseidon2_air;

const Engine = support.RecursiveEngine;

pub const schema =
    "stwo.ethereum.poseidon-provider-stage-a-checkpoint.v1";
pub const status = "stage-a-complete-nonproduction";
pub const max_checkpoint_bytes: usize = 4 * 1024 * 1024;
pub const root_word_count: usize = 8;

pub const RootPair = struct {
    main: [root_word_count]u32,
    preprocessed: [root_word_count]u32,

    fn validate(self: RootPair) !void {
        inline for (.{ self.preprocessed, self.main }) |root|
            for (root) |word|
                if (word >= m31.Modulus)
                    return error.NonCanonicalCheckpointRoot;
    }
};

pub const CoreRecord = struct {
    call_list_commitment_sha256: []const u8,
    identity_sha256: []const u8,
    interaction_columns: u16,
    log_size: u32,
    main_columns: u16,
    n_rows: u32,
    roots: RootPair,

    fn validate(self: CoreRecord) !void {
        _ = try contract.parseSha256(self.call_list_commitment_sha256);
        _ = try contract.parseSha256(self.identity_sha256);
        if (self.log_size == 0 or self.n_rows == 0 or
            self.main_columns == 0 or self.interaction_columns == 0)
        {
            return error.InvalidStageACheckpoint;
        }
        try self.roots.validate();
    }
};

pub const ProviderRecord = struct {
    call_count: u32,
    descriptor_identity_sha256: []const u8,
    expected_log_size: u32,
    first_call: u64,
    identity_sha256: []const u8,
    roots: RootPair,
    shard_index: u32,

    fn validate(self: ProviderRecord, index: usize) !void {
        _ = try contract.parseSha256(self.descriptor_identity_sha256);
        _ = try contract.parseSha256(self.identity_sha256);
        if (self.shard_index != index or self.call_count == 0 or
            self.expected_log_size == 0)
        {
            return error.InvalidStageACheckpoint;
        }
        try self.roots.validate();
    }
};

pub const SharedRelationRecord = struct {
    alpha_m31: [4]u32,
    identity_sha256: []const u8,
    interaction_pow: u64,
    interaction_pow_bits: u32,
    manifest_identity_sha256: []const u8,
    pow_context_sha256: []const u8,
    session_sha256: []const u8,
    z_m31: [4]u32,

    fn validate(self: SharedRelationRecord) !void {
        inline for (.{
            self.identity_sha256,
            self.manifest_identity_sha256,
            self.pow_context_sha256,
            self.session_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        if (self.interaction_pow_bits != joint.joint_interaction_pow_bits)
            return error.InvalidStageACheckpoint;
        inline for (.{ self.z_m31, self.alpha_m31 }) |words|
            for (words) |word|
                if (word >= m31.Modulus)
                    return error.NonCanonicalCheckpointField;
    }
};

pub const Checkpoint = struct {
    content_sha256: []const u8,
    call_list_commitment_sha256: []const u8,
    core: CoreRecord,
    manifest_identity_sha256: []const u8,
    plan_identity_sha256: []const u8,
    production_eligible: bool,
    providers: []ProviderRecord,
    recursive_admissible: bool,
    resource_plan_identity_sha256: []const u8,
    schema: []const u8,
    session_sha256: []const u8,
    shared_relation: SharedRelationRecord,
    shard_count: u32,
    status: []const u8,

    pub fn validate(self: Checkpoint) !void {
        if (!std.mem.eql(u8, self.schema, schema) or
            !std.mem.eql(u8, self.status, status) or
            self.production_eligible or self.recursive_admissible or
            self.shard_count == 0 or self.providers.len != self.shard_count)
        {
            return error.InvalidStageACheckpoint;
        }
        inline for (.{
            self.content_sha256,
            self.call_list_commitment_sha256,
            self.manifest_identity_sha256,
            self.plan_identity_sha256,
            self.resource_plan_identity_sha256,
            self.session_sha256,
        }) |digest| _ = try contract.parseSha256(digest);
        try self.core.validate();
        try self.shared_relation.validate();
        for (self.providers, 0..) |provider, index|
            try provider.validate(index);
    }
};

const ProviderHexStorage = struct {
    descriptor_identity: [64]u8,
    identity: [64]u8,
};

pub const Input = struct {
    calls: []const poseidon2_air.Call,
    manifest: *const joint.JointManifest(Engine),
    plan: *const authority.ProviderShardPlanV1,
    resource_plan: *const resource.ProviderResourcePlanV1,
    shared_relation: joint.SharedRelationAuthorityV1,
};

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
    try validateInput(allocator, input);
    const provider_storage = try allocator.alloc(
        ProviderHexStorage,
        input.manifest.providers.len,
    );
    defer allocator.free(provider_storage);
    const providers = try allocator.alloc(
        ProviderRecord,
        input.manifest.providers.len,
    );
    defer allocator.free(providers);
    for (
        input.manifest.providers,
        provider_storage,
        providers,
    ) |source, *storage, *destination| {
        storage.* = .{
            .descriptor_identity = hex(source.descriptor_identity),
            .identity = hex(source.identity),
        };
        destination.* = .{
            .call_count = source.call_count,
            .descriptor_identity_sha256 = &storage.descriptor_identity,
            .expected_log_size = source.expected_log_size,
            .first_call = source.first_call,
            .identity_sha256 = &storage.identity,
            .roots = .{
                .main = source.main_root,
                .preprocessed = source.preprocessed_root,
            },
            .shard_index = source.shard_index,
        };
    }

    const content_placeholder = [_]u8{'0'} ** 64;
    const resource_identity = hex(input.resource_plan.identity);
    const plan_identity = hex(input.plan.identity);
    const session = hex(input.plan.session);
    const call_list = hex(input.plan.call_list_commitment);
    const manifest_identity = hex(input.manifest.identity);
    const core_identity = hex(input.manifest.core.identity);
    const core_call_list = hex(input.manifest.core.call_list_commitment);
    const relation_identity = hex(input.shared_relation.relation_context.identity);
    const relation_session = hex(input.shared_relation.relation_context.session);
    const relation_manifest = hex(input.shared_relation.manifest_identity);
    const pow_context = hex(input.shared_relation.pow_context_digest);
    const value = Checkpoint{
        .content_sha256 = &content_placeholder,
        .call_list_commitment_sha256 = &call_list,
        .core = .{
            .call_list_commitment_sha256 = &core_call_list,
            .identity_sha256 = &core_identity,
            .interaction_columns = input.manifest.core.interaction_columns,
            .log_size = input.manifest.core.log_size,
            .main_columns = input.manifest.core.main_columns,
            .n_rows = input.manifest.core.n_rows,
            .roots = .{
                .main = input.manifest.core.main_root,
                .preprocessed = input.manifest.core.preprocessed_root,
            },
        },
        .manifest_identity_sha256 = &manifest_identity,
        .plan_identity_sha256 = &plan_identity,
        .production_eligible = false,
        .providers = providers,
        .recursive_admissible = false,
        .resource_plan_identity_sha256 = &resource_identity,
        .schema = schema,
        .session_sha256 = &session,
        .shared_relation = .{
            .alpha_m31 = qm31Words(input.shared_relation.relation_context.alpha),
            .identity_sha256 = &relation_identity,
            .interaction_pow = input.shared_relation.interaction_pow,
            .interaction_pow_bits = input.shared_relation.interaction_pow_bits,
            .manifest_identity_sha256 = &relation_manifest,
            .pow_context_sha256 = &pow_context,
            .session_sha256 = &relation_session,
            .z_m31 = qm31Words(input.shared_relation.relation_context.z),
        },
        .shard_count = input.plan.shard_count,
        .status = status,
    };
    const placeholder = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(placeholder);
    const unsigned = try removeContentPlaceholder(allocator, placeholder);
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
) !std.json.Parsed(Checkpoint) {
    if (bytes.len == 0 or bytes.len > max_checkpoint_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Checkpoint, allocator, bytes, .{
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

pub const Reopened = struct {
    manifest: joint.JointManifest(Engine),
    shared_relation: joint.SharedRelationAuthorityV1,

    pub fn deinit(self: *Reopened, allocator: std.mem.Allocator) void {
        self.manifest.deinit(allocator);
        self.* = undefined;
    }
};

pub fn reopen(
    allocator: std.mem.Allocator,
    checkpoint: Checkpoint,
    resource_plan: *const resource.ProviderResourcePlanV1,
    plan: *const authority.ProviderShardPlanV1,
    calls: []const poseidon2_air.Call,
) !Reopened {
    try checkpoint.validate();
    try resource_plan.validate();
    try plan.validate(calls);
    if (!std.mem.eql(
        u8,
        &hex(resource_plan.identity),
        checkpoint.resource_plan_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &hex(plan.identity),
        checkpoint.plan_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &hex(plan.session),
        checkpoint.session_sha256,
    ) or !std.mem.eql(
        u8,
        &hex(plan.call_list_commitment),
        checkpoint.call_list_commitment_sha256,
    ) or checkpoint.shard_count != plan.shard_count or
        resource_plan.shard_planning.shard_count != plan.shard_count)
    {
        return error.StageACheckpointAuthorityMismatch;
    }

    const provider_roots = try allocator.alloc(
        harness.StageACommitment(Engine),
        checkpoint.providers.len,
    );
    defer allocator.free(provider_roots);
    for (checkpoint.providers, provider_roots) |source, *roots| {
        roots.* = .{
            .preprocessed_root = source.roots.preprocessed,
            .main_root = source.roots.main,
        };
    }
    var manifest = try joint.JointManifest(Engine).create(
        allocator,
        plan,
        calls,
        .{
            .preprocessed_root = checkpoint.core.roots.preprocessed,
            .main_root = checkpoint.core.roots.main,
        },
        provider_roots,
    );
    errdefer manifest.deinit(allocator);
    try compareManifest(checkpoint, &manifest);

    const relation = try authority.PoseidonRelationContextV1.canonical(
        plan.session,
        qm31(checkpoint.shared_relation.z_m31),
        qm31(checkpoint.shared_relation.alpha_m31),
    );
    const shared = joint.SharedRelationAuthorityV1{
        .manifest_identity = try contract.parseSha256(
            checkpoint.shared_relation.manifest_identity_sha256,
        ),
        .interaction_pow_bits = checkpoint.shared_relation.interaction_pow_bits,
        .interaction_pow = checkpoint.shared_relation.interaction_pow,
        .pow_context_digest = try contract.parseSha256(
            checkpoint.shared_relation.pow_context_sha256,
        ),
        .relation_context = relation,
    };
    if (!std.mem.eql(
        u8,
        &hex(relation.identity),
        checkpoint.shared_relation.identity_sha256,
    )) return error.StageACheckpointAuthorityMismatch;
    _ = try joint.replaySharedTranscript(
        Engine,
        allocator,
        support.recursive_pcs_config,
        plan,
        calls,
        &manifest,
        shared,
    );
    return .{ .manifest = manifest, .shared_relation = shared };
}

fn validateInput(allocator: std.mem.Allocator, input: Input) !void {
    try input.resource_plan.validate();
    try input.plan.validate(input.calls);
    try input.manifest.validate(input.plan, input.calls);
    if (input.resource_plan.shard_planning.shard_count !=
        input.plan.shard_count or
        input.resource_plan.shard_planning.logical_row_count !=
            input.plan.total_call_count)
    {
        return error.StageACheckpointAuthorityMismatch;
    }
    _ = try joint.replaySharedTranscript(
        Engine,
        allocator,
        support.recursive_pcs_config,
        input.plan,
        input.calls,
        input.manifest,
        input.shared_relation,
    );
}

fn compareManifest(
    checkpoint: Checkpoint,
    manifest: *const joint.JointManifest(Engine),
) !void {
    if (!std.mem.eql(
        u8,
        &hex(manifest.identity),
        checkpoint.manifest_identity_sha256,
    ) or !std.mem.eql(
        u8,
        &hex(manifest.core.identity),
        checkpoint.core.identity_sha256,
    ) or !std.mem.eql(
        u8,
        &hex(manifest.core.call_list_commitment),
        checkpoint.core.call_list_commitment_sha256,
    ) or manifest.core.log_size != checkpoint.core.log_size or
        manifest.core.n_rows != checkpoint.core.n_rows or
        manifest.core.main_columns != checkpoint.core.main_columns or
        manifest.core.interaction_columns != checkpoint.core.interaction_columns or
        manifest.providers.len != checkpoint.providers.len)
    {
        return error.StageACheckpointAuthorityMismatch;
    }
    for (manifest.providers, checkpoint.providers) |expected, actual| {
        if (!std.mem.eql(
            u8,
            &hex(expected.identity),
            actual.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &hex(expected.descriptor_identity),
            actual.descriptor_identity_sha256,
        ) or expected.shard_index != actual.shard_index or
            expected.first_call != actual.first_call or
            expected.call_count != actual.call_count or
            expected.expected_log_size != actual.expected_log_size)
        {
            return error.StageACheckpointAuthorityMismatch;
        }
    }
}

fn removeContentPlaceholder(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) ![]u8 {
    const prefix = "{\"content_sha256\":\"";
    if (!std.mem.startsWith(u8, bytes, prefix))
        return error.InvalidStageACheckpoint;
    const end = prefix.len + 64;
    if (end + 1 >= bytes.len or bytes[end] != '"' or bytes[end + 1] != ',')
        return error.InvalidStageACheckpoint;
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

fn qm31Words(value: QM31) [4]u32 {
    var result: [4]u32 = undefined;
    for (value.toM31Array(), &result) |word, *destination|
        destination.* = word.toU32();
    return result;
}

fn qm31(words: [4]u32) QM31 {
    return QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]);
}

fn hex(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

test "Stage-A checkpoint reopens exact manifest and shared relation" {
    const allocator = std.testing.allocator;
    const calls = try allocator.alloc(poseidon2_air.Call, 17);
    defer allocator.free(calls);
    for (calls, 0..) |*call, index| {
        const left: u32 = @intCast(2 * index + 1);
        const right: u32 = @intCast(2 * index + 2);
        call.* = poseidon2_air.Call.narrowWithOutput(
            left,
            right,
            poseidon2.hashPair(left, right),
        );
    }
    const session = [_]u8{0x31} ** 32;
    const request = @import("stwo_prover_engine").pcs.residency_shard_plan.Request{
        .logical_row_count = calls.len,
        .column_count = resource.provider_main_columns,
        .min_shard_log_size = resource.provider_shard_log_size,
        .max_shard_log_size = resource.provider_shard_log_size,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = resource.host_byte_budget,
        .reserved_host_bytes = resource.provider_non_column_reserve_bytes,
        .requested_parallel_shards = 1,
    };
    var plan = try authority.ProviderShardPlanV1.create(
        allocator,
        session,
        calls,
        request,
    );
    defer plan.deinit(allocator);
    const resource_plan = try resource.testing.createFromGeometryAuthority(.{
        .snapshot_file_sha256 = [_]u8{0x41} ** 32,
        .snapshot_content_sha256 = [_]u8{0x42} ** 32,
        .source_request_sha256 = [_]u8{0x43} ** 32,
        .source_segment_sha256 = [_]u8{0x44} ** 32,
        .segment_index = 0,
        .legacy_poseidon = .{
            .infra_index = 2,
            .main_column_offset = 3140,
            .main_column_count = 445,
            .log_size = 24,
            .n_rows = @intCast(calls.len),
        },
        .tree0_column_count = 256,
        .tree0_log_sizes_sha256 = [_]u8{0x45} ** 32,
        .tree1_non_provider_column_count = 9374,
        .tree1_non_provider_log_sizes_sha256 = [_]u8{0x46} ** 32,
        .tree2_column_count = 9240,
        .tree2_log_sizes_sha256 = [_]u8{0x47} ** 32,
    });
    const provider_roots = [_]harness.StageACommitment(Engine){.{
        .preprocessed_root = testRoot(0x101),
        .main_root = testRoot(0x201),
    }};
    var manifest = try joint.JointManifest(Engine).create(
        allocator,
        &plan,
        calls,
        .{
            .preprocessed_root = testRoot(0x301),
            .main_root = testRoot(0x401),
        },
        &provider_roots,
    );
    defer manifest.deinit(allocator);
    const prepared = try joint.prepareSharedTranscript(
        Engine,
        allocator,
        support.recursive_pcs_config,
        &plan,
        calls,
        &manifest,
    );
    const bytes = try encode(allocator, .{
        .calls = calls,
        .manifest = &manifest,
        .plan = &plan,
        .resource_plan = &resource_plan,
        .shared_relation = prepared.authority_value,
    });
    defer allocator.free(bytes);
    var parsed = try parse(allocator, bytes);
    defer parsed.deinit();
    var reopened = try reopen(
        allocator,
        parsed.value,
        &resource_plan,
        &plan,
        calls,
    );
    try std.testing.expect(std.meta.eql(
        manifest.identity,
        reopened.manifest.identity,
    ));
    try std.testing.expect(std.meta.eql(
        prepared.authority_value.relation_context.identity,
        reopened.shared_relation.relation_context.identity,
    ));
    reopened.deinit(allocator);

    parsed.value.providers[0].roots.main[0] ^= 1;
    try std.testing.expectError(
        error.StageACheckpointAuthorityMismatch,
        reopen(
            allocator,
            parsed.value,
            &resource_plan,
            &plan,
            calls,
        ),
    );
}

fn testRoot(seed: u32) [root_word_count]u32 {
    var result: [root_word_count]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}
