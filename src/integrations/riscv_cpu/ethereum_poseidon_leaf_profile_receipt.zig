//! Optional, create-only performance evidence for one Poseidon v4 leaf proof.
//!
//! This transport is deliberately disjoint from the frozen producer-result
//! V1. It records only measurement and verifier-minted geometry; none of its
//! fields participate in the proof statement or transcript.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const prover_api = @import("stwo_prover_api");
const work_pool = @import("stwo_prover_engine").work_pool;

const artifact_io = @import("ethereum_precompile_artifact_io.zig");
const base = @import("ethereum_block_leaf_contract.zig");
const evidence = @import("ethereum_block_leaf_evidence.zig");
const product = @import("ethereum_poseidon_leaf_product_contract.zig");

pub const receipt_schema = "stwo.ethereum.poseidon-v4-leaf-proof-profile.v1";
pub const receipt_status = "profiled-diagnostic-only";
pub const runtime = "cpu";
pub const example = "ethereum-poseidon-v4-leaf";
pub const max_receipt_bytes: usize = 64 * 1024 * 1024;

const profile_v2 = frontend.recursion.vm_air_profile_v2;
const ethereum_context = frontend.recursion.ethereum_leaf_context_v1;

pub const TreeSpan = struct {
    declared_columns: u32,
    offset: u32,
    sampled_columns: u32,
};

pub const BaseComponent = struct {
    active: bool,
    claimed_sum_count: u32,
    claimed_sum_offset: u32,
    composition_log_split: u32,
    constraint_count: u32,
    interaction: TreeSpan,
    interaction_batch_count: u32,
    kind: []const u8,
    log_size: u32,
    main: TreeSpan,
    max_constraint_log_degree_bound: u32,
    n_rows: u32,
    physical_index: u32,
    preprocessed: TreeSpan,
    relation_event_count: u32,
    role: []const u8,
    shard_ordinal: u32,
};

pub const BaseGeometry = struct {
    air_instruction_count: u32,
    claimed_sum_count: u32,
    component_count: u32,
    components: []const BaseComponent,
    composition_log_degree_bound: u32,
    composition_log_split: u32,
    interaction_column_count: u32,
    lookup_activation_sha256: []const u8,
    lookup_manifest_sha256: []const u8,
    lookup_statement_sha256: []const u8,
    main_column_count: u32,
    max_log_degree_bound: u32,
    preprocessed_column_count: u32,
    profile_sha256: []const u8,
    relation_challenge_count: u32,
    sampled_value_count: u32,
    transcript_claimed_sum_count: u32,
};

pub const ExtensionComponent = struct {
    direct_constraint_count: u32,
    interaction_batch_count: u32,
    interaction_columns: u32,
    interaction_offset: u32,
    kind: []const u8,
    log_size: u32,
    main_columns: u32,
    main_offset: u32,
    n_rows: u32,
    preprocessed_columns: u32,
    preprocessed_offset: u32,
};

pub const ExtensionGeometry = struct {
    claim_sha256: []const u8,
    component_count: u32,
    components: []const ExtensionComponent,
    context_sha256: []const u8,
    full_component_count: u32,
    statement_sha256: []const u8,
};

pub const ExecutionPolicy = struct {
    contention_policy: []const u8,
    host_byte_budget: u64,
    host_byte_budget_unbounded: bool,
    worker_count: u32,
    worker_stack_bytes: u64,
};

pub const Receipt = struct {
    content_sha256: []const u8,
    base_geometry: BaseGeometry,
    execution_policy: ExecutionPolicy,
    extension_geometry: ExtensionGeometry,
    producer_result: base.Identity,
    producer_sha256: []const u8,
    proof: base.Identity,
    prove_timing: product.Timing,
    request: base.Identity,
    request_content_sha256: []const u8,
    schema: []const u8,
    segment_index: u32,
    stage_profile: prover_api.stage_profile.StageProfile,
    status: []const u8,
    task_profile: prover_api.task_profile.TaskProfile,
    work_complete_exact: bool,
    work_profile: prover_api.work_profile.Profile,

    pub fn validate(self: Receipt) !void {
        if (!std.mem.eql(u8, self.schema, receipt_schema) or
            !std.mem.eql(u8, self.status, receipt_status) or
            !std.mem.eql(u8, self.stage_profile.runtime, runtime) or
            !std.mem.eql(u8, self.stage_profile.example, example) or
            !std.mem.eql(u8, self.task_profile.runtime, runtime) or
            !std.mem.eql(u8, self.task_profile.example, example) or
            self.stage_profile.schema_version !=
                prover_api.stage_profile.SCHEMA_VERSION or
            self.task_profile.schema_version !=
                prover_api.task_profile.TASK_PROFILE_SCHEMA_VERSION or
            self.stage_profile.stages.len == 0 or
            self.prove_timing.wall_ns == 0 or
            self.execution_policy.worker_count == 0 or
            self.execution_policy.worker_stack_bytes == 0 or
            !std.mem.eql(
                u8,
                self.execution_policy.contention_policy,
                "strict",
            ) or
            self.execution_policy.host_byte_budget_unbounded !=
                (self.execution_policy.host_byte_budget == std.math.maxInt(u64)))
        {
            return error.InvalidProofProfileReceipt;
        }
        try self.proof.validate(false);
        try self.producer_result.validate(false);
        try self.request.validate(false);
        inline for (.{
            self.content_sha256,
            self.producer_sha256,
            self.request_content_sha256,
            self.base_geometry.lookup_activation_sha256,
            self.base_geometry.lookup_manifest_sha256,
            self.base_geometry.lookup_statement_sha256,
            self.base_geometry.profile_sha256,
            self.extension_geometry.claim_sha256,
            self.extension_geometry.context_sha256,
            self.extension_geometry.statement_sha256,
        }) |digest| _ = try base.parseSha256(digest);
        try self.work_profile.validate();
        if (self.work_complete_exact != self.work_profile.completeExact())
            return error.InvalidProofProfileReceipt;
        try validateBaseGeometry(self.base_geometry);
        try validateExtensionGeometry(self.extension_geometry);
    }
};

pub const Input = struct {
    base_geometry: BaseGeometry,
    execution_policy: ExecutionPolicy,
    extension_geometry: ExtensionGeometry,
    producer_result: base.Identity,
    producer_sha256: []const u8,
    proof: base.Identity,
    prove_timing: product.Timing,
    request: base.Identity,
    request_content_sha256: []const u8,
    schema: []const u8 = receipt_schema,
    segment_index: u32,
    stage_profile: prover_api.stage_profile.StageProfile,
    status: []const u8 = receipt_status,
    task_profile: prover_api.task_profile.TaskProfile,
    work_complete_exact: bool,
    work_profile: prover_api.work_profile.Profile,
};

pub const BuiltBaseGeometry = struct {
    components: []BaseComponent,
    value: BaseGeometry,

    pub fn deinit(self: *BuiltBaseGeometry, allocator: std.mem.Allocator) void {
        allocator.free(self.components);
        self.* = undefined;
    }
};

pub fn buildBaseGeometry(
    allocator: std.mem.Allocator,
    source: *const profile_v2.ProfileV2,
    profile_sha256: []const u8,
    manifest_sha256: []const u8,
    statement_sha256: []const u8,
    activation_sha256: []const u8,
) !BuiltBaseGeometry {
    try source.validate();
    const components = try allocator.alloc(BaseComponent, source.entries.len);
    errdefer allocator.free(components);
    for (source.entries, components) |entry, *out| {
        out.* = .{
            .active = entry.active,
            .claimed_sum_count = entry.claimed_sum_count,
            .claimed_sum_offset = entry.claimed_sum_offset,
            .composition_log_split = entry.composition_log_split,
            .constraint_count = entry.constraint_count,
            .interaction = span(entry.interaction),
            .interaction_batch_count = entry.interaction_batch_count,
            .kind = entryKind(entry),
            .log_size = entry.log_size,
            .main = span(entry.main),
            .max_constraint_log_degree_bound = entry.max_constraint_log_degree_bound,
            .n_rows = entry.n_rows,
            .physical_index = entry.physical_index,
            .preprocessed = span(entry.preprocessed),
            .relation_event_count = entry.relation_event_count,
            .role = @tagName(entry.registry),
            .shard_ordinal = entry.shard_ordinal,
        };
    }
    return .{
        .components = components,
        .value = .{
            .air_instruction_count = source.air_instruction_count,
            .claimed_sum_count = source.input_profile.claimed_sum_count,
            .component_count = source.physical_component_count,
            .components = components,
            .composition_log_degree_bound = source.composition_log_degree_bound,
            .composition_log_split = source.composition_log_split,
            .interaction_column_count = source.interaction_column_count,
            .lookup_activation_sha256 = activation_sha256,
            .lookup_manifest_sha256 = manifest_sha256,
            .lookup_statement_sha256 = statement_sha256,
            .main_column_count = source.main_column_count,
            .max_log_degree_bound = source.max_log_degree_bound,
            .preprocessed_column_count = source.preprocessed_column_count,
            .profile_sha256 = profile_sha256,
            .relation_challenge_count = source.input_profile.relation_challenge_count,
            .sampled_value_count = source.input_profile.sampled_value_count,
            .transcript_claimed_sum_count = source.input_profile.transcript_claimed_sum_count,
        },
    };
}

pub fn extensionGeometry(
    source: *const ethereum_context.ContextV1,
    components: *[ethereum_context.EXTENSION_COMPONENT_COUNT]ExtensionComponent,
    context_sha256: []const u8,
    statement_sha256: []const u8,
    claim_sha256: []const u8,
) ExtensionGeometry {
    for (source.components, components) |component, *out| out.* = .{
        .direct_constraint_count = component.direct_constraint_count,
        .interaction_batch_count = component.interaction_batch_count,
        .interaction_columns = component.interaction_columns,
        .interaction_offset = component.interaction_offset,
        .kind = @tagName(component.kind),
        .log_size = component.log_size,
        .main_columns = component.main_columns,
        .main_offset = component.main_offset,
        .n_rows = component.n_rows,
        .preprocessed_columns = component.preprocessed_columns,
        .preprocessed_offset = component.preprocessed_offset,
    };
    return .{
        .claim_sha256 = claim_sha256,
        .component_count = @intCast(components.len),
        .components = components,
        .context_sha256 = context_sha256,
        .full_component_count = source.full_component_count,
        .statement_sha256 = statement_sha256,
    };
}

pub fn executionPolicy(worker_count: usize, host_byte_budget: usize) !ExecutionPolicy {
    return .{
        .contention_policy = "strict",
        .host_byte_budget = std.math.cast(u64, host_byte_budget) orelse
            return error.ProofProfileCountOverflow,
        .host_byte_budget_unbounded = host_byte_budget == std.math.maxInt(usize),
        .worker_count = std.math.cast(u32, worker_count) orelse
            return error.ProofProfileCountOverflow,
        .worker_stack_bytes = work_pool.WORKER_STACK_SIZE,
    };
}

pub fn encode(allocator: std.mem.Allocator, input: Input) ![]u8 {
    const unsigned = try std.json.Stringify.valueAlloc(allocator, input, .{});
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
) !std.json.Parsed(Receipt) {
    if (bytes.len == 0 or bytes.len > max_receipt_bytes or
        bytes[bytes.len - 1] != '\n' or
        (bytes.len > 1 and bytes[bytes.len - 2] == '\n'))
    {
        return error.InvalidCanonicalJson;
    }
    var parsed = try std.json.parseFromSlice(Receipt, allocator, bytes, .{
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

fn span(value: profile_v2.TreeSpanV2) TreeSpan {
    return .{
        .declared_columns = value.declared_columns,
        .offset = value.offset,
        .sampled_columns = value.sampled_columns,
    };
}

fn entryKind(entry: profile_v2.EntryV2) []const u8 {
    return switch (entry.registry) {
        .opcode_semantic => |key| @tagName(key.descriptor.family),
        .opcode_lookup => |key| @tagName(key.family),
        .infrastructure => |key| @tagName(key.kind),
    };
}

fn validateBaseGeometry(value: BaseGeometry) !void {
    if (value.component_count == 0 or
        value.components.len != value.component_count or
        value.air_instruction_count == 0 or
        value.sampled_value_count == 0)
    {
        return error.InvalidProofProfileReceipt;
    }
    var preprocessed: u32 = 0;
    var main: u32 = 0;
    var interaction: u32 = 0;
    var claims: u32 = 0;
    for (value.components, 0..) |component, index| {
        if (!component.active or
            component.physical_index != @as(u32, @intCast(index)) or
            component.kind.len == 0 or component.role.len == 0 or
            component.claimed_sum_offset != claims)
        {
            return error.InvalidProofProfileReceipt;
        }
        claims = try checkedAdd(claims, component.claimed_sum_count);
        preprocessed = @max(preprocessed, try spanEnd(component.preprocessed));
        main = @max(main, try spanEnd(component.main));
        interaction = @max(interaction, try spanEnd(component.interaction));
    }
    if (claims != value.claimed_sum_count or
        preprocessed != value.preprocessed_column_count or
        main != value.main_column_count or
        interaction != value.interaction_column_count)
    {
        return error.InvalidProofProfileReceipt;
    }
}

fn validateExtensionGeometry(value: ExtensionGeometry) !void {
    if (value.component_count != ethereum_context.EXTENSION_COMPONENT_COUNT or
        value.components.len != value.component_count or
        value.full_component_count < value.component_count)
    {
        return error.InvalidProofProfileReceipt;
    }
    for (value.components) |component| if (component.kind.len == 0 or
        component.log_size == 0 or component.direct_constraint_count == 0)
    {
        return error.InvalidProofProfileReceipt;
    };
}

fn spanEnd(value: TreeSpan) !u32 {
    if (value.declared_columns > value.sampled_columns)
        return error.InvalidProofProfileReceipt;
    return checkedAdd(value.offset, value.sampled_columns);
}

fn checkedAdd(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.InvalidProofProfileReceipt;
}

fn validateContentSha256(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: []const u8,
) !void {
    _ = try base.parseSha256(expected);
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
    const encoded = std.fmt.bytesToHex(digest, .lower);
    if (!std.mem.eql(u8, &encoded, expected))
        return error.InvalidContentSha256;
}

pub fn publishCreateOnly(path: []const u8, bytes: []const u8) !void {
    return artifact_io.publishCreateOnlyDurable(path, bytes);
}
