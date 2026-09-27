//! Pointer-free authorities for the shared-context degree-five Ethereum
//! provider proof. Proof execution lives in the sibling proof module.

const std = @import("std");
const aggregation_hash = @import("../../aggregation/hash.zig");
const component_mod = @import("../../air/lang/typed_poseidon2_degree5_component.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const protocol = @import("ethereum_omit_protocol_v1.zig");
const proof_authority = @import("joint_proof_authority.zig");
const provider_order = @import("provider_order_component.zig");
const d5 = @import("degree5_provider_order_proof_v2.zig");

pub const format_version: u32 = 1;
pub const tree2_columns: usize = component_mod.INTERACTION_COLUMNS +
    provider_order.interaction_column_count;
pub const Digest = authority.Digest;
pub const VerifierProgramAuthorityV2 = d5.VerifierProgramAuthorityV2;
pub const ExecutionProfileV1 = d5.ExecutionProfileV1;
pub const ExecutionProfileV2 = d5.ExecutionProfileV2;
pub const FreshProviderClaimV2 = proof_authority.FreshProviderClaimV2;

pub const ProviderTree2GeometryV1 = struct {
    main_columns: u16,
    poseidon_logup_columns: u16,
    ordered_call_columns: u16,
    total_interaction_columns: u16,
    direct_constraints: u16,
    logup_constraints: u16,
    ordered_call_constraints: u16,
    max_constraint_log_degree_bound: u32,
    composition_log_size: u32,
    composition_log_split: u32,

    pub fn canonical(log_size: u32) !ProviderTree2GeometryV1 {
        if (log_size == 0 or log_size + component_mod.QUOTIENT_EXPANSION_BITS >= 31)
            return error.InvalidDegree5EthereumProviderGeometry;
        const composition_log_size = std.math.add(
            u32,
            log_size,
            component_mod.QUOTIENT_EXPANSION_BITS,
        ) catch return error.InvalidDegree5EthereumProviderGeometry;
        return .{
            .main_columns = component_mod.MAIN_COLUMNS,
            .poseidon_logup_columns = component_mod.INTERACTION_COLUMNS,
            .ordered_call_columns = provider_order.interaction_column_count,
            .total_interaction_columns = tree2_columns,
            .direct_constraints = component_mod.DIRECT_CONSTRAINTS,
            .logup_constraints = component_mod.LOGUP_CONSTRAINTS,
            .ordered_call_constraints = provider_order.constraint_count,
            .max_constraint_log_degree_bound = composition_log_size,
            .composition_log_size = composition_log_size,
            .composition_log_split = component_mod.COMPOSITION_LOG_SPLIT,
        };
    }
};

pub const ProviderStatementV1 = struct {
    format: u32,
    air_program_identity: Digest,
    plan_identity: Digest,
    manifest_identity: Digest,
    stage_a_identity: Digest,
    descriptor_identity: Digest,
    relation_context_identity: Digest,
    call_list_commitment: Digest,
    shard_index: u32,
    first_call: u64,
    call_count: u32,
    log_size: u32,
    geometry: ProviderTree2GeometryV1,
    claims: poseidon2_air.Claims,
    ordered_call_claim: provider_order.ClaimV1,
    identity: Digest,
};

pub const FreshDegree5ProviderClaimV1 = struct {
    format: u32,
    air_program_identity: Digest,
    execution_profile_identity: Digest,
    relation_context_identity: Digest,
    provider: FreshProviderClaimV2,
    shared_core_relation_context_verified: bool,
    global_degree5_domain_verified: bool,
    identity: Digest,

    pub fn validate(self: FreshDegree5ProviderClaimV1) !void {
        try self.provider.validate();
        if (self.format != format_version or
            !self.shared_core_relation_context_verified or
            !self.global_degree5_domain_verified or
            !aggregation_hash.eql(
                self.relation_context_identity,
                self.provider.native_claim.relation_context_identity,
            ) or !aggregation_hash.eql(self.identity, freshClaimIdentity(self)))
        {
            return error.InvalidFreshDegree5EthereumProviderClaim;
        }
    }
};

pub const FreshStrategyV1 = struct {
    format: u32,
    air_program_identity: Digest,
    execution_profile_identity: Digest,
    plan_identity: Digest,
    manifest_identity: Digest,
    preprocessed_commitment_identity: Digest,
    relation_context_identity: Digest,
    closure_identity: Digest,
    ordered_provider_claims_identity: Digest,
    shard_count: u32,
    every_provider_degree5_fresh_verified: bool,
    shared_core_zero_sum_verified: bool,
    production_eligible: bool,
    identity: Digest,

    pub fn validate(self: FreshStrategyV1) !void {
        if (self.format != format_version or self.shard_count == 0 or
            !self.every_provider_degree5_fresh_verified or
            !self.shared_core_zero_sum_verified or self.production_eligible or
            !aggregation_hash.eql(self.identity, strategyIdentity(self)))
        {
            return error.InvalidFreshDegree5EthereumProviderStrategy;
        }
    }
};

pub const ClosedStrategyV1 = struct {
    closure: protocol.VerifiedJointClosureV1,
    strategy: FreshStrategyV1,
};

pub fn preprocessedCommitmentIdentity(
    comptime Engine: type,
    program: VerifierProgramAuthorityV2,
    manifest: *const protocol.ProviderStageAManifestV1(Engine),
) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-d5-provider-preprocessed/v1\x00",
    );
    sink.writeAll(&program.air_program_identity) catch unreachable;
    sink.writeAll(&manifest.identity) catch unreachable;
    aggregation_hash.writeU32(&sink, @intCast(manifest.providers.len)) catch unreachable;
    for (manifest.providers) |record| {
        sink.writeAll(&record.descriptor_identity) catch unreachable;
        writeRoot(&sink, record.preprocessed_root);
    }
    return sink.finalize();
}

pub fn statementIdentity(value: ProviderStatementV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-d5-provider-statement/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.air_program_identity) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.stage_a_identity) catch unreachable;
    sink.writeAll(&value.descriptor_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.call_list_commitment) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_index) catch unreachable;
    aggregation_hash.writeU64(&sink, value.first_call) catch unreachable;
    aggregation_hash.writeU32(&sink, value.call_count) catch unreachable;
    aggregation_hash.writeU32(&sink, value.log_size) catch unreachable;
    writeGeometry(&sink, value.geometry);
    writeClaims(&sink, value.claims);
    writeOrderClaim(&sink, value.ordered_call_claim);
    return sink.finalize();
}

pub fn freshClaimIdentity(value: FreshDegree5ProviderClaimV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-d5-provider-fresh-claim/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.air_program_identity) catch unreachable;
    sink.writeAll(&value.execution_profile_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.provider.identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.shared_core_relation_context_verified),
        @intFromBool(value.global_degree5_domain_verified),
    }) catch unreachable;
    return sink.finalize();
}

pub fn strategyIdentity(value: FreshStrategyV1) Digest {
    var sink = aggregation_hash.HashSink.init(
        "stwo-zig/riscv/ethereum-d5-provider-strategy/v1\x00",
    );
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.air_program_identity) catch unreachable;
    sink.writeAll(&value.execution_profile_identity) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.preprocessed_commitment_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.closure_identity) catch unreachable;
    sink.writeAll(&value.ordered_provider_claims_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_count) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.every_provider_degree5_fresh_verified),
        @intFromBool(value.shared_core_zero_sum_verified),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    return sink.finalize();
}

fn writeGeometry(sink: anytype, value: ProviderTree2GeometryV1) void {
    aggregation_hash.writeU16(sink, value.main_columns) catch unreachable;
    aggregation_hash.writeU16(sink, value.poseidon_logup_columns) catch unreachable;
    aggregation_hash.writeU16(sink, value.ordered_call_columns) catch unreachable;
    aggregation_hash.writeU16(sink, value.total_interaction_columns) catch unreachable;
    aggregation_hash.writeU16(sink, value.direct_constraints) catch unreachable;
    aggregation_hash.writeU16(sink, value.logup_constraints) catch unreachable;
    aggregation_hash.writeU16(sink, value.ordered_call_constraints) catch unreachable;
    aggregation_hash.writeU32(sink, value.max_constraint_log_degree_bound) catch unreachable;
    aggregation_hash.writeU32(sink, value.composition_log_size) catch unreachable;
    aggregation_hash.writeU32(sink, value.composition_log_split) catch unreachable;
}

fn writeClaims(sink: anytype, claims: poseidon2_air.Claims) void {
    for (claims.sums) |claim| for (claim.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

fn writeOrderClaim(sink: anytype, claim: provider_order.ClaimV1) void {
    aggregation_hash.writeU32(sink, claim.format) catch unreachable;
    aggregation_hash.writeU64(sink, claim.first_call) catch unreachable;
    aggregation_hash.writeU32(sink, claim.call_count) catch unreachable;
    for (claim.terminal.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

fn writeRoot(sink: anytype, root: anytype) void {
    const bytes = std.mem.asBytes(&root);
    aggregation_hash.writeU32(sink, bytes.len) catch unreachable;
    sink.writeAll(bytes) catch unreachable;
}

comptime {
    if (component_mod.MAIN_COLUMNS != 239 or
        component_mod.INTERACTION_COLUMNS != poseidon2_air.N_INTERACTION_COLUMNS or
        tree2_columns != 12 or provider_order.selected_main_count != 17 or
        provider_order.constraint_count != 4 or
        component_mod.COMPOSITION_LOG_SPLIT != 2)
    {
        @compileError("Ethereum degree-five provider authority drifted");
    }
}
