//! Sealed statements and freshly verified claim receipts for the joint
//! narrow-memory Poseidon provider protocol.
//!
//! Proof execution lives in `joint_proof.zig`; this module is deliberately
//! limited to canonical geometry, identity domains, and fail-closed receipt
//! validation so integration checkpoints can consume one small authority.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const aggregation_hash = @import("../../aggregation/hash.zig");
const merkle_node = @import("../../air/memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../../air/memory_commitment/poseidon2_air.zig");
const authority = @import("authority.zig");
const harness = @import("proof_harness.zig");
const provider_order = @import("provider_order_component.zig");

pub const format_version: u32 = 1;
pub const provider_format_version_v2: u32 = 2;

pub const CoreResidencyGeometryV1 = struct {
    log_size: u32,
    n_rows: u32,
    tree0_columns: u32,
    tree1_columns: u32,
    tree2_columns: u32,
    max_constraint_log_degree_bound: u32,
    composition_log_size: u32,
    composition_log_split: u32,
    coefficient_retention: harness.CoefficientRetention,

    pub fn canonical(log_size: u32, n_rows: u32) !@This() {
        if (log_size < 4 or log_size >= 30 or
            n_rows == 0 or n_rows > (@as(u32, 1) << @intCast(log_size)))
        {
            return error.InvalidCoreGeometry;
        }
        return .{
            .log_size = log_size,
            .n_rows = n_rows,
            .tree0_columns = 2,
            .tree1_columns = merkle_node.N_MAIN_COLUMNS,
            .tree2_columns = merkle_node.N_INTERACTION_COLUMNS,
            .max_constraint_log_degree_bound = log_size + 2,
            .composition_log_size = log_size + 2,
            .composition_log_split = 1,
            .coefficient_retention = .never,
        };
    }
};

pub const CoreStatementV1 = struct {
    format: u32,
    plan_identity: authority.Digest,
    manifest_identity: authority.Digest,
    core_stage_a_identity: authority.Digest,
    relation_context_identity: authority.Digest,
    call_list_commitment: authority.Digest,
    geometry: CoreResidencyGeometryV1,
    claims: merkle_node.Claims,
    identity: authority.Digest,
};

pub const ProviderStatementV1 = struct {
    format: u32,
    plan_identity: authority.Digest,
    manifest_identity: authority.Digest,
    stage_a_identity: authority.Digest,
    descriptor_identity: authority.Digest,
    relation_context_identity: authority.Digest,
    shard_index: u32,
    first_call: u64,
    call_count: u32,
    log_size: u32,
    claims: poseidon2_air.Claims,
    identity: authority.Digest,
};

/// Exact commitment/composition geometry of a V2 provider proof.  V1 remains
/// available for retained diagnostic artifacts, but only V2 binds the ordered
/// call accumulator in the provider STARK's Tree 2.
pub const ProviderTree2GeometryV2 = struct {
    poseidon_logup_columns: u16,
    ordered_call_columns: u16,
    total_columns: u16,
    ordered_call_constraints: u16,
    max_constraint_log_degree_bound: u32,
    composition_log_size: u32,
    composition_log_split: u32,

    pub fn canonical(log_size: u32) !@This() {
        if (log_size < 4 or log_size >= 30) return error.InvalidProviderGeometry;
        const composition_log_size = std.math.add(u32, log_size, 2) catch
            return error.InvalidProviderGeometry;
        return .{
            .poseidon_logup_columns = poseidon2_air.N_INTERACTION_COLUMNS,
            .ordered_call_columns = provider_order.interaction_column_count,
            .total_columns = poseidon2_air.N_INTERACTION_COLUMNS +
                provider_order.interaction_column_count,
            .ordered_call_constraints = provider_order.constraint_count,
            .max_constraint_log_degree_bound = composition_log_size,
            .composition_log_size = composition_log_size,
            .composition_log_split = 1,
        };
    }
};

pub const ProviderStatementV2 = struct {
    format: u32,
    plan_identity: authority.Digest,
    manifest_identity: authority.Digest,
    stage_a_identity: authority.Digest,
    descriptor_identity: authority.Digest,
    relation_context_identity: authority.Digest,
    call_list_commitment: authority.Digest,
    shard_index: u32,
    first_call: u64,
    call_count: u32,
    log_size: u32,
    tree2_geometry: ProviderTree2GeometryV2,
    claims: poseidon2_air.Claims,
    ordered_call_claim: provider_order.ClaimV1,
    identity: authority.Digest,
};

pub const CoreWithoutProviderClaimV1 = struct {
    format: u32,
    plan_identity: authority.Digest,
    manifest_identity: authority.Digest,
    statement_identity: authority.Digest,
    relation_context_identity: authority.Digest,
    proof_commitments_identity: authority.Digest,
    fresh_core_stark_verified: bool,
    non_poseidon_buses_closed: bool,
    poseidon2_residual: QM31,
    identity: authority.Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != format_version or
            !self.fresh_core_stark_verified or
            !self.non_poseidon_buses_closed or
            !aggregation_hash.eql(self.identity, coreClaimIdentity(self)))
        {
            return error.InvalidFreshCoreClaim;
        }
    }

    pub fn native(self: @This()) authority.CorePoseidonClaimV1 {
        return .{
            .plan_identity = self.plan_identity,
            .relation_context_identity = self.relation_context_identity,
            .claim = self.poseidon2_residual,
        };
    }
};

pub const FreshProviderClaimV1 = struct {
    format: u32,
    manifest_identity: authority.Digest,
    statement_identity: authority.Digest,
    proof_commitments_identity: authority.Digest,
    fresh_provider_stark_verified: bool,
    native_claim: authority.ProviderShardClaimV1,
    identity: authority.Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != format_version or
            !self.fresh_provider_stark_verified or
            !aggregation_hash.eql(self.identity, providerClaimIdentity(self)))
        {
            return error.InvalidFreshProviderClaim;
        }
    }
};

pub const FreshProviderClaimV2 = struct {
    format: u32,
    manifest_identity: authority.Digest,
    statement_identity: authority.Digest,
    proof_commitments_identity: authority.Digest,
    fresh_provider_stark_verified: bool,
    ordered_call_air_verified: bool,
    ordered_call_claim_recomputed: bool,
    native_claim: authority.ProviderShardClaimV1,
    ordered_call_claim: provider_order.ClaimV1,
    identity: authority.Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != provider_format_version_v2 or
            !self.fresh_provider_stark_verified or
            !self.ordered_call_air_verified or
            !self.ordered_call_claim_recomputed or
            self.ordered_call_claim.format != provider_order.format_version or
            !aggregation_hash.eql(self.identity, providerClaimIdentityV2(self)))
        {
            return error.InvalidFreshProviderClaim;
        }
    }
};

pub const VerifiedJointClosureV1 = struct {
    format: u32,
    plan_identity: authority.Digest,
    manifest_identity: authority.Digest,
    relation_context_identity: authority.Digest,
    core_claim_identity: authority.Digest,
    ordered_provider_claims_identity: authority.Digest,
    shard_count: u32,
    core_claim: QM31,
    provider_claim: QM31,
    closed_sum: QM31,
    every_proof_freshly_verified: bool,
    complete_ordered_coverage: bool,
    one_shared_relation_context: bool,
    production_eligible: bool,
    identity: authority.Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != format_version or self.shard_count == 0 or
            !self.every_proof_freshly_verified or
            !self.complete_ordered_coverage or
            !self.one_shared_relation_context or
            self.production_eligible or !self.closed_sum.isZero() or
            !aggregation_hash.eql(self.identity, closureIdentity(self)))
        {
            return error.InvalidVerifiedJointClosure;
        }
    }
};

pub const VerifiedJointClosureV2 = struct {
    format: u32,
    plan_identity: authority.Digest,
    manifest_identity: authority.Digest,
    relation_context_identity: authority.Digest,
    core_claim_identity: authority.Digest,
    ordered_provider_claims_identity: authority.Digest,
    shard_count: u32,
    core_claim: QM31,
    provider_claim: QM31,
    closed_sum: QM31,
    every_proof_freshly_verified: bool,
    every_ordered_call_air_verified: bool,
    complete_ordered_coverage: bool,
    one_shared_relation_context: bool,
    production_eligible: bool,
    identity: authority.Digest,

    pub fn validate(self: @This()) !void {
        if (self.format != provider_format_version_v2 or self.shard_count == 0 or
            !self.every_proof_freshly_verified or
            !self.every_ordered_call_air_verified or
            !self.complete_ordered_coverage or
            !self.one_shared_relation_context or self.production_eligible or
            !self.closed_sum.isZero() or
            !aggregation_hash.eql(self.identity, closureIdentityV2(self)))
        {
            return error.InvalidVerifiedJointClosure;
        }
    }
};

pub fn coreStatementIdentity(value: CoreStatementV1) authority.Digest {
    var sink = aggregation_hash.HashSink.init(core_statement_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.core_stage_a_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.call_list_commitment) catch unreachable;
    hashCoreGeometry(&sink, value.geometry);
    hashClaims(&sink, &value.claims.sums);
    return sink.finalize();
}

pub fn providerStatementIdentity(value: ProviderStatementV1) authority.Digest {
    var sink = aggregation_hash.HashSink.init(provider_statement_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.stage_a_identity) catch unreachable;
    sink.writeAll(&value.descriptor_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_index) catch unreachable;
    aggregation_hash.writeU64(&sink, value.first_call) catch unreachable;
    aggregation_hash.writeU32(&sink, value.call_count) catch unreachable;
    aggregation_hash.writeU32(&sink, value.log_size) catch unreachable;
    hashClaims(&sink, &value.claims.sums);
    return sink.finalize();
}

pub fn providerStatementIdentityV2(value: ProviderStatementV2) authority.Digest {
    var sink = aggregation_hash.HashSink.init(provider_statement_domain_v2);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
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
    hashProviderTree2Geometry(&sink, value.tree2_geometry);
    hashClaims(&sink, &value.claims.sums);
    hashOrderClaim(&sink, value.ordered_call_claim);
    return sink.finalize();
}

pub fn coreClaimIdentity(value: CoreWithoutProviderClaimV1) authority.Digest {
    var sink = aggregation_hash.HashSink.init(core_claim_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.statement_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.proof_commitments_identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.fresh_core_stark_verified),
        @intFromBool(value.non_poseidon_buses_closed),
    }) catch unreachable;
    hashQm31(&sink, value.poseidon2_residual);
    return sink.finalize();
}

pub fn providerClaimIdentity(value: FreshProviderClaimV1) authority.Digest {
    var sink = aggregation_hash.HashSink.init(provider_claim_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.statement_identity) catch unreachable;
    sink.writeAll(&value.proof_commitments_identity) catch unreachable;
    sink.writeAll(&.{@intFromBool(value.fresh_provider_stark_verified)}) catch unreachable;
    sink.writeAll(&value.native_claim.plan_identity) catch unreachable;
    sink.writeAll(&value.native_claim.descriptor_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.native_claim.shard_index) catch unreachable;
    sink.writeAll(&value.native_claim.relation_context_identity) catch unreachable;
    hashClaims(&sink, &value.native_claim.claims.sums);
    return sink.finalize();
}

pub fn providerClaimIdentityV2(value: FreshProviderClaimV2) authority.Digest {
    var sink = aggregation_hash.HashSink.init(provider_claim_domain_v2);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.statement_identity) catch unreachable;
    sink.writeAll(&value.proof_commitments_identity) catch unreachable;
    sink.writeAll(&.{
        @intFromBool(value.fresh_provider_stark_verified),
        @intFromBool(value.ordered_call_air_verified),
        @intFromBool(value.ordered_call_claim_recomputed),
    }) catch unreachable;
    sink.writeAll(&value.native_claim.plan_identity) catch unreachable;
    sink.writeAll(&value.native_claim.descriptor_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.native_claim.shard_index) catch unreachable;
    sink.writeAll(&value.native_claim.relation_context_identity) catch unreachable;
    hashClaims(&sink, &value.native_claim.claims.sums);
    hashOrderClaim(&sink, value.ordered_call_claim);
    return sink.finalize();
}

pub fn closureIdentity(value: VerifiedJointClosureV1) authority.Digest {
    var sink = aggregation_hash.HashSink.init(closure_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.core_claim_identity) catch unreachable;
    sink.writeAll(&value.ordered_provider_claims_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_count) catch unreachable;
    hashQm31(&sink, value.core_claim);
    hashQm31(&sink, value.provider_claim);
    hashQm31(&sink, value.closed_sum);
    sink.writeAll(&.{
        @intFromBool(value.every_proof_freshly_verified),
        @intFromBool(value.complete_ordered_coverage),
        @intFromBool(value.one_shared_relation_context),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    return sink.finalize();
}

pub fn closureIdentityV2(value: VerifiedJointClosureV2) authority.Digest {
    var sink = aggregation_hash.HashSink.init(closure_domain_v2);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.plan_identity) catch unreachable;
    sink.writeAll(&value.manifest_identity) catch unreachable;
    sink.writeAll(&value.relation_context_identity) catch unreachable;
    sink.writeAll(&value.core_claim_identity) catch unreachable;
    sink.writeAll(&value.ordered_provider_claims_identity) catch unreachable;
    aggregation_hash.writeU32(&sink, value.shard_count) catch unreachable;
    hashQm31(&sink, value.core_claim);
    hashQm31(&sink, value.provider_claim);
    hashQm31(&sink, value.closed_sum);
    sink.writeAll(&.{
        @intFromBool(value.every_proof_freshly_verified),
        @intFromBool(value.every_ordered_call_air_verified),
        @intFromBool(value.complete_ordered_coverage),
        @intFromBool(value.one_shared_relation_context),
        @intFromBool(value.production_eligible),
    }) catch unreachable;
    return sink.finalize();
}

pub fn orderedProviderClaimsIdentity(
    values: []const FreshProviderClaimV1,
) authority.Digest {
    var sink = aggregation_hash.HashSink.init(provider_receipts_domain);
    aggregation_hash.writeU32(&sink, format_version) catch unreachable;
    aggregation_hash.writeU32(&sink, @intCast(values.len)) catch unreachable;
    for (values) |value| sink.writeAll(&value.identity) catch unreachable;
    return sink.finalize();
}

pub fn orderedProviderClaimsIdentityV2(
    values: []const FreshProviderClaimV2,
) authority.Digest {
    var sink = aggregation_hash.HashSink.init(provider_receipts_domain_v2);
    aggregation_hash.writeU32(&sink, provider_format_version_v2) catch unreachable;
    aggregation_hash.writeU32(&sink, @intCast(values.len)) catch unreachable;
    for (values) |value| sink.writeAll(&value.identity) catch unreachable;
    return sink.finalize();
}

pub fn commitmentsIdentity(
    comptime Engine: type,
    values: []const Engine.Hasher.Hash,
) authority.Digest {
    var sink = aggregation_hash.HashSink.init(commitments_domain);
    aggregation_hash.writeU32(&sink, @intCast(values.len)) catch unreachable;
    for (values) |value| {
        const bytes = std.mem.asBytes(&value);
        aggregation_hash.writeU32(&sink, bytes.len) catch unreachable;
        sink.writeAll(bytes) catch unreachable;
    }
    return sink.finalize();
}

fn hashCoreGeometry(sink: anytype, value: CoreResidencyGeometryV1) void {
    aggregation_hash.writeU32(sink, value.log_size) catch unreachable;
    aggregation_hash.writeU32(sink, value.n_rows) catch unreachable;
    aggregation_hash.writeU32(sink, value.tree0_columns) catch unreachable;
    aggregation_hash.writeU32(sink, value.tree1_columns) catch unreachable;
    aggregation_hash.writeU32(sink, value.tree2_columns) catch unreachable;
    aggregation_hash.writeU32(sink, value.max_constraint_log_degree_bound) catch unreachable;
    aggregation_hash.writeU32(sink, value.composition_log_size) catch unreachable;
    aggregation_hash.writeU32(sink, value.composition_log_split) catch unreachable;
    sink.writeAll(&.{@intFromEnum(value.coefficient_retention)}) catch unreachable;
}

fn hashProviderTree2Geometry(sink: anytype, value: ProviderTree2GeometryV2) void {
    aggregation_hash.writeU16(sink, value.poseidon_logup_columns) catch unreachable;
    aggregation_hash.writeU16(sink, value.ordered_call_columns) catch unreachable;
    aggregation_hash.writeU16(sink, value.total_columns) catch unreachable;
    aggregation_hash.writeU16(sink, value.ordered_call_constraints) catch unreachable;
    aggregation_hash.writeU32(sink, value.max_constraint_log_degree_bound) catch unreachable;
    aggregation_hash.writeU32(sink, value.composition_log_size) catch unreachable;
    aggregation_hash.writeU32(sink, value.composition_log_split) catch unreachable;
}

fn hashOrderClaim(sink: anytype, value: provider_order.ClaimV1) void {
    aggregation_hash.writeU32(sink, value.format) catch unreachable;
    aggregation_hash.writeU64(sink, value.first_call) catch unreachable;
    aggregation_hash.writeU32(sink, value.call_count) catch unreachable;
    hashQm31(sink, value.terminal);
}

fn hashClaims(sink: anytype, values: []const QM31) void {
    aggregation_hash.writeU32(sink, @intCast(values.len)) catch unreachable;
    for (values) |value| hashQm31(sink, value);
}

fn hashQm31(sink: anytype, value: QM31) void {
    for (value.toM31Array()) |limb|
        aggregation_hash.writeU32(sink, limb.v) catch unreachable;
}

const core_statement_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/core-statement/v1\x00";
const provider_statement_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/provider-statement/v1\x00";
const provider_statement_domain_v2 =
    "stwo-zig/riscv/narrow-memory-poseidon2/provider-statement/v2\x00";
const core_claim_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/fresh-core-claim/v1\x00";
const provider_claim_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/fresh-provider-claim/v1\x00";
const provider_claim_domain_v2 =
    "stwo-zig/riscv/narrow-memory-poseidon2/fresh-provider-claim/v2\x00";
const provider_receipts_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/ordered-provider-receipts/v1\x00";
const provider_receipts_domain_v2 =
    "stwo-zig/riscv/narrow-memory-poseidon2/ordered-provider-receipts/v2\x00";
const closure_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/fresh-joint-closure/v1\x00";
const closure_domain_v2 =
    "stwo-zig/riscv/narrow-memory-poseidon2/fresh-joint-closure/v2\x00";
const commitments_domain =
    "stwo-zig/riscv/narrow-memory-poseidon2/proof-commitments/v1\x00";

comptime {
    if (merkle_node.N_MAIN_COLUMNS != 10 or
        merkle_node.N_INTERACTION_COLUMNS != 12 or
        poseidon2_air.N_MAIN_COLUMNS != authority.main_column_count or
        poseidon2_air.N_INTERACTION_COLUMNS != authority.interaction_column_count or
        poseidon2_air.N_INTERACTION_COLUMNS + provider_order.interaction_column_count != 12 or
        standaloneCompositionLift() != 1)
    {
        @compileError("joint proof authority geometry drifted");
    }
}

fn standaloneCompositionLift() u32 {
    return @import("standalone_component.zig").composition_log_lift;
}
