//! Exact resource authority for sequential legacy Poseidon provider shards.
//!
//! This plan is additive and does not activate the provider split. It binds a
//! validated pre-Engine geometry snapshot, forces the existing 445-column AIR
//! into sequential log20 shards with coefficient retention `.never`, and
//! models every retained provider tree plus its standalone composition tree.
//! The schedule is two-pass: Stage A commits and tears down every owner before
//! the shared relation draw; Stage B regenerates and proves one ordinal at a
//! time. Caller and provider owners are never simultaneously resident.
//!
//! The resource envelope is useful before the joint proof protocol is ready,
//! but it is deliberately not proof admission. In particular, this V1 plan
//! records that the real RISC-V caller, AIR-bound ordered-call authority, and
//! recursive admission are not yet bound.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const pcs = @import("stwo_prover_engine").pcs;

const base = @import("ethereum_block_leaf_contract.zig");
const geometry_snapshot = @import("ethereum_poseidon_leaf_geometry_snapshot.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const residency = pcs.residency_estimate;
const shard_planner = pcs.residency_shard_plan;
const orchestration = frontend.prover_mod.guest_precompile
    .ethereum_segment_orchestration;

pub const format_version: u16 = 1;
pub const identity_domain =
    "stwo-zig/ethereum/poseidon-provider-resource-plan/v1\x00";
pub const host_byte_budget: u64 = 48 * 1024 * 1024 * 1024;
pub const provider_non_column_reserve_bytes: u64 =
    16 * 1024 * 1024 * 1024;
pub const provider_shard_log_size: u32 = 20;
pub const provider_preprocessed_columns: u64 = 2;
pub const provider_main_columns: u64 = 445;
pub const provider_interaction_columns: u64 = 8;
pub const provider_composition_columns: u64 = 8;
pub const provider_composition_column_log_size: u32 =
    provider_shard_log_size + 1;
pub const admitted_parallel_provider_owners: u32 = 1;

comptime {
    if (provider_main_columns != 445 or
        provider_interaction_columns != 8)
    {
        @compileError("legacy narrow-memory Poseidon geometry drifted");
    }
}

pub const Digest = [32]u8;

pub const GeometryAuthorityV1 = struct {
    snapshot_file_sha256: Digest,
    snapshot_content_sha256: Digest,
    source_request_sha256: Digest,
    source_segment_sha256: Digest,
    segment_index: u32,
    legacy_poseidon: orchestration.LegacyPoseidonSpan,
    tree0_column_count: u64,
    tree0_log_sizes_sha256: Digest,
    tree1_non_provider_column_count: u64,
    tree1_non_provider_log_sizes_sha256: Digest,
    tree2_column_count: u64,
    tree2_log_sizes_sha256: Digest,

    pub fn canonical(
        snapshot: *const geometry_snapshot.Snapshot,
        snapshot_file_sha256: Digest,
    ) !GeometryAuthorityV1 {
        try snapshot.validate();
        if (snapshot.log_blowup_factor != 1 or
            snapshot.legacy_poseidon.main_column_count !=
                provider_main_columns or
            snapshot.legacy_poseidon.log_size < provider_shard_log_size or
            snapshot.legacy_poseidon.n_rows == 0)
        {
            return error.InvalidProviderGeometryAuthority;
        }
        return .{
            .snapshot_file_sha256 = snapshot_file_sha256,
            .snapshot_content_sha256 = try base.parseSha256(
                snapshot.content_sha256,
            ),
            .source_request_sha256 = try base.parseSha256(
                snapshot.source_request.sha256,
            ),
            .source_segment_sha256 = try base.parseSha256(
                snapshot.source_segment.sha256,
            ),
            .segment_index = snapshot.segment_index,
            .legacy_poseidon = snapshot.legacy_poseidon,
            .tree0_column_count = try count(snapshot.tree0_log_sizes.len),
            .tree0_log_sizes_sha256 = logSizesSha256(
                snapshot.tree0_log_sizes,
            ),
            .tree1_non_provider_column_count = try count(
                snapshot.tree1_non_candidate_log_sizes.len,
            ),
            .tree1_non_provider_log_sizes_sha256 = logSizesSha256(
                snapshot.tree1_non_candidate_log_sizes,
            ),
            .tree2_column_count = try count(snapshot.tree2_log_sizes.len),
            .tree2_log_sizes_sha256 = logSizesSha256(
                snapshot.tree2_log_sizes,
            ),
        };
    }
};

pub const StageEstimateV1 = struct {
    tree0: residency.Estimate,
    tree1: residency.Estimate,
    tree2: residency.Estimate,
    composition: residency.Estimate,
    retained_opening_lower_bound_bytes: u64,
    commit_transient_lower_bound_bytes: u64,
    staged_peak_lower_bound_bytes: u64,
    non_column_reserve_bytes: u64,
    admitted_provider_peak_bytes: u64,

    pub fn canonical(log_blowup_factor: u32) !StageEstimateV1 {
        const tree0 = try residency.estimateUniform(
            provider_preprocessed_columns,
            provider_shard_log_size,
            log_blowup_factor,
            .never,
        );
        const tree1 = try residency.estimateUniform(
            provider_main_columns,
            provider_shard_log_size,
            log_blowup_factor,
            .never,
        );
        const tree2 = try residency.estimateUniform(
            provider_interaction_columns,
            provider_shard_log_size,
            log_blowup_factor,
            .never,
        );
        const composition = try residency.estimateUniform(
            provider_composition_columns,
            provider_composition_column_log_size,
            log_blowup_factor,
            .never,
        );

        var retained_prior: u64 = 0;
        var transient_peak: u64 = 0;
        inline for (.{ tree0, tree1, tree2, composition }) |stage| {
            transient_peak = @max(
                transient_peak,
                try add(
                    retained_prior,
                    try add(stage.source_bytes, stage.extended_evaluation_bytes),
                ),
            );
            retained_prior = try add(
                retained_prior,
                stage.minimum_resident_bytes,
            );
        }
        const staged_peak = @max(retained_prior, transient_peak);
        const admitted_peak = try add(
            staged_peak,
            provider_non_column_reserve_bytes,
        );
        if (admitted_peak > host_byte_budget)
            return error.ProviderResourceBudgetExceeded;
        return .{
            .tree0 = tree0,
            .tree1 = tree1,
            .tree2 = tree2,
            .composition = composition,
            .retained_opening_lower_bound_bytes = retained_prior,
            .commit_transient_lower_bound_bytes = transient_peak,
            .staged_peak_lower_bound_bytes = staged_peak,
            .non_column_reserve_bytes = provider_non_column_reserve_bytes,
            .admitted_provider_peak_bytes = admitted_peak,
        };
    }
};

pub const OwnershipScheduleV1 = struct {
    coefficient_retention_never: bool,
    stage_a_commit_then_teardown: bool,
    durable_stage_a_before_shared_draw: bool,
    stage_b_recompute_from_authenticated_calls: bool,
    caller_and_provider_owners_overlap: bool,
    admitted_parallel_provider_owners: u32,
    verify_and_publish_in_ordinal_order: bool,

    pub fn canonical() OwnershipScheduleV1 {
        return .{
            .coefficient_retention_never = true,
            .stage_a_commit_then_teardown = true,
            .durable_stage_a_before_shared_draw = true,
            .stage_b_recompute_from_authenticated_calls = true,
            .caller_and_provider_owners_overlap = false,
            .admitted_parallel_provider_owners = admitted_parallel_provider_owners,
            .verify_and_publish_in_ordinal_order = true,
        };
    }
};

pub const ProtocolReadinessV1 = struct {
    caller_resource_authority_bound: bool,
    real_riscv_caller_replaced: bool,
    ordered_calls_air_or_public_statement_bound: bool,
    joint_fresh_closure_bound: bool,
    recursive_admissible: bool,
    production_eligible: bool,

    pub fn blocked() ProtocolReadinessV1 {
        return .{
            .caller_resource_authority_bound = false,
            .real_riscv_caller_replaced = false,
            .ordered_calls_air_or_public_statement_bound = false,
            .joint_fresh_closure_bound = false,
            .recursive_admissible = false,
            .production_eligible = false,
        };
    }
};

pub const ProviderResourcePlanV1 = struct {
    format: u16,
    geometry: GeometryAuthorityV1,
    shard_planning: shard_planner.Plan,
    stage_estimate: StageEstimateV1,
    ownership: OwnershipScheduleV1,
    readiness: ProtocolReadinessV1,
    host_byte_budget: u64,
    identity: Digest,

    pub fn create(
        snapshot: *const geometry_snapshot.Snapshot,
        snapshot_file_sha256: Digest,
    ) !ProviderResourcePlanV1 {
        return createFromGeometry(try GeometryAuthorityV1.canonical(
            snapshot,
            snapshot_file_sha256,
        ));
    }

    pub fn validateAgainst(
        self: ProviderResourcePlanV1,
        snapshot: *const geometry_snapshot.Snapshot,
        snapshot_file_sha256: Digest,
    ) !void {
        try self.validate();
        const expected = try create(snapshot, snapshot_file_sha256);
        if (!std.meta.eql(self, expected))
            return error.InvalidProviderResourcePlan;
    }

    pub fn validate(self: ProviderResourcePlanV1) !void {
        const expected = try createFromGeometry(self.geometry);
        if (!std.meta.eql(self, expected))
            return error.InvalidProviderResourcePlan;
    }

    /// Exact frontend shard-planner request bound by this resource plan.
    /// Callers must not reconstruct these knobs independently when minting the
    /// typed provider plan used by Stage A and Stage B.
    pub fn providerShardRequest(
        self: ProviderResourcePlanV1,
    ) shard_planner.Request {
        return requestForGeometry(self.geometry);
    }
};

fn createFromGeometry(
    geometry: GeometryAuthorityV1,
) !ProviderResourcePlanV1 {
    if (geometry.legacy_poseidon.main_column_count != provider_main_columns or
        geometry.legacy_poseidon.log_size < provider_shard_log_size or
        geometry.legacy_poseidon.n_rows == 0)
    {
        return error.InvalidProviderGeometryAuthority;
    }
    const request = requestForGeometry(geometry);
    const shard_planning = try shard_planner.create(request);
    if (shard_planning.shard_log_size != provider_shard_log_size or
        shard_planning.admitted_parallel_shards !=
            admitted_parallel_provider_owners)
    {
        return error.InvalidProviderResourcePlan;
    }
    var result = ProviderResourcePlanV1{
        .format = format_version,
        .geometry = geometry,
        .shard_planning = shard_planning,
        .stage_estimate = try StageEstimateV1.canonical(1),
        .ownership = OwnershipScheduleV1.canonical(),
        .readiness = ProtocolReadinessV1.blocked(),
        .host_byte_budget = host_byte_budget,
        .identity = undefined,
    };
    result.identity = planIdentity(result);
    return result;
}

fn requestForGeometry(
    geometry: GeometryAuthorityV1,
) shard_planner.Request {
    return .{
        .logical_row_count = geometry.legacy_poseidon.n_rows,
        .column_count = provider_main_columns,
        .min_shard_log_size = provider_shard_log_size,
        .max_shard_log_size = provider_shard_log_size,
        .log_blowup_factor = 1,
        .retention_policy = .never,
        .host_byte_budget = host_byte_budget,
        .reserved_host_bytes = provider_non_column_reserve_bytes,
        .requested_parallel_shards = admitted_parallel_provider_owners,
    };
}

fn planIdentity(plan: ProviderResourcePlanV1) Digest {
    var hash = Sha256.init(.{});
    hash.update(identity_domain);
    hashInt(&hash, u16, plan.format);
    hashGeometry(&hash, plan.geometry);
    hash.update(&plan.shard_planning.plan_identity);
    hashEstimate(&hash, plan.stage_estimate.tree0);
    hashEstimate(&hash, plan.stage_estimate.tree1);
    hashEstimate(&hash, plan.stage_estimate.tree2);
    hashEstimate(&hash, plan.stage_estimate.composition);
    hashInt(
        &hash,
        u64,
        plan.stage_estimate.retained_opening_lower_bound_bytes,
    );
    hashInt(
        &hash,
        u64,
        plan.stage_estimate.commit_transient_lower_bound_bytes,
    );
    hashInt(
        &hash,
        u64,
        plan.stage_estimate.staged_peak_lower_bound_bytes,
    );
    hashInt(&hash, u64, plan.stage_estimate.non_column_reserve_bytes);
    hashInt(&hash, u64, plan.stage_estimate.admitted_provider_peak_bytes);
    hashBool(&hash, plan.ownership.coefficient_retention_never);
    hashBool(&hash, plan.ownership.stage_a_commit_then_teardown);
    hashBool(&hash, plan.ownership.durable_stage_a_before_shared_draw);
    hashBool(
        &hash,
        plan.ownership.stage_b_recompute_from_authenticated_calls,
    );
    hashBool(&hash, plan.ownership.caller_and_provider_owners_overlap);
    hashInt(
        &hash,
        u32,
        plan.ownership.admitted_parallel_provider_owners,
    );
    hashBool(&hash, plan.ownership.verify_and_publish_in_ordinal_order);
    hashBool(&hash, plan.readiness.caller_resource_authority_bound);
    hashBool(&hash, plan.readiness.real_riscv_caller_replaced);
    hashBool(
        &hash,
        plan.readiness.ordered_calls_air_or_public_statement_bound,
    );
    hashBool(&hash, plan.readiness.joint_fresh_closure_bound);
    hashBool(&hash, plan.readiness.recursive_admissible);
    hashBool(&hash, plan.readiness.production_eligible);
    hashInt(&hash, u64, plan.host_byte_budget);
    return hash.finalResult();
}

fn hashGeometry(hash: *Sha256, geometry: GeometryAuthorityV1) void {
    hash.update(&geometry.snapshot_file_sha256);
    hash.update(&geometry.snapshot_content_sha256);
    hash.update(&geometry.source_request_sha256);
    hash.update(&geometry.source_segment_sha256);
    hashInt(hash, u32, geometry.segment_index);
    hashInt(hash, u32, geometry.legacy_poseidon.infra_index);
    hashInt(hash, u32, geometry.legacy_poseidon.main_column_offset);
    hashInt(hash, u32, geometry.legacy_poseidon.main_column_count);
    hashInt(hash, u32, geometry.legacy_poseidon.log_size);
    hashInt(hash, u32, geometry.legacy_poseidon.n_rows);
    hashInt(hash, u64, geometry.tree0_column_count);
    hash.update(&geometry.tree0_log_sizes_sha256);
    hashInt(hash, u64, geometry.tree1_non_provider_column_count);
    hash.update(&geometry.tree1_non_provider_log_sizes_sha256);
    hashInt(hash, u64, geometry.tree2_column_count);
    hash.update(&geometry.tree2_log_sizes_sha256);
}

fn hashEstimate(hash: *Sha256, estimate: residency.Estimate) void {
    hashInt(hash, u64, estimate.column_count);
    hashInt(hash, u64, estimate.source_cells);
    hashInt(hash, u64, estimate.extended_cells);
    hashInt(hash, u64, estimate.source_bytes);
    hashInt(hash, u64, estimate.retained_coefficient_bytes);
    hashInt(hash, u64, estimate.extended_evaluation_bytes);
    hashInt(hash, u64, estimate.minimum_resident_bytes);
    hashInt(hash, u32, estimate.max_column_log_size);
    hashInt(hash, u32, estimate.log_blowup_factor);
    hashInt(hash, u8, @intFromEnum(estimate.retention_policy));
}

fn logSizesSha256(log_sizes: []const u32) Digest {
    var hash = Sha256.init(.{});
    for (log_sizes) |log_size| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, log_size, .little);
        hash.update(&bytes);
    }
    return hash.finalResult();
}

fn hashBool(hash: *Sha256, value: bool) void {
    hash.update(&.{@intFromBool(value)});
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn count(value: usize) !u64 {
    return std.math.cast(u64, value) orelse
        error.ProviderResourcePlanOverflow;
}

fn add(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch
        error.ProviderResourcePlanOverflow;
}

pub const testing = struct {
    pub fn createFromGeometryAuthority(
        geometry: GeometryAuthorityV1,
    ) !ProviderResourcePlanV1 {
        return createFromGeometry(geometry);
    }
};

test "real seg0 legacy provider selects ten sequential log20 shards" {
    const geometry = GeometryAuthorityV1{
        .snapshot_file_sha256 = [_]u8{0x01} ** 32,
        .snapshot_content_sha256 = [_]u8{0x02} ** 32,
        .source_request_sha256 = [_]u8{0x03} ** 32,
        .source_segment_sha256 = [_]u8{0x04} ** 32,
        .segment_index = 0,
        .legacy_poseidon = .{
            .infra_index = 2,
            .main_column_offset = 3140,
            .main_column_count = 445,
            .log_size = 24,
            .n_rows = 9_674_526,
        },
        .tree0_column_count = 256,
        .tree0_log_sizes_sha256 = [_]u8{0x05} ** 32,
        .tree1_non_provider_column_count = 9_374,
        .tree1_non_provider_log_sizes_sha256 = [_]u8{0x06} ** 32,
        .tree2_column_count = 9_240,
        .tree2_log_sizes_sha256 = [_]u8{0x07} ** 32,
    };
    const plan = try createFromGeometry(geometry);
    try std.testing.expectEqual(@as(u32, 20), plan.shard_planning.shard_log_size);
    try std.testing.expectEqual(@as(u64, 10), plan.shard_planning.shard_count);
    try std.testing.expectEqual(
        @as(u64, 237_342),
        plan.shard_planning.final_shard_rows,
    );
    try std.testing.expectEqual(
        @as(u64, 3_951_034_368),
        plan.stage_estimate.retained_opening_lower_bound_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 5_616_173_056),
        plan.stage_estimate.commit_transient_lower_bound_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 5_616_173_056),
        plan.stage_estimate.staged_peak_lower_bound_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 22_796_042_240),
        plan.stage_estimate.admitted_provider_peak_bytes,
    );
    try std.testing.expect(plan.ownership.coefficient_retention_never);
    try std.testing.expect(plan.ownership.stage_a_commit_then_teardown);
    try std.testing.expect(!plan.ownership.caller_and_provider_owners_overlap);
    try std.testing.expect(!plan.readiness.production_eligible);
    try std.testing.expect(
        plan.stage_estimate.admitted_provider_peak_bytes < host_byte_budget,
    );

    var mutated = plan;
    mutated.geometry.legacy_poseidon.n_rows -= 1;
    const rebuilt = try createFromGeometry(mutated.geometry);
    try std.testing.expect(!std.meta.eql(plan.identity, rebuilt.identity));
}

test "provider staged estimate includes every tree and commit transient" {
    const estimate = try StageEstimateV1.canonical(1);
    try std.testing.expectEqual(
        @as(u64, 16_777_216),
        estimate.tree0.minimum_resident_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 3_732_930_560),
        estimate.tree1.minimum_resident_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 67_108_864),
        estimate.tree2.minimum_resident_bytes,
    );
    try std.testing.expectEqual(
        @as(u64, 134_217_728),
        estimate.composition.minimum_resident_bytes,
    );
    try std.testing.expectEqual(
        residency.RetentionPolicy.never,
        estimate.tree1.retention_policy,
    );
}
