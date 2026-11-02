//! Shape-only resident contract for the actual OM31 route. This does not admit
//! a GPU job: no OM device kernels or allocation lifetime is qualified here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("../roster.zig");
const P = @import("../protocol.zig");
const W = @import("worker_protocol.zig");
const Retention = @import("retention_plan.zig");
const TruthRetention = @import("truth_retention.zig");
const Cpu = @import("cpu_components.zig");
const Truth = @import("truth_components.zig");
const Residency = engine.pcs.residency_estimate;
const BASE_BYTES = @sizeOf(core.fields.m31.M31);
const SECURE_BYTES = @sizeOf(W.O);
const DEGREE = SECURE_BYTES / BASE_BYTES;
// The compact target shares native incremental PCS storage authority. Uniform
// counters/backend metadata are per wave, not replicated at every leaf.
const PROGRESSIVE_STATE_BYTES = @sizeOf(engine.vcs_lifted.compact_blake_state.State);
fn add(x: u64, y: u64) !u64 {
    return std.math.add(u64, x, y);
}
fn mul(x: u64, y: u64) !u64 {
    return std.math.mul(u64, x, y);
}
fn power(log: u32) !u64 {
    if (log > 30) return error.InvalidResidentLayoutGeometry;
    return @as(u64, 1) << @intCast(log);
}
pub const Tree = struct {
    columns: u64,
    max_native_log: u32,
    coefficient_bytes: u64,
    lde_bytes: u64,
    full_merkle_node_bytes: u64,
    retained_contract_bytes: u64,
    compact_pruned_node_bytes: u64 = 0,
    compact_coefficient_resident_bytes: u64 = 0,
    streaming_native_tile_bytes: u64 = 0,
    streaming_lde_tile_bytes: u64 = 0,
    streaming_hash_state_upper_bytes: u64 = 0,
    pub fn fromLogs(logs: []const u32, beta: u32) !Tree {
        if (beta < 1 or beta > 2) return error.InvalidResidentLayoutGeometry;
        if (logs.len == 0) return .{ .columns = 0, .max_native_log = 0, .coefficient_bytes = 0, .lde_bytes = 0, .full_merkle_node_bytes = 0, .retained_contract_bytes = 0 };
        const estimate = try Residency.estimate(logs, beta, .always);
        const nodes = try mul(try std.math.sub(u64, try mul(try power(try std.math.add(u32, estimate.max_column_log_size, beta)), 2), 1), @sizeOf(W.H.Hash));
        const domain_log = try std.math.add(u32, estimate.max_column_log_size, beta);
        const retained_log = if (domain_log >= 20) domain_log - 4 else domain_log;
        const pruned_nodes = try mul(try std.math.sub(u64, try mul(try power(retained_log), 2), 1), @sizeOf(W.H.Hash));
        const tile_columns = @min(64, estimate.column_count);
        return .{ .columns = estimate.column_count, .max_native_log = estimate.max_column_log_size, .coefficient_bytes = estimate.retained_coefficient_bytes, .lde_bytes = estimate.extended_evaluation_bytes, .full_merkle_node_bytes = nodes, .retained_contract_bytes = try add(estimate.minimum_resident_bytes, nodes), .compact_pruned_node_bytes = pruned_nodes, .compact_coefficient_resident_bytes = try add(estimate.retained_coefficient_bytes, pruned_nodes), .streaming_native_tile_bytes = try mul(try mul(tile_columns, try power(estimate.max_column_log_size)), BASE_BYTES), .streaming_lde_tile_bytes = try mul(try mul(tile_columns, try power(domain_log)), BASE_BYTES), .streaming_hash_state_upper_bytes = try mul(try power(domain_log), PROGRESSIVE_STATE_BYTES) };
    }
};
pub const Contract = struct {
    beta: u32,
    secure_coordinates: usize = DEGREE,
    secure_value_bytes: usize = SECURE_BYTES,
    composition_split: u32,
    max_trace_log: u32,
    // FIXED is immutable identity-owned; MAIN/INTER/composition are worker-owned.
    trees: [4]Tree,
    binding_planes_per_local_role: u32 = @import("binding.zig").INTERACTION_COLUMNS,
    binding_bytes: u64,
    narrow_global_metadata_bytes: u64,
    local_proof_reserve_bytes: u64,
    local_gkr_peak_bytes: u64,
    composition_domain_log: u32,
    composition_secure_evaluation_bytes: u64,
    fri_initial_domain_log: u32,
    fri_initial_secure_bytes: u64,
    fri_all_secure_layers_upper_bytes: u64,
    fri_all_full_merkle_nodes_upper_bytes: u64,
    lifted_leaf_base_words_per_query: u64,
    secure_oods_samples_lower_bound: u64,
    secure_oods_samples_upper_bound: u64,
    secure_oods_samples_exact: ?u64 = null,
    compact: struct {
        streaming_column_cap: u32 = 64,
        progressive_state_bytes_per_leaf_upper: usize = PROGRESSIVE_STATE_BYTES,
        retained_main_bytes: u64,
        retained_inter_bytes: u64,
        retained_composition_bytes: u64,
        role_coset_shared_current_previous_upper_bytes: u64,
        deep_secure_aggregate_bytes: u64,
        main_commit_separate_buffers: u64,
        local_gkr_seal_with_retained_main: u64,
        sealed_manifest_barrier: u64,
        inter_commit_separate_buffers: u64,
        composition_one_coset: u64,
        composition_commit_separate_buffers: u64,
        deep_and_fri_upper: u64,
    },
    phases: struct {
        // Each excludes independently shared FIXED and unmodeled local source
        // query/capture metadata, allocator/runtime and extra PCS scratch. Known
        // global metadata/proof reserves are included where already live. These
        // are explicit separate-buffer contracts, not irreducible peaks.
        main_commit_separate_buffers: u64,
        local_gkr_seal_with_retained_main: u64,
        sealed_manifest_barrier: u64,
        inter_commit_separate_buffers: u64,
        composition_separate_buffers: u64,
        opening_fri_full_retention_upper: u64,
    },
    /// Necessary budget for the represented compact phase buffers only. Shared
    /// FIXED, local source-query metadata, extra PCS/runtime scratch and other
    /// queued workers require separate leases before any device admission.
    pub fn requireCompactRepresentedBudget(self: Contract, bytes: u64) !void {
        var maximum: u64 = 0;
        inline for (.{ "main_commit_separate_buffers", "local_gkr_seal_with_retained_main", "sealed_manifest_barrier", "inter_commit_separate_buffers", "composition_one_coset", "composition_commit_separate_buffers", "deep_and_fri_upper" }) |field| maximum = @max(maximum, @field(self.compact, field));
        if (bytes < maximum) return error.CompactRepresentedBudgetExceeded;
    }
    pub fn requireRetainedPcsBudget(self: Contract, bytes: u64) !void {
        const resident = try add(try add(self.trees[1].retained_contract_bytes, self.trees[2].retained_contract_bytes), self.trees[3].retained_contract_bytes);
        if (bytes < resident) return error.ResidentPcsContractBudgetExceeded;
    }
};
fn finish(fixed: []const u32, main: []const u32, inter: []const u32, beta: u32, split: u32, retained: Retention.RetentionPlan, role_coset_bytes: u64) !Contract {
    if (main.len == 0 or inter.len == 0 or split < 1 or split > 2) return error.InvalidResidentLayoutGeometry;
    var trees: [4]Tree = undefined;
    trees[0] = try Tree.fromLogs(fixed, beta);
    trees[1] = try Tree.fromLogs(main, beta);
    trees[2] = try Tree.fromLogs(inter, beta);
    const max_log = @max(trees[1].max_native_log, @max(trees[0].max_native_log, trees[2].max_native_log));
    const composition_columns = core.verifier_types.compositionColumnCount(split, DEGREE) orelse return error.InvalidResidentLayoutGeometry;
    var composition_logs: [32]u32 = undefined;
    if (composition_columns > composition_logs.len) return error.InvalidResidentLayoutGeometry;
    @memset(composition_logs[0..composition_columns], max_log);
    trees[3] = try Tree.fromLogs(composition_logs[0..composition_columns], beta);
    const composition_log = try std.math.add(u32, max_log, split);
    const composition_bytes = try mul(try power(composition_log), SECURE_BYTES);
    const fri_log = try std.math.add(u32, max_log, beta);
    const fri_bytes = try mul(try power(fri_log), SECURE_BYTES);
    const committed = try add(try add(trees[1].retained_contract_bytes, trees[2].retained_contract_bytes), trees[3].retained_contract_bytes);
    var leaf_words: u64 = 0;
    for (trees) |tree| leaf_words = try add(leaf_words, tree.columns);
    // One sample per MAIN/INTER/composition column is unavoidable here. This
    // upper bound counts all committed FIXED and worst five-point MAIN masks;
    // it is deliberately not advertised as exact serialized proof bytes.
    const sample_lower = try add(try add(trees[1].columns, trees[2].columns), trees[3].columns);
    const sample_upper = try add(try add(trees[0].columns, try mul(trees[1].columns, 5)), try add(try mul(trees[2].columns, 2), trees[3].columns));
    const metadata = try add(retained.global_metadata_bytes, retained.local_proof_reserve_bytes);
    const compact_main = trees[1].compact_coefficient_resident_bytes;
    const compact_inter = trees[2].compact_coefficient_resident_bytes;
    const compact_composition = trees[3].compact_coefficient_resident_bytes;
    const compact_committed = try add(try add(compact_main, compact_inter), compact_composition);
    const main_commit_work = try add(try add(trees[1].streaming_native_tile_bytes, trees[1].streaming_lde_tile_bytes), try add(trees[1].streaming_hash_state_upper_bytes, trees[1].full_merkle_node_bytes));
    const inter_commit_work = try add(try add(trees[2].streaming_native_tile_bytes, trees[2].streaming_lde_tile_bytes), try add(trees[2].streaming_hash_state_upper_bytes, trees[2].full_merkle_node_bytes));
    const composition_commit_work = try add(try add(trees[3].streaming_native_tile_bytes, trees[3].streaming_lde_tile_bytes), try add(trees[3].streaming_hash_state_upper_bytes, trees[3].full_merkle_node_bytes));
    const max_tile = @max(trees[1].streaming_lde_tile_bytes, @max(trees[2].streaming_lde_tile_bytes, trees[3].streaming_lde_tile_bytes));
    return .{ .beta = beta, .composition_split = split, .max_trace_log = max_log, .trees = trees, .binding_bytes = retained.binding_bytes, .narrow_global_metadata_bytes = retained.global_metadata_bytes, .local_proof_reserve_bytes = retained.local_proof_reserve_bytes, .local_gkr_peak_bytes = retained.gkr_peak_bytes, .composition_domain_log = composition_log, .composition_secure_evaluation_bytes = composition_bytes, .fri_initial_domain_log = fri_log, .fri_initial_secure_bytes = fri_bytes, .fri_all_secure_layers_upper_bytes = try mul(fri_bytes, 2), .fri_all_full_merkle_nodes_upper_bytes = try mul(try power(fri_log), 4 * @sizeOf(W.H.Hash)), .lifted_leaf_base_words_per_query = leaf_words, .secure_oods_samples_lower_bound = sample_lower, .secure_oods_samples_upper_bound = sample_upper, .compact = .{
        .retained_main_bytes = compact_main,
        .retained_inter_bytes = compact_inter,
        .retained_composition_bytes = compact_composition,
        .role_coset_shared_current_previous_upper_bytes = role_coset_bytes,
        .deep_secure_aggregate_bytes = fri_bytes,
        .main_commit_separate_buffers = try add(try add(try mul(trees[1].coefficient_bytes, 2), main_commit_work), retained.global_metadata_bytes),
        .local_gkr_seal_with_retained_main = try add(try add(compact_main, retained.gkr_peak_bytes), retained.global_metadata_bytes),
        .sealed_manifest_barrier = try add(compact_main, try add(retained.binding_bytes, metadata)),
        .inter_commit_separate_buffers = try add(try add(try add(compact_main, try mul(trees[2].coefficient_bytes, 2)), inter_commit_work), metadata),
        .composition_one_coset = try add(try add(try add(compact_committed, role_coset_bytes), composition_bytes), metadata),
        .composition_commit_separate_buffers = try add(try add(try add(try add(compact_main, compact_inter), try mul(trees[3].coefficient_bytes, 2)), composition_commit_work), metadata),
        .deep_and_fri_upper = try add(try add(try add(compact_committed, max_tile), try add(try mul(fri_bytes, 2), try mul(try power(fri_log), 4 * @sizeOf(W.H.Hash)))), metadata),
    }, .phases = .{
        .main_commit_separate_buffers = try add(try add(trees[1].retained_contract_bytes, trees[1].coefficient_bytes), retained.global_metadata_bytes),
        .local_gkr_seal_with_retained_main = try add(try add(trees[1].retained_contract_bytes, retained.gkr_peak_bytes), retained.global_metadata_bytes),
        .sealed_manifest_barrier = try add(trees[1].retained_contract_bytes, try add(retained.binding_bytes, metadata)),
        .inter_commit_separate_buffers = try add(try add(try add(trees[1].retained_contract_bytes, trees[2].retained_contract_bytes), trees[2].coefficient_bytes), metadata),
        .composition_separate_buffers = try add(try add(committed, composition_bytes), metadata),
        .opening_fri_full_retention_upper = try add(try add(committed, try add(try mul(fri_bytes, 2), try mul(try power(fri_log), 4 * @sizeOf(W.H.Hash)))), metadata),
    } };
}
pub fn forCpu(a: std.mem.Allocator, setup: *const R.CpuSetup, request: P.Request, config: W.PcsConfig) !Contract {
    var plan = try Cpu.Plan.init(a, setup);
    defer plan.deinit();
    const fixed = try setup.logs(a, 0);
    defer a.free(fixed);
    const main = try setup.logs(a, 1);
    defer a.free(main);
    const inter = try plan.interLogs(a);
    defer a.free(inter);
    const retained = try Retention.forCpu(a, setup, request, config, std.math.maxInt(usize), std.math.maxInt(usize));
    var role_coset_bytes: u64 = 0;
    var sample_upper: u64 = 0;
    for (plan.slots) |slot| {
        const descriptor = try @import("shape_metadata.zig").forOrigin(slot.origin);
        var width: u64 = 0;
        for (descriptor.widths) |count| width = try add(width, count);
        role_coset_bytes = @max(role_coset_bytes, try mul(try mul(width, try power(slot.log)), BASE_BYTES));
        sample_upper = try add(sample_upper, try mul(width, descriptor.max_samples));
    }
    var result = try finish(fixed, main, inter, config.fri_config.log_blowup_factor, 1, retained, role_coset_bytes);
    result.secure_oods_samples_upper_bound = try add(sample_upper, result.trees[3].columns);
    return result;
}
pub fn forTruth(a: std.mem.Allocator, truth: R.Truth, config: W.PcsConfig) !Contract {
    const shapes = try Truth.shapesForDeclaration(@import("../wire.zig").TruthDeclaration.from(truth));
    var counts: [3]usize = @splat(0);
    for (shapes) |role| for (role.widths(), &counts) |width, *count| {
        count.* = try std.math.add(usize, count.*, width);
    };
    const fixed = try a.alloc(u32, counts[0]);
    defer a.free(fixed);
    const main = try a.alloc(u32, counts[1]);
    defer a.free(main);
    const inter = try a.alloc(u32, counts[2]);
    defer a.free(inter);
    const trees = [_][]u32{ fixed, main, inter };
    var offsets: [3]usize = @splat(0);
    var role_coset_bytes: u64 = 0;
    var mask_samples: u64 = 0;
    for (shapes) |role| {
        var width: u64 = 0;
        for (role.widths(), trees, &offsets, 0..) |count, tree, *offset, part| {
            @memset(tree[offset.*..][0..count], role.log_size);
            offset.* += count;
            width = try add(width, count);
            for (0..count) |column| mask_samples = try add(mask_samples, role.shifts(part, column).len);
        }
        role_coset_bytes = @max(role_coset_bytes, try mul(try mul(width, try power(role.log_size)), BASE_BYTES));
    }
    const retained = try TruthRetention.forTruth(a, truth, config, std.math.maxInt(usize));
    var result = try finish(fixed, main, inter, config.fri_config.log_blowup_factor, if (truth == .keccak) 2 else 1, retained, role_coset_bytes);
    mask_samples = try add(mask_samples, result.trees[3].columns);
    result.secure_oods_samples_lower_bound = mask_samples;
    result.secure_oods_samples_upper_bound = mask_samples;
    result.secure_oods_samples_exact = mask_samples;
    return result;
}

test "resident OM layout preserves eight coordinates and separates beta from composition split" {
    const first = try finish(&.{5}, &.{ 5, 6 }, &.{6}, 1, 1, .{ .binding_bytes = 16 * 64 * 4 }, 4096);
    const second = try finish(&.{5}, &.{ 5, 6 }, &.{6}, 2, 1, .{ .binding_bytes = 16 * 64 * 4 }, 4096);
    try std.testing.expectEqual(@as(usize, 96), first.compact.progressive_state_bytes_per_leaf_upper);
    try std.testing.expectEqual(@as(usize, 8), first.secure_coordinates);
    try std.testing.expectEqual(@as(usize, 32), first.secure_value_bytes);
    try std.testing.expectEqual(@as(u64, 16), first.trees[3].columns);
    try std.testing.expectEqual(@as(u64, 16 * 64 * 4), first.binding_bytes);
    try std.testing.expectEqual(@as(u32, 7), first.composition_domain_log);
    try std.testing.expectEqual(@as(u64, 128 * 32), first.composition_secure_evaluation_bytes);
    for (first.trees, second.trees) |a, b| {
        try std.testing.expectEqual(a.coefficient_bytes, b.coefficient_bytes);
        try std.testing.expectEqual(2 * a.lde_bytes, b.lde_bytes);
        try std.testing.expectEqual((@as(u64, 1) << @intCast(a.max_native_log + 1)) * 96, a.streaming_hash_state_upper_bytes);
        try std.testing.expectEqual(2 * a.streaming_hash_state_upper_bytes, b.streaming_hash_state_upper_bytes);
        try std.testing.expect(b.full_merkle_node_bytes > a.full_merkle_node_bytes);
    }
    const keccak = try finish(&.{5}, &.{6}, &.{6}, 1, 2, .{}, 4096);
    try std.testing.expectEqual(@as(u64, 32), keccak.trees[3].columns);
    try std.testing.expectEqual(@as(u32, 8), keccak.composition_domain_log);
    try std.testing.expectEqual(@as(u64, 256 * 32), keccak.composition_secure_evaluation_bytes);
    try std.testing.expectEqual(@as(u64, 128 * 4), keccak.trees[2].streaming_lde_tile_bytes);
    const empty = try Tree.fromLogs(&.{}, 2);
    try std.testing.expectEqual(@as(u64, 0), empty.streaming_hash_state_upper_bytes);
    const tile = try Tree.fromLogs(&([_]u32{18} ** 64), 2);
    try std.testing.expectEqual(@as(u64, 256 << 20), tile.streaming_lde_tile_bytes);
    try std.testing.expect(keccak.compact.retained_main_bytes < keccak.trees[1].retained_contract_bytes);
    // Split increases the composition cosets/columns, not the separate trace
    // commitment's beta. FRI starts from the highest committed LDE height.
    try std.testing.expectEqual(@as(u32, 7), keccak.fri_initial_domain_log);
    try std.testing.expectError(error.ResidentPcsContractBudgetExceeded, first.requireRetainedPcsBudget(1));
    try first.requireRetainedPcsBudget(std.math.maxInt(u64));
    try std.testing.expectError(error.CompactRepresentedBudgetExceeded, first.requireCompactRepresentedBudget(1));
    try first.requireCompactRepresentedBudget(std.math.maxInt(u64));
    try std.testing.expectError(error.InvalidResidentLayoutGeometry, Tree.fromLogs(&.{5}, 0));
    try std.testing.expectError(error.InvalidResidentLayoutGeometry, Tree.fromLogs(&.{30}, 2));
    try std.testing.expectError(error.InvalidResidentLayoutGeometry, finish(&.{}, &.{}, &.{5}, 1, 1, .{}, 0));
}
