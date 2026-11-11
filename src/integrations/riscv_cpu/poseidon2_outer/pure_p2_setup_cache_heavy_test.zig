//! Optional real heavy source-only session. No MAIN/GKR/proving is invoked.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Runtime = @import("pure_p2_op_runtime.zig");
const C = @import("pure_p2_setup_cache.zig");
const Request = @import("../rv64_ethereum_request.zig");
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
const a = std.testing.allocator;
const Receipt = struct {
    steps: u64,
    cpu_workers: usize,
    truth_workers: usize,
    miller_workers: usize,
    cpu_fixed_classes: usize,
    unique_poseidon_fixed_roots: usize,
    unique_legacy_fixed_roots: usize,
    fixed_root_distribution: []const Runtime.FixedRootRecord,
    metadata_sha256: [32]u8,
    initial_cells_sha256: [32]u8,
    terminal_cells_sha256: [32]u8,
    final_pc: u64,
    final_registers: [32]u64,
    output: [43]u8,
    source_cells: [3]u64,
    setup_and_admission_ns: u64,
    capture_ns: u64,
    actual_immutable_fixed_disk_bytes: usize,
    actual_fixed_mapping_bytes: usize,
};
fn loadReceipt(path: []const u8) !std.json.Parsed(Receipt) {
    var dir = try std.fs.cwd().openDir(path, .{});
    defer dir.close();
    const bytes = try dir.readFileAlloc(a, "native-op-prepare.json", 1 << 20);
    defer a.free(bytes);
    return std.json.parseFromSlice(Receipt, a, bytes, .{ .ignore_unknown_fields = true });
}

test "OP heavy source session reuses all immutable classes across fresh prepare requests" {
    const config_path = std.posix.getenv("STWO_OP_NATIVE_PREPARE_REQUEST") orelse return error.SkipZigTest;
    const output = std.posix.getenv("STWO_OP_NATIVE_PREPARE_OUTPUT") orelse return error.SkipZigTest;
    const frozen_path = std.posix.getenv("STWO_OP_NATIVE_PREPARE_FROZEN") orelse return error.SkipZigTest;
    const config_bytes = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(config_bytes);
    const parsed = try std.json.parseFromSlice(Request.Config, a, config_bytes, .{});
    defer parsed.deinit();
    const frozen_bytes = try std.fs.cwd().readFileAlloc(a, frozen_path, 8 << 20);
    defer a.free(frozen_bytes);
    const frozen = try std.json.parseFromSlice(struct { metadata: Runtime.Metadata, steps: u64, final_pc: u64, final_registers: [32]u64, cells: [3]u64 }, a, frozen_bytes, .{ .ignore_unknown_fields = true });
    defer frozen.deinit();
    const canonical = try std.json.Stringify.valueAlloc(a, frozen.value.metadata, .{});
    defer a.free(canonical);
    var frozen_metadata_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(canonical, &frozen_metadata_hash, .{});
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 32 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try std.fs.cwd().makePath(output);
    var out = try std.fs.cwd().openDir(output, .{});
    defer out.close();
    const cache_path = try std.fs.path.join(a, &.{ output, "source-owned-fixed" });
    defer a.free(cache_path);
    const cache_limits = C.Limits{ .heap_bytes = 4 << 30, .disk_bytes = 52 << 30, .mapped_bytes = 1 << 30, .entries = 64, .metadata_bytes = 256 << 20 };
    var cache = try C.Cache.init(alloc, cache_path, cache_limits);
    var cache_alive = true;
    defer if (cache_alive) cache.deinit();
    const resources = Runtime.Resources{};
    const cold_path = try std.fs.path.join(a, &.{ output, "cold" });
    defer a.free(cold_path);
    const warm_path = try std.fs.path.join(a, &.{ output, "warm" });
    defer a.free(warm_path);
    const profile = Profile.op_target_b4_q72_p0_fold4_v1;
    var timer = try std.time.Timer.start();
    Runtime.prepareDirectoryWithCache(alloc, parsed.value, cold_path, profile, resources, &cache) catch |err| {
        try @import("../word16_execution/driver.zig").writeJson(a, out, "failure.json", .{ .phase = "cold", .error_name = @errorName(err), .cache = cache.snapshot(), .common_heap = budget.snapshot(), .proof_verified = false });
        return err;
    };
    const cold_ns = timer.read();
    const cold = cache.snapshot();
    const cold_parent = budget.snapshot();
    try std.testing.expectEqual(@as(usize, 36), cold.entries);
    try std.testing.expectEqual(@as(u64, 36), cold.misses);
    try std.testing.expectEqual(@as(u64, 0), cold.hits);
    try std.testing.expect(cold.active_leases == 0 and cold.owned_views == 0 and cold.mapped_bytes == 0 and !cold.heap.exceeded);
    timer.reset();
    Runtime.prepareDirectoryWithCache(alloc, parsed.value, warm_path, profile, resources, &cache) catch |err| {
        try @import("../word16_execution/driver.zig").writeJson(a, out, "failure.json", .{ .phase = "warm", .error_name = @errorName(err), .cache = cache.snapshot(), .common_heap = budget.snapshot(), .proof_verified = false });
        return err;
    };
    const warm_ns = timer.read();
    const warm = cache.snapshot();
    const warm_parent = budget.snapshot();
    try std.testing.expectEqual(cold.entries, warm.entries);
    try std.testing.expectEqual(cold.misses, warm.misses);
    try std.testing.expectEqual(@as(u64, 36), warm.hits);
    try std.testing.expectEqual(cold.parked_bytes, warm.parked_bytes);
    try std.testing.expect(warm.active_leases == 0 and warm.owned_views == 0 and warm.mapped_bytes == 0 and !warm.heap.exceeded and !warm_parent.exceeded);
    const r0 = try loadReceipt(cold_path);
    defer r0.deinit();
    const r1 = try loadReceipt(warm_path);
    defer r1.deinit();
    try std.testing.expectEqual(frozen.value.steps, r0.value.steps);
    try std.testing.expectEqual(@as(u64, 238226172), r0.value.steps);
    try std.testing.expectEqual(@as(usize, 57), r0.value.cpu_workers);
    try std.testing.expectEqual(@as(usize, 13), r0.value.truth_workers);
    try std.testing.expectEqual(@as(usize, 22), r0.value.miller_workers);
    try std.testing.expectEqualSlices(u8, &frozen_metadata_hash, &r0.value.metadata_sha256);
    try std.testing.expectEqual(frozen.value.final_pc, r0.value.final_pc);
    try std.testing.expectEqualSlices(u64, &frozen.value.final_registers, &r0.value.final_registers);
    try std.testing.expectEqualSlices(u64, &frozen.value.cells, &r0.value.source_cells);
    try std.testing.expectEqualSlices(u8, &r0.value.metadata_sha256, &r1.value.metadata_sha256);
    try std.testing.expectEqualSlices(u8, &r0.value.initial_cells_sha256, &r1.value.initial_cells_sha256);
    try std.testing.expectEqualSlices(u8, &r0.value.terminal_cells_sha256, &r1.value.terminal_cells_sha256);
    try std.testing.expectEqualSlices(u8, &r0.value.output, &r1.value.output);
    try std.testing.expectEqualSlices(u64, &r0.value.final_registers, &r1.value.final_registers);
    try std.testing.expectEqualDeep(r0.value.fixed_root_distribution, r1.value.fixed_root_distribution);
    try std.testing.expectEqual(@as(usize, 0), r0.value.actual_fixed_mapping_bytes);
    try std.testing.expectEqual(@as(usize, 0), r1.value.actual_fixed_mapping_bytes);
    cache.deinit();
    cache_alive = false;
    const final = budget.snapshot();
    try std.testing.expectEqual(@as(usize, 0), final.live_bytes);
    try std.testing.expectEqual(@as(usize, 0), final.external_live_bytes);
    try @import("../word16_execution/driver.zig").writeJson(a, out, "session.json", .{ .schema = "op-native-heavy-immutable-session/v1", .proof_verified = false, .production_admitted = false, .source_metadata_matches_frozen = true, .fresh_capture_public_cells_and_terminal_match = true, .cold_wall_ns = cold_ns, .warm_wall_ns = warm_ns, .cold_cache = cold, .warm_cache = warm, .cold_common_heap_after_request = cold_parent, .warm_common_heap_after_request = warm_parent, .final_common_heap = final, .cache_limits = cache_limits, .resources = resources });
    std.debug.print("OP_HEAVY_IMMUTABLE_SESSION source_only=true cold_ns={} warm_ns={} entries={} misses={} hits={} parked={} uniqueP2={} uniqueBlake={} final_heap={} final_external={}\n", .{ cold_ns, warm_ns, warm.entries, warm.misses, warm.hits, warm.parked_bytes, r0.value.unique_poseidon_fixed_roots, r0.value.unique_legacy_fixed_roots, final.live_bytes, final.external_live_bytes });
}
