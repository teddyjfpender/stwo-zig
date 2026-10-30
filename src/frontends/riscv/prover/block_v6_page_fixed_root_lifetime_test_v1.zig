const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Page = @import("block_v5_memory_source_unified_page_proof_v1.zig");
const Suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Column = engine.pcs.ColumnEvaluation;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, Suite.Hasher, Suite.MerkleChannel);

test "PAGE independent fixed roots preserve roots and transcript while retiring prior trees" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 3) };
    var values: [3][]M = undefined;
    var initialized: usize = 0;
    defer for (values[0..initialized]) |column| a.free(column);
    var columns: [3][1]Column = undefined;
    for (&values, &columns, 0..) |*column, *shape, index| {
        const log: u32 = @intCast(9 + index);
        column.* = try a.alloc(M, @as(usize, 1) << @intCast(log));
        initialized += 1;
        for (column.*, 0..) |*value, row| value.* = M.fromCanonical(@intCast(17 * row + index));
        shape.* = .{.{ .log_size = log, .values = column.* }};
    }
    const groups = [_][]const Column{ &columns[0], &columns[1], &columns[2] };
    var baseline_budget = engine.host_budget_allocator.HostBudgetAllocator.init(a, 64 << 20);
    const baseline_allocator = baseline_budget.allocator();
    var baseline = try Scheme.init(baseline_allocator, config);
    var baseline_live = true;
    defer if (baseline_live) baseline.deinit(baseline_allocator);
    baseline.setCoefficientRetentionPolicy(.never);
    var baseline_channel = Suite.Channel{};
    for (groups) |group| try baseline.commitBorrowedStreaming(baseline_allocator, group, 16, &baseline_channel);
    var roots = try baseline.roots(a);
    defer roots.deinit(a);
    const old_peak = baseline_budget.peak_live_bytes;
    baseline.deinit(baseline_allocator);
    baseline_live = false;
    try std.testing.expectEqual(@as(usize, 0), baseline_budget.live_bytes);

    var sequential_channel = Suite.Channel{};
    for (groups, roots.items) |group, expected| {
        var single = try Scheme.init(a, config);
        defer single.deinit(a);
        single.setCoefficientRetentionPolicy(.never);
        try single.commitBorrowedStreaming(a, group, 16, &sequential_channel);
        var one = try single.roots(a);
        defer one.deinit(a);
        try std.testing.expectEqual(@as(usize, 1), one.items.len);
        try std.testing.expectEqualDeep(expected, one.items[0]);
    }
    try std.testing.expectEqualDeep(baseline_channel, sequential_channel);
    var bounded = engine.host_budget_allocator.HostBudgetAllocator.init(a, 64 << 20);
    try Page.requireFixedRoots(bounded.allocator(), config, &groups, roots.items);
    try std.testing.expectEqual(@as(usize, 0), bounded.live_bytes);
    try std.testing.expect(bounded.peak_live_bytes < old_peak);
    roots.items[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageFixedRoots, Page.requireFixedRoots(a, config, &groups, roots.items));
    roots.items[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedSourcePageFixedRoots, Page.requireFixedRoots(a, config, &groups, roots.items[0..2]));
}
