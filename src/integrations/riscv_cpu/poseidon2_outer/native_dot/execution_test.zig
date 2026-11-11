//! Explicit complete actual-small R7 execution root qualification.
const std = @import("std");
const E = @import("stwo_prover_engine");
test "OP R7 complete actual small execution root with source-only fresh receiver" {
    const config_path = std.posix.getenv("STWO_OP_R7_ROOT_CONFIG") orelse return error.SkipZigTest;
    const native_path = std.posix.getenv("STWO_OP_R7_ROOT_NATIVE") orelse return error.MissingOpNativeDirectory;
    const output_path = std.posix.getenv("STWO_OP_R7_ROOT_OUT") orelse return error.MissingR7RootOutput;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const config = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer config.deinit();
    if (config.value.max_steps > 10_000_000) return error.R7SmallRootFixtureRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var bound = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer bound.deinit();
    {
        const a = budget.allocator();
        var root = try @import("execution_collect.zig").proveDirectory(a, config.value, native_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{}, .{ .artifact_directory = output_path, .retained_cpu_leaf = std.posix.getenv("STWO_OP_R7_ROOT_RETAINED_CPU") });
        defer root.deinit();
        try std.testing.expectEqual(@as(usize, 3), root.members);
        try std.testing.expectEqual(@as(usize, 2), root.reductions);
        var original = try std.fs.cwd().openDir(native_path, .{});
        defer original.close();
        var artifacts = try std.fs.cwd().openDir(output_path, .{});
        defer artifacts.close();
        try artifacts.makeDir("source-only");
        var source = try artifacts.openDir("source-only", .{});
        defer source.close();
        try original.copyFile("native-op.json", source, "native-op.json", .{});
        try original.copyFile("cells.bin", source, "cells.bin", .{});
        try std.testing.expectError(error.FileNotFound, source.access("native-op.bin", .{}));
        const path = try std.fs.path.join(a, &.{ output_path, "source-only" });
        defer a.free(path);
        const fresh = try @import("execution_runtime.zig").qualifyDirectory(a, config.value, path, output_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{}, .{});
        try std.testing.expectEqual(root.members, fresh.members);
        std.debug.print("OP_R7_COMPLETE_ROOT members={} reductions={} retained={} root_bytes={} incremental_ns={} source_ns={} fresh_ns={} peak={} security_qualified=false\n", .{ root.members, root.reductions, root.retained_leaves, root.proof.len, root.total_ns, fresh.source_ns, fresh.root_verify_ns, budget.snapshot().peak_live_bytes });
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}

test "OP R7 fresh root-only receiver reuses durable execution artifacts" {
    const config_path = std.posix.getenv("STWO_OP_R7_VERIFY_CONFIG") orelse return error.SkipZigTest;
    const source_path = std.posix.getenv("STWO_OP_R7_VERIFY_SOURCE") orelse return error.MissingOpNativeDirectory;
    const root_path = std.posix.getenv("STWO_OP_R7_VERIFY_ROOT") orelse return error.MissingR7RootOutput;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const config = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer config.deinit();
    if (config.value.max_steps > 10_000_000) return error.R7SmallRootFixtureRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var bound = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer bound.deinit();
    const fresh = @import("execution_runtime.zig").qualifyDirectory(budget.allocator(), config.value, source_path, root_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{}, .{}) catch |err| {
        std.debug.print("OP_R7_FRESH_FAILED {s}\n", .{@errorName(err)});
        return err;
    };
    try std.testing.expectEqual(@as(usize, 3), fresh.members);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    std.debug.print("OP_R7_ROOT_FRESH_COMPLETE bytes={} source_ns={} verify_ns={} peak={} native_proof_absent=true\n", .{ fresh.root_bytes, fresh.source_ns, fresh.root_verify_ns, budget.snapshot().peak_live_bytes });
}
