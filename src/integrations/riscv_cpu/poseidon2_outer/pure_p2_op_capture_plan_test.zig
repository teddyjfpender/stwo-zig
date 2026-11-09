//! Actual-small control for shared capture/setup extraction. No outer root.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("pure_p2_op_runtime.zig");
test "OP shared capture plan preserves actual classic native bundle bytes" {
    const config_path = std.posix.getenv("STWO_OP_CAPTURE_PLAN_CONFIG") orelse return error.SkipZigTest;
    const old_path = std.posix.getenv("STWO_OP_CAPTURE_PLAN_CONTROL") orelse return error.MissingOpNativeDirectory;
    const out_path = std.posix.getenv("STWO_OP_CAPTURE_PLAN_OUT") orelse return error.MissingOpNativeDirectory;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const parsed = try std.json.parseFromSlice(@import("../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.SmallCapturePlanControlRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    {
        const a = budget.allocator();
        try Runtime.produceDirectory(a, parsed.value, out_path, .op_target_b4_q72_p0_fold4_v1, .{});
        var old = try std.fs.cwd().openDir(old_path, .{});
        defer old.close();
        var fresh = try std.fs.cwd().openDir(out_path, .{});
        defer fresh.close();
        for ([_][]const u8{ "native-op.bin", "native-op.json", "cells.bin" }) |name| {
            const before = try old.readFileAlloc(a, name, 64 << 20);
            defer a.free(before);
            const after = try fresh.readFileAlloc(a, name, 64 << 20);
            defer a.free(after);
            try std.testing.expectEqualSlices(u8, before, after);
        }
        try Runtime.verifyDirectory(a, parsed.value, out_path, .op_target_b4_q72_p0_fold4_v1, .{});
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    std.debug.print("OP_CAPTURE_PLAN_CONTROL exact_native_bytes=true exact_metadata=true exact_cells=true fresh_received=true peak={}\n", .{budget.snapshot().peak_live_bytes});
}
