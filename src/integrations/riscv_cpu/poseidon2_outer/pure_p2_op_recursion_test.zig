//! Explicit opt-in real-block native-to-recursive-root physical qualification.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Request = @import("../rv64_ethereum_request.zig");
test "OP pure P2 complete real block physical recursive root" {
    const config_path = std.posix.getenv("STWO_OP_P2_ROOT_CONFIG") orelse return error.SkipZigTest;
    const native_path = std.posix.getenv("STWO_OP_P2_ROOT_NATIVE") orelse return error.MissingOpP2RootNativeDirectory;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const config = try std.json.parseFromSlice(Request.Config, std.testing.allocator, raw, .{});
    defer config.deinit();
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var result = try @import("pure_p2_op_recursion.zig").proveDirectory(budget.allocator(), config.value, native_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{});
    defer result.deinit();
    try std.testing.expect(result.members != 0);
    try std.testing.expectEqual(result.members - 1, result.reductions);
}
