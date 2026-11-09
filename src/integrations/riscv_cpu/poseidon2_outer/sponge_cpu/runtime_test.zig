const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("runtime.zig");
const Receiver = @import("receiver.zig");
const HookState = struct {
    next: usize = 0,
    completed: bool = false,
    fail: bool = false,
    fn fragment(raw: ?*anyopaque, _: std.mem.Allocator, value: Receiver.Verified) !void {
        const self: *HookState = @ptrCast(@alignCast(raw.?));
        try std.testing.expectEqual(self.next, value.ordinal);
        try std.testing.expectEqual(@as(usize, 4), value.capture.commitments.len);
        self.next += 1;
        if (self.fail) return error.IntentionalDetachedHookFailure;
    }
    fn complete(raw: ?*anyopaque, _: std.mem.Allocator, source: Runtime.SourceDirectory, closed: *const Receiver.Closed) !void {
        const self: *HookState = @ptrCast(@alignCast(raw.?));
        try std.testing.expectEqual(source.inventory.workers.len, self.next);
        try std.testing.expectEqual(source.inventory.workers.len, closed.claims.len);
        self.completed = true;
    }
    fn hooks(self: *HookState) Runtime.ReceptionHooks {
        return .{ .context = self, .complete = complete, .fragments = .{ .context = self, .fragment = fragment } };
    }
};
test "detached actual small native producer and independent receiver" {
    const path = std.posix.getenv("STWO_OP_DETACHED_CONFIG") orelse return error.SkipZigTest;
    const out = std.posix.getenv("STWO_OP_DETACHED_OUT") orelse return error.MissingOpNativeDirectory;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 16384);
    defer std.testing.allocator.free(raw);
    const parsed = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.SmallCapturePlanControlRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var bind = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer bind.deinit();
    const resources = Runtime.Resources{ .park_cpu_metadata = std.posix.getenv("STWO_OP_NATIVE_METADATA_PARKING") != null, .retire_source_auxiliaries = std.posix.getenv("STWO_OP_NATIVE_SOURCE_RETIREMENT") != null };
    try Runtime.produceDirectory(budget.allocator(), parsed.value, out, .op_target_b4_q72_p0_fold4_v1, resources);
    try Runtime.verifyDirectory(budget.allocator(), parsed.value, out, .op_target_b4_q72_p0_fold4_v1, .{});
    var hooks = HookState{};
    try Runtime.verifyDirectoryWithHooks(budget.allocator(), parsed.value, out, .op_target_b4_q72_p0_fold4_v1, .{}, hooks.hooks());
    try std.testing.expect(hooks.completed);
    var failing = HookState{ .fail = true };
    try std.testing.expectError(error.IntentionalDetachedHookFailure, Runtime.verifyDirectoryWithHooks(budget.allocator(), parsed.value, out, .op_target_b4_q72_p0_fold4_v1, .{}, failing.hooks()));
    try std.testing.expectEqual(@as(usize, 1), failing.next);
    try std.testing.expect(!failing.completed);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}

test "detached retained actual native bundle adversarial fresh source receiver" {
    const path = std.posix.getenv("STWO_OP_DETACHED_CONFIG") orelse return error.SkipZigTest;
    const out = std.posix.getenv("STWO_OP_DETACHED_OUT") orelse return error.MissingOpNativeDirectory;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, 16384);
    defer std.testing.allocator.free(raw);
    const parsed = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.SmallCapturePlanControlRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var bind = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer bind.deinit();
    var state = @import("runtime_attacks.zig").State{ .path = out };
    try Runtime.withSourceDirectory(budget.allocator(), parsed.value, out, .op_target_b4_q72_p0_fold4_v1, .{}, &state, @import("runtime_attacks.zig").State.run);
    try std.testing.expectEqual(@as(u32, 7), state.controls);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    std.debug.print("OP_DETACHED_ATTACKS controls={} restored_positive=true live=0 external=0 peak={}\n", .{ state.controls, budget.snapshot().peak_live_bytes });
}
