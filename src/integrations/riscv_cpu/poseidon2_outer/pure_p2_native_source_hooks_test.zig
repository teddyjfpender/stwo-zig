//! Fast native-to-source adapter qualification without proving an outer leaf.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("pure_p2_op_runtime.zig");
const Views = @import("pure_p2_root_source_view.zig");
const Hooks = @import("pure_p2_native_source_hooks.zig");
const State = struct {
    count: usize = 0,
    templates: usize = 0,
    completed: bool = false,
    fail: bool = false,
    fn accept(raw: ?*anyopaque, a: std.mem.Allocator, pending: Views.Pending) !void {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return error.MissingOpRootSession));
        if (self.fail) return error.TestSourceVisitorFailure;
        try std.testing.expectEqual(self.count, pending.ordinal);
        switch (pending.view) {
            inline else => |view| {
                try std.testing.expectEqual(pending.ordinal, view.expected.ordinal);
                try std.testing.expectEqualSlices(u8, &pending.main, &view.main);
            },
        }
        if (pending.template.take()) |bytes| {
            defer a.free(bytes);
            try std.testing.expect(bytes.len > 0);
            self.templates += 1;
        }
        self.count += 1;
    }
    fn complete(raw: ?*anyopaque, _: std.mem.Allocator, v: Runtime.CompleteVerified) !void {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return error.MissingOpRootSession));
        try std.testing.expectEqual(v.inventory.workers.len, self.count);
        self.completed = true;
    }
};
test "OP root shared native source hooks fresh admission and failure cleanup" {
    const config_path = std.posix.getenv("STWO_OP_SOURCE_HOOK_CONFIG") orelse return error.SkipZigTest;
    const native_path = std.posix.getenv("STWO_OP_SOURCE_HOOK_NATIVE") orelse return error.MissingOpNativeDirectory;
    const a = std.testing.allocator;
    const raw = try std.fs.cwd().readFileAlloc(a, config_path, 16384);
    defer a.free(raw);
    const config = try std.json.parseFromSlice(@import("../rv64_ethereum_request.zig").Config, a, raw, .{});
    defer config.deinit();
    if (config.value.max_steps > 10_000_000) return error.SmallSourceHookFixtureRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 8 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var bound = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer bound.deinit();
    var state: State = .{};
    var sink = Views.Sink{ .context = &state, .accept = State.accept };
    try Runtime.verifyDirectoryWithOptions(budget.allocator(), config.value, native_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{}, .{ .context = &state, .complete = State.complete, .fragments = Hooks.hooks(&sink) });
    try std.testing.expect(state.completed and state.count == 3 and state.templates == 1);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    state = .{ .fail = true };
    try std.testing.expectError(error.TestSourceVisitorFailure, Runtime.verifyDirectoryWithOptions(budget.allocator(), config.value, native_path, .op_target_b4_q72_p0_fold4_v1, .{}, .{}, .{ .context = &state, .complete = State.complete, .fragments = Hooks.hooks(&sink) }));
    try std.testing.expect(!state.completed and state.count == 0);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
