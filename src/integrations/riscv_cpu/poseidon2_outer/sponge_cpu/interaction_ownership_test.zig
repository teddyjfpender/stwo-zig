const std = @import("std");
const C = @import("stwo_core");
const E = @import("stwo_prover_engine");
const M = C.fields.m31.M31;
const O = C.fields.om31.OM31;
const Take = @import("interaction_ownership.zig");
const Parts = @import("../../word16_global_execution/services/gkr_local/cpu_components.zig");
const B = @import("../../word16_global_execution/services/gkr_local/witness.zig").Witness;
const G = @import("../../word16_global_execution/services/gkr_local/classic_witness.zig").Witness;
const F = @import("binding.zig").Witness;
const Fixture = struct {
    a: std.mem.Allocator,
    binding: B,
    globals: [2]?G,
    frontier: F,
    slots: [2]Parts.Slot = .{
        .{ .origin = .{ .core = .cpu }, .log = 5, .fixed_offset = 0, .main_offset = 0, .inter_offset = 0, .binding_index = 0, .claim_offset = 0 },
        .{ .origin = .{ .core = .initial }, .log = 5, .fixed_offset = 0, .main_offset = 0, .inter_offset = 16, .binding_index = null, .claim_offset = 0 },
    },
    fn init(a: std.mem.Allocator) !Fixture {
        const bindings = try a.alloc([]M, 1);
        errdefer a.free(bindings);
        bindings[0] = try a.alloc(M, 16 * 32);
        errdefer a.free(bindings[0]);
        @memset(bindings[0], M.fromCanonical(11));
        const global = try a.alloc(M, 16 * 32);
        errdefer a.free(global);
        @memset(global, M.fromCanonical(13));
        const frontier = try a.alloc(M, 24 * 32);
        errdefer a.free(frontier);
        @memset(frontier, M.fromCanonical(17));
        return .{ .a = a, .binding = .{ .allocator = a, .columns = bindings }, .globals = .{ null, .{ .allocator = a, .log_size = 5, .groups = [_]@import("../../word16_global_execution/services/gkr_local/classic_witness.zig").Group{.{ .inverses = 1 }} ** 4, .group_count = 1, .data = global, .claims = @splat(O.one()) } }, .frontier = .{ .allocator = a, .data = frontier, .claim = O.one() } };
    }
    fn plan(self: *Fixture) Parts.Plan {
        return .{ .allocator = self.a, .slots = &self.slots, .inter_columns = 32, .claim_count = 1, .binding_count = 1, .op_only = true };
    }
    fn deinit(self: *Fixture) void {
        self.binding.deinit();
        for (&self.globals) |*w| if (w.*) |*v| v.deinit();
        self.frontier.deinit();
    }
};
fn successAndOom(a: std.mem.Allocator) !void {
    var f = try Fixture.init(a);
    defer f.deinit();
    const before = [_][]M{ f.binding.columns[0], f.globals[1].?.data, f.frontier.data };
    var plan = f.plan();
    const commit = Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 5) catch |err| {
        try std.testing.expectEqualSlices(M, before[0], f.binding.columns[0]);
        try std.testing.expectEqual(@intFromPtr(before[0].ptr), @intFromPtr(f.binding.columns[0].ptr));
        try std.testing.expectEqual(@intFromPtr(before[1].ptr), @intFromPtr(f.globals[1].?.data.ptr));
        try std.testing.expectEqual(@intFromPtr(before[2].ptr), @intFromPtr(f.frontier.data.ptr));
        return err;
    };
    defer commit.deinit(a);
    try std.testing.expectEqual(@as(usize, 3), commit.backings.len);
    try std.testing.expectEqual(@as(usize, 56), commit.columns.len);
    for (before, commit.backings) |prior, backing| try std.testing.expectEqual(@intFromPtr(prior.ptr), @intFromPtr(backing.ptr));
    for ([_]usize{ 0, 16, 32 }, [_]u32{ 11, 13, 17 }) |index, value| try std.testing.expectEqual(value, commit.columns[index].values[0].v);
    try std.testing.expectEqual(@as(usize, 0), f.binding.columns[0].len);
    try std.testing.expectEqual(@as(usize, 0), f.globals[1].?.data.len);
    try std.testing.expectEqual(@as(usize, 0), f.frontier.data.len);
    try std.testing.expectError(error.SpongeCpuInteractionShape, Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 5));
}
test "OP CPU INTER success-only matrices transfer and all allocation failures retain custody" {
    try successAndOom(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, successAndOom, .{});
}
test "OP CPU INTER rejects alias gaps missing groups allocator and malformed shape atomically" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit();
    var plan = f.plan();
    const global = f.globals[1].?.data;
    {
        f.globals[1].?.data = f.binding.columns[0];
        defer f.globals[1].?.data = global;
        try std.testing.expectError(error.SpongeCpuInteractionAlias, Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 5));
    }
    f.slots[1].inter_offset = 17;
    try std.testing.expectError(error.SpongeCpuInteractionShape, Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 5));
    f.slots[1].inter_offset = 16;
    f.globals[1].?.group_count = 0;
    try std.testing.expectError(error.SpongeCpuInteractionShape, Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 5));
    f.globals[1].?.group_count = 1;
    {
        f.frontier.allocator = std.heap.page_allocator;
        defer f.frontier.allocator = a;
        try std.testing.expectError(error.SpongeCpuInteractionAllocator, Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 5));
    }
    try std.testing.expectError(error.SpongeCpuInteractionShape, Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 24));
    try std.testing.expectEqual(@as(usize, 512), f.binding.columns[0].len);
    try std.testing.expectEqual(@as(usize, 512), f.globals[1].?.data.len);
    try std.testing.expectEqual(@as(usize, 768), f.frontier.data.len);
}
test "OP CPU INTER owned PCS consumes every backing on early commit error" {
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 1 << 20);
    defer budget.destroy();
    {
        const a = budget.allocator();
        var f = try Fixture.init(a);
        defer f.deinit();
        var plan = f.plan();
        const commit = try Take.take(a, &plan, &f.binding, &f.globals, &f.frontier, 5);
        const W = @import("../pure_p2_worker_protocol.zig").W;
        var scheme = try W.Scheme.init(a, @import("../op_profile.zig").Profile.op_target_b4_q72_p0_fold4_v1.config());
        defer scheme.deinit(a);
        scheme.retained_column_allocator = a;
        var channel = W.Channel.init();
        try std.testing.expectError(error.UnsupportedRetainedColumnStorage, scheme.commitOwnedStreamingWithRecorderAndBacking(a, commit.columns, commit.backings, 65, null, &channel));
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}
