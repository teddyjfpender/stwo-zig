//! Independent stress allocators for the production-multiplicity resource bound.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Frame = @import("frame.zig");
const Child = @import("child.zig");
const Resource = @import("resource.zig");
const a = std.testing.allocator;
const Retaining = struct {
    child: std.mem.Allocator,
    copies: bool,
    blocks: std.AutoHashMapUnmanaged(usize, usize) = .{},
    live: usize = 0,
    peak: usize = 0,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn deinit(self: *@This()) void {
        std.debug.assert(self.blocks.count() == 0 and self.live == 0);
        self.blocks.deinit(self.child);
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const ptr = self.child.rawAlloc(len, alignment, ra) orelse return null;
        self.blocks.put(self.child, @intFromPtr(ptr), len) catch {
            self.child.rawFree(ptr[0..len], alignment, ra);
            return null;
        };
        self.live += len;
        self.peak = @max(self.peak, self.live);
        return ptr;
    }
    fn resize(ctx: *anyopaque, memory: []u8, _: std.mem.Alignment, len: usize, _: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.copies or len == 0) return false;
        return len <= (self.blocks.get(@intFromPtr(memory.ptr)) orelse return false);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        return if (resize(ctx, memory, alignment, len, ra)) memory.ptr else null;
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        const entry = self.blocks.fetchRemove(@intFromPtr(memory.ptr)) orelse unreachable;
        self.live -= entry.value;
        self.child.rawFree(memory.ptr[0..entry.value], alignment, ra);
    }
};
const Provider = struct {
    pub fn emit(_: @This(), instance: Frame.Instance, logical: usize, sink: *@import("inputs.zig").RowSink) !void {
        const weight = if (instance.origin.core == .alu) M.one() else M.one().neg();
        for (0..instance.terms) |i| sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast((logical + i) % 65536))}, weight);
    }
};
fn exercise(copies: bool, log: u32, terms: u32, streamed: bool) !void {
    var physical = Retaining{ .child = a, .copies = copies };
    defer physical.deinit();
    const allocator = physical.allocator();
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = log, .terms = terms, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = log, .terms = terms, .fixed_offset = 0, .main_offset = 0 },
    };
    const old = try Resource.Plan.forInstances(&instances, std.math.maxInt(usize));
    const plan = if (streamed) try Resource.Plan.forInstancesWithStreamedBottom(&instances, std.math.maxInt(usize)) else try Resource.Plan.forInstancesWithTightAdmission(&instances, std.math.maxInt(usize), false, true);
    try std.testing.expect(plan.peak_bytes < old.peak_bytes);
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const child = try Child.Unbound.proveTimedWithPolicy(allocator, plan.peak_bytes, scope, &instances, Provider{}, .{ .checkpointed = streamed, .tight_admission = true, .stream_bottom = streamed }, null);
    defer child.deinit();
    try std.testing.expectEqual(plan.peak_bytes, child.budget.limit);
    try std.testing.expect(child.peak_gkr_owned_bytes <= plan.peak_bytes);
    // Counts full original payload capacities even after logical resize, plus
    // the parent Unbound and binding planes. Tracking-map storage is excluded.
    try std.testing.expect(physical.peak <= plan.peak_bytes);
    var pending = try Child.verifyPending(a, scope, &instances, &child.result.proof, child.digest);
    defer pending.deinit(a);
    std.debug.print("PRODUCTION_CAP streamed={any} copies={any} rowlog={d} terms={d} requested_peak={d} original_capacity_peak={d} plan={d}\n", .{ streamed, copies, log, terms, child.peak_gkr_owned_bytes, physical.peak, plan.peak_bytes });
}
test "dense104 bounds original-capacity retention and worst nonresizing folds at exact cap" {
    for ([_]bool{ false, true }) |copies| {
        try exercise(copies, 12, 15, false);
        try exercise(copies, 15, 1, false);
    }
}

test "stream68 bounds retained capacities and no-resize copies at exact allocator cap" {
    for ([_]bool{ false, true }) |copies| {
        try exercise(copies, 12, 15, true);
        try exercise(copies, 15, 1, true);
    }
}

test "stream68 exact cap covers many heterogeneous source instances with original-capacity retention" {
    var physical = Retaining{ .child = a, .copies = false };
    defer physical.deinit();
    var instances: [12]Frame.Instance = undefined;
    const logs = [_]u32{ 5, 6, 7, 8, 9, 10 };
    const terms = [_]u32{ 1, 3, 7, 15, 63, 97 };
    for (logs, terms, 0..) |log, count, i| {
        instances[2 * i] = .{ .origin = .{ .core = .alu }, .row_log = log, .terms = count, .fixed_offset = 0, .main_offset = 0 };
        instances[2 * i + 1] = .{ .origin = .{ .core = .range16 }, .row_log = log, .terms = count, .fixed_offset = 0, .main_offset = 0 };
    }
    const plan = try Resource.Plan.forInstancesWithStreamedBottom(&instances, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(usize, 0), plan.input_bytes);
    try std.testing.expectError(error.LocalGkrBudgetExceeded, Resource.Plan.forInstancesWithStreamedBottom(&instances, plan.peak_bytes - 1));
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const child = try Child.Unbound.proveTimedWithPolicy(physical.allocator(), plan.peak_bytes, scope, &instances, Provider{}, .{ .checkpointed = true, .tight_admission = true, .stream_bottom = true }, null);
    defer child.deinit();
    try std.testing.expectEqual(plan.peak_bytes, child.budget.limit);
    try std.testing.expect(child.peak_gkr_owned_bytes <= plan.peak_bytes);
    try std.testing.expect(physical.peak <= plan.peak_bytes);
    var pending = try Child.verifyPending(a, scope, &instances, &child.result.proof, child.digest);
    defer pending.deinit(a);
    std.debug.print("STREAM68_MIXED instances={d} requested_peak={d} original_capacity_peak={d} plan={d}\n", .{ instances.len, child.peak_gkr_owned_bytes, physical.peak, plan.peak_bytes });
}

test "stream68 bounds synchronized equal-size first folds with nonresizing backing owners" {
    var physical = Retaining{ .child = a, .copies = true };
    defer physical.deinit();
    var instances: [16]Frame.Instance = undefined;
    for (&instances, 0..) |*instance, i| instance.* = .{ .origin = .{ .core = if (i % 2 == 0) .alu else .range16 }, .row_log = 8, .terms = 15, .fixed_offset = 0, .main_offset = 0 };
    const plan = try Resource.Plan.forInstancesWithStreamedBottom(&instances, std.math.maxInt(usize));
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const child = try Child.Unbound.proveTimedWithPolicy(physical.allocator(), plan.peak_bytes, scope, &instances, Provider{}, .{ .checkpointed = true, .tight_admission = true, .stream_bottom = true }, null);
    defer child.deinit();
    try std.testing.expect(child.peak_gkr_owned_bytes <= plan.peak_bytes);
    try std.testing.expect(physical.peak <= plan.peak_bytes);
    var pending = try Child.verifyPending(a, scope, &instances, &child.result.proof, child.digest);
    defer pending.deinit(a);
    std.debug.print("STREAM68_EQUAL instances={d} requested_peak={d} original_capacity_peak={d} plan={d}\n", .{ instances.len, child.peak_gkr_owned_bytes, physical.peak, plan.peak_bytes });
}
