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
fn exercise(copies: bool, log: u32, terms: u32) !void {
    var physical = Retaining{ .child = a, .copies = copies };
    defer physical.deinit();
    const allocator = physical.allocator();
    const instances = [_]Frame.Instance{
        .{ .origin = .{ .core = .alu }, .row_log = log, .terms = terms, .fixed_offset = 0, .main_offset = 0 },
        .{ .origin = .{ .core = .range16 }, .row_log = log, .terms = terms, .fixed_offset = 0, .main_offset = 0 },
    };
    const old = try Resource.Plan.forInstances(&instances, std.math.maxInt(usize));
    const plan = try Resource.Plan.forInstancesWithTightAdmission(&instances, std.math.maxInt(usize), false, true);
    try std.testing.expect(plan.peak_bytes < old.peak_bytes);
    const scope = @import("receipt.zig").Scope{ .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .ordinal = 0 };
    const child = try Child.Unbound.proveTimedWithPolicy(allocator, plan.peak_bytes, scope, &instances, Provider{}, .{ .tight_admission = true }, null);
    defer child.deinit();
    try std.testing.expectEqual(plan.peak_bytes, child.budget.limit);
    try std.testing.expect(child.peak_gkr_owned_bytes <= plan.peak_bytes);
    // Counts full original payload capacities even after logical resize, plus
    // the parent Unbound and binding planes. Tracking-map storage is excluded.
    try std.testing.expect(physical.peak <= plan.peak_bytes);
    var pending = try Child.verifyPending(a, scope, &instances, &child.result.proof, child.digest);
    defer pending.deinit(a);
    std.debug.print("DENSE104_CAP copies={any} rowlog={d} terms={d} requested_peak={d} original_capacity_peak={d} plan={d}\n", .{ copies, log, terms, child.peak_gkr_owned_bytes, physical.peak, plan.peak_bytes });
}
test "dense104 bounds original-capacity retention and worst nonresizing folds at exact cap" {
    for ([_]bool{ false, true }) |copies| {
        try exercise(copies, 12, 15);
        try exercise(copies, 15, 1);
    }
}
