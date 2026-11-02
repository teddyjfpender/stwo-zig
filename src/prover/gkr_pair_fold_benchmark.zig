//! Fold-only paired A/B. Allocations and input reset are outside the timer.
//! This does not measure GKR proof or execution latency.
const std = @import("std");
const core = @import("stwo_core");
const ML = @import("lookups/mle.zig");
const Pools = @import("work_pool.zig");
const S = core.fields.om31.OM31;
const M = core.fields.m31.M31;
// A bounded bump region may shrink either allocation without reclaiming it;
// reset between samples releases both. No fold fallback allocations are needed.
const Region = struct {
    bump: std.heap.FixedBufferAllocator,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.bump.allocator().rawAlloc(len, alignment, ra);
    }
    fn resize(_: *anyopaque, bytes: []u8, _: std.mem.Alignment, next: usize, _: usize) bool {
        return next <= bytes.len;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {}
};
fn dense(i: usize) S {
    var c: [8]M = undefined;
    for (&c, 0..) |*x, j| x.* = M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
    return S.fromM31Array(c);
}
pub fn main() !void {
    const a = std.heap.page_allocator;
    const writer = std.fs.File.stdout().deprecatedWriter();
    for ([_]usize{ 1, 8 }) |workers| {
        var pool: Pools.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers, .stack_size = 1024 * 1024 });
        defer pool.deinit();
        var binding = try Pools.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        for ([_]u5{ 14, 16, 20 }) |log| {
            const n = @as(usize, 1) << log;
            const storage = try a.alignedAlloc(u8, .of(S), 2 * n * @sizeOf(S));
            defer a.free(storage);
            for (0..12) |sample| {
                for (0..2) |order| {
                    const paired = (sample + order) % 2 == 1;
                    var region = Region{ .bump = std.heap.FixedBufferAllocator.init(storage) };
                    const child = region.allocator();
                    var left = try ML.MleFor(S, S).initOwned(try child.alloc(S, n));
                    var right = try ML.MleFor(S, S).initOwned(try child.alloc(S, n));
                    for (left.evals, right.evals, 0..) |*x, *y, i| {
                        x.* = dense(i);
                        y.* = dense(i + 211);
                    }
                    const r = dense(97);
                    var timer = try std.time.Timer.start();
                    if (paired) try left.foldOwnedSecurePair(&right, child, r) else {
                        try left.foldOwnedSecure(child, r);
                        try right.foldOwnedSecure(child, r);
                    }
                    const ns = timer.read();
                    const check = left.evals[n / 3].add(right.evals[n / 3]).toM31Array();
                    try writer.print("{{\"workers\":{d},\"log\":{d},\"sample\":{d},\"paired\":{},\"row_wave_calls\":{d},\"fold_ns\":{d},\"check0\":{d}}}\n", .{ workers, log, sample, paired, @as(u8, if (paired) 1 else 2), ns, check[0].toU32() });
                    left.deinit(child);
                    right.deinit(child);
                }
            }
        }
    }
}
