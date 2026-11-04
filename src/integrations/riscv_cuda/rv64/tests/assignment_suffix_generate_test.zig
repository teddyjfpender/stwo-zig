//! Exercise the actual production generate method with borrowed host memory.
//! This qualifies control flow/custody, never CUDA kernels or GPU performance.
const std = @import("std");
const A = @import("../outer_assignment.zig");
const N = @import("../pcs_native_abi.zig");
const SC = @import("../session_context.zig");
const S = @import("../assignment_suffix.zig");
const Fake = struct {
    a: std.mem.Allocator,
    leases: [4]?N.Lease = @splat(null),
    next: u64 = 1,
    range_calls: usize = 0,
    seed_calls: usize = 0,
    joins: usize = 0,
    pending: bool = false,
    poison_seed: bool = false,
    fail_range: bool = false,
    fn get(raw: *anyopaque) *@This() {
        return @ptrCast(@alignCast(raw));
    }
    fn allocate(raw: *anyopaque, n: u64, kind: u32, scope: *const [8]u32, out: *N.Lease) callconv(.c) c_int {
        const f = get(raw);
        if (kind != 0 or !std.mem.allEqual(u32, scope, 7)) return 1;
        for (&f.leases) |*slot| if (slot.* == null) {
            const words = f.a.alloc(u32, @intCast(n)) catch return 1;
            @memset(words, 0xdeadbeef);
            out.* = .{ .context_token = 3, .generation = f.next, .words = words.ptr, .count = n, .kind = kind };
            f.next += 1;
            slot.* = out.*;
            return 0;
        };
        return 1;
    }
    fn validate(raw: *anyopaque, p: [*]const u32, n: u64, token: u64, generation: u64, scope: *const [8]u32) callconv(.c) c_int {
        const f = get(raw);
        if (token != 3 or !std.mem.allEqual(u32, scope, 7)) return 1;
        for (f.leases) |slot| if (slot) |v| if (v.words == p and v.count >= n and v.generation == generation) return 0;
        return 1;
    }
    fn release(raw: *anyopaque, v: *N.Lease) callconv(.c) c_int {
        const f = get(raw);
        if (f.pending) return 1;
        for (&f.leases) |*slot| if (slot.*) |old| if (old.generation == v.generation) {
            f.a.free(old.words.?[0..@intCast(old.count)]);
            slot.* = null;
            v.* = .{};
            return 0;
        };
        return 1;
    }
    fn copy(_: *anyopaque, to: *anyopaque, from: *const anyopaque, n: usize) callconv(.c) c_int {
        @memcpy(@as([*]u8, @ptrCast(to))[0..n], @as([*]const u8, @ptrCast(from))[0..n]);
        return 0;
    }
    fn sync(raw: *anyopaque) callconv(.c) c_int {
        const f = get(raw);
        f.joins += 1;
        f.pending = false;
        return 0;
    }
    fn lane(_: *anyopaque, index: u32, out: *?*anyopaque) callconv(.c) c_int {
        if (index != 1) return 1;
        out.* = @ptrFromInt(16);
        return 0;
    }
    fn range(raw: *anyopaque, _: u32, j: *const A.RangeJob) callconv(.c) c_int {
        const f = get(raw);
        f.range_calls += 1;
        f.pending = true;
        for (j.ranges[0..j.range_count]) |r| for (r.first..r.first + r.count) |v| {
            j.values.words.?[v * 4] = r.value;
            @memset(j.values.words.?[v * 4 + 1 .. v * 4 + 4], 0);
        };
        return if (f.fail_range) 1 else 0;
    }
    fn seed(raw: *anyopaque, _: u32, j: *const A.Job) callconv(.c) c_int {
        const f = get(raw);
        f.seed_calls += 1;
        const seeds = @as([*]const A.Seed, @ptrCast(@alignCast(j.records)))[0..j.count];
        for (seeds) |s| @memcpy(j.values[s.out * 4 ..][0..4], &s.value);
        if (f.poison_seed) j.status.* = 1;
        return 0;
    }
    fn level(_: *anyopaque, _: u32, _: *const A.Job) callconv(.c) c_int {
        return 1;
    }
    pub fn immutableWords(_: *@This(), _: *anyopaque, _: [8]u32, _: [8]u32, _: []const u32) !N.Lease {
        return error.EmptyTaskCacheMustNotBeCalled;
    }
    fn create(out: *?*anyopaque, _: u32) callconv(.c) c_int {
        out.* = @ptrFromInt(16);
        return 0;
    }
    fn record(_: *anyopaque, _: *anyopaque) callconv(.c) c_int {
        return 0;
    }
    fn elapsed(out: *f32, _: *anyopaque, _: *anyopaque) callconv(.c) c_int {
        out.* = 0;
        return 0;
    }
    fn destroy(_: *anyopaque) callconv(.c) c_int {
        return 0;
    }
    fn live(f: *@This()) usize {
        var n: usize = 0;
        for (f.leases) |v| if (v != null) {
            n += 1;
        };
        return n;
    }
};
fn exercise(poison: bool, fail_range: bool) !void {
    const a = std.testing.allocator;
    var f = Fake{ .a = a, .poison_seed = poison, .fail_range = fail_range };
    const api = SC.Api{ .allocate = Fake.allocate, .release = Fake.release, .validate_range = Fake.validate, .upload = Fake.copy, .download = Fake.copy, .sync = Fake.sync, .lane_stream = Fake.lane };
    var ctx = SC.Context{ .session = &f, .native_context = &f, .token = 3, .scope = @splat(7), .api = &api };
    var backend = struct { service: *Fake, api: SC.Api }{ .service = &f, .api = api };
    var owner = struct { backend: *@TypeOf(backend), initial_scope: struct { fixed: [32]u8 } }{ .backend = &backend, .initial_scope = .{ .fixed = @splat(1) } };
    var ends = [_]usize{0};
    var seeds = [_]A.Seed{ .{ .out = 0, .value = @splat(0) }, .{ .out = 1, .value = .{ 1, 0, 0, 0 } }, .{ .out = 2, .value = .{ 7, 0, 0, 0 } } };
    var tail = S.Tail{ .full = 6, .prefix = 3, .add = 0, .triple = 0, .m31 = 0, .blake = 0, .count = 1 };
    tail.ranges[0] = .{ .first = 3, .count = 3, .value = 2 };
    const prepared = A.Prepared{ .allocator = a, .reference = null, .count = 6, .plan = .{ .allocator = a, .tasks = &.{}, .seeds = &.{}, .level_ends = &ends }, .tasks = &.{}, .indices = &.{}, .seeds = &seeds, .identity = @splat(1), .seed = Fake.seed, .level = Fake.level, .timing_api = .{ .create = Fake.create, .record = Fake.record, .elapsed = Fake.elapsed, .destroy = Fake.destroy }, .range_launch = Fake.range, .suffix = tail };
    if (fail_range) {
        try std.testing.expectError(error.CudaCircuitAssignmentRangeFailed, prepared.generate(&owner, &ctx));
        try std.testing.expect(!f.pending);
    } else if (poison) {
        try std.testing.expectError(error.InvalidCircuitDeviceAssignment, prepared.generate(&owner, &ctx));
    } else {
        var result = try prepared.generate(&owner, &ctx);
        try std.testing.expectEqual(@as(usize, 1), f.live());
        for (3..6) |v| try std.testing.expectEqualSlices(u32, &.{ 2, 0, 0, 0 }, result.words.?[v * 4 ..][0..4]);
        try ctx.release(&result);
    }
    try std.testing.expectEqual(@as(usize, 1), f.range_calls);
    try std.testing.expectEqual(@as(usize, if (fail_range) 0 else 1), f.seed_calls);
    try std.testing.expectEqual(@as(usize, 0), f.live());
}
test "actual Prepared.generate empty task route uses full values ranges joins and no cache" {
    try exercise(false, false);
}
test "actual Prepared.generate preserves seed failure and drains partial range error before release" {
    try exercise(true, false);
    try exercise(false, true);
}
