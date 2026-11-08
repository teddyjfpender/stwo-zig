const std = @import("std");
const T = @import("job_timing.zig");
const Fake = struct {
    var calls: usize = 0;
    var fail_at: usize = 0;
    var next: usize = 0;
    var live: [128]bool = @splat(false);
    var duplicate_destroy = false;
    var records: usize = 0;
    fn reset() void {
        calls = 0;
        fail_at = 0;
        next = 0;
        live = @splat(false);
        duplicate_destroy = false;
        records = 0;
    }
    fn count() usize {
        var n: usize = 0;
        for (live) |value| n += @intFromBool(value);
        return n;
    }
    fn create(out: *?*anyopaque) callconv(.c) c_int {
        calls += 1;
        out.* = null;
        if (calls == fail_at) return 1;
        next += 1;
        live[next] = true;
        out.* = @ptrFromInt(next * 16);
        return 0;
    }
    fn destroy(event: *anyopaque) callconv(.c) c_int {
        const index = @intFromPtr(event) / 16;
        if (!live[index]) duplicate_destroy = true;
        live[index] = false;
        return 0;
    }
    fn make(_: ?*anyopaque, out: *?*anyopaque) c_int {
        return create(out);
    }
    fn drop(_: ?*anyopaque, event: *anyopaque) void {
        _ = destroy(event);
    }
    fn record(_: ?*anyopaque, _: *anyopaque, _: *anyopaque) c_int {
        records += 1;
        return 0;
    }
    fn elapsed(_: ?*anyopaque, out: *f32, _: *anyopaque, _: *anyopaque) c_int {
        out.* = 5;
        return 0;
    }
    const api = T.Timing{ .create = make, .destroy = drop, .record = record, .elapsed = elapsed };
};

test "installed timing pairs separate actual parity and outlive borrowed jobs" {
    Fake.reset();
    var pool = T.Pool{};
    try pool.reserve(std.testing.allocator, 2, Fake.create, Fake.destroy);
    try std.testing.expectEqual(@as(usize, 8), Fake.count());
    const first = try pool.get(0, 1);
    const other = try pool.get(1, 1);
    try std.testing.expect(first.begin != other.begin);
    const installed_calls = Fake.calls;
    var span = T.Timing.Span.borrow(first);
    try span.open(&Fake.api);
    try span.mark(&Fake.api, .begin, @ptrFromInt(1));
    try span.mark(&Fake.api, .end, @ptrFromInt(1));
    span.read(&Fake.api);
    try std.testing.expectEqual(@as(f32, 5), span.gpu_ms);
    span.close(&Fake.api);
    try std.testing.expectEqual(installed_calls, Fake.calls);
    try std.testing.expectEqual(@as(usize, 8), Fake.count());
    try std.testing.expectError(error.JobTimingNotReserved, pool.get(0, 2));
    pool.deinit(std.testing.allocator, Fake.destroy);
    try std.testing.expectEqual(@as(usize, 0), Fake.count());
    try std.testing.expect(!Fake.duplicate_destroy);
}

test "timing pool growth failure preserves both old parity owners" {
    Fake.reset();
    var pool = T.Pool{};
    defer pool.deinit(std.testing.allocator, Fake.destroy);
    try pool.reserve(std.testing.allocator, 1, Fake.create, Fake.destroy);
    const old = try pool.get(0, 0);
    Fake.fail_at = Fake.calls + 4; // second parity's second new event
    try std.testing.expectError(error.CudaTimingFailed, pool.reserve(std.testing.allocator, 2, Fake.create, Fake.destroy));
    try std.testing.expectEqual(@as(usize, 4), Fake.count());
    try std.testing.expectEqual(old.begin, (try pool.get(0, 0)).begin);
    try std.testing.expectError(error.JobTimingNotReserved, pool.get(1, 1));
    try std.testing.expect(!Fake.duplicate_destroy);
}

test "owned timing span failure releases a partially created pair" {
    Fake.reset();
    Fake.fail_at = 2;
    var span = T.Timing.Span{};
    try std.testing.expectError(error.CudaTimingFailed, span.open(&Fake.api));
    try std.testing.expectEqual(@as(usize, 0), Fake.count());
    try std.testing.expect(span.begin == null and span.end == null);
    var borrowed = T.Timing.Span.borrow(.{});
    try std.testing.expectError(error.JobTimingNotReserved, borrowed.open(&Fake.api));
    try std.testing.expectEqual(@as(usize, 2), Fake.calls);
}
