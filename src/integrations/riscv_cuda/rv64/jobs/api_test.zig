const std = @import("std");
const api = @import("api.zig");
const W = @import("worker.zig");
const fake = @import("fake.zig");

test "contract surface matches spec §3.1" {
    // VTable shape: six entries in spec order.
    const fields = std.meta.fields(api.Job.VTable);
    const names = [_][]const u8{ "class_key", "footprint", "stage", "enqueue", "finish", "abort" };
    try std.testing.expectEqual(names.len, fields.len);
    inline for (fields, 0..) |f, i| try std.testing.expectEqualStrings(names[i], f.name);
    try std.testing.expect(@hasDecl(api.Stager, "alloc") and @hasDecl(api.Stager, "upload") and @hasDecl(api.Stager, "pinned"));
    inline for (.{ "ctx", "stream", "alloc", "free", "hostFn", "waitStaged" }) |name| try std.testing.expect(@hasDecl(api.Enqueue, name));
    try std.testing.expectEqual(api.Placement.top, api.Placement.bottom.other());
    try std.testing.expectEqual(@sizeOf([*]u32) + @sizeOf(usize), @sizeOf(api.DeviceBuffer));
}

test "device buffer slices are bounds checked" {
    var words: [8]u32 = @splat(0);
    const b = api.DeviceBuffer{ .ptr = &words, .words = 8 };
    const s = try b.slice(2, 6);
    try std.testing.expectEqual(@intFromPtr(&words[2]), @intFromPtr(s.ptr));
    try std.testing.expectError(error.DeviceBufferOutOfRange, b.slice(3, 6));
    try std.testing.expectError(error.DeviceBufferOutOfRange, b.slice(9, 0));
}

/// A job that misuses phases: phase-2 calls from phase 1 must fail cleanly.
const Misuse = struct {
    seen: ?anyerror = null,
    pub fn classKey(_: *Misuse) [32]u8 {
        return @splat(3);
    }
    pub fn footprint(_: *Misuse) api.Footprint {
        return .{ .device_words = 64 };
    }
    pub fn stage(self: *Misuse, s: *api.Stager) !void {
        const w: *W.Worker = @ptrCast(@alignCast(s.worker));
        if (w.enqueueAlloc(4)) |_| {} else |err| self.seen = err;
        const p = try s.persistent(@splat(9), 64);
        try std.testing.expect(p.fresh);
        const again = try s.persistent(@splat(9), 64);
        try std.testing.expect(!again.fresh);
        try std.testing.expectEqual(p.buffer.ptr, again.buffer.ptr);
        try std.testing.expectError(error.PersistentGeometryMismatch, s.persistent(@splat(9), 128));
    }
    pub fn enqueue(_: *Misuse, e: *api.Enqueue) !void {
        const w: *W.Worker = @ptrCast(@alignCast(e.worker));
        try std.testing.expectError(error.StagerOutsidePhaseOne, w.stageAlloc(4));
        try e.waitStaged();
        try e.waitStaged(); // idempotent
    }
    pub fn finish(_: *Misuse, v: api.SlabView) !void {
        try std.testing.expectEqual(@as(usize, 0), v.words.len);
    }
    pub fn abort(_: *Misuse) void {}
};

test "phase-scoped methods reject calls outside their phase; persistent memory is keyed" {
    fake.reset();
    const w = try W.Worker.create(std.testing.allocator, &fake.ops, .{ .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 64 });
    var job = Misuse{};
    const Done = struct {
        var result: ?anyerror!void = null;
        fn done(_: *anyopaque, c: api.Completion) void {
            result = c.result;
        }
    };
    try w.submit(api.Job.from(Misuse, &job), .{ .ctx = &job, .done = Done.done });
    while (w.load() != 0) std.Thread.yield() catch {};
    w.destroy();
    try Done.result.?;
    try std.testing.expectEqual(error.EnqueueOutsidePhaseTwo, job.seen.?);
    try std.testing.expectEqual([_]u8{3} ** 32, api.Job.from(Misuse, &job).classKey());
}
