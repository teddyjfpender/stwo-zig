//! Transfer the bucket before its first fallible numerical operation. Once
//! appended, only the caller's retained list may release it on any later error.
const std = @import("std");
pub fn adoptAndClear(a: std.mem.Allocator, context: anytype, retained: anytype, bucket: anytype, value: anytype, clear: anytype) !void {
    retained.append(a, value) catch |err| {
        var owned = value;
        try context.release(&owned);
        return err;
    };
    bucket.* = value;
    if (clear(context.native_context, @ptrCast(value.words.?), 0, value.count * 4) != 0) return error.SparseCompositionCudaFailed;
}
const Fixture = struct {
    const Lease = struct { words: ?[*]u32 = @ptrFromInt(4096), count: usize = 8 };
    native_context: *anyopaque = @ptrFromInt(8192),
    releases: usize = 0,
    fn release(self: *@This(), _: *Lease) !void {
        self.releases += 1;
    }
    fn failClear(_: *anyopaque, _: *anyopaque, _: c_int, _: usize) c_int {
        return 1;
    }
};
test "sparse bucket clear failure preserves exactly one caller owner" {
    var fixture: Fixture = .{};
    var list: std.ArrayList(Fixture.Lease) = .empty;
    defer list.deinit(std.testing.allocator);
    var bucket: ?Fixture.Lease = null;
    try std.testing.expectError(error.SparseCompositionCudaFailed, adoptAndClear(std.testing.allocator, &fixture, &list, &bucket, Fixture.Lease{}, Fixture.failClear));
    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expect(bucket != null);
    try std.testing.expectEqual(@as(usize, 0), fixture.releases);
    try fixture.release(&list.items[0]);
    try std.testing.expectEqual(@as(usize, 1), fixture.releases);
}
test "sparse bucket append failure releases untransferred owner once" {
    var fixture: Fixture = .{};
    var list: std.ArrayList(Fixture.Lease) = .empty;
    var bucket: ?Fixture.Lease = null;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, adoptAndClear(failing.allocator(), &fixture, &list, &bucket, Fixture.Lease{}, Fixture.failClear));
    try std.testing.expectEqual(@as(usize, 0), list.items.len);
    try std.testing.expect(bucket == null);
    try std.testing.expectEqual(@as(usize, 1), fixture.releases);
}
