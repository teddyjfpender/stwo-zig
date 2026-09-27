//! Allocation-free byte counting with an explicit early output cap. Reuse the
//! same serializer with a fixed buffer of the admitted count to preserve bytes.
const std = @import("std");
pub const Counting = struct {
    writer: std.Io.Writer,
    limit: usize,
    count: usize = 0,
    exceeded: bool = false,
    pub fn init(limit: usize) Counting {
        return .{ .writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} }, .limit = limit };
    }
    fn drain(writer: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const self: *Counting = @fieldParentPtr("writer", writer);
        const repeated = data[data.len - 1];
        var written = std.math.mul(usize, repeated.len, splat) catch return self.reject();
        for (data[0 .. data.len - 1]) |slice| written = std.math.add(usize, written, slice.len) catch return self.reject();
        const next = std.math.add(usize, self.count, written) catch return self.reject();
        if (next > self.limit) return self.reject();
        self.count = next;
        return written;
    }
    fn reject(self: *Counting) std.Io.Writer.Error {
        self.exceeded = true;
        return error.WriteFailed;
    }
};
test "block-v5 exact counting writer enforces boundary splat and overflow without allocations" {
    var counter = Counting.init(7);
    try counter.writer.writeAll("abc");
    try counter.writer.splatBytesAll("xy", 2);
    try std.testing.expectEqual(@as(usize, 7), counter.count);
    try std.testing.expectError(error.WriteFailed, counter.writer.writeByte('!'));
    try std.testing.expect(counter.exceeded);
    try std.testing.expectEqual(@as(usize, 7), counter.count);
    var overflow = Counting.init(std.math.maxInt(usize));
    try std.testing.expectError(error.WriteFailed, Counting.drain(&overflow.writer, &.{"xy"}, std.math.maxInt(usize)));
    try std.testing.expect(overflow.exceeded);
}

test "block-v5 exact counting preserves canonical JSON byte identity and rejects caps early" {
    const record = .{ .version = @as(u32, 1), .values = [_]u64{ 0, 123, std.math.maxInt(u64) }, .text = "line\nquote\"" };
    const expected = try std.json.Stringify.valueAlloc(std.testing.allocator, record, .{});
    defer std.testing.allocator.free(expected);
    var counter = Counting.init(expected.len);
    try std.json.Stringify.value(record, .{}, &counter.writer);
    try std.testing.expectEqual(expected.len, counter.count);
    const exact = try std.testing.allocator.alloc(u8, counter.count);
    defer std.testing.allocator.free(exact);
    var fixed = std.Io.Writer.fixed(exact);
    try std.json.Stringify.value(record, .{}, &fixed);
    try std.testing.expectEqualStrings(expected, fixed.buffered());
    var limited = Counting.init(expected.len - 1);
    try std.testing.expectError(error.WriteFailed, std.json.Stringify.value(record, .{}, &limited.writer));
    try std.testing.expect(limited.exceeded);
    try std.testing.expect(limited.count <= limited.limit);
}
