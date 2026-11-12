//! Canonical bounded byte I/O. No packet header, digest or admission policy.
const std = @import("std");
pub const Writer = struct {
    file: std.fs.File,
    buffer: [65536]u8 = undefined,
    used: usize = 0,
    pub fn bytes(self: *Writer, source: []const u8) !void {
        var rest = source;
        while (rest.len != 0) {
            const n = @min(rest.len, self.buffer.len - self.used);
            @memcpy(self.buffer[self.used..][0..n], rest[0..n]);
            self.used += n;
            rest = rest[n..];
            if (self.used == self.buffer.len) try self.flush();
        }
    }
    pub fn int(self: *Writer, comptime T: type, value: T) !void {
        var raw: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &raw, value, .little);
        try self.bytes(&raw);
    }
    pub fn flush(self: *Writer) !void {
        try self.file.writeAll(self.buffer[0..self.used]);
        self.used = 0;
    }
};
pub const Reader = struct {
    file: std.fs.File,
    remaining: usize,
    buffer: [65536]u8 = undefined,
    at: usize = 0,
    end: usize = 0,
    pub fn bytes(self: *Reader, output: []u8) !void {
        var rest = output;
        while (rest.len != 0) {
            if (self.at == self.end) {
                if (self.remaining == 0) return error.TruncatedWorkPacket;
                self.end = @min(self.remaining, self.buffer.len);
                try exact(self.file, self.buffer[0..self.end]);
                self.remaining -= self.end;
                self.at = 0;
            }
            const n = @min(rest.len, self.end - self.at);
            @memcpy(rest[0..n], self.buffer[self.at..][0..n]);
            self.at += n;
            rest = rest[n..];
        }
    }
    pub fn int(self: *Reader, comptime T: type) !T {
        var raw: [@sizeOf(T)]u8 = undefined;
        try self.bytes(&raw);
        return std.mem.readInt(T, &raw, .little);
    }
    pub fn finish(self: *const Reader) !void {
        if (self.remaining != 0 or self.at != self.end) return error.InvalidWorkPacketSection;
    }
};
pub fn exact(file: std.fs.File, output: []u8) !void {
    if (try file.readAll(output) != output.len) return error.TruncatedWorkPacket;
}

test "bounded file I/O preserves buffer edges and section refusal" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("section", .{ .read = true });
    defer file.close();
    var writer = Writer{ .file = file };
    const payload: [65537]u8 = @splat(0xa7);
    try writer.bytes(payload[0..1]);
    try writer.bytes(payload[1..]);
    try writer.int(u16, 0x5aa5);
    try writer.flush();
    try file.seekTo(0);
    var reader = Reader{ .file = file, .remaining = payload.len + 2 };
    var restored: [65537]u8 = undefined;
    try reader.bytes(&restored);
    try std.testing.expectEqualSlices(u8, &payload, &restored);
    try std.testing.expectError(error.InvalidWorkPacketSection, reader.finish());
    try std.testing.expectEqual(@as(u16, 0x5aa5), try reader.int(u16));
    try reader.finish();
    var extra: [1]u8 = undefined;
    try std.testing.expectError(error.TruncatedWorkPacket, reader.bytes(&extra));
    try file.seekTo(0);
    var bounded = Reader{ .file = file, .remaining = 1 };
    var pair: [2]u8 = undefined;
    try std.testing.expectError(error.TruncatedWorkPacket, bounded.bytes(&pair));
    try file.seekTo(65538);
    try std.testing.expectError(error.TruncatedWorkPacket, exact(file, &pair));
}
