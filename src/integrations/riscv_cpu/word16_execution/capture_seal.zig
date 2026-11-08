//! Buffered semantic encoder for private immutable capture ownership.
const std = @import("std");
pub const Hasher = struct {
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    buffer: [4096]u8 = undefined,
    used: usize = 0,
    pub fn write(self: *@This(), bytes: []const u8) void {
        if (bytes.len >= self.buffer.len) {
            self.hash.update(self.buffer[0..self.used]);
            self.used = 0;
            self.hash.update(bytes);
            return;
        }
        if (self.used + bytes.len > self.buffer.len) {
            self.hash.update(self.buffer[0..self.used]);
            self.used = 0;
        }
        @memcpy(self.buffer[self.used..][0..bytes.len], bytes);
        self.used += bytes.len;
    }
    pub fn value(self: *@This(), item: anytype) void {
        switch (@typeInfo(@TypeOf(item))) {
            .int => |info| {
                if (info.bits > 64) @compileError("capture scalar exceeds u64");
                const U = std.meta.Int(.unsigned, info.bits);
                var bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &bytes, @as(U, @bitCast(item)), .little);
                self.write(&bytes);
            },
            .bool => self.value(@as(u8, @intFromBool(item))),
            .@"enum" => self.value(@intFromEnum(item)),
            .array => {
                self.value(@as(usize, item.len));
                for (item) |entry| self.value(entry);
            },
            .pointer => |info| {
                if (info.size != .slice) @compileError("capture seal cannot hash pointers");
                self.value(item.len);
                for (item) |entry| self.value(entry);
            },
            .@"struct" => |info| inline for (info.fields) |field| self.value(@field(item, field.name)),
            else => @compileError("unsupported capture seal field " ++ @typeName(@TypeOf(item))),
        }
    }
    pub fn final(self: *@This()) [32]u8 {
        self.hash.update(self.buffer[0..self.used]);
        return self.hash.finalResult();
    }
};
