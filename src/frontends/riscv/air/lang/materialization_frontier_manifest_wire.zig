//! Allocation-free primitives for the materialization-frontier wire format.
//!
//! Semantic validation stays in `materialization_frontier_manifest.zig`; this
//! module contains only bounded byte access, canonical integers, and hashing.

const std = @import("std");

pub const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Digest = [32]u8;
pub const Error = error{ Truncated, TrailingSectionBytes, LengthLimitExceeded, InvalidEnum };

pub fn writeInt(writer: anytype, comptime T: type, value: T) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try writer.writeAll(&encoded);
}

pub fn writeOptionalU32(writer: anytype, value: ?u32) !void {
    if (value) |present| {
        try writeInt(writer, u8, 1);
        try writeInt(writer, u32, present);
    } else try writeInt(writer, u8, 0);
}

pub fn beginHash(domain: []const u8) Sha256 {
    var hash = Sha256.init(.{});
    hashInt(&hash, u16, @intCast(domain.len));
    hash.update(domain);
    return hash;
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

pub fn addLength(a: usize, b: usize) Error!usize {
    return std.math.add(usize, a, b) catch error.LengthLimitExceeded;
}

pub fn mulLength(a: usize, b: usize) Error!usize {
    return std.math.mul(usize, a, b) catch error.LengthLimitExceeded;
}

pub fn enumFromInt(comptime E: type, value: u8) ?E {
    inline for (std.meta.fields(E)) |field| {
        if (value == field.value) return @enumFromInt(value);
    }
    return null;
}

pub fn strictlyIncreasing(values: []const u32) bool {
    for (values, 0..) |value, index| {
        if (index != 0 and values[index - 1] >= value) return false;
    }
    return true;
}

pub fn contains(values: []const u32, needle: u32) bool {
    return std.sort.binarySearch(u32, values, needle, struct {
        fn order(key: u32, item: u32) std.math.Order {
            return std.math.order(key, item);
        }
    }.order) != null;
}

pub const Cursor = struct {
    bytes: []const u8,
    position: usize = 0,

    pub fn take(self: *Cursor, length: usize) Error![]const u8 {
        if (length > self.bytes.len -| self.position) return error.Truncated;
        defer self.position += length;
        return self.bytes[self.position..][0..length];
    }

    pub fn int(self: *Cursor, comptime T: type) Error!T {
        return std.mem.readInt(T, (try self.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }

    pub fn digest(self: *Cursor) Error!Digest {
        var result: Digest = undefined;
        @memcpy(&result, try self.take(result.len));
        return result;
    }

    pub fn optionalU32(self: *Cursor) Error!?u32 {
        return switch (try self.int(u8)) {
            0 => null,
            1 => try self.int(u32),
            else => error.InvalidEnum,
        };
    }

    pub fn boolean(self: *Cursor) Error!bool {
        return switch (try self.int(u8)) {
            0 => false,
            1 => true,
            else => error.InvalidEnum,
        };
    }

    pub fn finishSection(self: *Cursor) Error!void {
        if (self.position != self.bytes.len) return error.TrailingSectionBytes;
    }
};

pub fn readOptionalU32(cursor: *Cursor) Error!?u32 {
    return cursor.optionalU32();
}

pub fn readBool(cursor: *Cursor) Error!bool {
    return cursor.boolean();
}
