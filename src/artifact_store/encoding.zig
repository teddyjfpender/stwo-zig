//! Canonical little-endian encoding primitives for persistent artifact keys.

const std = @import("std");

pub const Digest = [32]u8;

pub const Encoder = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,

    pub fn init(allocator: std.mem.Allocator, domain: []const u8) !Encoder {
        if (domain.len == 0 or domain[domain.len - 1] != 0)
            return error.InvalidArtifactEncodingDomain;
        var self = Encoder{ .allocator = allocator };
        errdefer self.deinit();
        try self.bytes.appendSlice(allocator, domain);
        return self;
    }

    pub fn deinit(self: *Encoder) void {
        self.bytes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn finish(self: *Encoder) ![]u8 {
        return self.bytes.toOwnedSlice(self.allocator);
    }

    pub fn writeInt(self: *Encoder, comptime T: type, value: T) !void {
        var encoded: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &encoded, value, .little);
        try self.bytes.appendSlice(self.allocator, &encoded);
    }

    pub fn writeDigest(self: *Encoder, value: Digest) !void {
        try self.bytes.appendSlice(self.allocator, &value);
    }

    pub fn writeFixed(self: *Encoder, value: []const u8) !void {
        try self.bytes.appendSlice(self.allocator, value);
    }

    pub fn writeCount(self: *Encoder, count: usize) !void {
        if (count > std.math.maxInt(u32)) return error.ArtifactEncodingTooLarge;
        try self.writeInt(u32, @intCast(count));
    }
};

pub const Reader = struct {
    bytes: []const u8,
    index: usize = 0,

    pub fn init(bytes: []const u8, domain: []const u8) !Reader {
        if (domain.len == 0 or domain[domain.len - 1] != 0)
            return error.InvalidArtifactEncodingDomain;
        if (bytes.len < domain.len or !std.mem.eql(u8, bytes[0..domain.len], domain))
            return error.InvalidArtifactEncoding;
        return .{ .bytes = bytes, .index = domain.len };
    }

    pub fn readInt(self: *Reader, comptime T: type) !T {
        const encoded = try self.take(@sizeOf(T));
        const fixed: *const [@sizeOf(T)]u8 = @ptrCast(encoded.ptr);
        return std.mem.readInt(T, fixed, .little);
    }

    pub fn readDigest(self: *Reader) !Digest {
        const encoded = try self.take(32);
        var result: Digest = undefined;
        @memcpy(&result, encoded);
        return result;
    }

    pub fn take(self: *Reader, count: usize) ![]const u8 {
        const end = std.math.add(usize, self.index, count) catch
            return error.InvalidArtifactEncoding;
        if (end > self.bytes.len) return error.TruncatedArtifactEncoding;
        const result = self.bytes[self.index..end];
        self.index = end;
        return result;
    }

    pub fn expectEnd(self: Reader) !void {
        if (self.index != self.bytes.len) return error.NonCanonicalArtifactEncoding;
    }
};

pub fn digestBytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub fn isZeroDigest(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

pub fn requireNonzeroDigest(value: Digest) !void {
    if (isZeroDigest(value)) return error.InvalidArtifactIdentity;
}
