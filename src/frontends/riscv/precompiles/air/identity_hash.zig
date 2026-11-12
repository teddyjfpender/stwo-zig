//! Canonical allocation-free SHA-256 encoding helpers for guest identities.

const std = @import("std");

pub const Digest = [32]u8;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub fn init(domain_separator: []const u8) Sha256 {
    var hash = Sha256.init(.{});
    hashString(&hash, domain_separator);
    return hash;
}

pub fn finish(hash: *Sha256) Digest {
    var digest: Digest = undefined;
    hash.final(&digest);
    return digest;
}

pub fn hashInt(hash: *Sha256, comptime T: type, value: T) void {
    const info = @typeInfo(T);
    if (info != .int and info != .comptime_int)
        @compileError("canonical identity integer must be an integer type");
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

pub fn hashBool(hash: *Sha256, value: bool) void {
    hashInt(hash, u8, @intFromBool(value));
}

pub fn hashBytes(hash: *Sha256, bytes: []const u8) void {
    hashInt(hash, u32, @intCast(bytes.len));
    hash.update(bytes);
}

pub fn hashString(hash: *Sha256, value: []const u8) void {
    hashBytes(hash, value);
}

/// Channel adapter for canonical base statement mix methods. It deliberately
/// implements only the integer operation those methods expose.
pub const U32Channel = struct {
    hash: *Sha256,

    pub fn mixU32s(self: *U32Channel, values: []const u32) void {
        hashInt(self.hash, u32, @intCast(values.len));
        for (values) |value| hashInt(self.hash, u32, value);
    }
};
