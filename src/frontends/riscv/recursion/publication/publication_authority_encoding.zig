//! Shared canonical SHA encoding for publication authority receipts.
const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
pub const ShaHasher = struct {
    inner: std.crypto.hash.sha2.Sha256,

    pub fn init(domain: []const u8) ShaHasher {
        var inner = std.crypto.hash.sha2.Sha256.init(.{});
        inner.update(domain);
        return .{ .inner = inner };
    }

    pub fn u8Value(self: *ShaHasher, value: anytype) void {
        self.inner.update(&.{@intCast(value)});
    }

    pub fn u16Value(self: *ShaHasher, value: anytype) void {
        var bytes: [2]u8 = undefined;
        std.mem.writeInt(u16, &bytes, @intCast(value), .little);
        self.inner.update(&bytes);
    }

    pub fn u32Value(self: *ShaHasher, value: anytype) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, @intCast(value), .little);
        self.inner.update(&bytes);
    }

    pub fn rawBytes(self: *ShaHasher, value: []const u8) void {
        self.u32Value(value.len);
        self.inner.update(value);
    }

    pub fn nativeDigest(self: *ShaHasher, value: [8]u32) void {
        for (value) |word| self.u32Value(word);
    }

    pub fn qm31(self: *ShaHasher, value: QM31) void {
        for (value.toM31Array()) |word| self.u32Value(word.toU32());
    }

    pub fn finalize(self: *ShaHasher) [32]u8 {
        return self.inner.finalResult();
    }
};
