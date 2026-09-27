//! Batch small structural-seal fragments without changing their canonical bytes.
//! Every admission still hashes its complete input; this is not a digest cache.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Hasher = struct {
    hash: Sha256 = Sha256.init(.{}),
    buffer: [1024]u8 = undefined,
    used: usize = 0,

    pub fn init(_: struct {}) Hasher {
        return .{};
    }

    pub inline fn update(self: *Hasher, bytes: []const u8) void {
        if (bytes.len > self.buffer.len - self.used) {
            self.hash.update(self.buffer[0..self.used]);
            self.used = 0;
            if (bytes.len >= self.buffer.len) {
                self.hash.update(bytes);
                return;
            }
        }
        @memcpy(self.buffer[self.used..][0..bytes.len], bytes);
        self.used += bytes.len;
    }

    pub fn finalResult(self: *Hasher) [Sha256.digest_length]u8 {
        self.hash.update(self.buffer[0..self.used]);
        return self.hash.finalResult();
    }
};

test "structural SHA256 preserves unbuffered bytes across fragment and block boundaries" {
    var input: [8193]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index * 37);
    for ([_]usize{ 0, 1, 55, 56, 63, 64, 65, 1023, 1024, 1025, input.len }) |length| {
        for ([_]usize{ 1, 4, 17, 63, 64, 65, 1023, 1024, 1025, input.len }) |fragment| {
            var buffered = Hasher.init(.{});
            var canonical = Sha256.init(.{});
            canonical.update(input[0..length]);
            var position: usize = 0;
            while (position < length) {
                const end = @min(length, position + fragment);
                buffered.update(input[position..end]);
                buffered.update("");
                position = end;
            }
            try std.testing.expectEqualSlices(u8, &canonical.finalResult(), &buffered.finalResult());
        }
    }
}
