//! Bounded concrete file I/O, never buffers the tape or reads across a section.
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
pub const DIGEST_OFFSET = 328;
/// Header digest bytes are treated as zero. Hashes identify/corruption-check a
/// job, not execution authority. Requires an exclusively owned immutable file.
pub fn digest(file: std.fs.File, bytes: usize) ![32]u8 {
    try file.seekTo(0);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("RV64-PREPARED-JOB-CONTENT-V1");
    var buffer: [65536]u8 = undefined;
    var offset: usize = 0;
    while (offset < bytes) {
        const n = @min(buffer.len, bytes - offset);
        try exact(file, buffer[0..n]);
        if (offset <= DIGEST_OFFSET and DIGEST_OFFSET < offset + n) {
            const start = DIGEST_OFFSET - offset;
            if (start + 32 > n) return error.InvalidWorkPacketSection;
            @memset(buffer[start..][0..32], 0);
        }
        hasher.update(buffer[0..n]);
        offset += n;
    }
    return hasher.finalResult();
}
