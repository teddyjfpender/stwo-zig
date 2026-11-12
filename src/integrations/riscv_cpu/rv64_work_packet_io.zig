//! Bounded concrete file I/O, never buffers the tape or reads across a section.
const std = @import("std");
const IO = @import("bounded_file_io.zig");
pub const Writer = IO.Writer;
pub const Reader = IO.Reader;
pub const exact = IO.exact;
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
