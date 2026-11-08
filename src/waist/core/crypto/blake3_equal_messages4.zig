//! Four equal-length unkeyed BLAKE3 messages, with independent tree state.
//! The reader supplies one padded block per lane. No whole-message staging,
//! allocator, transcript framing or protocol limit is introduced here.
const std = @import("std");
const batch = @import("blake3_compression_batch.zig");
const compression = @import("blake3_compression.zig");
pub const Digests = [4][32]u8;
pub const Blocks = [4][16]u32;
const Cvs = [4][8]u32;
const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const Output = struct {
    cvs: Cvs,
    blocks: Blocks,
    counter: u64,
    length: u32,
    flags: u32,
    fn compress(self: Output, root: bool) [4][16]u32 {
        return batch.compress4(self.cvs, self.blocks, @splat(if (root) 0 else self.counter), @splat(self.length), @splat(self.flags | if (root) ROOT else @as(u32, 0))) catch unreachable;
    }
    fn chaining(self: Output) Cvs {
        const compressed = self.compress(false);
        var cvs: Cvs = undefined;
        inline for (0..4) |lane| cvs[lane] = compressed[lane][0..8].*;
        return cvs;
    }
};
fn parent(left: Cvs, right: Cvs) Output {
    var blocks: Blocks = undefined;
    inline for (0..4) |lane| blocks[lane] = left[lane] ++ right[lane];
    return .{ .cvs = @splat(compression.IV), .blocks = blocks, .counter = 0, .length = 64, .flags = PARENT };
}
/// reader.byteLength() preflights ownership/geometry; reader.block(offset,len)
/// returns canonical LE words, zero-padded beyond len, for all four lanes.
/// Every length, including exact chunk multiples and empty input, is handled.
pub fn hashReader(reader: anytype) !Digests {
    const length = try reader.byteLength();
    const chunk_count = if (length == 0) 1 else 1 + (length - 1) / 1024;
    // A usize-sized message cannot have more than this many pending subtrees.
    // The full standard BLAKE3 stack depth is54 on64-bit targets.
    var stack: [@bitSizeOf(usize) - 10]Cvs = undefined;
    var depth: usize = 0;
    for (0..chunk_count) |chunk| {
        const offset = chunk * 1024;
        const chunk_length = @min(1024, length - offset);
        const block_count = if (chunk_length == 0) 1 else 1 + (chunk_length - 1) / 64;
        var cvs: Cvs = @splat(compression.IV);
        for (0..block_count) |block| {
            const block_length = @min(64, chunk_length - block * 64);
            const last = block + 1 == block_count;
            var output = Output{
                .cvs = cvs,
                .blocks = reader.block(offset + block * 64, block_length),
                .counter = @intCast(chunk),
                .length = @intCast(block_length),
                .flags = (if (block == 0) CHUNK_START else @as(u32, 0)) | (if (last) CHUNK_END else @as(u32, 0)),
            };
            if (!last) {
                cvs = output.chaining();
                continue;
            }
            if (chunk + 1 == chunk_count) {
                while (depth > 0) {
                    depth -= 1;
                    output = parent(stack[depth], output.chaining());
                }
                const compressed = output.compress(true);
                var digests: Digests = undefined;
                inline for (0..4) |lane| inline for (0..8) |word| {
                    std.mem.writeInt(u32, digests[lane][4 * word ..][0..4], compressed[lane][word], .little);
                };
                return digests;
            }
            var value = output.chaining();
            var completed = chunk + 1;
            while (completed & 1 == 0) : (completed >>= 1) {
                depth -= 1;
                value = parent(stack[depth], value).chaining();
            }
            stack[depth] = value;
            depth += 1;
        }
    }
    unreachable;
}
pub fn words(bytes: *const [4][64]u8) Blocks {
    var result: Blocks = undefined;
    inline for (0..4) |lane| inline for (0..16) |word| {
        result[lane][word] = std.mem.readInt(u32, bytes[lane][4 * word ..][0..4], .little);
    };
    return result;
}
/// Copies a common prefix into the requested zero-padded block. Return value
/// is the number of bytes already written; payload follows immediately.
pub fn prefixBlock(prefix: []const u8, offset: usize, length: usize, bytes: *[4][64]u8) usize {
    bytes.* = @splat(@splat(0));
    if (offset >= prefix.len) return 0;
    const count = @min(length, prefix.len - offset);
    inline for (0..4) |lane| @memcpy(bytes[lane][0..count], prefix[offset..][0..count]);
    return count;
}
const Prefixed = struct {
    prefix: []const u8,
    messages: *const [4][]const u8,
    pub fn byteLength(self: Prefixed) !usize {
        for (self.messages) |message| if (message.len != self.messages[0].len) return error.Blake3BatchLengthMismatch;
        return std.math.add(usize, self.prefix.len, self.messages[0].len);
    }
    pub fn block(self: Prefixed, offset: usize, length: usize) Blocks {
        var bytes: [4][64]u8 = undefined;
        const prefix_length = prefixBlock(self.prefix, offset, length, &bytes);
        const payload = offset + prefix_length -| self.prefix.len;
        inline for (0..4) |lane| @memcpy(bytes[lane][prefix_length..length], self.messages[lane][payload..][0 .. length - prefix_length]);
        return words(&bytes);
    }
};
pub fn hashPrefixed(prefix: []const u8, messages: *const [4][]const u8) !Digests {
    return hashReader(Prefixed{ .prefix = prefix, .messages = messages });
}
