//! Four independent BLAKE3 compressions through the canonical G schedule.
//! This is execution batching only: each lane retains its own CV, counter,
//! block length and flags. No transcript/commitment encoding is defined here.
const std = @import("std");
const compression = @import("blake3_compression.zig");
pub const LANES = 4;
const V = @Vector(LANES, u32);
const Ops = struct {
    pub const Word = V;
    pub fn add(_: *Ops, a: V, b: V) !V { return a +% b; }
    pub fn xorRotate(_: *Ops, a: V, b: V, comptime rotation: u5) !V {
        const word = a ^ b;
        const left: u5 = @intCast(32 - @as(u6, rotation));
        return (word >> @as(@Vector(LANES, u5), @splat(rotation))) |
            (word << @as(@Vector(LANES, u5), @splat(left)));
    }
};
pub fn compress4(cv: [LANES][8]u32, blocks: [LANES][16]u32, counters: [LANES]u64, lengths: [LANES]u32, flags: [LANES]u32) ![LANES][16]u32 {
    for (lengths) |length| if (length > 64) return error.InvalidBlake3BlockLength;
    var state: [16]V = undefined;
    var message: [16]V = undefined;
    inline for (0..8) |i| state[i] = .{ cv[0][i], cv[1][i], cv[2][i], cv[3][i] };
    inline for (0..4) |i| state[8 + i] = @splat(compression.IV[i]);
    var low: [LANES]u32 = undefined;
    var high: [LANES]u32 = undefined;
    for (counters, &low, &high) |counter, *lo, *hi| {
        lo.* = @truncate(counter);
        hi.* = @truncate(counter >> 32);
    }
    state[12] = low;
    state[13] = high;
    state[14] = lengths;
    state[15] = flags;
    inline for (0..16) |i| message[i] = .{ blocks[0][i], blocks[1][i], blocks[2][i], blocks[3][i] };
    var ops = Ops{};
    inline for (0..7) |_| {
        inline for (compression.G_INDICES, 0..) |indices, i| {
            const out = compression.g(Ops, &ops, .{ state[indices[0]], state[indices[1]], state[indices[2]], state[indices[3]], message[2 * i], message[2 * i + 1] }) catch unreachable;
            inline for (indices, 0..) |index, j| state[index] = out[j];
        }
        const old = message;
        inline for (compression.PERMUTATION, 0..) |index, i| message[i] = old[index];
    }
    var result: [LANES][16]u32 = undefined;
    inline for (0..8) |i| {
        const first = state[i] ^ state[i + 8];
        const second = state[i + 8] ^ @as(V, .{ cv[0][i], cv[1][i], cv[2][i], cv[3][i] });
        inline for (0..LANES) |lane| {
            result[lane][i] = first[lane];
            result[lane][i + 8] = second[lane];
        }
    }
    return result;
}
/// A bounded one-chunk message per lane, including empty/full final blocks.
/// Completed short lanes are ignored while longer lanes finish their blocks.
pub fn hashChunk4(messages: [LANES][]const u8) ![LANES][32]u8 {
    var max_blocks: usize = 1;
    for (messages) |bytes| {
        if (bytes.len > 1024) return error.Blake3BatchMessageTooLarge;
        max_blocks = @max(max_blocks, (bytes.len + 63) / 64);
    }
    var cv: [LANES][8]u32 = @splat(compression.IV);
    var result: [LANES][32]u8 = undefined;
    for (0..max_blocks) |block_index| {
        var blocks: [LANES][16]u32 = undefined;
        var lengths: [LANES]u32 = @splat(0);
        var flags: [LANES]u32 = @splat(0);
        var active: [LANES]bool = @splat(false);
        var terminal: [LANES]bool = @splat(false);
        for (messages, 0..) |bytes, lane| {
            var padded: [64]u8 = @splat(0);
            const at = block_index * 64;
            if (at < bytes.len or (block_index == 0 and bytes.len == 0)) {
                active[lane] = true;
                const length = @min(64, bytes.len - at);
                @memcpy(padded[0..length], bytes[at..][0..length]);
                lengths[lane] = @intCast(length);
                terminal[lane] = at + length == bytes.len;
                flags[lane] = (if (block_index == 0) @as(u32, 1) else 0) | (if (terminal[lane]) @as(u32, 2 | 8) else 0);
            }
            inline for (0..16) |word| blocks[lane][word] = std.mem.readInt(u32, padded[word * 4 ..][0..4], .little);
        }
        const output = try compress4(cv, blocks, @splat(0), lengths, flags);
        for (0..LANES) |lane| {
            if (!active[lane]) continue;
            if (terminal[lane]) {
                inline for (0..8) |word| std.mem.writeInt(u32, result[lane][word * 4 ..][0..4], output[lane][word], .little);
            } else cv[lane] = output[lane][0..8].*;
        }
    }
    return result;
}

test "BLAKE3 batch compression preserves every word flags and 64-bit counters" {
    var rng = std.Random.DefaultPrng.init(0x20260926);
    for (0..32) |_| {
        var cvs: [LANES][8]u32 = undefined;
        var blocks: [LANES][16]u32 = undefined;
        rng.random().bytes(std.mem.asBytes(&cvs));
        rng.random().bytes(std.mem.asBytes(&blocks));
        const counters: [LANES]u64 = .{ 0, 0xffffffff, 0x100000000, 0xffffffffffffffff };
        const lengths: [LANES]u32 = .{ 0, 1, 63, 64 };
        const flags: [LANES]u32 = .{ 1, 2 | 8, 1 | 2 | 8, 4 };
        const result = try compress4(cvs, blocks, counters, lengths, flags);
        for (0..LANES) |lane| try std.testing.expectEqualDeep(try compression.compress(cvs[lane], blocks[lane], counters[lane], lengths[lane], flags[lane]), result[lane]);
    }
}
test "BLAKE3 batch chunk hashes match independent std at mixed block boundaries" {
    var bytes: [1024]u8 = undefined;
    var rng = std.Random.DefaultPrng.init(0x20260927);
    rng.random().bytes(&bytes);
    const lengths = [_][LANES]usize{ .{ 0, 1, 63, 64 }, .{ 65, 68, 72, 92 }, .{ 127, 128, 129, 1024 }, .{ 1024, 0, 512, 64 } };
    for (lengths) |group| {
        var messages: [LANES][]const u8 = undefined;
        for (group, &messages) |length, *message| message.* = bytes[0..length];
        const actual = try hashChunk4(messages);
        for (messages, actual) |message, digest| {
            var expected: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash(message, &expected, .{});
            try std.testing.expectEqualSlices(u8, &expected, &digest);
        }
    }
    try std.testing.expectError(error.InvalidBlake3BlockLength, compress4(@splat(compression.IV), @splat(@splat(0)), @splat(0), .{ 0, 64, 65, 1 }, @splat(1)));
}
