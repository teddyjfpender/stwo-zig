//! Four independent nonce candidates using the canonical BLAKE3 G schedule.
//! The 64-byte public PoW prefix has already been compressed with CHUNK_START.
//! Only the first final output word is needed by the unchanged nonce predicate.
const std = @import("std");
const core = @import("stwo_core");
const compression = core.crypto.blake3_compression;
pub const LANES = 4;
const V = @Vector(LANES, u32);
const Ops = struct {
    pub const Word = V;
    pub fn add(_: *Ops, a: V, b: V) !V {
        return a +% b;
    }
    pub fn xorRotate(_: *Ops, a: V, b: V, comptime rotation: u5) !V {
        const value = a ^ b;
        const left: u5 = @intCast(32 - @as(u6, rotation));
        return (value >> @as(@Vector(LANES, u5), @splat(rotation))) |
            (value << @as(@Vector(LANES, u5), @splat(left)));
    }
};
pub fn firstWords(cv: [8]u32, nonces: [LANES]u64) [LANES]u32 {
    var state: [16]V = undefined;
    inline for (0..8) |i| state[i] = @splat(cv[i]);
    inline for (0..4) |i| state[8 + i] = @splat(compression.IV[i]);
    state[12] = @splat(0);
    state[13] = @splat(0);
    state[14] = @splat(8); // Final block: one little-endian u64 nonce.
    state[15] = @splat(2 | 8); // CHUNK_END | ROOT, not CHUNK_START.
    var low: [LANES]u32 = undefined;
    var high: [LANES]u32 = undefined;
    for (nonces, &low, &high) |nonce, *lo, *hi| {
        lo.* = @truncate(nonce);
        hi.* = @truncate(nonce >> 32);
    }
    var message: [16]V = @splat(@splat(0));
    message[0] = low;
    message[1] = high;
    var ops = Ops{};
    inline for (0..7) |_| {
        inline for (compression.G_INDICES, 0..) |indices, i| {
            const out = compression.g(Ops, &ops, .{ state[indices[0]], state[indices[1]], state[indices[2]], state[indices[3]], message[2 * i], message[2 * i + 1] }) catch unreachable;
            inline for (indices, 0..) |index, j| state[index] = out[j];
        }
        const old = message;
        inline for (compression.PERMUTATION, 0..) |index, i| message[i] = old[index];
    }
    return state[0] ^ state[8];
}

test "BLAKE3 PoW batch matches streaming hash at nonce carries and full difficulty" {
    const Channel = core.channel.blake3.Channel;
    const groups = [_][LANES]u64{
        .{ 0, 1, 0xfffffffe, 0xffffffff },
        .{ 0x100000000, 0x8000000000000000, 0xfffffffffffffffe, 0xffffffffffffffff },
    };
    for ([_]u32{ 0, 1, 12, 26, 32 }) |bits| {
        var channel = Channel{};
        channel.mixU32s(&.{ 0x12345678, bits, 0xffffffff });
        for (groups) |nonces| {
            const actual = firstWords(try channel.powChainingValue(bits), nonces);
            for (nonces, actual) |nonce, word| {
                var reference = channel.powPrefix(bits);
                var bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &bytes, nonce, .little);
                reference.update(&bytes);
                const digest = reference.finalize();
                try std.testing.expectEqual(std.mem.readInt(u32, digest[0..4], .little), word);
                try std.testing.expectEqual(channel.verifyPowNonce(bits, nonce), @ctz(word) >= bits);
            }
        }
    }
}
