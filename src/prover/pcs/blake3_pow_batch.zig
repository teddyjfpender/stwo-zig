//! Four independent nonce candidates using the canonical BLAKE3 G schedule.
//! The 64-byte public PoW prefix has already been compressed with CHUNK_START.
//! Only the first final output word is needed by the unchanged nonce predicate.
const std = @import("std");
const core = @import("stwo_core");
const batch = core.crypto.blake3_compression_batch;
pub const LANES = batch.LANES;
pub fn firstWords(cv: [8]u32, nonces: [LANES]u64) [LANES]u32 {
    var blocks: [LANES][16]u32 = @splat(@splat(0));
    for (nonces, &blocks) |nonce, *block| {
        block[0] = @truncate(nonce);
        block[1] = @truncate(nonce >> 32);
    }
    // The public prefix has already consumed CHUNK_START. The nonce is the
    // final eight-byte block; only ROOT output word zero enters the predicate.
    const output = batch.compress4(@splat(cv), blocks, @splat(0), @splat(8), @splat(2 | 8)) catch unreachable;
    return .{ output[0][0], output[1][0], output[2][0], output[3][0] };
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
