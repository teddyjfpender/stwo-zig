//! `rand_chacha` 0.3 `ChaCha20Rng`, reproduced word for word.
//!
//! Recursion circuits derive ZK blinding values from
//! `ChaCha20Rng::from_seed(seed).next_u32()` (`crates/circuit_common/src/finalize.rs`
//! of https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, which locks `rand_chacha 0.3.1`).
//! The generator is the original (djb) ChaCha20 block function keyed by the
//! 32-byte seed, with a 64-bit block counter starting at 0 and a zero 64-bit
//! stream id. `rand_core`'s `BlockRng` refills four blocks (64 words) at a time
//! and hands them out in order, so `nextU32` is exactly the keystream read as
//! consecutive little-endian words. The refill granularity is kept so that the
//! buffer position matches upstream's `get_word_pos` at every call.
//!
//! This is a deterministic expansion of a public seed, not an entropy source.

const std = @import("std");

const ChaCha20 = std.crypto.stream.chacha.ChaCha20With64BitNonce;

pub const ChaCha20Rng = struct {
    key: [32]u8,
    /// Block counter of the first block in `buffer`.
    next_block: u64 = 0,
    buffer: [buffer_words]u32 = undefined,
    /// Next unread word of `buffer`; `buffer_words` means empty.
    index: usize = buffer_words,

    /// `rand_chacha`'s `BUF_BLOCKS`: blocks produced per refill.
    pub const buffer_blocks = 4;
    const block_words = 16;
    const buffer_words = buffer_blocks * block_words;

    pub fn fromSeed(seed: [32]u8) ChaCha20Rng {
        return .{ .key = seed };
    }

    pub fn nextU32(self: *ChaCha20Rng) u32 {
        if (self.index == buffer_words) self.refill();
        const word = self.buffer[self.index];
        self.index += 1;
        return word;
    }

    fn refill(self: *ChaCha20Rng) void {
        var bytes: [buffer_words * 4]u8 = undefined;
        // A 2^64-block counter is unreachable for the circuit's bounded draws;
        // `stream` asserts the range instead of silently wrapping.
        ChaCha20.stream(&bytes, self.next_block, self.key, [_]u8{0} ** ChaCha20.nonce_length);
        for (&self.buffer, 0..) |*word, i| {
            word.* = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
        }
        self.next_block += buffer_blocks;
        self.index = 0;
    }
};

fn drawWords(rng: *ChaCha20Rng, out: []u32) void {
    for (out) |*word| word.* = rng.nextU32();
}

test "chacha20 rng: rand_chacha 0.3.1 test_chacha_true_values_a" {
    // rand_chacha-0.3.1/src/chacha.rs, test vectors 1 and 2 of
    // draft-nir-cfrg-chacha20-poly1305-04.
    var rng = ChaCha20Rng.fromSeed([_]u8{0} ** 32);
    var words: [16]u32 = undefined;
    drawWords(&rng, &words);
    try std.testing.expectEqualSlices(u32, &.{
        0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653, 0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
        0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8, 0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
    }, &words);
    drawWords(&rng, &words);
    try std.testing.expectEqualSlices(u32, &.{
        0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73, 0xa0290fcb, 0x6965e348, 0x3e53c612, 0xed7aee32,
        0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874, 0x281fed31, 0x45fb0a51, 0x1f0ae1ac, 0x6f4d794b,
    }, &words);
}

test "chacha20 rng: rand_chacha 0.3.1 test_chacha_true_values_b and _c" {
    // Test vector 3: key with a trailing 1, block 1.
    var seed_b = [_]u8{0} ** 32;
    seed_b[31] = 1;
    var rng_b = ChaCha20Rng.fromSeed(seed_b);
    var skipped: [16]u32 = undefined;
    drawWords(&rng_b, &skipped);
    var words: [16]u32 = undefined;
    drawWords(&rng_b, &words);
    try std.testing.expectEqualSlices(u32, &.{
        0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1, 0xe8252083, 0x60818b01, 0xf38422b8, 0x5aaa49c9,
        0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f, 0x4436274e, 0x2561b3c8, 0xebdd4aa6, 0xa0136c00,
    }, &words);

    // Test vector 4: key byte 1 = 0xff, block 2.
    var seed_c = [_]u8{0} ** 32;
    seed_c[1] = 0xff;
    var rng_c = ChaCha20Rng.fromSeed(seed_c);
    var skipped_two: [32]u32 = undefined;
    drawWords(&rng_c, &skipped_two);
    drawWords(&rng_c, &words);
    try std.testing.expectEqualSlices(u32, &.{
        0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394, 0xa78dea8f, 0x5e269039, 0xa1bebbc1, 0xcaf09aae,
        0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6, 0x546ca624, 0x1bec45d5, 0x87f47473, 0x96f0992e,
    }, &words);
}

test "chacha20 rng: rand_chacha 0.3.1 test_chacha_construction and multiple_blocks" {
    var seed = [_]u8{0} ** 32;
    seed[8] = 1;
    seed[16] = 2;
    seed[24] = 3;
    var first = ChaCha20Rng.fromSeed(seed);
    try std.testing.expectEqual(@as(u32, 137206642), first.nextU32());

    // The i-th word of the i-th block for 16 blocks: crosses four refills.
    var seed_multi: [32]u8 = undefined;
    for (&seed_multi, 0..) |*byte, i| byte.* = if (i % 4 == 0) @intCast(i / 4) else 0;
    var rng = ChaCha20Rng.fromSeed(seed_multi);
    var diagonal: [16]u32 = undefined;
    for (&diagonal) |*word| {
        word.* = rng.nextU32();
        for (0..16) |_| _ = rng.nextU32();
    }
    try std.testing.expectEqualSlices(u32, &.{
        0xf225c81a, 0x6ab1be57, 0x04d42951, 0x70858036, 0x49884684, 0x64efec72, 0x4be2d186, 0x3615b384,
        0x11cfa18e, 0xd3c50049, 0x75c775f6, 0x434c6530, 0x2c5bad8f, 0x898881dc, 0x5f1c86d9, 0xc1f8e7f4,
    }, &diagonal);
}

test "chacha20 rng: words match rand_chacha 0.3.1 across a buffer refill" {
    // Oracle: `rand_chacha::ChaCha20Rng::from_seed([0, 1, .., 31])` then 70 x
    // `next_u32()`, rand_chacha 0.3.1 as locked by proving@5a7c5ed's Cargo.lock.
    // Words 64..69 come from the second four-block refill.
    var seed: [32]u8 = undefined;
    for (&seed, 0..) |*byte, i| byte.* = @intCast(i);
    var rng = ChaCha20Rng.fromSeed(seed);
    var words: [70]u32 = undefined;
    drawWords(&rng, &words);
    try std.testing.expectEqualSlices(u32, &.{
        0x7d2bfd39, 0x6a19c5d9, 0x7703bd8d, 0x494adcb8, 0x6fd8358a, 0xcc6adebc, 0x4c7dccb2, 0x9224ead8,
        0xe7cc232b, 0xab2360a2, 0x69ef0e3f, 0x647fc83a, 0xea358225, 0x2da3f7b1, 0xa06227c2, 0x0c415b48,
        0x3142b818, 0xd1a6e6ad, 0x615c6113, 0x274e43af, 0xf5f3b1f8, 0x5c5bade1, 0x12fcf8ec, 0x5c75352a,
        0x6d080872, 0x5d3ceed1, 0x2458819d, 0x3c000e64, 0x5ef6a09b, 0xce595dde, 0x7f4a2a0d, 0xcd5a9531,
        0xdc2df242, 0xd5924aa7, 0xef8aa76c, 0x3b728e29, 0x367f2360, 0xb7beea47, 0x309ce0f3, 0xe2e380ce,
        0x1b02a884, 0x240b5c8a, 0x8d3ccd94, 0x7e50135b, 0x78a0e7c7, 0xe2a3f44d, 0xd26281ea, 0x239dc561,
        0xc011abe7, 0x7e3b3cf7, 0x503998b0, 0xa0c4e2b3, 0xa93d848f, 0xb3fcb75f, 0x815634f1, 0x82b7516b,
        0xbdf9f24d, 0xb4d41356, 0xd82f95ed, 0x981bcd58, 0xfff8cb4a, 0xc8a7d11f, 0xa81cd806, 0x2c3baee4,
        0x18a1dbff, 0x438c5827, 0xea34548f, 0x8fbe56c9, 0xad43a095, 0x0afdcd04,
    }, &words);
}
