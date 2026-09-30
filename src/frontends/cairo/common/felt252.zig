//! Cairo field element: 252-bit prime field.
//!
//! P = 2^251 + 17 * 2^192 + 1
//!
//! Stored as 4 x u64 limbs (little-endian). For AIR constraint evaluation,
//! decomposed into 28 x 9-bit words represented as M31 elements.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

/// Number of 9-bit words in a Felt252 decomposition.
pub const N_WORDS: usize = 28;

/// Bits per word in the standard decomposition.
pub const BITS_PER_WORD: usize = 9;

/// Word mask for 9-bit extraction.
const WORD_MASK: u64 = (1 << BITS_PER_WORD) - 1; // 0x1FF

/// Number of 27-bit words in the wide decomposition.
pub const WIDTH27_N_WORDS: usize = 10;

/// Bits per word in the wide decomposition.
pub const WIDTH27_BITS_PER_WORD: usize = 27;

/// P = 2^251 + 17 * 2^192 + 1 (`core.fields.stark_prime`), as 4 x u64 limbs
/// (little-endian).
pub const PRIME: [4]u64 = blk: {
    const p = @import("stwo_core").fields.stark_prime;
    break :blk .{ @truncate(p), @truncate(p >> 64), @truncate(p >> 128), @truncate(p >> 192) };
};

/// P - 1 as 8 x u32 limbs (little-endian).
pub const P_MIN_1: [8]u32 = .{ 0, 0, 0, 0, 0, 0, 0x11, 0x0800_0000 };

/// P - 2 as 8 x u32 limbs (little-endian).
pub const P_MIN_2: [8]u32 = .{ 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x10, 0x0800_0000 };

/// P decomposed into 28 x 9-bit limbs (little-endian) as u32 values.
pub const P_FELTS: [N_WORDS]u32 = blk: {
    var result: [N_WORDS]u32 = .{0} ** N_WORDS;
    result[0] = 1;
    result[21] = 136; // 17 << 3 (17 * 2^192 starts at bit 192, word 21 = 192/9)
    result[27] = 256; // 2^251 starts at bit 251, word 27 = 251/9 (remainder 8, so 1<<8=256)
    break :blk result;
};

/// A Cairo field element (Felt252).
///
/// Stored as 4 x u64 limbs in little-endian order.
pub const Felt252 = struct {
    limbs: [4]u64,

    pub const ZERO: Felt252 = .{ .limbs = .{ 0, 0, 0, 0 } };
    pub const ONE: Felt252 = .{ .limbs = .{ 1, 0, 0, 0 } };

    /// Create from a small integer.
    pub fn fromU64(value: u64) Felt252 {
        return .{ .limbs = .{ value, 0, 0, 0 } };
    }

    /// Create from 8 x u32 limbs (little-endian), as used in memory representation.
    pub fn fromU32x8(words: [8]u32) Felt252 {
        return .{
            .limbs = .{
                @as(u64, words[0]) | (@as(u64, words[1]) << 32),
                @as(u64, words[2]) | (@as(u64, words[3]) << 32),
                @as(u64, words[4]) | (@as(u64, words[5]) << 32),
                @as(u64, words[6]) | (@as(u64, words[7]) << 32),
            },
        };
    }

    /// Convert to 8 x u32 limbs (little-endian).
    pub fn toU32x8(self: Felt252) [8]u32 {
        return .{
            @truncate(self.limbs[0]),
            @truncate(self.limbs[0] >> 32),
            @truncate(self.limbs[1]),
            @truncate(self.limbs[1] >> 32),
            @truncate(self.limbs[2]),
            @truncate(self.limbs[2] >> 32),
            @truncate(self.limbs[3]),
            @truncate(self.limbs[3] >> 32),
        };
    }

    /// Extract the i-th 9-bit word as an M31 element.
    pub fn getM31(self: Felt252, index: usize) M31 {
        std.debug.assert(index < N_WORDS);
        const bit_offset = index * BITS_PER_WORD;
        const limb_idx = bit_offset / 64;
        const bit_idx = @as(u6, @intCast(bit_offset % 64));

        var word: u64 = self.limbs[limb_idx] >> bit_idx;
        // Handle cross-limb boundary.
        if (bit_idx + BITS_PER_WORD > 64 and limb_idx + 1 < 4) {
            const carry_shift: u6 = @intCast(@as(u7, 64) - @as(u7, bit_idx));
            word |= self.limbs[limb_idx + 1] << carry_shift;
        }
        return M31.fromCanonical(@intCast(word & WORD_MASK));
    }

    /// All 28 9-bit words, little-endian: upstream `split_f252` /
    /// `Felt252::get_limbs`. The value is not reduced modulo P.
    pub fn limbs9(self: Felt252) [N_WORDS]M31 {
        var words: [N_WORDS]M31 = undefined;
        for (&words, 0..) |*word, index| word.* = self.getM31(index);
        return words;
    }

    /// Reconstruct from 28 x 9-bit M31 words.
    pub fn fromM31Words(words: [N_WORDS]M31) Felt252 {
        var result = Felt252.ZERO;
        for (0..N_WORDS) |i| {
            const bit_offset = i * BITS_PER_WORD;
            const limb_idx = bit_offset / 64;
            const bit_idx: u6 = @intCast(bit_offset % 64);
            result.limbs[limb_idx] |= @as(u64, words[i].v) << bit_idx;
            if (bit_idx + BITS_PER_WORD > 64 and limb_idx + 1 < 4) {
                const carry_shift: u6 = @intCast(@as(u7, 64) - @as(u7, bit_idx));
                result.limbs[limb_idx + 1] |= @as(u64, words[i].v) >> carry_shift;
            }
        }
        return result;
    }

    /// Returns true if the value fits in 72 bits (small value threshold).
    pub fn isSmall(self: Felt252) bool {
        const words = self.toU32x8();
        // Small if words[3..8] are all zero except words[2] < (1 << 8).
        return words[2] < (1 << 8) and
            words[3] == 0 and words[4] == 0 and words[5] == 0 and
            words[6] == 0 and words[7] == 0;
    }

    /// Convert a small Felt252 to u128 (assumes isSmall()).
    pub fn toSmallU128(self: Felt252) u128 {
        std.debug.assert(self.isSmall());
        return @as(u128, self.limbs[1]) << 64 | @as(u128, self.limbs[0]);
    }

    pub fn eql(a: Felt252, b: Felt252) bool {
        return a.limbs[0] == b.limbs[0] and a.limbs[1] == b.limbs[1] and
            a.limbs[2] == b.limbs[2] and a.limbs[3] == b.limbs[3];
    }
};

// ---------------------------------------------------------------
// Tests
// ---------------------------------------------------------------

test "felt252: zero and one" {
    try std.testing.expect(Felt252.ZERO.eql(Felt252.fromU64(0)));
    try std.testing.expect(Felt252.ONE.eql(Felt252.fromU64(1)));
}

test "felt252: m31 word roundtrip" {
    const val = Felt252.fromU64(0x1FFFFFFFFFF); // 41 bits set
    var words: [N_WORDS]M31 = undefined;
    for (0..N_WORDS) |i| words[i] = val.getM31(i);
    const reconstructed = Felt252.fromM31Words(words);
    try std.testing.expect(val.eql(reconstructed));
}

test "felt252: u32x8 roundtrip" {
    const words: [8]u32 = .{ 0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0, 0, 0, 0, 0 };
    const val = Felt252.fromU32x8(words);
    const back = val.toU32x8();
    try std.testing.expectEqualSlices(u32, &words, &back);
}

test "felt252: isSmall" {
    try std.testing.expect(Felt252.fromU64(42).isSmall());
    try std.testing.expect(Felt252.fromU64((1 << 63) - 1).isSmall());
    // Not small: bit 72+ set
    const big = Felt252{ .limbs = .{ 0, 0, 1 << 8, 0 } };
    try std.testing.expect(!big.isSmall());
}

test "felt252: P_FELTS decomposition" {
    // P = 2^251 + 17 * 2^192 + 1
    // Word 0: 1 (the +1)
    try std.testing.expectEqual(@as(u32, 1), P_FELTS[0]);
    // Word 21: 136 = 17 * 8 (17 * 2^192, and 192 = 21*9 + 3, so 17 << 3 = 136)
    try std.testing.expectEqual(@as(u32, 136), P_FELTS[21]);
    // Word 27: 256 = 2^8 (2^251 = 2^(27*9+8), so 1 << 8 = 256)
    try std.testing.expectEqual(@as(u32, 256), P_FELTS[27]);
}
