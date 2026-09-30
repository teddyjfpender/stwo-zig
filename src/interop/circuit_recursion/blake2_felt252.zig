//! A leaf's output digest from its decimal felt preimage.
//!
//! `LeafInput::output_digest` (`crates/stwo_run_and_prove_recursive_tree/src/
//! leaf_io.rs` at https://github.com/starkware-libs/proving commit
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): parse each felt with
//! `Felt::from_dec_str`, encode the list with
//! `Blake2Felt252::encode_felts_to_u32s` (starknet-types-core 0.2.4), hash the
//! words' little-endian bytes with Blake2s-256, and read the digest as eight
//! little-endian `u32` words.
//!
//! `encode_felts_to_u32s` writes a felt below 2^63 as two big-endian words
//! (bits 63..32, 31..0) and any other felt as its eight big-endian words with
//! bit 31 of the first set. `from_dec_str` accepts an optional leading `-`
//! (negation modulo the Stark prime) and one or more ASCII digits, and reduces
//! the value modulo the prime. Its 256-bit accumulator
//! (`UnsignedInteger::from_dec_str`, lambdaworks-math 0.13) rejects a multiply
//! by ten that overflows but adds each digit with `+`, which only
//! `debug_assert`s; upstream's release build therefore wraps that add modulo
//! 2^256 (`2^256` parses as 0 and `2^256 + 3` as 3, while `2^256 + 4`
//! overflows the multiply and is rejected).

const std = @import("std");

/// The Stark field prime, 2^251 + 17 * 2^192 + 1.
pub const stark_prime: u256 = (1 << 251) + 17 * (1 << 192) + 1;
const small_threshold: u256 = 1 << 63;
const big_marker: u32 = 1 << 31;

pub const Error = error{
    /// `Felt::from_dec_str` rejects the text.
    InvalidDecimalFelt,
} || std.mem.Allocator.Error;

/// `Felt::from_dec_str`: the canonical felt of a decimal string.
pub fn parseDecimalFelt(text: []const u8) Error!u256 {
    const negative = text.len != 0 and text[0] == '-';
    const digits = if (negative) text[1..] else text;
    if (digits.len == 0) return error.InvalidDecimalFelt;
    var value: u256 = 0;
    for (digits) |char| {
        if (!std.ascii.isDigit(char)) return error.InvalidDecimalFelt;
        const scaled = @mulWithOverflow(value, 10);
        if (scaled[1] != 0) return error.InvalidDecimalFelt;
        // Wrapping, as upstream's release build (see the module comment).
        value = scaled[0] +% (char - '0');
    }
    const reduced = value % stark_prime;
    return if (negative and reduced != 0) stark_prime - reduced else reduced;
}

/// Appends `Blake2Felt252::encode_felts_to_u32s([felt])` to `words`.
pub fn appendFeltWords(allocator: std.mem.Allocator, words: *std.ArrayList(u32), felt: u256) std.mem.Allocator.Error!void {
    std.debug.assert(felt < stark_prime);
    if (felt < small_threshold) {
        try words.appendSlice(allocator, &.{ @truncate(felt >> 32), @truncate(felt) });
        return;
    }
    var limbs: [8]u32 = undefined;
    for (&limbs, 0..) |*limb, index| limb.* = @truncate(felt >> @intCast(32 * (7 - index)));
    limbs[0] |= big_marker;
    try words.appendSlice(allocator, &limbs);
}

/// The leaf's output digest: eight little-endian words of
/// `blake2s(encode_felts_to_u32s(preimage))`.
pub fn outputDigest(allocator: std.mem.Allocator, preimage: []const []const u8) Error![8]u32 {
    var words: std.ArrayList(u32) = .empty;
    defer words.deinit(allocator);
    for (preimage) |text| try appendFeltWords(allocator, &words, try parseDecimalFelt(text));
    var hasher = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (words.items) |word| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        hasher.update(&bytes);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var out: [8]u32 = undefined;
    for (&out, 0..) |*word, index| word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    return out;
}

test "blake2 felt252: decimal parsing follows Felt::from_dec_str" {
    try std.testing.expectEqual(@as(u256, 0), try parseDecimalFelt("0"));
    try std.testing.expectEqual(@as(u256, 0), try parseDecimalFelt("-0"));
    try std.testing.expectEqual(stark_prime - 5, try parseDecimalFelt("-5"));
    try std.testing.expectEqual(@as(u256, 1), try parseDecimalFelt("3618502788666131213697322783095070105623107215331596699973092056135872020482"));
    try std.testing.expectEqual(@as(u256, 7), try parseDecimalFelt("007"));
    try std.testing.expectError(error.InvalidDecimalFelt, parseDecimalFelt(""));
    try std.testing.expectError(error.InvalidDecimalFelt, parseDecimalFelt("-"));
    try std.testing.expectError(error.InvalidDecimalFelt, parseDecimalFelt("+1"));
    try std.testing.expectError(error.InvalidDecimalFelt, parseDecimalFelt("0x1"));
    // The digit add wraps modulo 2^256; an overflowing multiply is rejected.
    try std.testing.expectEqual(@as(u256, 0), try parseDecimalFelt("115792089237316195423570985008687907853269984665640564039457584007913129639936"));
    try std.testing.expectEqual(@as(u256, 3), try parseDecimalFelt("115792089237316195423570985008687907853269984665640564039457584007913129639939"));
    try std.testing.expectEqual(stark_prime - 3, try parseDecimalFelt("-115792089237316195423570985008687907853269984665640564039457584007913129639939"));
    try std.testing.expectError(
        error.InvalidDecimalFelt,
        parseDecimalFelt("115792089237316195423570985008687907853269984665640564039457584007913129639940"),
    );
}

test "blake2 felt252: small and big felts use two and eight words" {
    const allocator = std.testing.allocator;
    var words: std.ArrayList(u32) = .empty;
    defer words.deinit(allocator);
    try appendFeltWords(allocator, &words, (1 << 63) - 1);
    try appendFeltWords(allocator, &words, 1 << 63);
    try std.testing.expectEqualSlices(u32, &.{ 0x7fffffff, 0xffffffff, 0x80000000, 0, 0, 0, 0, 0, 0x80000000, 0 }, words.items);
}
