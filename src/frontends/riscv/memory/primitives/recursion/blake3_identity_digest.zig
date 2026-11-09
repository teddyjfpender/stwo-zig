//! Lossless public-field encoding for BLAKE3 statement identities.
//! This is a new-format building block, not the legacy eight-M31-word digest.
//! AIR consumers must constrain every encoded word to 16 bits. Merely checking
//! M31 canonicality does not enforce this encoding.
const std = @import("std");

pub const BYTE_COUNT = 32;
pub const WORD_COUNT = 16;
pub const Words = [WORD_COUNT]u32;
pub const Error = error{NonCanonicalDigestLimb};

/// A struct deliberately prevents assignment from legacy [8]u32 identities.
/// All 256 bits are retained, including the high bit of each hash word.
pub const Digest = struct {
    bytes: [BYTE_COUNT]u8,

    pub fn toWords(self: Digest) Words {
        var words: Words = undefined;
        for (&words, 0..) |*word, i|
            word.* = std.mem.readInt(u16, self.bytes[i * 2 ..][0..2], .little);
        return words;
    }

    pub fn fromWords(words: Words) Error!Digest {
        var result: Digest = undefined;
        for (words, 0..) |word, i| {
            // Reject before narrowing; reduction/truncation creates aliases.
            const limb = std.math.cast(u16, word) orelse
                return error.NonCanonicalDigestLimb;
            std.mem.writeInt(u16, result.bytes[i * 2 ..][0..2], limb, .little);
        }
        return result;
    }
};

test "BLAKE3 identity encoding pins byte order and preserves all high bits" {
    const digest = Digest{ .bytes = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x87,
        0x08, 0x09, 0x0a, 0x8b, 0x0c, 0x0d, 0x0e, 0x8f,
        0x10, 0x11, 0x12, 0x93, 0x14, 0x15, 0x16, 0x97,
        0x18, 0x19, 0x1a, 0x9b, 0x1c, 0x1d, 0x1e, 0xff,
    } };
    const expected = Words{
        0x0100, 0x0302, 0x0504, 0x8706, 0x0908, 0x8b0a, 0x0d0c, 0x8f0e,
        0x1110, 0x9312, 0x1514, 0x9716, 0x1918, 0x9b1a, 0x1d1c, 0xff1e,
    };
    try std.testing.expectEqual(expected, digest.toWords());
    try std.testing.expectEqual(digest, try Digest.fromWords(expected));
    const ones = Digest{ .bytes = @splat(0xff) };
    try std.testing.expectEqual(ones, try Digest.fromWords(ones.toWords()));
}

test "BLAKE3 identity rejects M31-canonical aliases at every limb" {
    for (0..WORD_COUNT) |i| {
        for ([_]u32{ 0x10000, 0x7ffffffe, 0x7fffffff, 0xffffffff }) |invalid| {
            var words: Words = @splat(0);
            words[i] = invalid;
            try std.testing.expectError(error.NonCanonicalDigestLimb, Digest.fromWords(words));
        }
    }
}

test "every BLAKE3 digest bit changes its field encoding" {
    const zero = (Digest{ .bytes = @splat(0) }).toWords();
    for (0..256) |bit| {
        var digest = Digest{ .bytes = @splat(0) };
        digest.bytes[bit / 8] = @as(u8, 1) << @as(u3, @intCast(bit % 8));
        const words = digest.toWords();
        try std.testing.expect(!std.mem.eql(u32, &zero, &words));
        try std.testing.expectEqual(digest, try Digest.fromWords(words));
    }
}
