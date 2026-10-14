//! Experimental S31 context for CAS05. Both sides must derive this from an
//! installed key and an independently reconstructed public statement.
//! A caller-supplied roster digest has no authority by itself.
const std = @import("std");
const Channel = @import("../channel/blake2s.zig").Blake2sChannel;

const PRELUDE_TAG: u64 = 0x5333_3150_524c_3031; // S31PRL01
const KEY_TAG: u64 = 0x5333_314b_4559_3031; // S31KEY01
const PUBLIC_TAG: u64 = 0x5333_3150_5542_3031; // S31PUB01
const ROSTER_TAG: u64 = 0x5333_3152_5354_3031; // S31RST01

pub const Binding = struct {
    /// SHA-256 of the complete installed S31 candidate key bytes.
    installed_key_sha256: [32]u8,
    /// Reconstructed from the public ABI, never copied from a proof header.
    public_words: [8]u32,
    /// Digest of the compiler-owned, ordered source-to-AIR column/claim roster.
    source_air_roster_sha256: [32]u8,
};

/// Fixed-order, typed absorption before CAS05 binds its own v6 version and
/// source-root/profile. Each field gets a distinct tag. Digest bytes are
/// parsed as little-endian u32 words, matching the Blake2s channel's wire.
pub fn mix(channel: *Channel, binding: Binding) void {
    channel.mixU64(PRELUDE_TAG);
    channel.mixU64(KEY_TAG);
    mixDigest(channel, binding.installed_key_sha256);
    channel.mixU64(PUBLIC_TAG);
    channel.mixU32s(&binding.public_words);
    channel.mixU64(ROSTER_TAG);
    mixDigest(channel, binding.source_air_roster_sha256);
}

fn mixDigest(channel: *Channel, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i|
        word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

test "S31 prelude has fixed bytes and separates key, words, and roster" {
    const binding = Binding{
        .installed_key_sha256 = [_]u8{0x11} ** 32,
        .public_words = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .source_air_roster_sha256 = [_]u8{0x22} ** 32,
    };
    var channel = Channel{};
    mix(&channel, binding);
    // Independently computed as repeated hashlib.blake2s(previous_digest ||
    // little-endian typed input) from an all-zero initial digest.
    const expected = [32]u8{
        0x5a, 0x03, 0x96, 0xd7, 0xdd, 0xc8, 0x09, 0xea,
        0x60, 0xb9, 0x0f, 0x77, 0xbc, 0xd5, 0xa0, 0x69,
        0xd6, 0x8c, 0x26, 0x60, 0x5b, 0x00, 0x59, 0x71,
        0x05, 0x63, 0x3c, 0x6a, 0x84, 0xc7, 0x8f, 0x38,
    };
    try std.testing.expectEqualSlices(u8, &expected, &channel.digest);
    const digest = channel.digest;
    var changed = binding;
    changed.installed_key_sha256[0] ^= 1;
    var with_key_change = Channel{};
    mix(&with_key_change, changed);
    try std.testing.expect(!std.mem.eql(u8, &digest, &with_key_change.digest));
    changed = binding;
    changed.public_words[0] ^= 1;
    var with_word_change = Channel{};
    mix(&with_word_change, changed);
    try std.testing.expect(!std.mem.eql(u8, &digest, &with_word_change.digest));
    changed = binding;
    changed.source_air_roster_sha256[0] ^= 1;
    var with_roster_change = Channel{};
    mix(&with_roster_change, changed);
    try std.testing.expect(!std.mem.eql(u8, &digest, &with_roster_change.digest));
}
