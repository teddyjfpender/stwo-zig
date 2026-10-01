//! Official Cairo transcript operations outside the generic Stwo proof.

const std = @import("std");
const core = @import("stwo_core");
const statement_bootstrap = @import("../statement_bootstrap.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const interaction_pow_bits: u32 = core.cairo_air_layout.interaction_pow_bits;

const lookup_transcript = core.channel.lookup_transcript;

pub const LookupElements = lookup_transcript.LookupElements;
pub const mixChannelSalt = lookup_transcript.mixChannelSalt;

/// `FlatClaim::mix_into::<MC>` over statement ordinals 10 through 16: the
/// enable-bit count, the enable bits, the component log sizes, the program
/// length and the public claim as packed QM31s, then `MC::mix_hash` of the
/// output and program roots. The roots themselves are `MC::H` digests, the
/// plain Blake2s hasher for every Blake2s Merkle channel
/// (`Blake2sM31MerkleChannel::H` is `Blake2sMerkleHasher`); only `mix_hash`
/// differs between the official lane and the leaf lane.
pub fn mixClaim(
    comptime MC: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    statement: *const statement_bootstrap.OwnedStatementBootstrap,
) !void {
    for ([_]u32{ 10, 11, 12, 13, 14 }) |ordinal|
        try mixPackedWords(allocator, channel, statement.words(ordinal).?);
    MC.mixRoot(channel, rootBytes(statement.words(15).?));
    MC.mixRoot(channel, rootBytes(statement.words(16).?));
}

/// The 24-bit interaction grind, then its mix. Blake2s channels grind in Rust
/// `SimdBackend` order (`core.channel.blake2s.pow_order`), which both the
/// official lane and the leaf lane reproduce.
pub fn grindInteraction(channel: anytype) u64 {
    const nonce = channel.grind(interaction_pow_bits);
    channel.mixU64(nonce);
    return nonce;
}

pub const drawLookupElements = lookup_transcript.drawLookupElements;
pub const mixInteractionClaim = lookup_transcript.mixInteractionClaim;

fn mixPackedWords(
    allocator: std.mem.Allocator,
    channel: anytype,
    words: []const u32,
) !void {
    if (words.len % 4 != 0) return error.InvalidStatementGeometry;
    const felts = try allocator.alloc(QM31, words.len / 4);
    defer allocator.free(felts);
    var offset: usize = 0;
    for (felts) |*felt| {
        felt.* = QM31.fromM31(
            M31.fromCanonical(words[offset]),
            M31.fromCanonical(words[offset + 1]),
            M31.fromCanonical(words[offset + 2]),
            M31.fromCanonical(words[offset + 3]),
        );
        offset += 4;
    }
    channel.mixFelts(felts);
}

fn rootBytes(words: []const u32) [32]u8 {
    std.debug.assert(words.len == 8);
    var bytes: [32]u8 = undefined;
    for (words, 0..) |word, index|
        std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    return bytes;
}

test "Cairo transcript: the channel salt is reduced modulo P" {
    const Channel = core.channel.blake2s.Blake2sM31Channel;
    var reduced = Channel{};
    mixChannelSalt(&reduced, 0x7fff_ffff);
    var zero = Channel{};
    mixChannelSalt(&zero, 0);
    try std.testing.expectEqualSlices(u8, &zero.digestBytes(), &reduced.digestBytes());
    var wrapped = Channel{};
    mixChannelSalt(&wrapped, 0xffff_ffff);
    var one = Channel{};
    mixChannelSalt(&one, 1);
    try std.testing.expectEqualSlices(u8, &one.digestBytes(), &wrapped.digestBytes());
}
