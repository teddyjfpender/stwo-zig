//! Official Cairo transcript operations outside the generic Stwo proof.

const std = @import("std");
const core = @import("stwo_core");
const statement_bootstrap = @import("../statement_bootstrap.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const interaction_pow_bits: u32 = 24;

pub const LookupElements = struct {
    z: QM31,
    alpha: QM31,
};

/// `channel.mix_felts(&[channel_salt.into()])`: the salt is reduced modulo P
/// first, as upstream's `u32 -> M31` conversion does.
pub fn mixChannelSalt(channel: anytype, channel_salt: u32) void {
    channel.mixFelts(&[_]QM31{core.fields.qm31_pointwise.fromU32s(channel_salt, 0, 0, 0)});
}

/// `CairoClaim::mix_into::<MC>`: the flat claim as packed felts, then the
/// output and program roots with `MC::mix_hash`. The roots themselves are
/// `MC::H` digests, the plain Blake2s hasher for every Blake2s Merkle channel.
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

/// The 24-bit interaction grind, then its mix. A Merkle channel profile names
/// the search order of the prover it reproduces (upstream's
/// `SimdBackend::grind`); the existing lane keeps the channel's lowest-nonce
/// search.
pub fn grindInteraction(comptime MC: type, channel: anytype) !u64 {
    const nonce = if (comptime @hasDecl(MC, "grind_order"))
        try MC.grind(channel.*, interaction_pow_bits)
    else
        channel.grind(interaction_pow_bits);
    channel.mixU64(nonce);
    return nonce;
}

pub fn drawLookupElements(
    allocator: std.mem.Allocator,
    channel: anytype,
) !LookupElements {
    const values = try channel.drawSecureFelts(allocator, 2);
    defer allocator.free(values);
    return .{
        .z = values[0],
        .alpha = values[1],
    };
}

pub fn mixInteractionClaim(
    channel: anytype,
    claimed_sums: []const QM31,
) void {
    channel.mixFelts(claimed_sums);
}

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
