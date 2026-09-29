//! Official Cairo transcript operations outside the generic Stwo proof.

const std = @import("std");
const core = @import("stwo_core");
const statement_bootstrap = @import("../statement_bootstrap.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Blake2sMerkleChannel =
    core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleChannel;

pub const interaction_pow_bits: u32 = 24;

pub const LookupElements = struct {
    z: QM31,
    alpha: QM31,
};

pub fn mixChannelSalt(channel: anytype, channel_salt: u32) void {
    channel.mixFelts(&[_]QM31{
        QM31.fromM31(
            M31.fromCanonical(channel_salt),
            M31.zero(),
            M31.zero(),
            M31.zero(),
        ),
    });
}

/// `FlatClaim::mix_into` for the Cairo lane's `Blake2sMerkleChannel`.
pub fn mixClaim(
    allocator: std.mem.Allocator,
    channel: anytype,
    statement: *const statement_bootstrap.OwnedStatementBootstrap,
) !void {
    return mixClaimWith(Blake2sMerkleChannel, allocator, channel, statement);
}

/// `FlatClaim::mix_into::<MC>` over statement ordinals 10 through 16: the
/// enable-bit count, the enable bits, the component log sizes, the program
/// length and the public claim as packed QM31s, then `MC::mix_hash` of the
/// output and program roots. The roots are committed with the plain Blake2s
/// Merkle hasher on both lanes (`Blake2sM31MerkleChannel::H` is
/// `Blake2sMerkleHasher`); only `mix_hash` differs, so the leaf lane
/// instantiates `Blake2sM31MerkleChannel` here without re-deriving the claim.
pub fn mixClaimWith(
    comptime MerkleChannel: type,
    allocator: std.mem.Allocator,
    channel: anytype,
    statement: *const statement_bootstrap.OwnedStatementBootstrap,
) !void {
    for ([_]u32{ 10, 11, 12, 13, 14 }) |ordinal|
        try mixPackedWords(allocator, channel, statement.words(ordinal).?);
    MerkleChannel.mixRoot(channel, rootBytes(statement.words(15).?));
    MerkleChannel.mixRoot(channel, rootBytes(statement.words(16).?));
}

pub fn grindInteraction(channel: anytype) u64 {
    const nonce = channel.grind(interaction_pow_bits);
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
