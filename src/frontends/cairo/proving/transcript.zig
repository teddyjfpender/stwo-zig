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

pub fn mixClaim(
    allocator: std.mem.Allocator,
    channel: anytype,
    statement: *const statement_bootstrap.OwnedStatementBootstrap,
) !void {
    for ([_]u32{ 10, 11, 12, 13, 14 }) |ordinal|
        try mixPackedWords(allocator, channel, statement.words(ordinal).?);
    Blake2sMerkleChannel.mixRoot(channel, rootBytes(statement.words(15).?));
    Blake2sMerkleChannel.mixRoot(channel, rootBytes(statement.words(16).?));
}

pub fn grindInteraction(channel: anytype) u64 {
    const nonce = channel.grind(interaction_pow_bits);
    channel.mixU64(nonce);
    return nonce;
}

pub fn drawLookupElements(channel: anytype) LookupElements {
    return .{
        .z = channel.drawSecureFelt(),
        .alpha = channel.drawSecureFelt(),
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
