const std = @import("std");
const qm31 = @import("../../core/fields/qm31.zig");

const QM31 = qm31.QM31;

/// Channel wrapper that preserves behavior while allowing call-site instrumentation.
///
/// This port keeps logging as a boundary concern: all channel semantics are delegated unchanged to
/// the wrapped channel implementation.
pub fn LoggingChannel(comptime C: type) type {
    return struct {
        channel: C,

        const Self = @This();

        pub fn init(channel: C) Self {
            return .{ .channel = channel };
        }

        pub fn verifyPowNonce(self: Self, n_bits: u32, nonce: u64) bool {
            return self.channel.verifyPowNonce(n_bits, nonce);
        }

        pub fn mixFelts(self: *Self, felts: []const QM31) void {
            self.channel.mixFelts(felts);
        }

        pub fn mixU32s(self: *Self, data: []const u32) void {
            self.channel.mixU32s(data);
        }

        pub fn mixU64(self: *Self, value: u64) void {
            self.channel.mixU64(value);
        }

        pub fn drawSecureFelt(self: *Self) QM31 {
            return self.channel.drawSecureFelt();
        }

        pub fn drawSecureFelts(
            self: *Self,
            allocator: std.mem.Allocator,
            n_felts: usize,
        ) ![]QM31 {
            return self.channel.drawSecureFelts(allocator, n_felts);
        }

        pub fn drawU32s(self: *Self) [8]u32 {
            return self.channel.drawU32s();
        }
    };
}

/// Merkle-channel wrapper over `LoggingChannel`.
pub fn LoggingMerkleChannel(comptime MC: type, comptime C: type) type {
    return struct {
        pub fn mixRoot(channel: *LoggingChannel(C), root: anytype) void {
            MC.mixRoot(&channel.channel, root);
        }
    };
}

test "logging channel: delegates channel behavior exactly" {
    const Blake2sChannel = @import("../../core/channel/blake2s.zig").Blake2sChannel;
    const alloc = std.testing.allocator;
    const Channel = LoggingChannel(Blake2sChannel);

    var logging_channel = Channel.init(.{});
    var regular_channel = Blake2sChannel{};

    const felts = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
    };
    logging_channel.mixFelts(felts[0..]);
    regular_channel.mixFelts(felts[0..]);

    const value: u64 = 0x1234_5678_9abc_def0;
    logging_channel.mixU64(value);
    regular_channel.mixU64(value);

    const felt_logging = logging_channel.drawSecureFelt();
    const felt_regular = regular_channel.drawSecureFelt();
    try std.testing.expect(felt_logging.eql(felt_regular));

    const felts_logging = try logging_channel.drawSecureFelts(alloc, 6);
    defer alloc.free(felts_logging);
    const felts_regular = try regular_channel.drawSecureFelts(alloc, 6);
    defer alloc.free(felts_regular);
    try std.testing.expectEqual(@as(usize, 6), felts_logging.len);
    for (felts_logging, felts_regular) |lhs, rhs| try std.testing.expect(lhs.eql(rhs));

    const words_logging = logging_channel.drawU32s();
    const words_regular = regular_channel.drawU32s();
    try std.testing.expect(std.mem.eql(u8, std.mem.asBytes(&words_logging), std.mem.asBytes(&words_regular)));

    try std.testing.expect(std.mem.eql(
        u8,
        std.mem.asBytes(&logging_channel.channel.digestBytes()),
        std.mem.asBytes(&regular_channel.digestBytes()),
    ));
}

test "logging merkle channel: mixRoot delegates exactly" {
    const channel_blake2s = @import("../../core/channel/blake2s.zig");
    const lifted_blake2 = @import("../../core/vcs_lifted/blake2_merkle.zig");
    const Channel = LoggingChannel(channel_blake2s.Blake2sChannel);
    const MerkleChannel = LoggingMerkleChannel(
        lifted_blake2.Blake2sMerkleChannel,
        channel_blake2s.Blake2sChannel,
    );

    var logging_channel = Channel.init(.{});
    var regular_channel = channel_blake2s.Blake2sChannel{};
    const root = [_]u8{7} ** 32;

    MerkleChannel.mixRoot(&logging_channel, root);
    lifted_blake2.Blake2sMerkleChannel.mixRoot(&regular_channel, root);

    try std.testing.expect(std.mem.eql(
        u8,
        std.mem.asBytes(&logging_channel.channel.digestBytes()),
        std.mem.asBytes(&regular_channel.digestBytes()),
    ));
}
