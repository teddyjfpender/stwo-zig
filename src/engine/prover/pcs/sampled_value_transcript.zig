//! Transcript absorption for PCS sampled values.
//!
//! Values are mixed in tree, column, then sample order. The Blake2 channels
//! stream the same little-endian bytes as `mixFelts` without flattening all
//! values into an intermediate allocation.

const std = @import("std");
const builtin = @import("builtin");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs_core = @import("stwo_core").pcs;
const blake2_hash = @import("stwo_core").vcs.blake2_hash;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs_core.TreeVec;

pub fn mixIntoChannel(
    allocator: std.mem.Allocator,
    channel: anytype,
    sampled_values: TreeVec([][]QM31),
) !void {
    const Channel = @TypeOf(channel.*);
    if (@hasField(Channel, "channel")) {
        try mixIntoChannel(allocator, &channel.channel, sampled_values);
        return;
    }

    if (Channel == channel_blake2s.Blake2sChannel) {
        mixIntoBlake2Channel(false, channel, sampled_values);
        return;
    }
    if (Channel == channel_blake2s.Blake2sM31Channel) {
        mixIntoBlake2Channel(true, channel, sampled_values);
        return;
    }

    const flat = try flatten(allocator, sampled_values);
    defer allocator.free(flat);
    channel.mixFelts(flat);
}

fn flatten(
    allocator: std.mem.Allocator,
    sampled_values: TreeVec([][]QM31),
) ![]QM31 {
    var total: usize = 0;
    for (sampled_values.items) |tree| {
        for (tree) |column| total += column.len;
    }

    const out = try allocator.alloc(QM31, total);
    var at: usize = 0;
    for (sampled_values.items) |tree| {
        for (tree) |column| {
            @memcpy(out[at .. at + column.len], column);
            at += column.len;
        }
    }
    return out;
}

fn mixIntoBlake2Channel(
    comptime is_m31_output: bool,
    channel: *channel_blake2s.Blake2sChannelGeneric(is_m31_output),
    sampled_values: TreeVec([][]QM31),
) void {
    var hasher = blake2_hash.Blake2sHasherGeneric(is_m31_output).init();
    const digest = channel.digestBytes();
    hasher.update(digest[0..]);

    if (builtin.cpu.arch.endian() == .little) {
        for (sampled_values.items) |tree_values| {
            for (tree_values) |column_values| {
                if (column_values.len == 0) continue;
                hasher.update(std.mem.sliceAsBytes(column_values));
            }
        }
    } else {
        var scratch: [256 * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31)]u8 = undefined;
        for (sampled_values.items) |tree_values| {
            for (tree_values) |column_values| {
                var at: usize = 0;
                while (at < column_values.len) {
                    const chunk_len = @min(@as(usize, 256), column_values.len - at);
                    const byte_len = chunk_len * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31);
                    packSecureFeltsLe(scratch[0..byte_len], column_values[at .. at + chunk_len]);
                    hasher.update(scratch[0..byte_len]);
                    at += chunk_len;
                }
            }
        }
    }

    channel.updateDigest(hasher.finalize());
}

fn packSecureFeltsLe(dst: []u8, values: []const QM31) void {
    std.debug.assert(dst.len == values.len * qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31));
    var at: usize = 0;
    for (values) |value| {
        const coordinates = value.toM31Array();
        inline for (coordinates) |coordinate| {
            const encoded = coordinate.toBytesLe();
            @memcpy(dst[at .. at + @sizeOf(M31)], encoded[0..]);
            at += @sizeOf(M31);
        }
    }
}

test "prover pcs: streaming sampled-value mixing matches flattening path" {
    const allocator = std.testing.allocator;
    const LoggingChannel = @import("../channel/logging_channel.zig").LoggingChannel;

    const col00 = try allocator.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
    });
    const col01 = try allocator.alloc(QM31, 0);
    const col10 = try allocator.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(9, 10, 11, 12),
    });
    const col11 = try allocator.dupe(QM31, &[_]QM31{
        QM31.fromU32Unchecked(13, 14, 15, 16),
        QM31.fromU32Unchecked(17, 18, 19, 20),
        QM31.fromU32Unchecked(21, 22, 23, 24),
    });

    const tree0 = try allocator.dupe([]QM31, &[_][]QM31{ col00, col01 });
    const tree1 = try allocator.dupe([]QM31, &[_][]QM31{ col10, col11 });

    var sampled_values = TreeVec([][]QM31).initOwned(
        try allocator.dupe([][]QM31, &[_][][]QM31{ tree0, tree1 }),
    );
    defer sampled_values.deinitDeep(allocator);

    const flat = try flatten(allocator, sampled_values);
    defer allocator.free(flat);

    var expected_blake2 = channel_blake2s.Blake2sChannel{};
    expected_blake2.mixFelts(flat);
    var actual_blake2 = channel_blake2s.Blake2sChannel{};
    try mixIntoChannel(allocator, &actual_blake2, sampled_values);
    try std.testing.expectEqualSlices(u8, expected_blake2.digestBytes()[0..], actual_blake2.digestBytes()[0..]);

    var expected_blake2_m31 = channel_blake2s.Blake2sM31Channel{};
    expected_blake2_m31.mixFelts(flat);
    var actual_blake2_m31 = channel_blake2s.Blake2sM31Channel{};
    try mixIntoChannel(allocator, &actual_blake2_m31, sampled_values);
    try std.testing.expectEqualSlices(u8, expected_blake2_m31.digestBytes()[0..], actual_blake2_m31.digestBytes()[0..]);

    var expected_logging = LoggingChannel(channel_blake2s.Blake2sChannel).init(.{});
    expected_logging.mixFelts(flat);
    var actual_logging = LoggingChannel(channel_blake2s.Blake2sChannel).init(.{});
    try mixIntoChannel(allocator, &actual_logging, sampled_values);
    try std.testing.expectEqualSlices(
        u8,
        expected_logging.channel.digestBytes()[0..],
        actual_logging.channel.digestBytes()[0..],
    );
}

pub fn ForField(comptime S: type) type {
    if (S == QM31) return @This();
    return struct {
        pub fn mixIntoChannel(a: std.mem.Allocator, channel: anytype, values: TreeVec([][]S)) !void {
            var count: usize = 0;
            for (values.items) |tree| for (tree) |column| {
                count = try std.math.add(usize, count, column.len);
            };
            const flat = try a.alloc(S, count);
            defer a.free(flat);
            var at: usize = 0;
            for (values.items) |tree| for (tree) |column| {
                @memcpy(flat[at..][0..column.len], column);
                at += column.len;
            };
            channel.mixFelts(flat);
        }
    };
}
