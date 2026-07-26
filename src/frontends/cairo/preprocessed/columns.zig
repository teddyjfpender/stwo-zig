//! Logical-row evaluation of canonical Stwo-Cairo preprocessed columns.

const std = @import("std");
const blake = @import("../witness/deductions/blake.zig");
const pedersen = @import("../witness/deductions/pedersen.zig");
const poseidon = @import("../witness/deductions/poseidon.zig");

pub const Error = error{
    InvalidColumnIdentity,
    InvalidColumnIndex,
    InvalidRow,
    UnsupportedPedersenWindow,
};

pub fn value(identity: []const u8, row: u32) !u32 {
    if (std.mem.startsWith(u8, identity, "seq_"))
        return sequence(identity["seq_".len..], row);
    if (std.mem.startsWith(u8, identity, "range_check_"))
        return rangeCheck(identity["range_check_".len..], row);
    if (std.mem.startsWith(u8, identity, "bitwise_xor_"))
        return bitwiseXor(identity["bitwise_xor_".len..], row);
    if (std.mem.startsWith(u8, identity, "blake_sigma_"))
        return blakeSigma(identity["blake_sigma_".len..], row);
    if (std.mem.startsWith(u8, identity, "poseidon_round_keys_"))
        return poseidonRoundKey(identity["poseidon_round_keys_".len..], row);
    if (std.mem.startsWith(u8, identity, "pedersen_points_small_"))
        return Error.UnsupportedPedersenWindow;
    if (std.mem.startsWith(u8, identity, "pedersen_points_"))
        return pedersenPoint(identity["pedersen_points_".len..], row);
    return Error.InvalidColumnIdentity;
}

fn sequence(log_text: []const u8, row: u32) !u32 {
    const log_size = try parseUnsigned(u5, log_text);
    if (log_size >= 31 or row >= @as(u32, 1) << log_size) return Error.InvalidRow;
    return row;
}

fn rangeCheck(suffix: []const u8, row: u32) !u32 {
    const marker = "_column_";
    const marker_index = std.mem.lastIndexOf(u8, suffix, marker) orelse
        return Error.InvalidColumnIdentity;
    const shape = suffix[0..marker_index];
    const column = try parseUnsigned(u8, suffix[marker_index + marker.len ..]);

    var widths: [8]u5 = undefined;
    var width_count: usize = 0;
    var total_bits: u5 = 0;
    var parts = std.mem.splitScalar(u8, shape, '_');
    while (parts.next()) |part| {
        if (width_count == widths.len) return Error.InvalidColumnIdentity;
        const width = try parseUnsigned(u5, part);
        if (width == 0 or total_bits > 30 - width) return Error.InvalidColumnIdentity;
        widths[width_count] = width;
        width_count += 1;
        total_bits += width;
    }
    if (column >= width_count or row >= @as(u32, 1) << total_bits)
        return Error.InvalidRow;
    var shift: u5 = 0;
    for (widths[column + 1 .. width_count]) |width| shift += width;
    const mask = (@as(u32, 1) << widths[column]) - 1;
    return (row >> shift) & mask;
}

fn bitwiseXor(suffix: []const u8, row: u32) !u32 {
    const separator = std.mem.lastIndexOfScalar(u8, suffix, '_') orelse
        return Error.InvalidColumnIdentity;
    const bits = try parseUnsigned(u5, suffix[0..separator]);
    const column = try parseUnsigned(u2, suffix[separator + 1 ..]);
    if (bits == 0 or bits >= 16 or column > 2 or
        row >= @as(u32, 1) << @intCast(@as(u6, bits) * 2))
        return Error.InvalidRow;
    const lhs = row >> bits;
    const rhs = row & ((@as(u32, 1) << bits) - 1);
    return switch (column) {
        0 => lhs,
        1 => rhs,
        2 => lhs ^ rhs,
        else => unreachable,
    };
}

fn blakeSigma(column_text: []const u8, row: u32) !u32 {
    const column = try parseUnsigned(u5, column_text);
    if (column >= 16 or row >= 16) return Error.InvalidRow;
    var values: [16]u32 = undefined;
    try blake.applyRoundSigma(&.{if (row < 10) row else 0}, &values);
    return values[column];
}

fn poseidonRoundKey(column_text: []const u8, row: u32) !u32 {
    const column = try parseUnsigned(u6, column_text);
    if (column >= 30 or row >= 64) return Error.InvalidRow;
    var values: [30]u32 = undefined;
    try poseidon.applyRoundKeys(&.{if (row < 35) row else 0}, &values);
    return values[column];
}

fn pedersenPoint(column_text: []const u8, row: u32) !u32 {
    const column = try parseUnsigned(u6, column_text);
    if (column >= 56 or row >= 1 << 23) return Error.InvalidRow;
    var values: [56]u32 = undefined;
    try pedersen.applyPointsTable(&.{row}, &values);
    return values[column];
}

fn parseUnsigned(comptime T: type, text: []const u8) !T {
    if (text.len == 0) return Error.InvalidColumnIdentity;
    return std.fmt.parseUnsigned(T, text, 10) catch Error.InvalidColumnIdentity;
}

test "canonical Cairo sequence, range, XOR, and Blake columns are exact" {
    try std.testing.expectEqual(@as(u32, 17), try value("seq_6", 17));
    try std.testing.expectEqual(@as(u32, 5), try value("range_check_3_6_6_3_column_0", 5 << 15));
    try std.testing.expectEqual(@as(u32, 9), try value("range_check_3_6_6_3_column_3", 9));
    try std.testing.expectEqual(@as(u32, 3 ^ 7), try value("bitwise_xor_4_2", (3 << 4) | 7));
    try std.testing.expectEqual(@as(u32, 14), try value("blake_sigma_0", 1));
    try std.testing.expectEqual(@as(u32, 0), try value("blake_sigma_0", 15));
}
