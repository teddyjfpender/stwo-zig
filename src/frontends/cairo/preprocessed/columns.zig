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

const Sequence = struct {
    row_limit: u32,
};

const RangeCheck = struct {
    row_limit: u32,
    shift: u5,
    mask: u32,
};

const BitwiseXor = struct {
    bits: u5,
    column: u2,
    row_limit: u32,
};

pub const Plan = union(enum) {
    sequence: Sequence,
    range_check: RangeCheck,
    bitwise_xor: BitwiseXor,
    blake_sigma: u5,
    poseidon_round_key: u6,
    pedersen_point: u6,

    pub fn init(identity: []const u8) Error!Plan {
        if (std.mem.startsWith(u8, identity, "seq_")) {
            const log_size = try parseUnsigned(u5, identity["seq_".len..]);
            if (log_size >= 31) return Error.InvalidColumnIdentity;
            return .{ .sequence = .{
                .row_limit = @as(u32, 1) << log_size,
            } };
        }
        if (std.mem.startsWith(u8, identity, "range_check_"))
            return rangeCheckPlan(identity["range_check_".len..]);
        if (std.mem.startsWith(u8, identity, "bitwise_xor_"))
            return bitwiseXorPlan(identity["bitwise_xor_".len..]);
        if (std.mem.startsWith(u8, identity, "blake_sigma_")) {
            const column = try parseUnsigned(u5, identity["blake_sigma_".len..]);
            if (column >= 16) return Error.InvalidColumnIdentity;
            return .{ .blake_sigma = column };
        }
        if (std.mem.startsWith(u8, identity, "poseidon_round_keys_")) {
            const column = try parseUnsigned(u6, identity["poseidon_round_keys_".len..]);
            if (column >= 30) return Error.InvalidColumnIdentity;
            return .{ .poseidon_round_key = column };
        }
        if (std.mem.startsWith(u8, identity, "pedersen_points_small_"))
            return Error.UnsupportedPedersenWindow;
        if (std.mem.startsWith(u8, identity, "pedersen_points_")) {
            const column = try parseUnsigned(u6, identity["pedersen_points_".len..]);
            if (column >= 56) return Error.InvalidColumnIdentity;
            return .{ .pedersen_point = column };
        }
        return Error.InvalidColumnIdentity;
    }

    pub fn value(self: Plan, row: u32) !u32 {
        return switch (self) {
            .sequence => |plan| if (row < plan.row_limit)
                row
            else
                Error.InvalidRow,
            .range_check => |plan| if (row < plan.row_limit)
                (row >> plan.shift) & plan.mask
            else
                Error.InvalidRow,
            .bitwise_xor => |plan| bitwiseXorValue(plan, row),
            .blake_sigma => |column| blakeSigma(column, row),
            .poseidon_round_key => |column| poseidonRoundKey(column, row),
            .pedersen_point => |column| pedersenPoint(column, row),
        };
    }
};

pub fn value(identity: []const u8, row: u32) !u32 {
    return (try Plan.init(identity)).value(row);
}

fn rangeCheckPlan(suffix: []const u8) Error!Plan {
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
    if (column >= width_count) return Error.InvalidColumnIdentity;
    var shift: u5 = 0;
    for (widths[column + 1 .. width_count]) |width| shift += width;
    return .{ .range_check = .{
        .row_limit = @as(u32, 1) << total_bits,
        .shift = shift,
        .mask = (@as(u32, 1) << widths[column]) - 1,
    } };
}

fn bitwiseXorPlan(suffix: []const u8) Error!Plan {
    const separator = std.mem.lastIndexOfScalar(u8, suffix, '_') orelse
        return Error.InvalidColumnIdentity;
    const bits = try parseUnsigned(u5, suffix[0..separator]);
    const column = try parseUnsigned(u2, suffix[separator + 1 ..]);
    if (bits == 0 or bits >= 16 or column > 2)
        return Error.InvalidColumnIdentity;
    return .{ .bitwise_xor = .{
        .bits = bits,
        .column = column,
        .row_limit = @as(u32, 1) << @intCast(@as(u6, bits) * 2),
    } };
}

fn bitwiseXorValue(plan: BitwiseXor, row: u32) Error!u32 {
    if (row >= plan.row_limit) return Error.InvalidRow;
    const lhs = row >> plan.bits;
    const rhs = row & ((@as(u32, 1) << plan.bits) - 1);
    return switch (plan.column) {
        0 => lhs,
        1 => rhs,
        2 => lhs ^ rhs,
        else => unreachable,
    };
}

fn blakeSigma(column: u5, row: u32) !u32 {
    if (row >= 16) return Error.InvalidRow;
    var values: [16]u32 = undefined;
    try blake.applyRoundSigma(&.{if (row < 10) row else 0}, &values);
    return values[column];
}

fn poseidonRoundKey(column: u6, row: u32) !u32 {
    if (row >= 64) return Error.InvalidRow;
    var values: [30]u32 = undefined;
    try poseidon.applyRoundKeys(&.{if (row < 35) row else 0}, &values);
    return values[column];
}

fn pedersenPoint(column: u6, row: u32) !u32 {
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
