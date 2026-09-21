//! Exact lookup-table domains, geometry and tuple equations. No trace allocation.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const entry = @import("../entry.zig");

pub const MAX_ARITY: usize = 4;

pub const Kind = enum(u8) {
    bitwise,
    range_check_20,
    range_check_8_11,
    range_check_8_8_4,
    range_check_8_8,
    range_check_m31,
};

pub const KIND_COUNT: usize = @typeInfo(Kind).@"enum".fields.len;

pub const Error = error{
    InvalidArity,
    InvalidRelationDomain,
    NonBaseFieldValue,
    ValueOutOfRange,
    InvalidTuple,
};

pub fn domain(kind: Kind) entry.Domain {
    return switch (kind) {
        .bitwise => .bitwise,
        .range_check_20 => .range_check_20,
        .range_check_8_11 => .range_check_8_11,
        .range_check_8_8_4 => .range_check_8_8_4,
        .range_check_8_8 => .range_check_8_8,
        .range_check_m31 => .range_check_m31,
    };
}

pub fn logSize(kind: Kind) u32 {
    return switch (kind) {
        .bitwise => 18,
        .range_check_20 => 20,
        .range_check_8_11 => 19,
        .range_check_8_8_4 => 20,
        .range_check_8_8 => 16,
        .range_check_m31 => 15,
    };
}

pub fn arity(kind: Kind) usize {
    return switch (kind) {
        .bitwise => 4,
        .range_check_20 => 1,
        .range_check_8_11, .range_check_8_8, .range_check_m31 => 2,
        .range_check_8_8_4 => 3,
    };
}

pub fn size(kind: Kind) usize {
    return @as(usize, 1) << @intCast(logSize(kind));
}

pub const Tuple = struct {
    values: [MAX_ARITY]M31 = .{M31.zero()} ** MAX_ARITY,
    len: usize,

    pub fn slice(self: *const Tuple) []const M31 {
        return self.values[0..self.len];
    }
};

/// Canonical table row before the circle-domain bit-reversal permutation.
pub fn tupleAt(kind: Kind, row: usize) Error!Tuple {
    if (row >= size(kind)) return error.ValueOutOfRange;
    var result = Tuple{ .len = arity(kind) };
    switch (kind) {
        .bitwise => {
            const lhs: u32 = @intCast(row & 0xff);
            const rhs: u32 = @intCast((row >> 8) & 0xff);
            const operation: u32 = @intCast((row >> 16) & 0x3);
            const value = switch (operation) {
                0 => lhs & rhs,
                1 => lhs | rhs,
                2 => lhs ^ rhs,
                3 => 0,
                else => unreachable,
            };
            result.values[0] = M31.fromU64(lhs);
            result.values[1] = M31.fromU64(rhs);
            result.values[2] = M31.fromU64(value);
            result.values[3] = M31.fromU64(operation);
        },
        .range_check_20 => result.values[0] = M31.fromU64(row),
        .range_check_8_11 => {
            result.values[0] = M31.fromU64(row & 0xff);
            result.values[1] = M31.fromU64(row >> 8);
        },
        .range_check_8_8_4 => {
            result.values[0] = M31.fromU64(row & 0xff);
            result.values[1] = M31.fromU64((row >> 8) & 0xff);
            result.values[2] = M31.fromU64(row >> 16);
        },
        .range_check_8_8 => {
            result.values[0] = M31.fromU64(row & 0xff);
            result.values[1] = M31.fromU64(row >> 8);
        },
        .range_check_m31 => {
            if (row == size(kind) - 1) return .{ .len = 2 };
            result.values[0] = M31.fromU64(row & 0xff);
            result.values[1] = M31.fromU64(row >> 8);
        },
    }
    return result;
}

pub fn indexBase(kind: Kind, values: []const M31) Error!usize {
    if (values.len != arity(kind)) return error.InvalidArity;
    var raw: [MAX_ARITY]u32 = .{0} ** MAX_ARITY;
    for (values, raw[0..values.len]) |value, *dst| dst.* = value.toU32();
    return checkedIndex(kind, raw);
}

pub fn indexSecure(kind: Kind, values: []const QM31) Error!usize {
    if (values.len != arity(kind)) return error.InvalidArity;
    var raw: [MAX_ARITY]u32 = .{0} ** MAX_ARITY;
    for (values, raw[0..values.len]) |value, *dst| {
        const base = value.tryIntoM31() catch return error.NonBaseFieldValue;
        dst.* = base.toU32();
    }
    return checkedIndex(kind, raw);
}

fn checkedIndex(kind: Kind, raw: [MAX_ARITY]u32) Error!usize {
    const row: usize = switch (kind) {
        .bitwise => blk: {
            if (raw[0] >= 256 or raw[1] >= 256 or raw[2] >= 256 or raw[3] >= 4)
                return error.ValueOutOfRange;
            const expected = switch (raw[3]) {
                0 => raw[0] & raw[1],
                1 => raw[0] | raw[1],
                2 => raw[0] ^ raw[1],
                3 => 0,
                else => unreachable,
            };
            if (raw[2] != expected) return error.InvalidTuple;
            break :blk raw[0] | (@as(usize, raw[1]) << 8) | (@as(usize, raw[3]) << 16);
        },
        .range_check_20 => blk: {
            if (raw[0] >= 1 << 20) return error.ValueOutOfRange;
            break :blk raw[0];
        },
        .range_check_8_11 => blk: {
            if (raw[0] >= 256 or raw[1] >= 1 << 11) return error.ValueOutOfRange;
            break :blk raw[0] | (@as(usize, raw[1]) << 8);
        },
        .range_check_8_8_4 => blk: {
            if (raw[0] >= 256 or raw[1] >= 256 or raw[2] >= 16)
                return error.ValueOutOfRange;
            break :blk raw[0] | (@as(usize, raw[1]) << 8) | (@as(usize, raw[2]) << 16);
        },
        .range_check_8_8 => blk: {
            if (raw[0] >= 256 or raw[1] >= 256) return error.ValueOutOfRange;
            break :blk raw[0] | (@as(usize, raw[1]) << 8);
        },
        .range_check_m31 => blk: {
            if (raw[0] >= 256 or raw[1] >= 128) return error.ValueOutOfRange;
            if (raw[0] == 255 and raw[1] == 127) return error.InvalidTuple;
            break :blk raw[0] | (@as(usize, raw[1]) << 8);
        },
    };
    std.debug.assert(row < size(kind));
    return row;
}

pub fn validateRow(kind: Kind, row: usize, values: []const M31) Error!void {
    const expected = try tupleAt(kind, row);
    if (values.len != expected.len) return error.InvalidArity;
    for (values, expected.slice()) |actual, want| {
        if (!actual.eql(want)) return error.InvalidTuple;
    }
}
