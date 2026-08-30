//! Exact extension-local Keccak-f lookup-table schemas.
//!
//! Chi occupies its exact 2^21 domain. Xor5 has 46,656 semantic rows inside a
//! 2^16 commitment; remaining rows use distinct, unreachable sentinel tuples
//! and therefore cannot alias a valid lookup. Base proofs never commit either
//! table—these columns belong only to the Keccak execution profile.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const infra = @import("../../infra_trace.zig");
const authority = @import("keccakf_authority.zig");
const relations = @import("keccakf_relations.zig");

pub const arity: usize = 6;

pub const Kind = enum(u1) { chi, xor5 };

pub const Error = authority.Error || error{
    InvalidArity,
    InvalidTuple,
    SentinelTuple,
    ValueOutOfRange,
};

pub fn logSize(kind: Kind) u32 {
    return switch (kind) {
        .chi => 21,
        .xor5 => 16,
    };
}

pub fn size(kind: Kind) usize {
    return @as(usize, 1) << @intCast(logSize(kind));
}

pub fn semanticRows(kind: Kind) usize {
    return switch (kind) {
        .chi => authority.candidate.chi_table_rows,
        .xor5 => authority.candidate.xor5_table_rows,
    };
}

pub fn tupleAt(kind: Kind, row: usize) Error![arity]M31 {
    if (row >= size(kind)) return error.ValueOutOfRange;
    return switch (kind) {
        .chi => relations.chiTuple(@intCast(row)),
        .xor5 => if (row < semanticRows(.xor5))
            relations.xor5Tuple(@intCast(row))
        else
            xor5Sentinel(row),
    };
}

pub fn index(kind: Kind, tuple: []const M31) Error!usize {
    if (tuple.len != arity) return error.InvalidArity;
    const row = switch (kind) {
        .chi => try chiIndex(tuple),
        .xor5 => try xor5Index(tuple),
    };
    const expected = try tupleAt(kind, row);
    for (tuple, expected) |actual, wanted| {
        if (!actual.eql(wanted)) return error.InvalidTuple;
    }
    return row;
}

pub fn validateRow(kind: Kind, row: usize, tuple: []const M31) Error!void {
    const expected = try tupleAt(kind, row);
    if (tuple.len != arity) return error.InvalidArity;
    for (tuple, expected) |actual, wanted| {
        if (!actual.eql(wanted)) return error.InvalidTuple;
    }
}

pub const PreprocessedColumns = struct {
    columns: [arity][]M31,

    pub fn deinit(self: *PreprocessedColumns, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(column);
        self.* = undefined;
    }
};

pub fn generatePreprocessed(
    allocator: std.mem.Allocator,
    kind: Kind,
) !PreprocessedColumns {
    const domain_size = size(kind);
    var result: PreprocessedColumns = undefined;
    var initialized: usize = 0;
    errdefer for (result.columns[0..initialized]) |column| allocator.free(column);
    for (&result.columns) |*column| {
        column.* = try allocator.alloc(M31, domain_size);
        initialized += 1;
    }
    const reversal = try infra.BitReversalTable.init(allocator, logSize(kind));
    defer reversal.deinit(allocator);
    for (0..domain_size) |row| {
        const tuple = try tupleAt(kind, row);
        const destination = reversal.map(row);
        for (tuple, result.columns) |value, column| column[destination] = value;
    }
    return result;
}

fn chiIndex(tuple: []const M31) Error!usize {
    var packed_input = tuple[0].toU32();
    const iota: u32 = @intFromBool(packed_input >= authority.candidate.chi_span);
    if (iota != 0) packed_input -= authority.candidate.chi_span;
    var row: u32 = 0;
    var power: u32 = 1;
    for (0..5) |_| {
        const digit = packed_input % authority.candidate.chi_input_radix;
        packed_input /= authority.candidate.chi_input_radix;
        const a = digit % authority.candidate.slot_base;
        const b = digit / authority.candidate.slot_base;
        if (a >= 4 or b >= 4) return error.InvalidTuple;
        row += power * (a + 4 * b);
        power *= authority.candidate.chi_digit_radix;
    }
    if (packed_input != 0) return error.InvalidTuple;
    if (iota != 0) row += authority.candidate.chi_table_rows / 2;
    return row;
}

fn xor5Index(tuple: []const M31) Error!usize {
    var row: usize = 0;
    var power: usize = 1;
    for (tuple[0..3]) |value| {
        const sliced = value.toU32();
        const a = sliced % authority.candidate.slot_base;
        const b = sliced / authority.candidate.slot_base;
        if (a >= 6 or b >= 6) {
            if (sliced >= authority.candidate.xor5_table_rows)
                return error.SentinelTuple;
            return error.InvalidTuple;
        }
        row += power * (a + 6 * b);
        power *= authority.candidate.xor5_radix;
    }
    if (row >= semanticRows(.xor5)) return error.InvalidTuple;
    return row;
}

fn xor5Sentinel(row: usize) [arity]M31 {
    std.debug.assert(row >= semanticRows(.xor5) and row < size(.xor5));
    var result = [_]M31{M31.zero()} ** arity;
    result[0] = M31.fromCanonical(@intCast(row));
    return result;
}

comptime {
    if (size(.chi) != authority.candidate.chi_table_rows or
        size(.xor5) != 65_536 or semanticRows(.xor5) != 46_656)
    {
        @compileError("Keccak-f physical table geometry drifted");
    }
}
