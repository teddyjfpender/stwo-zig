//! Exact extension-local Keccak-f lookup-table schemas.
//!
//! The latency-oriented layout owns exact 2^13 chi and 2^10 xor5 domains.
//! Each row proves one output position for two sliced executions, avoiding the
//! enormous Cartesian products of the throughput-oriented five-output layout.
//! Base proofs never commit either table.

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
        .chi => 13,
        .xor5 => 10,
    };
}

pub fn size(kind: Kind) usize {
    return @as(usize, 1) << @intCast(logSize(kind));
}

pub fn semanticRows(kind: Kind) usize {
    return switch (kind) {
        .chi => authority.candidate.compact.chi_table_rows,
        .xor5 => authority.candidate.compact.xor5_table_rows,
    };
}

pub fn tupleAt(kind: Kind, row: usize) Error![arity]M31 {
    if (row >= size(kind)) return error.ValueOutOfRange;
    return switch (kind) {
        .chi => relations.chiTuple(@intCast(row)),
        .xor5 => relations.xor5Tuple(@intCast(row)),
    };
}

pub fn index(kind: Kind, tuple: []const M31) Error!usize {
    if (tuple.len != arity) return error.InvalidArity;
    const row: usize = switch (kind) {
        .chi => blk: {
            if (!tuple[5].isZero() or tuple[3].toU32() > 1)
                return error.InvalidTuple;
            for (tuple[0..3]) |value|
                if (value.toU32() > 27) return error.InvalidTuple;
            break :blk try authority.compactChiTableRow(.{
                @intCast(tuple[0].toU32()),
                @intCast(tuple[1].toU32()),
                @intCast(tuple[2].toU32()),
            }, tuple[3].isOne());
        },
        .xor5 => blk: {
            for (tuple[0..5]) |value|
                if (value.toU32() > 9) return error.InvalidTuple;
            break :blk try authority.compactXor5TableRow(.{
                @intCast(tuple[0].toU32()),
                @intCast(tuple[1].toU32()),
                @intCast(tuple[2].toU32()),
                @intCast(tuple[3].toU32()),
                @intCast(tuple[4].toU32()),
            });
        },
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

comptime {
    if (size(.chi) != authority.candidate.compact.chi_table_rows or
        size(.xor5) != authority.candidate.compact.xor5_table_rows)
    {
        @compileError("Keccak-f physical table geometry drifted");
    }
}
