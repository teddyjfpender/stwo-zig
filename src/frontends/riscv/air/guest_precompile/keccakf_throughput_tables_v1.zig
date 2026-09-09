//! Profile-distinct high-throughput Keccak-f lookup tables.
//!
//! The production compact profile checks one chi output and one parity
//! position per lookup.  This candidate uses the already-audited authority's
//! five-output chi row and three-position parity row.  Both tuples retain
//! arity six, but their meanings differ, so this module may only be selected
//! by a verifier program that binds the throughput profile identity.

const M31 = @import("stwo_core").fields.m31.M31;
const authority = @import("keccakf_authority.zig");

pub const arity: usize = 6;
pub const Kind = enum(u1) { chi, xor5 };

pub const Error = authority.Error || error{
    InvalidArity,
    InvalidTuple,
    ValueOutOfRange,
};

pub fn logSize(kind: Kind) u32 {
    return switch (kind) {
        .chi => 21,
        .xor5 => 16,
    };
}

pub fn domainSize(kind: Kind) usize {
    return @as(usize, 1) << @intCast(logSize(kind));
}

pub fn semanticRows(kind: Kind) usize {
    return switch (kind) {
        .chi => authority.geometry.chi_table_rows,
        .xor5 => authority.geometry.xor5_table_rows,
    };
}

/// Returns a canonical fixed-table row.  The xor table's unused domain suffix
/// is all-zero and must carry zero multiplicity in the candidate table trace.
pub fn tupleAt(kind: Kind, row: usize) Error![arity]M31 {
    if (row >= domainSize(kind)) return error.ValueOutOfRange;
    if (row >= semanticRows(kind)) return @splat(M31.zero());
    return semanticTupleAt(kind, row);
}

pub fn semanticTupleAt(kind: Kind, row: usize) Error![arity]M31 {
    if (row >= semanticRows(kind)) return error.ValueOutOfRange;
    return switch (kind) {
        .chi => blk: {
            const entry = try authority.chiTableEntry(@intCast(row));
            break :blk .{
                M31.fromCanonical(entry.packed_input),
                M31.fromCanonical(entry.output[0]),
                M31.fromCanonical(entry.output[1]),
                M31.fromCanonical(entry.output[2]),
                M31.fromCanonical(entry.output[3]),
                M31.fromCanonical(entry.output[4]),
            };
        },
        .xor5 => blk: {
            const entry = try authority.xor5TableEntry(@intCast(row));
            break :blk .{
                M31.fromCanonical(entry.sliced_sums[0]),
                M31.fromCanonical(entry.sliced_sums[1]),
                M31.fromCanonical(entry.sliced_sums[2]),
                M31.fromCanonical(entry.sliced_parities[0]),
                M31.fromCanonical(entry.sliced_parities[1]),
                M31.fromCanonical(entry.sliced_parities[2]),
            };
        },
    };
}

/// Reconstructs the unique semantic table row represented by a tuple.
/// Padded all-zero xor rows intentionally resolve to semantic row zero.
pub fn index(kind: Kind, tuple: []const M31) Error!usize {
    if (tuple.len != arity) return error.InvalidArity;
    const row = switch (kind) {
        .chi => try chiIndex(tuple),
        .xor5 => try xor5Index(tuple),
    };
    const expected = try semanticTupleAt(kind, row);
    for (tuple, expected) |actual, wanted| {
        if (!actual.eql(wanted)) return error.InvalidTuple;
    }
    return row;
}

fn chiIndex(tuple: []const M31) Error!usize {
    var packed_value = tuple[0].toU32();
    const iota = packed_value >= authority.geometry.chi_span;
    if (iota) packed_value -= authority.geometry.chi_span;
    if (packed_value >= authority.geometry.chi_span) return error.InvalidTuple;

    var row: u32 = 0;
    var power: u32 = 1;
    for (0..5) |_| {
        const sliced = packed_value % authority.geometry.chi_input_radix;
        packed_value /= authority.geometry.chi_input_radix;
        const a = sliced % authority.geometry.slot_base;
        const b = sliced / authority.geometry.slot_base;
        if (a >= 4 or b >= 4) return error.InvalidTuple;
        row += power * (a + 4 * b);
        power *= authority.geometry.chi_digit_radix;
    }
    if (packed_value != 0) return error.InvalidTuple;
    if (iota) row += power;
    if (row >= authority.geometry.chi_table_rows) return error.InvalidTuple;
    return row;
}

fn xor5Index(tuple: []const M31) Error!usize {
    var row: u32 = 0;
    var power: u32 = 1;
    for (tuple[0..3]) |value| {
        const sliced = value.toU32();
        const a = sliced % authority.geometry.slot_base;
        const b = sliced / authority.geometry.slot_base;
        if (a >= 6 or b >= 6) return error.InvalidTuple;
        row += power * (a + 6 * b);
        power *= authority.geometry.xor5_radix;
    }
    if (row >= authority.geometry.xor5_table_rows) return error.InvalidTuple;
    return row;
}

comptime {
    if (semanticRows(.chi) != 2_097_152 or
        semanticRows(.xor5) != 46_656 or
        domainSize(.chi) != semanticRows(.chi) or
        domainSize(.xor5) != 65_536)
    {
        @compileError("Keccak-f throughput table geometry drifted");
    }
}
