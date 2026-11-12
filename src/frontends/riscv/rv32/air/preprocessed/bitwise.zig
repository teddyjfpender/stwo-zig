//! Bitwise operation lookup table.
//! Contains all (a, b, and_result, or_result, xor_result) tuples for a,b in 0..255.
//!
//! Used by base_alu_reg/imm for bitwise operations (AND, OR, XOR).
//! The LogUp relation references this preprocessed table so the prover can
//! look up 8-bit limb results without re-deriving them inside the AIR.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

pub const TABLE_SIZE: usize = 256 * 256; // 65536 entries
pub const N_COLUMNS: usize = 5; // a, b, and, or, xor

/// Generate the bitwise lookup table columns.
/// Returns 5 columns of TABLE_SIZE M31 values:
///   [0] = a, [1] = b, [2] = a & b, [3] = a | b, [4] = a ^ b
pub fn generateTable(allocator: std.mem.Allocator) ![N_COLUMNS][]M31 {
    var columns: [N_COLUMNS][]M31 = undefined;
    for (0..N_COLUMNS) |i| {
        columns[i] = try allocator.alloc(M31, TABLE_SIZE);
    }

    var idx: usize = 0;
    for (0..256) |a| {
        for (0..256) |b| {
            const a_u32: u32 = @intCast(a);
            const b_u32: u32 = @intCast(b);
            columns[0][idx] = M31.fromCanonical(a_u32);
            columns[1][idx] = M31.fromCanonical(b_u32);
            columns[2][idx] = M31.fromCanonical(a_u32 & b_u32);
            columns[3][idx] = M31.fromCanonical(a_u32 | b_u32);
            columns[4][idx] = M31.fromCanonical(a_u32 ^ b_u32);
            idx += 1;
        }
    }
    return columns;
}

pub fn freeTable(allocator: std.mem.Allocator, columns: *[N_COLUMNS][]M31) void {
    for (columns) |col| {
        allocator.free(col);
    }
}

test "bitwise table size" {
    const allocator = std.testing.allocator;
    var cols = try generateTable(allocator);
    defer freeTable(allocator, &cols);

    for (cols) |col| {
        try std.testing.expectEqual(TABLE_SIZE, col.len);
    }
}

test "bitwise known values: 0xFF & 0x0F = 0x0F" {
    const allocator = std.testing.allocator;
    var cols = try generateTable(allocator);
    defer freeTable(allocator, &cols);

    // Row for (a=0xFF, b=0x0F) is at index 0xFF * 256 + 0x0F = 65295.
    const idx: usize = 0xFF * 256 + 0x0F;
    try std.testing.expectEqual(@as(u32, 0xFF), cols[0][idx].v);
    try std.testing.expectEqual(@as(u32, 0x0F), cols[1][idx].v);
    try std.testing.expectEqual(@as(u32, 0x0F), cols[2][idx].v); // AND
    try std.testing.expectEqual(@as(u32, 0xFF), cols[3][idx].v); // OR
    try std.testing.expectEqual(@as(u32, 0xF0), cols[4][idx].v); // XOR
}

test "bitwise known values: 0x00 & 0x00" {
    const allocator = std.testing.allocator;
    var cols = try generateTable(allocator);
    defer freeTable(allocator, &cols);

    // Row (0, 0) is at index 0.
    try std.testing.expectEqual(@as(u32, 0), cols[0][0].v);
    try std.testing.expectEqual(@as(u32, 0), cols[1][0].v);
    try std.testing.expectEqual(@as(u32, 0), cols[2][0].v);
    try std.testing.expectEqual(@as(u32, 0), cols[3][0].v);
    try std.testing.expectEqual(@as(u32, 0), cols[4][0].v);
}

test "bitwise known values: 0xAA ^ 0x55 = 0xFF" {
    const allocator = std.testing.allocator;
    var cols = try generateTable(allocator);
    defer freeTable(allocator, &cols);

    const idx: usize = 0xAA * 256 + 0x55;
    try std.testing.expectEqual(@as(u32, 0xAA), cols[0][idx].v);
    try std.testing.expectEqual(@as(u32, 0x55), cols[1][idx].v);
    try std.testing.expectEqual(@as(u32, 0x00), cols[2][idx].v); // AND
    try std.testing.expectEqual(@as(u32, 0xFF), cols[3][idx].v); // OR
    try std.testing.expectEqual(@as(u32, 0xFF), cols[4][idx].v); // XOR
}
