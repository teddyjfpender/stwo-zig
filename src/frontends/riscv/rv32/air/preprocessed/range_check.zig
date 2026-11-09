//! Range check preprocessed tables.
//!
//! These tables provide lookup columns for LogUp-based range checks.
//! Each table contains sequential values that cover the valid range,
//! allowing the AIR to verify that a witness value lies within a given
//! range by performing a LogUp lookup against the corresponding table.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

/// Range check for values in [0, 2^log_size).
/// A single column of sequential M31 values.
pub const RangeCheck = struct {
    pub const MAX_LOG_SIZE: u5 = 20;

    /// Generate a single-column range check table of size 2^log_size.
    pub fn generate(allocator: std.mem.Allocator, log_size: u5) ![]M31 {
        const size: usize = @as(usize, 1) << log_size;
        const col = try allocator.alloc(M31, size);
        for (0..size) |i| {
            col[i] = M31.fromCanonical(@intCast(i));
        }
        return col;
    }

    pub fn free(allocator: std.mem.Allocator, col: []M31) void {
        allocator.free(col);
    }
};

/// Range check for two 8-bit limbs: all (a, b) pairs with a, b in [0, 255].
pub const RangeCheck8x8 = struct {
    pub const SIZE: usize = 256 * 256; // 65536 entries
    pub const N_COLUMNS: usize = 2;

    pub fn generate(allocator: std.mem.Allocator) ![N_COLUMNS][]M31 {
        var columns: [N_COLUMNS][]M31 = undefined;
        for (0..N_COLUMNS) |i| {
            columns[i] = try allocator.alloc(M31, SIZE);
        }

        var idx: usize = 0;
        for (0..256) |a| {
            for (0..256) |b| {
                columns[0][idx] = M31.fromCanonical(@intCast(a));
                columns[1][idx] = M31.fromCanonical(@intCast(b));
                idx += 1;
            }
        }
        return columns;
    }

    pub fn free(allocator: std.mem.Allocator, columns: *[N_COLUMNS][]M31) void {
        for (columns) |col| {
            allocator.free(col);
        }
    }
};

/// Range check for (8-bit, 11-bit) pairs: a in [0, 255], b in [0, 2047].
pub const RangeCheck8x11 = struct {
    pub const SIZE: usize = 256 * 2048; // 524288 entries
    pub const N_COLUMNS: usize = 2;

    pub fn generate(allocator: std.mem.Allocator) ![N_COLUMNS][]M31 {
        var columns: [N_COLUMNS][]M31 = undefined;
        for (0..N_COLUMNS) |i| {
            columns[i] = try allocator.alloc(M31, SIZE);
        }

        var idx: usize = 0;
        for (0..256) |a| {
            for (0..2048) |b| {
                columns[0][idx] = M31.fromCanonical(@intCast(a));
                columns[1][idx] = M31.fromCanonical(@intCast(b));
                idx += 1;
            }
        }
        return columns;
    }

    pub fn free(allocator: std.mem.Allocator, columns: *[N_COLUMNS][]M31) void {
        for (columns) |col| {
            allocator.free(col);
        }
    }
};

/// Range check for (8-bit, 8-bit, 4-bit) triples: a, b in [0, 255], c in [0, 15].
pub const RangeCheck8x8x4 = struct {
    pub const SIZE: usize = 256 * 256 * 16; // 1048576 entries
    pub const N_COLUMNS: usize = 3;

    pub fn generate(allocator: std.mem.Allocator) ![N_COLUMNS][]M31 {
        var columns: [N_COLUMNS][]M31 = undefined;
        for (0..N_COLUMNS) |i| {
            columns[i] = try allocator.alloc(M31, SIZE);
        }

        var idx: usize = 0;
        for (0..256) |a| {
            for (0..256) |b| {
                for (0..16) |c| {
                    columns[0][idx] = M31.fromCanonical(@intCast(a));
                    columns[1][idx] = M31.fromCanonical(@intCast(b));
                    columns[2][idx] = M31.fromCanonical(@intCast(c));
                    idx += 1;
                }
            }
        }
        return columns;
    }

    pub fn free(allocator: std.mem.Allocator, columns: *[N_COLUMNS][]M31) void {
        for (columns) |col| {
            allocator.free(col);
        }
    }
};

/// Range check for M31 values.
/// Any M31 value is automatically in range [0, 2^31 - 2].
/// The preprocessed column would be the identity: column[i] = i for all valid i.
/// In practice, this table is too large to materialize (2^31 - 1 entries);
/// the AIR uses it as a virtual table with no physical column.
pub const RangeCheckM31 = struct {
    pub const IS_VIRTUAL: bool = true;
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "RangeCheck: generate size and boundary values" {
    const allocator = std.testing.allocator;
    const col = try RangeCheck.generate(allocator, 10);
    defer RangeCheck.free(allocator, col);

    try std.testing.expectEqual(@as(usize, 1024), col.len);
    try std.testing.expectEqual(@as(u32, 0), col[0].v);
    try std.testing.expectEqual(@as(u32, 1023), col[1023].v);
    try std.testing.expectEqual(@as(u32, 512), col[512].v);
}

test "RangeCheck8x8: size and sample lookups" {
    const allocator = std.testing.allocator;
    var cols = try RangeCheck8x8.generate(allocator);
    defer RangeCheck8x8.free(allocator, &cols);

    try std.testing.expectEqual(@as(usize, RangeCheck8x8.SIZE), cols[0].len);
    try std.testing.expectEqual(@as(usize, RangeCheck8x8.SIZE), cols[1].len);

    // Row (a=1, b=2) is at index 1*256 + 2 = 258.
    try std.testing.expectEqual(@as(u32, 1), cols[0][258].v);
    try std.testing.expectEqual(@as(u32, 2), cols[1][258].v);

    // Last row (a=255, b=255) is at index 65535.
    try std.testing.expectEqual(@as(u32, 255), cols[0][65535].v);
    try std.testing.expectEqual(@as(u32, 255), cols[1][65535].v);
}

test "RangeCheck8x11: size and sample lookups" {
    const allocator = std.testing.allocator;
    var cols = try RangeCheck8x11.generate(allocator);
    defer RangeCheck8x11.free(allocator, &cols);

    try std.testing.expectEqual(@as(usize, RangeCheck8x11.SIZE), cols[0].len);
    try std.testing.expectEqual(@as(usize, RangeCheck8x11.SIZE), cols[1].len);

    // Row (a=0, b=2047) is at index 2047.
    try std.testing.expectEqual(@as(u32, 0), cols[0][2047].v);
    try std.testing.expectEqual(@as(u32, 2047), cols[1][2047].v);

    // Row (a=1, b=0) is at index 2048.
    try std.testing.expectEqual(@as(u32, 1), cols[0][2048].v);
    try std.testing.expectEqual(@as(u32, 0), cols[1][2048].v);
}

test "RangeCheck8x8x4: size and sample lookups" {
    const allocator = std.testing.allocator;
    var cols = try RangeCheck8x8x4.generate(allocator);
    defer RangeCheck8x8x4.free(allocator, &cols);

    try std.testing.expectEqual(@as(usize, RangeCheck8x8x4.SIZE), cols[0].len);
    try std.testing.expectEqual(@as(usize, RangeCheck8x8x4.SIZE), cols[1].len);
    try std.testing.expectEqual(@as(usize, RangeCheck8x8x4.SIZE), cols[2].len);

    // Row (a=0, b=0, c=15) is at index 15.
    try std.testing.expectEqual(@as(u32, 0), cols[0][15].v);
    try std.testing.expectEqual(@as(u32, 0), cols[1][15].v);
    try std.testing.expectEqual(@as(u32, 15), cols[2][15].v);

    // Row (a=1, b=0, c=0) is at index 1*256*16 = 4096.
    try std.testing.expectEqual(@as(u32, 1), cols[0][4096].v);
    try std.testing.expectEqual(@as(u32, 0), cols[1][4096].v);
    try std.testing.expectEqual(@as(u32, 0), cols[2][4096].v);
}

test "RangeCheckM31: is virtual" {
    try std.testing.expect(RangeCheckM31.IS_VIRTUAL);
}
