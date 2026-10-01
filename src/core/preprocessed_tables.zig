//! Row formulas of the pure preprocessed lookup tables shared by AIRs.
//!
//! A preprocessed column here is a function of its row index alone; the
//! caller supplies its identity, domain and bit-reversal. The Cairo AIR and
//! the circuit-recursion AIR both use these two tables:
//!
//! - `seq_{log_size}`: row `i` holds `i` (stwo `constraint_framework`
//!   `preprocessed_columns::Seq`);
//! - `bitwise_xor_{n_bits}_{col_index}`: row `i = (a << n_bits) | b` holds
//!   `a`, `b` or `a ^ b` for column 0, 1 or 2 (`BitwiseXor` of
//!   `crates/common/src/preprocessed_columns/bitwise_xor.rs` in
//!   https://github.com/starkware-libs/proving at
//!   5a7c5ede4299c91a61df19a07cba4f7502c14230, and of stwo-cairo `82f2125`).
//!
//! Values are canonical M31 representatives returned as `u32`: every table
//! stays below `2^30`, so no reduction is needed. A row outside the table is
//! `error.InvalidRow`, never a wrapped value.

const std = @import("std");

pub const Error = error{InvalidTableParameters};
pub const RowError = error{InvalidRow};

/// `seq_{log_size}`: the identity column on `2^log_size` rows.
pub const Seq = struct {
    row_limit: u32,

    /// Largest supported log size: the rows must stay below the M31 modulus.
    pub const max_log_size: u5 = 30;

    pub fn init(log_size: u5) Error!Seq {
        if (log_size > max_log_size) return error.InvalidTableParameters;
        return .{ .row_limit = @as(u32, 1) << log_size };
    }

    pub inline fn value(self: Seq, row: u32) RowError!u32 {
        if (row >= self.row_limit) return error.InvalidRow;
        return row;
    }
};

/// `bitwise_xor_{n_bits}_{col_index}`: all `2^(2 n_bits)` pairs `(a, b)` of
/// `n_bits`-bit operands, with `a` in the high bits of the row index.
pub const BitwiseXor = struct {
    n_bits: u5,
    col_index: u2,
    row_limit: u32,

    /// Largest supported operand width: the `2^(2 n_bits)` row indices must
    /// stay below the M31 modulus.
    pub const max_n_bits: u5 = 15;

    /// `BitwiseXor::new`. Upstream asserts only `col_index < 3`; widths
    /// outside `1..=max_n_bits` have no representable table and are rejected.
    pub fn init(n_bits: u5, col_index: u2) Error!BitwiseXor {
        if (n_bits == 0 or n_bits > max_n_bits or col_index > 2)
            return error.InvalidTableParameters;
        return .{
            .n_bits = n_bits,
            .col_index = col_index,
            .row_limit = @as(u32, 1) << (n_bits * 2),
        };
    }

    pub inline fn value(self: BitwiseXor, row: u32) RowError!u32 {
        if (row >= self.row_limit) return error.InvalidRow;
        const lhs = row >> self.n_bits;
        const rhs = row & ((@as(u32, 1) << self.n_bits) - 1);
        return switch (self.col_index) {
            0 => lhs,
            1 => rhs,
            2 => lhs ^ rhs,
            3 => unreachable,
        };
    }
};

test "preprocessed tables: seq is the row index inside its domain" {
    const seq = try Seq.init(6);
    try std.testing.expectEqual(@as(u32, 0), try seq.value(0));
    try std.testing.expectEqual(@as(u32, 63), try seq.value(63));
    try std.testing.expectError(error.InvalidRow, seq.value(64));
    try std.testing.expectEqual(@as(u32, (1 << 30) - 1), try (try Seq.init(30)).value((1 << 30) - 1));
    try std.testing.expectError(error.InvalidTableParameters, Seq.init(31));
}

test "preprocessed tables: bitwise xor matches upstream test_packed_at_bitwise_xor" {
    // `bitwise_xor.rs::tests::test_packed_at_bitwise_xor`: LOG_SIZE (n_bits)
    // 8, row 1000 holds a = 1000 / 256, b = 1000 % 256, a ^ b.
    const row: u32 = 1000;
    try std.testing.expectEqual(row / 256, try (try BitwiseXor.init(8, 0)).value(row));
    try std.testing.expectEqual(row % 256, try (try BitwiseXor.init(8, 1)).value(row));
    try std.testing.expectEqual((row / 256) ^ (row % 256), try (try BitwiseXor.init(8, 2)).value(row));
}

test "preprocessed tables: bitwise xor rejects rows and shapes outside the table" {
    const xor4 = try BitwiseXor.init(4, 2);
    try std.testing.expectEqual(@as(u32, 3 ^ 7), try xor4.value((3 << 4) | 7));
    try std.testing.expectError(error.InvalidRow, xor4.value(1 << 8));
    try std.testing.expectError(error.InvalidTableParameters, BitwiseXor.init(0, 0));
    try std.testing.expectError(error.InvalidTableParameters, BitwiseXor.init(16, 0));
    try std.testing.expectError(error.InvalidTableParameters, BitwiseXor.init(4, 3));
    _ = try BitwiseXor.init(15, 2);
}
