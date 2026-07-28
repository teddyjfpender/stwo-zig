//! Stable commitment-column request and ownership types.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

pub const QuotientOpsError = error{
    ShapeMismatch,
    InvalidColumnLogSize,
    InvalidColumnLength,
};

/// Borrowed evaluations of one circle-domain column.
///
/// Lifting preserves Stwo's circle-domain storage order: each source pair is
/// repeated across the corresponding pair-aligned block in the larger domain.
pub const ColumnEvaluation = struct {
    log_size: u32,
    values: []const M31,

    pub fn validate(self: ColumnEvaluation) QuotientOpsError!void {
        const expected_len = try checkedPow2(self.log_size);
        if (self.values.len != expected_len) return error.InvalidColumnLength;
    }

    pub fn valueAtLiftingPosition(
        self: ColumnEvaluation,
        lifting_log_size: u32,
        position: usize,
    ) QuotientOpsError!M31 {
        try self.validate();
        if (self.log_size > lifting_log_size) return error.InvalidColumnLogSize;

        const lifting_domain_size = try checkedPow2(lifting_log_size);
        if (position >= lifting_domain_size) return error.ShapeMismatch;

        const log_shift = lifting_log_size - self.log_size;
        if (log_shift >= @bitSizeOf(usize)) return error.InvalidColumnLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);

        const index = ((position >> shift_amt) << 1) + (position & 1);
        if (index >= self.values.len) return error.InvalidColumnLength;
        return self.values[index];
    }
};

pub const QuadraticRecurrence = struct {
    log_n_rows: u32,
    recipe: [7]u32,
};

/// Structural producer attached to an owned commitment-column transaction.
pub const ColumnSource = union(enum) {
    materialized,
    quadratic_recurrence: QuadraticRecurrence,

    pub fn isMaterialized(self: ColumnSource) bool {
        return self == .materialized;
    }
};

pub fn checkedPow2(log_size: u32) QuotientOpsError!usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidColumnLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

test "column evaluation validates storage and lifting geometry" {
    const values = [_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(20),
        M31.fromCanonical(21),
    };
    const column = ColumnEvaluation{ .log_size = 2, .values = &values };
    try column.validate();
    try std.testing.expectEqual(@as(u32, 10), (try column.valueAtLiftingPosition(4, 0)).v);
    try std.testing.expectEqual(@as(u32, 20), (try column.valueAtLiftingPosition(4, 8)).v);
    try std.testing.expectError(error.ShapeMismatch, column.valueAtLiftingPosition(4, 16));
}

test "column source defaults to explicit materialized state" {
    const source: ColumnSource = .materialized;
    try std.testing.expect(source.isMaterialized());
}
