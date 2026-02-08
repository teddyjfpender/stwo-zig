const std = @import("std");
const m31 = @import("../../core/fields/m31.zig");
const qm31 = @import("../../core/fields/qm31.zig");
const quotients = @import("../../core/pcs/quotients.zig");
const pcs_utils = @import("../../core/pcs/utils.zig");
const secure_column = @import("../secure_column.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs_utils.TreeVec;
const PointSample = quotients.PointSample;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const QuotientOpsError = error{
    ShapeMismatch,
    InvalidColumnLogSize,
    InvalidColumnLength,
};

/// One committed trace/evaluation column.
///
/// Invariants:
/// - `values.len == 2^log_size`.
/// - `values` are in bit-reversed order, matching Stwo prover conventions.
pub const ColumnEvaluation = struct {
    log_size: u32,
    values: []const M31,

    pub fn validate(self: ColumnEvaluation) QuotientOpsError!void {
        const expected_len = try checkedPow2(self.log_size);
        if (self.values.len != expected_len) return QuotientOpsError.InvalidColumnLength;
    }

    /// Returns the value at lifted-domain position `position` where the maximal
    /// domain has log size `lifting_log_size`.
    pub fn valueAtLiftingPosition(
        self: ColumnEvaluation,
        lifting_log_size: u32,
        position: usize,
    ) QuotientOpsError!M31 {
        try self.validate();
        if (self.log_size > lifting_log_size) return QuotientOpsError.InvalidColumnLogSize;

        const lifting_domain_size = try checkedPow2(lifting_log_size);
        if (position >= lifting_domain_size) return QuotientOpsError.ShapeMismatch;

        const log_shift = lifting_log_size - self.log_size;
        if (log_shift >= @bitSizeOf(usize)) return QuotientOpsError.InvalidColumnLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);

        const idx = ((position >> shift_amt) << 1) + (position & 1);
        if (idx >= self.values.len) return QuotientOpsError.InvalidColumnLength;
        return self.values[idx];
    }
};

/// Computes FRI quotient evaluations for all points in the lifted domain.
///
/// Inputs:
/// - `columns`: per-tree, per-column evaluations and original log sizes.
/// - `samples`: per-tree, per-column OODS samples; shape must match `columns`.
/// - `random_coeff`: random challenge used for linear combination.
/// - `lifting_log_size`: maximal lifted domain size.
/// - `log_blowup_factor`: included for API parity (not used directly here).
///
/// Output:
/// - secure-field quotient evaluation values over all lifted-domain positions.
pub fn computeFriQuotients(
    allocator: std.mem.Allocator,
    columns: TreeVec([]ColumnEvaluation),
    samples: TreeVec([][]PointSample),
    random_coeff: QM31,
    lifting_log_size: u32,
    log_blowup_factor: u32,
) !SecureColumnByCoords {
    _ = log_blowup_factor;

    if (columns.items.len != samples.items.len) return QuotientOpsError.ShapeMismatch;

    for (columns.items, samples.items) |tree_columns, tree_samples| {
        if (tree_columns.len != tree_samples.len) return QuotientOpsError.ShapeMismatch;
        for (tree_columns) |column| {
            try column.validate();
            if (column.log_size > lifting_log_size) return QuotientOpsError.InvalidColumnLogSize;
        }
    }

    var column_log_sizes = try buildColumnLogSizes(allocator, columns);
    defer column_log_sizes.deinitDeep(allocator);

    var queried_values = try buildLiftedQueriedValues(allocator, columns, lifting_log_size);
    defer queried_values.deinitDeep(allocator);

    const query_positions = try fullQueryPositions(allocator, lifting_log_size);
    defer allocator.free(query_positions);

    const quot_values = try quotients.friAnswers(
        allocator,
        column_log_sizes,
        samples,
        random_coeff,
        query_positions,
        queried_values,
        lifting_log_size,
    );
    defer allocator.free(quot_values);

    return SecureColumnByCoords.fromSecureSlice(allocator, quot_values);
}

fn checkedPow2(log_size: u32) QuotientOpsError!usize {
    if (log_size >= @bitSizeOf(usize)) return QuotientOpsError.InvalidColumnLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn fullQueryPositions(
    allocator: std.mem.Allocator,
    lifting_log_size: u32,
) (std.mem.Allocator.Error || QuotientOpsError)![]usize {
    const domain_size = try checkedPow2(lifting_log_size);
    const out = try allocator.alloc(usize, domain_size);
    for (out, 0..) |*position, i| position.* = i;
    return out;
}

fn buildColumnLogSizes(
    allocator: std.mem.Allocator,
    columns: TreeVec([]ColumnEvaluation),
) !TreeVec([]u32) {
    const out = try allocator.alloc([]u32, columns.items.len);
    errdefer allocator.free(out);

    var initialized: usize = 0;
    errdefer {
        for (out[0..initialized]) |tree_sizes| allocator.free(tree_sizes);
    }

    for (columns.items, 0..) |tree_columns, tree_idx| {
        out[tree_idx] = try allocator.alloc(u32, tree_columns.len);
        initialized += 1;
        for (tree_columns, 0..) |column, col_idx| {
            out[tree_idx][col_idx] = column.log_size;
        }
    }

    return TreeVec([]u32).initOwned(out);
}

fn buildLiftedQueriedValues(
    allocator: std.mem.Allocator,
    columns: TreeVec([]ColumnEvaluation),
    lifting_log_size: u32,
) (std.mem.Allocator.Error || QuotientOpsError)!TreeVec([][]M31) {
    const out = try allocator.alloc([][]M31, columns.items.len);
    errdefer allocator.free(out);

    var initialized_trees: usize = 0;
    errdefer {
        for (out[0..initialized_trees]) |tree_values| {
            for (tree_values) |col_values| allocator.free(col_values);
            allocator.free(tree_values);
        }
    }

    const domain_size = try checkedPow2(lifting_log_size);

    for (columns.items, 0..) |tree_columns, tree_idx| {
        const tree_values = try allocator.alloc([]M31, tree_columns.len);
        out[tree_idx] = tree_values;
        initialized_trees += 1;

        var initialized_cols: usize = 0;
        errdefer {
            for (tree_values[0..initialized_cols]) |col_values| allocator.free(col_values);
            allocator.free(tree_values);
        }

        for (tree_columns, 0..) |column, col_idx| {
            const lifted = try allocator.alloc(M31, domain_size);
            tree_values[col_idx] = lifted;
            initialized_cols += 1;

            for (0..domain_size) |position| {
                lifted[position] = try column.valueAtLiftingPosition(lifting_log_size, position);
            }
        }
    }

    return TreeVec([][]M31).initOwned(out);
}

test "prover pcs quotient ops: compute fri quotients matches direct fri answers" {
    const alloc = std.testing.allocator;
    const lifting_log_size: u32 = 5;
    const domain_size = @as(usize, 1) << @intCast(lifting_log_size);

    const col0 = try alloc.alloc(M31, domain_size);
    defer alloc.free(col0);
    for (col0, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i + 1));

    const col1_log_size: u32 = 3;
    const col1 = try alloc.alloc(M31, @as(usize, 1) << @intCast(col1_log_size));
    defer alloc.free(col1);
    for (col1, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(101 + i));

    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = lifting_log_size, .values = col0 },
        .{ .log_size = col1_log_size, .values = col1 },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);

    const point0 = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(7);
    const point1 = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN.mul(19);

    const col0_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(1, 2, 3, 4) },
    });
    const col1_samples = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = point0, .value = QM31.fromU32Unchecked(5, 6, 7, 8) },
        .{ .point = point1, .value = QM31.fromU32Unchecked(9, 10, 11, 12) },
    });
    const tree_samples = try alloc.dupe([]PointSample, &[_][]PointSample{ col0_samples, col1_samples });
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{tree_samples}),
    );
    defer samples.deinitDeep(alloc);

    const alpha = QM31.fromU32Unchecked(3, 0, 1, 0);
    var quot_col = try computeFriQuotients(
        alloc,
        columns,
        samples,
        alpha,
        lifting_log_size,
        1,
    );
    defer quot_col.deinit(alloc);

    var col_sizes = TreeVec([]u32).initOwned(
        try alloc.dupe([]u32, &[_][]u32{try alloc.dupe(u32, &[_]u32{ lifting_log_size, col1_log_size })}),
    );
    defer col_sizes.deinitDeep(alloc);

    const q0 = try alloc.dupe(M31, col0);

    const q1 = try alloc.alloc(M31, domain_size);
    const shift: u32 = lifting_log_size - col1_log_size;
    const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
    for (0..domain_size) |position| {
        const idx = ((position >> shift_amt) << 1) + (position & 1);
        q1[position] = col1[idx];
    }

    var queried_values = TreeVec([][]M31).initOwned(
        try alloc.dupe([][]M31, &[_][][]M31{try alloc.dupe([]M31, &[_][]M31{ q0, q1 })}),
    );
    defer queried_values.deinitDeep(alloc);

    const query_positions = try alloc.alloc(usize, domain_size);
    defer alloc.free(query_positions);
    for (query_positions, 0..) |*position, i| position.* = i;

    const expected = try quotients.friAnswers(
        alloc,
        col_sizes,
        samples,
        alpha,
        query_positions,
        queried_values,
        lifting_log_size,
    );
    defer alloc.free(expected);

    const got = try quot_col.toVec(alloc);
    defer alloc.free(got);

    try std.testing.expectEqual(expected.len, got.len);
    for (expected, got) |lhs, rhs| {
        try std.testing.expect(lhs.eql(rhs));
    }
}

test "prover pcs quotient ops: rejects invalid column length" {
    const alloc = std.testing.allocator;

    const bad_column = [_]M31{ M31.one(), M31.one(), M31.one() };
    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = 2, .values = bad_column[0..] },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);

    const sample_col = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN, .value = QM31.one() },
    });
    const sample_tree = try alloc.dupe([]PointSample, &[_][]PointSample{sample_col});
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{sample_tree}),
    );
    defer samples.deinitDeep(alloc);

    try std.testing.expectError(
        QuotientOpsError.InvalidColumnLength,
        computeFriQuotients(alloc, columns, samples, QM31.one(), 2, 1),
    );
}

test "prover pcs quotient ops: rejects column log size above lifting" {
    const alloc = std.testing.allocator;

    const column = [_]M31{ M31.one(), M31.one(), M31.one(), M31.one() };
    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = 2, .values = column[0..] },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);

    const sample_col = try alloc.dupe(PointSample, &[_]PointSample{
        .{ .point = @import("../../core/circle.zig").SECURE_FIELD_CIRCLE_GEN, .value = QM31.one() },
    });
    const sample_tree = try alloc.dupe([]PointSample, &[_][]PointSample{sample_col});
    var samples = TreeVec([][]PointSample).initOwned(
        try alloc.dupe([][]PointSample, &[_][][]PointSample{sample_tree}),
    );
    defer samples.deinitDeep(alloc);

    try std.testing.expectError(
        QuotientOpsError.InvalidColumnLogSize,
        computeFriQuotients(alloc, columns, samples, QM31.one(), 1, 1),
    );
}

test "prover pcs quotient ops: rejects shape mismatch" {
    const alloc = std.testing.allocator;

    const column = [_]M31{ M31.one(), M31.one() };
    const tree_columns = try alloc.dupe(ColumnEvaluation, &[_]ColumnEvaluation{
        .{ .log_size = 1, .values = column[0..] },
    });
    var columns = TreeVec([]ColumnEvaluation).initOwned(
        try alloc.dupe([]ColumnEvaluation, &[_][]ColumnEvaluation{tree_columns}),
    );
    defer columns.deinitDeep(alloc);

    var samples = TreeVec([][]PointSample).initOwned(try alloc.alloc([][]PointSample, 0));
    defer samples.deinitDeep(alloc);

    try std.testing.expectError(
        QuotientOpsError.ShapeMismatch,
        computeFriQuotients(alloc, columns, samples, QM31.one(), 1, 1),
    );
}
