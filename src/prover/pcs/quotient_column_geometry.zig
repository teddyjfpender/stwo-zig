const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const pcs_utils = @import("stwo_core").pcs.utils;
const prover_api = @import("stwo_prover_api");

const M31 = m31.M31;
const TreeVec = pcs_utils.TreeVec;

pub const QuotientOpsError = prover_api.QuotientOpsError;
pub const ColumnEvaluation = prover_api.ColumnEvaluation;

/// Returns the exact domain size for a representable binary log size.
pub fn checkedPow2(log_size: u32) QuotientOpsError!usize {
    return prover_api.column.checkedPow2(log_size);
}

/// Flattens tree-major columns without taking ownership of their evaluations.
pub fn flattenColumnsBorrowed(
    allocator: std.mem.Allocator,
    columns: TreeVec([]const ColumnEvaluation),
) ![]ColumnEvaluation {
    const flattened = try allocator.alloc(ColumnEvaluation, countColumns(columns));
    var write_index: usize = 0;
    for (columns.items) |tree_columns| {
        for (tree_columns) |column| {
            flattened[write_index] = column;
            write_index += 1;
        }
    }
    return flattened;
}

/// Projects the tree/column shape into an independently owned log-size tree.
pub fn buildColumnLogSizes(
    allocator: std.mem.Allocator,
    columns: TreeVec([]const ColumnEvaluation),
) !TreeVec([]u32) {
    const log_size_trees = try allocator.alloc([]u32, columns.items.len);
    errdefer allocator.free(log_size_trees);

    var initialized: usize = 0;
    errdefer {
        for (log_size_trees[0..initialized]) |tree_sizes| allocator.free(tree_sizes);
    }

    for (columns.items, 0..) |tree_columns, tree_index| {
        log_size_trees[tree_index] = try allocator.alloc(u32, tree_columns.len);
        initialized += 1;
        for (tree_columns, 0..) |column, column_index| {
            log_size_trees[tree_index][column_index] = column.log_size;
        }
    }

    return TreeVec([]u32).initOwned(log_size_trees);
}

/// Counts columns across all trees without flattening them.
pub fn countColumns(columns: TreeVec([]const ColumnEvaluation)) usize {
    var total: usize = 0;
    for (columns.items) |tree_columns| total += tree_columns.len;
    return total;
}

test "quotient column geometry preserves pair-aligned lifting order" {
    const values = [_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(11),
        M31.fromCanonical(20),
        M31.fromCanonical(21),
    };
    const column = ColumnEvaluation{ .log_size = 2, .values = &values };
    const expected = [_]u32{ 10, 11, 10, 11, 10, 11, 10, 11, 20, 21, 20, 21, 20, 21, 20, 21 };

    for (expected, 0..) |value, position| {
        try std.testing.expectEqual(value, (try column.valueAtLiftingPosition(4, position)).v);
    }
}

test "quotient column geometry rejects invalid lengths and positions" {
    const values = [_]M31{ M31.one(), M31.one(), M31.one() };
    const column = ColumnEvaluation{ .log_size = 2, .values = &values };

    try std.testing.expectError(QuotientOpsError.InvalidColumnLength, column.validate());
    try std.testing.expectError(
        QuotientOpsError.InvalidColumnLogSize,
        checkedPow2(@bitSizeOf(usize)),
    );

    const valid_values = [_]M31{ M31.one(), M31.zero(), M31.one(), M31.zero() };
    const valid_column = ColumnEvaluation{ .log_size = 2, .values = &valid_values };
    try std.testing.expectError(
        QuotientOpsError.ShapeMismatch,
        valid_column.valueAtLiftingPosition(3, 8),
    );
    try std.testing.expectError(
        QuotientOpsError.InvalidColumnLogSize,
        valid_column.valueAtLiftingPosition(1, 0),
    );
}

test "quotient column tree geometry retains tree and column order" {
    const values_a = [_]M31{M31.one()} ** 2;
    const values_b = [_]M31{M31.one()} ** 4;
    const values_c = [_]M31{M31.one()} ** 8;
    const tree_a = [_]ColumnEvaluation{
        .{ .log_size = 1, .values = &values_a },
        .{ .log_size = 2, .values = &values_b },
    };
    const tree_b = [_]ColumnEvaluation{
        .{ .log_size = 3, .values = &values_c },
    };
    var trees = [_][]const ColumnEvaluation{ &tree_a, &tree_b };
    const columns = TreeVec([]const ColumnEvaluation).initOwned(&trees);

    try std.testing.expectEqual(@as(usize, 3), countColumns(columns));

    const flattened = try flattenColumnsBorrowed(std.testing.allocator, columns);
    defer std.testing.allocator.free(flattened);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 3 }, &.{
        flattened[0].log_size,
        flattened[1].log_size,
        flattened[2].log_size,
    });

    var log_sizes = try buildColumnLogSizes(std.testing.allocator, columns);
    defer log_sizes.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), log_sizes.items.len);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2 }, log_sizes.items[0]);
    try std.testing.expectEqualSlices(u32, &.{3}, log_sizes.items[1]);
}
