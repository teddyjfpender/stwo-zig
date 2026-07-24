//! Exact Native Blake trace geometry derived from the public statement.

const std = @import("std");
const cpu_blake = @import("../../../examples/blake.zig");

pub const columns_per_round: u32 = 96;

pub const Error = error{
    InvalidLogNRows,
    InvalidNRounds,
    GeometryOverflow,
};

pub const Geometry = struct {
    statement: cpu_blake.Statement,
    row_count: u32,
    main_columns: u32,
    main_cells: u64,
};

pub fn admit(statement: cpu_blake.Statement) Error!Geometry {
    if (statement.log_n_rows == 0 or statement.log_n_rows >= 31)
        return error.InvalidLogNRows;
    if (statement.n_rounds == 0) return error.InvalidNRounds;
    const row_count = @as(u32, 1) << @intCast(statement.log_n_rows);
    const main_columns = std.math.mul(
        u32,
        statement.n_rounds,
        columns_per_round,
    ) catch return error.GeometryOverflow;
    const main_cells = std.math.mul(
        u64,
        row_count,
        main_columns,
    ) catch return error.GeometryOverflow;
    return .{
        .statement = statement,
        .row_count = row_count,
        .main_columns = main_columns,
        .main_cells = main_cells,
    };
}

test "Blake geometry derives all rows and columns from the statement" {
    const geometry = try admit(.{ .log_n_rows = 10, .n_rounds = 10 });
    try std.testing.expectEqual(@as(u32, 1024), geometry.row_count);
    try std.testing.expectEqual(@as(u32, 960), geometry.main_columns);
    try std.testing.expectEqual(@as(u64, 983_040), geometry.main_cells);
}

test "Blake geometry rejects zero and overflowing statements" {
    try std.testing.expectError(
        error.InvalidLogNRows,
        admit(.{ .log_n_rows = 0, .n_rounds = 1 }),
    );
    try std.testing.expectError(
        error.InvalidNRounds,
        admit(.{ .log_n_rows = 3, .n_rounds = 0 }),
    );
    try std.testing.expectError(
        error.GeometryOverflow,
        admit(.{ .log_n_rows = 3, .n_rounds = std.math.maxInt(u32) }),
    );
}
