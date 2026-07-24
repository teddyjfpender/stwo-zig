//! Exact Native Plonk trace geometry derived from the public statement.

const std = @import("std");
const cpu_plonk = @import("../../../examples/plonk/input.zig");

pub const preprocessed_columns: u32 = 4;
pub const main_columns: u32 = 4;

pub const Error = cpu_plonk.Error || error{
    GeometryOverflow,
};

pub const Geometry = struct {
    statement: cpu_plonk.Statement,
    row_count: u32,
    preprocessed_cells: u64,
    main_cells: u64,
    committed_cells: u64,
};

pub fn admit(statement: cpu_plonk.Statement) Error!Geometry {
    try cpu_plonk.validate(statement);
    const row_count = @as(u32, 1) << @intCast(statement.log_n_rows);
    const preprocessed_cells = std.math.mul(
        u64,
        row_count,
        preprocessed_columns,
    ) catch return error.GeometryOverflow;
    const main_cells = std.math.mul(
        u64,
        row_count,
        main_columns,
    ) catch return error.GeometryOverflow;
    return .{
        .statement = statement,
        .row_count = row_count,
        .preprocessed_cells = preprocessed_cells,
        .main_cells = main_cells,
        .committed_cells = std.math.add(
            u64,
            preprocessed_cells,
            main_cells,
        ) catch return error.GeometryOverflow,
    };
}

test "Plonk geometry derives both four-column trees" {
    const geometry = try admit(.{ .log_n_rows = 14 });
    try std.testing.expectEqual(@as(u32, 1 << 14), geometry.row_count);
    try std.testing.expectEqual(
        @as(u64, 4 * (1 << 14)),
        geometry.preprocessed_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 4 * (1 << 14)),
        geometry.main_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 8 * (1 << 14)),
        geometry.committed_cells,
    );
}

test "Plonk geometry rejects zero and oversized logs" {
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(.{ .log_n_rows = 0 }),
    );
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(.{ .log_n_rows = 31 }),
    );
}
