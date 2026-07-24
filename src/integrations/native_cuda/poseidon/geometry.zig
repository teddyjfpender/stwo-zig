//! Exact Native Poseidon trace geometry derived from the public statement.

const std = @import("std");
const cpu_poseidon = @import("../../../examples/poseidon/input.zig");

pub const Error = cpu_poseidon.Error || error{
    GeometryOverflow,
};

pub const Geometry = struct {
    statement: cpu_poseidon.Statement,
    log_n_rows: u32,
    row_count: u32,
    main_columns: u32,
    main_cells: u64,
};

pub fn admit(statement: cpu_poseidon.Statement) Error!Geometry {
    const log_n_rows = try cpu_poseidon.logNRows(statement);
    const row_count = @as(u32, 1) << @intCast(log_n_rows);
    const main_columns = std.math.cast(
        u32,
        cpu_poseidon.N_COLUMNS,
    ) orelse return error.GeometryOverflow;
    const main_cells = std.math.mul(
        u64,
        row_count,
        main_columns,
    ) catch return error.GeometryOverflow;
    return .{
        .statement = statement,
        .log_n_rows = log_n_rows,
        .row_count = row_count,
        .main_columns = main_columns,
        .main_cells = main_cells,
    };
}

test "Poseidon geometry derives rows and all columns from instances" {
    const geometry = try admit(.{ .log_n_instances = 10 });
    try std.testing.expectEqual(@as(u32, 7), geometry.log_n_rows);
    try std.testing.expectEqual(@as(u32, 128), geometry.row_count);
    try std.testing.expectEqual(@as(u32, 1264), geometry.main_columns);
    try std.testing.expectEqual(@as(u64, 161_792), geometry.main_cells);
}

test "Poseidon geometry rejects a statement below one packed row" {
    try std.testing.expectError(
        error.InvalidLogNInstances,
        admit(.{ .log_n_instances = 2 }),
    );
}
