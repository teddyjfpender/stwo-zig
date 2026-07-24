//! Exact Native state-machine geometry derived from the public request.

const std = @import("std");
const cpu_state_machine =
    @import("../../../examples/state_machine/input.zig");

pub const preprocessed_columns: u32 = 1;
pub const main_columns: u32 = 2;

pub const Error = cpu_state_machine.Error || error{
    GeometryOverflow,
};

pub const Geometry = struct {
    request: cpu_state_machine.Request,
    row_count: u32,
    preprocessed_cells: u64,
    main_cells: u64,
    committed_cells: u64,
};

pub fn admit(request: cpu_state_machine.Request) Error!Geometry {
    try cpu_state_machine.validate(request);
    const row_count = @as(u32, 1) << @intCast(request.log_n_rows);
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
        .request = request,
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

test "state-machine geometry derives both commitment trees" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const geometry = try admit(.{
        .log_n_rows = 14,
        .initial_state = .{ M31.fromU64(17), M31.fromU64(23) },
    });
    try std.testing.expectEqual(@as(u32, 1 << 14), geometry.row_count);
    try std.testing.expectEqual(
        @as(u64, 1 << 14),
        geometry.preprocessed_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 2 * (1 << 14)),
        geometry.main_cells,
    );
    try std.testing.expectEqual(
        @as(u64, 3 * (1 << 14)),
        geometry.committed_cells,
    );
}

test "state-machine geometry rejects zero and oversized logs" {
    const M31 = @import("stwo_core").fields.m31.M31;
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(.{
            .log_n_rows = 0,
            .initial_state = .{ M31.one(), M31.one() },
        }),
    );
    try std.testing.expectError(
        error.InvalidLogSize,
        admit(.{
            .log_n_rows = 31,
            .initial_state = .{ M31.one(), M31.one() },
        }),
    );
}
