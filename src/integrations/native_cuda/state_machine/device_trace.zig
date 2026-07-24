//! State-machine binding to the resident circle-affine trace primitive.

const circle_affine = @import(
    "../../../backends/cuda/runtime/traces/circle_affine_state.zig",
);
const geometry_mod = @import("geometry.zig");

pub const Buffers = circle_affine.Destinations;

pub fn generate(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    var launch = try circle_affine.prepare(
        session,
        buffers,
        .{ .log_n_rows = geometry.statement.log_n_rows },
        .{ .initial_state = .{
            geometry.statement.initial_state[0].toU32(),
            geometry.statement.initial_state[1].toU32(),
        } },
        .{
            .increment_coordinate = 0,
            .increment_value = 1,
            .indicator_first = 1,
            .indicator_default = 0,
        },
    );
    try launch.launch(session);
}

test "state-machine device trace uses the existing strict-AOT recipe" {
    const std = @import("std");
    try std.testing.expectEqual(@as(u32, 1), circle_affine.preprocessed_columns);
    try std.testing.expectEqual(@as(u32, 2), circle_affine.main_columns);
}
