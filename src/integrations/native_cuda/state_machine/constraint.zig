//! State Machine policy for its transcript-derived constant composition.

const field = @import(
    "../../../backends/cuda/abi/field.zig",
);
const state_machine = @import(
    "../../../backends/cuda/runtime/constraints/state_machine.zig",
);
const geometry_mod = @import("geometry.zig");

pub const Buffers = state_machine.Buffers;

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !state_machine.PreparedLaunch {
    if (buffers.statement_parameters.len !=
        geometry_mod.statement_word_count or
        buffers.challenge_parameters.len != 4)
    {
        return error.InvalidKernelDescriptor;
    }
    return state_machine.prepare(
        session,
        buffers,
        .{
            .component_index = 0,
            .component_count = 1,
            .evaluation_log_size = geometry.composition_log_rows,
            .trace_log_size = geometry.statement.log_n_rows,
            .preprocessed_column_count = geometry_mod.preprocessed_columns,
            .main_column_count = geometry_mod.main_columns,
        },
        .{ .a = 0, .b = 0, .c = 0, .d = 0 },
    );
}

pub fn evaluate(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    var launch = try prepare(session, buffers, geometry);
    try launch.launch(session);
}

test "state-machine constraint binds the complete derived statement" {
    const std = @import("std");
    try std.testing.expectEqual(
        @as(usize, 14),
        geometry_mod.statement_word_count,
    );
}
