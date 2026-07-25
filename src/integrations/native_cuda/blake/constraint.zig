//! Blake-owned policy for the exact mixed-height resident CUDA AIR kernel.

const runtime_blake = @import(
    "../../../backends/cuda/runtime/constraints/blake.zig",
);
const geometry_mod = @import("geometry.zig");

pub const Buffers = runtime_blake.Buffers;

pub fn prepare(
    session: anytype,
    buffers: anytype,
    geometry: geometry_mod.Geometry,
) !runtime_blake.PreparedLaunch {
    if (geometry.statement.n_rounds != 10)
        return error.InvalidKernelDescriptor;
    if (comptime @TypeOf(buffers) != Buffers)
        return error.InvalidKernelDescriptor;
    const expected_log = try runtime_blake.maximumEvaluationLogSize(
        geometry.statement.log_n_rows,
    );
    const expected_rows = @as(usize, 1) << @intCast(expected_log);
    if (buffers.composition_coordinates.column_stride_words != expected_rows)
        return error.InvalidKernelDescriptor;
    return runtime_blake.prepare(
        session,
        buffers,
        geometry.statement.log_n_rows,
    );
}

pub fn evaluate(
    session: anytype,
    buffers: anytype,
    geometry: geometry_mod.Geometry,
) !void {
    var launch = try prepare(session, buffers, geometry);
    try launch.launch(session);
}

test "Blake constraint facade requires exact ten-round geometry" {
    const std = @import("std");
    const pcs = @import("stwo_core").pcs;
    const geometry = try geometry_mod.admit(
        .{ .log_n_rows = 10, .n_rounds = 10 },
        pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(
        @as(u32, 17),
        try runtime_blake.maximumEvaluationLogSize(
            geometry.statement.log_n_rows,
        ),
    );
    const provisional = try geometry_mod.admit(
        .{ .log_n_rows = 10, .n_rounds = 9 },
        pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(@as(u32, 9), provisional.statement.n_rounds);
}
