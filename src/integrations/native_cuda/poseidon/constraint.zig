//! Poseidon-owned policy for the exact resident CUDA AIR kernel.

const runtime_poseidon = @import("stwo_cuda_backend").runtime.constraints.poseidon;
const geometry_mod = @import("geometry.zig");

pub const Buffers = runtime_poseidon.Buffers;

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !runtime_poseidon.PreparedLaunch {
    if (buffers.source_evaluations.column_stride_words !=
        geometry.composition_rows or
        buffers.composition_coordinates.column_stride_words !=
            geometry.composition_rows)
    {
        return error.InvalidKernelDescriptor;
    }
    return runtime_poseidon.prepare(
        session,
        buffers,
        geometry.log_n_rows,
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

test "Poseidon constraint facade preserves the exact 4N evaluation domain" {
    const std = @import("std");
    const geometry = try geometry_mod.admit(
        .{ .log_n_instances = 13 },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    try std.testing.expectEqual(
        @as(usize, 4096),
        geometry.composition_rows,
    );
    try std.testing.expectEqual(
        @as(u32, 1296),
        runtime_poseidon.source_column_count,
    );
    try std.testing.expectEqual(
        @as(u32, 1144),
        runtime_poseidon.constraint_count,
    );
}
