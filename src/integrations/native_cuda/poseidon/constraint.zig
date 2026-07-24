//! Poseidon-owned policy for the generic constant-QM31 CUDA constraint kernel.

const field = @import(
    "../../../backends/cuda/abi/field.zig",
);
const constant_qm31 = @import(
    "../../../backends/cuda/runtime/constraints/constant_qm31.zig",
);
const geometry_mod = @import("geometry.zig");
const poseidon_input = @import("../../../examples/poseidon/input.zig");
const M31 = @import("stwo_core").fields.m31.M31;

pub const Buffers = constant_qm31.Buffers;

pub fn compositionValue(
    geometry: geometry_mod.Geometry,
) field.SecureField {
    return .{
        .a = M31.fromCanonical(
            geometry.statement.log_n_instances,
        ).toU32(),
        .b = M31.fromCanonical(
            @intCast(poseidon_input.N_COLUMNS_PER_REP),
        ).toU32(),
        .c = M31.fromCanonical(geometry.main_columns).toU32(),
        .d = M31.one().toU32(),
    };
}

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !constant_qm31.PreparedLaunch {
    if (buffers.statement_parameters.len != 1 or
        buffers.challenge_parameters.len != 4)
    {
        return error.InvalidKernelDescriptor;
    }
    return constant_qm31.prepare(
        session,
        buffers,
        .{
            .component_index = 0,
            .component_count = 1,
            .evaluation_log_size = geometry.composition_log_rows,
            .trace_log_size = geometry.log_n_rows,
            .preprocessed_column_count = geometry_mod.preprocessed_columns,
            .main_column_count = geometry.main_columns,
        },
        compositionValue(geometry),
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

test "Poseidon composition value matches the CPU AIR coordinate order" {
    const std = @import("std");
    const value = compositionValue(try geometry_mod.admit(
        .{ .log_n_instances = 13 },
        @import("stwo_core").pcs.PcsConfig.default(),
    ));
    try std.testing.expectEqual(@as(u32, 13), value.a);
    try std.testing.expectEqual(@as(u32, 158), value.b);
    try std.testing.expectEqual(@as(u32, 1264), value.c);
    try std.testing.expectEqual(@as(u32, 1), value.d);
}
