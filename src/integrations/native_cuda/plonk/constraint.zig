//! Plonk-owned policy for the generic constant-QM31 CUDA constraint kernel.

const field = @import(
    "../../../backends/cuda/abi/field.zig",
);
const constant_qm31 = @import(
    "../../../backends/cuda/runtime/constraints/constant_qm31.zig",
);
const geometry_mod = @import("geometry.zig");
const M31 = @import("stwo_core").fields.m31.M31;

pub const Buffers = constant_qm31.Buffers;

pub fn compositionValue(
    statement: @import("../../../examples/plonk.zig").Statement,
) field.SecureField {
    return .{
        .a = M31.fromCanonical(statement.log_n_rows).toU32(),
        .b = M31.fromCanonical(4).toU32(),
        .c = M31.one().toU32(),
        .d = M31.one().toU32(),
    };
}

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !constant_qm31.PreparedLaunch {
    if (buffers.statement_parameters.len !=
        geometry_mod.statement_word_count or
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
            .trace_log_size = geometry.statement.log_n_rows,
            .preprocessed_column_count = geometry_mod.preprocessed_columns,
            .main_column_count = geometry_mod.main_columns,
        },
        compositionValue(geometry.statement),
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

test "Plonk composition value matches the CPU AIR coordinate order" {
    const std = @import("std");
    const value = compositionValue(.{ .log_n_rows = 16 });
    try std.testing.expectEqual(@as(u32, 16), value.a);
    try std.testing.expectEqual(@as(u32, 4), value.b);
    try std.testing.expectEqual(@as(u32, 1), value.c);
    try std.testing.expectEqual(@as(u32, 1), value.d);
}
