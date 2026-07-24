//! XOR-owned policy for the generic constant-QM31 CUDA constraint kernel.

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
    statement: @import("../../../examples/xor.zig").Statement,
) field.SecureField {
    return .{
        .a = M31.fromCanonical(statement.log_size).toU32(),
        .b = M31.fromCanonical(statement.log_step).toU32(),
        .c = M31.fromU64(@intCast(statement.offset)).toU32(),
        .d = M31.one().toU32(),
    };
}

pub fn prepare(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !constant_qm31.PreparedLaunch {
    if (buffers.statement_parameters.len != 4 or
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
            .trace_log_size = geometry.statement.log_size,
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

test "XOR composition value matches the CPU AIR coordinate order" {
    const std = @import("std");
    const value = compositionValue(.{
        .log_size = 16,
        .log_step = 3,
        .offset = @as(usize, 2_147_483_647) + 5,
    });
    try std.testing.expectEqual(@as(u32, 16), value.a);
    try std.testing.expectEqual(@as(u32, 3), value.b);
    try std.testing.expectEqual(@as(u32, 5), value.c);
    try std.testing.expectEqual(@as(u32, 1), value.d);
}
