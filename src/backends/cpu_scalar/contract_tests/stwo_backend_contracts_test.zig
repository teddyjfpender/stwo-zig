//! Backend contracts relied on by the scalar CPU implementation.
const std = @import("std");
const provider = @import("stwo_backend_contracts");
const cpu = @import("stwo_cpu_backend");

comptime {
    provider.assertBackend(cpu.CpuBackend);
}

test "cdc: CPU trace geometry refuses invalid domains and checked overflow" {
    var geometry = provider.proof_program.NativeTraceGeometry{
        .component = 0,
        .log_rows = 5,
        .preprocessed_columns = 2,
        .main_columns = 3,
        .interaction_columns = 4,
    };
    try std.testing.expectEqual(@as(u64, 288), try geometry.elementCount());
    geometry.log_rows = 63;
    try std.testing.expectError(error.InvalidGeometry, geometry.elementCount());
    geometry.log_rows = 62;
    try std.testing.expectError(error.GeometryOverflow, geometry.elementCount());
}
