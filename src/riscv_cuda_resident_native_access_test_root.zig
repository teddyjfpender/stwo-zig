const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_access_program_v1.zig"));
}
test "resident native access CUDA export" {
    const a = std.testing.allocator;
    const P = @import("integrations/riscv_cuda/resident_native_access_program_v1.zig");
    const C = @import("integrations/riscv_cuda/resident_native_access_codegen_v1.zig");
    for ([_]u8{ 1, 2 }) |slot| for ([_]P.Mode{ .equations, .denominators }) |mode| {
        var p = try P.Owned.init(a, slot, mode);
        defer p.deinit();
        var writer: std.Io.Writer.Allocating = .init(a);
        defer writer.deinit();
        try C.emit(a, &writer.writer, "native_access", &p, .roots);
        if (mode == .equations) try C.emit(a, &writer.writer, "native_access_fold", &p, .folded_quotient);
        try std.testing.expect(writer.written().len > 0);
    };
}
test "resident native access export oracle" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_ACCESS_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("integrations/riscv_cuda/resident_native_access_codegen_v1.zig").exportOracle(a, path);
}
test "resident native access interaction export oracle" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_ACCESS_INTERACTION_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("integrations/riscv_cuda/resident_native_access_interaction_v1.zig").exportOracle(a, path);
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_access_interaction_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_access_witness_v1.zig"));
}
test "resident native access witness export oracle" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_ACCESS_WITNESS_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("integrations/riscv_cuda/resident_native_access_witness_v1.zig").exportOracle(a, path);
}
