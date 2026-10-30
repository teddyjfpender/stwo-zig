const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_native_direct_codegen_v1.zig"));
}
test "resident native direct export oracle" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_NATIVE_DIRECT_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("integrations/riscv_cuda/resident_native_direct_codegen_v1.zig").exportOracle(a, path);
}
