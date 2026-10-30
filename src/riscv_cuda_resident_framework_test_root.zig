const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_framework_plan_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_framework_v1.zig"));
}
test "resident framework export numeric parameters" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_RESIDENT_FRAMEWORK_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("integrations/riscv_cuda/resident_parent_framework_numeric_v1.zig").exportVectors(a, path);
}

test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_counter_wide_v1.zig"));
}
