const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_wire_registry_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_wire_resolve_plan_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_wire_resolve_v1.zig"));
}
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_wire_resolve_numeric_v1.zig"));
}
test "resident wire resolver export numeric" {
    const a = std.testing.allocator;
    const p = std.process.getEnvVarOwned(a, "STWO_RESIDENT_WIRE_EXPORT") catch return error.SkipZigTest;
    defer a.free(p);
    try @import("integrations/riscv_cuda/resident_parent_wire_resolve_numeric_v1.zig").exportVectors(a, p);
}
