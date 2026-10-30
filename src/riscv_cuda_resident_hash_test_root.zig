const std = @import("std");
test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_hash_plan_v1.zig"));
}
test "resident hash device codegen uses exact shared G ordering" {
    const a = std.testing.allocator;
    const s = try @import("integrations/riscv_cuda/resident_parent_hash_codegen_v1.zig").generate(a);
    defer a.free(s);
    try std.testing.expect(std.mem.indexOf(u8, s, "main[ulong(81)") != null);
}
test "export resident hash vectors" {
    const a = std.testing.allocator;
    const path = std.process.getEnvVarOwned(a, "STWO_RESIDENT_HASH_EXPORT") catch return error.SkipZigTest;
    defer a.free(path);
    try @import("integrations/riscv_cuda/resident_parent_hash_numeric_v1.zig").exportVectors(a, path);
}
test "resident hash executor semantic" {
    _ = &@import("integrations/riscv_cuda/resident_parent_hash_witness_v1.zig").executeNative;
}

test {
    std.testing.refAllDecls(@import("integrations/riscv_cuda/resident_parent_hash_fixed_plan_v1.zig"));
}
