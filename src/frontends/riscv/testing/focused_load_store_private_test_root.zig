const std = @import("std");

test "LOAD_STORE private fixed-authority declarations compile" {
    std.testing.refAllDecls(@import("stwo_riscv_rv32").air.lang.fixed_load_store);
    std.testing.refAllDecls(@import("stwo_riscv_rv32").air.lang.typed_load_store_authority);
    std.testing.refAllDecls(@import("stwo_riscv_rv32").execution.load_store_retirement);
}

comptime {
    _ = @import("cases/air/lang/tests/typed_load_store_authority_test.zig");
    _ = @import("stwo_riscv_rv32");
}
