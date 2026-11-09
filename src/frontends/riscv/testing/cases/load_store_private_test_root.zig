const std = @import("std");

test "LOAD_STORE private fixed-authority declarations compile" {
    std.testing.refAllDecls(@import("stwo_riscv_rv32").modules.air_lang_fixed_load_store);
    std.testing.refAllDecls(@import("stwo_riscv_rv32").modules.air_lang_typed_load_store_authority);
    std.testing.refAllDecls(@import("stwo_riscv_rv32").modules.runner_load_store_retirement);
}

comptime {
    _ = @import("air/lang/tests/typed_load_store_authority_test.zig");
    _ = @import("stwo_riscv_rv32").modules.runner_tests_load_store_retirement_test;
}
