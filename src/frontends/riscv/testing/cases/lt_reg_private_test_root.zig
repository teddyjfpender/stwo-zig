const std = @import("std");

test "LT_REG private fixed-authority declarations compile" {
    std.testing.refAllDecls(@import("stwo_riscv_rv32").modules.air_lang_typed_lt_reg_authority);
    std.testing.refAllDecls(@import("stwo_riscv_rv32").modules.runner_lt_reg_retirement);
}

comptime {
    _ = @import("air/lang/tests/typed_lt_reg_authority_test.zig");
    _ = @import("stwo_riscv_rv32").modules.runner_tests_lt_reg_retirement_test;
}
