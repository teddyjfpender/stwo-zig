const std = @import("std");

test "SHIFTS_REG private fixed-authority declarations compile" {
    std.testing.refAllDecls(@import("stwo_riscv_rv32").air.lang.typed_shifts_reg_authority);
    std.testing.refAllDecls(@import("stwo_riscv_rv32").execution.shifts_reg_retirement);
}

comptime {
    _ = @import("air/lang/tests/typed_shifts_reg_authority_test.zig");
    _ = @import("stwo_riscv_rv32");
}
