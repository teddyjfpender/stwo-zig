const std = @import("std");

test "SHIFTS_REG private fixed-authority declarations compile" {
    std.testing.refAllDecls(@import("air/lang/typed_shifts_reg_authority.zig"));
    std.testing.refAllDecls(@import("runner/shifts_reg_retirement.zig"));
}

comptime {
    _ = @import("air/lang/typed_shifts_reg_authority_test.zig");
    _ = @import("runner/shifts_reg_retirement_test.zig");
}
