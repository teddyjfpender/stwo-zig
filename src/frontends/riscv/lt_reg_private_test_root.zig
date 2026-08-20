const std = @import("std");

test "LT_REG private fixed-authority declarations compile" {
    std.testing.refAllDecls(@import("air/lang/typed_lt_reg_authority.zig"));
    std.testing.refAllDecls(@import("runner/lt_reg_retirement.zig"));
}

comptime {
    _ = @import("air/lang/typed_lt_reg_authority_test.zig");
    _ = @import("runner/lt_reg_retirement_test.zig");
}
