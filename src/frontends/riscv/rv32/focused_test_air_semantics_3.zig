//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("air/lang/typed_mul_authority.zig");
    _ = @import("air/lang/typed_mulh_authority.zig");
    _ = @import("air/lang/tests/typed_opcode_production_authority_test.zig");
    _ = @import("air/lang/typed_shifts_imm_authority.zig");
    _ = @import("air/lang/typed_shifts_reg_authority.zig");
}
