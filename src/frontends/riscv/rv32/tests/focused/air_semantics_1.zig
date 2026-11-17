//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("runner/tests/lui_retirement_test.zig");
    _ = @import("air/lang/typed_base_alu_imm_authority.zig");
    _ = @import("air/lang/typed_base_alu_reg_authority.zig");
    _ = @import("air/lang/typed_branch_eq_authority.zig");
    _ = @import("air/lang/typed_branch_lt_authority.zig");
}
