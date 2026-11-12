//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("air/lang/tests/typed_div_adversarial_test.zig");
    _ = @import("air/lang/typed_div_authority.zig");
    _ = @import("air/lang/tests/typed_jalr_adversarial_test.zig");
    _ = @import("air/lang/typed_jalr_authority.zig");
    _ = @import("air/lang/typed_jal_authority.zig");
    _ = @import("air/lang/typed_load_store_authority.zig");
    _ = @import("air/lang/typed_lt_imm_authority.zig");
    _ = @import("air/lang/typed_lt_reg_authority.zig");
}
