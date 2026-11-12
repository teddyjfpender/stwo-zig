//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("cases/air/lang/tests/typed_lt_reg_witness_test.zig");
    _ = @import("cases/air/lang/tests/typed_lt_reg_witness_adversarial_test.zig");
    _ = @import("cases/air/lang/tests/typed_mul_test.zig");
    _ = @import("cases/air/lang/tests/typed_mul_authority_test.zig");
    _ = @import("cases/air/lang/tests/typed_mul_adversarial_test.zig");
    _ = @import("cases/air/lang/tests/typed_mul_witness_test.zig");
    _ = @import("cases/air/lang/tests/typed_mulh_test.zig");
    _ = @import("cases/air/lang/tests/typed_mulh_authority_test.zig");
    _ = @import("cases/air/lang/tests/typed_mulh_witness_test.zig");
    _ = @import("cases/air/lang/tests/typed_mulh_witness_adversarial_test.zig");
    _ = @import("cases/air/lang/tests/typed_mulh_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_imm_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_imm_authority_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_imm_witness_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_imm_witness_adversarial_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_reg_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_reg_authority_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_reg_witness_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_reg_witness_adversarial_test.zig");
    _ = @import("cases/air/lang/tests/typed_shifts_reg_witness_performance_test.zig");
    _ = @import("cases/air/lang/tests/typed_lui_authority_test.zig");
    _ = @import("cases/air/lang/tests/typed_lui_test.zig");
    _ = @import("cases/air/lang/tests/typed_lui_witness_test.zig");
    _ = @import("cases/recursion/air/tests/inventory_test.zig");
}
