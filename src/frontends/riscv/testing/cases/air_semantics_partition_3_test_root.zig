//! One required compilation partition of the complete focused target.

test {
    _ = @import("air/lang/tests/typed_lt_reg_witness_test.zig");
    _ = @import("air/lang/tests/typed_lt_reg_witness_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_mul_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_mul_authority;
    _ = @import("air/lang/tests/typed_mul_authority_test.zig");
    _ = @import("air/lang/tests/typed_mul_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_mul_witness_test.zig");
    _ = @import("air/lang/tests/typed_mulh_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_mulh_authority;
    _ = @import("air/lang/tests/typed_mulh_authority_test.zig");
    _ = @import("air/lang/tests/typed_mulh_witness_test.zig");
    _ = @import("air/lang/tests/typed_mulh_witness_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_mulh_witness_performance_test.zig");
    _ = @import("stwo_riscv_air_lang").modules.tests_typed_opcode_production_authority_test;
    _ = @import("air/lang/tests/typed_shifts_imm_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_imm_authority;
    _ = @import("air/lang/tests/typed_shifts_imm_authority_test.zig");
    _ = @import("air/lang/tests/typed_shifts_imm_witness_test.zig");
    _ = @import("air/lang/tests/typed_shifts_imm_witness_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_shifts_reg_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_shifts_reg_authority;
    _ = @import("air/lang/tests/typed_shifts_reg_authority_test.zig");
    _ = @import("air/lang/tests/typed_shifts_reg_witness_test.zig");
    _ = @import("air/lang/tests/typed_shifts_reg_witness_adversarial_test.zig");
    _ = @import("air/lang/tests/typed_shifts_reg_witness_performance_test.zig");
    _ = @import("stwo_riscv_air_lang").modules.tests_typed_lui_adversarial_test;
    _ = @import("air/lang/tests/typed_lui_authority_test.zig");
    _ = @import("air/lang/tests/typed_lui_test.zig");
    _ = @import("air/lang/tests/typed_lui_witness_test.zig");
    _ = @import("recursion/air/tests/inventory_test.zig");
}
