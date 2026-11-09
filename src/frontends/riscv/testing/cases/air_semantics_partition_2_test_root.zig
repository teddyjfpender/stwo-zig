//! One required compilation partition of the complete focused target.

test {
    _ = @import("stwo_riscv_air_lang").modules.tests_typed_div_adversarial_test;
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_div_authority;
    _ = @import("air/lang/tests/typed_div_authority_test.zig");
    _ = @import("air/lang/tests/typed_div_test.zig");
    _ = @import("air/lang/tests/typed_div_witness_test.zig");
    _ = @import("air/lang/tests/typed_fence_test.zig");
    _ = @import("air/lang/tests/typed_fence_authority_test.zig");
    _ = @import("air/lang/tests/typed_fence_witness_test.zig");
    _ = @import("air/lang/tests/typed_fence_witness_adversarial_test.zig");
    _ = @import("stwo_riscv_air_lang").modules.tests_typed_jalr_adversarial_test;
    _ = @import("air/lang/tests/typed_jalr_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_jalr_authority;
    _ = @import("air/lang/tests/typed_jalr_authority_test.zig");
    _ = @import("air/lang/tests/typed_jalr_witness_test.zig");
    _ = @import("air/lang/tests/typed_jal_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_jal_authority;
    _ = @import("air/lang/tests/typed_jal_authority_test.zig");
    _ = @import("air/lang/tests/typed_jal_witness_test.zig");
    _ = @import("air/lang/tests/typed_jal_witness_adversarial_test.zig");
    _ = @import("stwo_riscv_air_lang").modules.tests_typed_load_store_adversarial_test;
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_load_store_authority;
    _ = @import("air/lang/tests/typed_load_store_authority_test.zig");
    _ = @import("air/lang/tests/typed_load_store_test.zig");
    _ = @import("air/lang/tests/typed_load_store_witness_test.zig");
    _ = @import("air/lang/tests/typed_lt_imm_test.zig");
    _ = @import("air/lang/tests/typed_lt_imm_witness_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_imm_authority;
    _ = @import("air/lang/tests/typed_lt_imm_authority_test.zig");
    _ = @import("air/lang/tests/typed_lt_reg_test.zig");
    _ = @import("stwo_riscv_rv32").modules.air_lang_typed_lt_reg_authority;
    _ = @import("air/lang/tests/typed_lt_reg_authority_test.zig");
}
