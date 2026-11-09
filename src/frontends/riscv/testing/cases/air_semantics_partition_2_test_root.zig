//! One required compilation partition of the complete focused target.

test {
    _ = @import("stwo_riscv_air_lang");
    _ = @import("stwo_riscv_rv32");
    _ = @import("air/lang/tests/typed_div_authority_test.zig");
    _ = @import("air/lang/tests/typed_div_test.zig");
    _ = @import("air/lang/tests/typed_div_witness_test.zig");
    _ = @import("air/lang/tests/typed_fence_test.zig");
    _ = @import("air/lang/tests/typed_fence_authority_test.zig");
    _ = @import("air/lang/tests/typed_fence_witness_test.zig");
    _ = @import("air/lang/tests/typed_fence_witness_adversarial_test.zig");
    _ = @import("stwo_riscv_air_lang");
    _ = @import("air/lang/tests/typed_jalr_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("air/lang/tests/typed_jalr_authority_test.zig");
    _ = @import("air/lang/tests/typed_jalr_witness_test.zig");
    _ = @import("air/lang/tests/typed_jal_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("air/lang/tests/typed_jal_authority_test.zig");
    _ = @import("air/lang/tests/typed_jal_witness_test.zig");
    _ = @import("air/lang/tests/typed_jal_witness_adversarial_test.zig");
    _ = @import("stwo_riscv_air_lang");
    _ = @import("stwo_riscv_rv32");
    _ = @import("air/lang/tests/typed_load_store_authority_test.zig");
    _ = @import("air/lang/tests/typed_load_store_test.zig");
    _ = @import("air/lang/tests/typed_load_store_witness_test.zig");
    _ = @import("air/lang/tests/typed_lt_imm_test.zig");
    _ = @import("air/lang/tests/typed_lt_imm_witness_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("air/lang/tests/typed_lt_imm_authority_test.zig");
    _ = @import("air/lang/tests/typed_lt_reg_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("air/lang/tests/typed_lt_reg_authority_test.zig");
}
