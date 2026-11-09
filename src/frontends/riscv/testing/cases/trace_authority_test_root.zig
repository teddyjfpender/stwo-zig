//! Focused production trace admission and typed authority retirement checks.
test {
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_air_lang");
    _ = @import("air/lang/tests/typed_base_alu_imm_authority_test.zig");
    _ = @import("air/lang/tests/typed_base_alu_reg_authority_test.zig");
}
