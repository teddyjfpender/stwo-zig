//! Focused private gate for the SLLI/SRLI/SRAI fixed-authority cutover.

const authority = @import("stwo_riscv_rv32").air_lang_typed_shifts_imm_authority;

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_shifts_imm_authority_test.zig");
    _ = @import("stwo_riscv_rv32");
    _ = @import("stwo_riscv_rv32");
}
